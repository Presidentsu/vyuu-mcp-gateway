"""RISK-1 · which LLM does the classification, and how it is called.

The vendor is a deployment choice, not an architectural one: a bank that
already has an Azure OpenAI contract should not have to fork this to use
it, and a tenant on Vertex should not be told to send its tool catalogue
to a third party. So the model is configuration, and adding one is a
registry entry rather than a code change.

## Structured output, per vendor

Every provider here is asked for the SAME JSON shape, but each one is
made to produce it by its own native mechanism — Anthropic tool-use,
OpenAI response_format json_schema, Gemini responseSchema. Parsing JSON
out of prose was the alternative and it is not one: a classifier whose
output occasionally fails to parse silently drops findings, and a risk
report that is quietly incomplete is worse than none.

## Why the catalogue is data and not an enum

Model identifiers move faster than this file will. `gpt-5.6-terra` and
`gpt-5.6-luna` did not exist when much of this gateway was written. An
operator who knows about a newer model must be able to name it without
waiting for a release, so `KNOWN_MODELS` seeds the picker and an
explicit `model_id` override is always honoured.

## Cost and blast radius

The classifier is sent tool NAMES, DESCRIPTIONS and INPUT SCHEMAS — the
public surface of the server. It is never sent credentials, secret refs,
audit rows, or user data; `classifier.py` builds that payload and is the
only thing that decides what leaves the tenant. That boundary is the
reason an operator can point this at a third-party API at all.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class RiskModelVendor(StrEnum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GEMINI = "gemini"


@dataclass(frozen=True)
class RiskModel:
    """One selectable model."""

    id: str
    vendor: RiskModelVendor
    label: str
    note: str


# Seeds the operator's picker. Verified against each vendor's published
# model list in August 2026 — treat as a starting point, not a closed
# set; `model_id` may name anything the vendor accepts.
KNOWN_MODELS: tuple[RiskModel, ...] = (
    RiskModel(
        id="claude-opus-5",
        vendor=RiskModelVendor.ANTHROPIC,
        label="Claude Opus 5",
        note="Most capable. Best for first assessment of an unfamiliar server.",
    ),
    RiskModel(
        id="claude-sonnet-5",
        vendor=RiskModelVendor.ANTHROPIC,
        label="Claude Sonnet 5",
        note="Balanced. Sensible default for routine re-assessment on sync.",
    ),
    RiskModel(
        id="gpt-5.6-terra",
        vendor=RiskModelVendor.OPENAI,
        label="GPT-5.6 Terra",
        note="Balances intelligence and cost.",
    ),
    RiskModel(
        id="gpt-5.6-luna",
        vendor=RiskModelVendor.OPENAI,
        label="GPT-5.6 Luna",
        note="Cost-sensitive, high-volume. For large catalogues.",
    ),
    RiskModel(
        id="gemini-3.7-flash",
        vendor=RiskModelVendor.GEMINI,
        label="Gemini 3.7 Flash",
        note="Google's latest GA model.",
    ),
)

MODELS_BY_ID: dict[str, RiskModel] = {m.id: m for m in KNOWN_MODELS}
DEFAULT_MODEL_ID = "claude-sonnet-5"


class RiskModelError(Exception):
    """The classifier could not be reached, or answered unusably.

    Deliberately NOT swallowed into an empty finding list. A failed
    assessment and a clean server produce the same "no findings" if you
    let them, and the operator publishing a vserver would read the
    failure as approval.
    """


@dataclass(frozen=True)
class RiskModelConfig:
    """Resolved settings for one call."""

    model_id: str
    vendor: RiskModelVendor
    api_key: str
    base_url: str | None = None
    timeout_seconds: float = 300.0
    # None = do not send the parameter at all.
    #
    # Temperature 0 is the obvious lever for a SCORING system — two
    # assessments of the same server must be comparable, and sampling
    # variance shows up as a band that moves while nothing changed.
    #
    # It is not available on the default model. Claude Sonnet 5 answers
    # `temperature is deprecated for this model` and refuses the whole
    # request, so sending it unconditionally breaks every Anthropic
    # assessment. Left as opt-in for vendors that still accept it, and
    # NOT sent to Anthropic at all (see `_anthropic`).
    #
    # Consequence: run-to-run variance on Anthropic cannot be reduced
    # this way. The anchored prompt is the only lever that applies, and
    # it narrows the spread rather than removing it.
    temperature: float | None = None
    # 8192 was too low and failed in a way that looked like a schema
    # bug: a run that hits the cap returns a PARTIAL tool input — valid
    # JSON with `findings` simply absent. A 141-tool CrowdStrike
    # catalogue reproduced it every time while an 11-tool one passed.
    # The failure now names itself (see `_anthropic`), but the real fix
    # is headroom: findings scale with the catalogue, and a large
    # catalogue is exactly when an operator most wants the answer.
    max_output_tokens: int = 32000


def vendor_for(model_id: str, declared: RiskModelVendor | None = None) -> RiskModelVendor:
    """Resolve the vendor for a model id.

    A known id resolves itself. An unknown id — an operator naming a
    model newer than this file — must declare its vendor, because the
    wire format cannot be guessed from the string.
    """

    known = MODELS_BY_ID.get(model_id)
    if known is not None:
        return known.vendor
    if declared is not None:
        return declared
    raise RiskModelError(
        f"unknown model {model_id!r}: declare its vendor "
        f"(one of {', '.join(v.value for v in RiskModelVendor)})"
    )


async def classify_json(
    config: RiskModelConfig,
    *,
    system_prompt: str,
    user_prompt: str,
    json_schema: dict[str, Any],
    http: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Run one classification and return the parsed object.

    Raises `RiskModelError` on transport failure, a non-2xx, or output
    that does not parse — never returns a partial result.
    """

    own = http is None
    client = http or httpx.AsyncClient(timeout=config.timeout_seconds)
    try:
        if config.vendor == RiskModelVendor.ANTHROPIC:
            return await _anthropic(client, config, system_prompt, user_prompt, json_schema)
        if config.vendor == RiskModelVendor.OPENAI:
            return await _openai(client, config, system_prompt, user_prompt, json_schema)
        if config.vendor == RiskModelVendor.GEMINI:
            return await _gemini(client, config, system_prompt, user_prompt, json_schema)
        raise RiskModelError(f"unsupported vendor {config.vendor}")
    finally:
        if own:
            await client.aclose()


def _parse(raw: str, *, vendor: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise RiskModelError(
            f"{vendor} returned output that is not JSON ({exc})"
        ) from exc
    if not isinstance(parsed, dict):
        raise RiskModelError(f"{vendor} returned {type(parsed).__name__}, expected an object")
    return parsed


async def _anthropic(
    client: httpx.AsyncClient,
    config: RiskModelConfig,
    system_prompt: str,
    user_prompt: str,
    json_schema: dict[str, Any],
) -> dict[str, Any]:
    # Tool-use with a forced tool_choice is Anthropic's structured-output
    # mechanism: the schema becomes the tool's input_schema and the model
    # must call it, so the reply is the object rather than prose about it.
    base = config.base_url or "https://api.anthropic.com"
    payload = {
        "model": config.model_id,
        "max_tokens": config.max_output_tokens,
        # No `temperature`: Claude Sonnet 5 rejects the request outright
        # with "temperature is deprecated for this model". Verified
        # against the live API, not inferred.
        # The system prompt is ~1,800 tokens and identical for every
        # chunk of a catalogue — a 5-slice server resent it five times.
        # Marking it cacheable turns that into one write and four reads.
        "system": [
            {
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        "messages": [{"role": "user", "content": user_prompt}],
        "tools": [
            {
                "name": "report_risk_assessment",
                "description": "Report the structured risk assessment.",
                "input_schema": json_schema,
            }
        ],
        "tool_choice": {"type": "tool", "name": "report_risk_assessment"},
    }
    try:
        response = await client.post(
            f"{base}/v1/messages",
            headers={
                "x-api-key": config.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=payload,
        )
    except httpx.HTTPError as exc:
        raise RiskModelError(f"anthropic unreachable ({exc.__class__.__name__})") from exc
    if response.status_code != 200:
        raise RiskModelError(
            f"anthropic returned HTTP {response.status_code}: {response.text[:300]}"
        )
    body = response.json()
    # Log what the cache actually did. Prompt caching is invisible
    # otherwise: it either works or silently does not, and the only
    # signal is a bill at the end of the month.
    usage = body.get("usage") or {}
    if usage:
        logger.info(
            "risk_model_usage",
            extra={
                "model": config.model_id,
                "input_tokens": usage.get("input_tokens"),
                "output_tokens": usage.get("output_tokens"),
                "cache_write": usage.get("cache_creation_input_tokens"),
                "cache_read": usage.get("cache_read_input_tokens"),
            },
        )
    stop_reason = body.get("stop_reason")
    for block in body.get("content", []):
        if block.get("type") == "tool_use":
            result = block.get("input")
            if isinstance(result, dict):
                # A run that hits the output cap returns a PARTIAL tool
                # input — valid JSON, missing fields. Silently passing
                # that on produced "`findings` missing or not a list",
                # which sends the reader looking for a schema bug that
                # is not there. Name the real cause.
                # Any truncated generation is unusable, regardless of
                # which keys survived. The first version only checked
                # for a MISSING `findings`, and the real partial had the
                # key present with an incomplete value — so it fell
                # through and the parser reported a phantom schema bug.
                if stop_reason == "max_tokens":
                    raise RiskModelError(
                        "anthropic hit the output limit before finishing the "
                        "assessment (stop_reason=max_tokens). The tool "
                        "catalogue is too large for one call at the current "
                        "max_output_tokens."
                    )
                return result
    raise RiskModelError(
        f"anthropic did not call the reporting tool "
        f"(stop_reason={stop_reason}, "
        f"blocks={[b.get('type') for b in body.get('content', [])]})"
    )


async def _openai(
    client: httpx.AsyncClient,
    config: RiskModelConfig,
    system_prompt: str,
    user_prompt: str,
    json_schema: dict[str, Any],
) -> dict[str, Any]:
    base = config.base_url or "https://api.openai.com"
    payload: dict[str, Any] = {
        "model": config.model_id,
        "messages": [
            # OpenAI caches long identical prefixes automatically, so the
            # system prompt going first is what makes that work.
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "risk_assessment",
                # Strict mode is what makes this a guarantee rather than
                # a request; without it the schema is a suggestion.
                "strict": True,
                "schema": json_schema,
            },
        },
    }
    if config.temperature is not None:
        payload["temperature"] = config.temperature
    try:
        response = await client.post(
            f"{base}/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {config.api_key}",
                "content-type": "application/json",
            },
            json=payload,
        )
    except httpx.HTTPError as exc:
        raise RiskModelError(f"openai unreachable ({exc.__class__.__name__})") from exc
    if response.status_code != 200:
        raise RiskModelError(
            f"openai returned HTTP {response.status_code}: {response.text[:300]}"
        )
    choices = response.json().get("choices") or []
    if not choices:
        raise RiskModelError("openai returned no choices")
    return _parse(choices[0].get("message", {}).get("content") or "", vendor="openai")


async def _gemini(
    client: httpx.AsyncClient,
    config: RiskModelConfig,
    system_prompt: str,
    user_prompt: str,
    json_schema: dict[str, Any],
) -> dict[str, Any]:
    base = config.base_url or "https://generativelanguage.googleapis.com"
    payload = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": _gemini_schema(json_schema),
            "maxOutputTokens": config.max_output_tokens,
        },
    }
    if config.temperature is not None:
        payload["generationConfig"]["temperature"] = config.temperature
    url = f"{base}/v1beta/models/{config.model_id}:generateContent"
    try:
        response = await client.post(
            url,
            headers={"x-goog-api-key": config.api_key, "content-type": "application/json"},
            json=payload,
        )
    except httpx.HTTPError as exc:
        raise RiskModelError(f"gemini unreachable ({exc.__class__.__name__})") from exc
    if response.status_code != 200:
        raise RiskModelError(
            f"gemini returned HTTP {response.status_code}: {response.text[:300]}"
        )
    candidates = response.json().get("candidates") or []
    if not candidates:
        raise RiskModelError("gemini returned no candidates")
    parts = candidates[0].get("content", {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts)
    return _parse(text, vendor="gemini")


def _gemini_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Strip keys Gemini's schema dialect rejects.

    It accepts a subset of JSON Schema and errors on the rest rather
    than ignoring it, so the same schema object cannot be posted to all
    three vendors unmodified.
    """

    unsupported = {"additionalProperties", "$schema", "strict", "default"}
    if not isinstance(schema, dict):
        return schema
    out: dict[str, Any] = {}
    for key, value in schema.items():
        if key in unsupported:
            continue
        if isinstance(value, dict):
            out[key] = _gemini_schema(value)
        elif isinstance(value, list):
            out[key] = [
                _gemini_schema(v) if isinstance(v, dict) else v for v in value
            ]
        else:
            out[key] = value
    return out
