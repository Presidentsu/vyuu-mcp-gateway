"""MCP-2 P3 · Multi-Round Tool Result (MRTR) as a governed policy surface.

The 2026-07-28 revision lets a tool answer a `tools/call` with
`InputRequiredResult` instead of a result: "before I can finish, I need
something from your side." MRTR replaces the old back-channel, and it is
the single largest new attack surface in the revision — because what the
upstream can ask for is not data, it is *capability*:

- `sampling/createMessage` — it drives the CALLER'S LLM. Prompt
  injection using the caller's model, quota and context.
- `roots/list` — the caller's filesystem roots: a map of the machine.
- `elicitation/create` (form mode) — a prompt rendered to the human,
  under a schema the upstream chose.
- `elicitation/create` (url mode) — **it sends the human to a URL of its
  choosing, with a message of its choosing.**

That last row is phishing, delivered inside a tool call the user already
consented to. "Your session expired, re-authenticate at
`https://not-really-okta.example`" is a well-formed MRTR response.

## Default is deny, and that is not a new restriction

Without this module nothing reaches the client anyway: SDK v2's
`ClientSession.call_tool` takes `allow_input_required=False` and refuses
these outright. So default-deny reproduces today's *effective* behaviour
exactly — what changes is that a denial is now visible, attributed, and
explained, instead of surfacing as an opaque upstream error.

Each kind is opt-in per deployment, because each buys a genuinely
different amount of trust. An operator turning on `sampling` is deciding
that this upstream may spend their users' model budget; that decision
should be made once, deliberately, not inherited from a default.

## Classified by `method` string, not `isinstance`

Deliberate. The MRTR types only exist on SDK v2, so an `isinstance` check
would make this module unimportable on v1 — and more importantly, an
upstream is not obliged to send something our SDK version can parse. The
`method` discriminator is the wire contract; anything we cannot classify
is `UNKNOWN`, which is denied, because "we do not understand what this
upstream is asking for" is the last situation in which to say yes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

__all__ = [
    "MRTR_RESULT_TYPE",
    "InputRequestKind",
    "MrtrDecision",
    "MrtrPolicy",
    "ClassifiedInputRequest",
    "classify_input_requests",
    "evaluate_input_requests",
    "is_input_required",
]

# `InputRequiredResult.result_type`, on the wire as `resultType`.
MRTR_RESULT_TYPE = "input_required"


class InputRequestKind(StrEnum):
    """What an upstream is asking the caller's side to do."""

    SAMPLING = "sampling"
    ROOTS = "roots"
    ELICIT_FORM = "elicit_form"
    ELICIT_URL = "elicit_url"
    # Something we could not classify. Denied — see the module docstring.
    UNKNOWN = "unknown"


_METHOD_TO_KIND = {
    "sampling/createMessage": InputRequestKind.SAMPLING,
    "roots/list": InputRequestKind.ROOTS,
    # `elicitation/create` splits by its params' `mode`, resolved below.
    "elicitation/create": InputRequestKind.ELICIT_FORM,
}


@dataclass(frozen=True)
class ClassifiedInputRequest:
    """One entry from `InputRequiredResult.inputRequests`, classified."""

    request_id: str
    kind: InputRequestKind
    method: str | None
    # Populated only for `ELICIT_URL`. The destination the upstream wants
    # the human sent to — the field an operator reviewing an incident
    # will actually want.
    url: str | None = None
    # The prose the upstream wants shown to the human. Captured because a
    # phishing attempt is a *message* plus a URL, and the message is what
    # persuades.
    message: str | None = None

    @property
    def url_host(self) -> str | None:
        if not self.url:
            return None
        try:
            return (urlparse(self.url).hostname or "").lower() or None
        except ValueError:
            return None


@dataclass(frozen=True)
class MrtrPolicy:
    """Which input-request kinds this deployment permits.

    Empty `allowed_kinds` (the default) denies everything, matching the
    SDK's own `allow_input_required=False`.
    """

    allowed_kinds: frozenset[InputRequestKind] = frozenset()
    # When ELICIT_URL is allowed, restrict destinations. Empty means "any
    # host", which is a real decision an operator has to make explicitly:
    # allowing URL elicitation without a host list permits the upstream to
    # send users anywhere.
    allowed_elicit_url_hosts: frozenset[str] = frozenset()

    def permits(self, request: ClassifiedInputRequest) -> tuple[bool, str | None]:
        """`(allowed, reason_if_denied)`."""

        if request.kind is InputRequestKind.UNKNOWN:
            return False, "unrecognised input-request method"
        if request.kind not in self.allowed_kinds:
            return False, f"{request.kind.value} input requests are not enabled"
        if request.kind is InputRequestKind.ELICIT_URL and self.allowed_elicit_url_hosts:
            host = request.url_host
            if host is None:
                return False, "url elicitation with no parseable host"
            if not _host_allowed(host, self.allowed_elicit_url_hosts):
                return False, f"url elicitation host {host!r} is not allowed"
        return True, None


@dataclass(frozen=True)
class MrtrDecision:
    """Outcome for one `InputRequiredResult`.

    `allowed` is all-or-nothing on purpose. A partially-satisfied MRTR
    round leaves the upstream waiting on a request that will never be
    answered, and the caller holding a half-finished tool call with no
    way to reason about which half. Refusing the round outright is the
    only outcome both sides can act on.
    """

    allowed: bool
    requests: tuple[ClassifiedInputRequest, ...] = ()
    denied_reasons: tuple[str, ...] = ()
    request_state: str | None = None

    @property
    def kinds(self) -> tuple[str, ...]:
        return tuple(r.kind.value for r in self.requests)

    def audit_detail(self) -> dict[str, Any]:
        """The shape that goes into the audit event. Flat and
        JSON-native, because this is read during incident review and
        nested structures do not grep."""

        detail: dict[str, Any] = {
            "mrtr_allowed": self.allowed,
            "mrtr_kinds": list(self.kinds),
            "mrtr_request_count": len(self.requests),
        }
        if self.denied_reasons:
            detail["mrtr_denied_reasons"] = list(self.denied_reasons)
        # URL elicitation is the phishing case; surface destination and
        # message even when allowed, because "allowed" is exactly when
        # nobody is looking.
        urls = [
            {"url": r.url, "host": r.url_host, "message": r.message}
            for r in self.requests
            if r.kind is InputRequestKind.ELICIT_URL and r.url
        ]
        if urls:
            detail["mrtr_elicit_urls"] = urls
        return detail


def is_input_required(result: Any) -> bool:
    """Is this upstream response an MRTR input-required round?

    Reads `result_type` / `resultType` off either an SDK model or a plain
    dict, so it works before and after deserialization and on either SDK.
    """

    if isinstance(result, dict):
        value = result.get("resultType", result.get("result_type"))
    else:
        value = getattr(result, "result_type", None)
        if value is None:
            value = getattr(result, "resultType", None)
    return value == MRTR_RESULT_TYPE


def classify_input_requests(result: Any) -> list[ClassifiedInputRequest]:
    """Classify every entry in an `InputRequiredResult`'s request map."""

    raw = _input_requests_map(result)
    out: list[ClassifiedInputRequest] = []
    for request_id, request in (raw or {}).items():
        method = _get(request, "method")
        params = _get(request, "params")
        kind = _METHOD_TO_KIND.get(method, InputRequestKind.UNKNOWN)
        url: str | None = None
        message: str | None = None
        if kind is InputRequestKind.ELICIT_FORM:
            message = _get(params, "message")
            # `mode` splits form from url elicitation. Absent mode is
            # treated as a form (the older, narrower shape) rather than
            # guessed at.
            if _get(params, "mode") == "url":
                kind = InputRequestKind.ELICIT_URL
                url = _get(params, "url")
        out.append(
            ClassifiedInputRequest(
                request_id=str(request_id),
                kind=kind,
                method=method if isinstance(method, str) else None,
                url=url if isinstance(url, str) else None,
                message=message if isinstance(message, str) else None,
            )
        )
    return out


def evaluate_input_requests(result: Any, policy: MrtrPolicy) -> MrtrDecision:
    """Classify and rule on an `InputRequiredResult`.

    An input-required round carrying NO requests is denied: it asks the
    caller to wait for nothing, and the only ways to produce it are an
    upstream bug or a deliberate stall.
    """

    requests = tuple(classify_input_requests(result))
    state = _get(result, "request_state") or _get(result, "requestState")

    if not requests:
        return MrtrDecision(
            allowed=False,
            requests=(),
            denied_reasons=("input-required round carried no input requests",),
            request_state=state if isinstance(state, str) else None,
        )

    reasons: list[str] = []
    for request in requests:
        permitted, reason = policy.permits(request)
        if not permitted and reason is not None:
            reasons.append(f"{request.request_id}: {reason}")

    return MrtrDecision(
        allowed=not reasons,
        requests=requests,
        denied_reasons=tuple(reasons),
        request_state=state if isinstance(state, str) else None,
    )


# --- helpers ----------------------------------------------------------------


def _get(obj: Any, name: str) -> Any:
    """Attribute or key, whichever this object has. MRTR payloads reach us
    as SDK models on the outbound path and as plain dicts on the inbound
    one; classification should not care which."""

    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _input_requests_map(result: Any) -> dict[str, Any] | None:
    raw = _get(result, "input_requests")
    if raw is None:
        raw = _get(result, "inputRequests")
    return raw if isinstance(raw, dict) else None


def _host_allowed(host: str, allowed: frozenset[str]) -> bool:
    """Exact host, or a `.suffix` match for an entry written as a domain.

    Suffix matching requires the dot: an entry of `okta.com` matches
    `login.okta.com` but NOT `evil-okta.com`. Same trap as the tenant
    subdomain parser — a bare `endswith` hands an attacker the match.
    """

    for entry in allowed:
        candidate = entry.strip().lower().lstrip(".")
        if not candidate:
            continue
        if host == candidate or host.endswith("." + candidate):
            return True
    return False
