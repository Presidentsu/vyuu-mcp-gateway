"""S8 — best-effort `mcp.json` manifest discovery.

⚠️  Spec stability note: as of 2026-04, the MCP `mcp.json` manifest
shape is **NOT a stable spec** — different upstream implementations
publish different conventions. This module pulls a deliberate
**conservative subset** of fields that several real-world manifests
agree on; anything outside that subset is ignored. When the upstream
spec stabilises, this module is the only place that needs to evolve.

The operator-facing flow:

1. Operator pastes a manifest URL (e.g. `https://upstream.example/mcp.json`).
2. `POST /api/v1/servers/from-manifest` fetches it (https-only by default,
   timeout-bound).
3. Returns a `ManifestPreviewResponse` with the auto-detected fields
   (transport, endpoint URL or command/args, display name, description)
   plus the raw JSON so the operator can see what wasn't auto-mapped.
4. Operator inspects → calls the existing `POST /api/v1/servers` with
   the pre-filled request body. **No auto-registration** — the operator
   always reviews + confirms before a server lands in the registry.

That last point is deliberate: a malicious manifest URL shouldn't be
able to silently land an arbitrary upstream in a tenant's registry.
The endpoint is read-only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


class ManifestFetchError(Exception):
    """The manifest URL could not be fetched (network error, non-2xx, etc.)."""


class ManifestParseError(Exception):
    """The manifest body was not a JSON object."""


@dataclass(frozen=True)
class ParsedManifest:
    """Conservative subset of `mcp.json` fields the gateway recognises.

    Any field can be `None` — operators see the gaps and fill them in.
    The `raw` payload is round-tripped to the UI verbatim so an operator
    eyeballing an unfamiliar manifest sees what wasn't auto-mapped.
    """

    display_name: str | None = None
    description: str | None = None
    transport: str | None = None
    source_type: str | None = None
    source_location: str | None = None
    args: list[str] = field(default_factory=list)
    auth_hint: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


_TRANSPORT_ALIASES = {
    "streamable-http": "streamable_http",
    "streamable_http": "streamable_http",
    "http": "streamable_http",
    "sse": "sse",
    "stdio": "stdio",
}


def parse_manifest(payload: dict[str, Any]) -> ParsedManifest:
    """Extract the recognised fields from a manifest dict.

    Defensive: never raises on missing or differently-named fields — we
    pull what we can and leave the rest for the operator to map by hand.
    """

    if not isinstance(payload, dict):
        raise ManifestParseError("manifest payload must be a JSON object")

    display_name = _first_string(payload, ["name", "display_name", "title"])
    description = _first_string(payload, ["description", "summary"])

    raw_transport = _first_string(payload, ["transport", "type"])
    transport = _TRANSPORT_ALIASES.get(raw_transport.lower()) if raw_transport else None

    # Stdio-style: command + args. HTTP-style: endpoint URL.
    command = _first_string(payload, ["command", "executable", "binary"])
    endpoint = _first_string(
        payload, ["endpoint", "url", "uri", "http_url", "streamable_http_url"]
    )

    source_type: str | None = None
    source_location: str | None = None
    args: list[str] = []

    if endpoint:
        source_type = "http"
        source_location = endpoint
        if transport is None:
            transport = "streamable_http"
    elif command:
        # We map shell commands to the closest source_type the gateway
        # supports today. `npx` → `npm`, `uvx` → `pypi`, anything else
        # stays as `stdio` and the operator will need to confirm the
        # command + allowlist.
        if command.endswith("/npx") or command == "npx":
            source_type = "npm"
            raw_args = payload.get("args") or []
            if isinstance(raw_args, list):
                args = [str(a) for a in raw_args]
                pkg = _last_arg_looking_like_package(args)
                if pkg:
                    source_location = pkg
        elif command.endswith("/uvx") or command == "uvx":
            source_type = "pypi"
            raw_args = payload.get("args") or []
            if isinstance(raw_args, list):
                args = [str(a) for a in raw_args]
                if args:
                    source_location = args[0]
        else:
            source_type = "stdio"
            source_location = command
            raw_args = payload.get("args") or []
            if isinstance(raw_args, list):
                args = [str(a) for a in raw_args]
        if transport is None:
            transport = "stdio"

    auth_hint = _extract_auth_hint(payload)

    return ParsedManifest(
        display_name=display_name,
        description=description,
        transport=transport,
        source_type=source_type,
        source_location=source_location,
        args=args,
        auth_hint=auth_hint,
        raw=payload,
    )


async def fetch_manifest(
    url: str,
    *,
    allow_http: bool = False,
    timeout_seconds: float = 5.0,
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Fetch a manifest URL and return the parsed JSON body.

    Defaults to HTTPS-only — pass `allow_http=True` for local dev.
    Same posture as the existing URL allowlist (`registry.url_security`)
    on registration: defensive by default, opt-in for relaxations.
    """

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ManifestFetchError(f"unsupported manifest URL scheme: {parsed.scheme!r}")
    if parsed.scheme == "http" and not allow_http:
        raise ManifestFetchError("manifest URL must be HTTPS (set allow_http=True for dev)")
    client = http_client or httpx.AsyncClient(timeout=timeout_seconds)
    try:
        try:
            response = await client.get(url)
        except httpx.HTTPError as exc:
            raise ManifestFetchError(
                f"manifest fetch failed: {exc.__class__.__name__}"
            ) from exc
        if response.status_code >= 400:
            raise ManifestFetchError(
                f"manifest fetch returned HTTP {response.status_code}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise ManifestParseError("manifest body was not JSON") from exc
    finally:
        if http_client is None:
            await client.aclose()
    if not isinstance(body, dict):
        raise ManifestParseError("manifest body must be a JSON object")
    return body


# --- Helpers --------------------------------------------------------------


def _first_string(payload: dict[str, Any], keys: list[str]) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _last_arg_looking_like_package(args: list[str]) -> str | None:
    """Pick the trailing `args` element that looks like a package name —
    skips flags like `-y`, `--silent`, etc. Best-effort only."""
    for arg in reversed(args):
        if not arg.startswith("-"):
            return arg
    return None


def _extract_auth_hint(payload: dict[str, Any]) -> str | None:
    """Return a human-readable hint about what auth shape the upstream
    expects. Doesn't try to be exhaustive — the operator finalises auth
    config anyway when they confirm the registration."""
    auth = payload.get("auth")
    if not isinstance(auth, dict):
        return None
    scheme = auth.get("scheme") or auth.get("type")
    if isinstance(scheme, str) and scheme.strip():
        return scheme.strip()
    return None
