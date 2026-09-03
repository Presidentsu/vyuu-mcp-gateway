"""Splunk HTTP Event Collector — wire format and client.

HEC is a POST of one or more JSON objects to `/services/collector/event`
with `Authorization: Splunk <token>`. Objects may be concatenated in one
body; Splunk splits them itself. Each object is an envelope
(`time`, `host`, `source`, `sourcetype`, optional `index`) around the
`event` payload. The Splunk OpenTelemetry Collector and Splunk Cloud
both speak this exact protocol, so "Splunk HEC" here covers all three.

## Why the URL is normalised, not just validated

Operators paste whatever their Splunk admin sent them: the bare origin,
the origin with `/services/collector`, or the full `/services/collector/
event`. All three mean the same target. Accepting all three and storing
the origin is friendlier than rejecting two of them, and it means the
health probe and the event endpoint are derived from one value instead
of guessed from a string that may or may not already contain a path.

## Retryability

Splunk's error codes are documented and stable. 5xx and 429 mean "try
again"; every other 4xx means the request is wrong — a bad token, an
index the token may not write to, malformed JSON — and retrying it only
delays the operator finding out. `HecDeliveryError.retryable` carries
that distinction to the exporter, which drops non-retryable batches
immediately and records the reason where the console can show it.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from vyuu_gateway.siem.events import SCHEMA_VERSION, SiemEvent

logger = logging.getLogger(__name__)

HEC_EVENT_PATH = "/services/collector/event"
HEC_HEALTH_PATH = "/services/collector/health"

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})
_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata"})
_PASTED_SUFFIXES = (
    "/services/collector/event/1.0",
    "/services/collector/event",
    "/services/collector/raw",
    "/services/collector/health",
    "/services/collector",
)


class InvalidHecUrlError(ValueError):
    """The HEC URL cannot be used. The message says why, for the UI."""


def normalise_hec_url(raw: str) -> str:
    """Return the HEC origin (scheme + host[:port] + base path) or raise.

    - https required, except for loopback hosts (a lab Splunk / mock).
    - A pasted collector path is stripped; a stray query string is
      refused rather than silently discarded.
    - Link-local and cloud-metadata addresses are refused outright: a
      SIEM lives on a network, not at 169.254.169.254, and the gateway
      posting tenant audit data there with a bearer header is the one
      outcome that must not be reachable from a settings form.
    """

    value = (raw or "").strip()
    if not value:
        raise InvalidHecUrlError("HEC URL is required")
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise InvalidHecUrlError("HEC URL must start with https:// (http:// only for localhost)")
    if not parts.hostname:
        raise InvalidHecUrlError("HEC URL has no host")
    if parts.query or parts.fragment:
        raise InvalidHecUrlError("HEC URL must not carry a query string or fragment")
    if parts.username or parts.password:
        raise InvalidHecUrlError("put the token in the token field, not in the URL")

    host = parts.hostname.lower()
    if host in _METADATA_HOSTS:
        raise InvalidHecUrlError("that host is a cloud metadata service, not a SIEM")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and address.is_link_local:
        raise InvalidHecUrlError("link-local addresses are not accepted as a SIEM target")
    if parts.scheme == "http" and host not in _LOOPBACK_HOSTS and not (
        address is not None and address.is_loopback
    ):
        raise InvalidHecUrlError(
            "HEC URL must use https:// — plain http is accepted only for localhost"
        )

    path = parts.path.rstrip("/")
    lowered = path.lower()
    for suffix in _PASTED_SUFFIXES:
        if lowered.endswith(suffix):
            path = path[: -len(suffix)]
            break
    path = path.rstrip("/")
    netloc = parts.netloc.lower()
    return f"{parts.scheme}://{netloc}{path}"


@dataclass(frozen=True, slots=True)
class HecTarget:
    """Everything needed to deliver to one collector. Holds the token —
    it is built inside the exporter worker from a secret ref and never
    stored, logged or returned."""

    url: str
    token: str
    index: str | None = None
    source: str = "vyuu-mcp-gateway"
    host: str | None = None
    verify_tls: bool = True

    @property
    def event_endpoint(self) -> str:
        return f"{self.url}{HEC_EVENT_PATH}"


class HecDeliveryError(Exception):
    def __init__(self, detail: str, *, status_code: int | None, retryable: bool) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code
        self.retryable = retryable


def envelope(
    event: SiemEvent,
    *,
    target: HecTarget,
    include_raw: bool,
    gateway_instance_id: str,
) -> dict[str, Any]:
    """One HEC object. `sourcetype` is per category so Splunk props apply."""

    body = dict(event.body)
    if not include_raw:
        for key in event.raw_fields:
            body.pop(key, None)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "category": event.category.value,
        "event_id": str(event.event_id),
        "tenant_id": str(event.tenant_id) if event.tenant_id is not None else None,
        "gateway_instance_id": gateway_instance_id,
        **body,
    }
    out: dict[str, Any] = {
        "time": round(event.timestamp.timestamp(), 3),
        "host": target.host or gateway_instance_id,
        "source": target.source,
        "sourcetype": f"vyuu:mcp:{event.category.value}",
        "event": payload,
    }
    if target.index:
        out["index"] = target.index
    return out


def render_batch(
    events: Sequence[SiemEvent],
    *,
    target: HecTarget,
    include_raw: bool,
    gateway_instance_id: str,
) -> bytes:
    """Concatenated JSON objects, newline-separated. `default=str` so a
    stray UUID / datetime in a detail dict cannot poison a whole batch."""

    lines = [
        json.dumps(
            envelope(
                e, target=target, include_raw=include_raw,
                gateway_instance_id=gateway_instance_id,
            ),
            separators=(",", ":"),
            default=str,
        )
        for e in events
    ]
    return "\n".join(lines).encode("utf-8")


HttpFactory = Callable[[bool], httpx.AsyncClient]


def _default_http_factory(verify_tls: bool) -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=verify_tls, timeout=httpx.Timeout(10.0))


class SplunkHecClient:
    """Delivers rendered batches. One httpx client per TLS-verify mode,
    because `verify` is a client property, not a request one."""

    def __init__(self, *, http_factory: HttpFactory | None = None) -> None:
        self._http_factory = http_factory or _default_http_factory
        self._clients: dict[bool, httpx.AsyncClient] = {}

    def _client(self, verify_tls: bool) -> httpx.AsyncClient:
        client = self._clients.get(verify_tls)
        if client is None:
            client = self._http_factory(verify_tls)
            self._clients[verify_tls] = client
        return client

    async def send_batch(
        self,
        target: HecTarget,
        events: Sequence[SiemEvent],
        *,
        include_raw: bool,
        gateway_instance_id: str,
    ) -> int:
        """POST one batch. Returns the number of events delivered; raises
        `HecDeliveryError` otherwise. Never logs the token."""

        if not events:
            return 0
        body = render_batch(
            events, target=target, include_raw=include_raw,
            gateway_instance_id=gateway_instance_id,
        )
        headers = {
            "Authorization": f"Splunk {target.token}",
            "Content-Type": "application/json",
        }
        try:
            response = await self._client(target.verify_tls).post(
                target.event_endpoint, content=body, headers=headers
            )
        except httpx.TimeoutException as exc:
            raise HecDeliveryError(
                f"timed out talking to {target.url}", status_code=None, retryable=True
            ) from exc
        except httpx.HTTPError as exc:
            raise HecDeliveryError(
                f"{exc.__class__.__name__} talking to {target.url}",
                status_code=None,
                retryable=True,
            ) from exc

        detail = _splunk_detail(response)
        if response.status_code == 200:
            # Splunk answers 200 with `code: 0` on success. Anything else
            # under a 200 is a partial / odd response worth surfacing.
            code = _splunk_code(response)
            if code not in (None, 0):
                raise HecDeliveryError(
                    f"HEC accepted the request but reported: {detail}",
                    status_code=200,
                    retryable=False,
                )
            return len(events)
        retryable = response.status_code >= 500 or response.status_code in (408, 429)
        raise HecDeliveryError(
            f"HTTP {response.status_code}: {detail}",
            status_code=response.status_code,
            retryable=retryable,
        )

    async def aclose(self) -> None:
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()


def _splunk_code(response: httpx.Response) -> int | None:
    try:
        data = response.json()
    except ValueError:
        return None
    code = data.get("code") if isinstance(data, dict) else None
    return code if isinstance(code, int) else None


def _splunk_detail(response: httpx.Response) -> str:
    """Splunk's own `text` field when present, else a trimmed body.
    Splunk's messages are precise ("Invalid token", "Incorrect index")
    and worth showing to the operator verbatim."""

    try:
        data = response.json()
    except ValueError:
        data = None
    if isinstance(data, dict):
        text = data.get("text")
        code = data.get("code")
        if isinstance(text, str):
            return f"{text} (code {code})" if code is not None else text
    snippet = response.text.strip().replace("\n", " ")
    return snippet[:200] or f"empty response ({response.status_code})"
