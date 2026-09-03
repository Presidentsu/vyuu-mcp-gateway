"""SIEM-1 · Splunk HEC wire format and client, no network."""

from __future__ import annotations

import asyncio
import json
from uuid import uuid4

import httpx
import pytest

from vyuu_gateway.siem.events import SiemCategory, SiemEvent
from vyuu_gateway.siem.hec import (
    HecDeliveryError,
    HecTarget,
    InvalidHecUrlError,
    SplunkHecClient,
    envelope,
    normalise_hec_url,
    render_batch,
)

# --- URL normalisation -----------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://splunk.corp:8088", "https://splunk.corp:8088"),
        ("https://splunk.corp:8088/", "https://splunk.corp:8088"),
        ("https://splunk.corp:8088/services/collector", "https://splunk.corp:8088"),
        ("https://splunk.corp:8088/services/collector/event", "https://splunk.corp:8088"),
        ("https://splunk.corp:8088/services/collector/event/1.0", "https://splunk.corp:8088"),
        ("HTTPS://Splunk.Corp:8088/Services/Collector/Event", "https://splunk.corp:8088"),
        ("https://hec.example.com/splunk", "https://hec.example.com/splunk"),
        ("http://localhost:8088", "http://localhost:8088"),
        ("http://127.0.0.1:8088/services/collector", "http://127.0.0.1:8088"),
    ],
)
def test_pasted_forms_normalise_to_the_origin(raw: str, expected: str) -> None:
    assert normalise_hec_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "splunk.corp:8088",
        "ftp://splunk.corp",
        "http://splunk.corp:8088",  # plain http off-loopback
        "https://splunk.corp:8088?token=abc",
        "https://splunk.corp:8088#frag",
        "https://user:pw@splunk.corp:8088",
        "http://169.254.169.254/latest",
        "https://metadata.google.internal",
    ],
)
def test_unusable_urls_are_refused_with_a_reason(raw: str) -> None:
    with pytest.raises(InvalidHecUrlError):
        normalise_hec_url(raw)


# --- envelope ---------------------------------------------------------------


def _event(**overrides: object) -> SiemEvent:
    kwargs: dict[str, object] = {
        "category": SiemCategory.TOOL_CALL,
        "tenant_id": uuid4(),
        "body": {"tool": "query", "raw_args": {"sql": "x"}, "raw_args_truncated": False},
        "raw_fields": ("raw_args",),
    }
    kwargs.update(overrides)
    return SiemEvent(**kwargs)  # type: ignore[arg-type]


def test_envelope_uses_per_category_sourcetype_and_omits_absent_index() -> None:
    target = HecTarget(url="https://s:8088", token="t")
    out = envelope(_event(), target=target, include_raw=True, gateway_instance_id="gw-1")
    assert out["sourcetype"] == "vyuu:mcp:tool_call"
    assert out["source"] == "vyuu-mcp-gateway"
    assert out["host"] == "gw-1"
    assert "index" not in out
    assert isinstance(out["time"], float)
    assert out["event"]["category"] == "tool_call"
    assert out["event"]["schema_version"] == "1"
    assert out["event"]["raw_args"] == {"sql": "x"}


def test_envelope_honours_index_and_host_override() -> None:
    target = HecTarget(url="https://s:8088", token="t", index="sec", host="vyuu-prod-1")
    out = envelope(_event(), target=target, include_raw=True, gateway_instance_id="gw-1")
    assert out["index"] == "sec"
    assert out["host"] == "vyuu-prod-1"


def test_raw_fields_are_stripped_per_target_but_truncation_flags_stay() -> None:
    target = HecTarget(url="https://s:8088", token="t")
    out = envelope(_event(), target=target, include_raw=False, gateway_instance_id="gw")
    assert "raw_args" not in out["event"]
    assert out["event"]["raw_args_truncated"] is False


def test_render_batch_is_newline_separated_json_objects() -> None:
    target = HecTarget(url="https://s:8088", token="t")
    body = render_batch(
        [_event(), _event()], target=target, include_raw=False, gateway_instance_id="gw"
    )
    lines = body.decode().split("\n")
    assert len(lines) == 2
    for line in lines:
        assert json.loads(line)["sourcetype"] == "vyuu:mcp:tool_call"


# --- client -----------------------------------------------------------------


def _client(handler: httpx.MockTransport | None = None) -> tuple[SplunkHecClient,
    list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def _handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert handler is not None
        response = handler.handler(request)
        assert isinstance(response, httpx.Response)
        return response

    def factory(verify_tls: bool) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(_handle))

    return SplunkHecClient(http_factory=factory), seen


def _ok(_: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"text": "Success", "code": 0})


def test_send_batch_posts_to_the_collector_with_the_splunk_auth_scheme() -> None:
    client, seen = _client(httpx.MockTransport(_ok))
    target = HecTarget(url="https://splunk.corp:8088", token="secret-token")

    async def run() -> int:
        return await client.send_batch(
            target, [_event()], include_raw=False, gateway_instance_id="gw"
        )

    assert asyncio.run(run()) == 1
    request = seen[0]
    assert str(request.url) == "https://splunk.corp:8088/services/collector/event"
    assert request.headers["authorization"] == "Splunk secret-token"
    assert request.headers["content-type"] == "application/json"
    # The token rides only in the header; never in the body.
    assert b"secret-token" not in request.content


def test_invalid_token_is_not_retryable_and_quotes_splunk() -> None:
    client, _ = _client(
        httpx.MockTransport(lambda r: httpx.Response(403, json={"text": "Invalid token",
            "code": 4}))
    )
    target = HecTarget(url="https://s:8088", token="bad")

    async def run() -> None:
        await client.send_batch(target, [_event()], include_raw=False, gateway_instance_id="gw")

    with pytest.raises(HecDeliveryError) as excinfo:
        asyncio.run(run())
    assert excinfo.value.retryable is False
    assert excinfo.value.status_code == 403
    assert "Invalid token" in excinfo.value.detail


def test_server_busy_is_retryable() -> None:
    client, _ = _client(
        httpx.MockTransport(lambda r: httpx.Response(503, json={"text": "Server is busy",
            "code": 9}))
    )
    target = HecTarget(url="https://s:8088", token="t")

    async def run() -> None:
        await client.send_batch(target, [_event()], include_raw=False, gateway_instance_id="gw")

    with pytest.raises(HecDeliveryError) as excinfo:
        asyncio.run(run())
    assert excinfo.value.retryable is True


def test_a_200_with_a_nonzero_splunk_code_is_still_a_failure() -> None:
    client, _ = _client(
        httpx.MockTransport(
            lambda r: httpx.Response(200, json={"text": "Invalid data format", "code": 6})
        )
    )
    target = HecTarget(url="https://s:8088", token="t")

    async def run() -> None:
        await client.send_batch(target, [_event()], include_raw=False, gateway_instance_id="gw")

    with pytest.raises(HecDeliveryError) as excinfo:
        asyncio.run(run())
    assert excinfo.value.retryable is False
    assert "Invalid data format" in excinfo.value.detail


def test_network_failures_are_retryable() -> None:
    def boom(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client, _ = _client(httpx.MockTransport(boom))
    target = HecTarget(url="https://s:8088", token="t")

    async def run() -> None:
        await client.send_batch(target, [_event()], include_raw=False, gateway_instance_id="gw")

    with pytest.raises(HecDeliveryError) as excinfo:
        asyncio.run(run())
    assert excinfo.value.retryable is True
    assert excinfo.value.status_code is None


def test_empty_batch_sends_nothing() -> None:
    client, seen = _client(httpx.MockTransport(_ok))
    target = HecTarget(url="https://s:8088", token="t")
    assert asyncio.run(client.send_batch(target, [], include_raw=False,
        gateway_instance_id="gw")) == 0
    assert seen == []
