"""Tests for the SaaS connector catalog API + module.

The catalog itself is a static Python module (no DB), so the unit
tests run in any environment. The API endpoint tests use the
operator-bearer test token and an in-memory FastAPI client — no
Postgres, no Redis, no NATS required.
"""
from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from vyuu_gateway.config import Settings
from vyuu_gateway.main import create_app
from vyuu_gateway.operator_auth.fake import mint_operator_test_token
from vyuu_gateway.upstream.connector_catalog import (
    CONNECTOR_CATALOG,
    ConnectorTemplate,
    get_by_key,
    get_catalog,
)

_SECRET = "connector-catalog-test-secret"


def _client_and_headers() -> tuple[TestClient, dict[str, str]]:
    app = create_app(
        Settings(
            app_name="connector-catalog-test",
            environment="test",
            log_level="CRITICAL",
            operator_auth_signing_secret=_SECRET,
        )
    )
    token = mint_operator_test_token(
        tenant_id=uuid4(), operator_id=uuid4(), signing_secret=_SECRET
    )
    return TestClient(app), {"Authorization": f"Bearer {token}"}


# ----------------------------------------------------------------------
# Catalog module — schema + content invariants
# ----------------------------------------------------------------------


def test_catalog_has_at_least_eight_connectors() -> None:
    catalog = get_catalog()
    assert len(catalog) >= 8, (
        f"v1 ships 8 connectors (GitHub/Notion/Slack/Linear/Jira/"
        f"Confluence/Asana/Microsoft 365); got {len(catalog)}"
    )


def test_every_connector_has_required_fields() -> None:
    """Every entry must be a usable ConnectorTemplate. Catches typos
    when adding a new connector."""
    for c in get_catalog():
        assert isinstance(c, ConnectorTemplate)
        assert c.key
        assert c.display_name
        assert c.vendor
        assert c.tagline
        assert c.runtime in {"http", "npm", "pypi", "stdio", "binary"}
        assert c.default_source
        assert c.default_transport in {"streamable_http", "stdio", "sse"}
        assert isinstance(c.oauth_authcode, dict)
        # `redirect_uri` and `scopes` are required regardless of mode.
        # DCR connectors auto-discover auth_url/token_url + auto-issue
        # client_id/secret, so those fields are optional in DCR mode.
        for required in ("redirect_uri", "scopes"):
            assert required in c.oauth_authcode, (
                f"connector {c.key!r} oauth_authcode missing {required!r}"
            )
        if c.dcr_enabled:
            # DCR mode: oauth_authcode JSON should declare it explicitly
            # so the schema validator's relaxed-required-fields path
            # fires at registration time.
            assert c.oauth_authcode.get("dcr_enabled") is True, (
                f"connector {c.key!r} has dcr_enabled=True on the "
                f"template but missing dcr_enabled in oauth_authcode JSON"
            )
        else:
            # Static-creds mode: must carry the four pre-configured
            # OAuth fields the operator's wizard preset relies on.
            for required in (
                "auth_url",
                "token_url",
                "client_id_ref",
                "client_secret_ref",
            ):
                assert required in c.oauth_authcode, (
                    f"connector {c.key!r} oauth_authcode missing {required!r}"
                )
        assert c.status in {"stable", "community", "beta"}


def test_connector_keys_are_unique() -> None:
    keys = [c.key for c in CONNECTOR_CATALOG]
    assert len(keys) == len(set(keys)), (
        f"duplicate connector keys: {[k for k in keys if keys.count(k) > 1]}"
    )


def test_get_by_key_returns_match_or_none() -> None:
    first = CONNECTOR_CATALOG[0]
    assert get_by_key(first.key) is first
    assert get_by_key("does-not-exist") is None


def test_expected_connectors_are_present() -> None:
    """Sanity check on the v1 list — if any of these keys disappear,
    the test fails so the change is intentional."""
    keys = {c.key for c in get_catalog()}
    for required in {
        "github-copilot",
        "notion",
        "linear",
        "jira",
        "confluence",
        "slack",
        "microsoft-365",
        "asana",
    }:
        assert required in keys, f"connector {required!r} missing from catalog"


# ----------------------------------------------------------------------
# API — auth + payload shape
# ----------------------------------------------------------------------


def test_catalog_endpoint_requires_operator_bearer() -> None:
    client, _ = _client_and_headers()
    r = client.get("/api/v1/operator/connector-catalog")
    assert r.status_code in (401, 403)


def test_catalog_endpoint_returns_full_list() -> None:
    client, headers = _client_and_headers()
    r = client.get("/api/v1/operator/connector-catalog", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert "items" in body and "total" in body
    assert body["total"] == len(get_catalog())
    assert len(body["items"]) == body["total"]


def test_catalog_endpoint_payload_shape() -> None:
    client, headers = _client_and_headers()
    r = client.get("/api/v1/operator/connector-catalog", headers=headers)
    body = r.json()
    for item in body["items"]:
        for required in (
            "key",
            "display_name",
            "vendor",
            "tagline",
            "runtime",
            "default_source",
            "default_transport",
            "oauth_authcode",
            "extra_field_hints",
            "docs_url",
            "status",
        ):
            assert required in item, f"item {item.get('key')} missing {required}"
        assert isinstance(item["extra_field_hints"], list)
        assert isinstance(item["oauth_authcode"], dict)


def test_catalog_payload_oauth_metadata_is_complete() -> None:
    """The card-click flow only works if every connector has the
    OAuth metadata the wizard preset expects. Catch missing fields
    here rather than in a confusing UI failure.

    DCR connectors (Notion, Linear) skip the static-fields check
    because the gateway auto-discovers + auto-issues at runtime."""
    client, headers = _client_and_headers()
    r = client.get("/api/v1/operator/connector-catalog", headers=headers)
    for item in r.json()["items"]:
        oa = item["oauth_authcode"]
        assert isinstance(oa["scopes"], list)
        if item["dcr_enabled"]:
            assert oa.get("dcr_enabled") is True
        else:
            assert oa["auth_url"].startswith("https://")
            assert oa["token_url"].startswith("https://")
            assert oa["client_id_ref"]
            assert oa["client_secret_ref"]
