"""Boot the gateway with a demo OAuth-authcode MCP pre-registered.

Seeds (idempotent):

- An MCP server `github-demo` configured with `auth_authcode` pointing
  at GitHub's real authorize / token URLs (so clicking Connect lands
  the user on a real GitHub consent page — though the callback will
  fail since this isn't a real OAuth app).
- A virtual server `github-demo-vserver` (PUBLIC visibility — every
  user in the tenant can see it).
- A tool exposure linking the vserver to the MCP server.
- The InMemorySecretStore is seeded with demo client_id +
  client_secret values so the /initiate endpoint produces a valid
  authorize URL (with the configured client_id baked in).

Run via `python -m scripts.demo_oauth_authcode` from the repo root.
"""

from __future__ import annotations

import os
from uuid import UUID

import uvicorn
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Configuration via env vars — fall back to dev defaults if unset.
os.environ.setdefault(
    "VYUU_DATABASE_URL",
    "postgresql+psycopg://krishna@localhost:5432/vyuu_gateway",
)
os.environ.setdefault(
    "VYUU_PORTAL_SESSION_SIGNING_SECRET",
    "dev-portal-secret-rotate-me-in-prod-32chars",
)
os.environ.setdefault(
    "VYUU_OPERATOR_AUTH_SIGNING_SECRET",
    "dev-operator-secret-rotate-me-in-prod-32chars",
)
# Cursor / Claude Desktop / agents send `Authorization: Bearer
# vyuu_user_...`. The default `fake` provider expects `x-vyuu-*`
# lab headers and would reject every real client with 401. The
# `api_key` provider validates the bearer against `user_api_keys`.
os.environ.setdefault("VYUU_INBOUND_IDENTITY_PROVIDER", "api_key")

from vyuu_gateway.config import Settings, get_settings  # noqa: E402
from vyuu_gateway.main import create_app  # noqa: E402

TENANT_ID = UUID("11111111-1111-1111-1111-111111111111")
OPERATOR_ID = UUID("44444444-4444-4444-4444-444444444444")
LAB_USER_ID = UUID("22222222-2222-2222-2222-222222222222")
SERVER_ID = UUID("99999999-9999-9999-9999-999999999991")
VSERVER_ID = UUID("99999999-9999-9999-9999-999999999992")

CLIENT_ID_REF = "github-demo-client-id"
CLIENT_SECRET_REF = "github-demo-client-secret"


def seed_db() -> None:
    """Idempotent DB seeding — operator + tenant assumed to exist
    already (lab bootstrap), this script just adds the demo server +
    vserver + tool exposure on top."""

    engine = create_engine(os.environ["VYUU_DATABASE_URL"], future=True)
    factory = sessionmaker(engine, autoflush=False, future=True)
    auth_authcode = (
        # GitHub's real OAuth URLs — clicking Connect bounces to a real
        # GitHub consent page. The callback fails because we don't
        # actually own a GitHub OAuth app, but the inbound flow + state
        # token + secret-store resolution all run end-to-end.
        '{'
        '"auth_url":"https://github.com/login/oauth/authorize",'
        '"token_url":"https://github.com/login/oauth/access_token",'
        f'"client_id_ref":"{CLIENT_ID_REF}",'
        f'"client_secret_ref":"{CLIENT_SECRET_REF}",'
        '"scopes":["read:user","repo"],'
        '"redirect_uri":"http://localhost:8000/api/v1/oauth-authcode/callback"'
        '}'
    )
    with factory() as session:
        # 1. MCP server with auth_authcode wired.
        session.execute(
            text(
                """
                INSERT INTO mcp_servers (
                    id, tenant_id, display_name, source_type, source_location,
                    transport, args, auth_headers, auth_env, auth_passthrough,
                    auth_authcode, registered_by, health_status
                ) VALUES (
                    :id, :tenant, 'github-demo', 'http',
                    'https://api.example.com/mcp',
                    'streamable_http', ARRAY[]::text[], '{}', '{}', '{}',
                    CAST(:authcode AS jsonb), :op, 'unknown'
                )
                ON CONFLICT (id) DO UPDATE SET
                    auth_authcode = CAST(:authcode AS jsonb),
                    display_name = 'github-demo'
                """
            ),
            {
                "id": SERVER_ID,
                "tenant": TENANT_ID,
                "op": OPERATOR_ID,
                "authcode": auth_authcode,
            },
        )

        # 2. Virtual server (public — every user can see it).
        session.execute(
            text(
                """
                INSERT INTO virtual_servers (
                    id, tenant_id, name, visibility, created_by, rename_map
                ) VALUES (
                    :id, :tenant, 'github-demo-vserver', 'public', :op, '{}'
                )
                ON CONFLICT (id) DO UPDATE SET
                    visibility = 'public', name = 'github-demo-vserver'
                """
            ),
            {"id": VSERVER_ID, "tenant": TENANT_ID, "op": OPERATOR_ID},
        )

        # 3. Tool exposure: vserver wraps one demo tool from the MCP.
        session.execute(
            text(
                """
                INSERT INTO virtual_server_tools (
                    tenant_id, vserver_id, server_id, tool_name
                ) VALUES (
                    :tenant, :vserver, :server, 'list_repos'
                )
                ON CONFLICT (vserver_id, server_id, tool_name) DO NOTHING
                """
            ),
            {
                "tenant": TENANT_ID,
                "vserver": VSERVER_ID,
                "server": SERVER_ID,
            },
        )

        session.commit()
    print("[demo] seeded mcp_servers + virtual_servers + virtual_server_tools")


def main() -> None:
    seed_db()

    # Build the app once so we can poke its in-memory SecretStore
    # before serving — production deployments wouldn't do this; they'd
    # use Vault / AWS Secrets Manager and seed there.
    get_settings.cache_clear()
    settings = Settings(
        app_name="Vyuu MCP Gateway (demo)",
        environment="local",
        log_level="INFO",
        operator_auth_signing_secret=os.environ[
            "VYUU_OPERATOR_AUTH_SIGNING_SECRET"
        ],
        portal_session_signing_secret=os.environ[
            "VYUU_PORTAL_SESSION_SIGNING_SECRET"
        ],
        # Validate `Authorization: Bearer vyuu_user_...` against
        # `user_api_keys` rather than trusting `x-vyuu-*` headers.
        inbound_identity_provider="api_key",
    )
    app = create_app(settings)
    # Seed the in-memory secret store. Real GitHub OAuth-app creds
    # come from env (`DEMO_GH_CLIENT_ID` / `DEMO_GH_CLIENT_SECRET`)
    # so this script can stay in source control without leaking the
    # secret. Falls back to fake values when unset — Connect still
    # bounces to GitHub but consent fails on unknown client_id.
    gh_client_id = os.environ.get("DEMO_GH_CLIENT_ID", "demo-github-client-id")
    gh_client_secret = os.environ.get(
        "DEMO_GH_CLIENT_SECRET", "demo-github-client-secret"
    )
    app.state.secret_store.put(TENANT_ID, CLIENT_ID_REF, gh_client_id)
    app.state.secret_store.put(TENANT_ID, CLIENT_SECRET_REF, gh_client_secret)
    is_real = gh_client_id != "demo-github-client-id"
    print(
        f"[demo] seeded SecretStore with github-demo client creds "
        f"({'REAL GitHub OAuth app' if is_real else 'fake demo values'})"
    )
    print("[demo] starting uvicorn on http://127.0.0.1:8000 ...")
    print("[demo] portal:   http://localhost:8000/portal")
    print("[demo] operator: http://localhost:8000/operator")
    print("[demo] tenant ID for login: " + str(TENANT_ID))

    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
