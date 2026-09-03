"""Pre-configured catalog of common SaaS MCP servers.

The operator-console "Quick add from catalog" grid reads this module via
`GET /api/v1/operator/connector-catalog`. Clicking a card opens the
existing 5-step register wizard with everything pre-filled except
client-id-ref / client-secret-ref (and per-vendor extras like
Slack workspace) so the admin only fills the secrets.

This is *guidance, not enforcement* — every field the catalog pre-fills
is editable in the wizard. Defaults exist so the admin doesn't have to
remember 8 vendors' OAuth metadata + upstream URLs.

To add a connector:
  1. Append a `ConnectorTemplate` entry below.
  2. Restart the gateway. The UI and API pick it up automatically.

OAuth metadata mirrors the existing `OAUTH_PROVIDER_PRESETS` in
`operator_ui.py` (canonical auth/token URLs + sensible default scopes).
The catalog *adds* the upstream URL + transport + display name on top.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ConnectorTemplate:
    """One row in the operator's quick-add catalog.

    All string fields are user-editable in the wizard. Defaults shown
    here pre-fill the form so the admin only fills secret refs (and
    per-vendor extras under `extra_field_hints`).
    """

    key: str
    """Stable id used in URLs and analytics. lowercase + hyphens."""

    display_name: str
    """Human label shown on the catalog card (and used as the default
    `display_name` for the `mcp_servers` row)."""

    vendor: str
    """The SaaS vendor name (for grouping / search)."""

    tagline: str
    """One-line value-prop shown under the card title."""

    runtime: str
    """One of: 'http', 'npm', 'pypi', 'stdio', 'binary'. Drives which
    register-wizard runtime card is auto-selected."""

    default_source: str
    """Pre-filled `source_location` — upstream URL for HTTP, package
    name for npm/pypi, absolute path for stdio."""

    default_transport: str
    """One of: 'streamable_http', 'stdio', 'sse'."""

    oauth_authcode: dict[str, Any]
    """Pre-filled `auth_authcode` JSON (auth_url, token_url, default
    client/secret refs, scopes, redirect_uri, extras). The admin
    overrides client_id_ref + client_secret_ref to point at their own
    secret-store entries."""

    extra_field_hints: list[str] = field(default_factory=list)
    """Extra fields the admin needs to fill in (e.g. Slack workspace,
    Atlassian cloud-id). Surfaced as a checklist on the card so the
    admin knows what to gather before clicking install."""

    docs_url: str | None = None
    """Vendor doc link the admin can follow if the defaults need
    overriding."""

    status: str = "stable"
    """One of: 'stable', 'community', 'beta'. Controls the badge on
    the card. 'community' = no vendor-hosted MCP, install path uses
    a community npm/pypi package; admin should verify against the
    vendor's current guidance."""

    dcr_enabled: bool = False
    """True for vendors that follow the MCP-Auth standard (RFC 9728 +
    8414 + 7591) — Notion, Linear, anything built on the official MCP
    SDK auth helpers. Admin doesn't pre-create an OAuth app; gateway
    discovers + registers itself on first Connect. UI hides the
    `client_id_ref` / `client_secret_ref` fields when this is True
    and shows a 'Dynamic registration' badge on the card."""


_REDIRECT_URI = "http://localhost:8000/api/v1/oauth-authcode/callback"


CONNECTOR_CATALOG: list[ConnectorTemplate] = [
    ConnectorTemplate(
        key="github-copilot",
        display_name="GitHub Copilot MCP",
        vendor="GitHub",
        tagline="Repository search, issue / PR access, code review tools",
        runtime="http",
        default_source="https://api.githubcopilot.com/mcp/",
        default_transport="streamable_http",
        oauth_authcode={
            "auth_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "client_id_ref": "github-mcp-client-id",
            "client_secret_ref": "github-mcp-client-secret",
            "scopes": ["read:user", "repo"],
            "redirect_uri": _REDIRECT_URI,
        },
        docs_url="https://github.com/settings/developers",
    ),
    ConnectorTemplate(
        key="notion",
        display_name="Notion",
        vendor="Notion",
        tagline="Workspace pages, databases, search across your Notion org",
        runtime="http",
        default_source="https://mcp.notion.com/mcp",
        default_transport="streamable_http",
        # Notion's hosted MCP is fully MCP-Auth spec compliant —
        # gateway discovers AS metadata + dynamically registers itself
        # at the upstream's `/register` endpoint on first Connect. No
        # operator-side OAuth-app setup required.
        oauth_authcode={
            "dcr_enabled": True,
            "scopes": [],
            "redirect_uri": _REDIRECT_URI,
        },
        docs_url="https://developers.notion.com/docs/mcp",
        dcr_enabled=True,
    ),
    ConnectorTemplate(
        key="linear",
        display_name="Linear",
        vendor="Linear",
        tagline="Issue tracking, projects, cycles, comments",
        runtime="http",
        default_source="https://mcp.linear.app/mcp",
        default_transport="streamable_http",
        # Linear's hosted MCP is fully MCP-Auth spec compliant — same
        # auto-discovery + DCR path as Notion.
        oauth_authcode={
            "dcr_enabled": True,
            "scopes": ["read", "write"],
            "redirect_uri": _REDIRECT_URI,
        },
        docs_url="https://linear.app/changelog",
        dcr_enabled=True,
    ),
    ConnectorTemplate(
        key="jira",
        display_name="Jira",
        vendor="Atlassian",
        tagline="Issues, projects, sprints, comments, JQL search",
        runtime="http",
        default_source="https://mcp.atlassian.com/v1/sse",
        default_transport="streamable_http",
        oauth_authcode={
            "auth_url": "https://auth.atlassian.com/authorize",
            "token_url": "https://auth.atlassian.com/oauth/token",
            "client_id_ref": "atlassian-client-id",
            "client_secret_ref": "atlassian-client-secret",
            "scopes": [
                "read:jira-work",
                "write:jira-work",
                "offline_access",
            ],
            "redirect_uri": _REDIRECT_URI,
            "extra_authorize_params": {
                "audience": "api.atlassian.com",
                "prompt": "consent",
            },
        },
        extra_field_hints=[
            "Atlassian cloud-id (your-org.atlassian.net)",
        ],
        docs_url="https://developer.atlassian.com/console/myapps/",
    ),
    ConnectorTemplate(
        key="confluence",
        display_name="Confluence",
        vendor="Atlassian",
        tagline="Pages, spaces, comments, full-text search",
        runtime="http",
        default_source="https://mcp.atlassian.com/v1/sse",
        default_transport="streamable_http",
        oauth_authcode={
            "auth_url": "https://auth.atlassian.com/authorize",
            "token_url": "https://auth.atlassian.com/oauth/token",
            "client_id_ref": "atlassian-client-id",
            "client_secret_ref": "atlassian-client-secret",
            "scopes": [
                "read:confluence-content.summary",
                "read:confluence-content.all",
                "write:confluence-content",
                "offline_access",
            ],
            "redirect_uri": _REDIRECT_URI,
            "extra_authorize_params": {
                "audience": "api.atlassian.com",
                "prompt": "consent",
            },
        },
        extra_field_hints=[
            "Atlassian cloud-id (your-org.atlassian.net)",
            "Same Atlassian app as Jira — reuse the client_id_ref / "
            "client_secret_ref if installing both",
        ],
        docs_url="https://developer.atlassian.com/console/myapps/",
    ),
    ConnectorTemplate(
        key="slack",
        display_name="Slack",
        vendor="Slack",
        tagline="Channels, messages, users, search across the workspace",
        runtime="npm",
        default_source="@modelcontextprotocol/server-slack",
        default_transport="stdio",
        oauth_authcode={
            "auth_url": "https://slack.com/oauth/v2/authorize",
            "token_url": "https://slack.com/api/oauth.v2.access",
            "client_id_ref": "slack-client-id",
            "client_secret_ref": "slack-client-secret",
            "scopes": ["chat:write", "channels:read", "users:read"],
            "redirect_uri": _REDIRECT_URI,
        },
        extra_field_hints=[
            "Slack workspace id (T0XXXXXXX) — set in env_vars_ref",
            "Bot user OAuth token (xoxb-...) — set in env_vars_ref",
        ],
        docs_url="https://api.slack.com/apps",
        status="community",
    ),
    ConnectorTemplate(
        key="microsoft-365",
        display_name="Microsoft 365 (Graph)",
        vendor="Microsoft",
        tagline="Outlook mail, Calendar, OneDrive, Teams, SharePoint",
        runtime="npm",
        default_source="@softeria/ms-365-mcp-server",
        default_transport="stdio",
        oauth_authcode={
            "auth_url":
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "token_url":
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "client_id_ref": "microsoft-client-id",
            "client_secret_ref": "microsoft-client-secret",
            "scopes": [
                "User.Read",
                "Mail.Read",
                "Calendars.Read",
                "Files.Read",
                "offline_access",
            ],
            "redirect_uri": _REDIRECT_URI,
        },
        extra_field_hints=[
            "Entra tenant id (or 'common' for multi-tenant) — replace "
            "'common' in auth_url + token_url if single-tenant",
        ],
        docs_url="https://entra.microsoft.com/",
        status="community",
    ),
    ConnectorTemplate(
        key="asana",
        display_name="Asana",
        vendor="Asana",
        tagline="Tasks, projects, teams, comments",
        runtime="npm",
        default_source="@cristip73/mcp-server-asana",
        default_transport="stdio",
        oauth_authcode={
            "auth_url": "https://app.asana.com/-/oauth_authorize",
            "token_url": "https://app.asana.com/-/oauth_token",
            "client_id_ref": "asana-client-id",
            "client_secret_ref": "asana-client-secret",
            "scopes": ["default"],
            "redirect_uri": _REDIRECT_URI,
        },
        docs_url="https://app.asana.com/0/my-apps",
        status="community",
    ),
]


def get_catalog() -> list[ConnectorTemplate]:
    """Return the catalog (frozen list — caller must not mutate)."""
    return CONNECTOR_CATALOG


def get_by_key(key: str) -> ConnectorTemplate | None:
    """Look up one template. Returns None if `key` is unknown."""
    for c in CONNECTOR_CATALOG:
        if c.key == key:
            return c
    return None
