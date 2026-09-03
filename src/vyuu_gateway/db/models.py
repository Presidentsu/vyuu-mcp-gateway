from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vyuu_gateway.db.base import Base


class TenantTier(StrEnum):
    SHARED = "shared"
    DEDICATED = "dedicated"


class OperatorRole(StrEnum):
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"


class UserAuthMethod(StrEnum):
    """How an end user authenticates to the gateway portal.

    `local` users have a `password_hash` (bcrypt). `microsoft` /
    `google` are pre-SCIM JIT-OIDC rows kept for back-compat. `scim`
    users are provisioned by an `IdpDirectory` (Entra ID or Google
    Workspace) and authenticate via the directory's chosen protocol
    (OIDC or SAML, picked at directory-connect time) — see
    `IdpDirectory.signin_protocol`.
    """

    LOCAL = "local"
    MICROSOFT = "microsoft"
    GOOGLE = "google"
    SCIM = "scim"


class VirtualServerVisibility(StrEnum):
    """Whether a vserver is implicitly visible to all tenant users
    (`public`) or requires an explicit grant per user / group (`private`).
    Default for new vservers is `private`."""

    PUBLIC = "public"
    PRIVATE = "private"


class GrantPrincipalKind(StrEnum):
    """A virtual_server_grant targets a single user or a whole group."""

    USER = "user"
    GROUP = "group"


class GrantVia(StrEnum):
    """JIT-1 · how a grant came to exist.

    `operator`     — a human operator issued it (the pre-JIT default, and
                     still the only source of standing access).
    `jit_auto`     — self-service JIT on an auto-approve vserver. No
                     operator decided this, which is exactly why
                     `granted_by` is NULL on these rows.
    `jit_approved` — a JIT request an operator approved; `granted_by` is
                     that operator.

    An auditor reading a grant needs "who decided" and "on what basis"
    to be unambiguous. Provenance lives here rather than being inferred
    from `expires_at IS NOT NULL`, because an operator can legitimately
    issue a time-boxed grant by hand without that being JIT.
    """

    OPERATOR = "operator"
    JIT_AUTO = "jit_auto"
    JIT_APPROVED = "jit_approved"


class AccessRequestStatus(StrEnum):
    """Lifecycle of an end-user access request.

    `pending`   — submitted by the user, not yet decided.
    `approved`  — admin approved; a `virtual_server_grants` row was
                  created (`created_grant_id` points at it).
    `declined`  — admin declined (optional `decision_note`).
    `withdrawn` — user cancelled their own pending request.
    """

    PENDING = "pending"
    APPROVED = "approved"
    DECLINED = "declined"
    WITHDRAWN = "withdrawn"


class McpServerSourceType(StrEnum):
    NPM = "npm"
    PYPI = "pypi"
    HTTP = "http"
    STDIO = "stdio"
    # Absolute-path executable pre-installed on the gateway host.
    # Distinct from STDIO (which is for curated relative names like
    # `python3`, `node`, `uvx`). BINARY means `/opt/vendor/foo-mcp`.
    BINARY = "binary"


class McpTransport(StrEnum):
    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable_http"


class McpServerHealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"
    UNKNOWN = "unknown"


class McpCapabilityKind(StrEnum):
    TOOL = "tool"
    RESOURCE = "resource"
    PROMPT = "prompt"


class RiskCategory(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    NETWORK = "network"
    CREDENTIAL_ACCESS = "credential_access"
    DATA_EXPORT = "data_export"
    ADMIN = "admin"
    UNKNOWN = "unknown"


def enum_values(enum_type: type[StrEnum]) -> list[str]:
    return [member.value for member in enum_type]


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint(
            f"tier IN {tuple(enum_values(TenantTier))}",
            name="tenants_tier_check",
        ),
        # A legal DNS label. Enforced here as well as in the app because
        # the DB is the one place every writer passes through, and a slug
        # containing a dot would silently extend the subdomain.
        CheckConstraint(
            "slug IS NULL OR slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'",
            name="tenants_slug_format_check",
        ),
        Index("tenants_slug_uq", "slug", unique=True),
    )

    id: Mapped[UUID] = mapped_column(postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    # IDP-3 · subdomain label, e.g. `acme` in `acme.gateway.example.com`.
    # NULL until a tenant opts in; unique among non-NULLs. A routing hint
    # only — see `api/tenant_routing.py` for why it must never become an
    # authorization input.
    slug: Mapped[str | None] = mapped_column(Text)
    # RISK-1 · which LLM classifies this tenant's MCP servers. Vendor is
    # stored alongside the id because an id newer than our registry
    # cannot have its wire format inferred from the string.
    risk_model_id: Mapped[str | None] = mapped_column(Text)
    risk_model_vendor: Mapped[str | None] = mapped_column(Text)
    # A SecretStore ref, never the key itself.
    risk_model_api_key_ref: Mapped[str | None] = mapped_column(Text)
    risk_model_base_url: Mapped[str | None] = mapped_column(Text)
    tier: Mapped[TenantTier] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    operators: Mapped[list["Operator"]] = relationship(
        back_populates="tenant",
        cascade="all, delete",
    )
    mcp_servers: Mapped[list["McpServer"]] = relationship(
        back_populates="tenant",
        cascade="all, delete",
    )
    mcp_capabilities: Mapped[list["McpCapability"]] = relationship(
        back_populates="tenant",
        cascade="all, delete",
    )
    virtual_servers: Mapped[list["VirtualServer"]] = relationship(
        back_populates="tenant",
        cascade="all, delete",
    )
    virtual_server_tools: Mapped[list["VirtualServerTool"]] = relationship(
        back_populates="tenant",
        cascade="all, delete",
    )


class Operator(Base):
    __tablename__ = "operators"
    __table_args__ = (
        CheckConstraint(
            f"role IN {tuple(enum_values(OperatorRole))}",
            name="operators_role_check",
        ),
        Index("operators_tenant_id_idx", "tenant_id"),
        Index("operators_tenant_email_idx", "tenant_id", "email", unique=True),
    )

    id: Mapped[UUID] = mapped_column(postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    email: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[OperatorRole] = mapped_column(Text, nullable=False)
    # bcrypt — null for legacy rows (lab seeded without password).
    # `OperatorPasswordAuthProvider` rejects login when null with a
    # generic 401 (anti-enumeration) so the absence of a password is
    # not visible to an attacker.
    password_hash: Mapped[str | None] = mapped_column(Text)
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    tenant: Mapped[Tenant] = relationship(back_populates="operators")
    registered_servers: Mapped[list["McpServer"]] = relationship(back_populates="registrar")
    created_virtual_servers: Mapped[list["VirtualServer"]] = relationship(back_populates="creator")


class McpServer(Base):
    __tablename__ = "mcp_servers"
    __table_args__ = (
        CheckConstraint(
            f"source_type IN {tuple(enum_values(McpServerSourceType))}",
            name="mcp_servers_source_type_check",
        ),
        CheckConstraint(
            f"transport IN {tuple(enum_values(McpTransport))}",
            name="mcp_servers_transport_check",
        ),
        CheckConstraint(
            f"health_status IN {tuple(enum_values(McpServerHealthStatus))}",
            name="mcp_servers_health_status_check",
        ),
        UniqueConstraint("tenant_id", "display_name", name="mcp_servers_tenant_name_uq"),
        Index("mcp_servers_tenant_id_idx", "tenant_id"),
        CheckConstraint(
            "sync_cadence_minutes IS NULL OR sync_cadence_minutes >= 0",
            name="mcp_servers_sync_cadence_nonneg",
        ),
    )

    id: Mapped[UUID] = mapped_column(postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[McpServerSourceType] = mapped_column(Text, nullable=False)
    source_location: Mapped[str] = mapped_column(Text, nullable=False)
    transport: Mapped[McpTransport] = mapped_column(Text, nullable=False)
    env_vars_ref: Mapped[str | None] = mapped_column(Text)
    args: Mapped[list[str]] = mapped_column(postgresql.ARRAY(Text), nullable=False, default=list)
    # `{header_name: secret_ref}` — applied to every outbound request when
    # transport is streamable_http. Refs resolve via the configured
    # `SecretStore`; raw credentials are never persisted in this table.
    auth_headers: Mapped[dict[str, str]] = mapped_column(
        postgresql.JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    # `{env_var_name: secret_ref}` — injected into the spawned subprocess's
    # environment when transport is stdio (npm / pypi / raw stdio). Same
    # ref-resolution model as `auth_headers`.
    auth_env: Mapped[dict[str, str]] = mapped_column(
        postgresql.JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    # `{inbound_header_name: upstream_header_name}` — user-tier auth.
    # The end user's MCP client supplies the credential on each request;
    # the gateway forwards it to the upstream under the configured name.
    # The gateway never persists the credential (no SecretStore involved);
    # each user brings their own. HTTP-only.
    auth_passthrough: Mapped[dict[str, str]] = mapped_column(
        postgresql.JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    # OAuth 2.0 client-credentials configuration (RFC 6749). When set,
    # the gateway brokers the M2M token exchange on each upstream
    # connection and rides the access token as `Authorization: Bearer`.
    # Shape: {token_url, client_id_ref, client_secret_ref, scope?,
    # audience?}. Refs resolve through the SecretStore. HTTP-only.
    auth_oauth: Mapped[dict[str, str] | None] = mapped_column(
        postgresql.JSONB,
        nullable=True,
    )
    # OAuth 2.0 authorization-code (phase 4 / A1) — per-user delegated
    # tokens. The gateway redirects users through an IdP consent screen
    # and stores their access + refresh tokens per-(tenant, user, server)
    # in `oauth_user_tokens`. On every upstream call the gateway looks
    # up the calling user's token and rides it as `Authorization: Bearer`.
    # Shape: {auth_url, token_url, client_id_ref, client_secret_ref,
    # scopes: [], redirect_uri}. HTTPS-only; cannot coexist with
    # `auth_oauth` (different auth modes per server).
    #
    # CAREFUL when filtering this (or any nullable JSONB column) in SQL:
    # SQLAlchemy's `none_as_null` defaults to False, so assigning Python
    # `None` stores the JSON value `null`, NOT SQL NULL — and
    # `'null'::jsonb IS NOT NULL` is TRUE. A `.is_not(None)` filter here
    # therefore matches every "no authcode configured" row. It did: the
    # end-user portal told users to connect an OAuth account for nine
    # servers that had none. Filter on the shape you want instead —
    # `func.jsonb_typeof(col) == "object"`. Reading the attribute in
    # Python is unaffected; JSON null deserialises to `None`.
    auth_authcode: Mapped[dict[str, Any] | None] = mapped_column(
        postgresql.JSONB,
        nullable=True,
    )
    # OAuth 2.0 JWT-bearer assertion grant (RFC 7523 — A2 / phase 5).
    # The gateway signs a short-lived JWT with a configured private key
    # and exchanges it at `token_url` for a bearer token. Used by
    # Workspace SAs (Drive, Calendar), IAM Roles Anywhere, and vendor
    # APIs that prefer asymmetric service identities. HTTP-only;
    # mutually exclusive with `auth_oauth` and `auth_authcode`.
    auth_jwt_bearer: Mapped[dict[str, Any] | None] = mapped_column(
        postgresql.JSONB,
        nullable=True,
    )
    # mTLS upstream auth (M-A1.5). When both refs are set, the gateway
    # resolves them to PEM-encoded blobs at provider-build time and
    # configures httpx with a client cert chain. The gateway never
    # logs / persists the resolved bytes; only the refs live here.
    # HTTP-only; cert + key must be set together (schema enforces).
    mtls_cert_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    mtls_key_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    registered_by: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("operators.id"),
        nullable=False,
    )
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    health_status: Mapped[McpServerHealthStatus] = mapped_column(
        Text,
        nullable=False,
        default=McpServerHealthStatus.UNKNOWN,
        server_default=McpServerHealthStatus.UNKNOWN.value,
    )
    last_health_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_health_error: Mapped[str | None] = mapped_column(Text)
    last_capabilities_pulled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Per-server cadence override for capability sync. NULL = use the
    # global default (`Settings.capability_sync_interval_seconds`).
    # 0 = manual only — scheduler skips this server. Concrete positive
    # values cap the scheduler's per-server frequency.
    sync_cadence_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Most recent `CapabilityDrift` (added / removed / changed lists)
    # serialised to JSON. Updated on each sync run; lets the operator
    # console show a diff on the server card without re-syncing.
    last_sync_drift: Mapped[dict[str, Any] | None] = mapped_column(
        postgresql.JSONB,
        nullable=True,
    )

    tenant: Mapped[Tenant] = relationship(back_populates="mcp_servers")
    registrar: Mapped[Operator] = relationship(back_populates="registered_servers")
    capabilities: Mapped[list["McpCapability"]] = relationship(
        back_populates="server",
        cascade="all, delete-orphan",
    )
    virtual_server_tools: Mapped[list["VirtualServerTool"]] = relationship(back_populates="server")


class McpCapability(Base):
    __tablename__ = "mcp_capabilities"
    __table_args__ = (
        CheckConstraint(
            f"kind IN {tuple(enum_values(McpCapabilityKind))}",
            name="mcp_capabilities_kind_check",
        ),
        CheckConstraint(
            f"risk_category IN {tuple(enum_values(RiskCategory))}",
            name="mcp_capabilities_risk_category_check",
        ),
        Index("mcp_capabilities_server_kind_idx", "server_id", "kind"),
        Index("mcp_capabilities_tenant_server_kind_idx", "tenant_id", "server_id", "kind"),
    )

    id: Mapped[UUID] = mapped_column(postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    server_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("mcp_servers.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[McpCapabilityKind] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    schema_json: Mapped[dict[str, Any]] = mapped_column(postgresql.JSONB, nullable=False)
    risk_category: Mapped[RiskCategory] = mapped_column(
        Text,
        nullable=False,
        default=RiskCategory.UNKNOWN,
        server_default=RiskCategory.UNKNOWN.value,
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    deprecated: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    tenant: Mapped[Tenant] = relationship(back_populates="mcp_capabilities")
    server: Mapped[McpServer] = relationship(back_populates="capabilities")


class VirtualServer(Base):
    __tablename__ = "virtual_servers"
    __table_args__ = (
        CheckConstraint(
            "visibility IN ('public', 'private')",
            name="virtual_servers_visibility_check",
        ),
        UniqueConstraint("tenant_id", "name", name="virtual_servers_tenant_name_uq"),
        Index("virtual_servers_tenant_id_idx", "tenant_id"),
        # JIT-1. Upper bound is 7 days: past that it is standing access
        # wearing a JIT label, which defeats the point of the feature.
        CheckConstraint(
            "jit_max_duration_seconds > 0 AND jit_max_duration_seconds <= 604800",
            name="virtual_servers_jit_max_duration_check",
        ),
    )

    id: Mapped[UUID] = mapped_column(postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    policy_id: Mapped[UUID | None] = mapped_column(postgresql.UUID(as_uuid=True))
    rename_map: Mapped[dict[str, str]] = mapped_column(
        postgresql.JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    # EMA-1 P3 · `exposed_tool_name -> required OAuth scope`. When a tool
    # appears here, a caller must present a token bearing that scope
    # (today only EMA/ID-JAG principals carry scopes). AND-combined with
    # visibility + grants + policy — it narrows, never widens. Empty map
    # (the default) means no tool on this vserver is scope-gated.
    required_scopes: Mapped[dict[str, str]] = mapped_column(
        postgresql.JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    # Default `private` — opt-in to public per user direction (Q1).
    visibility: Mapped[VirtualServerVisibility] = mapped_column(
        Text,
        nullable=False,
        default=VirtualServerVisibility.PRIVATE,
        server_default=VirtualServerVisibility.PRIVATE.value,
    )
    # --- JIT-1 · just-in-time access policy ---------------------------
    # Only meaningful on `private` vservers: a public one needs no grant,
    # so there is nothing to elevate into. Disabled by default, so every
    # existing vserver behaves exactly as it did before JIT landed.
    jit_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    # Ceiling on any single elevation. A request for more is rejected
    # rather than silently clamped — a user who asked for 8h and got 4h
    # without being told will plan around access they do not have.
    jit_max_duration_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=4 * 3600, server_default=text("14400")
    )
    # Trades the human review step for speed. Still time-boxed, still
    # audited, still justification-gated — but nobody is asked. Off by
    # default: which vservers are safe to self-serve is a real decision.
    jit_auto_approve: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    # On by default. A JIT grant with no stated reason is worse for the
    # auditor than a standing grant — it also lacks the deliberation a
    # standing grant implies.
    jit_require_justification: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    # JIT-2 · `exposed_tool_name -> max elevation seconds`. Symmetric with
    # `rename_map` / `required_scopes` on this same row, and deliberately
    # INDEPENDENT of `jit_enabled`: the primary use case is standing
    # access to the bundle with one dangerous tool gated behind an
    # elevation, on a vserver whose whole-bundle JIT is off. Empty (the
    # default) means no tool here is elevation-gated.
    jit_tools: Mapped[dict[str, int]] = mapped_column(
        postgresql.JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    created_by: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("operators.id"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    tenant: Mapped[Tenant] = relationship(back_populates="virtual_servers")
    creator: Mapped[Operator] = relationship(back_populates="created_virtual_servers")
    tools: Mapped[list["VirtualServerTool"]] = relationship(
        back_populates="virtual_server",
        cascade="all, delete-orphan",
    )
    grants: Mapped[list["VirtualServerGrant"]] = relationship(
        back_populates="virtual_server",
        cascade="all, delete-orphan",
    )


class VirtualServerTool(Base):
    __tablename__ = "virtual_server_tools"
    __table_args__ = (
        Index("virtual_server_tools_tenant_vserver_idx", "tenant_id", "vserver_id"),
    )

    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    vserver_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("virtual_servers.id", ondelete="CASCADE"),
        primary_key=True,
    )
    server_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("mcp_servers.id", ondelete="CASCADE"),
        primary_key=True,
    )
    tool_name: Mapped[str] = mapped_column(Text, primary_key=True)

    tenant: Mapped[Tenant] = relationship(back_populates="virtual_server_tools")
    virtual_server: Mapped[VirtualServer] = relationship(back_populates="tools")
    server: Mapped[McpServer] = relationship(back_populates="virtual_server_tools")


# --- A3-α: end-user identity model (users, groups, grants, API keys) -----


class User(Base):
    """End user — distinct from `Operator`. A human can have rows in BOTH
    tables on the same tenant; that's the "I'm an admin AND I use MCPs"
    case (Q5). No constraint forbids it.

    SCIM-provisioned users carry `idp_directory_id` + `external_id`
    pointing at the directory and the IdP's stable identifier
    (Entra `objectId`, Workspace `id`). Local + OIDC-JIT users leave
    those NULL. Soft-deleted SCIM users are picked up by the
    deactivation sweeper after a 7-day grace period.
    """

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            f"auth_method IN {tuple(enum_values(UserAuthMethod))}",
            name="users_auth_method_check",
        ),
        UniqueConstraint("tenant_id", "email", name="users_tenant_email_uq"),
        Index("users_tenant_id_idx", "tenant_id"),
        # Partial unique — local + JIT-OIDC rows have NULL external_id
        # and must not collide with each other.
        Index(
            "users_directory_external_id_uq",
            "tenant_id",
            "idp_directory_id",
            "external_id",
            unique=True,
            postgresql_where="external_id IS NOT NULL",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    email: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str | None] = mapped_column(Text)
    auth_method: Mapped[UserAuthMethod] = mapped_column(Text, nullable=False)
    # bcrypt for `local`. Null for OIDC-authed users.
    password_hash: Mapped[str | None] = mapped_column(Text)
    # OIDC `sub` claim. Null for `local`.
    external_subject: Mapped[str | None] = mapped_column(Text)
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # SCIM linkage — populated when the row was provisioned by an
    # IdpDirectory. NULL on local + OIDC-JIT rows.
    idp_directory_id: Mapped[UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("idp_directories.id", ondelete="SET NULL"),
        nullable=True,
    )
    # The IdP's stable identifier for this user (Entra `objectId`,
    # Workspace `id`). Stable across email changes — that's what we
    # match on during sign-in.
    external_id: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Set by the SCIM deactivation handler. The hard-delete sweeper
    # picks rows where `now() - soft_deleted_at > 7 days` and removes
    # them; admin_audit_log records the removal.
    soft_deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Group(Base):
    """Logical grouping of users. Admin-managed for local groups; SCIM
    pushes Entra / Workspace groups directly. Flat membership only —
    nested AD groups are deliberately not expanded recursively per the
    IDP-1 decision log (keeps "who can call X" queries fast)."""

    __tablename__ = "groups"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="groups_tenant_name_uq"),
        Index("groups_tenant_id_idx", "tenant_id"),
        Index(
            "groups_directory_external_id_uq",
            "tenant_id",
            "idp_directory_id",
            "external_id",
            unique=True,
            postgresql_where="external_id IS NOT NULL",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("operators.id"),
        nullable=False,
    )
    # SCIM linkage — same shape as User.
    idp_directory_id: Mapped[UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("idp_directories.id", ondelete="SET NULL"),
        nullable=True,
    )
    external_id: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class IdpDirectoryKind(StrEnum):
    """Which directory product is on the other end of the SCIM /
    sign-in connection. Drives provider-specific quirks (Entra PATCH
    `Operations[]` vs. Workspace `members[]`)."""

    ENTRA = "entra"
    GOOGLE_WORKSPACE = "google_workspace"


class IdpSigninProtocol(StrEnum):
    """The protocol an IdP-provisioned user authenticates with. Both
    Entra and Workspace support OIDC and SAML; the admin picks per
    directory at connect time."""

    OIDC = "oidc"
    SAML = "saml"


class IdpDirectory(Base):
    """A connected Entra ID or Google Workspace directory.

    Configured by an admin via the operator console. Drives:

    1. **SCIM provisioning** — the IdP pushes user / group lifecycle
       events at `/scim/v2/{directory_id}/Users` etc., authenticated
       via the bearer token whose hash we store here.
    2. **Sign-in** — users provisioned by this directory authenticate
       via `signin_protocol` (OIDC or SAML). The OIDC discovery URL
       or SAML SSO URL is stored inline; client_secrets / SAML signing
       keys live in the existing `secret_store` (Vault / Postgres) via
       `*_ref` pointers.

    Tenant isolation: RLS-enforced. One directory of a given kind per
    tenant — admins can connect both Entra and Workspace, but not
    two Entra tenants under the same Vyuu tenant (sniff a real use
    case before relaxing this).
    """

    __tablename__ = "idp_directories"
    __table_args__ = (
        CheckConstraint(
            f"kind IN {tuple(enum_values(IdpDirectoryKind))}",
            name="idp_directories_kind_check",
        ),
        CheckConstraint(
            f"signin_protocol IN {tuple(enum_values(IdpSigninProtocol))}",
            name="idp_directories_signin_protocol_check",
        ),
        UniqueConstraint(
            "tenant_id", "kind", name="idp_directories_tenant_kind_uq"
        ),
        Index("idp_directories_tenant_idx", "tenant_id"),
    )

    id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[IdpDirectoryKind] = mapped_column(Text, nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    signin_protocol: Mapped[IdpSigninProtocol] = mapped_column(Text, nullable=False)
    # argon2id-hashed SCIM bearer token. The plaintext is shown once
    # at connect-time so the admin can paste it into Entra / Workspace.
    scim_token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    # OIDC config (used when signin_protocol = 'oidc'). Public fields
    # are inline; client_secret lives behind the *_ref via secret_store.
    oidc_issuer: Mapped[str | None] = mapped_column(Text)
    oidc_client_id: Mapped[str | None] = mapped_column(Text)
    oidc_client_secret_ref: Mapped[str | None] = mapped_column(Text)
    # SAML config (used when signin_protocol = 'saml').
    saml_entity_id: Mapped[str | None] = mapped_column(Text)
    saml_sso_url: Mapped[str | None] = mapped_column(Text)
    # PEM-encoded IdP signing certificate. Public; safe inline.
    saml_idp_certificate: Mapped[str | None] = mapped_column(Text)
    # Provider-specific extras we don't promote to first-class columns
    # (Workspace customer_id, Entra app object_id, etc.).
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        postgresql.JSONB(astext_type=Text()),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    # --- EMA-1 · ID-JAG trust config (MCP Enterprise-Managed Auth) -----
    # Per-directory opt-in: connecting a directory for SCIM/SSO does NOT
    # silently start accepting ID-JAGs from its issuer. Orthogonal to
    # `signin_protocol` — a SAML-for-humans directory can be EMA-enabled
    # for agent traffic.
    ema_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false"), default=False
    )
    # Audience the IdP must stamp on ID-JAGs = our per-tenant resource-
    # authorization-server issuer id (`{public_base_url}/v/{tenant_id}`).
    ema_audience: Mapped[str | None] = mapped_column(Text)
    # Optional explicit JWKS endpoint; NULL = discover from
    # `oidc_issuer`'s /.well-known/openid-configuration.
    ema_jwks_uri: Mapped[str | None] = mapped_column(Text)
    # Allowlist of MCP client_ids permitted to present ID-JAGs. Empty =
    # accept any client the IdP's own policy already vetted.
    ema_allowed_client_ids: Mapped[list[str]] = mapped_column(
        postgresql.JSONB(astext_type=Text()),
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # --- IDP-2 · Google Workspace polling ------------------------------
    # Workspace custom SAML apps cannot SCIM-push, so a Workspace tenant
    # otherwise runs on JIT-create with MANUAL deprovisioning — the exact
    # property directory integration is adopted to avoid. When enabled,
    # the gateway polls the Admin SDK and applies changes through the
    # same service functions the SCIM endpoint uses.
    workspace_polling_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    # SecretStore REFERENCE, never the JSON itself: a service account with
    # domain-wide delegation can read every user in the customer's
    # directory, so it belongs where the deployment keeps secrets — not in
    # a column that appears in every backup.
    workspace_service_account_ref: Mapped[str | None] = mapped_column(Text)
    # Google customer id, or the `my_customer` alias. Required by
    # `users.list`; without it a reseller service account would enumerate
    # other customers' directories.
    workspace_customer_id: Mapped[str | None] = mapped_column(Text)
    # The admin whose authority domain-wide delegation impersonates.
    workspace_admin_subject: Mapped[str | None] = mapped_column(Text)
    workspace_last_polled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )


class EmaConsumedJti(Base):
    """EMA-1 · replay cache for redeemed ID-JAG grant tokens.

    The ID-JAG is a single-use authorization grant (~300 s lifetime,
    minted by the enterprise IdP). The token endpoint records each
    `jti` on first redemption; a second presentation within the
    grant's own `exp` is rejected as replay. PK `(tenant_id, jti)`
    because two tenants' IdPs may legitimately mint the same jti
    string. The hourly sweeper prunes rows once `expires_at` passes —
    the table holds at most a few minutes of grant traffic.
    """

    __tablename__ = "ema_consumed_jti"
    __table_args__ = (
        Index("ema_consumed_jti_expires_idx", "expires_at"),
    )

    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        primary_key=True,
    )
    jti: Mapped[str] = mapped_column(Text, primary_key=True)
    consumed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class AdminAuditActorKind(StrEnum):
    """Who triggered an admin-audit row."""

    OPERATOR = "operator"   # human via /operator
    SYSTEM = "system"       # cron / sweeper / startup migration
    SCIM = "scim"           # IdP-driven (provisioning / deprovisioning)


class AdminAuditLog(Base):
    """Server-side persistent log of admin actions.

    Distinct from the in-memory `RecentAuditEmitter` ring buffer that
    captures inbound MCP tool calls. This table is what compliance
    auditors read: "who did what to the platform, when, against
    which target".

    Action verbs are dotted free-text (`user.disable`, `vserver.delete`,
    `grant.revoke`, `idp.connect`, `scim.deactivate_user`,
    `scim.hard_delete_user`) so new admin endpoints don't need a
    migration to log. The structured `detail` JSONB carries the
    before/after diff or any other context that helps the auditor
    reconstruct the action.
    """

    __tablename__ = "admin_audit_log"
    __table_args__ = (
        CheckConstraint(
            f"actor_kind IN {tuple(enum_values(AdminAuditActorKind))}",
            name="admin_audit_log_actor_kind_check",
        ),
        Index(
            "admin_audit_log_tenant_occurred_idx",
            "tenant_id",
            "occurred_at",
        ),
        Index(
            "admin_audit_log_tenant_action_idx",
            "tenant_id",
            "action",
        ),
        Index(
            "admin_audit_log_target_idx",
            "tenant_id",
            "target_kind",
            "target_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    actor_operator_id: Mapped[UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("operators.id", ondelete="SET NULL"),
        nullable=True,
    )
    actor_kind: Mapped[AdminAuditActorKind] = mapped_column(Text, nullable=False)
    actor_display: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target_kind: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True), nullable=True
    )
    target_display: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict[str, Any]] = mapped_column(
        postgresql.JSONB(astext_type=Text()),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class ToolCallEvent(Base):
    """Durable persistent log of inbound MCP tool-call audit events.

    Source of truth for the operator-console Events / NHI map / Identities
    panels. Survives gateway restarts, server upgrades, schema migrations.
    The in-memory `RecentAuditEmitter` ring buffer is now strictly a
    read-through cache hydrated from this table on startup.

    Distinct from `AdminAuditLog` (which records *admin actions on the
    platform*). This table records *MCP tool-call traffic flowing through
    the gateway*. Both are durable; both are tenant-scoped under RLS.

    `event_id` is the natural primary key — generated by the audit
    pipeline before the row reaches Postgres so the same event-id is
    visible in the in-memory buffer and any downstream Kafka/NATS
    consumer. FKs to `vservers` / `mcp_servers` use `ON DELETE SET NULL`
    so deleting a vserver / upstream doesn't erase historical traffic
    against it — `vserver_name` is captured at write-time so the row
    stays human-readable after the FK target is gone.
    """

    __tablename__ = "tool_call_events"
    __table_args__ = (
        CheckConstraint(
            "event_type IN ('tool_call', 'access_attempt')",
            name="tool_call_events_event_type_check",
        ),
        CheckConstraint(
            "decision IN ('allow', 'deny', 'redact', 'rewrite')",
            name="tool_call_events_decision_check",
        ),
        CheckConstraint(
            "decision_mode IN ('monitor', 'enforce')",
            name="tool_call_events_decision_mode_check",
        ),
        CheckConstraint(
            "upstream_status IN ('ok', 'error', 'timeout', 'not_called')",
            name="tool_call_events_upstream_status_check",
        ),
        # Primary feed: "show me this tenant's recent events".
        Index(
            "tool_call_events_tenant_occurred_idx",
            "tenant_id",
            "occurred_at",
        ),
        # vserver drill-in.
        Index(
            "tool_call_events_tenant_vserver_idx",
            "tenant_id",
            "vserver_id",
            "occurred_at",
        ),
        # Identity timeline.
        Index(
            "tool_call_events_tenant_principal_idx",
            "tenant_id",
            "principal_id",
            "occurred_at",
        ),
        # Event-type filter (`access_attempt` vs `tool_call`).
        Index(
            "tool_call_events_tenant_event_type_idx",
            "tenant_id",
            "event_type",
            "occurred_at",
        ),
    )

    event_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    gateway_instance_id: Mapped[str] = mapped_column(Text, nullable=False)
    event_type: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("'tool_call'")
    )
    # `vserver_id` / `upstream_server_id` use SET NULL on delete so the
    # event row outlives its referent — forensic value > FK strictness.
    vserver_id: Mapped[UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("virtual_servers.id", ondelete="SET NULL"),
        nullable=True,
    )
    vserver_name: Mapped[str | None] = mapped_column(Text)
    upstream_server_id: Mapped[UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("mcp_servers.id", ondelete="SET NULL"),
        nullable=True,
    )
    tool: Mapped[str] = mapped_column(Text, nullable=False)
    principal_type: Mapped[str] = mapped_column(Text, nullable=False)
    principal_id: Mapped[str] = mapped_column(Text, nullable=False)
    principal_display: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("''")
    )
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    decision_mode: Mapped[str] = mapped_column(Text, nullable=False)
    policy_id: Mapped[UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True), nullable=True
    )
    policy_rule_id: Mapped[str | None] = mapped_column(Text)
    upstream_status: Mapped[str] = mapped_column(Text, nullable=False)
    latency_ms_total: Mapped[float | None] = mapped_column()
    latency_ms_upstream: Mapped[float | None] = mapped_column()
    response_size_bytes: Mapped[int | None] = mapped_column(Integer)
    auth_failure_reason: Mapped[str | None] = mapped_column(Text)
    args_summary: Mapped[dict[str, Any]] = mapped_column(
        postgresql.JSONB(astext_type=Text()),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    auth_modes: Mapped[dict[str, Any]] = mapped_column(
        postgresql.JSONB(astext_type=Text()),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    client_metadata: Mapped[dict[str, Any]] = mapped_column(
        postgresql.JSONB(astext_type=Text()),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    raw_args: Mapped[dict[str, Any] | None] = mapped_column(
        postgresql.JSONB(astext_type=Text()), nullable=True
    )
    raw_response: Mapped[dict[str, Any] | None] = mapped_column(
        postgresql.JSONB(astext_type=Text()), nullable=True
    )
    raw_args_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    raw_response_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )


class UserGroupMembership(Base):
    """Many-to-many user ↔ group join. Composite primary key."""

    __tablename__ = "user_group_memberships"
    __table_args__ = (
        Index("user_group_memberships_group_idx", "group_id"),
    )

    user_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    group_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("groups.id", ondelete="CASCADE"),
        primary_key=True,
    )
    added_by: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("operators.id"),
        nullable=False,
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class VirtualServerGrant(Base):
    """Explicit ACL row for a `private` virtual server. Targets either a
    single user or a whole group. A grant lets the principal connect; no
    grant = 403 on inbound MCP calls. `revoked_at` soft-deletes."""

    __tablename__ = "virtual_server_grants"
    __table_args__ = (
        CheckConstraint(
            f"principal_kind IN {tuple(enum_values(GrantPrincipalKind))}",
            name="virtual_server_grants_kind_check",
        ),
        Index(
            "virtual_server_grants_lookup_idx",
            "vserver_id",
            "principal_kind",
            "principal_id",
        ),
        Index("virtual_server_grants_tenant_idx", "tenant_id"),
        CheckConstraint(
            f"granted_via IN {tuple(enum_values(GrantVia))}",
            name="virtual_server_grants_granted_via_check",
        ),
        # "Who is elevated right now?" — the operator's live question.
        # Partial: standing grants (expires_at IS NULL) are the majority
        # and never belong in this index.
        Index(
            "virtual_server_grants_active_expiring_idx",
            "tenant_id",
            "expires_at",
            postgresql_where=text("revoked_at IS NULL AND expires_at IS NOT NULL"),
        ),
    )

    id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    vserver_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("virtual_servers.id", ondelete="CASCADE"),
        nullable=False,
    )
    principal_kind: Mapped[GrantPrincipalKind] = mapped_column(Text, nullable=False)
    principal_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), nullable=False
    )
    # JIT-1: NULLABLE. An auto-approved JIT elevation has no operator
    # behind it, and attributing it to a sentinel operator would put a
    # human's name on a decision they did not make. `granted_via` carries
    # the provenance, so NULL here is never ambiguous.
    granted_by: Mapped[UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("operators.id"),
        nullable=True,
    )
    granted_via: Mapped[GrantVia] = mapped_column(
        Text,
        nullable=False,
        default=GrantVia.OPERATOR,
        server_default=GrantVia.OPERATOR.value,
    )
    # Captured at request time from the end user. NULL on operator-issued
    # grants and on JIT vservers that do not require one.
    justification: Mapped[str | None] = mapped_column(Text)
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    # NULL = standing access. Non-NULL = the grant stops being honoured
    # at this instant; `virtual_servers/access.py` enforces it on every
    # inbound request, so a lapse mid-session cuts off at the next call.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    virtual_server: Mapped[VirtualServer] = relationship(back_populates="grants")


class VirtualServerToolGrant(Base):
    """JIT-2 · a time-boxed elevation into ONE exposed tool.

    Deliberately a separate table from `virtual_server_grants` rather
    than a nullable `tool_name` on it. That table is read as "may this
    principal reach this vserver" by the inbound check, the catalog, the
    identity graph and the NHI map; adding a tool column would change the
    meaning of every existing row for every query that forgot to filter
    on it. Here the old question keeps its old answer.

    `expires_at` is NOT NULL: a permanent per-tool grant is an ordinary
    vserver grant with extra steps.

    `exposed_tool_name` is the post-rename name the caller actually asks
    for — not an FK to `virtual_server_tools`, which keys on the upstream
    name. Re-pointing a rename must not silently transfer an elevation to
    a different underlying tool.
    """

    __tablename__ = "virtual_server_tool_grants"
    __table_args__ = (
        CheckConstraint(
            f"principal_kind IN {tuple(enum_values(GrantPrincipalKind))}",
            name="virtual_server_tool_grants_kind_check",
        ),
        CheckConstraint(
            f"granted_via IN {tuple(enum_values(GrantVia))}",
            name="virtual_server_tool_grants_via_check",
        ),
        # Hot path: "does this principal hold a live elevation for this
        # tool?", run once per gated tool call.
        Index(
            "virtual_server_tool_grants_lookup_idx",
            "tenant_id",
            "vserver_id",
            "exposed_tool_name",
            "principal_id",
            postgresql_where=text("revoked_at IS NULL"),
        ),
        Index(
            "virtual_server_tool_grants_expiry_idx",
            "tenant_id",
            "expires_at",
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )

    id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    vserver_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("virtual_servers.id", ondelete="CASCADE"),
        nullable=False,
    )
    exposed_tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    principal_kind: Mapped[GrantPrincipalKind] = mapped_column(Text, nullable=False)
    principal_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), nullable=False
    )
    granted_by: Mapped[UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("operators.id"), nullable=True
    )
    granted_via: Mapped[GrantVia] = mapped_column(
        Text,
        nullable=False,
        default=GrantVia.OPERATOR,
        server_default=GrantVia.OPERATOR.value,
    )
    justification: Mapped[str | None] = mapped_column(Text)
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ApiKeyPrincipalKind(StrEnum):
    """Scope an API-key lifetime policy applies to."""

    TENANT = "tenant"
    GROUP = "group"
    USER = "user"


class ApiKeyPolicy(Base):
    """CRED-1 · the maximum lifetime of a user's API keys.

    `UserApiKey.expires_at` was always enforced and never set — both
    issuance paths defaulted it to NULL, so a key lived until somebody
    remembered to revoke it. This is what finally sets it.

    Resolution is user → group → tenant → unlimited. When a user is in
    several groups the **shortest** policy wins, never the longest:
    otherwise joining a group would extend your own credential lifetime,
    making group membership a privilege escalation. Group membership can
    only ever tighten.

    `principal_id` carries the tenant id on `tenant` rows, so one unique
    constraint covers all three scopes without a nullable key column.
    """

    __tablename__ = "api_key_policies"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "principal_kind", "principal_id",
            name="api_key_policies_scope_uq",
        ),
        Index("api_key_policies_tenant_idx", "tenant_id"),
    )

    id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    principal_kind: Mapped[ApiKeyPrincipalKind] = mapped_column(
        Text, nullable=False
    )
    principal_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), nullable=False
    )
    max_ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    # Why this exception exists. An unexplained 90-day carve-out for one
    # contractor is indistinguishable from a mistake at review time.
    note: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class McpServerRiskAssessment(Base):
    """RISK-1 · one classifier run over one MCP server's public surface.

    Rows accumulate rather than being overwritten: a capability sync that
    adds a `delete_*` tool should show up as risk MOVING, and movement
    cannot be seen against a value that was replaced in place.
    """

    __tablename__ = "mcp_server_risk_assessments"
    __table_args__ = (
        Index("mcp_server_risk_latest_idx", "tenant_id", "server_id", "assessed_at"),
    )

    id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False,
    )
    server_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("mcp_servers.id", ondelete="CASCADE"), nullable=False,
    )
    model_id: Mapped[str] = mapped_column(Text, nullable=False)
    model_vendor: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[str] = mapped_column(Text, nullable=False, default="low")
    findings: Mapped[list[Any]] = mapped_column(
        postgresql.JSONB, nullable=False, default=list
    )
    exposure: Mapped[float] = mapped_column(Float, nullable=False)
    severity_profile: Mapped[float] = mapped_column(Float, nullable=False)
    overall: Mapped[float] = mapped_column(Float, nullable=False)
    normalised: Mapped[float] = mapped_column(Float, nullable=False)
    band: Mapped[str] = mapped_column(Text, nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False)
    capability_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # What the score is actually based on. Carried per row so an old
    # assessment cannot be read under today's assumptions.
    evidence_basis: Mapped[str] = mapped_column(Text, nullable=False, default="")
    scoring_version: Mapped[str] = mapped_column(Text, nullable=False, default="1")
    # RISK-2 · hash of the capability surface this score was computed
    # against (see `risk.service.capability_fingerprint`). A score is a
    # claim about a specific set of tools, and capability sync changes
    # that set — without this the console renders an old number as
    # current posture. NULL on rows written before RISK-2: freshness is
    # unprovable there, never assumed, and the read path falls back to
    # comparing `capability_count`.
    capability_fingerprint: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    assessed_by: Mapped[UUID | None] = mapped_column(postgresql.UUID(as_uuid=True))
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class VirtualServerRiskAssessment(Base):
    """RISK-1 · what publishing a curated bundle took off the table.

    Derived arithmetic over the source servers' findings, NOT a second
    classification — see `risk/reduction.py` for why that distinction is
    the whole point. `source_assessment_ids` records what it was computed
    from, so a stale comparison is detectable rather than merely
    suspicious.
    """

    __tablename__ = "virtual_server_risk_assessments"
    __table_args__ = (
        Index(
            "virtual_server_risk_latest_idx",
            "tenant_id", "vserver_id", "computed_at",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False,
    )
    vserver_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("virtual_servers.id", ondelete="CASCADE"), nullable=False,
    )
    source_assessment_ids: Mapped[list[Any]] = mapped_column(
        postgresql.JSONB, nullable=False, default=list
    )
    inherent_normalised: Mapped[float] = mapped_column(Float, nullable=False)
    inherent_band: Mapped[str] = mapped_column(Text, nullable=False)
    published_normalised: Mapped[float] = mapped_column(Float, nullable=False)
    published_band: Mapped[str] = mapped_column(Text, nullable=False)
    points_reduced: Mapped[float] = mapped_column(Float, nullable=False)
    percent_reduced: Mapped[float] = mapped_column(Float, nullable=False)
    eliminated: Mapped[list[Any]] = mapped_column(
        postgresql.JSONB, nullable=False, default=list
    )
    retained: Mapped[list[Any]] = mapped_column(
        postgresql.JSONB, nullable=False, default=list
    )
    scoring_version: Mapped[str] = mapped_column(Text, nullable=False, default="1")
    # RISK-2 · hash of BOTH inputs to the comparison: the source
    # assessments it read, and the tool set this bundle published. The
    # reduction claim ("publishing these 6 of 190 tools removed X") is
    # false the moment either changes, and publishing more tools is a
    # routine edit that silently invalidated the number on screen.
    inputs_fingerprint: Mapped[str | None] = mapped_column(Text, nullable=True)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class TenantSiemTarget(Base):
    """SIEM-1 · where this tenant's security events are shipped.

    One row per tenant: a Splunk HEC endpoint, a secret-store REFERENCE
    to its token, and what to send. The token itself never lands here —
    this table is dumped, backed up and read by support, and an HEC
    token buys an attacker the ability to write forged events into the
    tenant's SIEM, which is worse than reading it.

    Runtime delivery state (queue depth, last error, counts) is
    deliberately not persisted: it is per gateway instance, like a
    circuit breaker, and the status endpoint reads it from the exporter.
    """

    __tablename__ = "tenant_siem_targets"
    __table_args__ = (
        Index("tenant_siem_targets_tenant_uq", "tenant_id", unique=True),
    )

    id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Origin only (`https://splunk.corp:8088`); the collector path is
    # appended at send time. See `siem.hec.normalise_hec_url`.
    hec_url: Mapped[str] = mapped_column(Text, nullable=False)
    # A SecretStore ref. Never the token.
    hec_token_ref: Mapped[str] = mapped_column(Text, nullable=False)
    index: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(
        Text, nullable=False, default="vyuu-mcp-gateway"
    )
    # Overrides the HEC `host` field; defaults to the gateway instance id.
    host_override: Mapped[str | None] = mapped_column(Text)
    verify_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # `SiemCategory` values. Empty means "nothing" — an explicit choice,
    # distinct from a missing row.
    categories: Mapped[list[str]] = mapped_column(
        postgresql.JSONB, nullable=False, default=list
    )
    # Raw tool args / responses ship only if policy captured them (H5)
    # AND this is on. Off by default: a SIEM is one more place a
    # customer's business data would live.
    include_raw_payloads: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    # Threshold for the `gateway_log` category. Logging level NAME.
    min_log_level: Mapped[str] = mapped_column(
        Text, nullable=False, default="WARNING"
    )
    batch_max_events: Mapped[int] = mapped_column(
        Integer, nullable=False, default=100
    )
    flush_interval_seconds: Mapped[float] = mapped_column(
        Float, nullable=False, default=2.0
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class UserApiKey(Base):
    """Per-user bearer credential for inbound MCP calls. The user's
    Claude Desktop / Cursor / agent presents this key on the
    `Authorization: Bearer ...` header. Stored hashed; the plaintext is
    shown to the user once at issuance and never persisted."""

    __tablename__ = "user_api_keys"
    __table_args__ = (
        UniqueConstraint("user_id", "label", name="user_api_keys_user_label_uq"),
        Index("user_api_keys_tenant_idx", "tenant_id"),
        Index("user_api_keys_user_idx", "user_id"),
    )

    id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    label: Mapped[str] = mapped_column(Text, nullable=False)
    # argon2id-hashed full secret. Constant-time verified at validation.
    key_hash: Mapped[str] = mapped_column(Text, nullable=False)
    # First 8 chars of the plaintext secret, kept verbatim for operator-UI
    # display + log correlation. Not a security risk on its own.
    key_prefix: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# --- A3-γ: access requests (end-user → admin approval workflow) ----------


class AccessRequest(Base):
    """An end-user request for access to a private vserver.

    Submitted by a `User`; decided by an `Operator`. Approval atomically
    creates a `VirtualServerGrant` row and writes its id to
    `created_grant_id`, so the user can be told which grant covers the
    request and so the lineage is auditable.
    """

    __tablename__ = "access_requests"
    __table_args__ = (
        CheckConstraint(
            f"status IN {tuple(enum_values(AccessRequestStatus))}",
            name="access_requests_status_check",
        ),
        Index("access_requests_tenant_status_idx", "tenant_id", "status"),
        Index("access_requests_user_idx", "user_id"),
        Index("access_requests_vserver_idx", "vserver_id"),
        # One pending request per (user, vserver). Other statuses don't
        # block — a declined user can re-request after the world changes.
        Index(
            "access_requests_one_pending_per_target",
            "user_id",
            "vserver_id",
            unique=True,
            postgresql_where=text("status = 'pending'"),
        ),
        CheckConstraint(
            "requested_duration_seconds IS NULL OR requested_duration_seconds > 0",
            name="access_requests_requested_duration_check",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    vserver_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("virtual_servers.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[AccessRequestStatus] = mapped_column(
        Text, nullable=False, default=AccessRequestStatus.PENDING, server_default="pending"
    )
    note: Mapped[str | None] = mapped_column(Text)
    # JIT-1. NULL = a request for standing access (the pre-JIT shape).
    # Non-NULL = the user asked for a time-boxed elevation of this long,
    # so the approval queue shows *how much* access is being asked for,
    # not merely that access is being asked for.
    requested_duration_seconds: Mapped[int | None] = mapped_column(Integer)
    # JIT-2. NULL = a request for the whole vserver. Non-NULL = a request
    # to elevate into one tool. One queue rather than two — same reasoning
    # as JIT-1's duration.
    exposed_tool_name: Mapped[str | None] = mapped_column(Text)
    decision_note: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("operators.id"),
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_grant_id: Mapped[UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("virtual_server_grants.id"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


# --- A1: OAuth phase 4 — per-user delegated tokens -----------------------


class McpServerDcrClient(Base):
    """Gateway-as-OAuth-client credentials issued via Dynamic Client
    Registration (RFC 7591) against an MCP server's authorization
    server.

    For OAuth-authcode upstreams that ship `dcr_enabled=True` (Notion,
    Linear, anything built with the official MCP SDK auth helpers),
    operators don't pre-create an OAuth app in the vendor dashboard.
    Instead the gateway discovers the AS metadata (RFC 9728 + 8414),
    POSTs to `registration_endpoint` (RFC 7591) on first use, persists
    the returned `client_id` (+ optional `client_secret`) to this
    table, and reuses them for every subsequent user OAuth flow on
    the same server.

    One row per `mcp_servers.id`. Tenant-scoped via `tenant_id` for
    RLS. Re-registration on `invalid_client` 401: replace the row
    (PK collision), don't insert a duplicate.

    Since MCP-2 P3 the table also caches the **CIMD** outcome, where
    there is no registration at all — see `auth_mechanism`.
    """

    __tablename__ = "mcp_server_dcr_clients"
    __table_args__ = (
        Index("mcp_server_dcr_clients_tenant_idx", "tenant_id"),
    )

    # PK is `server_id` (one DCR client per upstream MCP server).
    server_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("mcp_servers.id", ondelete="CASCADE"),
        primary_key=True,
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    client_id: Mapped[str] = mapped_column(Text, nullable=False)
    # Confidential clients (Notion) get a client_secret. Public
    # clients (some PKCE-only AS) may omit it; we accept either.
    client_secret: Mapped[str | None] = mapped_column(Text)
    # Authorization server endpoints discovered alongside registration.
    # Cached on the row so the token-fetch hot path doesn't re-hit
    # `/.well-known/...` per call.
    authorization_endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    token_endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    # Nullable since MCP-2 P3: a CIMD row has no registration step, and
    # a placeholder here would read as a fact about where we registered.
    registration_endpoint: Mapped[str | None] = mapped_column(Text)
    # Which mechanism produced this row — `dcr`, `cimd`, or
    # `cimd_rejected`. The last is a tombstone, not a working row: the
    # AS advertised CIMD and then refused our client_id, so the next
    # Connect must take the DCR branch instead of re-presenting a URL
    # already refused. Deleting instead of marking would re-probe, get
    # the same advertisement, and loop forever.
    auth_mechanism: Mapped[str] = mapped_column(
        Text, nullable=False, default="dcr", server_default="dcr"
    )
    # Full RFC 7591 `client_information_response` body for diagnostics
    # + future re-registration via `registration_client_uri`.
    registration_response: Mapped[dict[str, Any]] = mapped_column(
        postgresql.JSONB, nullable=False, default=dict
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class OAuthUserToken(Base):
    """Per-(tenant, user, server) OAuth tokens from the authorization-code
    grant. Populated by the `/oauth-authcode/{server}/callback` endpoint
    after the IdP redirects the browser back. Read on every upstream call
    that targets an `auth_authcode`-using server.

    Tokens are stored as plaintext (DB at-rest encryption is the
    operator's responsibility for v1). KMS envelope encryption is sized
    in the backlog as a follow-on. Refresh-token rotation is supported:
    the auth server may return a new `refresh_token` on each refresh,
    in which case we update the row.
    """

    __tablename__ = "oauth_user_tokens"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "user_id",
            "server_id",
            name="oauth_user_tokens_unique_per_principal_server",
        ),
        Index("oauth_user_tokens_user_idx", "user_id"),
        Index("oauth_user_tokens_tenant_idx", "tenant_id"),
    )

    id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    server_id: Mapped[UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("mcp_servers.id", ondelete="CASCADE"),
        nullable=False,
    )
    access_token: Mapped[str] = mapped_column(Text, nullable=False)
    refresh_token: Mapped[str | None] = mapped_column(Text)
    token_type: Mapped[str] = mapped_column(
        Text, nullable=False, default="Bearer", server_default="Bearer"
    )
    scope: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    last_refreshed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
