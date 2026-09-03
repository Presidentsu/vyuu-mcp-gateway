"""End-user portal endpoints (A3-δ).

Mounted under `/api/v1/portal/{tenant_id}/...` next to the access-request
endpoints (which were the first portal-side surface to land, in γ).

Auth: portal session JWT (β). Cross-tenant defense: every endpoint
gates `session.tenant_id == path.tenant_id` — a leaked token replayed
against a different tenant's URL is rejected at the route layer.

Endpoints:

- `GET    /me`                    — whoami (decoded session)
- `GET    /catalog`               — vserver catalog with `has_access` flags
- `GET    /api-keys`              — list my keys
- `POST   /api-keys`              — issue a new key (plaintext returned ONCE)
- `DELETE /api-keys/{id}`         — revoke my key
- `POST   /password`              — self-rotate password (local-auth only)
- `GET    /recent-tool-calls`     — my last N tool calls (Home + Tool history)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from vyuu_gateway.audit.recent import RecentAuditEmitter
from vyuu_gateway.registry.api_key_policy_service import (
    ApiKeyPolicyError,
    enforce_requested_expiry,
    resolve_max_ttl,
)
from vyuu_gateway.registry.portal_schemas import (
    CatalogEntryResponse,
    IssuedMyApiKeyResponse,
    IssueMyApiKeyRequest,
    MyApiKeySummaryResponse,
    RecentToolCallResponse,
    RequiredUserAuthServer,
    RotateMyPasswordRequest,
    ToolHistorySummaryResponse,
    WhoAmIResponse,
)
from vyuu_gateway.registry.portal_service import (
    PortalApiKeyNotFoundError,
    PortalRequiresLocalAuthError,
    WrongCurrentPasswordError,
    issue_my_api_key,
    list_catalog,
    list_my_api_keys,
    revoke_my_api_key,
    rotate_my_password,
)
from vyuu_gateway.registry.users_service import (
    DuplicateApiKeyLabelError,
    UserNotFoundError,
    get_user,
)
from vyuu_gateway.users.passwords import PasswordTooWeakError
from vyuu_gateway.users.portal_dependency import (
    authenticate_portal_session,
    get_portal_scoped_db,
)
from vyuu_gateway.users.sessions import PortalSession

router = APIRouter(tags=["portal"])


def _enforce_path_tenant(session: PortalSession, tenant_id: UUID) -> None:
    if session.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="session does not match tenant in path",
        )


# --- Identity -------------------------------------------------------------


@router.get("/{tenant_id}/me", response_model=WhoAmIResponse)
def whoami_endpoint(
    tenant_id: UUID,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> WhoAmIResponse:
    _enforce_path_tenant(session, tenant_id)
    try:
        user = get_user(db, tenant_id=tenant_id, user_id=session.user_id)
    except UserNotFoundError as exc:
        # User was deleted between login and this call; treat as 401
        # so the SPA forces a fresh login.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user no longer exists",
        ) from exc
    return WhoAmIResponse(
        user_id=user.id,
        tenant_id=user.tenant_id,
        email=user.email,
        auth_method=user.auth_method.value
        if hasattr(user.auth_method, "value")
        else str(user.auth_method),
        must_change_password=user.must_change_password,
    )


# --- Catalog --------------------------------------------------------------


@router.get(
    "/{tenant_id}/catalog",
    response_model=list[CatalogEntryResponse],
)
def catalog_endpoint(
    tenant_id: UUID,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> list[CatalogEntryResponse]:
    _enforce_path_tenant(session, tenant_id)
    return [
        CatalogEntryResponse(
            vserver_id=entry.vserver_id,
            name=entry.name,
            description=entry.description,
            visibility=entry.visibility,
            has_access=entry.has_access,
            requires_user_auth_servers=[
                RequiredUserAuthServer(
                    server_id=req.server_id,
                    server_display_name=req.server_display_name,
                    connected=req.connected,
                )
                for req in entry.requires_user_auth_servers
            ],
            jit_enabled=entry.jit_enabled,
            jit_auto_approve=entry.jit_auto_approve,
            jit_tools=entry.jit_tools,
            access_expires_at=entry.access_expires_at,
        )
        for entry in list_catalog(
            db, tenant_id=tenant_id, user_id=session.user_id
        )
    ]


# --- Self-issue API keys --------------------------------------------------


@router.get(
    "/{tenant_id}/api-keys",
    response_model=list[MyApiKeySummaryResponse],
)
def list_my_api_keys_endpoint(
    tenant_id: UUID,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> list[MyApiKeySummaryResponse]:
    _enforce_path_tenant(session, tenant_id)
    return [
        MyApiKeySummaryResponse.model_validate(k)
        for k in list_my_api_keys(
            db, tenant_id=tenant_id, user_id=session.user_id
        )
    ]


@router.post(
    "/{tenant_id}/api-keys",
    response_model=IssuedMyApiKeyResponse,
    status_code=status.HTTP_201_CREATED,
)
def issue_my_api_key_endpoint(
    tenant_id: UUID,
    request: IssueMyApiKeyRequest,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> IssuedMyApiKeyResponse:
    _enforce_path_tenant(session, tenant_id)
    # CRED-1 · the tenant's key-lifetime policy decides the expiry. A
    # user cannot mint themselves a longer-lived credential than their
    # admin allows, and with no policy configured this resolves to the
    # pre-existing behaviour (no expiry).
    resolved = resolve_max_ttl(db, tenant_id=tenant_id, user_id=session.user_id)
    try:
        effective_expiry = enforce_requested_expiry(resolved, request.expires_at)
    except ApiKeyPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    try:
        row, issued = issue_my_api_key(
            db,
            tenant_id=tenant_id,
            user_id=session.user_id,
            label=request.label,
            expires_at=effective_expiry,
        )
    except DuplicateApiKeyLabelError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="api key with this label already exists",
        ) from exc
    return IssuedMyApiKeyResponse(
        id=row.id,
        label=row.label,
        plaintext=issued.plaintext,
        key_prefix=row.key_prefix,
        created_at=row.created_at,
        expires_at=row.expires_at,
    )


@router.delete(
    "/{tenant_id}/api-keys/{key_id}",
    response_model=MyApiKeySummaryResponse,
)
def revoke_my_api_key_endpoint(
    tenant_id: UUID,
    key_id: UUID,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> MyApiKeySummaryResponse:
    _enforce_path_tenant(session, tenant_id)
    try:
        key = revoke_my_api_key(
            db,
            tenant_id=tenant_id,
            user_id=session.user_id,
            key_id=key_id,
        )
    except PortalApiKeyNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="api key not found",
        ) from exc
    return MyApiKeySummaryResponse.model_validate(key)


# --- Self-rotate password -------------------------------------------------


@router.post(
    "/{tenant_id}/password",
    response_model=WhoAmIResponse,
)
def rotate_my_password_endpoint(
    tenant_id: UUID,
    request: RotateMyPasswordRequest,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> WhoAmIResponse:
    _enforce_path_tenant(session, tenant_id)
    try:
        user = rotate_my_password(
            db,
            tenant_id=tenant_id,
            user_id=session.user_id,
            current_password=request.current_password,
            new_password=request.new_password,
        )
    except PortalRequiresLocalAuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="password rotation requires local-auth account",
        ) from exc
    except WrongCurrentPasswordError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="current password incorrect",
        ) from exc
    except PasswordTooWeakError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="new password does not meet minimum requirements",
        ) from exc
    return WhoAmIResponse(
        user_id=user.id,
        tenant_id=user.tenant_id,
        email=user.email,
        auth_method=user.auth_method.value
        if hasattr(user.auth_method, "value")
        else str(user.auth_method),
        must_change_password=user.must_change_password,
    )


# --- Recent tool calls (user-scoped) -------------------------------------


@router.get(
    "/{tenant_id}/recent-tool-calls",
    response_model=list[RecentToolCallResponse],
)
def my_recent_tool_calls_endpoint(
    tenant_id: UUID,
    http_request: Request,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[RecentToolCallResponse]:
    """Return the calling user's recent tool calls.

    Reads from the in-memory `RecentAuditEmitter` ring buffer. Scoped
    to the user via their issued `user_api_keys` — if a tool call's
    audit principal id matches one of this user's API key ids, it
    counts as theirs. Other principal types (endpoint sessions,
    service-account agents) are NOT included; this endpoint is for
    the human's "what did I just do" view.

    Returns an empty list (200) when the gateway has no recent-events
    buffer wired up — keeps the portal UI benign on stripped-down
    deployments.
    """
    _enforce_path_tenant(session, tenant_id)
    recent = cast(
        RecentAuditEmitter | None,
        getattr(http_request.app.state, "recent_audit_emitter", None),
    )
    if recent is None:
        return []

    # Scope by USER id, not API-key id. `ApiKeyIdentityProvider` builds
    # `ApiKeyPrincipal(id=str(user_id), key_id=str(key_id))` — the
    # principal *is* the human; the key is only how they authenticated,
    # and it rides in a separate field that the emitted audit event does
    # not carry. Filtering on key ids therefore matched nothing, ever,
    # and this endpoint returned an empty list for every user who had
    # made calls. Covering every key the user has ever held was the
    # intent; scoping to the user achieves it directly, and keeps
    # working across key rotation.
    events = recent.query(
        tenant_id=tenant_id,
        principal_id_in=frozenset({str(session.user_id)}),
        limit=limit,
    )
    return [
        RecentToolCallResponse(
            event_id=ev.event_id,
            observed_at=ev.timestamp,
            tool=getattr(ev, "tool_name", None) or getattr(ev, "tool", None),
            vserver_id=ev.vserver_id,
            vserver_name=getattr(ev, "vserver_name", None),
            decision=getattr(ev.decision, "value", None) if ev.decision else None,
            via=ev.principal.display or None,
            latency_ms=getattr(ev, "duration_ms", None),
        )
        for ev in events
    ]


@router.get(
    "/{tenant_id}/tool-history-summary",
    response_model=ToolHistorySummaryResponse,
)
def my_tool_history_summary_endpoint(
    tenant_id: UUID,
    http_request: Request,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
    window_days: Annotated[int, Query(ge=1, le=90)] = 7,
) -> ToolHistorySummaryResponse:
    """KPI rollup for the portal's Tool history page.

    Three numbers + a couple of example blocked-tool names, scoped to
    the calling user's API keys (same principal-id filter as
    `recent-tool-calls`). Window defaults to 7 days; capped at 90 so a
    pathological window doesn't iterate the whole buffer needlessly.

    Best-effort over the in-memory `RecentAuditEmitter` ring buffer —
    anything past the buffer's tail (default 1000 events) is invisible
    here. Production deploys can swap in a Kafka/NATS query behind the
    same response shape.
    """
    _enforce_path_tenant(session, tenant_id)
    recent = cast(
        RecentAuditEmitter | None,
        getattr(http_request.app.state, "recent_audit_emitter", None),
    )
    if recent is None:
        return ToolHistorySummaryResponse(
            window_days=window_days,
            total_calls=0,
            distinct_tools=0,
            blocked_count=0,
        )

    # Same scoping fix as `/recent-tool-calls` — see the comment there.
    principal_ids = frozenset({str(session.user_id)})
    cutoff = datetime.now(UTC) - timedelta(days=window_days)
    # Ask for the buffer's full capacity (1000); the in-memory call is
    # cheap and we filter immediately. Anything older than `cutoff` gets
    # dropped — keeps the 90-day cap honest.
    events = recent.query(
        tenant_id=tenant_id,
        principal_id_in=principal_ids,
        limit=1000,
    )

    total = 0
    tool_names: set[str] = set()
    blocked_tools: list[str] = []
    for ev in events:
        ts = ev.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        if ts < cutoff:
            continue
        total += 1
        if ev.tool:
            tool_names.add(ev.tool)
        decision = getattr(ev.decision, "value", str(ev.decision)) if ev.decision else ""
        if decision in {"deny", "block", "redact"}:
            if ev.tool and ev.tool not in blocked_tools:
                blocked_tools.append(ev.tool)
    return ToolHistorySummaryResponse(
        window_days=window_days,
        total_calls=total,
        distinct_tools=len(tool_names),
        blocked_count=sum(
            1 for ev in events
            if (
                ev.timestamp.replace(
                    tzinfo=UTC
                ) if ev.timestamp.tzinfo is None else ev.timestamp
            ) >= cutoff
            and getattr(ev.decision, "value", str(ev.decision))
                in {"deny", "block", "redact"}
        ),
        blocked_tool_examples=blocked_tools[:5],
    )
