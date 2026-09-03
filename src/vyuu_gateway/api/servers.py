import asyncio
import logging
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.capabilities.client import CapabilityDescriptor, McpCapabilityClient
from vyuu_gateway.capabilities.sync import (
    DatabaseCapabilitySyncService,
    McpServerNotFoundError,
    list_capabilities_for_server,
    seed_server_capabilities,
)
from vyuu_gateway.db.models import (
    McpCapability,
    McpCapabilityKind,
    McpServer,
    McpServerSourceType,
    OAuthUserToken,
    Operator,
    User,
)
from vyuu_gateway.db.session import SessionLocal, bind_tenant_context
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator
from vyuu_gateway.registry.manifest import (
    ManifestFetchError,
    ManifestParseError,
    fetch_manifest,
    parse_manifest,
)
from vyuu_gateway.registry.schemas import (
    CapabilityChangeResponse,
    CapabilityResponse,
    CapabilitySeedRequest,
    CapabilitySyncResponse,
    ServerHealthResponse,
    ServerRegistrationRequest,
    ServerRegistrationResponse,
    ServerSyncCadenceUpdateRequest,
)
from vyuu_gateway.registry.service import (
    DuplicateServerNameError,
    OperatorNotFoundError,
    ServerNotFoundError,
    delete_mcp_server,
    list_mcp_servers,
    register_mcp_server,
    update_sync_cadence,
)
from vyuu_gateway.registry.url_security import (
    HttpUrlSecurityError,
    UrlSecurityPolicy,
    validate_http_source_url,
)
from vyuu_gateway.upstream.health import (
    UpstreamHealthServerNotFoundError,
    get_server_health,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/servers", tags=["servers"])


def _url_policy_from_request(request: Request) -> UrlSecurityPolicy:
    settings = request.app.state.settings
    return UrlSecurityPolicy(
        allow_private_networks=settings.http_url_allow_private_networks,
        allowlist=tuple(settings.http_url_allowlist),
        denylist=tuple(settings.http_url_denylist),
    )


def _innermost_exception(exc: BaseException) -> BaseException:
    """Drill into anyio task-group `BaseExceptionGroup` to the real cause.

    A failed upstream typically surfaces as `ExceptionGroup -> ExceptionGroup
    -> McpError("Connection closed")` because anyio wraps task-group failures.
    Operators care about the innermost `McpError`, not the wrapper.
    """

    while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) >= 1:
        exc = exc.exceptions[0]
    return exc


def _upstream_sync_error(server_id: UUID, exc: BaseException) -> HTTPException:
    """Map an upstream sync failure to a sanitized 502.

    The error class name is operator-actionable (`McpError`,
    `ConnectionRefusedError`, `TimeoutError`, …) without leaking raw upstream
    messages, which can carry credentials or internal hostnames.

    Special case: a stdio upstream that exited during initialize (e.g.
    `falcon-mcp` without credentials) surfaces as
    `UpstreamStartupDiagnosticError` with bounded + sanitized stderr captured
    by `_BoundedStderrBuffer`. We include that stderr in the operator-
    facing detail because it's almost always actionable ("Configuration
    error: API credentials not provided. Set FALCON_CLIENT_ID...") and
    the buffer + sanitization rules contain the leak surface.
    """

    from vyuu_gateway.mcp.outbound import UpstreamStartupDiagnosticError

    if isinstance(exc, UpstreamStartupDiagnosticError):
        error_type = exc.original_error_class
        detail = (
            f"upstream sync failed: {error_type} — upstream stderr: {exc.stderr}"
        )
    else:
        error_type = exc.__class__.__name__
        detail = f"upstream sync failed: {error_type}"

    logger.warning(
        "upstream_sync_failed",
        extra={"server_id": str(server_id), "error_type": error_type},
    )
    return HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=detail,
    )


@router.get("", response_model=list[ServerRegistrationResponse])
def list_servers(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> list[ServerRegistrationResponse]:
    servers = list_mcp_servers(db, tenant_id=operator.tenant_id)
    # One grouped query for the whole catalog, not one per row: the
    # console renders every server at once, so a per-server count would
    # be an N+1 the moment a tenant has more than a handful.
    counts = dict(
        db.execute(
            select(McpCapability.server_id, func.count())
            .where(
                McpCapability.tenant_id == operator.tenant_id,
                McpCapability.kind == McpCapabilityKind.TOOL,
                McpCapability.deprecated.is_(False),
            )
            .group_by(McpCapability.server_id)
        ).all()
    )
    responses = []
    for server in servers:
        payload = ServerRegistrationResponse.model_validate(server)
        # 0, not None, for a server that has synced and genuinely
        # exposes no tools — that is a real answer, and distinguishing
        # it from "never synced" is the point of the column.
        payload.tool_count = (
            counts.get(server.id, 0)
            if server.last_capabilities_pulled_at is not None
            else None
        )
        responses.append(payload)
    return responses


@router.post(
    "",
    response_model=ServerRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_server(
    request: ServerRegistrationRequest,
    http_request: Request,
    background_tasks: BackgroundTasks,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> ServerRegistrationResponse:
    if request.source_type == McpServerSourceType.HTTP:
        policy = _url_policy_from_request(http_request)
        try:
            validate_http_source_url(request.source_location, policy)
        except HttpUrlSecurityError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    try:
        server = register_mcp_server(
            db,
            request=request,
            tenant_id=operator.tenant_id,
            registered_by=operator.operator_id,
        )
    except OperatorNotFoundError as exc:
        # The bearer token's (operator_id, tenant_id) claim does not match
        # the operators table — either the key was issued for an operator
        # that has been removed, or the auth provider is misconfigured /
        # compromised. Reject as 401 and do not distinguish from "bad token"
        # in the response detail.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except DuplicateServerNameError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="server display_name already exists in tenant",
        ) from exc

    logger.info("mcp_server_registered")
    # Kick off a non-blocking health probe so `health_status` flips off
    # `unknown` without the operator needing to click "Check health".
    # Runs after the response is sent; failures swallowed inside the
    # probe (it persists DOWN + last_health_error rather than raising).
    checker = http_request.app.state.upstream_health_checker
    background_tasks.add_task(
        _probe_after_registration,
        checker,
        operator.tenant_id,
        server.id,
    )
    # Tier-1 stress-test fix: auto-sync capabilities on registration so
    # tool calls don't fail with `capabilities_not_synced` until the
    # operator manually clicks Sync. Fire-and-forget; failures log a
    # warning + leave `last_capabilities_pulled_at` NULL (operator UI
    # surfaces this as a "never synced" indicator). Disable via
    # `Settings.auto_sync_capabilities_on_registration=False` for
    # deployments that drive sync from a separate orchestrator.
    #
    # EXCEPTION: when the only auth path is `auth_authcode` (per-user
    # delegated OAuth), the gateway has NO bearer it can use for the
    # capability probe at registration time — there are no stored
    # `oauth_user_tokens` rows for this server yet. Auto-sync would
    # 401 N times, trip the upstream circuit breaker, and surface as
    # a confusing 502 during what should be a normal Connect → flow.
    # Skip auto-sync for these; the operator runs Connect → first,
    # then clicks Sync manually. Other auth modes (`auth_oauth` M2M,
    # `auth_jwt_bearer`, `auth_org_tier`, `auth_env`, `auth_passthrough`,
    # mTLS, or no auth) all have a credential available at registration.
    settings = http_request.app.state.settings
    if (
        settings.auto_sync_capabilities_on_registration
        and not _only_authcode(server)
    ):
        capability_client = http_request.app.state.capability_sync_client
        background_tasks.add_task(
            _sync_after_registration,
            capability_client,
            operator.tenant_id,
            server.id,
            settings.auto_sync_per_call_timeout_seconds,
        )
    return ServerRegistrationResponse.model_validate(server)


def _resolve_operator_user_id(
    tenant_id: UUID, operator_id: UUID
) -> UUID | None:
    """Find the portal `users.id` whose email matches the operator's.

    Capability sync against an `auth_authcode` upstream needs SOME
    user_id with a stored OAuth token. Operators and users are
    separate entities, but bootstrap maps them 1:1 by email
    (PLATFORM.md §3.1) — that mapping is the bridge.

    Uses a fresh `SessionLocal()` (NOT the request-scoped session)
    so the lookup doesn't consume queued scalar results in test
    fakes for the manual-sync endpoint. In production this hits the
    real Postgres directly. Returns None on any miss — caller
    passes None as `principal_id` to sync; non-authcode upstreams
    ignore it, authcode upstreams hit the
    `_maybe_raise_authcode_no_token` failure-path translator.
    """
    try:
        with SessionLocal() as session:
            bind_tenant_context(session, tenant_id)
            op = session.scalar(select(Operator).where(Operator.id == operator_id))
            if op is None:
                return None
            user = session.scalar(
                select(User).where(
                    User.tenant_id == tenant_id,
                    User.email == op.email,
                    User.disabled_at.is_(None),
                )
            )
            return user.id if user is not None else None
    except Exception:
        return None


def _maybe_raise_authcode_no_token(
    db: Session,
    tenant_id: UUID,
    server_id: UUID,
    exc: BaseException,
) -> None:
    """Translate a sync failure on an authcode-only server with no
    stored OAuth token into a friendly 412.

    Runs only on the failure path so the happy-path scalar() count is
    unchanged. The check is conservative: only fires when the upstream
    error looks auth-related (HTTP 401/403, McpError with auth phrasing,
    or generic httpx error) AND the server is authcode-only AND no
    `oauth_user_tokens` row exists for any user on this server. The
    operator gets actionable guidance instead of `502 upstream sync
    failed: HTTPStatusError`.
    """
    error_text = repr(exc).lower()
    looks_auth_failure = any(
        marker in error_text
        for marker in ("401", "403", "unauthorized", "auth")
    )
    if not looks_auth_failure:
        return
    server = db.scalar(select(McpServer).where(McpServer.id == server_id))
    if server is None or not _only_authcode(server):
        return
    has_token = db.scalar(
        select(OAuthUserToken.id)
        .where(OAuthUserToken.tenant_id == tenant_id)
        .where(OAuthUserToken.server_id == server_id)
        .limit(1)
    )
    if has_token is not None:
        return
    raise HTTPException(
        status_code=status.HTTP_412_PRECONDITION_FAILED,
        detail=(
            "Cannot sync — this server uses per-user OAuth "
            "(auth_authcode) and no user has authorized it yet. "
            "Click Connect → on this row to authorize at least one "
            "user, then click Sync."
        ),
    )


def _only_authcode(server: Any) -> bool:
    """True if `auth_authcode` is set and no auth path is configured
    that the gateway could use for an operator-less capability probe.

    Per-user OAuth-authcode upstreams have NO stored token at
    registration time — auto-sync would 401 N times and trip the
    upstream circuit breaker, surfacing as a confusing 502 during
    what should be a normal Connect → flow. This check suppresses
    auto-sync for those, leaving the operator to run Connect → first
    and click Sync manually.

    Schema enforces mutual exclusivity between `auth_authcode`,
    `auth_oauth`, and `auth_jwt_bearer`, so we only need to check
    the orthogonal credential paths here: `auth_env` (stdio env-var
    injection — irrelevant for HTTP but checked anyway),
    `auth_passthrough` (per-user header forwarding from the inbound
    request — gives sync nothing usable), and mTLS. Empty dicts (the
    default for `auth_env` / `auth_passthrough`) are falsy.
    """
    if not getattr(server, "auth_authcode", None):
        return False
    # `auth_passthrough` forwards inbound headers per-call; capability
    # sync runs without an inbound request, so this gives sync nothing
    # usable — still treat the server as authcode-only for sync purposes.
    if getattr(server, "mtls_cert_ref", None):
        return False
    if getattr(server, "mtls_key_ref", None):
        return False
    return True


async def _probe_after_registration(
    checker: object,
    tenant_id: UUID,
    server_id: UUID,
) -> None:
    """Run the upstream health probe after a successful registration.

    `UpstreamHealthChecker.check_server` already catches upstream
    exceptions and persists `health_status=DOWN` with the sanitized
    error class; this wrapper only catches gateway-internal failures
    (e.g. DB unavailable in the worker) so they don't surface as
    'task exception was never retrieved' warnings.
    """

    check = getattr(checker, "check_server", None)
    if not callable(check):
        return
    try:
        await check(tenant_id, server_id)
    except Exception:  # noqa: BLE001 - background task; never re-raise
        logger.warning(
            "registration_probe_failed",
            extra={"tenant_id": str(tenant_id), "server_id": str(server_id)},
        )


async def _sync_after_registration(
    capability_client: McpCapabilityClient,
    tenant_id: UUID,
    server_id: UUID,
    timeout_seconds: float,
) -> None:
    """Run a one-shot capability sync after a successful registration.

    Mirrors the periodic scheduler's per-server sync semantics:
    - Opens a fresh DB session bound to the tenant (RLS enforced).
    - Calls `DatabaseCapabilitySyncService.sync_server_capabilities`
      with a tight timeout — stdio MCPs spend most of that on uvx /
      npx subprocess cold-start, HTTP MCPs respond in <1s.
    - Failures are swallowed and logged; the sync timestamp on the
      `mcp_servers` row stays NULL so the operator UI can render a
      "never synced — tool calls will fail until you click Sync"
      indicator.
    - `asyncio.CancelledError` re-raised cleanly so the worker can
      shut down even if a sync is in-flight.
    """
    try:
        with SessionLocal() as session:
            bind_tenant_context(session, tenant_id)
            service = DatabaseCapabilitySyncService(session, capability_client)
            await asyncio.wait_for(
                service.sync_server_capabilities(tenant_id, server_id),
                timeout=timeout_seconds,
            )
            logger.info(
                "capability_sync_after_registration_ok",
                extra={
                    "tenant_id": str(tenant_id),
                    "server_id": str(server_id),
                },
            )
    except asyncio.CancelledError:
        raise
    except TimeoutError:
        logger.warning(
            "capability_sync_after_registration_timeout",
            extra={
                "tenant_id": str(tenant_id),
                "server_id": str(server_id),
                "timeout_seconds": timeout_seconds,
            },
        )
    except Exception as exc:  # noqa: BLE001 - background task; never re-raise
        # Drill into anyio task-group wrappers so the recorded error
        # class is operator-actionable (e.g. ConnectionRefusedError
        # rather than a generic ExceptionGroup).
        inner: BaseException = exc
        while isinstance(inner, BaseExceptionGroup) and len(inner.exceptions) >= 1:
            inner = inner.exceptions[0]
        logger.warning(
            "capability_sync_after_registration_failed",
            extra={
                "tenant_id": str(tenant_id),
                "server_id": str(server_id),
                "error_type": inner.__class__.__name__,
            },
        )


@router.get("/{server_id}/health", response_model=ServerHealthResponse)
def get_server_health_status(
    server_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> ServerHealthResponse:
    try:
        snapshot = get_server_health(db, tenant_id=operator.tenant_id, server_id=server_id)
    except UpstreamHealthServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="server not found",
        ) from exc

    return ServerHealthResponse.model_validate(snapshot)


@router.post("/{server_id}/health/check", response_model=ServerHealthResponse)
async def check_server_health(
    server_id: UUID,
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
) -> ServerHealthResponse:
    checker = http_request.app.state.upstream_health_checker
    try:
        snapshot = await checker.check_server(operator.tenant_id, server_id)
    except UpstreamHealthServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="server not found",
        ) from exc

    return ServerHealthResponse.model_validate(snapshot)


class DeleteServerResponse(BaseModel):
    """Cascade-delete summary for `DELETE /api/v1/servers/{id}`.

    Surfaces what got cleaned up so the operator console can render
    a confirmation toast. The actual rows are gone by the time this
    response arrives — these are pre-delete counts captured in the
    same transaction.
    """

    capabilities_deleted: int
    vserver_tool_exposures_removed: int
    oauth_user_tokens_revoked: int


@router.delete(
    "/{server_id}",
    response_model=DeleteServerResponse,
)
async def delete_server_endpoint(
    server_id: UUID,
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> DeleteServerResponse:
    """Delete an MCP server + cascade dependents.

    Cascades:
      - `mcp_capabilities` rows for this server (FK ondelete=CASCADE)
      - `virtual_server_tools` rows wrapping this server's tools
      - `oauth_user_tokens` rows for this (tenant, user, server)

    Vservers that wrap this server stay (tool allowlist becomes
    empty); operators who want them gone delete the vserver
    explicitly. Tenant-isolated: a server_id from another tenant
    returns 404 (no enumeration).

    Also tears down any live upstream connection. For an stdio server
    that means killing the spawned subprocess: deleting the row used to
    leave `uvx` / `npx` children running with the credentials they were
    started with, until the gateway process itself exited.

    `async def` + `run_in_threadpool` rather than a plain `def`: the
    teardown is async, and the DB work must stay off the event loop.
    """
    try:
        summary = await run_in_threadpool(
            delete_mcp_server,
            db,
            tenant_id=operator.tenant_id,
            server_id=server_id,
        )
    except ServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="server not found"
        ) from exc

    # Only after the row is really gone, so a failed delete cannot kill
    # a connection the gateway still needs.
    await _forget_upstream(http_request, operator.tenant_id, server_id)
    return DeleteServerResponse(**summary)


async def _forget_upstream(
    http_request: Request, tenant_id: UUID, server_id: UUID
) -> None:
    """Best-effort upstream teardown after a server is deleted.

    Deliberately swallows failures: the row is already gone and the
    caller's delete succeeded, so raising here would report a failure
    for work that did happen. A leaked subprocess is logged and cleaned
    up at the next gateway restart; a spurious 500 would have the
    operator retry a delete that cannot succeed twice.
    """

    provider = getattr(http_request.app.state, "upstream_clients", None)
    forget = getattr(provider, "forget_server", None)
    if forget is None:
        return
    try:
        await forget(tenant_id, server_id)
    except Exception:  # noqa: BLE001 - see docstring
        logger.warning(
            "upstream_teardown_failed_after_delete",
            extra={"tenant_id": str(tenant_id), "server_id": str(server_id)},
            exc_info=True,
        )


@router.patch(
    "/{server_id}/sync-cadence",
    response_model=ServerRegistrationResponse,
)
def update_server_sync_cadence(
    server_id: UUID,
    request: ServerSyncCadenceUpdateRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> ServerRegistrationResponse:
    """Update a server's per-server capability-sync cadence.

    `sync_cadence_minutes` semantics:
        None  → use the global default
        0     → manual only (skip auto-sync)
        N>0   → run no more often than every N minutes (capped 30d)
    """
    try:
        server = update_sync_cadence(
            db,
            tenant_id=operator.tenant_id,
            server_id=server_id,
            sync_cadence_minutes=request.sync_cadence_minutes,
        )
    except ServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="server not found"
        ) from exc
    return ServerRegistrationResponse.model_validate(server)


@router.post(
    "/{server_id}/sync",
    response_model=CapabilitySyncResponse,
    response_model_by_alias=True,
)
async def sync_server_capabilities(
    server_id: UUID,
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> CapabilitySyncResponse:
    """Probe the upstream MCP server and persist a fresh capability snapshot.

    Drives the operator-console "discover tools" step. Reuses the same
    upstream-client provider the tool-call hot path uses, so the call goes
    through the upstream pool / circuit breaker.
    """
    # Resolve operator → underlying portal user so phase-4 OAuth-authcode
    # upstreams can authenticate the capability probe with that user's
    # stored token. For other auth modes, this is unused. We DON'T 412
    # here when no matching user exists — non-authcode upstreams sync
    # fine without a principal_id, and the authcode-no-token case is
    # caught downstream by `_maybe_raise_authcode_no_token` with a
    # friendlier message.
    principal_id = _resolve_operator_user_id(operator.tenant_id, operator.operator_id)
    capability_client = http_request.app.state.capability_sync_client
    sync_service = DatabaseCapabilitySyncService(db, capability_client)
    try:
        result = await sync_service.sync_server_capabilities(
            operator.tenant_id, server_id, principal_id=principal_id
        )
    except McpServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="server not found",
        ) from exc
    except BaseExceptionGroup as exc:
        # anyio's task groups wrap upstream errors. Unwrap to the innermost
        # cause so operators see e.g. `McpError` / `ConnectionRefusedError`
        # instead of a generic `ExceptionGroup`.
        innermost = _innermost_exception(exc)
        _maybe_raise_authcode_no_token(db, operator.tenant_id, server_id, innermost)
        raise _upstream_sync_error(server_id, innermost) from exc
    except Exception as exc:
        _maybe_raise_authcode_no_token(db, operator.tenant_id, server_id, exc)
        raise _upstream_sync_error(server_id, exc) from exc

    drift = result.drift
    return CapabilitySyncResponse(
        tenant_id=result.tenant_id,
        server_id=result.server_id,
        synced_at=result.synced_at,
        capability_count=result.capability_count,
        added=[CapabilityChangeResponse(kind=c.kind, name=c.name) for c in drift.added],
        removed=[CapabilityChangeResponse(kind=c.kind, name=c.name) for c in drift.removed],
        changed=[CapabilityChangeResponse(kind=c.kind, name=c.name) for c in drift.changed],
        unchanged=[
            CapabilityChangeResponse(kind=c.kind, name=c.name) for c in drift.unchanged
        ],
    )


@router.get(
    "/{server_id}/capabilities",
    response_model=list[CapabilityResponse],
    response_model_by_alias=True,
)
def list_server_capabilities(
    server_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> list[CapabilityResponse]:
    """List the active capability snapshot for a server.

    Drives the operator-console "pick tools to publish" step — the operator
    sees the most recent sync's tool list and selects which to expose via a
    virtual server.
    """
    capabilities = list_capabilities_for_server(
        db,
        tenant_id=operator.tenant_id,
        server_id=server_id,
    )
    return [CapabilityResponse.model_validate(c) for c in capabilities]


@router.post(
    "/{server_id}/capabilities",
    response_model=CapabilitySyncResponse,
    response_model_by_alias=True,
)
async def seed_server_capabilities_endpoint(
    server_id: UUID,
    request: CapabilitySeedRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> CapabilitySyncResponse:
    """Manually seed a server's capability snapshot — no upstream probe.

    For credential-gated upstreams (CrowdStrike Falcon, etc.), air-gapped
    deployments, or pre-procurement evaluation. Operator pastes a tool
    catalog (typically from vendor docs); the gateway treats it as the
    active snapshot, marks the previous one deprecated, and returns the
    drift summary. `last_capabilities_pulled_at` is intentionally NOT
    updated — that field signals "verified against upstream" and a manual
    seed has no such verification.
    """

    descriptors = [
        CapabilityDescriptor(
            kind=entry.kind,
            name=entry.name,
            schema_json=entry.schema_payload,
        )
        for entry in request.capabilities
    ]
    risk_overrides = {
        entry.name: entry.risk_category
        for entry in request.capabilities
        if entry.risk_category is not None
    }
    try:
        result = await seed_server_capabilities(
            db,
            tenant_id=operator.tenant_id,
            server_id=server_id,
            descriptors=descriptors,
            risk_overrides=risk_overrides,
        )
    except McpServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="server not found",
        ) from exc

    drift = result.drift
    return CapabilitySyncResponse(
        tenant_id=result.tenant_id,
        server_id=result.server_id,
        synced_at=result.synced_at,
        capability_count=result.capability_count,
        added=[CapabilityChangeResponse(kind=c.kind, name=c.name) for c in drift.added],
        removed=[CapabilityChangeResponse(kind=c.kind, name=c.name) for c in drift.removed],
        changed=[CapabilityChangeResponse(kind=c.kind, name=c.name) for c in drift.changed],
        unchanged=[
            CapabilityChangeResponse(kind=c.kind, name=c.name) for c in drift.unchanged
        ],
    )


# --- S8 · register-by-manifest preview ---------------------------------


class ManifestPreviewRequest(BaseModel):
    """Operator pastes a `mcp.json` URL; the gateway fetches it and
    returns a pre-filled registration body the operator confirms."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    manifest_url: Annotated[str, Field(min_length=1, max_length=4096)]
    allow_http: bool = Field(
        default=False,
        description=(
            "HTTPS-only by default. Set true for local-dev manifests served"
            " over plain HTTP - production should never need this."
        ),
    )


class ManifestPreviewResponse(BaseModel):
    """Auto-detected fields plus the raw manifest body. Operator inspects,
    fills in any gaps, and POSTs to the regular `/servers` endpoint to
    actually register. NO auto-registration - preserves the rule that
    registry mutations require explicit operator confirmation."""

    model_config = ConfigDict(from_attributes=False)

    display_name: str | None
    description: str | None
    transport: str | None
    source_type: str | None
    source_location: str | None
    args: list[str]
    auth_hint: str | None
    raw_manifest: dict[str, Any]
    notes: list[str] = Field(default_factory=list)


@router.post(
    "/from-manifest",
    response_model=ManifestPreviewResponse,
)
async def manifest_preview_endpoint(
    request: ManifestPreviewRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
) -> ManifestPreviewResponse:
    """Fetch + parse a `mcp.json` manifest, return auto-detected fields.

    Why preview-only and not register: a malicious manifest URL must
    not be able to silently land an upstream in the tenant's registry.
    The operator always confirms via the existing `POST /servers`
    after seeing what was auto-detected here.
    """

    try:
        body = await fetch_manifest(
            request.manifest_url,
            allow_http=request.allow_http,
        )
    except ManifestFetchError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"manifest fetch failed: {exc}",
        ) from exc
    except ManifestParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"manifest parse failed: {exc}",
        ) from exc

    parsed = parse_manifest(body)
    notes: list[str] = []
    if parsed.transport is None:
        notes.append("transport could not be auto-detected; please specify")
    if parsed.source_location is None:
        notes.append("source_location could not be auto-detected")
    if parsed.auth_hint:
        notes.append(
            f"manifest hints at auth scheme {parsed.auth_hint!r}; "
            "wire auth_headers / auth_oauth as needed before publishing"
        )
    notes.append(
        "Manifest spec is still evolving upstream; review the raw payload"
        " and confirm via POST /api/v1/servers."
    )
    return ManifestPreviewResponse(
        display_name=parsed.display_name,
        description=parsed.description,
        transport=parsed.transport,
        source_type=parsed.source_type,
        source_location=parsed.source_location,
        args=parsed.args,
        auth_hint=parsed.auth_hint,
        raw_manifest=parsed.raw,
        notes=notes,
    )
