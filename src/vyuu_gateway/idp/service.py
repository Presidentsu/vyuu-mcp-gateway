"""Service-layer ops for the IdP-directory admin endpoints.

Mirrors the shape of `users_service.py` and `virtual_servers/service.py`:

- Each mutation accepts an `actor: AdminAuditActor | None` param and
  emits an `admin_audit_log` row in the same DB transaction.
- Service functions own their `db.commit()` so the audit row commits
  atomically with the mutation.
- Tenant scoping is explicit on every entry point + reinforced via
  RLS on the table.

The SCIM token is generated here (not at the API layer) so the audit
detail can capture which protocol was wired without ever including
the plaintext.
"""

from __future__ import annotations

from datetime import datetime
from typing import cast
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vyuu_gateway.audit.admin_audit import (
    AdminAuditActor,
    AdminAuditTarget,
    record_admin_action,
)
from vyuu_gateway.db.models import (
    IdpDirectory,
)
from vyuu_gateway.idp.schemas import ConnectIdpDirectoryRequest
from vyuu_gateway.idp.scim_tokens import IssuedScimToken, issue_scim_token

# --- Errors ---------------------------------------------------------------


class IdpDirectoryNotFoundError(Exception):
    """No directory with that id in the requested tenant."""


class DuplicateIdpDirectoryError(Exception):
    """A directory of this `kind` is already connected to the tenant.

    The unique `(tenant_id, kind)` constraint deliberately blocks
    connecting Entra (or Workspace) twice — admins should disconnect
    first if they need to re-pair against a different Entra tenant.
    """


# --- CRUD -----------------------------------------------------------------


class WorkspacePollingConfigError(Exception):
    """IDP-2 · polling was enabled without the fields it needs."""


def list_idp_directories(
    db: Session, *, tenant_id: UUID
) -> list[IdpDirectory]:
    """Newest-first list of directories the tenant has connected."""

    return list(
        db.scalars(
            select(IdpDirectory)
            .where(IdpDirectory.tenant_id == tenant_id)
            .order_by(IdpDirectory.created_at.desc())
        ).all()
    )


def get_idp_directory(
    db: Session, *, tenant_id: UUID, directory_id: UUID
) -> IdpDirectory:
    directory = cast(
        IdpDirectory | None,
        db.scalar(
            select(IdpDirectory).where(
                IdpDirectory.tenant_id == tenant_id,
                IdpDirectory.id == directory_id,
            )
        ),
    )
    if directory is None:
        raise IdpDirectoryNotFoundError
    return directory


def get_idp_directory_for_scim(
    db: Session, *, directory_id: UUID
) -> IdpDirectory | None:
    """Untenanted lookup — used by the SCIM auth dependency before
    the tenant context is known. The dependency binds RLS to the
    directory's tenant once the bearer-hash check succeeds.

    Returns None for unknown ids (the auth path responds 401 with no
    detail; we never disclose whether the directory exists or just
    has the wrong bearer)."""

    return cast(
        IdpDirectory | None,
        db.scalar(
            select(IdpDirectory).where(IdpDirectory.id == directory_id)
        ),
    )


def connect_idp_directory(
    db: Session,
    *,
    tenant_id: UUID,
    request: ConnectIdpDirectoryRequest,
    actor: AdminAuditActor | None = None,
) -> tuple[IdpDirectory, IssuedScimToken]:
    """Persist a fresh directory + mint its SCIM bearer.

    The plaintext bearer in the returned tuple is shown to the admin
    exactly once via the create response. The hash is what lands in
    the DB.
    """

    issued = issue_scim_token()
    directory = IdpDirectory(
        id=uuid4(),
        tenant_id=tenant_id,
        kind=request.kind,
        display_name=request.display_name,
        signin_protocol=request.signin_protocol,
        scim_token_hash=issued.token_hash,
        oidc_issuer=request.oidc.issuer if request.oidc else None,
        oidc_client_id=request.oidc.client_id if request.oidc else None,
        oidc_client_secret_ref=(
            request.oidc.client_secret_ref if request.oidc else None
        ),
        saml_entity_id=request.saml.entity_id if request.saml else None,
        saml_sso_url=request.saml.sso_url if request.saml else None,
        saml_idp_certificate=(
            request.saml.idp_certificate if request.saml else None
        ),
        metadata_json=dict(request.metadata),
    )
    try:
        db.add(directory)
        if actor is not None:
            record_admin_action(
                db,
                tenant_id=tenant_id,
                actor=actor,
                action="idp.connect",
                target=AdminAuditTarget(
                    kind="idp_directory",
                    id=directory.id,
                    display=directory.display_name,
                ),
                detail={
                    "kind": _enum_value(request.kind),
                    "signin_protocol": _enum_value(request.signin_protocol),
                    # Capture the wiring we recorded but NEVER the
                    # plaintext bearer. The hash is also omitted —
                    # it's a credential, not audit data.
                    "oidc_issuer": (
                        request.oidc.issuer if request.oidc else None
                    ),
                    "saml_sso_url": (
                        request.saml.sso_url if request.saml else None
                    ),
                },
            )
        db.commit()
        db.refresh(directory)
    except IntegrityError as exc:
        db.rollback()
        raise DuplicateIdpDirectoryError from exc
    return directory, issued


def disconnect_idp_directory(
    db: Session,
    *,
    tenant_id: UUID,
    directory_id: UUID,
    actor: AdminAuditActor | None = None,
) -> None:
    """Hard-remove a directory. The FKs from `users.idp_directory_id`
    + `groups.idp_directory_id` are `ON DELETE SET NULL`, so SCIM-
    provisioned rows survive (orphaned, but their existence is
    preserved for the audit trail). Operators can choose to disable
    the now-orphaned users separately if they want a hard cleanup.
    """

    directory = get_idp_directory(
        db, tenant_id=tenant_id, directory_id=directory_id
    )
    captured_display = directory.display_name
    captured_kind = _enum_value(directory.kind)
    db.delete(directory)
    if actor is not None:
        record_admin_action(
            db,
            tenant_id=tenant_id,
            actor=actor,
            action="idp.disconnect",
            target=AdminAuditTarget(
                kind="idp_directory",
                id=directory_id,
                display=captured_display,
            ),
            detail={"kind": captured_kind},
        )
    db.commit()


def configure_directory_ema(
    db: Session,
    *,
    tenant_id: UUID,
    directory_id: UUID,
    enabled: bool,
    audience: str,
    jwks_uri: str | None,
    allowed_client_ids: list[str],
    actor: AdminAuditActor,
) -> IdpDirectory:
    """Turn MCP Enterprise-Managed Authorization on/off for one directory.

    This is the switch that decides whether the gateway will honour
    ID-JAG grants minted by this directory's issuer. Off by default:
    connecting a directory for SCIM/SSO must never silently start
    trusting it to authorize agent traffic.

    Disabling is an instant, retroactive revocation — the hot-path
    provider re-checks `ema_enabled` on every call, so tokens already
    in the wild stop working immediately rather than lingering until
    they expire. That is recorded in the audit detail so the trail
    shows the blast radius.
    """

    directory = get_idp_directory(db, tenant_id=tenant_id, directory_id=directory_id)
    was_enabled = bool(directory.ema_enabled)

    directory.ema_enabled = enabled
    directory.ema_audience = audience or None
    directory.ema_jwks_uri = jwks_uri or None
    directory.ema_allowed_client_ids = list(allowed_client_ids)

    record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=actor,
        action="idp.ema_enable" if enabled else "idp.ema_disable",
        target=AdminAuditTarget(
            kind="idp_directory",
            id=directory.id,
            display=directory.display_name,
        ),
        detail={
            "was_enabled": was_enabled,
            "now_enabled": enabled,
            "audience": audience or None,
            "jwks_uri": jwks_uri or None,
            "allowed_client_ids": list(allowed_client_ids),
            "revokes_outstanding_tokens": was_enabled and not enabled,
        },
    )
    db.commit()
    return directory


def configure_workspace_polling(
    db: Session,
    *,
    tenant_id: UUID,
    directory_id: UUID,
    enabled: bool,
    customer_id: str | None = None,
    admin_subject: str | None = None,
    service_account_ref: str | None = None,
    actor: AdminAuditActor,
) -> IdpDirectory:
    """IDP-2 · turn Google Workspace directory polling on or off.

    Enabling requires all three of customer id, delegated admin subject
    and service-account ref. Validated here rather than left to fail on
    the first poll, because a poller that silently never runs looks
    exactly like a directory with nothing to sync — and the whole reason
    this feature exists is that Workspace's *absence* of deprovisioning
    is silent.

    Does not commit; the caller owns the transaction.
    """

    directory = get_idp_directory(db, tenant_id=tenant_id, directory_id=directory_id)

    if enabled:
        resolved_customer = (customer_id or directory.workspace_customer_id or "").strip()
        resolved_admin = (admin_subject or directory.workspace_admin_subject or "").strip()
        resolved_ref = (
            service_account_ref or directory.workspace_service_account_ref or ""
        ).strip()
        missing = [
            name
            for name, value in (
                ("customer_id", resolved_customer),
                ("admin_subject", resolved_admin),
                ("service_account_ref", resolved_ref),
            )
            if not value
        ]
        if missing:
            raise WorkspacePollingConfigError(
                "workspace polling needs " + ", ".join(missing)
            )
        directory.workspace_customer_id = resolved_customer
        directory.workspace_admin_subject = resolved_admin
        directory.workspace_service_account_ref = resolved_ref

    before = bool(directory.workspace_polling_enabled)
    directory.workspace_polling_enabled = enabled

    record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=actor,
        action=(
            "idp.workspace_polling_enable" if enabled
            else "idp.workspace_polling_disable"
        ),
        target=AdminAuditTarget(
            kind="idp_directory", id=directory.id, display=directory.display_name
        ),
        detail={
            "before": before,
            "after": enabled,
            "customer_id": directory.workspace_customer_id,
            "admin_subject": directory.workspace_admin_subject,
            # The REF, never the material.
            "service_account_ref": directory.workspace_service_account_ref,
            # Spelled out because this is the consequence an operator is
            # actually deciding about.
            "deprovisioning": (
                "polled from the Workspace directory"
                if enabled
                else "MANUAL — Workspace custom SAML apps cannot SCIM-push"
            ),
        },
    )
    return directory


def find_or_jit_create_directory_user(
    db: Session,
    *,
    directory: IdpDirectory,
    subject: str,
    email: str,
    display_name: str | None,
) -> tuple[object, bool]:
    """Locate (or JIT-create) the user row provisioned for `subject`
    under `directory`. Shared by all three directory-rooted entry
    points — OIDC sign-in, SAML sign-in, and EMA-1's ID-JAG token
    exchange — so the `(directory_id, external_id)` matching rule and
    the placeholder-row shape cannot drift between them. The next SCIM
    sync reconciles a JIT placeholder into canonical state by the same
    key and back-fills metadata.

    Returns `(user, jit_created)`. Caller owns the commit.
    """

    from vyuu_gateway.db.models import User, UserAuthMethod  # local import — avoids cycle

    user = db.scalar(
        select(User).where(
            User.tenant_id == directory.tenant_id,
            User.idp_directory_id == directory.id,
            User.external_id == subject,
        )
    )
    if user is not None:
        return user, False

    user = User(
        tenant_id=directory.tenant_id,
        email=email.strip().lower(),
        display_name=display_name,
        auth_method=UserAuthMethod.SCIM,
        password_hash=None,
        external_subject=subject,
        idp_directory_id=directory.id,
        external_id=subject,
    )
    db.add(user)
    db.flush()
    return user, True


def find_users_due_for_hard_delete(
    db: Session,
    *,
    older_than: datetime,
) -> list[tuple[UUID, UUID, str]]:
    """Untenanted scan — returns (tenant_id, user_id, email) for every
    SCIM-soft-deleted row whose grace window has elapsed.

    The sweeper opens this UNTENANTED so it can find rows across all
    tenants in one pass, then commits the actual hard-delete inside a
    per-tenant transaction (so RLS catches any tenant-id mismatch and
    the admin_audit row lands in the right tenant scope).
    """

    from vyuu_gateway.db.models import User  # local import — avoids cycle

    rows = db.execute(
        select(User.tenant_id, User.id, User.email).where(
            User.soft_deleted_at.is_not(None),
            User.soft_deleted_at < older_than,
        )
    ).all()
    return [(row[0], row[1], row[2]) for row in rows]


def hard_delete_user(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    captured_email: str,
    actor: AdminAuditActor,
) -> None:
    """Drop a user row whose grace window has elapsed.

    Cascades from `users.id` clear `user_api_keys`, `user_group_memberships`,
    `oauth_user_tokens`, `access_requests`. The audit row is written in
    the same transaction and survives — `admin_audit_log.target_id` is
    deliberately NOT a FK so the row stays even after its target row is
    gone (you'd lose the audit trail otherwise).
    """

    from vyuu_gateway.db.models import User  # local import — avoids cycle

    db.execute(User.__table__.delete().where(User.id == user_id))
    record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=actor,
        action="scim.hard_delete_user",
        target=AdminAuditTarget(
            kind="user", id=user_id, display=captured_email
        ),
        detail={"reason": "soft_deletion_grace_elapsed"},
    )
    db.commit()


def stamp_last_sync(
    db: Session,
    *,
    tenant_id: UUID,
    directory_id: UUID,
    when: datetime,
) -> None:
    """Record that we just received traffic on this directory's SCIM
    endpoint. Called from the SCIM auth dependency on every successful
    bearer check. No audit row — this is a heartbeat, not an admin
    action."""

    db.execute(
        IdpDirectory.__table__.update()
        .where(
            IdpDirectory.tenant_id == tenant_id,
            IdpDirectory.id == directory_id,
        )
        .values(last_sync_at=when)
    )
    db.commit()


def _enum_value(maybe_enum: object) -> str:
    """StrEnum members serialise to their `value` for JSONB storage
    and audit details. Callers may pass either an enum or its raw str."""

    if hasattr(maybe_enum, "value"):
        return str(maybe_enum.value)  # type: ignore[attr-defined]
    return str(maybe_enum)
