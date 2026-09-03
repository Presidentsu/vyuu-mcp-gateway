"""IDP-2 · Google Workspace directory polling.

Workspace **custom SAML apps cannot SCIM-push.** Auto-provisioning is
reserved for apps in Google's own catalog; an app a customer creates
themselves gets SAML SSO and nothing more. So our SCIM endpoint never
hears from Workspace, and a Workspace tenant runs on JIT-create at first
sign-in with **manual deprovisioning** — which is exactly the property
enterprises adopt directory integration to obtain. Someone terminated in
HR keeps working access until an operator happens to notice.

This closes that by pulling instead of waiting to be pushed.

## It applies changes through the SCIM service functions, not over HTTP

The original sketch had the poller POST to our own `/scim/v2/...`
endpoint "as an internal SCIM client". **That is not implementable**, and
finding out why is worth writing down: we store `scim_token_hash` — a
bcrypt digest. The plaintext bearer is shown to the operator once, at
directory-connect time, and never persisted. The gateway cannot
authenticate to its own SCIM endpoint, by design.

Calling `scim/users.py`'s service functions directly is better anyway: no
self-HTTP, no self-auth, no second copy of the reconciliation rules — and
identical audit rows, because those functions are what write them. A
polled deactivation is indistinguishable in `admin_audit_log` from a
pushed one, which is the correct outcome: the auditor cares that the
directory said so, not which transport carried it.

## Deactivate, never delete

Suspended, archived or absent users are soft-deactivated
(`scim.deactivate_user`), and the existing `HardDeleteSweeper` removes
them after its 7-day grace. The poller has no hard-delete path at all.

That matters because polling has a failure mode a push does not: if the
API returns a *partial* page — a transient error mid-pagination, a
permission narrowed halfway through — "absent from the response" is
indistinguishable from "deleted". A soft deactivation is recoverable
within the grace window (the next successful poll reactivates); a hard
delete is not. So a partial read must never be able to destroy anything,
and `_reconcile` refuses to act on absence unless the listing completed.

## Auth

Service account + domain-wide delegation: sign a JWT asserting the
delegated admin's identity, exchange it for an access token (RFC 7523),
call the Admin SDK. The gateway already does RFC 7523 for upstream
service accounts (A2); this is the same grant pointed at Google.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import IdpDirectory, User
from vyuu_gateway.db.session import bind_tenant_context
from vyuu_gateway.scim import users as scim_users
from vyuu_gateway.scim.schemas import ScimName, ScimUser

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]

_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 — endpoint, not a secret
_DIRECTORY_USERS_URL = "https://admin.googleapis.com/admin/directory/v1/users"
_SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly"

# Google caps `maxResults` at 500 for users.list.
_PAGE_SIZE = 500
# Refuse to walk forever. A directory larger than this per cycle is a
# real deployment, but it needs a conversation about incremental sync
# rather than an unbounded loop in a background task.
_MAX_PAGES = 40

DEFAULT_INTERVAL_SECONDS = 300.0


class WorkspacePollError(Exception):
    """The Workspace directory could not be read.

    Never results in deactivations — see `_reconcile`. An outage must not
    look like a mass termination.
    """


@dataclass
class PollReport:
    """What one cycle did, per directory."""

    directories_polled: int = 0
    created: int = 0
    reactivated: int = 0
    deactivated: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def changed(self) -> int:
        return self.created + self.reactivated + self.deactivated


@dataclass(frozen=True)
class WorkspaceUser:
    """One entry from the Admin SDK, narrowed to what we act on."""

    external_id: str
    email: str
    display_name: str | None
    active: bool

    def to_scim(self) -> ScimUser:
        """Render as the SCIM shape the existing service functions take,
        so a polled user and a pushed user are the same object by the
        time anything writes it."""

        return ScimUser(
            userName=self.email,
            externalId=self.external_id,
            displayName=self.display_name,
            active=self.active,
            name=ScimName(),
            emails=[{"value": self.email, "primary": True}],
        )


def parse_workspace_user(raw: dict[str, Any]) -> WorkspaceUser | None:
    """Map an Admin SDK user resource. None when unusable.

    `suspended` and `archived` both mean "should not have access".
    Google models them separately (suspended = disabled, archived = kept
    for retention without a licence); for our purposes they are the same
    answer, and treating archived as active would leave departed staff
    with working credentials.
    """

    external_id = raw.get("id")
    email = raw.get("primaryEmail")
    if not external_id or not email:
        return None
    name = raw.get("name") or {}
    display = name.get("fullName") or None
    active = not (raw.get("suspended") or raw.get("archived"))
    return WorkspaceUser(
        external_id=str(external_id),
        email=str(email).strip().lower(),
        display_name=display,
        active=bool(active),
    )


async def fetch_access_token(
    *,
    service_account_json: str,
    admin_subject: str,
    http: httpx.AsyncClient,
    now: float | None = None,
) -> str:
    """RFC 7523 jwt-bearer against Google, impersonating `admin_subject`.

    Domain-wide delegation is what lets a service account act as a real
    admin. `sub` is the impersonation; without it Google rejects the
    assertion, because a service account has no directory of its own.
    """

    try:
        credentials = json.loads(service_account_json)
        private_key = credentials["private_key"]
        client_email = credentials["client_email"]
    except (ValueError, KeyError, TypeError) as exc:
        raise WorkspacePollError(
            "workspace service-account JSON is malformed or missing "
            "private_key / client_email"
        ) from exc

    issued_at = int(now if now is not None else time.time())
    assertion = jwt.encode(
        {
            "iss": client_email,
            "sub": admin_subject,
            "scope": _SCOPE,
            "aud": _GOOGLE_TOKEN_URL,
            "iat": issued_at,
            "exp": issued_at + 3600,
        },
        private_key,
        algorithm="RS256",
    )
    try:
        response = await http.post(
            _GOOGLE_TOKEN_URL,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            },
            headers={"Accept": "application/json"},
        )
    except httpx.HTTPError as exc:
        raise WorkspacePollError(
            f"google token endpoint unreachable: {exc.__class__.__name__}"
        ) from exc
    if response.status_code != 200:
        # Google's error body names the misconfiguration (unauthorized
        # client, invalid scope) and contains no secret — but it is
        # third-party text, so it is bounded before it reaches a log.
        detail = " ".join(response.text.split())[:200]
        raise WorkspacePollError(
            f"google token exchange failed ({response.status_code}): {detail}"
        )
    token = response.json().get("access_token")
    if not isinstance(token, str) or not token:
        raise WorkspacePollError("google token response carried no access_token")
    return token


async def list_workspace_users(
    *, access_token: str, customer_id: str, http: httpx.AsyncClient
) -> list[WorkspaceUser]:
    """Walk `users.list` to completion.

    Raises on ANY page failing. Returning a partial list would let a
    transient error read as "these users no longer exist" — see the
    module docstring on why absence must never be inferred from an
    incomplete read.
    """

    users: list[WorkspaceUser] = []
    page_token: str | None = None
    for _page in range(_MAX_PAGES):
        params: dict[str, str] = {
            "customer": customer_id,
            "maxResults": str(_PAGE_SIZE),
            # `projection=basic` keeps the payload small; we only read
            # id / primaryEmail / name / suspended / archived.
            "projection": "basic",
        }
        if page_token:
            params["pageToken"] = page_token
        try:
            response = await http.get(
                _DIRECTORY_USERS_URL,
                params=params,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise WorkspacePollError(
                f"admin directory unreachable: {exc.__class__.__name__}"
            ) from exc
        if response.status_code != 200:
            detail = " ".join(response.text.split())[:200]
            raise WorkspacePollError(
                f"admin directory returned {response.status_code}: {detail}"
            )
        body = response.json()
        for raw in body.get("users") or []:
            parsed = parse_workspace_user(raw)
            if parsed is not None:
                users.append(parsed)
        page_token = body.get("nextPageToken")
        if not page_token:
            return users
    raise WorkspacePollError(
        f"admin directory listing exceeded {_MAX_PAGES} pages; "
        "incremental sync is needed for a directory this size"
    )


def reconcile(
    db: Session,
    *,
    directory: IdpDirectory,
    workspace_users: list[WorkspaceUser],
    listing_complete: bool,
    report: PollReport,
) -> None:
    """Apply the directory's state to our `users` rows.

    Creates and reactivations run whenever we have data. **Deactivations
    only run when `listing_complete`** — absence is only meaningful if we
    know we saw everything.
    """

    by_external_id = {u.external_id: u for u in workspace_users}

    existing = list(
        db.scalars(
            select(User).where(
                User.tenant_id == directory.tenant_id,
                User.idp_directory_id == directory.id,
            )
        ).all()
    )
    existing_by_external_id = {
        u.external_id: u for u in existing if u.external_id is not None
    }

    for external_id, remote in by_external_id.items():
        local = existing_by_external_id.get(external_id)
        if local is None:
            if not remote.active:
                # Never seen here and already inactive there — nothing to
                # provision. Creating it just to deactivate it would
                # manufacture two audit rows for a non-event.
                continue
            try:
                scim_users.create_from_scim(
                    db, directory=directory, payload=remote.to_scim()
                )
                report.created += 1
            except scim_users.ScimUserExists:
                # Raced with a JIT sign-in creating the same user. The
                # sign-in path wins; nothing to reconcile.
                logger.info(
                    "workspace_poll_user_already_exists",
                    extra={"external_id": external_id},
                )
            continue
        if remote.active and local.disabled_at is not None:
            scim_users.set_active(db, directory=directory, user=local, active=True)
            report.reactivated += 1
        elif not remote.active and local.disabled_at is None:
            scim_users.set_active(db, directory=directory, user=local, active=False)
            report.deactivated += 1

    if not listing_complete:
        return
    for external_id, local in existing_by_external_id.items():
        if external_id in by_external_id or local.disabled_at is not None:
            continue
        # Gone from the directory entirely. Soft-deactivate only — the
        # hard-delete sweeper applies the 7-day grace, which is what makes
        # a wrong answer here recoverable.
        scim_users.set_active(db, directory=directory, user=local, active=False)
        report.deactivated += 1


class WorkspacePollingAdapter:
    """Async cron-style poller. Same shape as `HardDeleteSweeper` —
    `start()` / `stop()` / `run_one_cycle()` — so it is testable without
    `asyncio.sleep`."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
        secret_store: Any,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
        http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._secret_store = secret_store
        self._interval = max(30.0, float(interval_seconds))
        self._http_client_factory = http_client_factory or (
            lambda: httpx.AsyncClient(timeout=30.0)
        )
        self._task: asyncio.Task[None] | None = None
        self._cycle_count = 0
        self._last_report = PollReport()

    @property
    def cycle_count(self) -> int:
        return self._cycle_count

    @property
    def last_report(self) -> PollReport:
        return self._last_report

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def aclose(self) -> None:
        await self.stop()

    async def _run(self) -> None:
        while True:
            try:
                await self.run_one_cycle()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — never crash the worker
                logger.warning("workspace_poll_cycle_failed", exc_info=True)
            await asyncio.sleep(self._interval)

    async def run_one_cycle(self) -> PollReport:
        report = PollReport()
        for tenant_id, directory_id in self._enabled_directories():
            try:
                await self._poll_directory(tenant_id, directory_id, report)
            except WorkspacePollError as exc:
                # One directory's outage must not stop the others, and
                # must not deactivate anybody.
                report.errors.append(f"{directory_id}: {exc}")
                logger.warning(
                    "workspace_poll_directory_failed",
                    extra={"directory_id": str(directory_id), "error": str(exc)},
                )
        self._cycle_count += 1
        self._last_report = report
        return report

    def _enabled_directories(self) -> list[tuple[UUID, UUID]]:
        """Untenanted scan for work. `idp_directories` is FORCE RLS, so
        this needs the same `app.scim_bootstrap` capability the SCIM auth
        path uses — but we would rather not widen that flag's blast
        radius, so we walk tenants instead."""

        from vyuu_gateway.db.models import Tenant

        with self._session_factory() as session:
            tenant_ids = [row[0] for row in session.execute(select(Tenant.id)).all()]
        out: list[tuple[UUID, UUID]] = []
        for tenant_id in tenant_ids:
            with self._session_factory() as session:
                bind_tenant_context(session, tenant_id)
                rows = session.scalars(
                    select(IdpDirectory.id).where(
                        IdpDirectory.tenant_id == tenant_id,
                        IdpDirectory.workspace_polling_enabled.is_(True),
                    )
                ).all()
            out.extend((tenant_id, directory_id) for directory_id in rows)
        return out

    async def _poll_directory(
        self, tenant_id: UUID, directory_id: UUID, report: PollReport
    ) -> None:
        with self._session_factory() as session:
            bind_tenant_context(session, tenant_id)
            directory = session.get(IdpDirectory, directory_id)
            if directory is None:
                return
            ref = directory.workspace_service_account_ref
            customer_id = directory.workspace_customer_id
            admin_subject = directory.workspace_admin_subject
        if not ref or not customer_id or not admin_subject:
            raise WorkspacePollError(
                "workspace polling is enabled but service-account ref, "
                "customer id or admin subject is unset"
            )

        service_account_json = await self._secret_store.get_secret(tenant_id, ref)

        async with self._http_client_factory() as http:
            token = await fetch_access_token(
                service_account_json=service_account_json,
                admin_subject=admin_subject,
                http=http,
            )
            workspace_users = await list_workspace_users(
                access_token=token, customer_id=customer_id, http=http
            )

        with self._session_factory() as session:
            bind_tenant_context(session, tenant_id)
            directory = session.get(IdpDirectory, directory_id)
            if directory is None:
                return
            reconcile(
                session,
                directory=directory,
                workspace_users=workspace_users,
                # We only get here when the listing walked to completion —
                # `list_workspace_users` raises otherwise.
                listing_complete=True,
                report=report,
            )
            directory.workspace_last_polled_at = datetime.now(UTC)
            session.commit()
        report.directories_polled += 1
