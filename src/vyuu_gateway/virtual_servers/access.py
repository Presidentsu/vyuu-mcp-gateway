"""Visibility + grant enforcement for inbound MCP connections.

A vserver's `visibility` column dictates the default access policy:

- `public`  → any authenticated principal in the tenant can connect.
- `private` → the principal must have a non-revoked, non-expired grant
              in `virtual_server_grants`, either directly (principal_kind='user',
              principal_id=user.id) or transitively via a group they
              belong to (principal_kind='group', principal_id ∈ user.groups).

A single SELECT EXISTS query covers both grant paths — joins
`virtual_server_grants` with `user_group_memberships` for the group leg.

Compatibility with the lab / fake identity provider:
The fake provider returns principals whose `id` is a free-form string
(not a UUID into `users`). For private vservers, those principals fail
the grant check (no row matches) and get denied. The lab's pre-baked
demo vservers must be `visibility=public` for the lab to keep working.
The bootstrap script handles that.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import (
    GrantPrincipalKind,
    UserGroupMembership,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerVisibility,
)
from vyuu_gateway.identity.models import Principal, PrincipalType


class VirtualServerAccessDeniedError(Exception):
    """The principal does not have access to this vserver. 403 on inbound."""


def assert_principal_can_access_vserver(
    session: Session,
    *,
    tenant_id: UUID,
    vserver: VirtualServer,
    principal: Principal,
) -> None:
    """Raise `VirtualServerAccessDeniedError` if the principal cannot
    connect to `vserver`. No-op on success.

    `tenant_id` and `vserver.tenant_id` must already match — that's the
    inbound-route's URL-path responsibility, not this function's. We
    assume the caller has already validated tenant boundary.
    """

    if vserver.visibility == VirtualServerVisibility.PUBLIC:
        return

    # Only principals that resolve to a real `users.id` can hold grants.
    # `api_key` (production API-key provider) and `federated_user`
    # (EMA-1 ID-JAG → JIT directory user) both carry `id = str(users.id)`;
    # other types (endpoint_session / server_agent — test/lab shapes)
    # are denied on private vservers by default.
    if principal.type not in (
        PrincipalType.API_KEY,
        PrincipalType.FEDERATED_USER,
    ):
        raise VirtualServerAccessDeniedError(
            "principal type cannot hold grants on private vservers"
        )
    try:
        user_id = UUID(principal.id)
    except ValueError as exc:
        raise VirtualServerAccessDeniedError(
            "principal id is not a user uuid"
        ) from exc

    now = datetime.now(UTC)

    # Single query: does ANY non-revoked, non-expired grant exist for
    # this vserver that targets either the user directly or any of the
    # user's groups?
    direct_grant = (
        select(VirtualServerGrant.id)
        .where(
            VirtualServerGrant.vserver_id == vserver.id,
            VirtualServerGrant.tenant_id == tenant_id,
            VirtualServerGrant.principal_kind == GrantPrincipalKind.USER,
            VirtualServerGrant.principal_id == user_id,
            VirtualServerGrant.revoked_at.is_(None),
        )
    )
    group_grant = (
        select(VirtualServerGrant.id)
        .join(
            UserGroupMembership,
            UserGroupMembership.group_id == VirtualServerGrant.principal_id,
        )
        .where(
            VirtualServerGrant.vserver_id == vserver.id,
            VirtualServerGrant.tenant_id == tenant_id,
            VirtualServerGrant.principal_kind == GrantPrincipalKind.GROUP,
            VirtualServerGrant.revoked_at.is_(None),
            UserGroupMembership.user_id == user_id,
        )
    )

    candidates = list(session.scalars(direct_grant.union_all(group_grant)).all())
    if not candidates:
        raise VirtualServerAccessDeniedError("no active grant for this principal")

    # Optional: enforce expires_at. Pulled in a second query so the
    # primary EXISTS stays cheap. Could be folded in but the SQL gets
    # noisier; pre-mature optimization until measurement says otherwise.
    grant_rows = list(
        session.scalars(
            select(VirtualServerGrant).where(VirtualServerGrant.id.in_(candidates))
        ).all()
    )
    for grant in grant_rows:
        if grant.expires_at is None or grant.expires_at > now:
            return
    raise VirtualServerAccessDeniedError("all matching grants are expired")
