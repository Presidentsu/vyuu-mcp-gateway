"""CRED-1 · operator API for API-key lifetime policy.

See `registry/api_key_policy_service.py` for the resolution rules. This
module is transport only: schemas, HTTP status codes, and the one thing
the service cannot decide — that applying a policy to already-issued
keys is a separate, deliberate request rather than a side effect of
saving one.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.audit.admin_audit import AdminAuditActor
from vyuu_gateway.db.models import ApiKeyPrincipalKind, Group, User
from vyuu_gateway.operator_auth.dependency import (
    AuthenticatedOperator,
    authenticate_operator,
)
from vyuu_gateway.registry.api_key_policy_service import (
    MAX_TTL_SECONDS,
    ApiKeyPolicyError,
    apply_to_existing_keys,
    delete_policy,
    find_nonconforming_keys,
    list_policies,
    upsert_policy,
)

router = APIRouter(prefix="/admin/api-key-policies", tags=["admin"])


class ApiKeyPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    principal_kind: ApiKeyPrincipalKind
    principal_id: UUID
    # Resolved at read time so the console can name the group or user
    # instead of printing a UUID at an operator reviewing exceptions.
    principal_display: str | None = None
    max_ttl_seconds: int
    note: str | None = None
    created_at: datetime
    updated_at: datetime


class NonConformingKeyResponse(BaseModel):
    key_id: UUID
    user_id: UUID
    user_email: str | None
    label: str
    expires_at: datetime | None
    allowed_expires_at: datetime


class ApiKeyPolicyListResponse(BaseModel):
    policies: list[ApiKeyPolicyResponse]
    max_ttl_seconds_allowed: int
    # Keys already issued that outlive the policy now in force. Almost
    # always the ones minted before any policy existed, carrying no
    # expiry at all — the exact population the feature is aimed at.
    nonconforming: list[NonConformingKeyResponse]


class UpsertApiKeyPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_kind: ApiKeyPrincipalKind
    # Ignored for tenant scope, where the tenant's own id is used — a
    # caller cannot create a second, unreachable default.
    principal_id: UUID | None = None
    max_ttl_seconds: int = Field(gt=0, le=MAX_TTL_SECONDS)
    note: str | None = Field(default=None, max_length=500)


class ApplyExistingResponse(BaseModel):
    keys_updated: int


def _displays(db: Session, tenant_id: UUID) -> dict[UUID, str]:
    out: dict[UUID, str] = {}
    for gid, name in db.execute(
        select(Group.id, Group.name).where(Group.tenant_id == tenant_id)
    ).all():
        out[gid] = str(name)
    for uid, email in db.execute(
        select(User.id, User.email).where(User.tenant_id == tenant_id)
    ).all():
        out[uid] = str(email)
    return out


@router.get("", response_model=ApiKeyPolicyListResponse)
def list_api_key_policies_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> ApiKeyPolicyListResponse:
    tenant_id = operator.tenant_id
    names = _displays(db, tenant_id)
    rows = []
    for policy in list_policies(db, tenant_id=tenant_id):
        item = ApiKeyPolicyResponse.model_validate(policy)
        item.principal_display = (
            "Everyone in this tenant"
            if policy.principal_kind == ApiKeyPrincipalKind.TENANT.value
            else names.get(policy.principal_id)
        )
        rows.append(item)

    offenders = []
    for item in find_nonconforming_keys(db, tenant_id=tenant_id):
        offenders.append(
            NonConformingKeyResponse(
                key_id=item.key_id,
                user_id=item.user_id,
                user_email=names.get(item.user_id),
                label=item.label,
                expires_at=item.expires_at,
                allowed_expires_at=item.allowed_expires_at,
            )
        )
    return ApiKeyPolicyListResponse(
        policies=rows,
        max_ttl_seconds_allowed=MAX_TTL_SECONDS,
        nonconforming=offenders,
    )


@router.put("", response_model=ApiKeyPolicyResponse)
def upsert_api_key_policy_endpoint(
    request: UpsertApiKeyPolicyRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> ApiKeyPolicyResponse:
    tenant_id = operator.tenant_id
    principal_id = (
        tenant_id
        if request.principal_kind == ApiKeyPrincipalKind.TENANT
        else request.principal_id
    )
    if principal_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="principal_id is required for group and user policies",
        )
    try:
        row = upsert_policy(
            db,
            tenant_id=tenant_id,
            principal_kind=request.principal_kind,
            principal_id=principal_id,
            max_ttl_seconds=request.max_ttl_seconds,
            note=request.note,
            created_by=operator.operator_id,
            actor=AdminAuditActor.operator(operator),
        )
    except ApiKeyPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    item = ApiKeyPolicyResponse.model_validate(row)
    item.principal_display = (
        "Everyone in this tenant"
        if row.principal_kind == ApiKeyPrincipalKind.TENANT.value
        else _displays(db, tenant_id).get(row.principal_id)
    )
    return item


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_api_key_policy_endpoint(
    policy_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> None:
    try:
        delete_policy(
            db,
            tenant_id=operator.tenant_id,
            policy_id=policy_id,
            actor=AdminAuditActor.operator(operator),
        )
    except ApiKeyPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@router.post("/apply-existing", response_model=ApplyExistingResponse)
def apply_existing_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> ApplyExistingResponse:
    """Bring already-issued keys under the current policy.

    Its own endpoint on purpose. Saving a policy states intent;
    shortening credentials that are in use is an outage for whoever
    holds them, and the operator should choose when that lands rather
    than discover it as a side effect.
    """

    updated = apply_to_existing_keys(
        db,
        tenant_id=operator.tenant_id,
        actor=AdminAuditActor.operator(operator),
    )
    return ApplyExistingResponse(keys_updated=updated)
