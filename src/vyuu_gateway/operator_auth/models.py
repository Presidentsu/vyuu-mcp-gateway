"""Identity types for the operator (admin) API.

Distinct from `vyuu_gateway.identity` — that module models principals on the
MCP-tool-call data plane (endpoint sessions, server agents, API keys for
runtime traffic). This module models the human operator authenticated against
the gateway's admin/control surface (e.g., `POST /api/v1/servers`). The two
surfaces have different threat models, different credential lifetimes, and
different replacement timelines, so the types are kept separate by design.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class AuthenticatedOperator:
    """Operator identity resolved from a verified bearer token.

    `tenant_id` and `operator_id` here are *trusted* values produced by the
    auth provider after signature/issuer verification. Service-layer code
    must use these — never tenant_id supplied in a request body — when
    deciding which tenant a write lands under.
    """

    tenant_id: UUID
    operator_id: UUID
    display: str = ""
