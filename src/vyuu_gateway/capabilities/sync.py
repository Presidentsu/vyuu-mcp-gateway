from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol, cast
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.capabilities.client import CapabilityDescriptor, McpCapabilityClient
from vyuu_gateway.capabilities.drift import CapabilityDrift, detect_capability_drift
from vyuu_gateway.capabilities.risk import classify_tool_risk
from vyuu_gateway.db.models import (
    McpCapability,
    McpServer,
    McpServerHealthStatus,
    RiskCategory,
)


class CapabilitySyncResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    tenant_id: UUID
    server_id: UUID
    synced_at: datetime
    capability_count: int
    drift: CapabilityDrift


class CapabilitySyncService(Protocol):
    async def sync_server_capabilities(
        self,
        tenant_id: UUID,
        server_id: UUID,
        *,
        principal_id: UUID | None = None,
    ) -> CapabilitySyncResult:
        """Fetch, persist, and compare capabilities for a tenant-scoped MCP server.

        `principal_id` is required for phase-4 OAuth-authcode upstreams
        — sync needs an operator-resolved user with a stored token to
        authenticate the probe. Other auth modes ignore it.
        """


class CapabilitySyncSession(Protocol):
    def scalar(self, statement: Any) -> Any:
        """Return one scalar ORM result."""

    def scalars(self, statement: Any) -> Iterable[McpCapability]:
        """Return iterable ORM rows."""

    def add(self, instance: object) -> None:
        """Stage an ORM instance for persistence."""

    def commit(self) -> None:
        """Commit staged changes."""


class McpServerNotFoundError(Exception):
    """Raised when a server does not exist inside the requested tenant."""


# Closure type for the classify-helper passed into drift serialisation —
# takes a descriptor, returns the resolved risk_category string.
_ClassifyFn = Callable[[CapabilityDescriptor], str | None]


def _serialize_drift_for_storage(
    drift: CapabilityDrift,
    *,
    synced_at: datetime,
    current_descriptors: list[CapabilityDescriptor],
    previous_capabilities: list[McpCapability],
    classify: "_ClassifyFn",
) -> dict[str, Any]:
    """Build the JSON shape persisted to `mcp_servers.last_sync_drift`.

    Richer than the in-memory `CapabilityDrift` — each change row also
    carries the resolved `risk_category` so the operator console can
    tone the diff (added a `delete` tool? Show it red).

    Shape:
        {
          "synced_at": ISO8601,
          "has_changes": bool,
          "added":   [{"kind", "name", "risk_category"}, ...],
          "removed": [{"kind", "name", "risk_category"}, ...],
          "changed": [{"kind", "name", "risk_category"}, ...],
          "unchanged_count": int,
        }

    Wiped on the next sync run, so it always reflects "the last sync".
    History across multiple runs is a separate (later) feature.
    """
    current_by_key = {(d.kind, d.name): d for d in current_descriptors}
    previous_by_key = {(c.kind, c.name): c for c in previous_capabilities}

    def _entry_for(change_kind: str, name: str, *, source: str) -> dict[str, Any]:
        risk: str | None = None
        if source == "current":
            descriptor = current_by_key.get((change_kind, name))  # type: ignore[arg-type]
            # `_classify_descriptor` needs a server arg; the caller passes
            # a closure with the server bound so the JSON-builder stays
            # decoupled from the McpServer model.
            if descriptor is not None:
                risk = classify(descriptor)
        else:
            previous = previous_by_key.get((change_kind, name))  # type: ignore[arg-type]
            if previous is not None:
                # `risk_category` may come through as either an enum or a
                # raw string depending on whether SQLAlchemy hydrated it
                # — handle both safely.
                rc = previous.risk_category
                risk = rc.value if hasattr(rc, "value") else (str(rc) if rc else None)
        return {"kind": change_kind, "name": name, "risk_category": risk}

    def _kind_str(kind: object) -> str:
        # `CapabilityChange.kind` is typed as `McpCapabilityKind` but the
        # `removed` list builds its entries from previous-capabilities
        # ORM rows where SQLAlchemy may surface the column as a plain str
        # (the table is stored as Text + CheckConstraint, not a real
        # postgres enum). Coerce defensively.
        return kind.value if hasattr(kind, "value") else str(kind)

    return {
        "synced_at": synced_at.isoformat(),
        "has_changes": drift.has_changes,
        "added": [
            _entry_for(_kind_str(c.kind), c.name, source="current") for c in drift.added
        ],
        "removed": [
            _entry_for(_kind_str(c.kind), c.name, source="previous") for c in drift.removed
        ],
        "changed": [
            _entry_for(_kind_str(c.kind), c.name, source="current") for c in drift.changed
        ],
        "unchanged_count": len(drift.unchanged),
    }


class DatabaseCapabilitySyncService:
    def __init__(self, db: CapabilitySyncSession | Session, client: McpCapabilityClient) -> None:
        self._db = db
        self._client = client

    async def sync_server_capabilities(
        self,
        tenant_id: UUID,
        server_id: UUID,
        *,
        principal_id: UUID | None = None,
    ) -> CapabilitySyncResult:
        server = cast(
            McpServer | None,
            self._db.scalar(
                select(McpServer).where(
                    McpServer.tenant_id == tenant_id,
                    McpServer.id == server_id,
                )
            )
        )
        if server is None:
            raise McpServerNotFoundError

        current_capabilities = await self._client.list_capabilities(
            server, principal_id=principal_id
        )
        previous_capabilities = list(
            self._db.scalars(
                select(McpCapability).where(
                    McpCapability.tenant_id == tenant_id,
                    McpCapability.server_id == server_id,
                    McpCapability.deprecated.is_(False),
                )
            )
        )
        drift = detect_capability_drift(previous_capabilities, current_capabilities)
        synced_at = datetime.now(UTC)

        for capability in previous_capabilities:
            capability.deprecated = True

        for current_capability in current_capabilities:
            self._db.add(
                McpCapability(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    server_id=server_id,
                    kind=current_capability.kind,
                    name=current_capability.name,
                    schema_json=current_capability.schema_json,
                    risk_category=_classify_descriptor(current_capability, server),
                    observed_at=synced_at,
                    deprecated=False,
                )
            )

        server.last_capabilities_pulled_at = synced_at
        # A completed sync IS a successful connection: we opened a
        # session, spoke MCP and read the capability list. Recording that
        # as health closes a contradiction operators actually hit — the
        # automatic probe runs with a short timeout (5 s by default) and
        # races the first `uvx` / `npx` package fetch on a newly
        # registered stdio server, so the row is marked `down` while the
        # sync that follows pulls hundreds of capabilities. Nothing
        # re-probes, so a working upstream reads `down` until somebody
        # clicks. Evidence we already have should not be thrown away in
        # favour of a stale failure.
        server.health_status = McpServerHealthStatus.HEALTHY
        server.last_health_checked_at = synced_at
        server.last_health_error = None
        # Persist drift so the operator console can show "what changed"
        # on the server card without re-syncing. Wiped + replaced on
        # the next sync run — only ever holds the most recent snapshot.
        server.last_sync_drift = _serialize_drift_for_storage(
            drift,
            synced_at=synced_at,
            current_descriptors=current_capabilities,
            previous_capabilities=previous_capabilities,
            classify=lambda d: _classify_descriptor(d, server).value,
        )
        self._db.commit()

        return CapabilitySyncResult(
            tenant_id=tenant_id,
            server_id=server_id,
            synced_at=synced_at,
            capability_count=len(current_capabilities),
            drift=drift,
        )


async def seed_server_capabilities(
    db: CapabilitySyncSession | Session,
    *,
    tenant_id: UUID,
    server_id: UUID,
    descriptors: list[CapabilityDescriptor],
    risk_overrides: dict[str, RiskCategory] | None = None,
) -> CapabilitySyncResult:
    """Manually seed a server's capabilities without probing the upstream.

    Used when the upstream is unreachable, credential-gated, behind a
    compliance-freeze firewall, or simply not yet provisioned. Operators
    paste the tool catalog from vendor docs; the gateway treats the seed
    as the active capability snapshot, runs drift detection over the
    previous state, and writes new rows.

    Differs from `DatabaseCapabilitySyncService.sync_server_capabilities`
    in two ways:
    - No upstream probe — descriptors come from the caller verbatim.
    - `last_capabilities_pulled_at` is **not** updated. That field
      semantically means "synced from upstream"; manually-seeded rows
      should not pretend otherwise. Operator UI surfaces "manually
      seeded — not verified against upstream" based on this flag.

    `risk_overrides` lets operators pin a risk_category by capability
    name (e.g. compliance team forces `delete_diagram` to `delete`
    even if the heuristic would have classified it `write`). Names
    without an override go through the standard `classify_tool_risk`
    heuristic.
    """

    server = cast(
        McpServer | None,
        db.scalar(
            select(McpServer).where(
                McpServer.tenant_id == tenant_id,
                McpServer.id == server_id,
            )
        ),
    )
    if server is None:
        raise McpServerNotFoundError

    previous_capabilities = list(
        db.scalars(
            select(McpCapability).where(
                McpCapability.tenant_id == tenant_id,
                McpCapability.server_id == server_id,
                McpCapability.deprecated.is_(False),
            )
        )
    )
    drift = detect_capability_drift(previous_capabilities, descriptors)
    seeded_at = datetime.now(UTC)

    for capability in previous_capabilities:
        capability.deprecated = True

    overrides = risk_overrides or {}
    for descriptor in descriptors:
        risk = overrides.get(descriptor.name) or _classify_descriptor(descriptor, server)
        db.add(
            McpCapability(
                id=uuid4(),
                tenant_id=tenant_id,
                server_id=server_id,
                kind=descriptor.kind,
                name=descriptor.name,
                schema_json=descriptor.schema_json,
                risk_category=risk,
                observed_at=seeded_at,
                deprecated=False,
            )
        )

    # Note: `last_capabilities_pulled_at` is intentionally NOT touched
    # here — that field signals "verified against upstream", and a
    # manual seed has no such verification. We DO persist the drift
    # snapshot, though — operators want to see what their seed
    # changed compared to the prior catalogue.
    def _classify_with_overrides(d: CapabilityDescriptor) -> str | None:
        rc = overrides.get(d.name) or _classify_descriptor(d, server)
        return rc.value if rc else None

    server.last_sync_drift = _serialize_drift_for_storage(
        drift,
        synced_at=seeded_at,
        current_descriptors=descriptors,
        previous_capabilities=previous_capabilities,
        classify=_classify_with_overrides,
    )
    db.commit()

    return CapabilitySyncResult(
        tenant_id=tenant_id,
        server_id=server_id,
        synced_at=seeded_at,
        capability_count=len(descriptors),
        drift=drift,
    )


def list_capabilities_for_server(
    db: CapabilitySyncSession | Session,
    *,
    tenant_id: UUID,
    server_id: UUID,
) -> list[McpCapability]:
    """Return the active (non-deprecated) capability snapshot for a server.

    Tenant-scoped on the way in so the SQL filter and (when active) the RLS
    policy align. Used by the operator UI to show the operator the tools a
    registered server is currently exposing, so they can pick which to
    bundle into a virtual server.
    """

    return list(
        db.scalars(
            select(McpCapability)
            .where(
                McpCapability.tenant_id == tenant_id,
                McpCapability.server_id == server_id,
                McpCapability.deprecated.is_(False),
            )
            .order_by(McpCapability.kind, McpCapability.name)
        )
    )


def _classify_descriptor(
    descriptor: CapabilityDescriptor,
    server: McpServer,
) -> RiskCategory:
    schema = descriptor.schema_json
    description: str | None = None
    input_schema: Mapping[str, Any] | None = None
    if isinstance(schema, Mapping):
        raw_description = schema.get("description")
        if isinstance(raw_description, str):
            description = raw_description
        raw_input_schema = schema.get("inputSchema")
        if isinstance(raw_input_schema, Mapping):
            input_schema = raw_input_schema

    return classify_tool_risk(
        kind=descriptor.kind,
        name=descriptor.name,
        description=description,
        input_schema=input_schema,
        server=server,
    )
