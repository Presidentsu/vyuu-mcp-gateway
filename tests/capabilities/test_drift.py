from uuid import uuid4

from vyuu_gateway.capabilities.client import CapabilityDescriptor
from vyuu_gateway.capabilities.drift import detect_capability_drift
from vyuu_gateway.db.models import McpCapability, McpCapabilityKind


def capability_row(
    *,
    kind: McpCapabilityKind = McpCapabilityKind.TOOL,
    name: str,
    schema_json: dict[str, object],
) -> McpCapability:
    return McpCapability(
        id=uuid4(),
        tenant_id=uuid4(),
        server_id=uuid4(),
        kind=kind,
        name=name,
        schema_json=schema_json,
        deprecated=False,
    )


def descriptor(
    *,
    kind: McpCapabilityKind = McpCapabilityKind.TOOL,
    name: str,
    schema_json: dict[str, object],
) -> CapabilityDescriptor:
    return CapabilityDescriptor(kind=kind, name=name, schema_json=schema_json)


def test_detect_capability_drift_reports_added_removed_changed_and_unchanged() -> None:
    drift = detect_capability_drift(
        previous=[
            capability_row(name="unchanged", schema_json={"type": "object"}),
            capability_row(name="changed", schema_json={"required": ["before"]}),
            capability_row(name="removed", schema_json={"type": "object"}),
        ],
        current=[
            descriptor(name="unchanged", schema_json={"type": "object"}),
            descriptor(name="changed", schema_json={"required": ["after"]}),
            descriptor(name="added", schema_json={"type": "object"}),
        ],
    )

    assert drift.has_changes
    assert [(change.kind, change.name) for change in drift.added] == [
        (McpCapabilityKind.TOOL, "added")
    ]
    assert [(change.kind, change.name) for change in drift.removed] == [
        (McpCapabilityKind.TOOL, "removed")
    ]
    assert [(change.kind, change.name) for change in drift.changed] == [
        (McpCapabilityKind.TOOL, "changed")
    ]
    assert [(change.kind, change.name) for change in drift.unchanged] == [
        (McpCapabilityKind.TOOL, "unchanged")
    ]


def test_detect_capability_drift_treats_kind_and_name_as_identity() -> None:
    drift = detect_capability_drift(
        previous=[
            capability_row(
                kind=McpCapabilityKind.RESOURCE,
                name="status",
                schema_json={"type": "resource"},
            )
        ],
        current=[
            descriptor(
                kind=McpCapabilityKind.TOOL,
                name="status",
                schema_json={"type": "tool"},
            )
        ],
    )

    assert [(change.kind, change.name) for change in drift.added] == [
        (McpCapabilityKind.TOOL, "status")
    ]
    assert [(change.kind, change.name) for change in drift.removed] == [
        (McpCapabilityKind.RESOURCE, "status")
    ]
