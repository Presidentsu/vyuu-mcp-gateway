from dataclasses import dataclass, field

from vyuu_gateway.capabilities.client import CapabilityDescriptor
from vyuu_gateway.db.models import McpCapability, McpCapabilityKind

type CapabilityKey = tuple[McpCapabilityKind, str]


@dataclass(frozen=True)
class CapabilityChange:
    kind: McpCapabilityKind
    name: str


@dataclass(frozen=True)
class CapabilityDrift:
    added: list[CapabilityChange] = field(default_factory=list)
    removed: list[CapabilityChange] = field(default_factory=list)
    changed: list[CapabilityChange] = field(default_factory=list)
    unchanged: list[CapabilityChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)


def capability_key(capability: CapabilityDescriptor | McpCapability) -> CapabilityKey:
    return (capability.kind, capability.name)


def detect_capability_drift(
    previous: list[McpCapability],
    current: list[CapabilityDescriptor],
) -> CapabilityDrift:
    previous_by_key = {capability_key(capability): capability for capability in previous}
    current_by_key = {capability_key(capability): capability for capability in current}

    added: list[CapabilityChange] = []
    removed: list[CapabilityChange] = []
    changed: list[CapabilityChange] = []
    unchanged: list[CapabilityChange] = []

    for key, current_capability in sorted(current_by_key.items()):
        previous_capability = previous_by_key.get(key)
        change = CapabilityChange(kind=key[0], name=key[1])
        if previous_capability is None:
            added.append(change)
        elif previous_capability.schema_json != current_capability.schema_json:
            changed.append(change)
        else:
            unchanged.append(change)

    for key in sorted(previous_by_key.keys() - current_by_key.keys()):
        removed.append(CapabilityChange(kind=key[0], name=key[1]))

    return CapabilityDrift(
        added=added,
        removed=removed,
        changed=changed,
        unchanged=unchanged,
    )
