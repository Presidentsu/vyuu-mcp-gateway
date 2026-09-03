from enum import StrEnum


class AuditFailureMode(StrEnum):
    STRICT = "strict"
    CONTINUITY = "continuity"
    MONITOR = "monitor"
