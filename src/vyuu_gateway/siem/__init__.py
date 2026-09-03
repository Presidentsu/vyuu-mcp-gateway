"""SIEM export — ship every security-relevant event to a Splunk HEC endpoint.

Vyuu has three audit families that never meet: `AuditEvent` (tool calls
and connection-level rejections, fanned out through the audit chain),
`admin_audit_log` rows (written in the caller's transaction, read only by
the console) and structured stdout logs. A SIEM wants all of them in one
stream, plus two families that were never events at all — logins and
per-user tool authorisation.

This package is that stream:

- `events.py`    — `SiemEvent`, the one shape every category projects into
- `hec.py`       — Splunk HTTP Event Collector wire format + client
- `exporter.py`  — non-blocking batching exporter with per-target delivery
- `targets.py`   — where a tenant's (and the deployment's) HEC target comes from
- `bridges.py`   — hooks that turn existing audit / admin / log paths into events
- `registry.py`  — process-wide exporter handle for code with no `app.state`

Two tiers of target. A **deployment** target comes from `VYUU_SIEM_*`
env and receives everything, including gateway-wide log lines that carry
no tenant. A **tenant** target is configured by that tenant's admins in
the console and receives only events carrying that tenant's id. The
exporter never infers a tenant from event content.
"""
