# Customising the platform

Every integration point is a small Python Protocol or a table you can
edit from the console. This page lists them from least to most invasive.

## 1. Configure, don't code

Most behaviour is environment-driven (see
[`DEPLOYMENT.md`](DEPLOYMENT.md#configuration-reference)): identity
provider, secret-store backend, back-pressure, payload caps, retention,
SIEM target, telemetry, OIDC apps, MRTR allow-lists, SSRF lists.

Per-tenant behaviour is data, edited in the operator console and stored
in Postgres: identity-provider directories, API-key lifetime policies,
the risk-classifier model and key reference, SIEM targets, bundle
visibility, grants, JIT windows, tool elevation.

## 2. Swap a backend behind a Protocol

Each seam is constructed in `src/vyuu_gateway/main.py::create_app`, and
every one can be injected as a keyword argument (which is also how the
tests do it).

| Seam | Protocol | Ships with | Add your own |
|---|---|---|---|
| Inbound identity | `identity/provider.py::IdentityProvider` | `ApiKeyIdentityProvider`, EMA / ID-JAG, `FakeIdentityProvider` (lab) | Implement `validate_principal(...)`; return a `Principal` |
| Policy | `policy/interfaces.py::PolicyProvider` | `SimplePolicyProvider`, `ManagementPlanePolicyProvider` | Return `PolicyDecision.allow/deny(...)` with `rule_id`; opt into raw capture per rule |
| Secret store | `secrets/store.py::SecretStore` | memory, Vault KV v2, AWS Secrets Manager, Kubernetes Secrets | `async get_secret(tenant_id, ref)`; add `put` only if writes from the console are acceptable |
| Session registry | `sessions/registry.py::SessionRegistry` | in-memory, Redis | Any shared store keyed by `(tenant, session_id)` |
| Audit producer | `audit/producer.py::AuditProducer` | Kafka, NATS JetStream, disk spool, Splunk HEC (via `siem/`) | `async produce(event)`; wrap in `AsyncAuditEmitter` for a queue + spool |
| Graph events | `graph/emitter.py::GraphEventEmitter` | no-op, in-memory, Kafka/NATS | Same shape as audit |
| Envelope cipher | `crypto/` | local master key, AWS KMS | Seal/unseal bytes with a key you control |
| Upstream OAuth | `upstream/oauth*.py` | client-credentials, auth-code + DCR/CIMD, JWT-bearer | Extend `OAuthTokenProvider` |
| Telemetry | `telemetry/__init__.py::Telemetry` | no-op, OpenTelemetry | Implement `span()` and `record_*()`; never raise |
| Risk model vendor | `risk/providers.py` | Anthropic, OpenAI, Gemini | Add a `KNOWN_MODELS` entry and a wire-format adapter |

## 3. Extend the SIEM export

`siem/events.py` defines one `SiemEvent` per category. To ship a new
family of events, build one with `SiemEvent(category=..., tenant_id=...,
body=...)` and call `siem.registry.emit(event)`; routing, batching, retry
and per-tenant isolation are handled by the exporter. To target another
SIEM vendor, implement the two methods of `siem/hec.py::SplunkHecClient`
(`send_batch`, `aclose`) for its wire format — the event model and the
exporter do not change.

## 4. Add an operator-console panel

Both web apps are single Python strings served by FastAPI, so a panel is
a router plus three additions to `api/operator_ui.py`:

1. a sidebar button `<button class="nav-item" data-nav="my-panel">`;
2. a `<section class="panel events-panel-v2" data-nav="my-panel">` using
   the shared header (eyebrow · serif title · one-line subtitle · actions);
3. a `loadMyPanel()` function registered in the `loaders` map inside
   `setActiveNav`, building DOM nodes (the CSP forbids `style=`
   attributes; set styles through `element.style`).

Design tokens (`:root` in the CSS block) carry the palette, type scale,
radii and density; new rules should use them rather than literal values.
[`onboarding/FRONTEND.md`](onboarding/FRONTEND.md) has the full pattern.

## 5. Add an admin action

Any mutating operator endpoint calls
`record_admin_action(db, tenant_id=..., actor=AdminAuditActor.operator(op),
action="thing.verb", target=..., detail={...})` before `db.commit()`.
That one call gives the auditor's table, the Admin audit panel and the
SIEM `admin_action` stream the row — at commit, never on rollback.

## 6. Add a table

Follow [`onboarding/MIGRATIONS.md`](onboarding/MIGRATIONS.md): a
tenant-scoped table gets `tenant_id`, an RLS policy on
`app.current_tenant_id`, and — when it holds audit or secret material —
`FORCE ROW LEVEL SECURITY`. Add the table name to the inventory in
`tests/tenant_isolation/test_tenant_isolation.py`; the suite fails until
you do, which is the point.

## 7. Change the connector catalog

`upstream/connector_catalog.py` lists the SaaS presets the register
wizard offers (runtime, URL, transport, OAuth shape, which refs the
operator must supply). Add an entry; no UI change needed.

## 8. Brand and theme

Colours, type and spacing are CSS custom properties defined once per
app (`--vyuu-*`), with a dark-theme override block. Replace the brand
lockup SVG (`_LOGO_LOCKUP` in `api/operator_ui.py`) and the token
values; components inherit them.

## 9. Running your own policy or identity service

`ManagementPlanePolicyProvider` pulls policy documents from
`VYUU_MANAGEMENT_PLANE_POLICY_BASE_URL` on a TTL with last-known-good
fallback; the identity chain accepts EMA tokens minted from your IdP's
ID-JAG. Both are the intended hooks for a central management plane —
the gateway stays a data plane.
