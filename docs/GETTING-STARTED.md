# Vyuu MCP Gateway — Getting started

**Audience.** DevOps / SRE / first-time deployers setting the gateway
up in their network or data centre. Walks from a clean Linux box to a
working production-grade deployment.

**Last revision:** 2026-05-01 (post A1 / mTLS / A2 / NHI dashboard +
relation graph + map / admin dashboard / Users-admin drill-in).

This guide has three deployment shapes:

1. **Single-VM POC** (~30 minutes) — one Linux box, Vault on the
   same host, single Postgres, no HA. Ideal for trying the gateway
   end-to-end before committing infrastructure.
2. **Production single-region** (~½ day) — k8s deployment with HA
   Postgres, Redis, Vault HA cluster, Kafka audit pipeline, NGINX
   ingress with TLS.
3. **Hybrid (gateway on-prem, secrets in AWS)** (~½ day) — same as
   production but pointing at AWS Secrets Manager via IAM Roles
   Anywhere instead of self-hosted Vault.

Pick the shape that matches your goal, follow the corresponding
section, then return to the **common operations** section at the
end for credential rotation / monitoring / etc.

> **Shortcut.** `deploy/setup/setup-linux.sh` / `setup-macos.sh` automate
> shapes 1 and 2 (Docker Compose on one host, or a Kubernetes namespace):
> prerequisites, secrets, migrations, first-admin bootstrap and a sign-in
> check. See [`deploy/setup/README.md`](../deploy/setup/README.md). The
> sections below remain the reference for what those scripts do and for
> the pieces they leave to you (TLS, HA Postgres, Vault).

---

## 0. Prerequisites

### Software (on the deployment host or build environment)

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.12+ (3.13 / 3.14 recommended) | Runtime |
| pip | latest | Package install |
| Postgres client (`psql`) | 14+ | Bootstrap + manual queries |
| Postgres server | 14+ (16+ recommended) | Catalog + audit DB |
| Redis | 6+ (optional) | Multi-instance session registry |
| Vault | 1.18+ (option A — POC + on-prem) | Secret storage |
| OR AWS account | (option B — AWS-native) | AWS Secrets Manager + IAM |
| Docker (optional) | 24+ | If using container deployment |
| `node` | 18+ (CI only — for JS-syntax test) | Test gating |

### Network access required

- Outbound HTTPS (port 443) to:
  - Each upstream MCP server's host
  - Microsoft Entra ID / Google OIDC issuers (if using OIDC)
  - AWS Secrets Manager region endpoint (if using AWS backend)
  - Vault address (if using Vault)
- Inbound HTTPS to the gateway from agent clients (Cursor, Claude
  Desktop, your AIShield Agent, etc.) — typically through a load
  balancer / ingress.

### Decisions to make before starting

1. **Which secret store?**
   - Vault — recommended for on-prem-only deployments and POCs.
   - AWS Secrets Manager — recommended if you're AWS-native or
     already standardise secrets there.
2. **Which inbound identity provider?**
   - `api_key` — production. Real users sign in to `/portal`,
     issue API keys for their MCP clients.
   - `fake` — lab / POC. Skips real identity.
3. **Which audit pipeline?**
   - Local-only (in-memory, lost on restart) — POC.
   - Kafka — production durable, most common.
   - NATS — production durable, lower-overhead alternative.
4. **TLS termination point?**
   - k8s NGINX ingress + cert-manager (recommended)
   - Caddy on a VM
   - Cloud LB (AWS ALB, GCP Cloud Run, Azure App Service)
5. **One pod or many?**
   - One: skip Redis.
   - Many: Redis is required for shared session registry.

---

## 1. Single-VM POC (~30 minutes)

The fastest path to a working gateway. Ubuntu 22.04 / 24.04 example;
adapt for your distro.

### 1.1 Install Postgres

```bash
sudo apt update
sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable --now postgresql
```

Create a database + user:

```bash
sudo -u postgres psql <<'EOF'
CREATE USER vyuu WITH PASSWORD 'change-me-strong-12+chars';
CREATE DATABASE vyuu_gateway OWNER vyuu;
\c vyuu_gateway
-- The gateway uses the GUC `app.current_tenant_id` for RLS scoping.
-- Pre-create it so RLS policies on tenant-scoped tables can read it.
ALTER DATABASE vyuu_gateway SET app.current_tenant_id = '00000000-0000-0000-0000-000000000000';
EOF
```

### 1.2 Install Vault (POC mode — single node, in-memory)

```bash
wget -O- https://apt.releases.hashicorp.com/gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update
sudo apt install -y vault

# Quick dev mode for the POC (DO NOT use for prod):
vault server -dev -dev-listen-address=127.0.0.1:8200 \
  -dev-root-token-id=dev-only-root-token &
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-only-root-token
```

For production you'll want the HA setup — see section 2.4 below.

### 1.3 Install + run the gateway

```bash
git clone <your-repo> /opt/vyuu-gateway
cd /opt/vyuu-gateway

# Use a venv to keep system Python clean
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .

# Apply migrations
export VYUU_DATABASE_URL="postgresql+psycopg://vyuu:change-me-strong-12+chars@127.0.0.1:5432/vyuu_gateway"
alembic upgrade head
```

Generate signing secrets (once — keep them safe):

```bash
export VYUU_OPERATOR_AUTH_SIGNING_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
export VYUU_PORTAL_SESSION_SIGNING_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
```

Save both somewhere durable — losing the operator signing secret
invalidates every issued operator token; losing the portal session
secret invalidates every signed-in user's session (they'll need to
sign in again).

Set the bootstrap admin credentials:

```bash
export VYUU_BOOTSTRAP_TENANT_NAME="Acme Corp"
export VYUU_BOOTSTRAP_ADMIN_EMAIL="admin@your-corp.example"
export VYUU_BOOTSTRAP_ADMIN_PASSWORD="initial-password-12+chars-rotate-me"
export VYUU_BOOTSTRAP_ADMIN_DISPLAY="Acme Admin"
```

Wire production-grade defaults:

```bash
export VYUU_INBOUND_IDENTITY_PROVIDER=api_key
export VYUU_SECRET_STORE_BACKEND=vault
export VYUU_VAULT_ADDR=http://127.0.0.1:8200
export VYUU_VAULT_TOKEN=dev-only-root-token

# OPTIONAL: enable raw-input/output capture for the operator dashboard
# (privacy-by-default OFF in production; ON makes the Events panel show
# full request + response bodies — fine for POC, decide before prod).
export VYUU_AUDIT_CAPTURE_RAW_DEFAULT=true
```

Start the gateway:

```bash
uvicorn vyuu_gateway.main:create_app --factory \
  --host 0.0.0.0 --port 8000 --workers 4
```

You should see:

```
{"level":"INFO","logger":"vyuu_gateway.bootstrap","message":"bootstrap_admin_seeded",
 "tenant_id":"...","operator_id":"...","email":"admin@your-corp.example"}
{"level":"INFO","logger":"uvicorn.error","message":"Uvicorn running on http://0.0.0.0:8000"}
```

Note the `tenant_id` and `operator_id` from the bootstrap line — you'll
need them.

### 1.4 First sign-in

Open `http://<your-host>:8000/operator` in a browser.

Sign in:
- **Tenant ID:** `<from bootstrap log>`
- **Email:** `admin@your-corp.example`
- **Password:** (the value of `VYUU_BOOTSTRAP_ADMIN_PASSWORD`)

After login the operator console should render — Gateway health,
Registered servers (empty), Virtual servers (empty), Admins (one row:
you), etc.

The same admin can also sign in to `/portal` with the same credentials
to test the end-user surface.

### 1.5 Register your first MCP

In the operator console, scroll to the **Register MCP server** form.
Try a public MCP first (no auth needed):

- **Display name:** `drawio-http`
- **Source type:** `http`
- **Source location:** `https://mcp.draw.io/mcp`
- **Transport:** `streamable_http`
- (leave auth fields empty)

Submit. The new server appears in the **Registered servers** panel.

Click **Sync capabilities** on the server card — capabilities populate.

Scroll to **Create virtual server**:
- **Name:** `drawio-public`
- **Tools:** copy/paste the `server_id:tool_name` lines from the
  capabilities panel.
- Submit.

The vserver appears. Toggle visibility to `public` via the **Manage
access** expander on its card so any tenant principal can use it.

The MCP URL for clients is:
`http://<your-host>:8000/v/<tenant_id>/drawio-public/mcp`

### 1.6 First end-user connection

Open `/portal` in a new tab (still as the bootstrap admin — they're
both an operator AND a user, since the bootstrap seeded both rows).

- **Catalog tab** → see `drawio-public` with the `public` + `granted`
  pills.
- Click **Show config** → copy the Cursor JSON.
- **API keys tab** → fill label "Cursor" → **Issue key**. Copy the
  plaintext (starts with `vyuu_user_`). It's shown only once.
- Replace `<YOUR_API_KEY>` in the Cursor JSON with the plaintext.
- Paste into Cursor's `~/.cursor/mcp.json` and restart Cursor.

> **One config flip needed for real clients.** The default identity
> provider (`fake`) trusts `x-vyuu-*` headers, not `Authorization:
> Bearer` — Cursor / Claude Desktop / curl all use the latter. Set
> `VYUU_INBOUND_IDENTITY_PROVIDER=api_key` in your environment so
> the gateway validates `vyuu_user_…` keys against the
> `user_api_keys` table.

Cursor connects, you see a tool call land on the operator's **Events**
panel. Scroll up to the **Dashboard** to see the rolling counts move,
and to the **NHI map** to see Cursor appear in the AI-apps column.

### 1.7 Connecting a SaaS account (A1 — OAuth authcode)

To exercise the per-user OAuth flow ("Connect to GitHub"):

1. Register an OAuth app at the SaaS IdP. For a local demo with
   GitHub, set:
   - Homepage URL: `http://localhost:8000/portal`
   - Authorization callback URL:
     `http://localhost:8000/api/v1/oauth-authcode/callback`
2. Register the upstream MCP server with `auth_authcode` set:
   ```json
   {
     "auth_authcode": {
       "auth_url": "https://github.com/login/oauth/authorize",
       "token_url": "https://github.com/login/oauth/access_token",
       "client_id_ref": "github-demo-client-id",
       "client_secret_ref": "github-demo-client-secret",
       "scopes": ["read:user", "repo"],
       "redirect_uri": "http://localhost:8000/api/v1/oauth-authcode/callback"
     }
   }
   ```
   For Google Drive add
   `"extra_authorize_params": {"access_type": "offline", "prompt": "consent"}`
   so Google issues a refresh token.
3. Seed the SecretStore with the OAuth-app's client_id + client_secret
   under those refs. (Vault: `vault kv put secret/data/{tenant}/github-demo-client-id value=…`.)
4. Wrap the MCP in a virtual server and grant the user access.
5. End user opens `/portal` → Catalog → vserver card now shows a
   **Connect github-demo** button. Click → consent on GitHub →
   redirected back to the gateway's "Connected" HTML page.
6. The user's row in `oauth_user_tokens` is populated. Subsequent
   tool calls into that vserver from this user ride
   `Authorization: Bearer <github-token>` upstream — GitHub sees the
   user's identity, not the gateway's.

A ready-to-run demo lives at `scripts/demo_oauth_authcode.py` —
seeds the DB, the in-memory SecretStore, and starts uvicorn:

```bash
DEMO_GH_CLIENT_ID=… \
DEMO_GH_CLIENT_SECRET=… \
python3 scripts/demo_oauth_authcode.py
```

### 1.8 Operator surfaces — what to look at first

After signing in to `/operator`, the page is laid out top-to-bottom:

1. **Dashboard** — KPI grid. Watch `pending_access_requests` and
   `high_risk_calls_24h` for things needing attention. Tinted pills
   (warn-amber / alert-red) flag non-zero values.
2. **NHI map** — 4-column "People & AI — who uses what" SVG. Switch
   to the **Sanctioned** filter to confirm only allowlisted MCP
   clients are reaching the gateway. Anything dashed = unrecognised
   user-agent → investigate.
3. **Identities** — per-principal aggregation with risk-score, OAuth
   reach, dependency graph (radial), and full activity timeline.
   Click "Show graph" on any identity to see a radial visual of
   their tools/upstreams; tool nodes are risk-tinted.
4. **Users** — admin roster. Each row's "Show activity" + "API
   keys" expanders let admins audit and revoke per user.

**That's the basic loop.** Continue to section 2 / 3 for production-
grade hardening.

---

## 2. Production single-region deployment (k8s)

Builds on the POC. Replace dev-mode shortcuts with HA infra.

### 2.1 Postgres — managed or HA self-hosted

**Recommended:** managed (RDS, Cloud SQL, Azure Database for Postgres).
HA failover, automated backups, connection-pool size > 100.

If self-hosting:
- Primary + sync replica with `pg_basebackup` + WAL streaming.
- Daily logical backups via `pg_dump` to S3 / GCS.
- Connection pooler in front (PgBouncer) for high gateway pod count.

Schema:
- Run `alembic upgrade head` against the primary at deploy time.
- The gateway image's startup does NOT run migrations automatically —
  this is by design (avoid race conditions with multiple pods racing).

### 2.2 Redis (required for HA)

Single Redis instance is fine for sessions if loss-on-restart is
acceptable (sessions just expire and users re-sign-in). For higher
SLA: Redis Sentinel or managed (ElastiCache, MemoryStore).

Set on the gateway:
```
VYUU_REDIS_URL=redis://redis-master.svc:6379/0
VYUU_SESSION_REDIS_KEY_PREFIX=vyuu:session:prod
```

### 2.3 TLS termination — NGINX ingress + cert-manager

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vyuu-gateway
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/backend-protocol: HTTP
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    # HSTS — once cert is stable
    nginx.ingress.kubernetes.io/configuration-snippet: |
      add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
spec:
  ingressClassName: nginx
  tls:
    - hosts: [gateway.your-corp.example]
      secretName: vyuu-gateway-tls
  rules:
    - host: gateway.your-corp.example
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: vyuu-gateway
                port: { number: 8000 }
```

See `docs/operations/tls-and-mtls.md` for Caddy / cloud-LB
alternatives.

### 2.4 Vault HA (production)

Migration from POC's dev mode:

```bash
# 1. Stop the dev-mode Vault.
# 2. Edit /etc/vault.d/vault.hcl for production config:
cat <<'EOF' | sudo tee /etc/vault.d/vault.hcl
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "vault-node-1"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/etc/vault.d/tls/server.crt"
  tls_key_file  = "/etc/vault.d/tls/server.key"
  # tls_disable = false  # always TLS in prod
}
api_addr = "https://vault.your-corp.example:8200"
cluster_addr = "https://vault-internal.your-corp.example:8201"
ui = true

# Auto-unseal via cloud KMS (recommended over manual unseal):
seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "<arn>"
}
EOF

sudo systemctl enable --now vault
vault operator init
# save unseal recovery keys + initial root token
```

Bootstrap the Vyuu paths:

```bash
export VAULT_ADDR=https://vault.your-corp.example:8200
export VAULT_TOKEN=<initial-root-token>

# KV v2 mount
vault secrets enable -path=secret -version=2 kv

# Service token for the gateway with read-only access to Vyuu paths
vault policy write gateway-read - <<'EOF'
path "secret/data/*" { capabilities = ["read"] }
path "sys/health"    { capabilities = ["read"] }
EOF

# Renewable, periodic — doesn't need re-issuance every 24h
vault token create -policy=gateway-read -period=720h \
  -display-name=vyuu-gateway-prod
# → save this for the gateway's VYUU_VAULT_TOKEN env var
```

Per-tenant ACL (optional but recommended): use Vault entity-template
policies to gate `secret/data/{{identity.entity.metadata.tenant_id}}/*`
per tenant token.

### 2.5 Kafka audit pipeline

Install the Kafka extra:
```
pip install vyuu-mcp-gateway[kafka]
```

Wire (gateway env / k8s ConfigMap):
```
VYUU_AUDIT_KAFKA_BOOTSTRAP_SERVERS=kafka-broker-0:9092,kafka-broker-1:9092
VYUU_AUDIT_KAFKA_TOPIC=vyuu.audit.v1
VYUU_AUDIT_KAFKA_CLIENT_ID=vyuu-gateway
# ...optional auth (SASL/SCRAM, mTLS)
```

(Exact env-var shape may vary — check `vyuu_gateway/config.py` for
the canonical names; this is the design pattern.)

### 2.6 Kubernetes Deployment manifest (skeleton)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vyuu-gateway
spec:
  replicas: 3
  selector:
    matchLabels: { app: vyuu-gateway }
  template:
    metadata:
      labels: { app: vyuu-gateway }
    spec:
      containers:
      - name: gateway
        image: registry.your-corp.example/vyuu-gateway:1.0.0
        ports:
        - containerPort: 8000
        env:
        - { name: VYUU_DATABASE_URL, valueFrom: { secretKeyRef: { name: vyuu-db, key: url } } }
        - { name: VYUU_REDIS_URL,    valueFrom: { secretKeyRef: { name: vyuu-redis, key: url } } }
        - { name: VYUU_OPERATOR_AUTH_SIGNING_SECRET, valueFrom: { secretKeyRef: { name: vyuu-secrets, key: operator-signing } } }
        - { name: VYUU_PORTAL_SESSION_SIGNING_SECRET, valueFrom: { secretKeyRef: { name: vyuu-secrets, key: portal-signing } } }
        - { name: VYUU_VAULT_ADDR,   value: https://vault.your-corp.example:8200 }
        - { name: VYUU_VAULT_TOKEN,  valueFrom: { secretKeyRef: { name: vyuu-vault, key: token } } }
        - { name: VYUU_SECRET_STORE_BACKEND,    value: vault }
        - { name: VYUU_INBOUND_IDENTITY_PROVIDER, value: api_key }
        - { name: VYUU_GATEWAY_INSTANCE_ID,     valueFrom: { fieldRef: { fieldPath: metadata.name } } }
        # bootstrap is OPTIONAL - only set on first deploy. Remove
        # after the first admin lands so it's not stale.
        - { name: VYUU_BOOTSTRAP_TENANT_NAME,    value: "Acme Corp" }
        - { name: VYUU_BOOTSTRAP_ADMIN_EMAIL,    value: "admin@your-corp.example" }
        - { name: VYUU_BOOTSTRAP_ADMIN_PASSWORD, valueFrom: { secretKeyRef: { name: vyuu-bootstrap, key: password } } }
        readinessProbe:
          httpGet: { path: /api/v1/health, port: 8000 }
          periodSeconds: 5
        livenessProbe:
          httpGet: { path: /api/v1/health, port: 8000 }
          periodSeconds: 15
        resources:
          requests: { cpu: 250m, memory: 256Mi }
          limits:   { cpu: 1,    memory: 512Mi }
---
apiVersion: v1
kind: Service
metadata:
  name: vyuu-gateway
spec:
  selector: { app: vyuu-gateway }
  ports: [{ port: 8000, targetPort: 8000 }]
```

### 2.7 Operator first-run

Same as POC section 1.4. Sign in at `https://gateway.your-corp.example/operator`.

Once the first admin signs in, **remove the bootstrap env vars**
from the deployment so they're not stale credentials sitting in
the cluster. Bootstrap is idempotent (skips when an operator
already exists), but cleanup is good hygiene.

---

## 3. Hybrid (gateway on-prem, secrets in AWS)

Same gateway deployment as section 2 — but skip Vault and use AWS
Secrets Manager.

### 3.1 IAM Roles Anywhere setup

For on-prem instances to assume IAM roles without long-lived access
keys.

1. Create a Trust Anchor in IAM Roles Anywhere (your corporate CA's
   public cert).
2. Issue an X.509 client cert to the gateway host (private + public
   key kept on the host; private key never leaves).
3. Create an IAM Profile that maps the cert to a role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["secretsmanager:GetSecretValue"],
    "Resource": "arn:aws:secretsmanager:us-east-1:*:secret:vyuu/*"
  }]
}
```

4. Install the `aws_signing_helper` on the gateway host:

```bash
curl -O https://rolesanywhere.amazonaws.com/releases/1.5.0/X86_64/Linux/aws_signing_helper
chmod +x aws_signing_helper
sudo mv aws_signing_helper /usr/local/bin/
```

5. Configure `~/.aws/config` for the gateway service account:

```ini
[profile vyuu-gateway]
credential_process = /usr/local/bin/aws_signing_helper credential-process \
    --certificate /etc/vyuu/client.crt \
    --private-key /etc/vyuu/client.key \
    --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:...:trust-anchor/... \
    --profile-arn arn:aws:rolesanywhere:us-east-1:...:profile/... \
    --role-arn arn:aws:iam::...:role/vyuu-gateway
```

6. Set env on the gateway:
```
AWS_PROFILE=vyuu-gateway
VYUU_SECRET_STORE_BACKEND=aws_secrets_manager
VYUU_AWS_REGION=us-east-1
VYUU_AWS_SECRETS_PREFIX=vyuu
```

boto3's default credential chain picks up the profile + signing
helper transparently.

### 3.2 Provision secrets

```bash
aws secretsmanager create-secret \
  --region us-east-1 \
  --name "vyuu/<tenant_uuid>/paypal-bearer" \
  --secret-string "Bearer the-real-token"
```

In the gateway, register an MCP with:
```
auth_headers = {"Authorization": "Bearer {secret:paypal-bearer}"}
```

The gateway resolves `{secret:paypal-bearer}` via AWS Secrets
Manager at `vyuu/<tenant_uuid>/paypal-bearer`.

### 3.3 Compliance note

Some customers are data-residency-restricted: secrets must not leave
their infrastructure. For those tenants, deploy Vault on-prem
(section 2.4) instead. The choice is per-deployment, not per-tenant
— if you need per-tenant backend mixing, that's an unbuilt feature
(track in backlog).

See `docs/operations/secret-store-setup.md` for the full picker.

---

## 4. Common operations

### 4.1 Adding a second admin

Sign in as the bootstrap admin, scroll to **Admins** panel, fill the
"Add admin" form. New admin gets a temporary password +
`must_change_password=true` — they're forced to rotate on first sign-in.

If you've lost the bootstrap admin's password, you can reset it at
the database:

```sql
UPDATE operators
SET password_hash = crypt('new-strong-12+chars-password', gen_salt('bf', 12)),
    must_change_password = true
WHERE email = 'admin@your-corp.example' AND tenant_id = '...';
```

(Requires `pgcrypto` extension; install with `CREATE EXTENSION pgcrypto;`.)

### 4.2 Rotating signing secrets

The two HMAC signing secrets (`VYUU_OPERATOR_AUTH_SIGNING_SECRET` and
`VYUU_PORTAL_SESSION_SIGNING_SECRET`) can be rotated, but every
existing token signed with the old secret becomes invalid:

- Operator JWT rotation → all operators must sign in again. Tolerable
  during off-hours.
- Portal session JWT rotation → all `/portal` users must sign in
  again. They lose their session but their issued API keys (used
  by Cursor / Claude Desktop) still work because those are stored
  in the DB hash, not signed by this secret.

Rotation procedure:
1. Generate new secret: `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`
2. Update the env var on all gateway pods + restart.
3. Communicate the rotation to operators (they need to sign in
   again).

### 4.3 Rotating a Vault service token

```bash
# Issue a new periodic token
vault token create -policy=gateway-read -period=720h
# → save new token

# Update VYUU_VAULT_TOKEN on all gateway pods, restart
# Old token can stay valid until its TTL expires
```

### 4.4 Rotating an upstream MCP's secret in Vault

```bash
vault kv put secret/<tenant>/<ref> value="<new-secret>"
```

The gateway's httpx pool picks up the new value at the next
upstream-client construction (when an existing pool entry expires
or the circuit breaker resets). For immediate effect, restart the
gateway pods or trigger a `POST /api/v1/servers/{id}/health/check`
which forces pool refresh.

### 4.5 Monitoring

Logs: structured JSON to stdout (`logger.info("...", extra={...})`).
Pipe into Loki / CloudWatch / Datadog / your stack.

Key log events to alert on:
- `bootstrap_admin_seeded` — fires once at first deploy, then
  silent. If it fires again, something deleted your operators table.
- `bootstrap_seed_failed` — bootstrap tried but couldn't (DB
  unreachable, wrong password strength, etc.).
- `audit_emit_failed` (loglevel WARNING) — Kafka/NATS producer
  rejected an event. Cluster issue or auth problem.
- `upstream_circuit_breaker_opened` — repeated failures against an
  upstream. Either the upstream is down or auth is misconfigured.
- `inbound_mcp_session_created` (INFO) — useful for tracking
  active sessions.

Metrics: not yet exposed via `/metrics`. Backlog item — instrumenting
with `prometheus_client` would surface request latency, audit-queue
depth, breaker state, pool size.

Health: `GET /api/v1/health` returns liveness. Use as readiness +
liveness probe.

### 4.6 Backups

Postgres: nightly `pg_dump --format=custom` to S3 / GCS. The catalog
+ user data is the precious bit. Audit history (when persisted via
Kafka → downstream) lives outside the gateway.

Vault: nightly snapshot via `vault operator raft snapshot save`. Store
encrypted, off-site.

AWS Secrets Manager: AWS handles backup. Versioning is automatic per
secret.

### 4.7 Upgrading the gateway

1. Pull new image / source.
2. Run `alembic upgrade head` against Postgres BEFORE rolling out
   pods. This is critical — old pods can't start against a newer
   schema.
3. Test against a staging tenant before prod rollout.
4. Rolling deploy via Kubernetes — gateways are stateless modulo
   Redis sessions.

Migrations are forward-compatible by design (e.g. operator-password
migration backfilled legacy operators automatically). But check
the migration file's docstring before applying — anything destructive
will be flagged.

### 4.8 Disaster recovery

Loss of:
- **Postgres** → restore from snapshot. All catalog + users +
  grants come back. Sessions in Redis are best-effort lost; users
  re-sign-in.
- **Vault / AWS Secrets Manager** → restore from snapshot. Until
  restored, upstream MCPs that need secret resolution will fail
  with backend errors — operators see the failures in audit.
- **Kafka** → audit pipeline pauses. Gateway keeps running
  (`AuditFailureMode.MONITOR`, the default, doesn't block requests).
  When Kafka recovers, in-flight events drain through the producer
  queue.
- **Gateway pods** → just restart them. State is in Postgres + Redis
  + Vault + Kafka.

---

## 5. Verification checklist

After your deployment, run this checklist before declaring "live":

- [ ] `curl https://gateway.your-corp.example/api/v1/health` → 200
- [ ] `curl https://gateway.your-corp.example/operator` → 200, HTML
- [ ] `curl https://gateway.your-corp.example/portal` → 200, HTML
- [ ] Sign in at `/operator` with bootstrap admin → succeeds
- [ ] Sign in at `/portal` with bootstrap admin → succeeds
- [ ] **Secret store** panel shows `healthy: true`
- [ ] Register a public MCP (e.g. drawio) → sync → create vserver
- [ ] Issue an API key from `/portal`
- [ ] Connect Cursor / curl to `/v/<tenant>/<vserver>/mcp` → tools/list
      returns capabilities
- [ ] Make a tool call → it lands in **Events** panel
- [ ] Trigger an access denial (try a vserver you don't have a grant
      on) → it lands as `access_attempt` in the Events panel with
      `auth_failure_reason: no_grant`
- [ ] Add a second admin via Admins panel → new admin can sign in
- [ ] Operator JWT signing secret rotated to your random value (not
      the dev placeholder)
- [ ] Portal session signing secret rotated to your random value
- [ ] Bootstrap env vars REMOVED from the deployment (after first
      admin lands)
- [ ] TLS termination working (HTTPS only, HSTS header set)
- [ ] (Production) Audit pipeline reaching downstream consumer
- [ ] (Production) Postgres backups verified by a test-restore

---

## 6. Troubleshooting

### "401 invalid bearer token" on the operator console

The operator JWT signing secret changed since the token was minted.
Sign in again at `/operator`.

### "Authentication failed" from Cursor on a vserver URL

- Check `VYUU_INBOUND_IDENTITY_PROVIDER=api_key` on the gateway.
  If it's still `fake`, the gateway expects custom `x-vyuu-*`
  headers, not a Bearer token.
- Check the API key wasn't revoked at `/portal` → API keys.
- Check the operator console **Events** panel — you'll see the
  rejection with the failure reason.

### "Secret store unhealthy" on the operator panel

- Vault: check `VYUU_VAULT_ADDR` reachable + `VYUU_VAULT_TOKEN`
  hasn't expired. Run `vault status` from the gateway host.
- AWS: check IAM credentials valid. Run `aws sts get-caller-identity`
  from the gateway host with the same env vars.

### Migrations fail with "permission denied for schema public"

The Postgres user needs DDL rights on the database. Re-run the
`CREATE DATABASE ... OWNER vyuu` step, or grant explicitly:
```sql
GRANT ALL ON SCHEMA public TO vyuu;
```

### "Method Not Allowed" GETting `/v/<tenant>/<vserver>/mcp`

That endpoint is `POST` only (MCP Streamable HTTP convention). Use a
proper MCP client; `curl` for smoke tests needs `POST` with the
right JSON-RPC body. Cursor / Claude Desktop / the MCP SDK handle
this automatically.

### Cursor logs `404 OAuth metadata not found` warnings

Cursor probes for `/.well-known/oauth-protected-resource` before
falling back to bearer auth. The gateway uses static bearer tokens
(no OAuth metadata endpoint), so the 404 is expected. The actual
MCP connection still works — the warnings are cosmetic.

### Gateway crashes on startup with "VYUU_VAULT_ADDR is required"

You set `VYUU_SECRET_STORE_BACKEND=vault` but didn't set the
companion env vars. Either set them or fall back to `memory` for a
quick smoke (won't work for any MCP that requires upstream auth,
but good for sanity-checking startup).

---

## 7. Where to go from here

- **Architecture deep-dive:** `docs/PLATFORM.md`
- **Tech-stack reasoning:** `docs/TECH-STACK.md`
- **TLS / mTLS specifics:** `docs/operations/tls-and-mtls.md`
- **Vault vs AWS picker:** `docs/operations/secret-store-setup.md`
- **What's in the backlog:** `BACKLOG.md`
- **Chronological session log + how-to-resume:** `HANDOFF.md`

For specific issues, search the codebase for the exact log line —
modules use structured loggers with named events that match the
docs.
