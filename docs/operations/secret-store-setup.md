# Secret store — Vault vs AWS Secrets Manager (operations guide)

The Vyuu gateway resolves upstream-MCP authentication credentials
(`auth_headers`, `auth_env`, OAuth client-credentials) through a
pluggable `SecretStore`. Three backends ship today:

| Backend | When to use |
|---|---|
| **`memory`** (default) | Dev, lab, tests. Secrets live in process memory and are lost on restart. **Never use for production.** |
| **`vault`** | **Recommended for POC + early production**, especially on-prem. Self-hosted alongside the gateway, no external SaaS dependency. |
| **`aws_secrets_manager`** | **Recommended for AWS-native deployments** and customers who already standardise secrets on AWS. Works on-prem too via IAM Roles Anywhere. |

The choice is made via `VYUU_SECRET_STORE_BACKEND`. The operator console
exposes a "Secret store" panel that shows the active backend, a
connectivity health probe, and the env vars to switch — read-only on
purpose (the actual flip happens at deployment time).

## Why deployment-time and not UI-driven

1. **Auth blast radius**: the store holds long-lived credentials
   (Vault token, AWS keys). Letting any operator with UI access flip
   them mid-flight changes the privilege model meaningfully. Customers
   should treat the env var as part of their IaC.
2. **Pool consistency**: existing httpx clients in the upstream pool
   have already-resolved secrets baked in. A runtime switch would need
   pool-wide invalidation, in-flight call coordination, and rollback —
   significant complexity for a knob that flips once per environment.
3. **Validation**: `health_check` lets operators confirm the
   configured backend works AS-DEPLOYED — which is the actual question
   the panel needs to answer.

## POC → production progression

The recommended customer journey:

```
┌──────────────────────────┐
│ POC (week 1)             │  VYUU_SECRET_STORE_BACKEND=vault
│ Single VM or k8s pod     │  Vault dev mode on the same host
│ Lab tenant, < 10 secrets │  No HA, no rotation, root token
└──────────────────────────┘
              │
              ▼
┌──────────────────────────┐
│ Early production         │  VYUU_SECRET_STORE_BACKEND=vault
│ HA Vault cluster         │  3-5 nodes, Raft storage, auto-unseal
│ Per-tenant ACL templates │  Renewable service tokens (gateway-read policy)
│ TLS at Vault listener    │  VYUU_VAULT_ADDR=https://...
└──────────────────────────┘
              │
              ▼ (if AWS-native or compliance prefers)
┌──────────────────────────┐
│ Production on AWS        │  VYUU_SECRET_STORE_BACKEND=aws_secrets_manager
│ Per-tenant resource ARNs │  IAM policy gates {prefix}/{tenant_id}/*
│ Auto-rotation policies   │  Built-in AWS rotation for supported services
│ IAM Roles Anywhere       │  No long-lived access keys on-prem
└──────────────────────────┘
```

Most customers stop at the middle row. Some standardise on AWS
Secrets Manager regardless of where the gateway runs — the on-prem
case works fine; only data residency compliance might rule it out.

## Vault setup

See `docs/operations/tls-and-mtls.md` § 1 for ingress-side TLS, then:

```bash
# Install Vault (Ubuntu)
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
  sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault
sudo systemctl enable --now vault

# Initialise + unseal (one-time; save the unseal keys + root token securely)
vault operator init
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# KV v2 mount (if not already on the default `secret/` path)
vault secrets enable -path=secret -version=2 kv

# Service token for the gateway with read-only access to the Vyuu prefix
vault policy write gateway-read - <<'EOF'
path "secret/data/*" { capabilities = ["read"] }
EOF
vault token create -policy=gateway-read -period=720h
# → save the token as VYUU_VAULT_TOKEN
```

Provision a per-tenant secret:

```bash
vault kv put secret/<tenant_uuid>/paypal-bearer value="Bearer the-real-token"
```

Wire the gateway:

```
VYUU_SECRET_STORE_BACKEND=vault
VYUU_VAULT_ADDR=https://vault.your-corp.example:8200
VYUU_VAULT_TOKEN=<service-token>
# optional:
VYUU_VAULT_MOUNT=secret             # default
VYUU_VAULT_NAMESPACE=acme/finance   # only for Vault Enterprise
VYUU_VAULT_VALUE_FIELD=value        # default; the JSON field inside the secret
```

## AWS Secrets Manager setup

```bash
# Provision a secret per (tenant, ref). Default prefix is `vyuu`.
aws secretsmanager create-secret \
  --region us-east-1 \
  --name "vyuu/<tenant_uuid>/paypal-bearer" \
  --secret-string "Bearer the-real-token"
```

IAM policy for the gateway's principal — least-privilege scope:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:us-east-1:*:secret:vyuu/*"
    }
  ]
}
```

For tighter per-tenant isolation, attach a policy with
`Resource: "arn:aws:secretsmanager:*:*:secret:vyuu/<tenant_uuid>/*"`
and issue per-tenant role bindings — the gateway's per-tenant URL
prefix lines up directly so the IAM ARN templating works out of the
box.

Wire the gateway:

```
VYUU_SECRET_STORE_BACKEND=aws_secrets_manager
VYUU_AWS_REGION=us-east-1
# auth via the boto3 default credential chain — pick one:
#
# A. on-prem with IAM Roles Anywhere (recommended for prod):
#    Configure the AWS profile via ~/.aws/config + a roles-anywhere
#    helper that mints session creds from a client cert. boto3 picks
#    them up.
#
# B. on-prem with static keys (POC only — rotate aggressively):
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
#
# C. AWS-resident (EC2 / ECS / EKS): no env needed — boto3 picks up
#    the instance profile / task role / pod identity automatically.
#
# optional:
VYUU_AWS_SECRETS_PREFIX=vyuu                # default
VYUU_AWS_SECRETS_VALUE_FIELD=               # unset = whole SecretString IS the value
                                             # set if your secrets are JSON-shaped
```

## Validating the configured backend

After deploying with the new env vars + a restart:

```bash
curl -s "http://gateway.example/api/v1/secret-store/status" \
  -H "Authorization: Bearer $OPERATOR_JWT" | jq
```

Or open the operator console → "Secret store" panel → click Refresh.
The card shows:
- Active backend name + recommendation context
- `healthy: true/false` from a no-cost connectivity probe (Vault
  `/sys/health`, AWS `list_secrets` with MaxResults=1)
- Detail message — Vault version, IAM posture, network error class
- Switch instructions for the two non-active backends

Healthy + correct backend → wire your first upstream MCP's
`auth_headers` with a `{secret:ref}` template (H6) and you're done.

## On-prem ↔ AWS Secrets Manager — yes, this works

For customers running the gateway on-prem who want to use AWS
Secrets Manager: the gateway makes outbound HTTPS API calls to
`secretsmanager.<region>.amazonaws.com`. Same as any service that
talks to a SaaS API. boto3 honours `HTTP_PROXY` / `HTTPS_PROXY` env
vars for corporate egress proxies.

Latency: ~50-200ms per AWS API call from on-prem (vs ~5ms in-region).
**Not a hot-path concern** — secrets resolve at upstream-client
*construction* time and are reused via the httpx pool, not per
request. A tenant making 1,000 tool calls/sec hits AWS only on pool
warm-up + rotation events.

Cost: ~$0.40/secret/month + $0.05 per 10K API calls. Cheap unless
you have millions of tenants.

Compliance caveat: some customers' policies are "secrets must not
leave our infrastructure." For those, Vault is the right answer.
For everyone else, AWS Secrets Manager is FedRAMP High / PCI-DSS /
HIPAA-eligible — covers most regulated verticals.

## Next steps

- AWS KMS direct integration (envelope encryption for at-rest data
  in our DB) — not currently blocking. Sized when the use case is
  concrete.
- AWS Secrets Manager auto-rotation — already supported by AWS for
  many services (RDS, IAM access keys); the gateway just reads the
  current value, no special wiring needed for rotation to work.
- Per-tenant SSO-federated AWS roles — operators with AWS IAM
  Identity Center can federate per-tenant role assumption. Documented
  pattern, no gateway code change needed.
