# One-command setup

Two scripts, one per operating system, drive the manifests in this
directory end to end: they check and (with your permission) install the
tools they need, ask a handful of questions, generate every secret, apply
the database migrations, start the gateway, prove that the first
operator can sign in, and print where to go next.

| Host | Script | Single VM (Docker Compose) | Kubernetes |
|---|---|---|---|
| Linux (Ubuntu/Debian, Fedora/RHEL family) | [`setup-linux.sh`](setup-linux.sh) | installs Docker Engine via get.docker.com if missing | installs kubectl / kind if missing; any reachable cluster |
| macOS | [`setup-macos.sh`](setup-macos.sh) | Docker Desktop or Colima via Homebrew | Docker Desktop, kind, Colima, OrbStack, or a remote cluster |
| either | [`teardown.sh`](teardown.sh) | shuts the stack down (`--purge` also deletes the data) | same |

Both share [`lib/common.sh`](lib/common.sh); the OS files only know how to
install and start things. Everything runs on the bash 3.2 that ships with
macOS.

```bash
# interactive — asks what to set up and walks you through it
./deploy/setup/setup-linux.sh          # or setup-macos.sh

# non-interactive single VM
./deploy/setup/setup-linux.sh --mode vm -y --admin-email you@corp.example --tenant-name "Corp"

# Kubernetes into an existing cluster, prebuilt image, managed Postgres, ingress with TLS
./deploy/setup/setup-linux.sh --mode k8s --context prod --namespace vyuu \
    --image-strategy pull --image registry.corp.example/vyuu-gateway:1.0.0 \
    --db-url 'postgresql+psycopg://vyuu:…@pg.corp.internal:5432/vyuu_gateway' \
    --secret-store kubernetes --ingress-host mcp.corp.example --tls-secret mcp-tls

# see the plan without changing anything
./deploy/setup/setup-macos.sh --mode k8s --dry-run

# shut everything down (data kept); add --purge to delete volumes / namespace / env files
./deploy/setup/teardown.sh --mode vm
```

`--help` lists every option; each can also be given as an environment
variable (`VYUU_SETUP_ADMIN_EMAIL`, `VYUU_SETUP_K8S_CONTEXT`, …), which is
how you drive the scripts from CI or a provisioning tool.

## What each mode does

**Single VM** — `deploy/docker/docker-compose.yml`

1. Preflight: `curl`, `openssl`, Docker + Compose v2 (offers to install).
2. Configure: host port, public URL, organisation, first operator, secret store.
3. Writes `deploy/docker/.env` (Compose interpolation: Postgres password,
   image, port) and `deploy/docker/gateway.env` (identity, signing
   secrets, envelope key, bootstrap admin) — both mode 0600, git-ignored.
4. Builds the image from the checkout (or pulls `--image`), starts
   Postgres / Redis / NATS, runs `alembic upgrade head` from the gateway
   image, starts the gateway.
5. Waits for `/healthz`, signs in as the first operator through the API,
   prints the console and portal URLs plus the credentials.

**Kubernetes** — `deploy/kubernetes/*`

1. Preflight: kubectl, a reachable context (offers to create a local
   `kind` cluster when there is none).
2. Configure: namespace, replicas, image strategy (`build-local` for
   local clusters, `build-push`, or `pull`), Postgres and Redis (in-cluster
   evaluation add-ons or external URLs), optional Ingress, secret store.
3. Renders into `deploy/kubernetes/generated/` (git-ignored, 0600):
   namespace, ConfigMap, Secret, RBAC for the Kubernetes secret store,
   add-ons, migration Job, the gateway Deployment/Service (PDB and HPA are
   left out below 3 replicas), Ingress.
4. Applies them in order, waits for Postgres and Redis, runs the migration
   Job from the gateway image, rolls the Deployment out.
5. Port-forwards the Service, checks `/healthz`, signs in as the first
   operator, prints access instructions and hygiene steps.

## Re-runs, upgrades, teardown

- **Re-running is safe.** Existing tenant id, signing secrets, envelope
  key and database password are reused, so sessions and sealed data
  survive. The bootstrap seed is idempotent in the gateway itself.
- **Upgrade** = `git pull` and run the same command again: it rebuilds,
  migrates and restarts / rolls out.
- **Teardown**: `./deploy/setup/teardown.sh` (or `setup-<os>.sh --teardown`)
  removes the running pieces and keeps data; add `--purge` to also delete
  volumes (VM), the namespace (Kubernetes) and the generated files. Interactive runs confirm before deleting data;
  with `--yes`, passing `--purge` is taken as that consent.

## After the first sign-in

- The first operator is created with `must_change_password`, so the
  console forces a new password immediately.
- Remove the `VYUU_BOOTSTRAP_*` lines from `gateway.env` / the bootstrap
  key from the Kubernetes Secret once you no longer want the initial
  password on disk (the summary prints the exact command).
- Terminate TLS in front of the gateway (nginx, Caddy, Traefik, or the
  rendered Ingress) and re-run with `--public-url https://…` so OAuth
  callbacks and issuer URLs match.
- `memory` is the evaluation secret store; production installs pick
  `vault`, `aws_secrets_manager`, or (on Kubernetes) `kubernetes`.

## What the scripts deliberately do not do

- Obtain TLS certificates or configure DNS.
- Run HA Postgres: the in-cluster add-on is a single StatefulSet on one
  PVC. Point `--db-url` at managed Postgres for production.
- Install Vault or create AWS resources; they only wire the gateway to
  ones you already have.
