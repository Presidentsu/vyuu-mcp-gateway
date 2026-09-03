#!/usr/bin/env bash
# deploy/setup/lib/common.sh — shared logic for the Vyuu MCP Gateway setup
# scripts. Sourced (never executed) by setup-linux.sh and setup-macos.sh
# AFTER they define the OS hooks it calls:
#
#   os_label                 print a short OS description for the banner
#   os_ensure_docker         make `docker` + `docker compose` usable (install /
#                            start the daemon); return non-zero if it cannot
#   os_ensure_kubectl        install kubectl if missing; return non-zero if not
#   os_ensure_kind           install kind if missing; return non-zero if not
#   os_local_cluster_hint    print how to get a local Kubernetes cluster
#   os_local_ip              print a LAN IP for the summary (best effort)
#
# Written for bash 3.2 (the macOS default): no associative arrays, no
# mapfile, no ${var,,}. Every side effect goes through run() so --dry-run
# prints the plan instead of executing it.

set -o errexit -o nounset -o pipefail -o errtrace

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$LIB_DIR/../../.." && pwd)
COMPOSE_DIR="$REPO_ROOT/deploy/docker"
COMPOSE_FILE="$COMPOSE_DIR/docker-compose.yml"
COMPOSE_ENV="$COMPOSE_DIR/.env"
GATEWAY_ENV="$COMPOSE_DIR/gateway.env"
K8S_DIR="$REPO_ROOT/deploy/kubernetes"
GEN_DIR="$K8S_DIR/generated"
CREDENTIALS_FILE=""

# ---------------------------------------------------------------------------
# Options. Precedence: flag > VYUU_SETUP_* environment > prompt > default.
# ---------------------------------------------------------------------------
MODE=${VYUU_SETUP_MODE:-}                       # vm | k8s
ASSUME_YES=${VYUU_SETUP_YES:-0}
DRY_RUN=0
ACTION=install                                  # install | teardown
PURGE=0
INSTALL_DEPS=${VYUU_SETUP_INSTALL_DEPS:-ask}    # ask | yes | no
IMAGE=${VYUU_SETUP_IMAGE:-}
GATEWAY_PORT=${VYUU_SETUP_PORT:-8000}
PUBLIC_URL=${VYUU_SETUP_PUBLIC_URL:-}
TENANT_NAME=${VYUU_SETUP_TENANT_NAME:-}
ADMIN_EMAIL=${VYUU_SETUP_ADMIN_EMAIL:-}
ADMIN_DISPLAY=${VYUU_SETUP_ADMIN_DISPLAY:-}
ADMIN_PASSWORD=${VYUU_SETUP_ADMIN_PASSWORD:-}
SECRET_STORE=${VYUU_SETUP_SECRET_STORE:-}       # memory | vault | aws_secrets_manager | kubernetes
VAULT_ADDR_IN=${VYUU_SETUP_VAULT_ADDR:-${VAULT_ADDR:-}}
VAULT_TOKEN_IN=${VYUU_SETUP_VAULT_TOKEN:-${VAULT_TOKEN:-}}
AWS_REGION_IN=${VYUU_SETUP_AWS_REGION:-${AWS_REGION:-}}
K8S_NAMESPACE=${VYUU_SETUP_K8S_NAMESPACE:-vyuu}
K8S_CONTEXT=${VYUU_SETUP_K8S_CONTEXT:-}
K8S_REPLICAS=${VYUU_SETUP_K8S_REPLICAS:-}
K8S_IMAGE_STRATEGY=${VYUU_SETUP_K8S_IMAGE_STRATEGY:-}   # build-local | build-push | pull
DB_URL=${VYUU_SETUP_DB_URL:-}                   # k8s: external Postgres URL (empty = in-cluster)
REDIS_URL=${VYUU_SETUP_REDIS_URL:-}             # k8s: external Redis URL (empty = in-cluster)
INGRESS_HOST=${VYUU_SETUP_INGRESS_HOST:-}
INGRESS_CLASS=${VYUU_SETUP_INGRESS_CLASS:-nginx}
TLS_SECRET=${VYUU_SETUP_TLS_SECRET:-}
LOCAL_PORT=${VYUU_SETUP_LOCAL_PORT:-18000}      # k8s: port-forward port for the smoke test

# Derived / generated state
DOCKER=(docker)
COMPOSE=(docker compose)
KUBECTL=(kubectl)
CLUSTER_KIND=remote                             # kind | docker-desktop | minikube | k3d | orbstack | remote
IMAGE_PULL_POLICY=IfNotPresent
TENANT_ID=""
INSTANCE_ID=""
POSTGRES_PASSWORD=""
OPERATOR_SECRET=""
PORTAL_SECRET=""
ENVELOPE_KEY=""
STEP_N=0
PF_PID=""
TMP=""

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
_c() { if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then printf '\033[%sm' "$1"; fi; }
say()  { printf '%s\n' "$*"; }
info() { printf '%s->%s %s\n' "$(_c 36)" "$(_c 0)" "$*"; }
ok()   { printf '%s OK%s %s\n' "$(_c 32)" "$(_c 0)" "$*"; }
warn() { printf '%s !!%s %s\n' "$(_c 33)" "$(_c 0)" "$*" >&2; }
fail() { printf '\n%s ERROR: %s%s\n' "$(_c 31)" "$*" "$(_c 0)" >&2; exit 1; }
hr()   { printf '%s\n' "------------------------------------------------------------------"; }
step() {
  STEP_N=$((STEP_N + 1))
  printf '\n%s%sStep %s · %s%s\n' "$(_c 1)" "$(_c 35)" "$STEP_N" "$*" "$(_c 0)"
  hr
}
kv()   { printf '   %-28s %s\n' "$1" "$2"; }

run() {
  if [ "$DRY_RUN" = 1 ]; then
    printf '%s[dry-run]%s' "$(_c 2)" "$(_c 0)"
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

on_error() {
  local line=$1
  printf '\n%s Setup stopped (line %s). Nothing here is one-way: fix the cause and re-run the\n same command — every step is idempotent and picks up where it left off.%s\n' \
    "$(_c 31)" "$line" "$(_c 0)" >&2
}
trap 'on_error $LINENO' ERR

cleanup() {
  if [ -n "$PF_PID" ]; then kill "$PF_PID" >/dev/null 2>&1 || true; fi
  if [ -n "$TMP" ] && [ -d "$TMP" ]; then rm -rf "$TMP"; fi
}
trap cleanup EXIT

need_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Prompts. Non-interactive (--yes, or no TTY) takes the default.
# ---------------------------------------------------------------------------
interactive() { [ "$ASSUME_YES" != 1 ] && [ -t 0 ]; }

# ask VAR "Prompt" "default"  — keeps VAR if already set (flag / env).
ask() {
  local var=$1 prompt=$2 default=${3:-} current reply
  eval "current=\${$var:-}"
  if [ -n "$current" ]; then kv "$prompt" "$current"; return 0; fi
  if ! interactive; then printf -v "$var" '%s' "$default"; kv "$prompt" "${default:-(none)}"; return 0; fi
  if [ -n "$default" ]; then printf '   %s [%s]: ' "$prompt" "$default"; else printf '   %s [none]: ' "$prompt"; fi
  if ! read -r reply; then reply=""; fi
  reply=${reply:-$default}
  printf -v "$var" '%s' "$reply"
}

# ask_secret VAR "Prompt"  — hidden input; empty answer keeps VAR unset.
ask_secret() {
  local var=$1 prompt=$2 current reply
  eval "current=\${$var:-}"
  if [ -n "$current" ]; then kv "$prompt" "(provided)"; return 0; fi
  if ! interactive; then return 0; fi
  printf '   %s (input hidden, leave empty to generate): ' "$prompt"
  if ! read -r -s reply; then reply=""; fi
  printf '\n'
  printf -v "$var" '%s' "$reply"
}

# confirm "Question" [y|n]  → 0 = yes
confirm() {
  local prompt=$1 default=${2:-y} reply
  if ! interactive; then [ "$default" = y ]; return $?; fi
  if [ "$default" = y ]; then printf '   %s [Y/n]: ' "$prompt"; else printf '   %s [y/N]: ' "$prompt"; fi
  if ! read -r reply; then reply=""; fi
  reply=${reply:-$default}
  case "$reply" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

# choose VAR "Prompt" default "value|label" "value|label" ...
choose() {
  local var=$1 prompt=$2 default=$3 current reply i value label
  shift 3
  eval "current=\${$var:-}"
  if [ -n "$current" ]; then kv "$prompt" "$current"; return 0; fi
  if ! interactive; then printf -v "$var" '%s' "$default"; kv "$prompt" "$default"; return 0; fi
  printf '   %s\n' "$prompt"
  i=0
  for opt in "$@"; do
    i=$((i + 1)); value=${opt%%|*}; label=${opt#*|}
    if [ "$value" = "$default" ]; then printf '     %s) %s  (default)\n' "$i" "$label"; else printf '     %s) %s\n' "$i" "$label"; fi
  done
  printf '   Choice: '
  if ! read -r reply; then reply=""; fi
  if [ -z "$reply" ]; then printf -v "$var" '%s' "$default"; return 0; fi
  i=0
  for opt in "$@"; do
    i=$((i + 1))
    if [ "$reply" = "$i" ] || [ "$reply" = "${opt%%|*}" ]; then printf -v "$var" '%s' "${opt%%|*}"; return 0; fi
  done
  warn "Unrecognised choice '$reply'; using the default ($default)."
  printf -v "$var" '%s' "$default"
}

# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------
rand_hex()  { openssl rand -hex "${1:-32}"; }
rand_b64()  { openssl rand -base64 32; }
# 20 chars, letters + digits, plus a fixed suffix so every character class the
# password policy might require is present.
gen_password() { printf '%s-9Qz' "$(openssl rand -base64 30 | tr -dc 'A-Za-z0-9' | cut -c1-20)"; }
gen_uuid() {
  local h
  if need_cmd uuidgen; then uuidgen | tr '[:upper:]' '[:lower:]'; return 0; fi
  if [ -r /proc/sys/kernel/random/uuid ]; then cat /proc/sys/kernel/random/uuid; return 0; fi
  h=$(openssl rand -hex 16)
  printf '%s-%s-4%s-%x%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:13:3}" "$(( (0x${h:16:1} & 3) | 8 ))" "${h:17:3}" "${h:20:12}"
}
sha256_of() { openssl dgst -sha256 "$1" | awk '{print $NF}'; }
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
yaml_dq() { printf '"%s"' "$(json_escape "$1")"; }
env_sq() {
  case "$1" in *"'"*) fail "Value '$1' contains a single quote, which the env file cannot carry. Pick another." ;; esac
  printf "'%s'" "$1"
}
# valid_master_key KEY → 0 when KEY is base64 of exactly 32 bytes (what
# VYUU_ENVELOPE_MASTER_KEY must be).
valid_master_key() {
  [ -n "$1" ] || return 1
  [ "$(printf '%s' "$1" | openssl base64 -d -A 2>/dev/null | wc -c | tr -d ' ')" = 32 ]
}
is_uuid() { printf '%s' "$1" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; }
env_get() { # file key
  [ -f "$1" ] || return 1
  grep -E "^$2=" "$1" | tail -1 | cut -d= -f2- | sed -e "s/^'//" -e "s/'\$//"
}
# port_in_use PORT → 0 when something on this host already listens on it.
port_in_use() {
  if need_cmd lsof; then lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; return $?; fi
  if need_cmd ss; then ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$1\$"; return $?; fi
  if need_cmd netstat; then netstat -an 2>/dev/null | grep -E "LISTEN" | awk '{print $4}' | grep -Eq "[:.]$1\$"; return $?; fi
  return 1
}
wait_http() { # url seconds
  local url=$1 secs=${2:-120} waited=0 code
  while [ "$waited" -lt "$secs" ]; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" 2>/dev/null || true)
    if [ "$code" = 200 ]; then return 0; fi
    sleep 2; waited=$((waited + 2))
  done
  return 1
}
login_smoke() { # base_url  → 0 when the bootstrap admin can sign in
  local body code
  body=$(printf '{"tenant_id":"%s","email":"%s","password":"%s"}' \
    "$TENANT_ID" "$(json_escape "$ADMIN_EMAIL")" "$(json_escape "$ADMIN_PASSWORD")")
  code=$(curl -s -o "$TMP/login.json" -w '%{http_code}' --max-time 20 \
    -H 'Content-Type: application/json' -d "$body" "$1/api/v1/operator-auth/login" 2>/dev/null || true)
  [ "$code" = 200 ]
}

usage() {
  cat <<USAGE
Vyuu MCP Gateway setup ($(os_label))

Usage: $0 [--mode vm|k8s] [options]
       $0 --teardown [--purge] [--mode vm|k8s]

Modes
  vm      Single VM / single host: Docker Compose (gateway + Postgres + Redis + NATS)
  k8s     Kubernetes: renders and applies deploy/kubernetes/* into a namespace

General
  -y, --yes               Non-interactive: accept defaults, read VYUU_SETUP_* env vars
      --dry-run           Print every command instead of running it
      --install-deps      Install missing tools (Docker, kubectl, kind) without asking
      --no-install-deps   Never install tools; fail with instructions instead
      --teardown          Stop and remove what this script deployed (keeps data)
      --purge             With --teardown: also delete volumes / namespace / env files
  -h, --help              This text

Identity (both modes)
      --tenant-name NAME  Organisation name for the first tenant     [Acme Corp]
      --admin-email MAIL  First operator's email                     [admin@example.com]
      --admin-password P  First operator's password (generated if omitted; rotated on first login)
      --public-url URL    Externally visible origin of the gateway   [http://<host>:<port>]
      --secret-store S    memory | vault | aws_secrets_manager | kubernetes (k8s only)

Single VM
      --port N            Host port to publish the gateway on         [8000]
      --image REF         Use a prebuilt image instead of building from this checkout

Kubernetes
      --context NAME      kubectl context                            [current]
      --namespace NS      Namespace                                  [vyuu]
      --replicas N        Gateway replicas                           [1 local clusters, 3 otherwise]
      --image-strategy S  build-local | build-push | pull
      --image REF         Image reference for build-push / pull
      --db-url URL        External Postgres URL (omit → in-cluster eval Postgres)
      --redis-url URL     External Redis URL (omit → in-cluster Redis)
      --ingress-host H    Render an Ingress for this host (with --ingress-class, --tls-secret)

Every option can also be given as VYUU_SETUP_<NAME>, e.g. VYUU_SETUP_ADMIN_EMAIL.
Generated secrets land in deploy/docker/gateway.env (vm) or
deploy/kubernetes/generated/ (k8s), mode 0600, git-ignored. Re-running is safe:
existing secrets are reused, never regenerated.
USAGE
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --mode) MODE=$2; shift ;;
      -y|--yes) ASSUME_YES=1 ;;
      --dry-run) DRY_RUN=1 ;;
      --install-deps) INSTALL_DEPS=yes ;;
      --no-install-deps) INSTALL_DEPS=no ;;
      --teardown) ACTION=teardown ;;
      --purge) PURGE=1 ;;
      --tenant-name) TENANT_NAME=$2; shift ;;
      --admin-email) ADMIN_EMAIL=$2; shift ;;
      --admin-password) ADMIN_PASSWORD=$2; shift ;;
      --public-url) PUBLIC_URL=$2; shift ;;
      --secret-store) SECRET_STORE=$2; shift ;;
      --port) GATEWAY_PORT=$2; shift ;;
      --image) IMAGE=$2; shift ;;
      --context) K8S_CONTEXT=$2; shift ;;
      --namespace) K8S_NAMESPACE=$2; shift ;;
      --replicas) K8S_REPLICAS=$2; shift ;;
      --image-strategy) K8S_IMAGE_STRATEGY=$2; shift ;;
      --db-url) DB_URL=$2; shift ;;
      --redis-url) REDIS_URL=$2; shift ;;
      --ingress-host) INGRESS_HOST=$2; shift ;;
      --ingress-class) INGRESS_CLASS=$2; shift ;;
      --tls-secret) TLS_SECRET=$2; shift ;;
      --local-port) LOCAL_PORT=$2; shift ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; fail "Unknown option: $1" ;;
    esac
    shift
  done
  case "$MODE" in ""|vm|k8s) ;; *) fail "--mode must be vm or k8s (got '$MODE')" ;; esac
  case "$INSTALL_DEPS" in ask|yes|no) ;; *) fail "VYUU_SETUP_INSTALL_DEPS must be ask, yes or no" ;; esac
}

banner() {
  printf '\n%s%sVyuu MCP Gateway · setup%s  (%s)\n' "$(_c 1)" "$(_c 35)" "$(_c 0)" "$(os_label)"
  hr
  say "Checkout: $REPO_ROOT"
  if [ "$DRY_RUN" = 1 ]; then warn "Dry run: commands are printed, nothing is changed."; fi
}

# may_install "tool"  → 0 if the script is allowed to install it
may_install() {
  case "$INSTALL_DEPS" in
    yes) return 0 ;;
    no)  return 1 ;;
    *)   confirm "$1 is missing. Install it now?" y ;;
  esac
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
preflight_common() {
  step "Preflight"
  local missing=""
  for t in curl openssl; do
    if need_cmd "$t"; then ok "$t: $(command -v "$t")"; else missing="$missing $t"; fi
  done
  [ -z "$missing" ] || fail "Missing required tools:$missing. Install them and re-run."
  [ -f "$COMPOSE_FILE" ] || fail "Compose file not found at $COMPOSE_FILE — run this from a full checkout."
  TMP=$(mktemp -d "${TMPDIR:-/tmp}/vyuu-setup.XXXXXX")
}

docker_ready() {
  if docker info >/dev/null 2>&1; then DOCKER=(docker); return 0; fi
  if need_cmd docker && [ "$(uname -s)" = Linux ]; then
    if sudo -n docker info >/dev/null 2>&1; then
      DOCKER=(sudo docker)
      warn "Docker needs root on this host; using 'sudo docker'. Add yourself to the docker group to avoid that:"
      warn "  sudo usermod -aG docker \$USER   (then log out and back in)"
      return 0
    fi
  fi
  return 1
}

ensure_docker() {
  if docker_ready; then
    local dver
    dver=$("${DOCKER[@]}" version --format '{{.Server.Version}}' 2>/dev/null || true)
    ok "Docker ${dver:-?} is running"
  else
    os_ensure_docker || fail "Docker is required for this mode. Install Docker, start it, and re-run."
    if [ "$DRY_RUN" = 1 ] && ! docker_ready; then
      warn "[dry-run] Docker is not reachable; continuing with the plan as if it were."
      return 0
    fi
    docker_ready || fail "Docker is installed but the daemon is not reachable. Start it and re-run."
    ok "Docker is running"
  fi
  if "${DOCKER[@]}" compose version >/dev/null 2>&1; then
    COMPOSE=("${DOCKER[@]}" compose)
    local cver
    cver=$("${COMPOSE[@]}" version --short 2>/dev/null || true)
    ok "Docker Compose ${cver:-?}"
  else
    fail "Docker Compose v2 (the 'docker compose' plugin, 2.24+) is required. See https://docs.docker.com/compose/install/"
  fi
}

# ---------------------------------------------------------------------------
# Shared configuration (identity, secrets)
# ---------------------------------------------------------------------------
# load_stored_identity FILE — a previous run's VYUU_BOOTSTRAP_* values become
# the defaults, so a re-run prints the credentials that actually work (the
# seed only ever runs once) instead of inventing a new password.
STORED_TENANT_NAME=""; STORED_ADMIN_EMAIL=""; STORED_ADMIN_DISPLAY=""; STORED_ADMIN_PASSWORD=""
load_stored_identity() {
  STORED_TENANT_NAME=$(env_get "$1" VYUU_BOOTSTRAP_TENANT_NAME || true)
  STORED_ADMIN_EMAIL=$(env_get "$1" VYUU_BOOTSTRAP_ADMIN_EMAIL || true)
  STORED_ADMIN_DISPLAY=$(env_get "$1" VYUU_BOOTSTRAP_ADMIN_DISPLAY || true)
  STORED_ADMIN_PASSWORD=$(env_get "$1" VYUU_BOOTSTRAP_ADMIN_PASSWORD || true)
}

configure_identity() {
  ask TENANT_NAME "Organisation / tenant name" "${STORED_TENANT_NAME:-Acme Corp}"
  ask ADMIN_EMAIL "First operator email" "${STORED_ADMIN_EMAIL:-admin@example.com}"
  ask ADMIN_DISPLAY "First operator display name" "${STORED_ADMIN_DISPLAY:-Gateway admin}"
  if [ -z "$ADMIN_PASSWORD" ] && [ -n "$STORED_ADMIN_PASSWORD" ] && [ "$ADMIN_EMAIL" = "$STORED_ADMIN_EMAIL" ]; then
    ADMIN_PASSWORD=$STORED_ADMIN_PASSWORD
    info "Reusing the stored first-login password (rotate it in the console; the seed never runs twice)."
  else
    ask_secret ADMIN_PASSWORD "First operator password"
  fi
  if [ -n "$ADMIN_PASSWORD" ] && [ "${#ADMIN_PASSWORD}" -lt 12 ]; then
    fail "The password must be at least 12 characters (the gateway refuses to seed a weaker one)."
  fi
  if [ -z "$ADMIN_PASSWORD" ]; then ADMIN_PASSWORD=$(gen_password); info "Generated a first-login password (rotation is forced on first sign-in)."; fi
  if [ "$ADMIN_EMAIL" = "admin@example.com" ]; then warn "Using the placeholder email admin@example.com — change it with --admin-email for a real install."; fi
}

# Loads previously generated material so a re-run never rotates secrets.
load_or_generate_secrets() { # existing-env-file (may be missing)
  local f=$1
  TENANT_ID=$(env_get "$f" VYUU_DEFAULT_TENANT_ID || true)
  OPERATOR_SECRET=$(env_get "$f" VYUU_OPERATOR_AUTH_SIGNING_SECRET || true)
  PORTAL_SECRET=$(env_get "$f" VYUU_PORTAL_SESSION_SIGNING_SECRET || true)
  ENVELOPE_KEY=$(env_get "$f" VYUU_ENVELOPE_MASTER_KEY || true)
  if [ -n "$TENANT_ID" ]; then
    info "Reusing tenant id and signing secrets from $f"
  fi
  is_uuid "$TENANT_ID" || TENANT_ID=$(gen_uuid)
  [ -n "$OPERATOR_SECRET" ] || OPERATOR_SECRET=$(rand_hex 48)
  [ -n "$PORTAL_SECRET" ] || PORTAL_SECRET=$(rand_hex 48)
  if [ -n "$ENVELOPE_KEY" ] && ! valid_master_key "$ENVELOPE_KEY"; then
    warn "The stored VYUU_ENVELOPE_MASTER_KEY is not valid base64 of 32 bytes; generating a new one."
    warn "(Only safe if no OAuth tokens were sealed with the old key — the gateway cannot have started with it.)"
    ENVELOPE_KEY=""
  fi
  [ -n "$ENVELOPE_KEY" ] || ENVELOPE_KEY=$(rand_b64)
}

configure_secret_store() { # allowed: "memory vault aws_secrets_manager [kubernetes]"
  local default=$1; shift
  choose SECRET_STORE "Secret store for upstream MCP credentials" "$default" "$@"
  case "$SECRET_STORE" in
    memory)
      warn "memory: upstream credentials live in the gateway process and are lost on restart."
      warn "        Fine for evaluation; switch to vault / aws_secrets_manager / kubernetes for production." ;;
    vault)
      ask VAULT_ADDR_IN "Vault address" "http://127.0.0.1:8200"
      ask_secret VAULT_TOKEN_IN "Vault token"
      [ -n "$VAULT_TOKEN_IN" ] || fail "A Vault token is required for the vault backend (VYUU_SETUP_VAULT_TOKEN)." ;;
    aws_secrets_manager)
      ask AWS_REGION_IN "AWS region" "us-east-1"
      info "AWS credentials come from the standard boto3 chain (env vars, instance profile, IAM Roles Anywhere)." ;;
    kubernetes) ;;
    *) fail "Unknown secret store '$SECRET_STORE'" ;;
  esac
}

# Emits the VYUU_* settings both modes share, in KEY=VALUE form, one per line.
# Values are raw; callers quote for their format.
shared_settings() {
  printf 'VYUU_PUBLIC_BASE_URL=%s\n' "$PUBLIC_URL"
  printf 'VYUU_GATEWAY_INSTANCE_ID=%s\n' "$INSTANCE_ID"
  printf 'VYUU_DEFAULT_TENANT_ID=%s\n' "$TENANT_ID"
  printf 'VYUU_INBOUND_IDENTITY_PROVIDER=api_key\n'
  printf 'VYUU_SECRET_STORE_BACKEND=%s\n' "$SECRET_STORE"
  case "$SECRET_STORE" in
    vault) printf 'VYUU_VAULT_ADDR=%s\n' "$VAULT_ADDR_IN" ;;
    aws_secrets_manager) printf 'VYUU_AWS_REGION=%s\n' "$AWS_REGION_IN" ;;
    kubernetes) printf 'VYUU_K8S_NAMESPACE=%s\n' "$K8S_NAMESPACE" ;;
  esac
  printf 'VYUU_ENVELOPE_ENCRYPTION_BACKEND=local\n'
  printf 'VYUU_BOOTSTRAP_TENANT_ID=%s\n' "$TENANT_ID"
  printf 'VYUU_BOOTSTRAP_TENANT_NAME=%s\n' "$TENANT_NAME"
  printf 'VYUU_BOOTSTRAP_ADMIN_EMAIL=%s\n' "$ADMIN_EMAIL"
  printf 'VYUU_BOOTSTRAP_ADMIN_DISPLAY=%s\n' "$ADMIN_DISPLAY"
}
# Secret-bearing settings, same form.
secret_settings() {
  printf 'VYUU_OPERATOR_AUTH_SIGNING_SECRET=%s\n' "$OPERATOR_SECRET"
  printf 'VYUU_PORTAL_SESSION_SIGNING_SECRET=%s\n' "$PORTAL_SECRET"
  printf 'VYUU_ENVELOPE_MASTER_KEY=%s\n' "$ENVELOPE_KEY"
  printf 'VYUU_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "$ADMIN_PASSWORD"
  [ "$SECRET_STORE" = vault ] && printf 'VYUU_VAULT_TOKEN=%s\n' "$VAULT_TOKEN_IN"
  return 0
}

print_credentials() {
  printf '\n%s%sSign-in details%s\n' "$(_c 1)" "$(_c 32)" "$(_c 0)"
  kv "Operator console" "$PUBLIC_URL/operator"
  kv "End-user portal" "$PUBLIC_URL/portal"
  kv "Tenant / organisation id" "$TENANT_ID  (pre-filled: the login pages resolve it automatically)"
  kv "Email" "$ADMIN_EMAIL"
  kv "Password" "$ADMIN_PASSWORD  (you will be asked to change it on first sign-in)"
  kv "Saved to" "$CREDENTIALS_FILE  (mode 0600 — delete once rotated)"
}

# ===========================================================================
# MODE: single VM (Docker Compose)
# ===========================================================================
compose() { "${COMPOSE[@]}" -f "$COMPOSE_FILE" --project-directory "$COMPOSE_DIR" "$@"; }

vm_configure() {
  step "Configure (single VM · Docker Compose)"
  local host
  host=$(hostname 2>/dev/null || echo localhost)
  ask GATEWAY_PORT "Host port for the gateway" "8000"
  ask PUBLIC_URL "Public URL clients will use (put your TLS proxy here later)" "http://$host:$GATEWAY_PORT"
  load_stored_identity "$GATEWAY_ENV"
  configure_identity
  configure_secret_store memory \
    "memory|In-process (evaluation only)" \
    "vault|HashiCorp Vault KV v2" \
    "aws_secrets_manager|AWS Secrets Manager"
  INSTANCE_ID=$(env_get "$GATEWAY_ENV" VYUU_GATEWAY_INSTANCE_ID || true)
  [ -n "$INSTANCE_ID" ] || INSTANCE_ID="gateway-$host"
  load_or_generate_secrets "$GATEWAY_ENV"
  POSTGRES_PASSWORD=$(env_get "$COMPOSE_ENV" POSTGRES_PASSWORD || true)
  [ -n "$POSTGRES_PASSWORD" ] || POSTGRES_PASSWORD=$(rand_hex 16)
  if [ -z "$IMAGE" ]; then IMAGE="vyuu-gateway:latest"; fi
  CREDENTIALS_FILE=$GATEWAY_ENV
}

vm_write_env() {
  step "Write configuration"
  if [ "$DRY_RUN" = 1 ]; then info "[dry-run] would write $COMPOSE_ENV and $GATEWAY_ENV (mode 0600)"; return 0; fi
  umask 077
  {
    printf '# Docker Compose interpolation values — written by deploy/setup on %s. Keep private.\n' "$(date)"
    printf 'POSTGRES_PASSWORD=%s\n' "$POSTGRES_PASSWORD"
    printf 'VYUU_IMAGE=%s\n' "$IMAGE"
    printf 'VYUU_GATEWAY_PORT=%s\n' "$GATEWAY_PORT"
  } > "$COMPOSE_ENV"
  {
    printf '# Vyuu MCP Gateway — deployment identity + secrets (compose env_file).\n'
    printf '# Written by deploy/setup on %s. Mode 0600. Never commit this file.\n' "$(date)"
    printf '# Re-running the setup script keeps every value below.\n#\n'
    printf '# The VYUU_BOOTSTRAP_* block seeds the first admin once (it is ignored as soon as\n'
    printf '# an operator exists). Remove those lines after the first sign-in if you prefer\n'
    printf '# not to keep the initial password on disk.\n'
    { shared_settings; secret_settings; } | while IFS= read -r line; do
      printf '%s=%s\n' "${line%%=*}" "$(env_sq "${line#*=}")"
    done
  } > "$GATEWAY_ENV"
  chmod 0600 "$COMPOSE_ENV" "$GATEWAY_ENV"
  ok "Wrote $COMPOSE_ENV"
  ok "Wrote $GATEWAY_ENV"
}

vm_deploy() {
  step "Deploy"
  # A re-run finds our own gateway on the port; anything else is a conflict
  # worth naming now rather than as a bind error from Docker later.
  if [ "$DRY_RUN" != 1 ] && port_in_use "$GATEWAY_PORT" && [ -z "$(compose ps -q --status running gateway 2>/dev/null)" ]; then
    fail "Port $GATEWAY_PORT is already in use on this host. Re-run with --port <free port> (the gateway container always listens on 8000 internally)."
  fi
  if [ "$IMAGE" = "vyuu-gateway:latest" ]; then
    info "Building the gateway image from this checkout (first build takes a few minutes)"
    run compose build gateway
  else
    info "Pulling $IMAGE"
    run compose pull gateway
  fi
  info "Starting Postgres, Redis and NATS"
  run compose up -d --wait postgres redis nats
  info "Applying database migrations (alembic upgrade head)"
  run compose run --rm --no-deps gateway alembic upgrade head
  info "Starting the gateway"
  run compose up -d --wait gateway
}

vm_verify() {
  step "Verify"
  if [ "$DRY_RUN" = 1 ]; then info "[dry-run] would wait for http://127.0.0.1:$GATEWAY_PORT/healthz and test the operator login"; return 0; fi
  info "Waiting for the gateway health probe"
  wait_http "http://127.0.0.1:$GATEWAY_PORT/healthz" 120 || {
    compose logs --tail=40 gateway >&2 || true
    fail "The gateway did not become healthy. The last log lines are above."
  }
  ok "/healthz is green"
  if login_smoke "http://127.0.0.1:$GATEWAY_PORT"; then
    ok "Operator sign-in works for $ADMIN_EMAIL"
  else
    warn "Health is green but the operator sign-in did not succeed. If this gateway was bootstrapped earlier with"
    warn "different credentials, sign in with those — the seed only runs once. Details: $TMP/login.json"
    compose logs --tail=20 gateway >&2 || true
  fi
}

vm_summary() {
  step "Done"
  local ip
  ip=$(os_local_ip 2>/dev/null || true)
  print_credentials
  printf '\n%s%sNext steps%s\n' "$(_c 1)" "$(_c 34)" "$(_c 0)"
  [ -n "$ip" ] && kv "On your LAN" "http://$ip:$GATEWAY_PORT/operator"
  kv "Logs" "docker compose -f deploy/docker/docker-compose.yml logs -f gateway"
  kv "Stop / start" "docker compose -f deploy/docker/docker-compose.yml stop | start"
  kv "Upgrade" "git pull && $0 --mode vm   (rebuilds, migrates, restarts)"
  kv "Remove" "$0 --teardown --mode vm [--purge]"
  say ""
  say "   Put a TLS terminator (nginx, Caddy, Traefik) in front of port $GATEWAY_PORT before exposing"
  say "   the gateway beyond this host, then set --public-url to that https origin and re-run."
  [ "$SECRET_STORE" = memory ] && say "   Secret store is 'memory' (evaluation). See docs/DEPLOYMENT.md for Vault / AWS."
  return 0
}

vm_teardown() {
  step "Teardown (single VM)"
  ensure_docker
  if [ "$PURGE" = 1 ]; then
    # --purge is explicit consent; the prompt only guards interactive typos.
    if interactive; then confirm "Remove containers AND volumes (the database) AND the env files?" n || fail "Aborted."; fi
    run compose down --remove-orphans -v
    run rm -f "$COMPOSE_ENV" "$GATEWAY_ENV"
    ok "Containers, volumes and env files removed"
  else
    run compose down --remove-orphans
    ok "Containers removed; database volume and env files kept (add --purge to delete them)"
  fi
}

# ===========================================================================
# MODE: Kubernetes
# ===========================================================================
kc() { "${KUBECTL[@]}" --context "$K8S_CONTEXT" "$@"; }
kcn() { kc -n "$K8S_NAMESPACE" "$@"; }

k8s_detect_cluster_kind() {
  case "$K8S_CONTEXT" in
    kind-*) CLUSTER_KIND=kind ;;
    docker-desktop) CLUSTER_KIND=docker-desktop ;;
    minikube*) CLUSTER_KIND=minikube ;;
    k3d-*) CLUSTER_KIND=k3d ;;
    orbstack) CLUSTER_KIND=orbstack ;;
    colima*) CLUSTER_KIND=colima ;;
    rancher-desktop) CLUSTER_KIND=rancher-desktop ;;
    *) CLUSTER_KIND=remote ;;
  esac
}

k8s_cluster_reachable() { kc cluster-info --request-timeout=10s >/dev/null 2>&1; }

k8s_preflight() {
  step "Kubernetes preflight"
  local requested_context=$K8S_CONTEXT contexts current version
  if ! need_cmd kubectl; then
    if may_install kubectl; then os_ensure_kubectl || fail "kubectl could not be installed."; else fail "kubectl is required. Install it and re-run (see os hint below)."; fi
  fi
  if ! need_cmd kubectl; then
    [ "$DRY_RUN" = 1 ] || fail "kubectl is still not on PATH."
    warn "[dry-run] kubectl is not installed; continuing with the plan as if it were."
    K8S_CONTEXT=${K8S_CONTEXT:-dry-run}
    k8s_detect_cluster_kind
    return 0
  fi
  version=$(kubectl version --client 2>/dev/null | head -1 | sed 's/Client Version: //' || true)
  ok "kubectl ${version:-?}"
  contexts=$(kubectl config get-contexts -o name 2>/dev/null || true)
  current=$(kubectl config current-context 2>/dev/null || true)
  if [ -z "$K8S_CONTEXT" ] && [ -n "$contexts" ]; then
    say "   Available contexts:"; printf '%s\n' "$contexts" | sed 's/^/     - /'
    ask K8S_CONTEXT "kubectl context to deploy into" "${current:-}"
  fi
  if [ -z "$K8S_CONTEXT" ] || ! k8s_cluster_reachable; then
    warn "No reachable Kubernetes cluster${K8S_CONTEXT:+ via context $K8S_CONTEXT}."
    if [ -n "$requested_context" ] && ! interactive; then
      fail "Context '$requested_context' was requested explicitly but is not reachable. Fix access or pick another --context."
    fi
    if k8s_offer_local_cluster; then :; else os_local_cluster_hint; fail "Point --context at a reachable cluster and re-run."; fi
  fi
  k8s_detect_cluster_kind
  ok "Cluster reachable via context '$K8S_CONTEXT' ($CLUSTER_KIND)"
}

# Creates a local kind cluster when the user agrees. Needs Docker.
k8s_offer_local_cluster() {
  if ! confirm "Create a local 'kind' cluster in Docker for this install?" y; then return 1; fi
  ensure_docker
  if ! need_cmd kind; then
    if may_install kind; then os_ensure_kind || fail "kind could not be installed."; else return 1; fi
  fi
  if ! kind get clusters 2>/dev/null | grep -qx vyuu; then
    info "Creating kind cluster 'vyuu' (about a minute)"
    run kind create cluster --name vyuu --wait 120s
  fi
  K8S_CONTEXT=kind-vyuu
  if [ "$DRY_RUN" = 1 ]; then return 0; fi
  k8s_cluster_reachable
}

k8s_configure() {
  step "Configure (Kubernetes)"
  ask K8S_NAMESPACE "Namespace" "vyuu"
  local default_replicas=3 default_strategy=pull
  case "$CLUSTER_KIND" in remote) ;; *) default_replicas=1; default_strategy=build-local ;; esac
  ask K8S_REPLICAS "Gateway replicas" "$default_replicas"
  choose K8S_IMAGE_STRATEGY "Gateway image" "$default_strategy" \
    "build-local|Build from this checkout and load it into the local cluster" \
    "build-push|Build from this checkout and push to a registry you name" \
    "pull|Use an image that already exists in a registry"
  case "$K8S_IMAGE_STRATEGY" in
    build-local)
      case "$CLUSTER_KIND" in
        remote) fail "build-local only works for local clusters (kind, minikube, k3d, Docker Desktop, OrbStack, Colima). Use build-push or pull." ;;
      esac
      IMAGE="vyuu-gateway:local-$(date +%Y%m%d%H%M%S)"; IMAGE_PULL_POLICY=IfNotPresent ;;
    build-push)
      ask IMAGE "Image reference to push (registry/repo:tag)" ""
      [ -n "$IMAGE" ] || fail "--image is required for build-push"
      IMAGE_PULL_POLICY=Always ;;
    pull)
      ask IMAGE "Image reference to deploy" ""
      [ -n "$IMAGE" ] || fail "--image is required for pull"
      IMAGE_PULL_POLICY=Always ;;
    *) fail "Unknown image strategy '$K8S_IMAGE_STRATEGY'" ;;
  esac
  ask DB_URL "External Postgres URL (empty = in-cluster evaluation Postgres)" ""
  ask REDIS_URL "External Redis URL (empty = in-cluster Redis)" ""
  ask INGRESS_HOST "Ingress hostname (empty = none, access via port-forward)" ""
  if [ -n "$INGRESS_HOST" ]; then
    ask INGRESS_CLASS "Ingress class" "nginx"
    ask TLS_SECRET "TLS secret name for the Ingress (empty = plain http)" ""
    if [ -z "$PUBLIC_URL" ]; then if [ -n "$TLS_SECRET" ]; then PUBLIC_URL="https://$INGRESS_HOST"; else PUBLIC_URL="http://$INGRESS_HOST"; fi; fi
  fi
  ask PUBLIC_URL "Public URL clients will use" "http://127.0.0.1:$LOCAL_PORT"
  load_stored_identity "$GEN_DIR/secrets.env"
  configure_identity
  local default_store=kubernetes
  [ "$CLUSTER_KIND" = remote ] || default_store=memory
  configure_secret_store "$default_store" \
    "kubernetes|Kubernetes Secrets in this namespace (vyuu-<tenant_id>)" \
    "vault|HashiCorp Vault KV v2" \
    "aws_secrets_manager|AWS Secrets Manager" \
    "memory|In-process (evaluation only)"
  INSTANCE_ID="gateway-$K8S_NAMESPACE"
  [ "$DRY_RUN" = 1 ] || mkdir -p "$GEN_DIR"
  load_or_generate_secrets "$GEN_DIR/secrets.env"
  if [ -z "$DB_URL" ]; then
    POSTGRES_PASSWORD=$(env_get "$GEN_DIR/secrets.env" POSTGRES_PASSWORD || true)
    [ -n "$POSTGRES_PASSWORD" ] || POSTGRES_PASSWORD=$(rand_hex 16)
    DB_URL="postgresql+psycopg://vyuu:$POSTGRES_PASSWORD@vyuu-postgres.$K8S_NAMESPACE.svc:5432/vyuu_gateway"
  fi
  [ -n "$REDIS_URL" ] || REDIS_URL="redis://vyuu-redis.$K8S_NAMESPACE.svc:6379/0"
  CREDENTIALS_FILE=$GEN_DIR/credentials.txt
}

# Drops whole YAML documents whose `kind:` matches $2 from file $1 (stdout).
yaml_drop_kinds() {
  awk -v drop="$2" '
    function flush() {
      if (buf != "" && buf !~ ("kind: (" drop ")")) { if (n++) printf "---\n"; printf "%s", buf }
      buf = ""
    }
    /^---[[:space:]]*$/ { flush(); next }
    { buf = buf $0 "\n" }
    END { flush() }' "$1"
}

k8s_render() {
  step "Render manifests → $GEN_DIR"
  if [ "$DRY_RUN" = 1 ]; then info "[dry-run] would render namespace, configmap, secret, add-ons, migrate job, deployment into $GEN_DIR"; return 0; fi
  mkdir -p "$GEN_DIR"; chmod 0700 "$GEN_DIR"; umask 077
  local automount=false sub
  [ "$SECRET_STORE" = kubernetes ] && automount=true
  sub="s|__NAMESPACE__|$K8S_NAMESPACE|g; s|__IMAGE__|$IMAGE|g; s|__IMAGE_PULL_POLICY__|$IMAGE_PULL_POLICY|g; s|__TENANT_ID__|$TENANT_ID|g; s|__POSTGRES_PASSWORD__|$POSTGRES_PASSWORD|g"

  printf 'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n  labels:\n    app.kubernetes.io/part-of: vyuu-gateway\n' "$K8S_NAMESPACE" > "$GEN_DIR/00-namespace.yaml"
  # The ServiceAccount is shared by the migration Job and the Deployment, so it
  # is applied first, on its own (the copy inside deployment.yaml is dropped).
  printf 'apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: vyuu-gateway\n  namespace: %s\nautomountServiceAccountToken: %s\n' "$K8S_NAMESPACE" "$automount" > "$GEN_DIR/05-serviceaccount.yaml"

  { sed -e "s|^  namespace: vyuu$|  namespace: $K8S_NAMESPACE|" "$K8S_DIR/configmap.yaml"
    printf '\n  # ---- Written by deploy/setup ------------------------------------------\n'
    shared_settings | while IFS= read -r line; do printf '  %s: %s\n' "${line%%=*}" "$(yaml_dq "${line#*=}")"; done
  } > "$GEN_DIR/10-configmap.yaml"

  { printf 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: vyuu-gateway-secrets\n  namespace: %s\ntype: Opaque\nstringData:\n' "$K8S_NAMESPACE"
    printf '  VYUU_DATABASE_URL: %s\n' "$(yaml_dq "$DB_URL")"
    printf '  VYUU_REDIS_URL: %s\n' "$(yaml_dq "$REDIS_URL")"
    secret_settings | while IFS= read -r line; do printf '  %s: %s\n' "${line%%=*}" "$(yaml_dq "${line#*=}")"; done
  } > "$GEN_DIR/11-secret.yaml"

  { printf '# Re-run material for deploy/setup (mode 0600). Never commit.\n'
    printf 'VYUU_DEFAULT_TENANT_ID=%s\n' "$TENANT_ID"
    printf 'VYUU_OPERATOR_AUTH_SIGNING_SECRET=%s\n' "$OPERATOR_SECRET"
    printf 'VYUU_PORTAL_SESSION_SIGNING_SECRET=%s\n' "$PORTAL_SECRET"
    printf 'VYUU_ENVELOPE_MASTER_KEY=%s\n' "$ENVELOPE_KEY"
    [ -n "$POSTGRES_PASSWORD" ] && printf 'POSTGRES_PASSWORD=%s\n' "$POSTGRES_PASSWORD"
    printf 'VYUU_BOOTSTRAP_TENANT_NAME=%s\n' "$(env_sq "$TENANT_NAME")"
    printf 'VYUU_BOOTSTRAP_ADMIN_EMAIL=%s\n' "$(env_sq "$ADMIN_EMAIL")"
    printf 'VYUU_BOOTSTRAP_ADMIN_DISPLAY=%s\n' "$(env_sq "$ADMIN_DISPLAY")"
    printf 'VYUU_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "$(env_sq "$ADMIN_PASSWORD")"
  } > "$GEN_DIR/secrets.env"

  rm -f "$GEN_DIR/12-rbac.yaml" "$GEN_DIR/20-postgres.yaml" "$GEN_DIR/21-redis.yaml" "$GEN_DIR/50-ingress.yaml"
  [ "$SECRET_STORE" = kubernetes ] && sed -e "$sub" "$K8S_DIR/rbac-secret-store.yaml" > "$GEN_DIR/12-rbac.yaml"
  case "$DB_URL" in *"@vyuu-postgres.$K8S_NAMESPACE.svc:"*) sed -e "$sub" "$K8S_DIR/addons/postgres.yaml" > "$GEN_DIR/20-postgres.yaml" ;; esac
  case "$REDIS_URL" in *"vyuu-redis.$K8S_NAMESPACE.svc:"*) sed -e "$sub" "$K8S_DIR/addons/redis.yaml" > "$GEN_DIR/21-redis.yaml" ;; esac
  sed -e "$sub" "$K8S_DIR/migrate-job.yaml" > "$GEN_DIR/30-migrate-job.yaml"

  local csum_config csum_secret
  csum_config=$(sha256_of "$GEN_DIR/10-configmap.yaml"); csum_secret=$(sha256_of "$GEN_DIR/11-secret.yaml")
  sed -e "s|^  namespace: vyuu$|  namespace: $K8S_NAMESPACE|" \
      -e "s|image: ghcr.io/your-org/vyuu-gateway:v1.0.0|image: $IMAGE|" \
      -e "s|imagePullPolicy: IfNotPresent|imagePullPolicy: $IMAGE_PULL_POLICY|" \
      -e "s|^  replicas: 3$|  replicas: $K8S_REPLICAS|" \
      -e "s|\"\${CHECKSUM_CONFIG}\"|\"$csum_config\"|" \
      -e "s|\"\${CHECKSUM_SECRET}\"|\"$csum_secret\"|" \
      -e "s|^      automountServiceAccountToken: false$|      automountServiceAccountToken: $automount|" \
      "$K8S_DIR/deployment.yaml" > "$TMP/deployment.yaml"
  if [ "$K8S_REPLICAS" -lt 3 ]; then
    info "replicas=$K8S_REPLICAS: leaving out the PodDisruptionBudget and HPA (they assume 3+)"
    yaml_drop_kinds "$TMP/deployment.yaml" "ServiceAccount|PodDisruptionBudget|HorizontalPodAutoscaler" > "$GEN_DIR/40-gateway.yaml"
  else
    yaml_drop_kinds "$TMP/deployment.yaml" "ServiceAccount" > "$GEN_DIR/40-gateway.yaml"
  fi
  if [ -n "$INGRESS_HOST" ]; then
    local tls="# tls: none (plain http)"
    [ -n "$TLS_SECRET" ] && tls="tls: [{hosts: [\"$INGRESS_HOST\"], secretName: \"$TLS_SECRET\"}]"
    sed -e "$sub" -e "s|__HOST__|$INGRESS_HOST|g" -e "s|__INGRESS_CLASS__|$INGRESS_CLASS|g" -e "s|__TLS_LINE__|$tls|" \
      "$K8S_DIR/ingress.yaml.example" > "$GEN_DIR/50-ingress.yaml"
  fi
  { printf 'Vyuu MCP Gateway — written by deploy/setup on %s. Mode 0600. Delete once rotated.\n' "$(date)"
    printf 'context=%s namespace=%s\n' "$K8S_CONTEXT" "$K8S_NAMESPACE"
    printf 'operator console: %s/operator\nportal: %s/portal\n' "$PUBLIC_URL" "$PUBLIC_URL"
    printf 'tenant_id=%s\nemail=%s\npassword=%s\n' "$TENANT_ID" "$ADMIN_EMAIL" "$ADMIN_PASSWORD"
  } > "$CREDENTIALS_FILE"
  chmod 0600 "$GEN_DIR"/*.yaml "$GEN_DIR/secrets.env" "$CREDENTIALS_FILE"
  local rendered=""
  for f in "$GEN_DIR"/*.yaml; do rendered="$rendered ${f##*/}"; done
  ok "Rendered:$rendered"
}

k8s_build_image() {
  case "$K8S_IMAGE_STRATEGY" in
    build-local|build-push) ;;
    *) return 0 ;;
  esac
  step "Build image $IMAGE"
  ensure_docker
  run "${DOCKER[@]}" build -t "$IMAGE" "$REPO_ROOT"
  case "$K8S_IMAGE_STRATEGY" in
    build-push) info "Pushing $IMAGE"; run "${DOCKER[@]}" push "$IMAGE" ;;
    build-local)
      case "$CLUSTER_KIND" in
        kind) run kind load docker-image "$IMAGE" --name "${K8S_CONTEXT#kind-}" ;;
        minikube) run minikube -p "$K8S_CONTEXT" image load "$IMAGE" ;;
        k3d) run k3d image import "$IMAGE" -c "${K8S_CONTEXT#k3d-}" ;;
        docker-desktop|orbstack|rancher-desktop|colima) info "Cluster shares the local Docker image store; nothing to load." ;;
      esac ;;
  esac
}

k8s_apply() {
  step "Apply to '$K8S_CONTEXT' / namespace '$K8S_NAMESPACE'"
  if [ "$DRY_RUN" = 1 ]; then info "[dry-run] would kubectl apply the rendered files in order, wait for Postgres/Redis, run the migration Job, then roll out the gateway"; return 0; fi
  kc apply -f "$GEN_DIR/00-namespace.yaml"
  kc apply -f "$GEN_DIR/05-serviceaccount.yaml" -f "$GEN_DIR/10-configmap.yaml" -f "$GEN_DIR/11-secret.yaml"
  [ -f "$GEN_DIR/12-rbac.yaml" ] && kc apply -f "$GEN_DIR/12-rbac.yaml"
  if [ -f "$GEN_DIR/20-postgres.yaml" ]; then
    kc apply -f "$GEN_DIR/20-postgres.yaml"
    info "Waiting for Postgres"; kcn rollout status statefulset/vyuu-postgres --timeout=300s
  fi
  if [ -f "$GEN_DIR/21-redis.yaml" ]; then
    kc apply -f "$GEN_DIR/21-redis.yaml"
    info "Waiting for Redis"; kcn rollout status deployment/vyuu-redis --timeout=180s
  fi
  info "Running database migrations (Job vyuu-gateway-migrate)"
  kcn delete job vyuu-gateway-migrate --ignore-not-found >/dev/null
  kc apply -f "$GEN_DIR/30-migrate-job.yaml"
  if ! kcn wait --for=condition=complete --timeout=300s job/vyuu-gateway-migrate >/dev/null 2>&1; then
    kcn describe job/vyuu-gateway-migrate 2>/dev/null | sed -n '/^Events:/,$p' >&2 || true
    kcn logs job/vyuu-gateway-migrate --tail=60 >&2 || true
    fail "The migration Job did not complete. Its events and logs are above."
  fi
  ok "Migrations applied"
  kc apply -f "$GEN_DIR/40-gateway.yaml"
  info "Waiting for the gateway rollout"; kcn rollout status deployment/vyuu-gateway --timeout=300s
  [ -f "$GEN_DIR/50-ingress.yaml" ] && kc apply -f "$GEN_DIR/50-ingress.yaml"
  return 0
}

k8s_verify() {
  step "Verify"
  if [ "$DRY_RUN" = 1 ]; then info "[dry-run] would port-forward svc/vyuu-gateway to 127.0.0.1:$LOCAL_PORT, check /healthz and test the operator login"; return 0; fi
  kcn port-forward svc/vyuu-gateway "$LOCAL_PORT:80" >"$TMP/pf.log" 2>&1 &
  PF_PID=$!
  info "Port-forward on 127.0.0.1:$LOCAL_PORT (pid $PF_PID)"
  wait_http "http://127.0.0.1:$LOCAL_PORT/healthz" 90 || {
    kcn logs deployment/vyuu-gateway --tail=40 >&2 || true
    fail "The gateway did not answer on /healthz through the port-forward. Pod logs are above."
  }
  ok "/healthz is green"
  if login_smoke "http://127.0.0.1:$LOCAL_PORT"; then
    ok "Operator sign-in works for $ADMIN_EMAIL"
  else
    warn "Health is green but the operator sign-in did not succeed. If this database was bootstrapped earlier with"
    warn "different credentials, sign in with those — the seed only runs once. Details: $TMP/login.json"
  fi
  kill "$PF_PID" >/dev/null 2>&1 || true; PF_PID=""
}

k8s_summary() {
  step "Done"
  print_credentials
  printf '\n%s%sNext steps%s\n' "$(_c 1)" "$(_c 34)" "$(_c 0)"
  if [ -n "$INGRESS_HOST" ]; then
    kv "Ingress" "$PUBLIC_URL  (DNS for $INGRESS_HOST must point at your ingress controller)"
  fi
  kv "Local access" "kubectl --context $K8S_CONTEXT -n $K8S_NAMESPACE port-forward svc/vyuu-gateway $LOCAL_PORT:80"
  kv "Logs" "kubectl --context $K8S_CONTEXT -n $K8S_NAMESPACE logs -f deployment/vyuu-gateway"
  kv "Upgrade" "git pull && $0 --mode k8s   (re-renders, migrates, rolls out)"
  kv "Remove" "$0 --teardown --mode k8s [--purge]"
  kv "Manifests" "$GEN_DIR  (what was applied, secrets included — keep private)"
  say ""
  say "   After the first sign-in, drop the bootstrap block from the Secret so the initial password"
  say "   is not kept in the cluster:"
  say "     kubectl --context $K8S_CONTEXT -n $K8S_NAMESPACE patch secret vyuu-gateway-secrets --type=json \\"
  say "       -p='[{\"op\":\"remove\",\"path\":\"/data/VYUU_BOOTSTRAP_ADMIN_PASSWORD\"}]'"
  if [ "$SECRET_STORE" = kubernetes ]; then
    say "   Upstream MCP credentials go into one Secret for this tenant, keyed by reference name:"
    say "     kubectl --context $K8S_CONTEXT -n $K8S_NAMESPACE create secret generic vyuu-$TENANT_ID --from-literal=<ref>=<value>"
  fi
  [ -f "$GEN_DIR/20-postgres.yaml" ] && say "   Postgres runs in-cluster on a single PVC (evaluation grade). Point --db-url at managed Postgres for production."
  [ "$SECRET_STORE" = memory ] && say "   Secret store is 'memory' (evaluation). Re-run with --secret-store kubernetes|vault|aws_secrets_manager for production."
  return 0
}

k8s_teardown() {
  step "Teardown (Kubernetes)"
  need_cmd kubectl || fail "kubectl not found."
  [ -n "$K8S_CONTEXT" ] || K8S_CONTEXT=$(kubectl config current-context 2>/dev/null || true)
  [ -n "$K8S_CONTEXT" ] || fail "No kubectl context; pass --context."
  ask K8S_NAMESPACE "Namespace" "vyuu"
  if [ "$PURGE" = 1 ]; then
    if interactive; then confirm "Delete namespace '$K8S_NAMESPACE' on '$K8S_CONTEXT' (all pods, the database volume) AND the generated files?" n || fail "Aborted."; fi
    run kc delete namespace "$K8S_NAMESPACE" --ignore-not-found --wait=true
    run rm -rf "$GEN_DIR"
    ok "Namespace and generated files removed"
    if [ "$K8S_CONTEXT" = kind-vyuu ] && need_cmd kind && confirm "Also delete the local kind cluster 'vyuu'?" n; then run kind delete cluster --name vyuu; fi
  else
    for f in 50-ingress 40-gateway 30-migrate-job 21-redis 12-rbac 05-serviceaccount; do
      [ -f "$GEN_DIR/$f.yaml" ] && run kc delete -f "$GEN_DIR/$f.yaml" --ignore-not-found
    done
    ok "Gateway, Redis, migration Job and RBAC removed; Postgres, its volume, Secret/ConfigMap and generated files kept (add --purge to delete everything)"
  fi
}

# ===========================================================================
# Entry point
# ===========================================================================
vyuu_setup_main() {
  parse_args "$@"
  banner
  preflight_common
  if [ -z "$MODE" ]; then
    choose MODE "What are you setting up?" vm \
      "vm|Single VM / single host — Docker Compose (gateway + Postgres + Redis + NATS)" \
      "k8s|Kubernetes — render and apply deploy/kubernetes into a namespace"
  fi
  if [ "$ACTION" = teardown ]; then
    case "$MODE" in vm) vm_teardown ;; k8s) k8s_teardown ;; esac
    return 0
  fi
  case "$MODE" in
    vm)
      ensure_docker
      vm_configure; vm_write_env; vm_deploy; vm_verify; vm_summary ;;
    k8s)
      k8s_preflight; k8s_configure; k8s_render; k8s_build_image; k8s_apply; k8s_verify; k8s_summary ;;
  esac
}
