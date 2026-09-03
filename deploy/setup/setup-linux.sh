#!/usr/bin/env bash
# Vyuu MCP Gateway — one-command setup for Linux hosts.
#
#   ./deploy/setup/setup-linux.sh                 interactive
#   ./deploy/setup/setup-linux.sh --mode vm -y    single VM (Docker Compose), non-interactive
#   ./deploy/setup/setup-linux.sh --mode k8s      Kubernetes
#   ./deploy/setup/setup-linux.sh --help          every option
#
# Tested paths: Ubuntu / Debian (apt) and Fedora / RHEL-family (dnf). Other
# distributions work when Docker (or kubectl) is already installed. The
# shared logic lives in lib/common.sh; this file only knows how to install
# tools on Linux.

set -o errexit -o nounset -o pipefail

if [ "$(uname -s)" != Linux ]; then
  printf 'This is the Linux variant. On macOS run deploy/setup/setup-macos.sh\n' >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# OS hooks (see lib/common.sh for the contract)
# ---------------------------------------------------------------------------
os_id() { # debian | ubuntu | fedora | rhel | ... (lower-case, from os-release)
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    ( . /etc/os-release && printf '%s %s' "${ID:-}" "${ID_LIKE:-}" ) | tr '[:upper:]' '[:lower:]'
  fi
}
os_label() {
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    ( . /etc/os-release && printf '%s' "${PRETTY_NAME:-Linux}" )
  else
    printf 'Linux'
  fi
}
os_arch() { case "$(uname -m)" in x86_64) echo amd64 ;; aarch64|arm64) echo arm64 ;; *) uname -m ;; esac; }

_sudo() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }

os_ensure_docker() {
  if need_cmd docker; then
    info "Docker is installed but not running — starting it"
    run _sudo systemctl enable --now docker || true
    return 0
  fi
  case " $(os_id) " in
    *debian*|*ubuntu*|*fedora*|*rhel*|*centos*|*rocky*|*alma*) ;;
    *) warn "Unrecognised distribution; install Docker Engine + the compose plugin manually: https://docs.docker.com/engine/install/"; return 1 ;;
  esac
  may_install "Docker Engine (via https://get.docker.com)" || {
    warn "Install Docker Engine and the compose plugin, then re-run: https://docs.docker.com/engine/install/"
    return 1
  }
  info "Installing Docker Engine with Docker's official install script"
  if [ "$DRY_RUN" = 1 ]; then run sh -c 'curl -fsSL https://get.docker.com | sh'; return 0; fi
  curl -fsSL https://get.docker.com -o "$TMP/get-docker.sh"
  _sudo sh "$TMP/get-docker.sh"
  _sudo systemctl enable --now docker
  if [ "$(id -u)" != 0 ]; then
    _sudo usermod -aG docker "$USER" || true
    warn "Added $USER to the docker group; it takes effect after you log out and back in. This run continues with sudo."
  fi
  return 0
}

os_ensure_kubectl() {
  local ver
  info "Installing kubectl to /usr/local/bin"
  ver=$(curl -fsSL https://dl.k8s.io/release/stable.txt)
  run curl -fsSLo "$TMP/kubectl" "https://dl.k8s.io/release/$ver/bin/linux/$(os_arch)/kubectl"
  run _sudo install -m 0755 "$TMP/kubectl" /usr/local/bin/kubectl
}

os_ensure_kind() {
  info "Installing kind to /usr/local/bin"
  run curl -fsSLo "$TMP/kind" "https://github.com/kubernetes-sigs/kind/releases/latest/download/kind-linux-$(os_arch)"
  run _sudo install -m 0755 "$TMP/kind" /usr/local/bin/kind
}

os_local_cluster_hint() {
  say "   Options for a cluster on this host:"
  say "     - kind (runs in Docker):  re-run and answer yes when offered, or: kind create cluster --name vyuu"
  say "     - k3s (single node):      curl -sfL https://get.k3s.io | sh -   then   export KUBECONFIG=/etc/rancher/k3s/k3s.yaml"
  say "     - a managed cluster:      point kubectl at it and pass --context <name>"
}

os_local_ip() { hostname -I 2>/dev/null | awk '{print $1}'; }

# ---------------------------------------------------------------------------
# shellcheck source=lib/common.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"
vyuu_setup_main "$@"
