#!/usr/bin/env bash
# Vyuu MCP Gateway — one-command setup for macOS.
#
#   ./deploy/setup/setup-macos.sh                 interactive
#   ./deploy/setup/setup-macos.sh --mode vm -y    single host (Docker Compose), non-interactive
#   ./deploy/setup/setup-macos.sh --mode k8s      Kubernetes (Docker Desktop, kind, Colima, or remote)
#   ./deploy/setup/setup-macos.sh --help          every option
#
# Works with the bash 3.2 that ships with macOS. Tools are installed with
# Homebrew when you allow it. The shared logic lives in lib/common.sh; this
# file only knows how to install and start things on a Mac.

set -o errexit -o nounset -o pipefail

if [ "$(uname -s)" != Darwin ]; then
  printf 'This is the macOS variant. On Linux run deploy/setup/setup-linux.sh\n' >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# OS hooks (see lib/common.sh for the contract)
# ---------------------------------------------------------------------------
os_label() { printf 'macOS %s · %s' "$(sw_vers -productVersion 2>/dev/null || echo '?')" "$(uname -m)"; }

_brew() {
  if ! need_cmd brew; then
    warn "Homebrew is not installed. Get it from https://brew.sh, then re-run — or install the tool by hand."
    return 1
  fi
  run brew "$@"
}

# Waits until the Docker daemon answers (Docker Desktop / Colima start asynchronously).
_wait_docker() {
  local waited=0
  while [ "$waited" -lt 120 ]; do
    if docker info >/dev/null 2>&1; then return 0; fi
    sleep 3; waited=$((waited + 3))
  done
  return 1
}

os_ensure_docker() {
  local runtime
  if need_cmd docker; then
    if [ -d /Applications/Docker.app ]; then
      info "Starting Docker Desktop"
      run open -a Docker
    elif need_cmd colima; then
      info "Starting Colima"
      run colima start
    else
      warn "docker is installed but no daemon is running. Start Docker Desktop, Colima or OrbStack and re-run."
      return 1
    fi
    [ "$DRY_RUN" = 1 ] || _wait_docker || return 1
    return 0
  fi
  may_install "Docker" || {
    warn "Install Docker Desktop (https://docs.docker.com/desktop/setup/install/mac-install/) or 'brew install colima docker docker-compose', then re-run."
    return 1
  }
  runtime=desktop
  choose runtime "Which Docker runtime?" desktop \
    "desktop|Docker Desktop (brew install --cask docker)" \
    "colima|Colima — lightweight, CLI-only (brew install colima docker docker-compose)"
  case "$runtime" in
    desktop)
      _brew install --cask docker || return 1
      run open -a Docker
      info "Docker Desktop is starting; accept its first-run dialog if it appears" ;;
    colima)
      _brew install colima docker docker-compose || return 1
      # Expose Homebrew's docker-compose as the `docker compose` plugin.
      run mkdir -p "$HOME/.docker/cli-plugins"
      run ln -sfn "$(brew --prefix)/opt/docker-compose/bin/docker-compose" "$HOME/.docker/cli-plugins/docker-compose"
      run colima start --cpu 4 --memory 6 ;;
  esac
  [ "$DRY_RUN" = 1 ] || _wait_docker
}

os_ensure_kubectl() { _brew install kubectl; }
os_ensure_kind() { _brew install kind; }

os_local_cluster_hint() {
  say "   Options for a local cluster on this Mac:"
  say "     - Docker Desktop:  Settings → Kubernetes → Enable, wait for the green light, re-run with --context docker-desktop"
  say "     - kind:            re-run and answer yes when offered, or: brew install kind && kind create cluster --name vyuu"
  say "     - Colima:          colima start --kubernetes   (then --context colima)"
  say "     - OrbStack:        enable Kubernetes in OrbStack settings (context 'orbstack')"
}

os_local_ip() { ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true; }

# ---------------------------------------------------------------------------
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"
vyuu_setup_main "$@"
