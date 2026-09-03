#!/usr/bin/env bash
# Vyuu MCP Gateway — shut the whole stack down with one command.
#
#   ./deploy/setup/teardown.sh                  asks which stack (vm | k8s), stops it, keeps data
#   ./deploy/setup/teardown.sh --mode vm        single VM: docker compose down (volumes kept)
#   ./deploy/setup/teardown.sh --mode k8s       Kubernetes: gateway, Redis, Job, RBAC removed (Postgres kept)
#   ./deploy/setup/teardown.sh --mode vm --purge -y
#                                               ...and delete the data too (volumes / namespace / env files)
#
# This is only a front door: it picks the setup script for this OS and runs it
# with --teardown, so every option of setup-<os>.sh (--context, --namespace,
# --yes, --dry-run, ...) works here as well. Re-run setup-<os>.sh to bring the
# stack back; without --purge it reuses the same secrets and database.

set -o errexit -o nounset -o pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "$(uname -s)" in
  Linux)  script="$here/setup-linux.sh" ;;
  Darwin) script="$here/setup-macos.sh" ;;
  *) printf 'Unsupported OS: %s (run setup-linux.sh or setup-macos.sh --teardown directly)\n' "$(uname -s)" >&2; exit 1 ;;
esac
exec "$script" --teardown "$@"
