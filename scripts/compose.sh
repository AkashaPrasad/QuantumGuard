#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/image-lib.sh"
compose_pins
cd "$QG_ROOT"
# Disable Compose's implicit reading of .env.
exec docker compose --env-file /dev/null "$@"
