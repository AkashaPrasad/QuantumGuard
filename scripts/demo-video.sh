#!/usr/bin/env bash
# Drives the timed demo in visible browser windows for screen recording (brief/video-script.md).
#
#   bash scripts/demo-video.sh          fresh demo stack on http://localhost:18080, then the timed run
#   bash scripts/demo-video.sh --down   remove the demo stack, its data and keys
#
# Every take starts from new data and keys. The stack on port 8080 is never touched.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/image-lib.sh"
cd "$QG_ROOT"
dc() { bash scripts/compose.sh -p qgdemo -f docker-compose.yml -f scripts/demo-video.compose.yml "$@"; }

if [[ ${1:-} == --down ]]; then
    dc down -v --remove-orphans
    exit 0
fi

printf 'demo: starting a fresh stack on http://localhost:18080 (project qgdemo)\n'
dc down -v --remove-orphans >/dev/null 2>&1 || true
dc up --build -d --wait
[[ -d web/node_modules ]] || pnpm --dir web install --frozen-lockfile
pnpm --dir web exec playwright install chromium >/dev/null

QG_DEMO_URL=http://localhost:18080 pnpm --dir web exec playwright test -c demo/playwright.demo.config.ts
printf 'demo: done. The stack stays up for a look around; remove it with: bash scripts/demo-video.sh --down\n'
