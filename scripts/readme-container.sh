#!/usr/bin/env bash
set -euo pipefail
cd /work
trap 'docker compose --env-file /dev/null down -v --remove-orphans' EXIT
awk '
    /<!-- qg:quickstart -->/ { block=1; next }
    /<!-- \/qg:quickstart -->/ { block=0 }
    block && /^```(bash|sh|shell)?$/ { fence=!fence; next }
    block && fence { print }
' README.md > /tmp/quickstart.sh
[[ -s /tmp/quickstart.sh ]] || { printf 'README quick-start contains no shell commands.\n' >&2; exit 2; }
# Fresh source snapshot, fresh daemon, no host keys and no credential files.
bash -euo pipefail /tmp/quickstart.sh
docker compose --env-file /dev/null exec -T quantumguard /app/backend/.venv/bin/python -c \
    'import json, urllib.request; assert json.load(urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=3)) == {"status":"ok"}'
