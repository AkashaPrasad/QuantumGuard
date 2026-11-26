#!/usr/bin/env bash
# An isolated Docker daemon keeps README volumes and cleanup off the host daemon.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/image-lib.sh"
snapshot=$(mktemp -d)
container="quantumguard-readme-$$"
cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf -- "$snapshot"
}
trap cleanup EXIT
"$QG_ROOT/scripts/source-snapshot.sh" "$snapshot"
[[ -f $snapshot/Makefile ]] || { printf 'README gate requires the real Makefile.\n' >&2; exit 2; }
if ! sed -n '/<!-- qg:quickstart -->/,/<!-- \/qg:quickstart -->/p' "$snapshot/README.md" | grep -q 'docker compose'; then
    printf 'README must mark its executable quick-start block with <!-- qg:quickstart --> and <!-- /qg:quickstart -->.\n' >&2
    exit 2
fi
compose_pins
# Only this ephemeral nested daemon receives privileges; the app stays constrained.
docker run --rm --privileged --name "$container" \
    --mount "type=bind,src=$snapshot,dst=/source,readonly" \
    -e DOCKER_TLS_CERTDIR= -e QG_NODE_IMAGE -e QG_PYTHON_IMAGE -e QG_UV_IMAGE -e QG_CADDY_IMAGE \
    "$(image_value DOCKER_IMAGE)" sh -ec '
        apk add --no-cache bash make git
        cp -R /source /work
        cd /work
        test ! -e info.txt
        test ! -e .env
        # The image entrypoint points DOCKER_HOST at a host named docker; use the local socket.
        export DOCKER_HOST=unix:///var/run/docker.sock
        dockerd-entrypoint.sh >/var/log/dockerd.log 2>&1 &
        count=0
        until docker info >/dev/null 2>&1; do
            count=$((count + 1))
            if [ "$count" -ge 60 ]; then cat /var/log/dockerd.log; exit 1; fi
            sleep 1
        done
        exec bash scripts/readme-container.sh
    '
