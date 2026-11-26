#!/usr/bin/env bash
# Shared immutable-image checks. Never source an environment file.
set -euo pipefail
QG_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

image_value() {
    local key=$1 value
    value=$(sed -n "s/^${key}=//p" "$QG_ROOT/scripts/images.lock")
    if [[ ! $value =~ ^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$ ]]; then
        printf 'Missing immutable pin for %s; resolve scripts/images.lock first.\n' "$key" >&2
        return 2
    fi
    printf '%s\n' "$value"
}

compose_pins() {
    QG_NODE_IMAGE=$(image_value NODE_IMAGE)
    QG_PYTHON_IMAGE=$(image_value PYTHON_IMAGE)
    QG_UV_IMAGE=$(image_value UV_IMAGE)
    QG_CADDY_IMAGE=$(image_value CADDY_IMAGE)
    export QG_NODE_IMAGE QG_PYTHON_IMAGE QG_UV_IMAGE QG_CADDY_IMAGE
}
