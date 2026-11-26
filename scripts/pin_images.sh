#!/usr/bin/env bash
# Explicit opt-in network operation; run only when registry access is authorized.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/image-lib.sh"
[[ ${1:-} == --allow-registry ]] || {
    printf 'Usage: scripts/pin_images.sh --allow-registry (contacts public image registries)\n' >&2
    exit 2
}
temporary=$(mktemp)
trap 'rm -f -- "$temporary"' EXIT
while IFS= read -r line; do
    if [[ $line =~ ^([A-Z]+)_REF=(.+)$ ]]; then
        name=${BASH_REMATCH[1]}
        reference=${BASH_REMATCH[2]}
        printf 'Resolving %s\n' "$reference" >&2
        digest=$(docker buildx imagetools inspect "$reference" | awk '$1 == "Digest:" && !seen { print $2; seen=1 }')
        [[ $digest =~ ^sha256:[a-f0-9]{64}$ ]] || exit 2
        printf '%s_REF=%s\n%s_IMAGE=%s@%s\n' "$name" "$reference" "$name" "$reference" "$digest" >> "$temporary"
    elif [[ ! $line =~ ^[A-Z]+_IMAGE= ]]; then
        printf '%s\n' "$line" >> "$temporary"
    fi
done < "$QG_ROOT/scripts/images.lock"
mv -- "$temporary" "$QG_ROOT/scripts/images.lock"
"$QG_ROOT/scripts/sync_image_defaults.sh"
