#!/usr/bin/env bash
# Copy tracked and unignored source without reading credential files or local stores.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/image-lib.sh"
destination=${1:?Usage: source-snapshot.sh DESTINATION}
mkdir -p -- "$destination"
file_list=$(mktemp)
trap 'rm -f -- "$file_list"' EXIT
cd "$QG_ROOT"
while IFS= read -r -d '' path; do
    case "/$path" in
        */info.txt|*/.env|*/.env.*|*/.git/*|*/.herd/*|*/node_modules/*|*/.venv/*|*/__pycache__/*|/data/*|/keys/*|/reports/*|*/.pytest_cache/*) continue ;;
    esac
    [[ -f $path ]] || continue
    if [[ -L $path ]]; then
        printf 'Refusing symlink in scanner source: %s\n' "$path" >&2
        exit 2
    fi
    printf '%s\0' "$path" >> "$file_list"
done < <(git ls-files --cached --others --exclude-standard -z)
tar -c -f - --null -T "$file_list" | tar -x -f - -C "$destination"
# Scanner containers run as their own non-root users and mount the snapshot read-only; mktemp creates
# it as 0700, so grant read and directory traversal to everyone (it holds no credential files).
chmod -R a+rX "$destination"
