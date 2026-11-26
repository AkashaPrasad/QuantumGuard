#!/usr/bin/env bash
# Keep ordinary docker build/compose commands pinned, with no environment file.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/image-lib.sh"
node=$(image_value NODE_IMAGE)
python=$(image_value PYTHON_IMAGE)
uv=$(image_value UV_IMAGE)
caddy=$(image_value CADDY_IMAGE)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
sed -e "s|^FROM .* AS web-build|FROM $node AS web-build|" \
    -e "s|^FROM .* AS uv$|FROM $uv AS uv|" \
    -e "s|^FROM .* AS python-build|FROM $python AS python-build|" \
    -e "s|^FROM .* AS python-tools|FROM $python AS python-tools|" \
    -e "s|^FROM .* AS test$|FROM $python AS test|" \
    -e "s|^FROM .* AS runtime|FROM $python AS runtime|" \
    "$QG_ROOT/Dockerfile" > "$temporary/Dockerfile"
sed -e "s|    image: \${QG_CADDY_IMAGE:.*|    image: \${QG_CADDY_IMAGE:-$caddy}|" \
    "$QG_ROOT/docker-compose.yml" > "$temporary/docker-compose.yml"
mv -- "$temporary/Dockerfile" "$QG_ROOT/Dockerfile"
mv -- "$temporary/docker-compose.yml" "$QG_ROOT/docker-compose.yml"
