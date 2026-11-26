#!/usr/bin/env bash
# Scanner failures and missing inputs are failures. Nothing silently skips a gate.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/image-lib.sh"
cd "$QG_ROOT"
scanner=${1:-all}
case "$scanner" in
    all|gitleaks|semgrep|bandit|pip-audit|pnpm-audit|trivy-fs|trivy-image|hadolint|banned-deps|zap) ;;
    *) printf 'Unknown scanner: %s\n' "$scanner" >&2; exit 2 ;;
esac
if [[ $scanner == all ]]; then
    result=0
    for tool in gitleaks semgrep bandit pip-audit pnpm-audit trivy-fs trivy-image hadolint banned-deps zap; do
        printf '\nRunning %s\n' "$tool"
        "$0" "$tool" || result=1
    done
    exit "$result"
fi

snapshot=$(mktemp -d)
trap 'rm -rf -- "$snapshot"' EXIT
"$QG_ROOT/scripts/source-snapshot.sh" "$snapshot"
mount_source=(--mount "type=bind,src=$snapshot,dst=/src,readonly" --workdir /src)
restricted=(--rm --cap-drop ALL --security-opt no-new-privileges --pids-limit 256)

python_tools() {
    docker build --target python-tools --quiet "$snapshot"
}

case "$scanner" in
    gitleaks)
        # Refuse forbidden credential paths by filename, without reading their bytes.
        credential_paths=$(git log --all --format= --name-only -- 'info.txt' '**/info.txt' '.env' '**/.env' '.env.*' '**/.env.*' ':!.env.example' ':!**/.env.example' | sed '/^$/d')
        if [[ -n $credential_paths ]]; then
            printf 'Credential filename found in history; remove it and rotate credentials.\n' >&2
            exit 1
        fi
        git -c core.pager=cat log --all -p --no-ext-diff --no-textconv -- . ':!.env.example' ':!**/.env.example' |
            docker run "${restricted[@]}" --network none -i "${mount_source[@]}" \
                "$(image_value GITLEAKS_IMAGE)" stdin --config /src/.gitleaks.toml --redact --exit-code 1
        # Also scan uncommitted source, so local make scan is useful before committing.
        docker run "${restricted[@]}" --network none "${mount_source[@]}" \
            "$(image_value GITLEAKS_IMAGE)" dir /src --config /src/.gitleaks.toml --redact --exit-code 1
        ;;
    semgrep)
        docker run "${restricted[@]}" --network none -e SEMGREP_SEND_METRICS=off \
            -e SEMGREP_ENABLE_VERSION_CHECK=0 "${mount_source[@]}" "$(image_value SEMGREP_IMAGE)" \
            semgrep scan --config /src/.semgrep.yml --metrics off --disable-version-check --error --strict /src
        ;;
    bandit)
        [[ -d $snapshot/backend ]] || { printf 'backend/ is required.\n' >&2; exit 2; }
        docker run "${restricted[@]}" --network none "${mount_source[@]}" "$(python_tools)" \
            bandit --recursive /src/backend --severity-level medium --confidence-level medium
        ;;
    pip-audit)
        [[ -f $snapshot/backend/uv.lock ]] || { printf 'backend/uv.lock is required.\n' >&2; exit 2; }
        # Export from the frozen lock; do not let the auditor resolve project code.
        docker run "${restricted[@]}" "${mount_source[@]}" "$(python_tools)" sh -ec \
            'uv export --project /src/backend --frozen --no-dev --no-emit-project --format requirements-txt --output-file /tmp/requirements.txt; pip-audit --require-hashes --disable-pip --no-deps -r /tmp/requirements.txt'
        ;;
    pnpm-audit)
        [[ -f $snapshot/web/pnpm-lock.yaml ]] || { printf 'web/pnpm-lock.yaml is required.\n' >&2; exit 2; }
        docker run "${restricted[@]}" "${mount_source[@]}" "$(image_value NODE_IMAGE)" sh -ec \
            'cp -R /src/web /tmp/web; corepack enable --install-directory /tmp; cd /tmp/web; corepack install; /tmp/pnpm audit --prod --audit-level high'
        ;;
    trivy-fs)
        docker run "${restricted[@]}" --volume quantumguard-trivy-cache:/root/.cache/trivy \
            "${mount_source[@]}" "$(image_value TRIVY_IMAGE)" \
            fs --no-progress --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --exit-code 1 /src
        ;;
    trivy-image)
        image_id=$(docker image inspect quantumguard:local --format '{{.Id}}')
        docker save "$image_id" -o "$snapshot/runtime.tar"
        docker run "${restricted[@]}" --volume quantumguard-trivy-cache:/root/.cache/trivy \
            "${mount_source[@]}" "$(image_value TRIVY_IMAGE)" \
            image --no-progress --input /src/runtime.tar --scanners vuln,secret --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1
        ;;
    hadolint)
        docker run "${restricted[@]}" --network none -i "$(image_value HADOLINT_IMAGE)" \
            hadolint --failure-threshold warning - < "$QG_ROOT/Dockerfile"
        ;;
    banned-deps)
        docker run "${restricted[@]}" --network none "${mount_source[@]}" "$(image_value PYTHON_IMAGE)" \
            python /src/scripts/check_banned_deps.py /src
        ;;
    zap)
        # Join only this project's network, never accept an arbitrary target URL.
        container=$("$QG_ROOT/scripts/compose.sh" ps -q quantumguard)
        [[ -n $container ]] || { printf 'Start the local stack before ZAP.\n' >&2; exit 2; }
        network=$(docker inspect "$container" --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}')
        mkdir "$snapshot/zap"
        chmod 777 "$snapshot/zap"
        docker run "${restricted[@]}" --network "$network" --mount "type=bind,src=$snapshot/zap,dst=/zap/wrk" \
            "$(image_value ZAP_IMAGE)" zap-baseline.py -t http://quantumguard:8080 \
            -m 1 -T 5 -I -J baseline.json
        # ZAP's default policy labels rules WARN even at high risk. Inspect risk codes
        # explicitly rather than accepting a zero exit from the baseline script.
        docker run "${restricted[@]}" --network none "${mount_source[@]}" "$(image_value PYTHON_IMAGE)" \
            python /src/scripts/check_zap_report.py /src/zap/baseline.json
        ;;
esac
