#!/usr/bin/env bash
# Hosted deployment: the API on AWS, the web console on Cloudflare, one public hostname.
#
#   QG_DOMAIN=console.example.org AWS_REGION=eu-west-1 [AWS_PROFILE=name] deploy/deploy.sh [image|aws|web|all]
#
# Needs: docker, terraform, the AWS CLI signed in, and `wrangler login` done for the account that owns the domain.
# Creates billable resources (one small instance, an API gateway, a registry). `deploy.sh destroy` removes them.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tf="$root/deploy/aws"
cf="$root/deploy/cloudflare"
stage="${1:-all}"

: "${AWS_REGION:?set AWS_REGION}"
tag="$(git -C "$root" rev-parse --short=12 HEAD)"
tfvars=(-var "region=$AWS_REGION" -var "image_tag=$tag")
[ -n "${AWS_PROFILE:-}" ] && tfvars+=(-var "profile=$AWS_PROFILE")

image() {
  terraform -chdir="$tf" init -input=false >/dev/null
  terraform -chdir="$tf" apply -input=false -auto-approve "${tfvars[@]}" -target=aws_ecr_repository.app
  local repo registry
  repo="$(terraform -chdir="$tf" output -raw repository_url)"
  registry="${repo%%/*}"
  docker build --target runtime --platform linux/arm64 -t "$repo:$tag" "$root"
  aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$registry" >/dev/null
  docker push "$repo:$tag"
}

aws_stack() {
  terraform -chdir="$tf" init -input=false >/dev/null
  terraform -chdir="$tf" apply -input=false -auto-approve "${tfvars[@]}"
}

web() {
  : "${QG_DOMAIN:?set QG_DOMAIN to the public hostname}"
  local origin
  origin="$(terraform -chdir="$tf" output -raw api_origin)"
  (cd "$root/web" && pnpm install --frozen-lockfile && pnpm build)
  # The same headers the API sets on its own responses (backend/qg/app.py), so the policy has one source.
  python3 - "$root" > "$root/web/dist/_headers" <<'PY'
import re, sys
src = open(sys.argv[1] + "/backend/qg/app.py", encoding="utf-8").read()
csp = "".join(re.findall(r'"([^"]*)"', re.search(r"CSP = \((.*?)\n\)", src, re.S).group(1)))
print("/*")
for name, value in [
    ("Content-Security-Policy", csp),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    # no-transform: the edge must serve these bytes as built. Without it a zone-level feature (for example
    # automatic analytics) can add a third-party script to the page, which the policy above then blocks.
    ("Cache-Control", "public, max-age=0, must-revalidate, no-transform"),
]:
    print(f"  {name}: {value}")
print("/assets/*")
print("  ! Cache-Control")
print("  Cache-Control: public, max-age=31536000, immutable, no-transform")
PY
  terraform -chdir="$tf" output -raw edge_key | (cd "$cf" && wrangler secret put EDGE_KEY >/dev/null)
  (cd "$cf" && wrangler deploy --domain "$QG_DOMAIN" --var "ORIGIN_URL:$origin")
}

destroy() {
  (cd "$cf" && wrangler delete --force) || true
  terraform -chdir="$tf" destroy -input=false -auto-approve "${tfvars[@]}"
}

case "$stage" in
  image) image ;;
  aws) aws_stack ;;
  web) web ;;
  all) image; aws_stack; web ;;
  destroy) destroy ;;
  *) echo "usage: deploy.sh [image|aws|web|all|destroy]" >&2; exit 2 ;;
esac
