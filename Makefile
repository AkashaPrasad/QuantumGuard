# QuantumGuard. Every target exits non-zero on failure. Python runs through uv (backend/pyproject.toml).
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

ROOT      := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
UV        ?= uv
PY        := cd $(ROOT) && PYTHONPATH=$(ROOT)/backend:$(ROOT)/cli $(UV) run --quiet --project $(ROOT)/backend
PYTEST    := $(PY) pytest -c $(ROOT)/backend/pyproject.toml --rootdir $(ROOT)
PNPM      ?= pnpm
WEB       := $(PNPM) --dir $(ROOT)/web run
QG_PORT   ?= 8080
export QG_PORT
# Only Docker is required: demo, scenarios and test run inside the compose stack. dev-* targets run on the host.
COMPOSE   := bash $(ROOT)/scripts/compose.sh
EXEC      := $(COMPOSE) exec -T quantumguard python

.PHONY: help preflight setup requirements dev dev-api dev-web build up down seed demo demo-kit recovery-kit dev-demo spec-lint \
        spec-export vectors test dev-test test-unit test-crypto test-api test-security test-detect \
        test-reliability test-perf test-e2e test-a11y web-lint web-typecheck lint types fuzz scan scan-secrets \
        bench bench-detect brief demo-video readme-test verify scenarios dev-scenarios

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-20s %s\n", $$1, $$2}'

## ---- setup -----------------------------------------------------------------------------------

setup: ## Install Python (uv) and web (pnpm) dependencies from lockfiles
	cd $(ROOT)/backend && $(UV) sync --frozen --python 3.12
	@if [ -f $(ROOT)/web/package.json ]; then $(PNPM) --dir $(ROOT)/web install --frozen-lockfile; fi

requirements: ## Export backend/requirements.txt from uv.lock
	cd $(ROOT)/backend && $(UV) export --frozen --no-dev --no-hashes --no-emit-project -o requirements.txt >/dev/null

preflight: ## Tools, ignore rules, hooks, PQ library gate, banned dependencies
	bash $(ROOT)/scripts/check_banned_deps.sh
	$(PY) python -c "from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa, x25519, ed25519; print('pq ok')"
	@git -C $(ROOT) check-ignore -q info.txt && echo "info.txt ignored"
	@test "$$(git -C $(ROOT) config core.hooksPath)" = "scripts/hooks" && echo "hooks installed"

## ---- run -------------------------------------------------------------------------------------

dev-api: ## API on 127.0.0.1:$QG_PORT with a throwaway data directory
	@tmp=$$(mktemp -d); echo "data in $$tmp" >&2; \
	QG_DATA_DIR=$$tmp/data QG_KEYS_DIR=$$tmp/keys QG_DEMO=$${QG_DEMO:-1} \
	$(PY) python -m qg.server

dev-web: ## Vite dev server (proxies /api to dev-api)
	$(WEB) dev

dev: ## API and web dev server together
	$(MAKE) -j2 dev-api dev-web

build: ## Build the web bundle
	$(WEB) build

up: ## docker compose up
	docker compose -f $(ROOT)/docker-compose.yml up --build -d

down: ## docker compose down
	docker compose -f $(ROOT)/docker-compose.yml down

recovery-kit: ## Issue the recovery kit once; the private half is printed to this terminal (keep it offline)
	$(EXEC) -m qg.admin recovery-kit init

seed: ## Enrol the seeded people in the running container through the public API
	$(COMPOSE) exec -T -e QG_PASSPHRASE=$$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n') quantumguard \
	  python -m qg.client demo seed --server http://127.0.0.1:8080 --dir /tmp/qg-demo

demo-kit:
	@if $(EXEC) -m qg.admin recovery-kit init --out /tmp/qg-demo/recovery-kit.json; then \
	  echo "demo recovery kit written inside the container at /tmp/qg-demo/recovery-kit.json (tmpfs, gone on restart)"; \
	  echo "copy it out now if you want to keep it: docker compose cp quantumguard:/tmp/qg-demo/recovery-kit.json ."; \
	else echo "recovery kit already issued earlier; continuing"; fi

demo: demo-kit seed ## Issue the demo recovery kit, seed, run the hero flow against the server, leave the incident
	$(COMPOSE) exec -T -e QG_URL=http://127.0.0.1:8080 quantumguard python -m qg.scenarios revoke

dev-demo: ## Host variant: hero scenario against a throwaway local server
	$(PY) python -m qg.scenarios revoke

## ---- spec ------------------------------------------------------------------------------------

spec-export: ## Write spec/openapi.yaml and spec/schemas/ from the app
	$(PY) python -m qg.spec_export --write

spec-lint: ## Fail if committed OpenAPI/schemas differ from a fresh export or miss an API.md route
	$(PY) python -m qg.spec_export --check

vectors: ## Regenerate QuantumGuard's own vectors (official ones: spec/vectors/import_official.py)
	$(PY) python spec/vectors/generate.py

## ---- tests -----------------------------------------------------------------------------------

test-unit: ## Python unit tests (and web unit tests when present)
	$(PYTEST) tests/unit
	@if [ -d $(ROOT)/web/node_modules ]; then $(WEB) test; fi

test-crypto: ## Known-answer and property tests in both languages
	$(PYTEST) tests/crypto
	@if [ -d $(ROOT)/web/node_modules ]; then $(WEB) test:crypto; fi

test-api: ## Endpoint tests against the contract
	$(PYTEST) -n auto -m "not fuzz" tests/api

test-security: ## Negative security tests per claim and regression tests for fixed findings
	$(PYTEST) tests/security tests/attacks

test-detect: ## One test per detection rule
	$(PYTEST) tests/detect

test-reliability: ## Crash, duplicate, out-of-order, malformed, fail-closed
	$(PYTEST) tests/reliability

test-perf: ## Performance smoke tests
	$(PYTEST) tests/perf

test-e2e: ## Playwright interaction matrix
	$(WEB) test:e2e

test-a11y: ## axe checks on every route
	$(WEB) test:a11y

web-lint:
	$(WEB) lint

web-typecheck:
	$(WEB) typecheck

lint: ## ruff and bandit on Python code, and the web linter when the web app is installed
	$(PY) ruff check --config $(ROOT)/backend/pyproject.toml backend/qg cli/qg scenarios spec/vectors $(wildcard bench/*.py) $(wildcard tests/unit tests/crypto tests/api tests/detect tests/reliability tests/perf)
	$(PY) bandit -q -r backend/qg cli/qg -c $(ROOT)/backend/pyproject.toml
	@if [ -d $(ROOT)/web/node_modules ]; then $(WEB) lint; fi

types: ## mypy on the Python packages, and the web type check when installed
	$(PY) mypy --config-file $(ROOT)/backend/pyproject.toml backend/qg cli/qg
	@if [ -d $(ROOT)/web/node_modules ]; then $(WEB) typecheck; fi

test: ## Full suite inside the test image (Docker only)
	$(COMPOSE) --profile test run --rm tests

dev-test: test-unit test-crypto test-api test-detect test-reliability test-security ## Full suite on the host

fuzz: ## Schemathesis against the OpenAPI document (no 5xx, no schema violations)
	$(PYTEST) -m fuzz tests/api/test_fuzz.py

## ---- scenarios (one JSON line on stdout, exit 0 on pass) -----------------------------------
# make scenario-NAME runs inside the running container; make dev-scenario-NAME runs on the host.

SCENARIOS := normal revoke interrupt verify rotate privilege messaging

scenario-%: ## Scenario inside the running container (normal revoke interrupt verify rotate privilege messaging)
	@case " $(SCENARIOS) " in *" $* "*) ;; *) echo "unknown scenario $*" >&2; exit 2;; esac
	$(EXEC) -m qg.scenarios $*

dev-scenario-%: ## Scenario on the host against a throwaway server
	@case " $(SCENARIOS) " in *" $* "*) ;; *) echo "unknown scenario $*" >&2; exit 2;; esac
	$(PY) python -m qg.scenarios $*

scenarios: $(addprefix scenario-,normal revoke interrupt verify rotate privilege)

dev-scenarios: $(addprefix dev-scenario-,normal revoke interrupt verify rotate privilege)

## ---- evidence, scanning, packaging -----------------------------------------------------------

bench: ## Performance JSON to bench/latest.json
	$(PY) python $(ROOT)/bench/bench.py --out $(ROOT)/bench/latest.json

bench-detect: ## Detection quality (F1, false alerts per 1,000 benign events, time to alert) to bench/detection.json
	$(PY) python $(ROOT)/bench/detection.py --out $(ROOT)/bench/detection.json --rounds 10 --steps 400

scan: ## All scanners (scripts/scan.sh)
	bash $(ROOT)/scripts/scan.sh

scan-secrets: ## gitleaks over the tree and history
	bash $(ROOT)/scripts/scan_secrets.sh

brief: ## Build brief/brief.pdf (A4, exactly two pages, demo video link required) with pinned images
	bash $(ROOT)/scripts/brief.sh

demo-video: ## Timed demo in one visible browser window for screen recording (brief/video-script.md)
	bash $(ROOT)/scripts/demo-video.sh

readme-test: ## Run the README commands in a clean container with no info.txt
	bash $(ROOT)/scripts/readme_test.sh

verify: preflight spec-lint lint types dev-test dev-scenarios scan-secrets ## Everything on the host, stopping at the first failure
