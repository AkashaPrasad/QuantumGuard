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

.PHONY: help preflight setup dev dev-api dev-web build up down seed demo spec-lint spec-export \
        test test-unit test-crypto test-api test-security test-detect test-reliability test-perf test-e2e \
        test-a11y web-lint web-typecheck fuzz scan scan-secrets bench readme-test verify vectors lint \
        scenario-normal scenario-revoke scenario-interrupt scenario-verify scenario-rotate \
        scenario-privilege scenario-messaging scenarios \
        requirements

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

seed: ## Seed demo data through the public API (needs a running server)
	$(PY) python -m qg.client demo seed

demo: ## Seed and run the hero scenario against a running server
	$(PY) python -m qg.client demo seed
	$(MAKE) scenario-revoke

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
	@if [ -f $(ROOT)/web/package.json ]; then $(WEB) test; fi

test-crypto: ## Known-answer and property tests in both languages
	$(PYTEST) tests/crypto
	@if [ -f $(ROOT)/web/package.json ]; then $(WEB) test:crypto; fi

test-api: ## Endpoint tests against the contract
	$(PYTEST) -n auto tests/api

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

lint: ## ruff, mypy and bandit on Python code
	$(PY) ruff check backend/qg cli/qg
	$(PY) bandit -q -r backend/qg cli/qg -x tests

test: test-unit test-crypto test-api test-detect test-reliability test-security ## Full automated suite

fuzz: ## Schemathesis against the OpenAPI document (no 5xx, no schema violations)
	$(PY) python -m qg.testing fuzz

## ---- scenarios (one JSON line on stdout, exit 0 on pass) -----------------------------------

scenario-normal: ## Invite, enrol, sign in, policy allow, receipt
	$(PY) python $(ROOT)/scenarios/run.py normal

scenario-revoke: ## Lost device: enforce time, exposure, denied attempt with QG-R001
	$(PY) python $(ROOT)/scenarios/run.py revoke

scenario-interrupt: ## Crash during re-key, duplicate events, malformed input, policy down
	$(PY) python $(ROOT)/scenarios/run.py interrupt

scenario-verify: ## Verify a receipt offline; tamper and find the first bad index
	$(PY) python $(ROOT)/scenarios/run.py verify

scenario-rotate: ## Service key rotation; retired key denied (QG-R010)
	$(PY) python $(ROOT)/scenarios/run.py rotate

scenario-privilege: ## Unexpected privilege change detected and quarantined (QG-R005)
	$(PY) python $(ROOT)/scenarios/run.py privilege

scenario-messaging: ## Messaging device revocation
	$(PY) python $(ROOT)/scenarios/run.py messaging

scenarios: scenario-normal scenario-revoke scenario-interrupt scenario-verify scenario-rotate scenario-privilege

## ---- evidence, scanning, packaging -----------------------------------------------------------

bench: ## Performance JSON to bench/latest.json
	$(PY) python $(ROOT)/bench/bench.py --out $(ROOT)/bench/latest.json

scan: ## All scanners (scripts/scan.sh)
	bash $(ROOT)/scripts/scan.sh

scan-secrets: ## gitleaks over the tree and history
	bash $(ROOT)/scripts/scan_secrets.sh

readme-test: ## Run the README commands in a clean container with no info.txt
	bash $(ROOT)/scripts/readme_test.sh

verify: preflight spec-lint test-unit test-crypto test-api test-detect test-reliability scenarios scan-secrets ## Everything, stopping at the first failure
