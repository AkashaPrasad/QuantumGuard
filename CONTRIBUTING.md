# Contributing to QuantumGuard

Thank you for your interest in improving QuantumGuard. This guide covers the local setup, the checks
every change must pass, and the conventions the repository follows.

## Development setup

Requirements: Python 3.12 with [`uv`](https://docs.astral.sh/uv/), Node 22 with `pnpm` (via
`corepack`), Docker with Compose v2, Git and Make.

```bash
make setup                               # install Python and web dependencies from the lockfiles
git config core.hooksPath scripts/hooks  # enable the repository's git hooks
make preflight                           # check tools, ignore rules, hooks and the PQ library
make dev                                 # API on 127.0.0.1:8080 and the Vite dev server
```

## Checks

Run the full host gate before opening a pull request:

```bash
make verify
```

It runs the spec lint, `ruff`, `bandit`, `mypy`, every Python suite, the scenarios and the secret scan,
stopping at the first failure. Web changes should also pass `make web-lint`, `make web-typecheck`,
`make test-e2e` and `make test-a11y`. CI runs the same targets plus the scanners in `scripts/scan.sh`.

Guidelines:

- **Contract first.** API changes update [spec/API.md](spec/API.md); then run `make spec-export` so
  `spec/openapi.*` and `spec/schemas/` match. `make spec-lint` fails on drift.
- **Byte-level changes** to encodings, transcripts or envelopes update [spec/SUITE.md](spec/SUITE.md)
  and the vectors (`make vectors`), and must pass in both the Python and browser implementations.
- **Security claims** need a negative test in `tests/security` and an entry in
  [THREAT_MODEL.md](THREAT_MODEL.md).
- **Dependencies** are pinned in the lockfiles and listed with a reason in
  [DEPENDENCIES.md](DEPENDENCIES.md) or [web/DEPENDENCIES.md](web/DEPENDENCIES.md).

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(scope): …`, `fix: …`,
  `docs(spec): …`, `test: …`, `build: …`, `ci: …`, `chore: …`.
- Keep each commit focused and passing.
- Never commit secrets, `.env` files, keys or runtime data. The pre-commit hook and gitleaks block them.
- Tool attribution trailers in commit messages are rejected by the `commit-msg` hook and by CI.

## Reporting security issues

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).
