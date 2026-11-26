# Security reporting and validation

QuantumGuard is a research prototype for synthetic data. Report a vulnerability privately
to the project maintainers through the repository's security reporting channel when enabled;
otherwise contact a maintainer before publishing exploit details. Include the commit, local
reproduction, expected and observed behavior, and impact. Never include credentials, key
material, real user files or live service tokens.

Security tests target this project's in-process app or localhost stack only. Pulling official
container images, packages and vulnerability databases is permitted. Scanner downloads are
not attack targets. No external target URL is accepted by the ZAP wrapper.

## Running the gates

`scripts/scan.sh` runs gitleaks, Semgrep, Bandit, pip-audit, pnpm production audit, Trivy
filesystem and runtime image scans, hadolint, the banned dependency check and ZAP baseline.
Each can be selected independently, for example `scripts/scan.sh semgrep`.
`scripts/scan_secrets.sh`, `scripts/check_banned_deps.sh` and `scripts/readme_test.sh` are
the Makefile integration points. Scanners use immutable Docker images from
`scripts/images.lock`; changing pins is a deliberate reviewable update with
`scripts/pin_images.sh --allow-registry`.

Missing tools, lockfiles, pins, runtime images or a running stack fail the corresponding gate.
Gitleaks and Semgrep findings fail at any severity; Bandit fails on medium/high confidence
medium/high severity; dependency audits fail on vulnerabilities (pnpm: high and critical);
Trivy fails on high/critical; ZAP baseline fails its FAIL rules and records warnings. No scanner
result is a blanket assurance. Medium findings require a documented rationale here with the
tool/rule, location, impact, owner and expiration. There are currently no accepted exceptions.
Never add a credential-path allowlist to gitleaks.

The source snapshot used by Docker scanners and README testing excludes local credentials,
environment files, data and keys without reading their contents. Gitleaks scans complete Git
history and the sanitized working source; a credential filename in history fails before content
is read. Do not commit `info.txt` or real environment files. The runtime build context uses
the repository's `.dockerignore`; only backend source, the built web bundle and runtime helpers
enter the final image. No credential is required to build or run.

## Runtime isolation

Run `scripts/compose.sh up --build -d --wait` or the README's plain Compose command.
Both use committed image digests. The service binds localhost:8080, runs as UID/GID 10001,
has a read-only root filesystem, drops every Linux capability and has no-new-privileges.
Its separate data and key volumes persist; `/tmp` is a bounded non-executable tmpfs.
The final Python runtime removes shell/package-management executables. The Python-only
healthcheck validates the exact `/healthz` response.

`scripts/compose.sh --profile tls up -d --wait` adds localhost:8443 with Caddy's local CA.
Trust the generated root certificate explicitly on the test machine; never disable TLS
verification in clients. Caddy stores local certificates in memory-backed storage, so its
local CA changes when recreated. This profile is for local testing, not public deployment.
The README gate starts a privileged ephemeral Docker-in-Docker daemon for isolation from
host volumes; only this test harness is privileged, and it is removed on exit.

## Detection catalogue

Responses must be scoped to the offending identity, device, session or credential, time-boxed
and liftable. Global freezes (QG-R013 in the plan) require particular denial-of-service review.

| Rule | Trigger | Expected response |
|---|---|---|
| QG-R001 | Revoked device request | Deny and attach to incident |
| QG-R002 | Sequence replay | End offending session |
| QG-R003 | Stale directory epoch | Deny and require fresh session |
| QG-R004 | Decoy touched | End session and quarantine device |
| QG-R005 | Unsigned privilege change | Quarantine identity for sensitive resources and cancel leases |
| QG-R006 | Self-approved privilege followed by access | Quarantine affected identity |
| QG-R007 | Unapproved path to sensitive resource | Alert with evidence path |
| QG-R008 | Per-identity statistical rate anomaly | Require fresh session proof |
| QG-R009 | Repeated denied object enumeration | Throttle offending session for five minutes |
| QG-R010 | Retired service key | Deny |
| QG-R011 | Enrollment during open loss incident | Hold affected identity's enrollment |
| QG-R012 | Repeated MAC/signature failures | Throttle offending session or device |
| QG-R013 | Checkpoint/consistency mismatch | Alert and freeze release pending operator action |
| QG-R014 | Unknown/weaker suite | Deny |

These are requirements, not claims of implementation. `tests/security/README.md` describes
pending core integration. `claims.json` records passing, failing and skipped test IDs; skipped
claims do not count as evidence. CI's strict security invocation fails missing fixtures.
Revocation cannot erase plaintext or keys already held by a device. A stolen running server
and its key volume are outside the database-copy-only protection claim.
