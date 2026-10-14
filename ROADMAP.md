# Roadmap

## MVP release scope

The current release target is a tested local-first AppSec MVP: CLI scanning, secret detection, Python dependency inventory/advisories, machine-readable reports, opt-in AI reasoning and review-only patch proposals, a bounded local API/dashboard, opt-in SQLite history, project-scoped team roles, and GitHub Actions PR checks. It is not a hosted multi-tenant SaaS platform. Cross-repository GitHub App installation/webhooks remain post-MVP.

## Phase 0 — Foundation
- [x] Repository structure
- [x] Domain models
- [x] Scanner interface
- [x] Configuration
- [x] Unit-test foundation
- [x] Docker/CI foundation

## Phase 1 — Deterministic SAST MVP
- [x] Python security scanner foundation
- [x] High-confidence dynamic execution detection
- [x] shell=True command execution detection
- [x] Evidence extraction
- [x] JavaScript/TypeScript security rules
- [x] Finding deduplication
- [x] SARIF 2.1.0 output and CLI flag
- [x] JSON output
- [x] CLI scan command

## Phase 2 — Secrets & Dependencies
- [x] High-confidence secret rules
- [x] Entropy-assisted secret detection
- [x] Python lockfile parsing (`uv.lock`, `poetry.lock`, `Pipfile.lock`)
- [x] OSV advisory integration for exact-pinned Python dependencies
- [x] CycloneDX 1.5 SBOM generation for exact-pinned Python dependencies
- [x] Deterministic dependency risk scoring

## Phase 3 — AI Security Reasoning
- [x] Provider-neutral reasoning request/response contract
- [x] OpenAI-compatible chat-completions adapter (opt-in)
- [x] Finding explanation integrated into CLI (`--explain`)
- [x] Exploitability/context analysis integrated into CLI
- [x] Remediation guidance integrated into CLI
- [x] Guarded AI patch proposal generation (review-only unified diff; no automatic application)
- [x] Guardrails for finding identity, supplied references, and unsupported CVE/CWE identifiers

## Phase 4 — GitHub Developer Workflow
- [ ] Cross-repository GitHub App installation/webhooks (post-MVP; same-repository PR checks are implemented with GitHub Actions)
- [x] Pull-request source scanning workflow (GitHub Actions scans `appsec/` on PRs)
- [x] Inline workflow annotations generated from SARIF results
- [x] Severity-based security gate (`--fail-on`; high/critical findings fail the PR scan job)
- [x] Local JSON baseline and deterministic finding suppression (`--baseline`, `--write-baseline`)
- [x] GitHub API check-run reporting for same-repository pull requests (fork PRs use normal workflow status because their token is read-only)

## Phase 5 — Product Layer
- [x] Local JSON API service (`/health`, bounded `POST /scan`; loopback-only default)
- [x] Local web dashboard for source submission, findings, and dependency risk
- [x] Local project registry and project-scoped scan history
- [x] SQLite-backed historical scan results and findings
- [x] Local team workflows (user token creation/revocation, project membership and admin/editor/viewer roles)
- [x] Optional shared bearer-token authentication for local API data routes
- [x] Per-user bearer tokens, project roles, membership management, and user revocation (local SQLite)
- [x] Local usage counters (scan count, files, findings, source bytes; no billing)

## Quality gates

Before calling the CLI MVP production-ready:

- [x] Automated tests for scanner, report, and AI-provider behavior (103 tests passed in merged-main CI run #209)
- [x] Deterministic scanner fixtures
- [x] Verify no secrets exist in repository history (Gitleaks full-history scan passed in merged-main CI run #209)
- [x] Dependency pinning/lock strategy (`uv.lock`, hashes, `uv sync --locked` in CI)
- [x] Reproducible Docker dependency install and pinned Python base-image digest
- [x] CI security checks beyond lint/tests/type checking (`pip-audit`, Gitleaks PR and full-history scans)
- [x] Documented threat model (`THREAT_MODEL.md`)
- [x] Documented limitations and false-positive handling (README and threat model)
- [x] Release smoke checks on merged main (CI run #209 on `5e55cfcba30f7b49c762aaa499b798dd44c0d6c8`: Ruff, 103 pytest tests, mypy, pip-audit, Gitleaks PR and full-history scans, Docker build, and non-root CLI smoke test all passed)

## Release discipline

- A CI run is considered green only when Ruff, pytest, and mypy all pass on the commit being released.
- A pull request being merged is not evidence that its CI passed; verify the post-merge run.
- AI explanations are opt-in, can be incorrect, and must not replace deterministic findings or developer review.
- The local CLI quality gates have passed on main in subsequent CI runs; always verify the latest merged-main run before release. The PR scan workflow, severity gate, local baseline/suppression, guarded review-only AI patch proposals, local API/dashboard, project registry, opt-in scan history and usage counters, shared admin and per-user bearer tokens, project roles, membership management, user revocation, and dedicated GitHub Checks API reporting are implemented. Cross-repository GitHub App installation/webhooks, hosted identity, and multi-tenant SaaS remain post-MVP. Local history and usage counters are opt-in via `APPSEC_DB_PATH`; usage counts are not billing.
