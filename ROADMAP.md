# Roadmap

## MVP release scope

The current release target is a tested local CLI MVP for deterministic source scanning, secret detection, Python dependency inventory/advisories, machine-readable reports, and opt-in AI explanations. It is not a GitHub App or hosted SaaS platform. Do not describe pending phases as implemented.

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
- [x] Optional GitHub App integration for same-repository PR check runs (requires `APP_ID` and `APP_PRIVATE_KEY` secrets; fork PRs use the standard workflow)
- [x] Pull-request source scanning workflow (GitHub Actions scans `appsec/` on PRs)
- [x] Inline workflow annotations generated from SARIF results
- [x] Severity-based security gate (`--fail-on`; high/critical findings fail the PR scan job)
- [x] Local JSON baseline and deterministic finding suppression (`--baseline`, `--write-baseline`)
- [x] Dedicated GitHub Checks API check-run with severity-based conclusion and bounded inline annotations

## Phase 5 — Product Layer
- [x] Local JSON API service (`/health`, bounded `POST /scan`; loopback-only default)
- [x] Local web dashboard for source submission, findings, and dependency risk
- [x] Local project registry and project-scoped scan history
- [x] SQLite-backed historical scan results and findings
- [ ] Team workflows
- [x] Optional shared bearer-token authentication for local API data routes
- [ ] Per-user authorization, roles, and team access controls
- [x] Local usage counters (scan count, files, findings, source bytes; no billing)

## Quality gates

Before calling the CLI MVP production-ready:

- [x] Automated tests for scanner, report, and AI-provider behavior (65 tests passed in CI run #134)
- [x] Deterministic scanner fixtures
- [x] Verify no secrets exist in repository history (Gitleaks full-history scan passed in main CI run #149)
- [x] Dependency pinning/lock strategy (`uv.lock`, hashes, `uv sync --locked` in CI)
- [x] Reproducible Docker dependency install and pinned Python base-image digest
- [x] CI security checks beyond lint/tests/type checking (`pip-audit`, Gitleaks PR and full-history scans)
- [x] Documented threat model (`THREAT_MODEL.md`)
- [x] Documented limitations and false-positive handling (README and threat model)
- [x] Release smoke checks on merged main (CI run #149 on `8b928bb5f4084e1e638d51cfee9e3bd481e5259e`: Ruff, 65 pytest tests, mypy, pip-audit, Gitleaks scans, Docker build, and non-root CLI smoke test all passed)

## Release discipline

- A CI run is considered green only when Ruff, pytest, and mypy all pass on the commit being released.
- A pull request being merged is not evidence that its CI passed; verify the post-merge run.
- AI explanations are opt-in, can be incorrect, and must not replace deterministic findings or developer review.
- The listed quality gates for the local CLI MVP passed on main SHA `8b928bb5f4084e1e638d51cfee9e3bd481e5259e` (CI run #149). The initial PR scan workflow, severity gate, local baseline/suppression, and guarded review-only AI patch proposals are implemented; GitHub App integration, GitHub API check-run creation, Per-user authorization/roles and team workflows remain separate roadmap work. GitHub App checks require administrator-provided secrets and are limited to same-repository PRs; usage counters are local metrics, not billing.
