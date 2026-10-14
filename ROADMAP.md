# Roadmap

## MVP release scope

The current release target is the tested local-first AppSec MVP: CLI scanning, secret detection, Python dependency inventory/advisories, machine-readable reports, opt-in AI reasoning and review-only patch proposals, a bounded local API/dashboard, opt-in SQLite history, project-scoped team roles, GitHub Actions PR checks, reusable cross-repository scanning, and optional GitHub App-owned check runs. **All checklist items in this release scope are implemented.** The project is not a hosted multi-tenant SaaS platform. GitHub App installation and repository secret configuration are administrator setup steps documented in README.md; a centralized webhook service is not part of this release scope.

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
- [x] Reusable cross-repository GitHub Actions PR scanning workflow (trusted scanner checkout, SARIF, annotations, severity gate, dedicated check run)
- [x] Pull-request source scanning workflow (GitHub Actions scans `appsec/` on PRs)
- [x] Inline workflow annotations generated from SARIF results
- [x] Severity-based security gate (`--fail-on`; high/critical findings fail the PR scan job)
- [x] Local JSON baseline and deterministic finding suppression (`--baseline`, `--write-baseline`)
- [x] GitHub API check-run reporting for same-repository and fork PRs through the reusable trusted `pull_request_target` workflow (PR source is scanned as data only)
- [x] Optional GitHub App-owned check-run workflow for same-repository PRs (requires App installation and `APP_ID` / `APP_PRIVATE_KEY` secrets; source is scanned as data only)

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

- [x] Automated tests for scanner, report, AI-provider behavior, team access, and GitHub App check reporting (117 tests passed in PR #32 validation; merged-main CI run #227 passed)
- [x] Deterministic scanner fixtures
- [x] Verify no secrets exist in repository history (Gitleaks PR-change and full-history scans passed during the latest security validation)
- [x] Dependency pinning/lock strategy (`uv.lock`, hashes, `uv sync --locked` in CI)
- [x] Reproducible Docker dependency install and pinned Python base-image digest
- [x] CI security checks beyond lint/tests/type checking (`pip-audit`, Gitleaks PR and full-history scans)
- [x] Documented threat model (`THREAT_MODEL.md`)
- [x] Documented limitations and false-positive handling (README and threat model)
- [x] Release smoke checks on merged main (post-merge CI run #227 passed; PR validation included Ruff, 117 pytest tests, mypy, pip-audit, Gitleaks PR and full-history scans, Docker image build, and non-root CLI smoke test)

## Release discipline

- A CI run is considered green only when Ruff, pytest, and mypy all pass on the commit being released.
- A pull request being merged is not evidence that its CI passed; verify the post-merge run.
- AI explanations are opt-in, can be incorrect, and must not replace deterministic findings or developer review.
- The latest verified post-merge main CI run is [run 38520944215](https://github.com/rohitkrchandoliya/ai-appsec-platform/actions/runs/38520944215) on commit `b2813c6a1f64c2277d921a097c02b57c5c152102`; it passed. PR #34 added a trusted base-versus-head SARIF delta gate that blocks newly introduced high/critical findings and fails closed on scan/comparison errors. PR #35 documented this behavior. All tasks defined in the local-first MVP release scope above are implemented and checked off. Repository-admin setup for optional GitHub App-owned checks is documented in README.md. A centralized webhook service, hosted identity, and multi-tenant SaaS are explicitly outside this release scope rather than unfinished MVP checklist items. Local history and usage counters are opt-in via `APPSEC_DB_PATH`; usage counts are not billing.
