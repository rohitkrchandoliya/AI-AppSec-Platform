# Project Status

**Repository:** `rohitkrchandoliya/ai-appsec-platform`  
**Branch reviewed:** `main`  
**Last verified main commit:** `5c1b169aa203414dc6a64cc4a55f441b1e9d5942`  
**Last verified post-merge CI:** [Run 38521872939](https://github.com/rohitkrchandoliya/ai-appsec-platform/actions/runs/38521872939) — passed.

## Release status

The defined **local-first MVP implementation is complete**. This does not mean every possible vulnerability is detected, that production deployment has been independently validated, or that optional GitHub App configuration has been performed by a repository administrator.

Implemented release capabilities include:

- Deterministic Python and JavaScript/TypeScript security checks, secret detection, Python dependency inventory/advisory lookup, deterministic risk scoring, and CycloneDX SBOM output.
- Human-readable, JSON, and SARIF reports; severity gate; deterministic baselines and suppression.
- Optional AI finding explanations and review-only patch proposals with guardrails. AI output is advisory and never automatically applied.
- Local API and browser dashboard, opt-in SQLite scan history and usage counters, local user tokens, project membership, and admin/editor/viewer roles.
- GitHub Actions PR security workflow, reusable cross-repository workflow, SARIF annotations and dedicated checks, and an optional GitHub App-owned check-run reporter.
- CI quality gates including Ruff, pytest, mypy, pip-audit, Gitleaks, Docker build, and non-root smoke test.

## Verification evidence

- PR #32 validation: 117 tests passed; Ruff and mypy passed.
- Security validation: pip-audit reported no known vulnerabilities; Gitleaks PR-change and full-history scans passed.
- Docker production image build and non-root CLI smoke test passed.
- Post-merge main CI run #227 passed on commit `9c0df5940876296728df7638b7fcb457527d92ca`.

These results apply to the verified commit and test scope. Re-run CI after any subsequent code change.

## Repository-admin setup still required (documented, not code work)

The optional App-owned check remains disabled until an administrator creates/installs a GitHub App and adds repository Actions secrets `APP_ID` and `APP_PRIVATE_KEY`. Follow the **Optional GitHub App check-run setup** section in [README.md](README.md). The standard GitHub Actions security gate and reusable workflow do not require this App setup.

A centralized webhook service, hosted identity provider, and hosted multi-tenant SaaS are not included in the current release scope.

## Release acceptance checklist

- [x] MVP implementation and automated tests
- [x] Main CI green at the verified release commit
- [x] Roadmap aligned with implemented release scope
- [x] README setup and security limitations documented
- [x] Threat model documented
- [ ] Administrator optionally activates the GitHub App-owned check and verifies a real pull request
- [ ] Repository administrator sets branch protection/rulesets according to the checks they want to require

The final two items require access and choices by the repository administrator; they must not be marked complete based on code review alone.
