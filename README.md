# AI AppSec Platform

A local-first application security platform with deterministic source-code and secret checks, normalized findings, machine-readable reports, guarded AI patch proposals, GitHub Actions PR checks, a local API/dashboard, opt-in SQLite history, and project-scoped team roles. It is not a hosted multi-tenant SaaS product.

## Who This Is For

This platform helps students and developers learn application security through safe, hands-on labs.

## Current implementation

- **Python SAST:** AST-based rules for `eval()` / `exec()` and `subprocess.run(..., shell=True)`.
- **JavaScript/TypeScript SAST:** pattern rules for `eval()`, `new Function()`, `exec()` / `execSync()`, `innerHTML`, and React `dangerouslySetInnerHTML`.
- **Secret detection:** patterns for private-key headers, AWS access key IDs, GitHub tokens, Slack token-like strings, and quoted hardcoded credential assignments. Evidence is redacted by the current secret rules.
- **Dependency inventory:** parses PEP 621 dependencies and optional groups from `pyproject.toml`, requirements files (including safe local `-r` / `-c` includes), and exact versions from `uv.lock`, `poetry.lock`, and `Pipfile.lock`.
- **Dependency advisory audit:** opt-in `--audit-dependencies` queries the OSV API for exact-pinned Python dependencies and adds known advisories to findings. Network access is required for this option.
- **SBOM export:** `--sbom` emits CycloneDX 1.5 JSON from exact-pinned Python dependencies; unresolved version ranges are intentionally excluded.
- **Dependency risk scoring:** each discovered dependency receives a deterministic 0–100 risk score based on version pinning and OSV-derived advisory severity/count.
- **Finding normalization:** root-relative paths where possible, deterministic sorting, and duplicate removal.
- **Local API and dashboard:** optional standard-library HTTP service exposes a local browser dashboard, `/health`, and `POST /scan` for bounded in-memory source files; it does not accept filesystem paths and defaults to loopback-only binding. Static assets use a restrictive Content Security Policy and DOM text insertion for scan output.
- **CLI reports:** human-readable output, JSON (`--json`), and SARIF 2.1.0 (`--sarif`). The optional `--fail-on info|low|medium|high|critical` flag exits with status 1 when a finding meets or exceeds the selected severity, enabling CI security gates while keeping JSON/SARIF on stdout.
- **Finding baselines:** `--write-baseline .appsec-baseline.json` records current findings; `--baseline .appsec-baseline.json` suppresses matching known findings while preserving new findings for the gate. Baseline fingerprints are deterministic, ignore line-number-only shifts, and do not store raw evidence.
- **Optional AI explanations:** `--explain` asks a configured OpenAI-compatible chat-completions endpoint for explanations, exploitability context, remediation guidance, confidence, and limitations. The deterministic scanner findings remain the source of truth.
- **AI patch proposals:** `--propose-patches` requests a minimal unified diff for each finding. Proposals are restricted to the finding’s single relative file, checked for malformed paths/multi-file changes/likely secrets, and are never automatically applied. A developer must review every proposal.
- **Quality checks:** GitHub Actions CI runs Ruff, pytest, and mypy.

This is an early MVP with intentionally limited rule coverage. The JavaScript/TypeScript checks are regex-based, not full semantic or taint analysis. A clean scan does not prove that a repository is secure. Review [the threat model](THREAT_MODEL.md) before using results as a release gate.

## Quick start

Requires Python 3.12 or newer. `uv.lock` pins resolved direct and transitive dependencies; use `uv sync --locked` to install the committed versions. Update dependencies intentionally with `uv lock` and commit the resulting lockfile.

```bash
python -m pip install uv==0.13.0
uv sync --locked --all-extras
# Run commands through the locked environment:
uv run --locked appsec scan ./path-to-project
```

Run a human-readable scan:

```bash
uv run --locked appsec scan ./path-to-project
```

Export JSON:

```bash
uv run --locked appsec scan ./path-to-project --json
```

Export SARIF 2.1.0:

```bash
uv run --locked appsec scan ./path-to-project --sarif
```

Audit exact-pinned Python dependencies against OSV (requires network access):

```bash
uv run --locked appsec scan ./path-to-project --audit-dependencies --json
```

Export a CycloneDX SBOM:

```bash
uv run --locked appsec scan ./path-to-project --sbom
```

### Reuse the PR scan in another repository

For repositories where you want the same scanner, add a caller workflow like this (replace `main` with a reviewed commit SHA if you want to pin the scanner version):

```yaml
name: AI AppSec

on:
  pull_request_target:
    branches: ["main"]

permissions:
  contents: read
  checks: write

jobs:
  security:
    uses: rohitkrchandoliya/ai-appsec-platform/.github/workflows/reusable-appsec-scan.yml@main
```

The reusable workflow checks out the scanner from this repository and the target pull request's base and head revisions separately. It treats both target revisions as data only; it never runs target scripts, tests, package hooks, build steps, or dependency installation. It compares stable SARIF finding fingerprints and fails on newly introduced high/critical findings, while reporting the finding delta as workflow annotations, a SARIF artifact, and a dedicated check run. Existing findings are excluded from the blocking delta only when the same fingerprint exists on the trusted base revision. The caller uses `pull_request_target`, so the reusable workflow definition and scanner come from the trusted base revision. The ordinary `pull_request` workflow is read-only and has no `checks: write` permission. This cross-repository workflow requires no GitHub App private key; centralized webhook-based installation is not included in the local-first MVP.

### Optional AI explanations

Set a key for the OpenAI-compatible endpoint you intend to use. The model can be overridden with `OPENAI_MODEL` and the endpoint with `OPENAI_BASE_URL` (defaults to `https://api.openai.com/v1`).

```bash
export OPENAI_API_KEY="your-key"
# Optional:
export OPENAI_MODEL="gpt-4.1-mini"
export OPENAI_BASE_URL="https://api.openai.com/v1"

uv run --locked appsec scan ./path-to-project --explain
uv run --locked appsec scan ./path-to-project --json --explain
# Review-only AI patch proposals; requires configured provider
uv run --locked appsec scan ./path-to-project --propose-patches
```

**Privacy note:** `--explain` is opt-in. It sends finding metadata and a small redacted source window to the configured endpoint. Review your organization's data-handling policy before using it with private repositories. The implementation redacts recognized secret patterns, but no redaction system can guarantee that every sensitive value is removed. AI output is untrusted, is checked against the finding identity and supplied references, and must be reviewed by a developer. `--explain` cannot be combined with `--sarif` or `--sbom`.

Use `--json`, `--sarif`, and `--sbom` separately; they cannot be combined in one invocation.

### Local API, dashboard, and history

Run the local API and browser dashboard (loopback-only; authentication is optional):

```bash
uv run --locked appsec-api --port 8765
```

Open `http://127.0.0.1:8765/`. The dashboard accepts a JSON object mapping safe relative paths to source text and sends it to `POST /scan`. The API never accepts server filesystem paths and refuses non-loopback binds. It limits request size and file count, validates paths, and uses a temporary directory for scans.

Persistence is opt-in. To enable project management, scan history, and local usage counters, set a database path before launching:

```bash
export APPSEC_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
APPSEC_DB_PATH=.appsec-state.sqlite3 APPSEC_API_TOKEN="$APPSEC_API_TOKEN" uv run --locked appsec-api --port 8765
```

With `APPSEC_API_TOKEN` set, data endpoints require `Authorization: Bearer <token>`; the dashboard accepts the token in its password field and does not persist it. This enables `POST /users`, `GET /users`, `DELETE /users/USERNAME`, `POST /projects`, `GET /projects`, `GET /projects/NAME/members`, `POST /projects/NAME/members`, `DELETE /projects/NAME/members/USERNAME`, `GET /history?project=NAME`, `GET /history/SCAN_ID`, and `GET /usage`. To save a scan under a named project, include `"project": "demo"` alongside the `"files"` map in the `POST /scan` JSON body. User tokens are scoped to project memberships; only the shared administrator token can create/revoke users. The SQLite database stores scan results and redacted finding evidence/metadata, not the submitted full source files. Protect the database file. The local API is loopback-only. Set `APPSEC_API_TOKEN` to a strong shared administrator token (at least 32 ASCII characters). The administrator can create individual users with `POST /users`; each user receives a one-time token whose SHA-256 hash is stored in SQLite. The dashboard token field keeps the token in page memory only. Project roles are `admin`, `editor`, and `viewer`: editors/admins can scan, viewers can read results, and project admins can manage membership. The global administrator can list/revoke users. This is a local-first access model, not a hosted identity provider.

### Optional GitHub App-owned check-run integration

The standard GitHub Actions gate and reusable cross-repository workflow work without a custom GitHub App. To publish an additional check owned by an installed GitHub App for same-repository pull requests:

1. Install a GitHub App on this repository with **Contents: read** and **Checks: write** permissions.
2. Add repository Actions secrets named `APP_ID` and `APP_PRIVATE_KEY`.
3. Open or update a pull request targeting `main`. If either secret is missing, the optional workflow records a skip summary and the standard security gate remains active.
4. The workflow runs from the trusted base revision and checks out PR source into a separate `target/` directory as data only. It never executes PR scripts, tests, package hooks, builds, or installs PR dependencies.
5. The short-lived App token is scoped to this repository and passed only to the trusted check-run reporter, not to the scanner.

This is an optional app-owned check identity; centralized installation/webhooks and managing App installations across other repositories remain post-MVP.

## How it works

1. The CLI accepts a project directory.
2. Python, JavaScript/TypeScript, and secret scanners inspect supported source files; dependency manifests and lockfiles are inventoried separately.
3. Findings are normalized, sorted, and deduplicated.
4. The CLI prints human-readable results or exports JSON/SARIF. Optional flags enable OSV advisory lookup and CycloneDX SBOM output.
5. With explicit `--explain` opt-in, the reasoning provider receives the finding and a bounded, redacted source context. Its structured output is validated before display.

The SARIF `rulesRun` property reports the combined configured rule counts for the source scanners. OSV advisories are queried only when requested and are findings from an external advisory database, not additional fixed scanner rules.

## Engineering principles

1. Prefer high-confidence deterministic detection over AI-only vulnerability claims.
2. Every finding should have a reproducible rule identifier and source location.
3. Treat scanned source code as untrusted data.
4. Do not export raw secret evidence in machine-readable reports.
5. Never commit credentials, API keys, tokens, or private customer data.
6. Test scanners as security-critical software and document limitations.

## Roadmap and security documentation

- [Roadmap and release gates](ROADMAP.md)
- [Threat model, trust boundaries, and safe operating guidance](THREAT_MODEL.md)

## Release status and final setup

**Release scope:** the local-first MVP implementation is complete. The repository includes the CLI scanners, reports/SBOM/baselines, opt-in AI explanation and review-only patch proposals, local API/dashboard/history/team roles, reusable cross-repository GitHub Actions scanning, and the optional GitHub App-owned check-run reporter. The project is not a hosted multi-tenant SaaS service.

The default GitHub Actions security workflow and reusable workflow do not require a GitHub App installation. App-owned check runs are an optional enhancement and remain inactive until a repository administrator completes the setup below. This is configuration, not missing scanner implementation.

### Optional GitHub App check_run Setup

Do this only if you want the check to be authored by your GitHub App rather than the standard GitHub Actions identity.

1. Open **GitHub → Settings → Developer settings → GitHub Apps → New GitHub App**.
2. Give the App a recognizable name and set **Webhook Active** to off if you are only using the current check-run workflow; no webhook URL or webhook secret is required for this workflow.
3. Under **Repository permissions**, grant only:
   - **Contents: Read-only**
   - **Checks: Read and write**
4. Create the App, note its **App ID**, and generate a private key. Store the private key securely; never commit it to this repository or paste it into an issue or log.
5. Install the App on the repository `rohitkrchandoliya/ai-appsec-platform`. Select only the repositories that should receive the App-owned check.
6. In the repository, open **Settings → Secrets and variables → Actions → New repository secret** and add:
   - `APP_ID`: the numeric App ID.
   - `APP_PRIVATE_KEY`: the complete generated private key, including its header and footer.
7. Open or update a same-repository pull request targeting `main`. The **Optional GitHub App Security Check** workflow should run and publish **AI AppSec GitHub App Scan**. Confirm the run and check result in the PR Checks tab.
8. If the optional workflow skips because the secrets are absent, that is expected; the standard AppSec workflow remains the active security gate.

**Trust boundary:** the optional workflow checks out scanner code and dependencies from the trusted PR base revision. Pull-request source is checked out separately and scanned as data only; it must not be executed, built, or used to install dependencies. The App installation token is passed only to the trusted check-run reporter.

### Cross-repository use

For another repository, follow the reusable workflow example above. Prefer pinning the reusable workflow reference to a reviewed full commit SHA instead of `@main` for stricter supply-chain control. Configure required workflow permissions in the caller repository and verify the result on a test pull request before making the check a required branch-protection rule.

### Final verification checklist

- [ ] Run the local commands in **Quick start** and scan a small test project.
- [ ] Review [ROADMAP.md](ROADMAP.md) and [THREAT_MODEL.md](THREAT_MODEL.md).
- [ ] If using the optional App-owned check, complete the setup above and verify a real PR check.
- [ ] Configure branch protection / rulesets to require the intended AppSec check only after observing a successful test PR.
- [ ] Keep the App private key in GitHub Secrets; rotate it if it is exposed.
- [ ] Review findings manually. A clean scan is not proof that software is secure.

## Current limitations

- Detection coverage is narrow and rule-based.
- JavaScript/TypeScript analysis is regex-based and may produce false positives or miss indirect/obfuscated cases.
- Secret patterns do not cover every provider, token type, encoding, or credential storage pattern.
- Dependency inventory, OSV advisory lookup, risk scoring, and SBOM generation currently cover Python manifests and exact-pinned versions only; they do not resolve packages, evaluate every environment marker, or analyze JavaScript, Rust, Go, or other ecosystems.
- AI reasoning and patch proposals are advisory, may be wrong, require a configured external provider, and are not a substitute for security review. Patch proposals are returned for manual review only and are never applied automatically.
- The GitHub Actions PR gate scans the `appsec/` source tree, fails on high/critical findings, emits escaped workflow annotations, uploads SARIF, and publishes a dedicated check run. The reusable workflow can be called from another repository's trusted `pull_request_target` workflow; PR source is scanned as data only. An optional app-owned check is available for same-repository PRs after App installation and secret configuration.
- The local API/dashboard supports project registry, per-user tokens, project-scoped roles, opt-in scan history and usage counters. It remains loopback-only and is not a hosted identity provider. Protect the SQLite history file because finding snippets may still contain sensitive code.
- This is not a hosted multi-tenant SaaS. Cross-repository scanning is provided by a reusable GitHub Actions workflow; centralized GitHub App installation/webhooks remain post-MVP.

## License

The project metadata declares MIT licensing. The repository includes the MIT license in `LICENSE`.
