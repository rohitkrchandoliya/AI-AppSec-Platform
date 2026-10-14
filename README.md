# AI AppSec Platform

A developer-first application security scanner with deterministic source-code and secret checks, normalized findings, machine-readable reports, guarded AI patch proposals, GitHub Actions PR checks, and an optional local API/dashboard. It is a local-first tool, not a hosted multi-user SaaS product.

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

Run the local API and browser dashboard (loopback-only; no authentication):

```bash
uv run --locked appsec-api --port 8765
```

Open `http://127.0.0.1:8765/`. The dashboard accepts a JSON object mapping safe relative paths to source text and sends it to `POST /scan`. The API never accepts server filesystem paths and refuses non-loopback binds. It limits request size and file count, validates paths, and uses a temporary directory for scans.

Persistence is opt-in. To enable project management, scan history, and local usage counters, set a database path before launching:

```bash
export APPSEC_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
APPSEC_DB_PATH=.appsec-state.sqlite3 APPSEC_API_TOKEN="$APPSEC_API_TOKEN" uv run --locked appsec-api --port 8765
```

With `APPSEC_API_TOKEN` set, data endpoints require `Authorization: Bearer <token>`; the dashboard accepts the token in its password field and does not persist it. This enables `POST /projects`, `GET /projects`, `GET /history?project=NAME`, `GET /history/SCAN_ID`, and `GET /usage`. To save a scan under a named project, include `"project": "demo"` alongside the `"files"` map in the `POST /scan` JSON body. The SQLite database stores scan results and redacted finding evidence/metadata, not the submitted full source files. Protect the database file. The local API is loopback-only. Optional shared bearer-token authentication can be enabled with `APPSEC_API_TOKEN` (minimum 32 ASCII characters); the dashboard token field keeps it in page memory only. This is not per-user authorization, team access control, or a substitute for TLS and deployment hardening.

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

## Current limitations

- Detection coverage is narrow and rule-based.
- JavaScript/TypeScript analysis is regex-based and may produce false positives or miss indirect/obfuscated cases.
- Secret patterns do not cover every provider, token type, encoding, or credential storage pattern.
- Dependency inventory, OSV advisory lookup, risk scoring, and SBOM generation currently cover Python manifests and exact-pinned versions only; they do not resolve packages, evaluate every environment marker, or analyze JavaScript, Rust, Go, or other ecosystems.
- AI reasoning and patch proposals are advisory, may be wrong, require a configured external provider, and are not a substitute for security review. Patch proposals are returned for manual review only and are never applied automatically.
- The initial GitHub Actions PR gate scans the `appsec/` source tree, fails on high/critical findings, emits escaped GitHub Actions check annotations from SARIF, and uploads a SARIF artifact. GitHub App installation, GitHub API check-run creation, dashboard, project management, authentication/authorization, historical findings, team workflows, and usage metering are not implemented yet.
- Production readiness still requires dependency pinning/lock strategy, reproducible builds, CI security checks, repository-history review, and a green final release verification on the merged main branch.

## License

The project metadata declares MIT licensing. The repository includes the MIT license in `LICENSE`.
