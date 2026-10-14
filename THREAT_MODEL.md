# Threat Model — AI AppSec Platform MVP

## Scope

This document covers the current local CLI scanner: Python AST rules, JavaScript/TypeScript pattern rules, secret detection, Python dependency inventory, optional OSV advisory lookups, JSON/SARIF reports, and CycloneDX SBOM output.

The MVP is a developer aid, not a complete security assurance system or a hosted multi-tenant service. The AI explanation path is opt-in and uses an OpenAI-compatible endpoint; it is not required for deterministic scanning.

## Assets to protect

- Source code and repository metadata supplied for scanning.
- Credentials and tokens that may appear in source files or findings.
- Integrity of findings, source locations, and machine-readable reports.
- Developer and CI environments that execute the scanner.
- Dependency inventory and advisory data returned by external services.

## Trust boundaries and attacker-controlled inputs

- Scanned source files, manifests, lockfiles, and local requirements includes are untrusted input.
- Findings and evidence derived from scanned files must be treated as untrusted output.
- OSV responses are external data and may be unavailable, malformed, stale, or incomplete.
- A malicious repository may contain very large files, malformed encodings, symlinks, path traversal attempts, or crafted dependency manifests.
- AI-provider responses must be considered untrusted and must not override deterministic findings or invent security identifiers/references.

## Current controls

- Python rules use AST parsing rather than matching only source text.
- Source traversal is restricted to supported files under the scan root and avoids following file symlinks outside it.
- Local requirements/constraints includes are constrained to the repository root and cycle-checked.
- Secret evidence is redacted before findings are emitted; SARIF does not include raw finding evidence.
- Findings are normalized, deduplicated, sorted, and assigned source locations.
- JSON, SARIF 2.1.0, and CycloneDX 1.5 output modes are separate.
- OSV advisory lookup is opt-in and requires network access.
- The opt-in `--explain` path uses a strict response schema and rejects finding-identity changes, unsupplied references, and unsupported CVE/CWE identifiers. Tests use mocked provider responses; production provider behavior still depends on the configured external service.

## Known limitations and residual risks

- Detection coverage is intentionally narrow. A clean scan does not prove a project is secure.
- JavaScript/TypeScript checks are regex-based and are not full semantic, taint, or data-flow analysis.
- Secret patterns do not cover every provider, token format, encoding, or credential storage method. Redaction reduces exposure but cannot guarantee all secrets are detected.
- Dependency inventory and risk scoring currently focus on Python manifests/lockfiles and exact-pinned versions; they do not resolve every environment marker or transitive dependency.
- OSV lookups depend on network availability and third-party advisory quality. Results should be reviewed before gating releases.
- AI explanations require explicit configuration and an external API key, send a bounded source window after known-pattern redaction, and may still disclose sensitive data that the redactor does not recognize. Review privacy policy before enabling them.
- There is no hosted API/dashboard, authentication, authorization, tenant isolation, or service-level operational control in the current MVP.
- The scanner should not be run with elevated privileges on untrusted repositories. Run it in a least-privilege environment and avoid mounting sensitive host paths into CI jobs.

## Safe operating guidance

1. Run scans as an unprivileged user against a dedicated checkout.
2. Do not provide secrets as test fixtures except synthetic tokens.
3. Treat reports as potentially sensitive because paths, dependency names, and code excerpts may be present.
4. Review findings and false positives before using results as a release gate.
5. Keep the scanner and its development dependencies updated; CI runs lint, tests, type checks, dependency vulnerability auditing, repository-history secret scanning, and a Docker build/smoke test once those checks pass on the target commit.
6. `uv.lock` now records resolved dependency versions and hashes, CI installs from the lock in locked mode, and the Docker build uses the same lock plus a pinned Python base-image digest. Keep the lock current and review dependency updates before merging.
7. For OSV audits, account for outbound network access and validate results before making release decisions.

## Out of scope for this MVP

- Guaranteed vulnerability detection or false-positive elimination.
- Full taint analysis, exploit verification, penetration testing, or runtime monitoring.
- A secure hosted service or multi-tenant SaaS deployment.
- Autonomous code modification or applying AI-generated patches.
- A guarantee that a repository contains no secrets or known vulnerable dependencies.


## Local API, dashboard, and scan history

The optional `appsec-api` service accepts source text as a JSON file map; it does not accept filesystem paths. Requests have a 1 MB total body limit, 128 KB per-file limit, a 200-file limit, and path traversal/control-character checks before files are written into a temporary directory. The server refuses non-loopback bind addresses. Optional `APPSEC_API_TOKEN` shared bearer-token authentication can protect data routes; tokens must be at least 32 ASCII characters and are compared with a constant-time comparison. The dashboard keeps the token only in page memory. This is not per-user authorization and does not make the service suitable for network exposure.

The browser dashboard serves only packaged static assets with a restrictive Content Security Policy, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and a no-referrer policy. It uses DOM text insertion rather than rendering scan results as HTML. The API does not enable CORS.

Persistent history is disabled unless `APPSEC_DB_PATH` is set. When enabled, SQLite stores project names, timestamps, usage counters, scan result JSON, and redacted finding evidence/metadata; it does not store the submitted full source files. Finding snippets may still reveal sensitive code, so protect the database file and remove it when no longer needed. The service is local-only and has no multi-user authorization or billing.

AI patch proposals are untrusted suggestions. The application validates finding identity, relative path, single-file diff headers, hunk presence, size, and likely secret patterns. It never applies the proposal to the working tree. Developers must review the diff and run their own tests before applying any changes.


## GitHub App PR check workflow

The optional GitHub App workflow uses `pull_request_target` only to obtain a scoped Checks API token and run the trusted base-branch scanner. PR contents are checked out into a separate directory as data; no PR scripts, build steps, package hooks, or tests are executed. The App token is passed only to the trusted check-run reporter, not to the scanner. The workflow is restricted to same-repository pull requests and requires administrator-configured `APP_ID` and `APP_PRIVATE_KEY` secrets. The check reporter validates SARIF paths and limits inline annotations to 50 per check request. Fork PRs are handled by the standard read-only Actions workflow until a safe cross-repository App flow is implemented.
