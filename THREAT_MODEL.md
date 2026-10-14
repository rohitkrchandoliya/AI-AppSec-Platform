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
6. Dependency version ranges are currently declared in `pyproject.toml`; a committed, fully resolved dependency lock and pinned container base-image digest remain release-hardening work until added and verified.
7. For OSV audits, account for outbound network access and validate results before making release decisions.

## Out of scope for this MVP

- Guaranteed vulnerability detection or false-positive elimination.
- Full taint analysis, exploit verification, penetration testing, or runtime monitoring.
- A secure hosted service or multi-tenant SaaS deployment.
- Autonomous code modification or applying AI-generated patches.
- A guarantee that a repository contains no secrets or known vulnerable dependencies.
