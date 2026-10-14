# Roadmap

## MVP release scope

The current release target is a tested local CLI MVP for deterministic source scanning, secret detection, Python dependency inventory/advisories, and machine-readable reports. It is not yet a complete AI reasoning product, GitHub App, or hosted SaaS platform. Do not describe pending phases as implemented.

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
- [ ] Actual AI provider adapter
- [ ] Finding explanation integrated into scan workflow
- [ ] Exploitability/context analysis integrated into scan workflow
- [ ] Remediation generation integrated into scan workflow
- [ ] Patch proposal generation
- [ ] End-to-end guardrails for AI-generated output

## Phase 4 — GitHub Developer Workflow
- [ ] GitHub App integration
- [ ] Pull-request scanning
- [ ] Inline findings
- [ ] Security gate
- [ ] Baseline/suppression support
- [ ] Check-run reporting

## Phase 5 — Product Layer
- [ ] API service
- [ ] Web dashboard
- [ ] Project management
- [ ] Historical findings
- [ ] Team workflows
- [ ] Authentication and authorization
- [ ] Usage metering

## Quality gates

Before calling the CLI MVP production-ready:

- [x] Automated tests for scanner and report behavior
- [x] Deterministic scanner fixtures
- [ ] Verify no secrets exist in repository history
- [ ] Dependency pinning/lock strategy
- [ ] Reproducible Docker build
- [ ] CI security checks
- [x] Documented threat model (`THREAT_MODEL.md`)
- [x] Documented limitations and false-positive handling (README and threat model)
- [ ] Final release smoke test on the merged main branch

## Release discipline

- A CI run is considered green only when Ruff, pytest, and mypy all pass on the commit being released.
- A pull request being merged is not evidence that its CI passed.
- Do not claim production readiness while any required quality gate remains unchecked.
