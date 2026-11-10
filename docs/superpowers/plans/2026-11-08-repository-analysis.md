# Repository Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bind a chosen GitHub repository and run inspectable source analysis within platform.
**Architecture:** Fixed-host GitHub REST reader; encrypted per-project credential; immutable snapshot worker; shared scan ledger and dedicated repository UI.
**Tech Stack:** Existing Next16/Node24/SQLite/React/TypeScript; built-in crypto and bounded HTTPS transport.
**Spec:** docs/superpowers/specs/2026-11-08-repository-design.md

## Global Constraints
No repository execution, credential echo, external code upload by default, or fabricated vulnerabilities. 1000 files / 256KiB per file / 20MiB / 10 minutes defaults. Retain URL flow and old records.

## Review Focus
Cross-owner access; token disclosure; ref drift; untrusted GitHub tree paths/symlinks/redirects; cancellation/rate limits/partial scans.

### Task 1: Trusted reader and analyzer
- [x] Add failing tests in tests/repository.test.ts for target validation, encrypted credential AAD, immutable commit reads, source rule locations/redaction, exclusions and truncation.
- [x] Implement src/lib/repository/{github,vault,analyzer}.ts and type contracts; read-only GitHub API via injected transport for deterministic tests.
- [x] Run focused suite then full tests.

### Task 2: Binding and scan lifecycle
- [x] Test owner isolation, no credential serialization, repo scan without website-verification bypass of URL gate, queue protocol, disconnect cancellation.
- [x] Extend Store/additive tables, API project/repository endpoints, worker dispatch and cancellation-bounded repository runner.
- [x] Run API and lifecycle tests/full suite.

### Task 3: UI and delivery
- [x] Add repository binding panel and active deep scan option with accurate setup guidance.
- [x] Add source details, file ledger and coverage, preserve outputs and text-only AI; distinguish report scope and comparison mode.
- [x] Typecheck/build/full suite, independent code review and browser UI review.
- [x] Update upgrade guide, package and replace existing ZIP preserving Library identity.


Execution ledger: native implementation in existing isolated feature branch, baseline dd79d79. Tasks 1–3 complete. Choice retained from spec: fixed-host REST + per-repository fine-grained read token, no GitHub App provisioning or write/PR permissions. No extra dependency installation. Independent review identified 3 P2 collection/coverage cases, all reproduced and fixed with regressions; an additional active-job guard limit was regression-tested and corrected. Final evidence: 103 tests, typecheck and build passed. Live GitHub smoke blocked by EAI_AGAIN DNS; private credentials untested. See docs/REPOSITORY_VERIFICATION.md. Deliver updated source ZIP, retain current branch; no remote merge/deploy requested.
