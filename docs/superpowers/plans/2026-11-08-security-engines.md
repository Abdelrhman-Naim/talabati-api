# Security Engines Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for inline execution.

**Goal:** Run real AST and vulnerability-advisory engines and optional verified runtime HTTP checks.
**Architecture:** Local AST analyzer; lockfile version extractor and bounded fixed-host OSV client; shared security ledger with explicit execution reasons. Existing worker owns lifecycle/cancellation and owner scope.
**Tech Stack:** Next16, Node24, TypeScript compiler API, SQLite, existing public DNS-pinned transport.
**Spec:** docs/superpowers/specs/2026-11-08-security-engines-design.md

## Global Constraints
No repository execution, fabricated passes/CVE severity, credentials in results or unconsented source/dependency disclosure. OSV only after scan opt-in; runtime only after domain verification.

## Review Focus
Comment/string false positives; malformed/missing lock versions; OSV partial/withdrawn/paginated responses; scope expiry/cancellation; lockfile response limits and old worker compatibility.

### Task 1: Engines
- [x] RED tests for JS AST comments/real calls/multiline and lock parsing/version dedup/query disclosure/advisory failure.
- [x] Implement ast.ts/dependencies.ts/osv.ts and bounded POST service transport; integrate immutable large lockfile reads.
- [x] Focused tests and full suite.
### Task 2: Lifecycle
- [x] RED tests for OSV opt-in and runtime owner/domain gates, expiry/cancellation and real results.
- [x] Integrate worker scan flags and engine summaries; queuev8. Failures never earn a pass.
- [x] Full suite and typecheck.
### Task 3: Presentation and delivery
- [x] Engine summaries, options, actionable unavailable reasons, exports and regression checks.
- [x] Independent review, production build/UI QA; upgrade docs and same-identity ZIP replacement.


Execution ledger: inline work on existing feature branch, baseline 04a0504. AST engine parses without emission; TypeScript moved to runtime dependency. OSV never runs for old jobs or without explicit per-scan selection; runtime option requires verified project URL. Independent review fixes all regression-covered: consent unchecked by default, leases cannot revive expired work, incomplete lock discovery downgrades inventory, malformed pagination cannot yield a pass. No minor findings deferred. Verification: 121 tests, typecheck and production build passed. Live OSV query unavailable from executor, documented without success claim. Delivery preserves current branch and existing ZIP identity; no remote merge/deploy requested.
