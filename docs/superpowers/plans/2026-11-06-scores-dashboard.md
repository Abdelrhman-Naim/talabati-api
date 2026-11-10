# Measured Scores Dashboard Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans. Execute inline; user explicitly requested this concrete improvement.

**Goal:** Replace the decorative-first dashboard with meaningful percentages, pass/fail counts, deeper SEO/GEO readiness checks and auditable denominators.

**Architecture:** Persist per-page AuditCheck records alongside findings. A pure versioned scoring module computes weighted pass rate over performed checks and separate execution coverage. React renders category score cards and a check ledger; old JSON remains readable but unscored.

**Tech Stack:** Existing Next.js / Node.js / TypeScript / SQLite, no new dependencies.

**Spec:** Screenshot supplied by user and direct request for clear SEO/GEO and other metrics. Existing full spec is amended: custom checklist scores now allowed; never represent these as Lighthouse, ranking, WCAG compliance or comprehensive security.

## Global Constraints
- Weighted score = rounded passed weight / (passed + failed weight) × 100.
- Coverage = rounded executed check instances / applicable planned check instances × 100. Not applicable is excluded; unavailable remains in coverage denominator.
- No executed checks => null score, never 100. Existing v0.1 reports without checks are legacy and require a fresh scan.
- SEO/GEO numbers are local checklist indicators; performance measures HTTP transport only, not Core Web Vitals.
- Preserve owner authorization, secret redaction, existing DB, cancellation, API scope and Ollama settings.

## Review Focus
- A failed page must not produce a high SEO score from the lack of findings.
- Missing data, NA and unavailable checks must not inflate percentages.
- Malformed JSON-LD and private values must remain safe evidence.
- Legacy reports must retain findings without fabricated scores.
- All detail filters and exports must use the same metrics as the dashboard.

### Task 1: Deterministic checks and score model
Files: src/lib/types.ts, src/lib/checks.ts, src/lib/scoring.ts, tests/scoring.test.ts, tests/checks.test.ts.
Interfaces: evaluateChecks(page:HttpPage):AuditCheck[]; summarizeChecks(checks:AuditCheck[]):ScoreSummary; scoreReport(result?:ScanResult|null):ScoreSummary.
- [x] Write tests for 2:1 weighted mix, NA/unavailable, empty/legacy, malformed schema, HTML error pages, improving SEO/GEO fixtures and exact metrics.
- [x] Run tests red; implement check outcomes with redacted evidence and versioned score calculation.
- [x] Run suite green.

### Task 2: Persist and export real results
Files: src/lib/audit.ts, src/lib/jobs.ts, src/lib/demo.ts, src/lib/prompts.ts; tests/store.test.ts, tests/scoring.test.ts.
Interfaces: AuditOutput.checks and scoreVersion; ScanResult.checks/scoreVersion/collection optional for backwards compatibility.
- [x] Capture new check outcomes from pages and secret outcomes from fetched scripts; persist on progress and finish.
- [x] Export score and coverage/counts in Markdown. Keep HTML content in memory only.
- [x] Test fixture scan round-trip and no automatic upgrade of old reports.

### Task 3: Metrics-first responsive dashboard
Files: src/components/score-dashboard.tsx, src/components/check-ledger.tsx, src/components/workspace.tsx, src/app/globals.css; tests/interface.test.ts.
Interfaces: ScoreDashboard(result,onCategory,onRescan), CheckLedger(checks,category,onFinding), pure summary function shared with exports.
- [x] Test SSR labels and real numbers with NA/legacy results.
- [x] Replace oversized hero with scan selection, seven category cards, weighted summary, collection context, severity breakdown, prioritized actions and pass/fail ledger.
- [x] Keep all stats linked to the selected scan; charts use real counts. Expose weight, denominator and methodology.
- [x] Verify tests, TypeScript, production build and browser desktop/mobile layout where available.

### Task 4: Review and deliver upgrade
Files: README_AR.md, UPGRADE_AR.md, docs/PROGRESS.md, source ZIP.
- [x] Independent review, resolve Important findings with regression tests.
- [x] Document preservation of data/.env.local and restarting both processes; fresh scans required for old reports.
- [x] Save updated ZIP as a new version of the existing source artifact.

## Decisions
Native checklist approach selected under the user's existing authorization to add clear metrics. Live SEO engine APIs or AI-invented numbers were rejected: they would require external credentials or give non-evidenced scores. GEO readiness uses structural heuristics, not a universal standard. The fixed HTML content-length threshold is a transparent local heuristic, not a search ranking requirement.

## Validation
39 tests passed; TypeScript and production build passed. Independent review findings about missing JavaScript and redirected duplicate counts were fixed with failing-then-passing tests. Browser confirmed score cards, category filtering and expanded GEO evidence. No mobile device emulation was performed. Upgrade instructions preserve existing data and require fresh scans for old reports.
