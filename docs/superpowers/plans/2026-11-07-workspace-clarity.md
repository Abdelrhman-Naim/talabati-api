# Workspace clarity and scan outputs implementation plan

**Goal:** Deliver the user's requested organized Arabic workspace, light/dark appearance, trustworthy scan activity, and visible report/whole-scan repair prompt actions.
**Architecture:** Keep native Next.js/Node/SQLite and the current feature checkout. Add focused client components for themes, activity and outputs. Persist actual worker events inside the existing result JSON; expose report/prompt generation behind existing owner checks. Preserve historical data.
**Spec:** User's explicit change request in this conversation; Ollama stays text-only. No additional approval or platform choices required for this authorized reversible implementation.

## Requirements and constraints
- Existing projects, sessions, verification and cancellation remain intact.
- Reports contain real available checks and limitations, not fabricated scores. Live activity has no invented percentage or timers implying engine progress.
- Theme preference persists locally; initial system preference supported. Both themes must be readable on mobile and desktop.
- Actions labelled تقرير الفحص and برومبت الإصلاح are visible with the selected scan. Whole-scan prompts support category/severity filtering and include acceptance criteria.
- Text generation templates work without AI. Ollama is still used only for optional textual explanation; no images.
- Read-only demo may preview/download templates locally, explicitly marked synthetic. No live scans or AI requests from demo.

## Review focus
- Cross-owner report/prompt access denied; unknown finding IDs rejected.
- Running/failed/empty/legacy scans cannot look like a completed comprehensive audit.
- Cancellation/deadline doesn't fabricate completed events or overwrite a cancelled scan.
- Theme, filters, dialogs and selected report stay usable on a narrow screen and keyboard.
- Exported report and on-screen scores/coverage agree; HTML evidence stays escaped and secrets redacted.

## Tasks
1. [x] Write failing tests for whole-scan prompt selection/redaction, real-browser report wording, owner endpoint denial and real worker events. Implement pure text export functions and additive event log, keeping old results readable. Run suite and commit.
2. [x] Add appearance toggle and no-flash initialization, activity timeline, printable report and scoped prompt center. Organize results into summary/issues/checks/outputs and history as separate navigation. Preserve all existing project/auth features; read-only demo previews outputs. Verify with SSR and build.
3. [x] Rework contrast, spacing, responsive navigation and dark tokens throughout existing controls/cards/dialogs. Inspect light/dark, outputs, filtering and activity in browser. No screenshots or image inputs to Ollama.
4. [x] Full tests/typecheck/build, independent review, fix important issues with regression tests. Update upgrade guide and ZIP; replace same persistent deliverable. Disclose any unverified browser-engine limitation.

## Review and validation ledger
Task1: 52 core tests passed; commit bba35e3. Task2/3: typecheck and build passed; CUA verified desktop light/dark, stored dark preference on reload, SEO subset prompt4/20, individual prompt, generated report and activity/history. Native Print dialog/PDF output and narrow viewport were not visually verifiable in CUA; responsive and print styles supplied; temporary iframe QA page removed.
Review: independent reviewer found cross-project activity selection; fixed with selectedScan test RED→GREEN. Historical running event upgraded to Important for credibility; fixed with SSR regression RED→GREEN. Author caught/fixed dark modal header and printed demo disclaimer; no raw HTML rendering. Collector subphase persistence regression RED→GREEN.
Ruling: keep existing v3 queue protocol, since optional events are additive and historical scans remain readable; upgrade guide requires restarting old workers. Cost: old workers do not emit activity events.

Final verification: 57/57 core tests passed; TypeScript and final Next.js production build passed. Source ZIP includes complete 0.4.0 changes and upgrade guide, excluding credentials, runtime DB and build/dependency directories. No additional independent re-review after regression fixes; no deferred code-review findings.
