# Execution ledger — 2026-11-06-beta-implementation

User authorized execution in Next.js and Node.js. No existing repository was present; new isolated project created on feat/audit-beta.

Ruling: Ship native Next.js/Node server source rather than substituting Vinext/Workers hosting — long-lived worker and Node SQLite require a real Node host. Cost: no Sites deployment URL.
Ruling: First working milestone implements passive HTTP/DOM scanning; browser engines, active API tests and repo writes remain explicitly unavailable — do not invent coverage. Cost: full product needs later milestones.
Ruling: SQLite is single-host beta persistence with an independent worker — no external database credentials available. Cost: migrate to PostgreSQL/queue for multi-host scale.

Preflight: audit output types consumed by worker and UI; store IDs passed through API enforce ownership; AI receives redacted findings only. No conflicting interfaces.

Task 1: complete — initial missing-module RED; safe transport/audit GREEN 9 tests; commit 60f25d0 includes core.
Task 2: complete — store RED; corrected SQL placeholder count at insertion source; 15 tests GREEN.
Task 3: complete — Ollama/prompt RED; adapter and fallback template GREEN 18 tests.
Task 4: complete for first working milestone — route integration, UI, docs, optional Docker; 24 tests GREEN, TypeScript and production build pass.
Ruling: HTTP smoke could not connect from executor to browser-only preview port — verified real Next Route Handlers directly plus browser-rendered public demo instead. Cost: socket-level authenticated E2E remains unverified.
Final review: independent reviewer found 3 Important and 3 Minor, no Critical.
Final: fixed secret-bearing target storage — network URL rejection test RED→GREEN and independent redaction of result scope.
Final: fixed invisible modal errors — SSR dialog error test RED→GREEN; also verified in browser via read-only action rejection.
Final: fixed historical future-baseline comparison — historical comparison test RED→GREEN; strictly older same-project/same-kind reports.
Final: minor (deferred): versioned JavaScript URLs with queries excluded; may miss bundles.
Final: minor (deferred): transient refresh error shows login; server session remains valid.
Final: minor (deferred): job lease renewed with progress, not periodic heartbeat; one worker only until lease strategy upgraded.
Additional verification: worker fixture completes, stores real parsed findings and does not probe discovered third-party API. Pinned DNS callback supports Node autoSelectFamily lookup contract.
Browser: / and /demo rendered; finding evidence and modal error verified. No user credentials entered.
Deliverable: source ZIP, no runtime DB, auth tokens, dependencies or generated build files. Keep local feature branch; no base branch or remote repository existed, so no merge/push performed.

## 0.2.0 — requested numeric scores upgrade
Ruling: implement custom versioned checklist scores for available engines — user explicitly requests numeric SEO/GEO/other metrics; cost: these indicators are not universal ranking or compliance standards.
Task 1: weighted score/coverage/NA/legacy and document check fixtures RED to GREEN.
Task 2: worker persistence and Markdown export assertions RED to GREEN.
Task 3: metrics-first cards, coverage, severity percentages, collection context and audit ledger; SSR tests RED to GREEN. Browser confirmed cards, GEO filtering and rule evidence.
Review: independent reviewer found missing-script success inflation (Important) and redirect duplication (regraded Important for exact-count requirement). Both fixed with 404/throw/redirect alias regression tests RED to GREEN.
Additional correctness: failed HTML performance and dangling button labels RED to GREEN; malformed JSON-LD cannot improve readiness, empty author objects cannot earn a pass.
Final verification: 39 tests pass; TypeScript and Next.js production build pass. No new deferred review issues. Existing single-worker, JS-query exclusion and transient-refresh beta limitations remain in README.
No live scan of the user website or live Ollama inference performed. No destructive schema migration. Legacy reports keep findings and need a fresh scan for scores. Upgrade guide preserves data and .env.local.

## 0.3.0 — rendered URL engine and worker integrity
Protocol-isolated queue, versioned heartbeat, periodic leases, dev auto-worker, gzip/binary transport, guarded Playwright+axe pipeline, observed API provenance, lab LCP/CLS, invalid-record rescan diagnostic. Prior query-string JS exclusion and page-progress-only lease notes are superseded.
Independent review P1 stalled evaluate and P2 self-removing secret scripts fixed with RED-to-GREEN tests. 47 tests, TypeScript and Next production build passed. Chromium integration attempted: launch fails with socket() EPERM in executor; no claimed real-browser engine success. CUA checked synthetic demo and live worker health: explicit HTTP fallback reason. Docker not built; live user site/Ollama not tested. Upgrade preserves data/.env.local and requires fresh scan.

## 0.3.1 — explicit text-only Ollama contract
User confirmed text-only server. Existing allowlisted request already excluded images; system instructions now prohibit visual-inspection claims and invented scores. UI, UX fallback wording and design doc distinguish browser DOM measurements from AI explanation. Added request contract regression: media attachment fields excluded, text-only instructions present. 48 tests, typecheck and production build passed; live Ollama not called. No model/server/DB changes.

## 0.3.2 — scan waits and 404 diagnostics
User reports long scan and generic console404; exact failing URL unavailable. Read attached TaskFlow plan: unrelated Firebase task app, no edits. Confirmed code only checked180s budget between fetches, had no per-fetch deadline; UI reset session on every refresh failure; favicon absent. Added bounded per-fetch/total collection, abort signal to renderer, pre-fetch stage and elapsed time, response endpoint/status diagnostics, preserve session except401, actual favicon, per-resource404 report warnings. No claim that unknown user404 source was reproduced. New stalled-fetch and non-JSON404 regressions plus full suite/build validation.

Verification: 50 tests passed, typecheck and Next production build passed. Generated favicon route metadata confirms HTTP200 image/x-icon. No live reproduction of unknown console404; no new live Ollama call or Chromium run claimed.

## 0.4.0 — workspace clarity, themes, activity and outputs
Implemented user-authorized layout restructure into projects/activity/results/history/services; summary/issues/checks/outputs separate. Persistent light/dark theme, text-only local report and scoped prompt generation, print/PDF browser action, real worker event timeline and collector subphases. Existing data preserved, no AI or live user-site call. Independent review fixes: cross-project selection and stale current event; print synthetic disclosure preserved, dark modal contrast corrected. See 2026-11-07-workspace-clarity plan for validation/limits.

Final 0.4.0 verification: 57 core tests pass; tsc and production Next build pass. CUA checked actual desktop light/dark, saved preference, report generation, scoped/individual prompts, issues dialog, activity and history. Print/PDF output and narrow viewport not visually verified. Source package preserves existing data contract and excludes runtime secrets/DB.

## 0.5.0 — expanded same-origin crawling
Removed five-page default,25-link extraction/frontier truncations and blanket query exclusion. Default full mode with nested/gzip sitemap/robots and canonicalized pagination; explicit quick mode. Additive scan_settings and v5 queue protect new jobs from older workers. Accurate pending/failed/skipped/maps/stop summaries in UI/exports. Signals cancel active reads; redirect destinations and browser navigation checked before fetching. Core71 tests include38-page fixture, cap remaining, query dedup, robots groups/wildcards/Unicode, transport redirects, cancellation and gzip. Independent review important findings fixed; see expanded-crawl plan. Existing scores and text-only AI retained.

Final 0.5.0 verification: 71 tests pass, tsc and production Next build pass. CUA checked full mode selected by default, optional limit input and quick switch, and crawl summary. No live user-site or real Chromium crawl claimed. Source ZIP excludes .env.local, DB/dependencies/builds.

## 0.5.1 — larger crawl follow-up
User asked to continue validation. A new122-page fixture exposed HTML base resolution, relative child maps and missing declared-map diagnostics. Regression tests failed first; fixes now resolve base URLs correctly, scope external-base links away, resolve child maps/relative page URLs against final sitemap URL, and mark declared404/410 as incomplete discovery.75/75 tests, tsc and production build passed. No live user-site or Chromium test claimed. No schema/model/dependency change.
