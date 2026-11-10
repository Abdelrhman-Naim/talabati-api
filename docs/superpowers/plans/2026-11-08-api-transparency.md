# API access matrix implementation plan

Goal: execute explicit read-only API fixture checks and expose every outcome, without claiming arbitrary API or RLS coverage.
Architecture: encrypted per-project configuration, independent origin proof, two test identities and two canary fixtures, GET-only isolated transport, immutable scan configuration ID, additive SQLite migration and v9 queue isolation.
Constraints: no production probing now; no writes; no credentials or response bodies in reports; deny private networks/redirects; expired proof, baseline failure and incomplete evidence cannot pass.
Review focus: broken baselines, cross-origin credentials, stale configuration, cancellation, secret leakage.

1. Tests first: fixture isolation/access leak, invalid baseline/inconclusive response, expiry/cancellation, owner isolation/encrypted storage, invalid paths and privileged keys. Implement src/lib/api-tests.ts and Store configuration methods.
2. Integrate job, API handlers and newscan UI; settings inside repository panel, all six planned cases recorded even on failures. Show expected/observed metadata and complete JSON export in ledger. Verify tests/typecheck/build.
3. Independent final review, resolve significant findings with regression tests; package source and upgrade instructions; replace existing ZIP.

Execution ledger: existing isolated feat/audit-beta branch; inline implementation authorized by user. No live API requests performed on the user's projects.

Completed: encrypted configuration/proof and six-case matrix; UI and per-request ledger; cancellation and early failure preserve planned outcomes; complete JSON and Markdown evidence. Independent review's three Important findings reproduced RED→GREEN and resolved. Minor Storage expected text corrected together with the Storage denial regression. Final 144/144 tests, typecheck, production build and diff check passed. UI preview unavailable due local connection refusal, documented explicitly. No live user API probing performed.
