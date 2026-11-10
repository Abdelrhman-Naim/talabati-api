# Security release verification — 0.6.0

Date: 2026-11-07

- npm test: 86 passed, 0 failed. Regression coverage includes CSP precedence/handlers/wildcard hosts, cookies/expiry, CORS semantics, public vs privileged keys and redaction, secret-free report/prompt output, URL scope, authorization, queue isolation, crawl cancellation and persistence.
- npm run typecheck: passed.
- npm run build: passed (production routes generated).
- Independent focused review: CSP false-pass cases reproduced, corrected and added to regressions.
- UI reviewed through browser: Security results tab, numerical scores and coverage, finding evidence/impact/steps, scoped security prompt, dark appearance; demo is explicitly synthetic.
- npm run test:browser: blocked by Chromium socket() EPERM in the executor. This integration test did not pass here. Run on deployment host with Node24 and installed Chromium. UI review uses a separate browser and is not evidence that the collector integration passed.

No real target was penetration tested for this release. Authorization, RLS, exploitability and credential validity are not inferred from passive configuration checks. No raw cookie values or matched secret values are stored in the new security detail records.

Upgrade: preserve data/ and .env.local, stop all old processes, install dependencies, restart worker/server and launch a new scan. Old reports remain readable without inventing new results.
