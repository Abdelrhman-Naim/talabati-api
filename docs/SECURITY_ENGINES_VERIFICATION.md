# Security engine release verification — 0.8.0

Date: 2026-11-08

- npm test: 121 passed, 0 failed.
- npm run typecheck: passed.
- npm run build: passed, production routes generated.
- AST regressions: actual call nodes versus comment/string mentions; multiline SQL interpolation; syntax-error unavailable handling; declaration files without emission; public-secret comment exclusion; JSON syntax classification remains technical.
- Dependency tests: pinned npm v1/v2/v3 extraction, nested scoped names/dedup, missing/uncollected lock inventory, explicit OSV opt-in, payload excludes source/file/repo/token data, exact service POST restriction and body cap, malformed batch/pagination/withdrawal rejection, partial queries cannot earn clean passes.
- Runtime tests: owner/domain verification, verification expiry after queue, expired worker lease prevents reads/renewal/progress, cancellation aborts active OSV reads, legacy queues cannot claim new jobs.
- Independent review: four issues reproduced and fixed—default OSV consent removed, job lease enforced, missing-lock coverage partial, pagination type validation. Regression tests passed after fixes.
- UI reviewed in browser: engine summary, explicit unchecked OSV selection, runtime option gated by domain verification, setup requirements and synthetic preview labels.

Live OSV smoke query used public fixture lodash@4.17.20, not user repository data. External query could not complete in this execution environment (status unavailable, queried0). The live OSV service path has NOT been verified here. Deployment host needs outbound DNS/HTTPS to api.osv.dev. Local integration tests use controlled responses for malformed, clean, matched, partial and cancelled cases. No user's repository or live API was queried for this verification.

No repository code or package install scripts were executed. Active authorization/RLS tests, exploitation and full-project dataflow remain outside scope. OSV version matching is evidence of an advisory match, not exploitability; absent source severity is not fabricated.

Upgrade preserves data/ including repository encryption key and .env.local; restart all processes and launch a fresh scan with explicit engine selections. Old reports retain their original observations.
