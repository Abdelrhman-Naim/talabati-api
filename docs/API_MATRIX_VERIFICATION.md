# Verification — 0.9.0

- npm test: 144 passed, 0 failed.
- npm run typecheck: passed.
- npm run build (Next.js webpack production): passed.
- git diff --check: passed.
- 17 API matrix regression cases cover encrypted tenant-isolated configuration, opt-in/proof/expiry, positive exposure, owner baseline and cross-user baseline failures, unexpected bodies/redirects, Storage empty-array ambiguity, same JWT subject, anonymous-key role validation, credentials in paths (including encoding), cancellation/abort, stale configurations, early GitHub failure and job/report integration.
- Route integration covers API settings metadata-only responses, cross-owner access, CSRF, authenticated result export and complete ledger count.
- Final independent review identified anonymous JWT role confusion, omitted early-failure/cancellation rows, and credential URLs. Each was reproduced with a failing regression test and fixed; full suite green afterward. Storage expected-outcome copy also corrected.

Injected transports were used to exercise all response branches; no requests were sent to the user's API/Supabase deployment. No claims of live RLS coverage, exhaustive vulnerabilities, production penetration testing or interactive visual QA. Browser preview and local curl could not connect to the local Next server in this execution environment despite its ready log; production compilation and route tests succeeded.

Operational scope: selected staging fixtures, two explicitly supplied test identities, read-only GETs. All broader checks remain explicitly limited/unexecuted. Existing reports are immutable evidence of their original engine; run a new scan after upgrade.
