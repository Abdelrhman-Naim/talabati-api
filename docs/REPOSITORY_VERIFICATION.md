# Repository release verification — 0.7.0

Date: 2026-11-08

- Full suite: npm test — 103 passed, 0 failed.
- TypeScript: npm run typecheck — passed.
- Production: npm run build — passed.
- Reader tests: exact GitHub repository validation, rejection of alternate hosts/credentials/ref URLs, immutable commit/tree/blob SHA verification, redirect and API-error rejection.
- Credential tests: authenticated encryption with owner/project/link AAD, no plaintext in serialized metadata/database rows, private key 0600 persistence across reopen, HTTPS/loopback credential origin guard.
- Lifecycle tests: cross-owner isolation, URL verification gate remains intact, repository scans without domain verification, legacy worker queue isolation, active-job guards beyond UI's 100-report limit, disconnect cancellation, timeout, truncated discovery/file limits/large-file/binary exclusions and pending counts.
- Static rules: safe secret summaries with file/line, public Supabase key exclusion, code-pattern indicators, HTML JavaScript, explicit reduced language coverage, RLS indicators.
- UI review: GitHub repository/branch/token guidance, active deep-analysis selector, immutable source details, file/line evidence and text repair prompt. Preview remains synthetic and mutation-disabled.
- Independent review: oversized-file ordering, unsupported-encoding handling, and HTML coverage cases were reproduced RED and corrected GREEN with regressions. No credential disclosure or cross-owner bypass found in focused review.

Live GitHub smoke read was attempted against public octocat/Hello-World but blocked by executor DNS: getaddrinfo EAI_AGAIN api.github.com. Live GitHub access and private credentials were NOT verified here. No user's repository was connected or modified. Deployment host must provide DNS/HTTPS egress to api.github.com and owner-authorized repository access.

Existing Chromium integration is outside this repository feature. Static repository analysis does not require Chromium. No repository programs/install scripts were executed. No dependency CVE database, dynamic authorization/RLS testing, Git history analysis, patch application or PR creation is claimed.
