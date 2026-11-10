# Planted issues and benign contexts

Ground truth authored from fixture intent and source, not current scanner output. Frozen dev/holdout allocation established before Task 2. All cases were already observed during Task 1; this is a prospective holdout, not a historically blind test.

## seeded

| ID | Category | Planted location | Split |
| --- | --- | --- | --- |
| stripe-file | secret | src/stripe.ts:1 | dev |
| openai-file | secret | src/openai.ts:1 | holdout |
| aws-pair | secret | src/aws.ts:1 | dev |
| supabase-service-role | secret | src/supabase.ts:1 | dev |
| frontend-bundle-secret | secret | public/_next/static/chunks/bundle.js:1 | holdout |
| next-public-misuse | secret | src/public-config.ts:1 | dev |
| deleted-history-secret | secret | src/deleted-secret.ts:1 | holdout |
| eval-input | code | src/eval.ts:1 | dev |
| sql-concat | code | src/query.ts:1 | dev |
| shell-input | code | src/shell.ts:1 | holdout |
| html-input | code | app/unsafe/page.tsx:1 | dev |
| tls-disabled | config | src/tls.ts:1 | dev |
| missing-rls | config | supabase/migrations/001_table.sql:1 | dev |
| public-read-policy | config | supabase/migrations/002_read.sql:1 | dev |
| public-write-policy | config | supabase/migrations/003_write.sql:1 | holdout |
| edge-jwt-disabled | config | supabase/config.toml:2 | holdout |
| no-auth-route | api | app/api/private/route.ts:1 | dev |
| idor-route | api | app/api/records/[id]/route.ts:1 | holdout |
| jwt-none | api | src/jwt.ts:1 | dev |
| cors-reflection | api | src/cors.ts:1 | dev |
| lodash-known-advisory | dependency | package-lock.json:8 | dev |

The dependency case intentionally pins lodash 4.17.20, affected by the official advisory [GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm). Other cases are deliberate unsafe code/configuration patterns planted in fixtures.ts. The deleted credential exists in Git history only.

## clean-marketing

Static authored Next.js-shaped page; no planted issues.

## clean-docs

MD5 is used solely for a non-security checksum, not password/security protection; no planted issue.

## clean-portal

dangerouslySetInnerHTML receives only source-authored constant HTML, not untrusted input; no planted issue.

## clean-holdout-cache

New Task 2.5 holdout negative: SHA1 is solely an HTTP entity-tag/cache validator for public content, not authentication, passwords or signatures. No planted security issue.

## clean-holdout-frame

New Task 2.5 holdout negative: source-authored immutable release text is assembled into a constant native DOM fragment. No untrusted interpolation. No planted security issue.

## clean-holdout-cms

New Task 2.5 holdout negative: CMS preview HTML passes through the imported isomorphic DOMPurify sanitizer with default options before assignment. No planted security issue.

These three targets are evaluated only in final measurements after rule-code freeze. Their expected output was authored from these benign intentions, never copied from the detector. Any false positives will be reported without rule tuning on this set.
