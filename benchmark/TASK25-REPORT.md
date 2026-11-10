# Task 2.5 — precision of existing rules

Completed Task 2.5 only; Task 3 has not started. Package/engine version stays **0.12.0**. Only `repo.weak-hash` and `repo.html-sink` detection logic changed. Scoring and all other detection rules were preserved. Redaction presentation and scan-stage confidentiality were verified as requested.

## Measured before/after on the same extended set

Before: real Task 2 scanner checkout `a221077`. After: frozen implementation `d680f66`. Both used the same final benchmark harness, offline OSV fixture and exactly matching repository snapshot hashes. The extended set includes the original seeded/development negatives plus the three newly sealed negative holdouts.

| Category | Recall before | Recall after | Precision before | Precision after | TP before → after | FP before → after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| secret | 71.43% | 71.43% | 100.00% | 100.00% | 5 → 5 | 0 → 0 |
| api | 50.00% | 50.00% | 100.00% | 100.00% | 2 → 2 | 0 → 0 |
| code | 100.00% | 100.00% | 44.44% | 100.00% | 4 → 4 | 5 → 0 |
| dependency | 100.00% | 100.00% | 100.00% | 100.00% | 1 → 1 | 0 → 0 |
| config | 80.00% | 80.00% | 100.00% | 100.00% | 4 → 4 | 0 → 0 |

Combined-set recall: **76.19% → 76.19%**, with all 16 true positives retained. Precision: **76.19% → 100.00%**. No measured category recall dropped.

For direct comparison with the previously published Task 2 set (without the three new negatives), code precision is **66.67% → 100%**, and its recall stays **100% → 100%**. The 44.44% starting value in the extended-set table includes the old scanner’s three additional false positives on the new holdout set.

Dependencies are the explicitly labeled offline official-advisory fixture profile in both runs. These 100% figures are parser/integration measurements for the planted dependency case, not successful live OSV coverage. Docker targets remain not_run and have no scores.

## Established development negatives

| Target | False positives before | False positives after | Rules before |
| --- | ---: | ---: | --- |
| clean-marketing | 0 | 0 | None |
| clean-docs | 1 | 0 | repo.weak-hash @ src/checksum.ts:1 |
| clean-portal | 1 | 0 | repo.html-sink @ app/help/page.tsx:2 |

## NEW holdout negatives — reported separately

| Target | False positives before | False positives after | Rules before |
| --- | ---: | ---: | --- |
| clean-holdout-cache | 1 | 0 | repo.weak-hash @ src/http-entity-tag.ts:3 |
| clean-holdout-frame | 1 | 0 | repo.html-sink @ src/release-frame.ts:4 |
| clean-holdout-cms | 1 | 0 | repo.html-sink @ src/cms-preview.ts:4 |

New negative target expectations come from their authored benign-intent list in PLANTED-ISSUES.md, not detector output. The initial rule hash was recorded before authoring these targets. Independent development review then found seven issues; these were fixed using standalone dev examples, with a final code seal before any new holdout measurement. The reviewer did not open the new holdout inputs. Both old/new final runs occurred after that seal. No rule or holdout input changed after final measurement. Default dev runs exclude these targets, and explicit dev requests reject them before reading their source.

## General rule logic

### repo.weak-hash

A literal MD5/SHA1 createHash/createHmac use produces medium only when bounded local AST context establishes a security-named input, a security output/use, a named authentication function or secret comparison. Local const input aliases and separate hash-handle/digest bindings are followed with depth/cycle limits. Unrelated password/session arguments in a surrounding cache or logging call do not establish security use. Comments and filenames never participate. Checksum/cache/ETag-only use produces no finding. This is local context analysis, not whole-program taint tracking.

### repo.html-sink

Compile-time literal/const string expressions are accepted; mutable, shadowed, escaped or unknown values remain dynamic. Object effective __html properties are checked in order; unknown spreads/computed keys and accessors invalidate earlier constant assumptions. Imported/required dompurify, isomorphic-dompurify and sanitize-html default calls are recognized with binding provenance; a locally declared require or fake/mutated sanitizer object is not trusted. Only the complete sanitized value is accepted, not a sanitized fragment interpolated into an arbitrary new HTML context. Recognized calls currently use one input/default-options argument; unknown configuration is conservatively reported. JSX, native innerHTML/outerHTML (including static element access) and insertAdjacentHTML are covered. Unsupported non-JS HTML classification is unavailable rather than a guessed clean or vulnerable result.

The old AST test titled weak password hash previously only instantiated MD5 without a password input. Its source was updated to actually hash a password, preserving all original fail assertions and JWT/CORS checks under the new security-context contract.

## Required real-path and confidentiality evidence

1. **Production wiring:** src/lib/repository/job.ts normalizes progress and final results; src/lib/jobs.ts does the same for URL scans. src/worker.ts uses the normalized failure fallback. The real scan test asserts canonical repo.secret findings, findingNormalization.version=1, non-empty scan activity and real progress persistence.
2. **First4 + last4:** packages/findings/redact.ts masks complete recognized or explicitly supplied credential values with their first/last four characters, with short values fully hidden. Example output: `sk_l********cdef`. Redaction is tested for idempotence and through normalize. Private-key blocks and database URIs remain fully redacted; unknown opaque generic credential values remain fully redacted. Secret detector count-only evidence remains count-only.
3. **No full secret at tested boundaries:** tests/real-secret-boundary.test.ts runs the actual repository job with fake provider-format credentials, actual file-backed SQLite, captured console/stdout/stderr, non-empty progress/event logs, and the authenticated application Next GET /api/state handler returning NextResponse. It checks serialized DB rows and physical SQLite/WAL bytes, API response text, and captured logs for every complete fake value. The test failed first because a secret in a filename could enter the raw stage string; both worker stage writes now redact that string. No API response or database operation in this test is mocked.

## Tests first, review and final checks

- Initial targeted rule/redaction run: 7 tests, 6 failed / 1 passed before implementation (security hash/HMAC coverage; benign hashes; dynamic element access; constant HTML; sanitizer recognition; partial token display).
- Additional context-alias and unsupported-language regressions were written and observed failing before their fixes.
- Independent review found seven Important issues using dev examples only; dedicated regressions first failed 7 tests, then passed after fixes. No Critical finding or deferred minor remains.
- Final application/normalizer suite: **218/218 passed**. Benchmark suite: **21/21 passed**. Typecheck and production Next.js build passed.
- Original expected locks, new negative holdout lock and reviewed rule-code seal verified. Source snapshot hashes match between old/new runs. benchmark/score.ts, scoring weights and version files are unchanged.

## Durations and skipped targets

Durations are scanner milliseconds, including normalization, excluding fixture generation and container startup.

| Target | Before ms | After ms | Status after |
| --- | ---: | ---: | --- |
| seeded | 269 | 533 | completed |
| clean-marketing | 13 | 36 | completed |
| clean-docs | 18 | 40 | completed |
| clean-portal | 17 | 37 | completed |
| clean-holdout-cache | 20 | 39 | completed |
| clean-holdout-frame | 18 | 36 | completed |
| clean-holdout-cms | 17 | 35 | completed |
| juice-shop | Not run | Not run | not_run |
| nodegoat | Not run | Not run | not_run |
| dvwa | Not run | Not run | not_run |

Juice Shop, NodeGoat and DVWA could not run because Docker is unavailable. Their version-specific annotations remain pending, and no results were invented. The new context analysis takes additional local work; timing observations are provided without claiming a performance gain.

Raw observations: [before](task25-before-final-offline.json), [after](task25-after-final-offline.json), [development-only run](task25-dev-offline.json). Seals: [rule code](task25-rule-freeze.json), [new holdout inputs](task25-holdout.lock.json). Implementation and scope decisions are in [DECISIONS.md](../docs/DECISIONS.md).
