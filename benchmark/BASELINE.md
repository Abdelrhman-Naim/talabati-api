# Measured 0.12.0 baseline — Task 1

Run timestamp: 2026-11-09T15:34:51.697Z. Scanner source base: `b2fcb2f`. This is a **partial baseline**, not a statement that all targets or checks passed.

## Measured category results

| Category | Expected measured | True positives | False negatives | False positives | Recall | Precision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| secret | 7 | 5 | 2 | 0 | 71.43% | 100.00% |
| api | 4 | 2 | 2 | 0 | 50.00% | 100.00% |
| code | 4 | 4 | 0 | 2 | 100.00% | 66.67% |
| dependency | 1 (unmeasured) | — | — | — | Unmeasured | Unmeasured |
| config | 5 | 4 | 1 | 0 | 80.00% | 100.00% |

Measured aggregate: 15/20 expected cases detected; recall **75.00%**, precision **88.24%**; 2 false positives. High/critical precision: **100.00%**. These are small synthetic-fixture metrics, not a population estimate.

The dependency fixture has **one expected vulnerability, unmeasured** because the real OSV request could not complete. It is excluded from the measured aggregate and retained as unmatched in the raw seeded-target score. The code-category precision includes both benign-context false positives from the negative set.

## Targets and durations

| Target | Status | Scanner duration | False positives | Reason |
| --- | --- | ---: | ---: | --- |
| seeded | partial | 289 ms | 0 | OSV query did not complete; dependency quality unmeasured |
| clean-marketing | completed | 23 ms | 0 | Executed local repository scan |
| clean-docs | completed | 21 ms | 1 | Executed local repository scan |
| clean-portal | completed | 28 ms | 1 | Executed local repository scan |
| juice-shop | not_run | Not run | Unmeasured | Docker binary/server or named running loopback-bound container unavailable; target was not scanned |
| nodegoat | not_run | Not run | Unmeasured | Docker binary/server or named running loopback-bound container unavailable; target was not scanned |
| dvwa | not_run | Not run | Unmeasured | Docker binary/server or named running loopback-bound container unavailable; target was not scanned |

The seeded source includes 21 expected cases: 20 measured cases plus the unmeasured dependency case. The five measured misses are the AWS pair, deleted-history credential, unauthenticated route, IDOR-shaped route and missing RLS enablement. They remain expected failures, not suppressed findings.

Clean-negative false positives: non-security MD5 checksum (clean-docs) and trusted static HTML (clean-portal). Clean-marketing produced none. No clean fixture was installed or executed.

Docker CLI/server was unavailable: Juice Shop, NodeGoat and DVWA URL targets did not run. Their source-repository target scans and version-specific ground-truth annotation also remain unrun/pending. Their expected JSON arrays are explicitly pending, not clean negative sets. The supplied Compose setup has not been executed here. The future URL profile is HTTP-only (root and up to three scripts), not a full crawler/browser run.

Durations exclude fixture generation, dependency installation and Docker startup. Unattempted targets have null duration. No fabricated result or mock OSV response is included. See [README.md](README.md), [targets/README.md](targets/README.md), [baseline.json](baseline.json) and [decisions](../docs/DECISIONS.md) for rerun instructions and boundaries.

## Validation

- Application suite: 185/185 tests passed.
- Benchmark suite: 15/15 tests passed.
- TypeScript typecheck passed.
- Production Next.js build passed.
- No production `src/` files were changed.
- Independent review found no Critical/Important blocker; the reported documentation reference was completed and Docker target identity checking was added.

Task 2 has not started.

## Every unmatched expected case in the original baseline

The dependency row is unmeasured, not a confirmed detector false negative. Reasons refer to the frozen 0.12.0 implementation and collection boundary; no detection rule has been tuned.

| Expected ID | Category | Reason |
| --- | --- | --- |
| aws-pair | secret | The 0.12.0 regex inventory has no AWS access-key/secret-key pair rule. |
| deleted-history-secret | secret | LocalReader/current GitHubReader scan the current tree, not deleted Git-history blobs. |
| missing-rls | config | The existing RLS rule looks for explicit disabling or permissive policies; it does not establish missing ENABLE ROW LEVEL SECURITY for a created table. |
| no-auth-route | api | The current static rules do not implement route-handler authentication coverage. |
| idor-route | api | The current static rules do not implement object ownership/data-flow authorization checks. |
| lodash-known-advisory | dependency | Unmeasured: real OSV request failed before an advisory response. Original baseline did not retain the underlying exception; an exact historical cause cannot be reconstructed. New runs record it. |

## Every clean-negative false positive

| Target | Rule ID | File | Line | Benign context |
| --- | --- | --- | ---: | --- |
| clean-docs | repo.weak-hash | src/checksum.ts | 1 | Non-security checksum |
| clean-portal | repo.html-sink | app/help/page.tsx | 2 | Source-authored constant HTML |

Historical baseline presentation was corrected in this follow-up: unmeasured dependency counts are null and the seeded target totals exclude the unqueried case. Original detector observations, timings and measured category/aggregate results were not changed.
