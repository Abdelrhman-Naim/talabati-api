# Task 2 — verified normalizer and comparison

Scope: six Task 1 follow-ups, then Task 2 only. Application version remains **0.12.0**. Task 3 has not started.

## Changes

Canonical schema, redaction, stable context fingerprint, deduplication, numeric confidence, retained suppressions and explicit incomplete tool status are implemented in packages/findings. Both workers normalize progress and final results before persistence; the existing UI view preserves rule IDs, category, severity and its legacy string confidence. API matrix principals remain separate canonical cases. Failure fallback is normalized as incomplete.

No detector or scoring implementation was modified. Expected annotation IDs, categories, severities, locations and split allocation remained frozen. Original baseline findings/timings were preserved; unmeasured dependency counters were corrected to null for presentation.

## Full measured category comparison

Final run uses offline OSV fixtures. The original baseline used a real OSV attempt that could not complete, so dependency quality is not a like-for-like live comparison. All other category metrics compare the same full seeded/negative set.

| Category | Baseline recall | Task 2 recall | Baseline precision | Task 2 precision | Change | FP before → after |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| secret | 71.43% | 71.43% | 100.00% | 100.00% | 0 percentage points for recall and precision | 0 → 0 |
| api | 50.00% | 50.00% | 100.00% | 100.00% | 0 percentage points for recall and precision | 0 → 0 |
| code | 100.00% | 100.00% | 66.67% | 66.67% | 0 percentage points for recall and precision | 2 → 2 |
| dependency | Unmeasured | 100.00% | Unmeasured | 100.00% | Not comparable: old live unavailable; new offline fixture | Unmeasured → 0 |
| config | 80.00% | 80.00% | 100.00% | 100.00% | 0 percentage points for recall and precision | 0 → 0 |

The same-profile **offline dev** reference was recorded before Task 2; all five categories have exactly the same TP/FN/FP/recall/precision after normalization. In particular dependency remains 1/1 detected with zero FP in that fixture, not a live-database claim.

## Final holdout reporting

The frozen holdout contains seven planted cases: five detected, two missed; recall 71.43%, precision 100%, zero FP. The remaining misses are `deleted-history-secret` and `idor-route`. No detector was tuned from this result. `task2-final-offline.json` contains separate dev/holdout scores. These are prospectively held-out cases; they were already observed in original Task 1 and are not presented as historically blind.

## Execution and durations

| Target | Status | Task 2 duration | Reason |
| --- | --- | ---: | --- |
| seeded | completed | 250 ms | Executed current repository scanner + normalizer |
| clean-marketing | completed | 14 ms | Executed current repository scanner + normalizer |
| clean-docs | completed | 22 ms | Executed current repository scanner + normalizer |
| clean-portal | completed | 19 ms | Executed current repository scanner + normalizer |
| juice-shop | not_run | Not run | Docker binary/server or named running loopback-bound container unavailable; target was not scanned |
| nodegoat | not_run | Not run | Docker binary/server or named running loopback-bound container unavailable; target was not scanned |
| dvwa | not_run | Not run | Docker binary/server or named running loopback-bound container unavailable; target was not scanned |

Scanner durations exclude fixture setup/container build. The different OSV modes make timing comparisons with the original live-attempt baseline unsuitable for performance claims. Docker targets and their version-specific expected annotations remain pending. No container was run here.

## Verification

- 200 application/normalizer tests passed; 20 benchmark tests passed.
- Typecheck passed and production Next.js build passed.
- Independent review found three Important issues; each was reproduced RED then fixed: batch-secret leakage across findings, inaccurate successful custom status on failed runtime/API collection, and outer-worker failure bypassing normalization.
- Progress and completion persistence are both asserted against real Store snapshots; removing progress normalization caused the regression test to fail, then restoring it passed.
- No detection rules were changed or tuned; benchmark/score.ts is unchanged.
- Expected provenance and split lock hashes verified unchanged at final measurement.
- Real live OSV follow-up failed with DNS EAI_AGAIN api.osv.dev; diagnostic captured on stderr and in dependency-live-attempt.json.
- npm run benchmark:docker exited 2 because Docker is unavailable; no Docker execution or results fabricated.

## Boundaries and rulings

- The historical holdout is prospective only; default dev runs exclude its source files and final measurement reports misses without tuning. Treating it as a previously blind independent dataset would overstate validation.
- Offline OSV is a labeled official-advisory-derived parser/integration fixture, never a substitute for successful live vulnerability intelligence. Original unmeasured counts are null, not a clean zero.
- NodeGoat follows the official source-build route with a published release revision and digest-pinned base; it has no fabricated prebuilt image digest. The full source SHA and resulting local image ID are recorded on the Docker machine. Registry digest availability/runtime behavior are unvalidated here.
- API matrix case identity is part of canonical location to preserve distinct principals; legacy rule IDs and severity are unchanged.
- Canonical numeric confidence is separate from the current UI string labels. Account-managed suppression UI and later scan-service work are outside Task 2.

Sources and run details: [baseline](BASELINE.md), [frozen raw baseline](baseline.json), [final observations](task2-final-offline.json), [before dev reference](reference-dev-offline.json), [after dev observations](task2-dev-offline.json), [decisions](../docs/DECISIONS.md), [Docker pin provenance](docker-pins.json).
