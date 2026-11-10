# Unified findings — Task 2

`normalize(rawTools, suppressions)` returns canonical validated findings and per-tool status. Invalid findings and failed/partial tools produce `incomplete`, never a successful empty scan. Findings already produced by a partially failed tool remain available.

- `schema.ts`: canonical schema and input/suppression types.
- `redact.ts`: explicit secret masking (first/last four only for values longer than eight) and recognized-format text redaction. Explicit secret hints are removed from metadata and tool-status keys too. Unrecognizable arbitrary text cannot be guaranteed to be a credential without a supplied hint; existing detectors produce redacted evidence already.
- `dedupe.ts`: SHA-256 fingerprint over category, rule, normalized location and redacted evidence; one finding per fingerprint. Rules and severities are never lowered. If two observations of one fingerprint disagree on severity, the higher severity survives.
- `confidence.ts`: deterministic per-tool/per-rule base table. Custom regex evidence starts lower; contextual custom evidence adds 0.1. Agreement by independently named tools adds 0.2, capped at 1. Repetition from the same tool does not boost confidence. This is a calibration heuristic, not a probability or exploitability guarantee.
- `suppress.ts`: active fingerprints are marked suppressed and retained; expired or blank-reason entries do not suppress.

`src/lib/findings-adapter.ts` is called at progress and final persistence in both URL and repository jobs. It emits `ScanResult.normalizedFindings` and `findingNormalization`, and derives a legacy-compatible findings view from normalized survivors so the existing UI keeps rule IDs, categories, severity and string confidence. Numeric canonical confidence lives in `normalizedFindings`; a future UI task can display it. API matrix cases include their stable case identity in canonical location, because different principals on one resource must not collapse into one finding. File locations remain file:line. No detector, score weights or benchmark matching rule is changed.

Suppression is accepted by the adapter API; adding account-managed suppression controls is outside Task 2. Canonical fingerprints intentionally depend on redacted evidence as specified, so a materially changed evidence string produces a different fingerprint.
