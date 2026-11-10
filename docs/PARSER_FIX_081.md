# Parser reliability fix — 0.8.1

Reported symptom: public-secret checks unavailable; API/RLS checks out of scope. These are separate conditions.

Reproduced local defects: .mts/.cts generic code parsed as TSX; application/ld+json parsed as JavaScript; syntax failure suppressing a public assignment elsewhere. Fixes preserve formats, ignore non-JavaScript MIME scripts, honor script language and retain positive recovery-AST results. Negative fallback is conservative: possible public names or lexical errors cannot produce a clean pass. Regex text cannot become a positive assignment. Numeric TS diagnostics show code/line/column without source values.

Independent review found typed/object assignment misses, discarded mixed-script positives and regex-body false positives in the initial fallback. All reproduced in regressions and fixed. Valid JSX apostrophes remain supported.

Verification: npm test 127 passed; npm run typecheck passed; npm run build passed. No user repository inspected; these reproduced cases are not proof of the exact six file failures in the screenshot. A fresh scan exposes locations for remaining real errors.

No active API authorization or Supabase RLS/Storage test engine added. That capability is still unimplemented, rather than a GitHub connection problem. A future implementation needs a staging target, test accounts/resources and explicit expected-access cases; repository reading alone cannot establish live authorization behavior. No credentials or production requests used for this fix.
