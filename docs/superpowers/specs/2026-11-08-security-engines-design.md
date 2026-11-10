# Security engines for repository scans

Authorized improvement: replace repository placeholders where actual engines can operate. Implement local TypeScript AST analysis for JS/TS and embedded HTML scripts, npm pinned dependency extraction and live OSV advisory checks, and an explicitly selected verified-site passive HTTP security check. Never execute repository code, claim active authorization/RLS tests, or convert unavailable rules to passes without evidence.

OSV receives only names/versions after per-scan explicit selection; no source, credential, resolved URLs or repo identity. Parse npm package-lock v1/2/3, cap 2000 unique versions, batch queries, bounded advisory detail retrieval. Query failures/pagination/limits remain partial/unexecuted. Unknown severity must not be invented from absent CVSS. Lockfiles up to 4MiB, other source files 256KiB; response cap8MiB, total20MiB. Preserve immutable commit/blob verification.

AST checks actual syntax nodes instead of comment/string regex for supported JS formats. Preserve honest unsupported-language checks. JSON is parsed and configuration formats clearly scoped. Runtime option reads only verified same-origin project URL with public pinned transport, rechecks authorization lease, aborts on cancellation. It reports real response security checks and separately marks active API/RLS tests unexecuted.

UI exposes engine/configuration/collection reasons, dependency summary/advisories and runtime setup options. Preserve old records, use queuev8/worker0.8 for new jobs. No auto PRs, dependency installation, key validation, data-changing requests or automatic third-party source upload.
