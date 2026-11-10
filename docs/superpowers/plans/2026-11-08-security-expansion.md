# Security expansion design and execution plan

User goal: strengthen actual security coverage with transparent evidence. Existing scan has source patterns, npm OSV, and optional verified six-case API read matrix. Screenshot contains no executed API calls; existing reports must never be silently rewritten.

Design: add a bounded SQL tokenizer and statement analyzer for actual policy declarations, grants, RLS configuration and security-definer functions; extend TypeScript AST with explicit insecure JWT/CORS/hash/config calls; analyze Supabase verify_jwt configuration. Integrate with every repository file; show engine update and API setup guidance in security UI. All results include file/line, method, scope, fix and verification. No code execution or data-changing requests. Absence of a pattern is scoped to parsed input, never a certificate of security. Incomplete syntax cannot pass.

1. RED: tests with SQL comments/literals/dollar bodies and malformed input; permissive policies/grants/search_path; safe alternatives; AST insecure JWT/CORS/hash and safe examples. GREEN: implement independent advanced-security module and analyzer integration.
2. Update UI capability explanation/version guidance and documentation. Verify full test suite, typecheck, build.
3. One fresh independent final reviewer, regression-fix significant findings, package ZIP and replace existing deliverable.

Execution completed inline on feat/audit-beta. Added SQL/TOML masked lexical helpers, source checks and AST checks with 16 new regression cases. Existing tests exposed v10 cancellation regression and it was corrected before delivery. Independent reviewer: no Critical; Important cancellation, UPDATE open target selection and function-EXECUTE classification all reproduced RED→GREEN and fixed. Also corrected observation cap, simple true equivalents, quoted row_security setting and removed unused configuration argument. Final full suite 160/160; typecheck passed. No live deployment security test performed. Bounds and unimplemented SQL dialect features documented; no universal security claim.
