# Audit Beta Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans task-by-task.

**Goal:** Deliver a runnable Next.js/Node.js beta with private projects, verified passive web scans, transparent findings, prompt export and the supplied Ollama adapter.

**Architecture:** Next.js App Router control plane plus a separate durable Node worker. SQLite is a single-host development store; job leases survive restarts. Bounded pinned-IP HTTP transport collects passive HTML evidence without executing target scripts. Native Ollama adapter is server-only.

**Tech Stack:** Node 24, Next.js 16, React 19, TypeScript, SQLite, Cheerio, Zod, Node test runner.

**Spec:** ../specs/2026-11-06-audit-design.md

## Global Constraints
- No subscriptions; no claim that unperformed tests passed.
- AI uses https://ollama-qa.apps.taqat.academy and qwen2.5:1.5b, stream false, 90-second timeout, one local generation at a time.
- Require verified origin and user authorization before live scan. Never probe discovered third-party services.
- Redact secrets before storage, AI, logs and exports. Protect all resources by owner ID.
- Keep repo patching, active API attacks, browser runtime, Lighthouse and axe explicitly unavailable in this first working milestone; do not replace them with mock results.

## Review Focus
1. SSRF via IPv6, alternate numeric hosts, mixed DNS answers and redirects must be denied.
2. Cross-user IDs and mutation requests from a different Origin must not grant access.
3. Secret evidence and URL credentials must never reach persisted reports or AI.
4. An empty, truncated or malformed AI response must not appear as verified remediation.
5. Worker cancellation/restart and failed collection must not mark missing issues as fixed.

### Task 1: Safety and evidence core
Files: src/lib/network.ts, src/lib/audit.ts, src/lib/types.ts; tests/network.test.ts, tests/audit.test.ts.
Interfaces: validateTarget(input:string):URL; assertPublicAddress(ip:string):void; collect(url:string):Promise<HttpPage>; analyze(page:HttpPage):AuditOutput.
- [x] Write tests for blocked addresses/credentials, SEO/accessibility findings, Supabase public key handling, privileged key redaction and API references.
- [x] Run npm test and observe missing-module failures before implementation.
- [x] Implement pinned DNS transport, redirect policy, body/time caps and deterministic evidence-based rules.
- [x] Run the suite; commit tested core.

### Task 2: Durable identity, projects and jobs
Files: src/lib/db.ts, src/lib/auth.ts, src/lib/jobs.ts, src/worker.ts; tests/store.test.ts.
Interfaces: Store(file), createUser, sessionUser, createProject, ownedProject, queueScan, claimJob, finishScan, cancelScan; runJob(store, job, collectFn).
- [x] Write temporary-SQLite tests for user isolation, password verification, expired sessions, leases, cancellation and partial failure.
- [x] Run tests red; implement schema, scrypt, hashed random session tokens, DNS/file ownership verification and separate worker.
- [x] Run tests green; commit.

### Task 3: Ollama and remediation prompts
Files: src/lib/ai.ts, src/lib/prompts.ts; tests/ai.test.ts.
Interfaces: remediationPrompt(finding):string; parseOllamaResponse(value):string; enrichFinding(finding):Promise<string>.
- [x] Write tests for missing/length-truncated content, untrusted instructions and secret redaction.
- [x] Run red; implement short task prompts, bounded response, timeout and cross-process SQLite lock for this platform; document cross-project coordination remains external.
- [x] Run green; commit.

### Task 4: Protected HTTP API and developer interface
Files: src/app/api/[...path]/route.ts, src/app/page.tsx, src/app/globals.css, src/components/workspace.tsx.
Interfaces: auth endpoints, project CRUD/verify, scan create/get/cancel/export, finding prompt, AI explain/test; all through authenticated same-origin JSON.
- [x] Add HTTP integration smoke script for auth, hostile Origin, ownership, unverified scan rejection, demo and export.
- [x] Implement Arabic RTL responsive dashboard, project wizard, findings/details, coverage, service inventory, comparison and honest integrations/settings.
- [x] Run unit tests, typecheck, production build and HTTP smoke; review diff independently.
- [x] Bundle source, .env.example, Dockerfile/compose and README_AR; exclude data, tokens and dependencies.

## Milestone boundaries and next work
The original product includes later browser engines, repository analysis and patch/PR workflows. This first milestone establishes a real passive collection loop; later engines must fit its adapters and coverage model. SQLite is a deliberate single-host beta default; PostgreSQL/Redis and distributed tenant quotas are later deployment tasks, not represented as implemented.

## Verification record
- 24 tests passed, including real Route Handlers with NextRequest and temporary SQLite.
- Native HTTP smoke remains unverified in this executor: preview port is accessible only from the cloud browser. The route-handler integration is the API verification performed here.
- TypeScript and production Next.js build passed.
- Browser QA: login view, read-only demo dashboard, finding detail and in-dialog error state verified.
- Source packaged for Node hosting; no deployment or live Ollama call performed.
