# Rendered Link Audit and Worker Integrity Plan

**Goal:** Make link scans analyze real rendered JavaScript content and eliminate successful-looking empty reports or old-worker output.

**Architecture:** Native Playwright/Chromium renderer with all HTTP requests fulfilled through DNS-pinned Node transport. Dead-end browser proxy and blocked WebSockets/service workers/non-proxied WebRTC prevent direct fallback. Only public GET/HEAD resources, bounded origins/navigation/request counts/body/time; privileged credentials and write requests blocked. axe-core and lab browser performance observations add evidence. Plain HTTP remains an explicit fallback when Chromium is unavailable.

**Spec:** Existing audit design plus user's screenshot showing pages collected but 0/0 checks. Root hypothesis: an old worker produces legacy result JSON consumed by the upgraded UI; original collector also cannot render SPAs.

## Tasks
- [x] Regression tests: missing check records with pages are invalid, v3 queues invisible to old workers, periodic job leases and process lock, versioned worker heartbeat.
- [x] Implement protocol-isolated queue statuses, startup orchestration, scan integrity diagnostics and legacy recovery messaging. Preserve existing SQLite and .env.local.
- [x] Test safe resource transport: binary/gzip decoding limits, pinned DNS, redirects and method/header policy. Existing collect behavior preserved.
- [x] Browser collector: render HTML and scripts, observe GET API/network metadata and failures, console errors, layout overflow, navigation timing/LCP/CLS; axe outcomes. Never store raw cookies/keys/DOM screenshots.
- [ ] Runtime verification blocked by sandbox socket EPERM. Fixture implemented, not passed: SPA renders through JS and a versioned script, external API read, blocked POST/private resource; results persisted with scores, axe and real browser measurements. No live third-party scan needed.
- [x] Integrate checks/coverage/service provenance into reports and show missing-browser/worker causes clearly instead of 0/0 cards. Backwards compatible old reports require re-scan.
- [x] Tests, production build, independent review, upgrade guide, source ZIP update.

## Decisions
- GET requests observed while loading the authorized application are normal page reads; discovered endpoints are not separately fuzzed or attacked. POST/PUT/PATCH/DELETE, popups/downloads, WebSockets and privileged API credentials are blocked.
- No claim of Lighthouse or field INP. Browser metrics are bounded laboratory observations with viewport/window recorded.
- Chromium may be preinstalled or installed via npm run browser:install. If missing, HTTP fallback is explicit and still produces deterministic checks; it never pretends browser tests ran.
- dev starts one versioned worker automatically. Standalone worker stays available for production/compose. New internal queue statuses prevent a still-running v0.1/v0.2 worker from consuming new jobs.
- Verify the product browser engine with an offline synthetic website; CUA remains the path for UI QA. No runtime credentials required.

## Verification and review
47 core tests passed; typecheck and production build passed. Chromium integration was executed and failed at launch because this executor denies socket(). UI demo and /api/health verified through CUA; health reports explicit HTTP fallback reason. Independent review found unbounded browser evaluation and original-HTML secret removal; failing regression tests added, both fixed and green. Docker image not built.
