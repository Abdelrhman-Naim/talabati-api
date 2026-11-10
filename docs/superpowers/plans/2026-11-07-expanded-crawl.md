# Expanded same-origin crawling

User explicitly asks to attempt all pages, not the five-page sample. Implement default full crawl and an explicit quick mode; retain Node/Next/SQLite and text-only Ollama.

- [x] Regression tests for >25 links and >5 pages, nested sitemap discovery, pagination queries/tracking dedup, exclusions and robots longest rule. Preserve existing quick-mode tests.
- [x] Crawl URL normalization, robots allow/disallow matching, XML sitemap/index parser, configuration (full defaults5000 pages/60min, quick5/60sec), hard maximum10000 pages/4h, bounded discovery inventory and sitemap documents. No external-origin crawl, arbitrary API probing, write requests or auth bypass.
- [x] Persist per-scan options additively; v5 queue isolated from old workers, claim old queued jobs safely. Crawl sequentially with deduplicated pending set, sitemap/robots HTTP discovery independent of renderer. Show exact exhaustion/limit/failure/skipped counts and preserve cancellation/deadlines. Check every loaded page for further links.
- [x] Mode/limit UI before starting; discovered/pending/skipped/failed/stop reason in activity and report. Keep old reports readable. Legacy MAX_SCAN_PAGES=5 and MAX_SCAN_DURATION_MS apply only to explicit quick mode, so retained .env.local does not silently restore five-page full scans.
- [x] Full tests/typecheck/build, independent review and regression fixes, documentation, replace source ZIP.

Limits: this attempts all discoverable public allowed same-origin pages, not a guarantee of every page existing on the server. Hidden/auth-required/hash-only routes and pages beyond explicit safety budgets are not claimed visited. Missing optional robots/sitemap404 is normal. Respect supported robots rules. External sitemap/API origins are not fetched. Bounded XML bodies inherit pinned transport and decompression limits.

Review focus: cancellation during discovery; URL-query crawl traps and secrets; wildcard/agent robots specificity; nested sitemap cycles/unsafe origins; redirect aliases; truthful pending counts when time/page/discovery limits reached. Sequential collection with bounded snapshots/log sizes; real Chromium remains subject to host availability.

## Verification and review
71 core tests passed before final packaging. Full fixture fetched38 pages, nested sitemap/orphan and pagination, excluded outside origin and robots paths. Verified cap7 leaves4 pending and partial status. Independent review found empty robots group boundary, redirects bypassing policy, and discovery cancellation not reaching transport. All fixed with regression tests RED→GREEN; native collect now checks policy per redirect, signal threaded through DNS/HTTP/redirects and browser resources, cancellation interrupts discovery. Replaced dynamic wildcard regex with literal segment matching; added Unicode/gzip coverage. CUA verified default-full radio, quick switch and summary; no live user-site crawl or live Chromium run claimed.
Ruling: full defaults5000 pages/60min rather than unbounded traversal, with hard caps10000/4h and bounded discovery; this costs potential undiscovered pages but exposes every limit and remaining count. Legacy five-page settings apply quick mode only. No known deferred code-review findings.
