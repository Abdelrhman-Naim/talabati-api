# GitHub repository analysis

User-authorized extension to existing Next.js/Node beta: bind one GitHub repository and branch per project, run real source analysis, show evidence inside platform with file/line/commit and repair prompts. Existing URL scans remain available.

Implementation choice: public repository URL or a fine-grained read-only token restricted to selected repository; no GitHub App provisioning prerequisite. Tokens encrypted with AES-256-GCM, owner/project/link identity as AAD, key persisted privately alongside SQLite (or env override). No token in browser responses, logs, prompts, or snapshots. A GitHub App/OAuth installation and PR write permissions would add deployment provisioning; source read-only binding delivers this request without those prerequisites. No automatic edits or PR creation in this release.

GitHub API fixed host only; reject user-controlled API endpoints/redirects. Resolve requested branch to immutable commit and tree; fetch bounded text blobs by SHA. Never clone, install dependencies, execute repository scripts, follow symlinks/submodules, or transmit source to Ollama automatically. Defaults: 1000 eligible files, 256KiB/file, 20MiB decoded content, 10min/scan; 2MiB JSON response transport cap. Exclusions and limits/truncated trees/fetch errors yield transparent partial reports. Cancellation aborts active reads.

Run static local rules for privileged secret patterns, public-secret configuration, risky eval/HTML sinks, dynamic SQL/process execution, TLS bypass, Supabase RLS and dependency reproducibility. Pattern-only findings labelled indicators requiring verification; no invented CVEs, full dataflow claims, runtime UX/SEO/geo, or active API authorization. Show successful rules and unavailable dependency-CVE/runtime tests. Retain no raw source or credential snippets in result JSON.

Persist binding and job snapshot additively. Owner checks/CSRF existing controls apply. Link cannot change during active scan; disconnect cancels repository jobs. New worker queue v7 and engine0.7 protect jobs from legacy workers. Reports distinguish repository from URL scope; old reports remain readable.
