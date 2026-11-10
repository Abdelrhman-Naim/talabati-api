# 0.12.0 baseline benchmark — Task 1

This measures the existing custom engine, not Ollama or new security tools. It is a baseline, not a security certification. See `../docs/DECISIONS.md` and `BASELINE.md` for boundaries and measured results.

## Run repository fixtures

Node 24+, Git, and the application's existing `npm ci` dependencies are required. No Docker or GitHub token is needed for the four local repository targets. Do not use a production process. The explicit benchmark flag is refused when `NODE_ENV=production`.

```bash
npm run test:benchmark
BENCHMARK_MODE=1 NODE_ENV=test npm run benchmark -- --target all --osv-live --output benchmark/runs/local.json
```

PowerShell:

```powershell
$env:BENCHMARK_MODE = '1'
$env:NODE_ENV = 'test'
npm run benchmark -- --target all --osv-live --output benchmark/runs/local.json
```

Omit `--osv-live` for an offline run; dependency quality will be unmeasured, never silently clean. The live attempt calls the real OSV service using the unchanged application adapter. Run a single target with `--target seeded`, `clean-marketing`, `clean-docs`, `clean-portal`, `juice-shop`, `nodegoat` or `dvwa`. The command does not install tools or start target containers. Docker probes require the expected named running container and loopback port binding, and record its image ID; an unrelated service on the port is not accepted as a Docker target. Outputs and generated fixtures are ignored by Git; `baseline.json` is the committed baseline exception by path.

The fixture generator creates a local-only seeded Git repository including a deleted, fake history credential and current-tree fixtures (secret, bundle, NEXT_PUBLIC misuse, unauthenticated route, IDOR-shaped route, SQL/shell/HTML sinks, RLS configuration and an old dependency). LocalReader reads the working tree, not history: missed cases remain visible as false negatives. All values are derived from public fake labels or invalid fake JWT signatures. Do not replace them with real credentials or add a Git remote.

The three synthetic negative fixtures cover static marketing, checksum/documentation code, and trusted static HTML in a portal. They intentionally include benign patterns to quantify current false positives. They are small scanner inputs; they are not installed, built, or executed as Next.js apps. Test fixtures exercise the scorer, local reader, production refusal, unchanged application ownership/SSRF checks, and local HTTP redirects.

## Docker targets (not run in the authoring environment)

Docker CLI and server were unavailable. No container results or version-specific ground truth were invented. The three Docker expected arrays are explicitly **pending**, not empty clean sets. Even if a target becomes reachable, this harness reports HTTP observations and duration but keeps its quality metrics `null` until a reviewed version-specific annotation is supplied in a later benchmark update. Do not present them as measured recall.

Run `npm run benchmark:docker` on your Docker-enabled test machine. The root Compose file pins registry images, binds only 127.0.0.1, and separates applications on internal networks. NodeGoat is built from official release v1.4 (published commit prefix 9e35cae) using a sourced digest-pinned Node base; its built output ID is recorded after build. No official prebuilt NodeGoat digest is invented. The script refuses a dirty source checkout and records the full resolved commit and image IDs in benchmark/runs. Run `npm run benchmark:docker -- --down` to remove the test stack. Initialize DVWA at http://127.0.0.1:3003/setup.php if needed. Runtime setup remains unvalidated here because Docker is absent. See [docker-pins.json](docker-pins.json) for pin sources and this deliberate NodeGoat exception.

## Interpret the numbers

`expected/*.json` for local fixtures is curated independently of scanner output and checked against the generator. `scoreRun` uses category + normalized location, matching each expected finding at most once. It returns TP, FN, FP, recall, precision, high/critical precision and per-category counts. The required unit example produces recall 0.5, precision 0.5 and one FP. `scoreRun` uses numeric zero for an empty denominator; the report's category summary converts unavailable denominators to `null`.

The committed `baseline.json` contains each target's expected and actual metadata, raw score, tool status, duration and reason; `aggregate` namespaces locations by target. Unmeasured dependency rows remain in the expected list, but are excluded from measured target/aggregate metrics; unknown category counters are null. Docker targets with pending annotation are excluded entirely. Never compare runs as equivalent unless targets, annotation versions, dependency availability and scan profile agree.

No baseline improvement is implemented here. Task 2 has not started.

## Frozen dev / holdout contract (Task 1 follow-up)

Expected manifests now contain `source`, `annotationStatus`, and `findings` with a frozen `split`. The local authority is [PLANTED-ISSUES.md](PLANTED-ISSUES.md), authored from planted code and benign contexts; external annotations must come from the target's official documentation, never a detector's current output. Pending external annotations remain pending, not clean.

The default benchmark runs **dev only** and omits holdout source files from the generated working tree. `--final` includes dev + holdout and is reserved for final measurement. **Do not tune, add, disable, threshold, or suppress any detection rule against holdout cases at any point.** A failing holdout remains a reported miss. The split is prospective: every original case was already seen in Task 1, so it cannot be represented as a previously blind validation set. Fixture/schema/normalizer safety tests are permitted; they must not become detector tuning.

`--osv-offline` feeds a small, clearly labeled official-advisory-derived fixture through the real existing OSV parser and dependency engine. It tests dependency integration without claiming a live database scan. Unknown fixture requests fail closed. `--osv-live` uses the real service and records underlying error kind/code/message on stderr and in the JSON report. A required unmeasured dependency step exits with code 2. Unmeasured counts/quality are null, not a clean zero. The original historical baseline did not retain the underlying OSV exception; no exact historical network cause is invented.

Docker setup now uses the root `docker-compose.benchmark.yml` and `npm run benchmark:docker` (`-- --down` stops it). Registry images have sourced digest pins; NodeGoat has no official prebuilt image in its deployment instructions, so it is built from the recorded official source revision with a digest-pinned Node 12 base. Its resulting image ID is recorded at build time, never fabricated. See `docker-pins.json` for provenance. Runtime containers and old registry digest availability remain unvalidated here because Docker is absent. This replaces the earlier variable/template Compose instructions above.

## Task 2.5 negative holdout and precision measurement

`clean-holdout-cache`, `clean-holdout-frame` and `clean-holdout-cms` are new clean negative targets. Their input files and sourced empty expectations are sealed separately in `task25-holdout.lock.json`; default development measurements exclude them. An explicit target request without `--final` is refused before the fixture is loaded. Never tune a detection rule or suppression from these holdout results. The final report separates their false positives from clean-marketing/clean-docs/clean-portal. See `TASK25-REPORT.md` for before/after measurements, real-path redaction proof, independently reviewed edge cases and the unchanged recall.

The before comparison was actually run from an isolated checkout of Task 2 (`a221077`) with this same updated benchmark harness and sealed target data, while production src/packages in that checkout remained unchanged. The after run used the frozen Task 2.5 implementation (`d680f66`). Both final runs use `--osv-offline --final` and record identical source snapshots. Rule hashes are in `task25-rule-freeze.json`. New holdout data was not used for rule tuning; seven independent development-review fixes were completed before the final measurement/seal.
