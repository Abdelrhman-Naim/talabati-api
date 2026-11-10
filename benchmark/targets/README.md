# Benchmark targets

| Target | Input | Expected annotation | Current execution |
| --- | --- | --- | --- |
| seeded | Local-only generated Next.js-shaped Git repository, 21 planted issues | `../expected/seeded.json` | Current-tree repository job ran; history unsupported; OSV incomplete |
| clean-marketing | Synthetic static Next.js-shaped source | Empty, curated clean | Ran |
| clean-docs | Synthetic Next.js-shaped source with non-security checksum | Empty, curated clean | Ran |
| clean-portal | Synthetic Next.js-shaped source with trusted static HTML | Empty, curated clean | Ran |
| juice-shop | Isolated Docker HTTP target, 127.0.0.1:3001 | Pending version-specific annotation | Not run: Docker unavailable |
| nodegoat | Isolated Docker HTTP target, 127.0.0.1:3002 | Pending version-specific annotation | Not run: Docker unavailable |
| dvwa | Isolated Docker HTTP target, 127.0.0.1:3003 | Pending version-specific annotation | Not run: Docker unavailable |

See [the benchmark instructions](../README.md) for local runs and the unexecuted Docker setup. Docker applications' URL and source-repository benchmark measurements are pending; their source repositories were not fetched or measured in this environment. Only the four generated local repositories have measured results. Empty Docker JSON arrays do not certify a clean target.
