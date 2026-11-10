import type { Store } from '../src/lib/db';
export class BenchmarkModeError extends Error {
}
export function assertBenchmarkMode() {
    if (process.env.NODE_ENV === 'production' || process.env.BENCHMARK_MODE !== '1')
        throw new BenchmarkModeError('Benchmark requires BENCHMARK_MODE=1 and refuses NODE_ENV=production');
}
export function validateBenchmarkUrl(input: string) {
    assertBenchmarkMode();
    const u = new URL(input);
    if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || !['127.0.0.1', 'localhost', '[::1]', 'juice-shop', 'nodegoat', 'dvwa'].includes(u.hostname) || u.hash)
        throw new BenchmarkModeError('Only local benchmark fixture hosts are permitted');
    return u;
}
export function authorizeBenchmarkProject(store: Store, owner: string, project: string, url: string) {
    assertBenchmarkMode();
    const target = validateBenchmarkUrl(url);
    if (!store.ownedProject(owner, project))
        throw new BenchmarkModeError('Unknown benchmark project');
    store.db.prepare('UPDATE projects SET url=? WHERE id=? AND owner_id=?').run(target.href, project, owner);
    store.verifyProject(owner, project);
}
