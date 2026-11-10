import { inspectDockerTarget } from './docker';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/lib/db';
import { assertBenchmarkMode, authorizeBenchmarkProject, validateBenchmarkUrl } from './guard';
function env(mode: string | undefined, node: string | undefined, fn: () => void) {
    const m = process.env.BENCHMARK_MODE, n = process.env.NODE_ENV;
    try {
        if (mode === undefined)
            delete process.env.BENCHMARK_MODE;
        else
            process.env.BENCHMARK_MODE = mode;
        if (node === undefined)
            Reflect.deleteProperty(process.env, 'NODE_ENV');
        else
            Reflect.set(process.env, 'NODE_ENV', node);
        fn();
    }
    finally {
        if (m === undefined)
            delete process.env.BENCHMARK_MODE;
        else
            process.env.BENCHMARK_MODE = m;
        if (n === undefined)
            Reflect.deleteProperty(process.env, 'NODE_ENV');
        else
            Reflect.set(process.env, 'NODE_ENV', n);
    }
}
test('benchmark bypass is off by default', () => env(undefined, 'test', () => assert.throws(() => assertBenchmarkMode())));
test('production never honors BENCHMARK_MODE or mutates ownership state', () => env('1', 'production', () => { assert.throws(() => assertBenchmarkMode()); assert.throws(() => validateBenchmarkUrl('http://127.0.0.1:3001')); const s = new Store(':memory:'), u = s.createUser('b@example.com', 'hash'), p = s.createProject(u.id, 'Bench', 'https://benchmark.example.com'); assert.throws(() => authorizeBenchmarkProject(s, u.id, p.id, 'http://127.0.0.1:3001')); assert.equal(s.ownedProject(u.id, p.id)?.verified_until, 0); s.close(); }));
test('benchmark bypass permits only explicit local fixture hosts, not arbitrary private/public services', () => env('1', 'test', () => {
    assert.equal(validateBenchmarkUrl('http://127.0.0.1:3001/').origin, 'http://127.0.0.1:3001');
    for (const url of ['http://169.254.169.254', 'http://10.0.0.1', 'https://google.com', 'file:///tmp/a', 'http://user:pass@localhost:3001'])
        assert.throws(() => validateBenchmarkUrl(url));
}));
test('application SSRF and ownership guards stay active even with benchmark mode enabled', () => env('1', 'test', () => {
    for (const url of ['http://127.0.0.1', 'http://10.0.0.1', 'http://localhost'])
        assert.throws(() => validateTarget(url));
    const s = new Store(':memory:'), u = s.createUser('b@example.com', 'hash'), p = s.createProject(u.id, 'Normal', 'https://benchmark.example.com');
    assert.throws(() => s.queueScan(u.id, p.id), /ملكية/);
    s.close();
}));
test('LocalReader and HTTP bypass refuse production before any I/O', async () => {
    const m = process.env.BENCHMARK_MODE, n = process.env.NODE_ENV;
    try {
        process.env.BENCHMARK_MODE = '1';
        Reflect.set(process.env, 'NODE_ENV', 'production');
        assert.throws(() => new LocalReader('/nonexistent'));
        assert.throws(() => inspectDockerTarget('juice-shop'), /production/);
        await assert.rejects(fetchBenchmarkUrl('http://127.0.0.1:3001/', 'http://127.0.0.1:3001'), /production/);
    }
    finally {
        if (m === undefined)
            delete process.env.BENCHMARK_MODE;
        else
            process.env.BENCHMARK_MODE = m;
        if (n === undefined)
            Reflect.deleteProperty(process.env, 'NODE_ENV');
        else
            Reflect.set(process.env, 'NODE_ENV', n);
    }
});
import { validateTarget } from '../src/lib/network';
import { LocalReader } from './local-reader';
import { fetchBenchmarkUrl } from './url-transport';
