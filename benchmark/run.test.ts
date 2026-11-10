import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main } from './run';
import { fakeCredentials } from './fixtures';
test('real local baseline writes valid structured JSON without credentials or source excerpts', async () => {
    const mode = process.env.BENCHMARK_MODE;
    process.env.BENCHMARK_MODE = '1';
    const dir = mkdtempSync(join(tmpdir(), 'aegis-baseline-'));
    try {
        const file = join(dir, 'run.json');
        await main(['--target', 'seeded', '--output', file]);
        const raw = readFileSync(file, 'utf8'), report = JSON.parse(raw);
        assert.equal(report.scannerVersion, '0.12.0');
        assert.equal(report.partial, true);
        assert.equal(report.results[0].toolStatus.osv, 'not_requested');
        assert.deepEqual(report.results[0].unmeasuredCategories, ['dependency']);
        assert.equal(report.aggregate.byCategory.dependency.recall, null);
        assert.equal(report.phase,'dev');
        assert.ok(report.results[0].expected.every((e:{split:string})=>e.split==='dev'));
        assert.equal(report.aggregate.byCategory.dependency.actual,null);
        for (const value of Object.values(fakeCredentials()))
            assert.equal(raw.includes(value), false);
        for (const finding of report.results[0].actual) {
            assert.deepEqual(Object.keys(finding).sort(), ['category', 'id', 'location', 'rule', 'severity']);
        }
    }
    finally {
        rmSync(dir, { recursive: true, force: true });
        if (mode === undefined)
            delete process.env.BENCHMARK_MODE;
        else
            process.env.BENCHMARK_MODE = mode;
    }
});
