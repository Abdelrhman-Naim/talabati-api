import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fixtureDefinition, prepareFixture, fakeCredentials, localTargets } from './fixtures';
import { LocalReader } from './local-reader';
test('seeded fixture has fake history-only credential, no Git remote, and committed expected locations', async () => {
    const old = process.env.BENCHMARK_MODE;
    process.env.BENCHMARK_MODE = '1';
    const base = mkdtempSync(join(tmpdir(), 'aegis-fixture-'));
    try {
        const { root, expected } = prepareFixture(base, 'seeded');
        const git = (...args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8' });
        assert.equal(git('remote').trim(), '');
        assert.equal(git('rev-list', '--count', 'HEAD').trim(), '2');
        assert.equal(existsSync(join(root, 'src/deleted-secret.ts')), false);
        assert.ok(git('show', 'HEAD~1:src/deleted-secret.ts').includes(fakeCredentials().history));
        const snap = await new LocalReader(root).snapshot('main');
        assert.ok(snap.files.some(f => f.path === 'public/_next/static/chunks/bundle.js'));
        assert.ok(!snap.files.some(f => f.path.startsWith('.git/')));
        assert.deepEqual(JSON.parse(readFileSync(new URL('./expected/seeded.json', import.meta.url), 'utf8')).findings.map(({split,...f}:any)=>f), expected);
        for (const name of localTargets) {
            assert.deepEqual(JSON.parse(readFileSync(new URL('./expected/' + name + '.json', import.meta.url), 'utf8')).findings.map(({split,...f}:any)=>f), fixtureDefinition(name).expected);
        }
        assert.equal(expected.length, 21);
    }
    finally {
        rmSync(base, { recursive: true, force: true });
        if (old === undefined)
            delete process.env.BENCHMARK_MODE;
        else
            process.env.BENCHMARK_MODE = old;
    }
});
