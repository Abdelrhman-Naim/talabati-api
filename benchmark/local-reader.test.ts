import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalReader } from './local-reader';
async function fixture(fn: (dir: string) => Promise<void>) {
    const dir = mkdtempSync(join(tmpdir(), 'aegis-reader-'));
    const mode = process.env.BENCHMARK_MODE;
    process.env.BENCHMARK_MODE = '1';
    try {
        await fn(dir);
    }
    finally {
        if (mode === undefined)
            delete process.env.BENCHMARK_MODE;
        else
            process.env.BENCHMARK_MODE = mode;
        rmSync(dir, { recursive: true, force: true });
    }
}
test('LocalReader matches GitHubReader snapshot/blob interface and never runs repository code', () => fixture(async (dir) => { writeFileSync(join(dir, 'a.ts'), 'export const x=1'); writeFileSync(join(dir, 'package.json'), JSON.stringify({ scripts: { preinstall: 'must-not-run' } })); mkdirSync(join(dir, '.git')); writeFileSync(join(dir, '.git', 'ignored'), 'git metadata'); const reader = new LocalReader(dir); const snap = await reader.snapshot('main'); assert.equal(snap.files.length, 2); assert.match(snap.commit, /^[a-f0-9]{40}$/); assert.equal(await reader.blob(snap.files.find(f => f.path === 'a.ts')!), 'export const x=1'); }));
test('LocalReader rejects symlinks and traversal', () => fixture(async (dir) => { symlinkSync('/etc/passwd', join(dir, 'escape.ts')); await assert.rejects(new LocalReader(dir).snapshot('main')); await assert.rejects(new LocalReader(dir).blob({ path: '../escape', size: 1, sha: 'a'.repeat(40), mode: '100644' })); }));
test('LocalReader enforces limits and immutable blob hashes', () => fixture(async (dir) => { writeFileSync(join(dir, 'a.ts'), 'first'); writeFileSync(join(dir, 'b.ts'), 'second'); await assert.rejects(new LocalReader(dir, { maxFiles: 1 }).snapshot('main')); const r = new LocalReader(dir), snap = await r.snapshot('main'); writeFileSync(join(dir, 'a.ts'), 'changed'); await assert.rejects(r.blob(snap.files.find(f => f.path === 'a.ts')!)); }));
