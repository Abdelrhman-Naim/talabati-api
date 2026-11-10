import { open, readdir, lstat, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve, relative, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { assertBenchmarkMode } from './guard';
import { UnsupportedRepositoryFile, type Snapshot, type RepositoryFile } from '../src/lib/repository/github';
const hash = (bytes: Uint8Array) => createHash('sha1').update('blob ' + bytes.byteLength + '\0').update(bytes).digest('hex');
export class LocalReader {
    private root: string;
    private snapshotFiles = new Map<string, RepositoryFile>();
    constructor(root: string, private limits: {
        maxFiles?: number;
        maxBytes?: number;
    } = {}) { assertBenchmarkMode(); this.root = resolve(root); }
    private async rootPath() {
        assertBenchmarkMode();
        if ((await lstat(this.root)).isSymbolicLink())
            throw new Error('LocalReader root cannot be a symlink');
        if (await realpath(this.root) !== this.root)
            throw new Error('LocalReader root must be canonical');
        return this.root;
    }
    private async read(path: string, limit: number, signal?: AbortSignal) {
        assertBenchmarkMode();
        signal?.throwIfAborted();
        const root = await this.rootPath(), full = resolve(root, path);
        if (path.startsWith('/') || path.includes('\\') || path.split('/').some(p => ['..', '.', ''].includes(p)) || relative(root, full).startsWith('..' + sep))
            throw new Error('Unsafe local path');
        const canonical = await realpath(full);
        if (!canonical.startsWith(root + sep))
            throw new Error('File escapes fixture root');
        const st = await lstat(full);
        if (!st.isFile() || st.isSymbolicLink() || st.size > limit)
            throw new Error('Unsafe or oversized fixture file');
        const file = await open(full, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
        try {
            const actual = await file.stat();
            if (st.ino !== actual.ino || st.dev !== actual.dev || actual.size > limit)
                throw new Error('Fixture changed');
            const bytes = Buffer.alloc(actual.size + 1);
            const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
            if (bytesRead !== actual.size)
                throw new Error('Fixture changed during read');
            signal?.throwIfAborted();
            return bytes.subarray(0, bytesRead);
        }
        finally {
            await file.close();
        }
    }
    async snapshot(_branch: string, signal?: AbortSignal): Promise<Snapshot> {
        const root = await this.rootPath(), files: RepositoryFile[] = [];
        let total = 0;
        this.snapshotFiles.clear();
        const walk = async (dir: string) => {
            for (const entry of (await readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
                signal?.throwIfAborted();
                const full = resolve(dir, entry.name), st = await lstat(full);
                if (st.isSymbolicLink())
                    throw new Error('Symlink fixture rejected');
                if (entry.name === '.git')
                    continue;
                if (st.isDirectory()) {
                    await walk(full);
                    continue;
                }
                if (!st.isFile())
                    throw new Error('Nonregular fixture file');
                if (files.length >= (this.limits.maxFiles ?? 3000) || total + st.size > (this.limits.maxBytes ?? 20 * 1024 * 1024))
                    throw new Error('LocalReader fixture limits exceeded');
                const path = relative(root, full).split(sep).join('/'), bytes = await this.read(path, 4 * 1024 * 1024, signal), f = { path, sha: hash(bytes), size: bytes.length, mode: '100644' };
                total += bytes.length;
                files.push(f);
                this.snapshotFiles.set(path, f);
            }
        };
        await walk(root);
        const tree = createHash('sha1').update(JSON.stringify(files)).digest('hex');
        return { commit: tree, tree, files, excluded: 0, truncated: false };
    }
    async blob(file: RepositoryFile, signal?: AbortSignal) {
        assertBenchmarkMode();
        const pinned = this.snapshotFiles.get(file.path);
        if (!pinned || pinned.sha !== file.sha || pinned.size !== file.size)
            throw new Error('Blob is not in local snapshot');
        const bytes = await this.read(file.path, /(?:package-lock|npm-shrinkwrap)\.json$/.test(file.path) ? 4 * 1024 * 1024 : 256 * 1024, signal);
        if (bytes.length !== file.size || hash(bytes) !== file.sha)
            throw new Error('Local fixture SHA mismatch');
        if (bytes.includes(0))
            throw new UnsupportedRepositoryFile();
        try {
            return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        }
        catch {
            throw new UnsupportedRepositoryFile();
        }
    }
}
