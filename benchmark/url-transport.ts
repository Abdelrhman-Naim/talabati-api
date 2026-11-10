import http from 'node:http';
import https from 'node:https';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import type { HttpPage } from '../src/lib/types';
import { decodeHttpResponseBody, pinnedLookup } from '../src/lib/network';
import { assertBenchmarkMode, validateBenchmarkUrl } from './guard';
export async function fetchBenchmarkUrl(input: string, scopeOrigin: string, hop = 0): Promise<HttpPage> {
    assertBenchmarkMode();
    if (hop > 3)
        throw new Error('Benchmark redirect limit');
    const u = validateBenchmarkUrl(input);
    if (u.origin !== scopeOrigin)
        throw new Error('Benchmark cross-origin redirect blocked');
    const addresses = isIP(u.hostname.replace(/^\[|\]$/g, '')) ? [{ address: u.hostname.replace(/^\[|\]$/g, ''), family: u.hostname.includes(':') ? 6 : 4 }] : await lookup(u.hostname, { all: true });
    for (const a of addresses) {
        const loopback = /^127\./.test(a.address) || a.address === '::1', privateDocker = /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(a.address);
        if (!loopback && (!['juice-shop', 'nodegoat', 'dvwa'].includes(u.hostname) || !privateDocker))
            throw new Error('Benchmark DNS resolved outside approved isolated ranges');
    }
    const pinned = addresses.find(a => a.family === 4) ?? addresses[0];
    if (!pinned)
        throw new Error('Benchmark DNS empty');
    const start = Date.now();
    const response = await new Promise<HttpPage>((resolve, reject) => {
        const request = (u.protocol === 'https:' ? https : http).request(u, { method: 'GET', agent: false, lookup: pinnedLookup(pinned) as never, headers: { 'user-agent': 'AegisBenchmark/0.12.0', 'accept-encoding': 'identity' }, signal: AbortSignal.timeout(5000) }, r => {
            const chunks: Buffer[] = [];
            let size = 0;
            r.on('data', (part: Buffer) => {
                size += part.length;
                if (size > 2 * 1024 * 1024) {
                    request.destroy(new Error('Benchmark response size limit'));
                    return;
                }
                chunks.push(part);
            });
            r.on('error', reject);
            r.on('end', () => {
                try {
                    const headers: Record<string, string> = {};
                    for (const [k, v] of Object.entries(r.headers))
                        if (v !== undefined)
                            headers[k] = Array.isArray(v) ? v.join('\n') : v;
                    const body = decodeHttpResponseBody(Buffer.concat(chunks), headers['content-encoding'], 2 * 1024 * 1024, 'GET', r.statusCode ?? 0).toString('utf8');
                    resolve({ url: u.href, status: r.statusCode ?? 0, headers, body, bytes: size, elapsedMs: Date.now() - start });
                }
                catch (e) {
                    reject(e);
                }
            });
        });
        request.on('error', reject);
        request.end();
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
        if (!response.headers.location)
            throw new Error('Benchmark redirect missing location');
        return fetchBenchmarkUrl(new URL(response.headers.location, u).href, scopeOrigin, hop + 1);
    }
    return response;
}
