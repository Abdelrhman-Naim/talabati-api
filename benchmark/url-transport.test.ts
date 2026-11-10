import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fetchBenchmarkUrl } from './url-transport';
test('benchmark HTTP transport pins loopback, follows same-origin and rejects cross-origin redirects', async () => {
    const mode = process.env.BENCHMARK_MODE;
    process.env.BENCHMARK_MODE = '1';
    const server = http.createServer((req, res) => {
        if (req.url === '/same') {
            res.writeHead(302, { location: '/' });
            res.end();
        }
        else if (req.url === '/outside') {
            res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' });
            res.end();
        }
        else {
            res.writeHead(200, { 'content-type': 'text/html' });
            res.end('<html>Unit test fixture</html>');
        }
    });
    try {
        await new Promise<void>((ok, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', ok); });
        const address = server.address();
        assert.ok(address && typeof address !== 'string');
        const origin = 'http://127.0.0.1:' + address.port;
        assert.equal((await fetchBenchmarkUrl(origin + '/same', origin)).status, 200);
        await assert.rejects(fetchBenchmarkUrl(origin + '/outside', origin));
        await assert.rejects(fetchBenchmarkUrl(origin + '/', origin, 4));
    }
    finally {
        await new Promise<void>(ok => server.close(() => ok()));
        if (mode === undefined)
            delete process.env.BENCHMARK_MODE;
        else
            process.env.BENCHMARK_MODE = mode;
    }
});
