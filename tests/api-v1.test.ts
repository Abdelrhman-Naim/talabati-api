import test from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { GET, POST, OPTIONS } from '../src/app/api/[...path]/route.ts';

test('API v1 endpoints: CORS, documentation, code scanning and URL validation', async () => {
  const base = 'http://localhost:3000';

  async function call(path: string, method = 'GET', data?: unknown, headers: Record<string, string> = {}) {
    const req = new NextRequest(base + '/api/' + path, {
      method,
      headers: {
        ...(data !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...headers,
      },
      body: data !== undefined ? JSON.stringify(data) : undefined,
    });
    const fn = method === 'GET' ? GET : method === 'OPTIONS' ? OPTIONS : POST;
    const r = (await fn(req, { params: Promise.resolve({ path: path.split('/') }) }))!;
    const cors = r.headers.get('access-control-allow-origin');
    let json: any = null;
    try {
      json = await r.json();
    } catch {}
    return { status: r.status, data: json, cors };
  }

  // 1. CORS preflight
  const preflight = await call('v1/scan', 'OPTIONS');
  assert.equal(preflight.status, 204);
  assert.equal(preflight.cors, '*');

  // 2. Documentation endpoint
  const docs = await call('v1');
  assert.equal(docs.status, 200);
  assert.equal(docs.data.service, 'Aegis Security Audit API');
  assert.ok(docs.data.endpoints.scan);
  assert.equal(docs.cors, '*');

  // 3. Health endpoint
  const health = await call('v1/health');
  assert.equal(health.status, 200);
  assert.equal(health.data.success, true);
  assert.equal(health.data.status, 'healthy');

  // 4. Scan vulnerable code snippet
  const vulnerableCode = `
    const apiKey = 'sb_secret_mock_test_token_123456789';
    function execute(userCmd) {
      eval(userCmd);
    }
  `;
  const codeScan = await call('v1/scan', 'POST', { code: vulnerableCode, filename: 'auth.js' });
  assert.equal(codeScan.status, 200);
  assert.equal(codeScan.data.success, true);
  assert.equal(codeScan.data.type, 'code');
  assert.ok(codeScan.data.findings.length >= 2, 'Should detect secret and eval');
  assert.ok(codeScan.data.findings.some((f: any) => f.rule === 'repo.secret'));
  assert.ok(codeScan.data.findings.some((f: any) => f.rule === 'repo.eval'));
  assert.ok(codeScan.data.score < 100, 'Score should be penalized for vulnerabilities');
  assert.equal(codeScan.cors, '*');

  // 5. Scan clean code snippet
  const cleanCode = `
    export function add(a: number, b: number): number {
      return a + b;
    }
  `;
  const cleanScan = await call('v1/scan', 'POST', { code: cleanCode, filename: 'math.ts' });
  assert.equal(cleanScan.status, 200);
  assert.equal(cleanScan.data.success, true);
  assert.equal(cleanScan.data.findings.length, 0);
  assert.equal(cleanScan.data.score, 100);
  assert.equal(cleanScan.data.grade, 'A+');

  // 6. Direct /api/scan alias (without v1/)
  const aliasScan = await call('scan', 'POST', { code: cleanCode, filename: 'clean.ts' });
  assert.equal(aliasScan.status, 200);
  assert.equal(aliasScan.data.success, true);

  // 7. Reject empty payload
  const emptyScan = await call('v1/scan', 'POST', {});
  assert.equal(emptyScan.status, 400);
  assert.equal(emptyScan.data.success, false);

  // 8. SSRF Guard rejects private IP / localhost target
  const ssrfScan = await call('v1/scan', 'POST', { url: 'http://127.0.0.1:8080/admin' });
  assert.equal(ssrfScan.status, 400);
  assert.equal(ssrfScan.data.success, false);
});
