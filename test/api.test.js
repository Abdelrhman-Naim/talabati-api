const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../server');

let server;
let baseUrl;

test.before(async () => {
  await new Promise(resolve => {
    server = app.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });
});

test.after(async () => {
  await new Promise(resolve => server.close(resolve));
});

function request(path, method = 'GET', data = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const req = http.request(url, {
      method,
      headers: {
        ...(data ? { 'Content-Type': 'application/json' } : {}),
      }
    }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch {}
        resolve({
          status: res.statusCode,
          headers: res.headers,
          data: json,
          text
        });
      });
    });
    req.on('error', reject);
    if (data) req.write(JSON.stringify(data));
    req.end();
  });
}

test('1. Root endpoint GET / returns JSON documentation with ZERO HTML', async () => {
  const res = await request('/');
  assert.equal(res.status, 200);
  assert.equal(res.headers['content-type'].includes('application/json'), true);
  assert.equal(res.data.status, 'online');
  assert.ok(res.data.endpoints.scan);
});

test('2. Health check GET /health returns healthy status', async () => {
  const res = await request('/health');
  assert.equal(res.status, 200);
  assert.equal(res.data.status, 'healthy');
  assert.ok(typeof res.data.uptimeSeconds === 'number');
});

test('3. Code scan POST /api/scan catches eval and secret leaks', async () => {
  const payload = {
    code: `
      const token = 'sb_secret_sample_mock_123456789';
      eval(userCmd);
    `,
    filename: 'danger.js'
  };

  const res = await request('/api/scan', 'POST', payload);
  assert.equal(res.status, 200);
  assert.equal(res.data.success, true);
  assert.equal(res.data.type, 'code');
  assert.ok(res.data.findings.length >= 2, 'Should detect secret and eval');
  assert.ok(res.data.findings.some(f => f.type === 'SECRET_LEAK'));
  assert.ok(res.data.findings.some(f => f.id === 'VULN-EVAL'));
  assert.ok(res.data.score < 80);
});

test('4. Code scan POST /api/scan on clean code returns score 100', async () => {
  const payload = {
    code: `function sum(a, b) { return a + b; }`,
    filename: 'math.js'
  };

  const res = await request('/api/scan', 'POST', payload);
  assert.equal(res.status, 200);
  assert.equal(res.data.success, true);
  assert.equal(res.data.findings.length, 0);
  assert.equal(res.data.score, 100);
  assert.equal(res.data.grade, 'A+');
});

test('5. SSRF validation rejects localhost / private IP targets', async () => {
  const res = await request('/api/scan', 'POST', { url: 'http://127.0.0.1:8080/admin' });
  assert.equal(res.status, 400);
  assert.equal(res.data.success, false);
  assert.ok(res.data.error.includes('SSRF'));
});

test('6. Empty request returns 400 with helpful guide', async () => {
  const res = await request('/api/scan', 'POST', {});
  assert.equal(res.status, 400);
  assert.equal(res.data.success, false);
});
