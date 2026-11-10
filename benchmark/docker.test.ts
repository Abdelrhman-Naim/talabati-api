import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateDockerTarget } from './docker';
// Synthetic Docker metadata tests only; these are not scan/target results.
const info = () => ({ Name: '/aegis-benchmark-juice-shop', Id: 'unit-test-container', Image: 'sha256:' + 'a'.repeat(64), State: { Running: true }, NetworkSettings: { Ports: { '3000/tcp': [{ HostIp: '127.0.0.1', HostPort: '3001' }] } } });
test('Docker provenance requires the named running loopback-bound target', () => { assert.equal(validateDockerTarget(info(), 'juice-shop').imageId, 'sha256:' + 'a'.repeat(64)); for (const mutate of [(v: ReturnType<typeof info>) => v.Name = '/another-app', (v: ReturnType<typeof info>) => v.State.Running = false, (v: ReturnType<typeof info>) => v.NetworkSettings.Ports['3000/tcp'][0].HostIp = '0.0.0.0', (v: ReturnType<typeof info>) => v.NetworkSettings.Ports['3000/tcp'][0].HostPort = '8080']) {
    const v = info();
    mutate(v);
    assert.throws(() => validateDockerTarget(v, 'juice-shop'));
} assert.throws(() => validateDockerTarget({}, 'nodegoat')); });
