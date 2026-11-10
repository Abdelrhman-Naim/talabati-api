import { assertBenchmarkMode } from './guard';
import { execFileSync } from 'node:child_process';
import type { DockerTarget } from './targets';
export function validateDockerTarget(info: unknown, name: DockerTarget) {
    const v = info as {
        Name?: string;
        Id?: string;
        Image?: string;
        State?: {
            Running?: boolean;
        };
        NetworkSettings?: {
            Ports?: Record<string, {
                HostIp: string;
                HostPort: string;
            }[] | null>;
        };
    };
    const ports = { 'juice-shop': ['3000/tcp', '3001'], nodegoat: ['4000/tcp', '3002'], dvwa: ['80/tcp', '3003'] } as const;
    const [containerPort, hostPort] = ports[name], bindings = v?.NetworkSettings?.Ports?.[containerPort];
    if (v?.Name !== '/aegis-benchmark-' + name || !v.State?.Running || !v.Id || !/^sha256:[a-f0-9]{64}$/.test(v.Image ?? '') || !bindings?.length || bindings.some(b => b.HostIp !== '127.0.0.1' || b.HostPort !== hostPort))
        throw new Error('Unverified benchmark container');
    return { containerId: v.Id, imageId: v.Image! };
}
export function inspectDockerTarget(name: DockerTarget) {
    assertBenchmarkMode();
    try {
        const options = { encoding: 'utf8' as const, stdio: ['ignore', 'pipe', 'pipe'] as [
                'ignore',
                'pipe',
                'pipe'
            ], timeout: 4000, maxBuffer: 2 * 1024 * 1024 };
        const dockerVersion = execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], options).trim();
        if (!dockerVersion)
            return { available: false as const, reason: 'Docker binary/server unavailable; target was not started or scanned' };
        const info = JSON.parse(execFileSync('docker', ['inspect', '--type', 'container', '--format', '{{json .}}', 'aegis-benchmark-' + name], options));
        return { available: true as const, provenance: { ...validateDockerTarget(info, name), dockerVersion } };
    }
    catch {
        return { available: false as const, reason: 'Docker binary/server or named running loopback-bound container unavailable; target was not scanned' };
    }
}
