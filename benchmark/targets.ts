import type { ExpectedFinding } from './score';
export const dockerTargets = {
    'juice-shop': { url: 'http://127.0.0.1:3001/', source: 'https://github.com/juice-shop/juice-shop', expectedStatus: 'pending-versioned-annotation' },
    nodegoat: { url: 'http://127.0.0.1:3002/', source: 'https://github.com/OWASP/NodeGoat', expectedStatus: 'pending-versioned-annotation' },
    dvwa: { url: 'http://127.0.0.1:3003/', source: 'https://github.com/digininja/DVWA', expectedStatus: 'pending-versioned-annotation' }
} as const;
export type DockerTarget = keyof typeof dockerTargets;
// Empty expected files for these targets are explicitly pending, never clean ground truth.
export type ExpectedManifest = {
    target: string;
    status: 'curated-local' | 'pending-versioned-annotation';
    expected: ExpectedFinding[];
};
