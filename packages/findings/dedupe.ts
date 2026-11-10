import { createHash } from 'node:crypto';
import type { Finding } from './schema';
export function normalizeLocation(location: string) { return location.replaceAll('\\', '/').replace(/^\.\//, '').replace(/#L(\d+)$/, ':$1'); }
export function fingerprint(f: Pick<Finding, 'category' | 'rule' | 'location' | 'redactedEvidence'>) { return createHash('sha256').update(JSON.stringify([f.category, f.rule, normalizeLocation(f.location), f.redactedEvidence])).digest('hex'); }
const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export function dedupe(findings: Finding[]) {
    const groups = new Map<string, {
        finding: Finding;
        tools: Set<string>;
        confidence: number;
    }>();
    for (const f of findings) {
        const old = groups.get(f.fingerprint);
        if (!old) {
            groups.set(f.fingerprint, { finding: { ...f }, tools: new Set([f.tool]), confidence: f.confidence });
            continue;
        }
        old.tools.add(f.tool);
        old.confidence = Math.max(old.confidence, f.confidence);
        if (rank[f.severity] > rank[old.finding.severity])
            old.finding.severity = f.severity;
        if (f.fix < old.finding.fix)
            old.finding.fix = f.fix;
    }
    return [...groups.values()].map(({ finding, tools, confidence }) => ({ ...finding, tool: [...tools].sort().join(','), confidence: Math.min(1, confidence + (new Set([...tools].map(t => t.startsWith('custom') ? 'custom' : t)).size > 1 ? 0.2 : 0)) })).sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
}
