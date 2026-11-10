import { FindingSchema, RawFindingSchema, type Finding, type RawToolResult, type Suppression } from './schema';
import { redactText } from './redact';
import { fingerprint, dedupe, normalizeLocation } from './dedupe';
import { confidenceFor } from './confidence';
import { suppress } from './suppress';
export function normalize(raw: RawToolResult[], suppressions: Suppression[]) {
    const allSecrets = raw.flatMap(r => r.findings.flatMap(f => f.secrets ?? []));
    const findings: Finding[] = [], toolStatus: Record<string, 'ok' | 'incomplete' | 'failed'> = Object.create(null);
    for (const result of raw) {
        const tool = redactText(result.tool, allSecrets) || 'unknown';
        if (result.state !== 'ok' || toolStatus[tool] === 'incomplete')
            toolStatus[tool] = 'incomplete';
        else
            toolStatus[tool] = 'ok';
        for (const item of result.findings) {
            const parsed = RawFindingSchema.safeParse(item);
            if (!parsed.success) {
                toolStatus[tool] = 'incomplete';
                continue;
            }
            const f = parsed.data, secrets = allSecrets, safe = (s: string) => redactText(s, secrets);
            const base = { tool: safe(tool), rule: safe(f.rule), category: safe(f.category), severity: f.severity, location: normalizeLocation(safe(f.location)), redactedEvidence: safe(f.evidence), fix: safe(f.fix), confidence: confidenceFor(tool, f.rule, f.context), status: 'open' as const };
            const fp = fingerprint(base);
            const normalized = FindingSchema.safeParse({ ...base, id: fp.slice(0, 20), fingerprint: fp });
            if (!normalized.success) {
                toolStatus[tool] = 'incomplete';
                continue;
            }
            findings.push(normalized.data);
        }
    }
    return { findings: suppress(dedupe(findings), suppressions), toolStatus };
}
