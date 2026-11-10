import type { ScanResult, Finding as LegacyFinding } from './types';
import { normalize } from '../../packages/findings/normalizer';
import { redactText } from '../../packages/findings/redact';
import type { RawToolResult, Suppression } from '../../packages/findings/schema';
export function legacyLocation(f: LegacyFinding) { return f.file ? f.file + ':' + (f.line ?? 1) : ['security.api-auth', 'security.supabase-rls'].includes(f.rule) ? f.url + '#case=' + encodeURIComponent(f.id) : f.url; }
function redactValue<T>(value: T): T { if (typeof value === 'string')
    return redactText(value) as T; if (Array.isArray(value))
    return value.map(redactValue) as T; if (value && typeof value === 'object')
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redactValue(v)])) as T; return value; }
const key = (rule: string, category: string, location: string, evidence: string) => JSON.stringify([rule, category, location.replaceAll('\\', '/').replace(/^\.\//, '').replace(/#L(\d+)$/, ':$1'), evidence]);
/** Worker persistence boundary: detectors and the UI's legacy fields keep their semantics. */
export function normalizeLegacyResult(result: ScanResult, suppressions: Suppression[] = []): ScanResult {
    const safe = redactValue(result), originals = new Map<string, LegacyFinding>(), custom: RawToolResult = { tool: 'custom', state: safe.errors.length || safe.repository?.failed || safe.repository?.pending || safe.repository?.truncated || safe.runtimeSecurity?.status==='unavailable' || safe.apiHttp?.status==='partial' || safe.checks?.some(c=>c.status==='unavailable'&&c.unavailableReason==='collection_error') ? 'incomplete' : 'ok', findings: [] }, osv: RawToolResult = { tool: 'osv', state: safe.dependencyAudit?.status === 'completed' ? 'ok' : 'incomplete', findings: [] };
    for (const f of safe.findings) {
        const location = legacyLocation(f);
        originals.set(key(f.rule, f.category, location, f.evidence), f);
        (f.rule.startsWith('repo.osv.') ? osv : custom).findings.push({ rule: f.rule, category: f.category, severity: f.severity, location, evidence: f.evidence, fix: f.recommendation, context: f.security?.basis === 'configuration' });
    }
    const tools = [custom];
    if (osv.findings.length || safe.dependencyAudit && safe.dependencyAudit.status !== 'not_enabled')
        tools.push(osv);
    const normalized = normalize(tools, suppressions);
    const findings = normalized.findings.flatMap(n => { const legacy = originals.get(key(n.rule, n.category, n.location, n.redactedEvidence)); return legacy ? [{ ...legacy, evidence: n.redactedEvidence, recommendation: n.fix }] : []; });
    return { ...safe, findings, normalizedFindings: normalized.findings, findingNormalization: { version: 1, toolStatus: normalized.toolStatus } };
}

export function failedWorkerResult(scoreVersion:string):ScanResult{return normalizeLegacyResult({findings:[],services:[],coverage:[],pages:[],errors:['تعطل عامل الجمع؛ راجع تشخيص المحرك.'],scope:'',engine:'aegis-link-audit@0.8.0',scoreVersion,checks:[]});}
