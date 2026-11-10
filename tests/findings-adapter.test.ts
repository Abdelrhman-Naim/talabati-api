import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/lib/db';
import { runJob } from '../src/lib/jobs';
import { normalizeLegacyResult } from '../src/lib/findings-adapter';
import type { Finding, ScanResult } from '../src/lib/types';
const rawFinding = (rule = 'repo.secret'): Finding => ({ id: 'legacy-id', rule, category: 'security', severity: 'high', confidence: 'medium', title: 'Observed issue', description: 'Review source', url: 'https://example.com', file: 'src/config.ts', line: 2, evidence: 'FAKE sk_live_1234567890abcdef', recommendation: 'Rotate credential', checks: [] });
const result = (): ScanResult => ({ findings: [rawFinding()], services: [], coverage: [], pages: [], errors: [], scope: 'fixture', engine: 'aegis-repository-security@0.12.0' });
test('legacy compatibility adapter preserves rule/category/severity and redacts before persistence', () => { const r = normalizeLegacyResult(result()); assert.equal(r.findings[0].rule, 'repo.secret'); assert.equal(r.findings[0].category, 'security'); assert.equal(r.findings[0].severity, 'high'); assert.equal(r.findings[0].confidence, 'medium'); assert.equal(r.normalizedFindings?.[0].rule, 'repo.secret'); assert.ok(r.normalizedFindings![0].confidence >= 0 && r.normalizedFindings![0].confidence <= 1); assert.equal(JSON.stringify(r).includes('sk_live_1234567890abcdef'), false); });
test('unavailable dependency tool is visible as incomplete alongside valid custom findings', () => { const r = result(); r.dependencyAudit = { status: 'unavailable', total: 1, queried: 0, checkedAt: 0, advisories: [], packages: [], errors: ['OSV connection unavailable'] }; assert.equal(normalizeLegacyResult(r).findingNormalization?.toolStatus.osv, 'incomplete'); });
test('URL worker persists canonical normalized findings at progress and completion', async () => { const s = new Store(':memory:'), u = s.createUser('normalizer@example.com', 'hash'), p = s.createProject(u.id, 'Normalizer', 'https://example.com'); s.verifyProject(u.id, p.id); s.queueScan(u.id, p.id, { mode: 'quick' }); const job = s.claimJob()!; const snapshots:ScanResult[]=[];const publish=s.progress.bind(s);s.progress=(id:string,stage:string,value:ScanResult)=>{snapshots.push(structuredClone(value));publish(id,stage,value);}; try {
    await runJob(s, job, async (url) => ({ url, status: 200, headers: { 'content-type': 'text/html' }, body: '<html><body><h1>Test</h1></body></html>', elapsedMs: 1, bytes: 60 }), 10);
    const saved = s.ownedScan(u.id, job.id)!.result!;
    assert.ok(snapshots.length>0);
    assert.ok(snapshots.every(r=>Array.isArray(r.normalizedFindings)&&r.findingNormalization?.version===1));
    assert.ok(snapshots.some(r=>r.normalizedFindings!.length>0));
    assert.ok(saved.normalizedFindings?.length);
    assert.equal(saved.findingNormalization?.version, 1);
    assert.ok(saved.findings.every(f => saved.normalizedFindings!.some(n => n.rule === f.rule && n.severity === f.severity)));
}
finally {
    s.close();
} });
test('different authorized API matrix identities on one URL are not deduplicated', () => { const r = result(); r.findings = ['api-A-B', 'api-A-anon'].map(id => ({ ...rawFinding('security.api-auth'), id, file: undefined, line: undefined, title: id, evidence: 'Same resource exposure' })); const normalized = normalizeLegacyResult(r); assert.equal(normalized.findings.length, 2); assert.equal(normalized.normalizedFindings!.length, 2); assert.notEqual(normalized.normalizedFindings![0].fingerprint, normalized.normalizedFindings![1].fingerprint); });
test('runtime and API collection failures cannot report the custom tool as ok',()=>{for(const extra of [{runtimeSecurity:{status:'unavailable' as const,detail:'HTTP timeout'}},{apiHttp:{status:'partial'}},{checks:[{status:'unavailable',unavailableReason:'collection_error'}]}]){const r=Object.assign(result(),extra) as ScanResult;assert.equal(normalizeLegacyResult(r).findingNormalization?.toolStatus.custom,'incomplete');}});
test('outer worker failure has canonical empty findings and explicit incomplete status',async()=>{const module=await import('../src/lib/findings-adapter');assert.equal(typeof module.failedWorkerResult,'function');const failed=module.failedWorkerResult('unchanged-score-version');assert.deepEqual(failed.normalizedFindings,[]);assert.equal(failed.findingNormalization?.toolStatus.custom,'incomplete');assert.equal(failed.scoreVersion,'unchanged-score-version');});
