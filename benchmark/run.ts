import {readExpected,selectExpected} from './expected';
import {createOsvTransport,type OsvMode} from './osv';
import { inspectDockerTarget } from './docker';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { load } from 'cheerio';
import { assertBenchmarkMode, authorizeBenchmarkProject } from './guard';
import { fixtureDefinition, prepareFixture, localTargets, negativeHoldoutTargets, fakeCredentials } from './fixtures';
import { LocalReader } from './local-reader';
import { adaptFindings } from './adapter';
import { scoreRun, categories, type ExpectedFinding, type BenchmarkFinding } from './score';
import { dockerTargets, type DockerTarget } from './targets';
import { fetchBenchmarkUrl } from './url-transport';
import { Store } from '../src/lib/db';
import { runRepositoryJob } from '../src/lib/repository/job';
import { analyze } from '../src/lib/audit';
export const benchmarkRoot = dirname(fileURLToPath(import.meta.url));
type CategoryScore=ReturnType<typeof scoreRun>['byCategory'][string];
type ReportScore=Omit<ReturnType<typeof scoreRun>,'byCategory'>&{byCategory:Record<string,{[K in keyof CategoryScore]:CategoryScore[K]|null}&{status?:string}>};
export type TargetResult = {
    target: string;
    kind: 'repo' | 'url';
    status: 'completed' | 'partial' | 'not_run';
    reason?: string;
    durationMs: number | null;
    expectedStatus: string;
    expected: ExpectedFinding[];
    actual: BenchmarkFinding[];
    metrics: ReportScore | null;
    unmeasuredCategories: string[];
    toolStatus: Record<string, string>;
    sourceSnapshot?: string;
    osvMode?:OsvMode;
    osvDiagnostics?:ReturnType<typeof createOsvTransport>['diagnostics'];
    provenance?: {
        containerId: string;
        imageId: string;
        dockerVersion: string;
    };
};
export function reportScore(expected:ExpectedFinding[],actual:BenchmarkFinding[],unmeasured:string[]){const score:ReportScore=scoreRun(expected.filter(e=>!unmeasured.includes(e.category)),actual.filter(e=>!unmeasured.includes(e.category)));for(const [category,row] of Object.entries(score.byCategory))score.byCategory[category]={...row,recall:row.expected?row.recall:null,precision:row.actual?row.precision:null,status:row.expected||row.actual?'measured':'no_examples'};for(const category of unmeasured)score.byCategory[category]={expected:expected.filter(e=>e.category===category).length,actual:null,truePositives:null,falseNegatives:null,falsePositives:null,recall:null,precision:null,status:'unmeasured'};return score;}
function expectedFor(name:string){return readExpected(name).findings;}
export async function scanLocalTarget(name: string, osvMode:OsvMode = 'off', phase:'dev'|'final'='dev'): Promise<TargetResult> {
    assertBenchmarkMode();
    if(phase!=='final'&&(negativeHoldoutTargets as readonly string[]).includes(name))throw new Error('Negative holdout requires --final');
    const manifest=readExpected(name), allExpected=manifest.findings, expected=selectExpected(manifest,phase), definition = fixtureDefinition(name);
    const strip=(rows:typeof allExpected)=>rows.map(({split,...f})=>f);
    const osv=createOsvTransport(osvMode);
    if (JSON.stringify(strip(allExpected)) !== JSON.stringify(definition.expected))
        throw new Error('Expected manifest differs from reviewed fixture definition');
    const { root } = prepareFixture(resolve(benchmarkRoot, 'generated'), name,phase), store = new Store(':memory:'), user = store.createUser('benchmark@example.invalid', 'not-an-account'), project = store.createProject(user.id, 'Local benchmark', 'https://benchmark.example.com/');
    store.linkRepository(user.id, project.id, { owner: 'benchmark-local', name, branch: 'main', private: false }, '');
    store.queueScan(user.id, project.id, { kind: 'repository', dependencyAudit: osvMode!=='off' && name === 'seeded' });
    const job = store.claimJob()!, start = performance.now();
    try {
        await runRepositoryJob(store, job, { reader: new LocalReader(root), requestMs: 5500, osvTransport:osv.fetch, apiHttpTransport: async () => { throw new Error('Benchmark blocks external API probing; no synthetic response supplied'); } });
        const scan = store.ownedScan(user.id, job.id)!, result = scan.result;
        if (!result || scan.status === 'failed')
            throw new Error('Local scanner failed');
        const actual = adaptFindings(result.findings), dependencyExpected = expected.some(e => e.category === 'dependency'), dependencyOk = result.dependencyAudit?.status === 'completed', unmeasured = dependencyExpected && !dependencyOk ? ['dependency'] : [];
        return { target: name, kind: 'repo', status: scan.status === 'completed' && unmeasured.length === 0 ? 'completed' : 'partial', durationMs: Math.round(performance.now() - start), expectedStatus: 'curated-local', expected, actual, metrics: reportScore(expected,actual,unmeasured), unmeasuredCategories: unmeasured, toolStatus: { 'custom-0.12.0': 'ok', osv: !dependencyExpected ? 'not_applicable' : dependencyOk ? 'ok' : osvMode!=='off' ? 'incomplete' : 'not_requested', 'git-history': 'unsupported-current-scanner', 'external-api-probes': 'not_requested' }, sourceSnapshot: result.repository?.commit, osvMode, osvDiagnostics:osv.diagnostics, ...(unmeasured.length ? { reason: osvMode!=='off' ? 'OSV incomplete: '+JSON.stringify(osv.diagnostics.length?osv.diagnostics:result.dependencyAudit?.errors)+'; dependency quality unmeasured' : 'OSV not requested; dependency quality unmeasured' } : {}) };
    }
    finally {
        store.close();
    }
}
export async function scanDockerTarget(name: DockerTarget): Promise<TargetResult> {
    assertBenchmarkMode();
    const target = dockerTargets[name], expected = expectedFor(name), docker = inspectDockerTarget(name);
    const base = { target: name, kind: 'url' as const, expectedStatus: target.expectedStatus, ...(docker.available ? { provenance: docker.provenance } : {}), expected, actual: [] as BenchmarkFinding[], metrics: null, unmeasuredCategories: [...categories], toolStatus: { 'docker-target': 'incomplete' } };
    if (!docker.available)
        return { ...base, status: 'not_run', durationMs: null, reason: docker.reason };
    const store = new Store(':memory:'), u = store.createUser('benchmark@example.invalid', 'not-an-account'), p = store.createProject(u.id, 'Benchmark URL', 'https://benchmark.example.com/');
    authorizeBenchmarkProject(store, u.id, p.id, target.url);
    const start = performance.now();
    try {
        const root = await fetchBenchmarkUrl(target.url, new URL(target.url).origin);
        if (root.status < 200 || root.status >= 300 || !/html/i.test(root.headers['content-type'] ?? ''))
            throw new Error('Benchmark target did not provide successful HTML');
        const out = analyze(root), $ = load(root.body);
        const scripts = $('script[src]').toArray().map(el => new URL($(el).attr('src')!, root.url)).filter(url => url.origin === new URL(target.url).origin).slice(0, 3);
        for (const url of scripts) {
            const asset = await fetchBenchmarkUrl(url.href, new URL(target.url).origin);
            if (asset.status >= 200 && asset.status < 300 && /javascript|ecmascript|text\/plain/i.test(asset.headers['content-type'] ?? ''))
                out.findings.push(...analyze(asset).findings.filter(f => f.rule === 'security.secret' || f.rule === 'security.api-reference-https'));
        }
        const actual = adaptFindings(out.findings);
        return { ...base, status: 'partial', durationMs: Math.round(performance.now() - start), actual, toolStatus: { 'docker-target': 'ok', 'http-analyzer-0.12.0': 'ok', 'ground-truth': 'incomplete', 'browser': 'not_run', 'repository': 'not_run' }, reason: 'HTTP-only local benchmark adapter ran; version-specific ground truth is pending, so quality metrics intentionally remain null' };
    }
    catch {
        return { ...base, status: 'not_run', durationMs: Math.round(performance.now() - start), reason: 'Docker exists but the approved loopback target was unreachable or invalid; no quality results recorded' };
    }
    finally {
        store.close();
    }
}
export function summarize(results: TargetResult[]) {
    const measured = results.filter(r => r.metrics), expected = measured.flatMap(r => r.expected.filter(e => !r.unmeasuredCategories.includes(e.category))), actual = measured.flatMap(r => r.actual.filter(e => !r.unmeasuredCategories.includes(e.category)));
    const scopedExpected = measured.flatMap(r => r.expected.filter(e => !r.unmeasuredCategories.includes(e.category)).map(e => ({ ...e, location: r.target + '/' + e.location }))), scopedActual = measured.flatMap(r => r.actual.filter(e => !r.unmeasuredCategories.includes(e.category)).map(e => ({ ...e, location: r.target + '/' + e.location })));
    const score = scoreRun(scopedExpected, scopedActual);
    const byCategory = Object.fromEntries(categories.map(category => { const row = score.byCategory[category], notMeasured = results.some(r => r.unmeasuredCategories.includes(category) && r.expected.some(e => e.category === category)); return [category, { ...row, ...(notMeasured?{expected:results.reduce((n,r)=>n+r.expected.filter(e=>e.category===category).length,0),actual:null,truePositives:null,falseNegatives:null,falsePositives:null}:{}), recall: !notMeasured&&row.expected ? row.recall : null, precision: !notMeasured&&row.actual ? row.precision : null, status: notMeasured ? 'partial' : row.expected || row.actual ? 'measured' : 'no_examples', unmeasuredExpected: results.reduce((n, r) => n + (r.unmeasuredCategories.includes(category) ? r.expected.filter(e => e.category === category).length : 0), 0) }]; }));
    return { expected: expected.length, actual: actual.length, recall: score.recall, precision: score.precision, falsePositives: score.falsePositives, truePositives: score.truePositives, falseNegatives: score.falseNegatives, highCriticalPrecision: score.highCriticalPrecision, byCategory, holdoutNegativeSet:results.filter(r=>(negativeHoldoutTargets as readonly string[]).includes(r.target)).map(r=>({target:r.target,status:r.status,falsePositives:r.metrics?.falsePositives??null,durationMs:r.durationMs})), cleanNegativeSet: results.filter(r => r.target.startsWith('clean-')&&!(negativeHoldoutTargets as readonly string[]).includes(r.target)).map(r => ({ target: r.target, status: r.status, falsePositives: r.metrics?.falsePositives ?? null, durationMs: r.durationMs })) };
}
export async function main(args = process.argv.slice(2)) {
    assertBenchmarkMode();
    const allowed = new Set(['--target', '--output', '--osv-live','--osv-offline','--final']);
    for (let i = 0; i < args.length; i++)
        if (args[i].startsWith('--') && !allowed.has(args[i]))
            throw new Error('Unknown benchmark option');
    const flag = (key: string, fallback: string) => { const i = args.indexOf(key); return i < 0 ? fallback : args[i + 1] ?? fallback; };
    const name = flag('--target', 'all'), names = [...localTargets, ...Object.keys(dockerTargets)];
    if (name !== 'all' && !names.includes(name))
        throw new Error('Unknown benchmark target');
    if(args.includes('--osv-live')&&args.includes('--osv-offline'))throw new Error('Choose one OSV mode');
    const liveOsv = args.includes('--osv-live'), osvMode:OsvMode=liveOsv?'live':args.includes('--osv-offline')?'offline':'off', phase=args.includes('--final')?'final':'dev', selected = name === 'all' ? names.filter(n=>phase==='final'||!(negativeHoldoutTargets as readonly string[]).includes(n)) : [name], results: TargetResult[] = [];
    for (const name of selected) {
        const result = localTargets.includes(name as typeof localTargets[number]) ? await scanLocalTarget(name, osvMode,phase) : await scanDockerTarget(name as DockerTarget);
        results.push(result);
        if(result.osvDiagnostics?.length)console.error(JSON.stringify({target:name,OSV:result.osvDiagnostics}));
        console.log(JSON.stringify({ target: result.target, status: result.status, durationMs: result.durationMs, reason: result.reason ?? null, falsePositives: result.metrics?.falsePositives ?? null }));
    }
    const splitMetrics=phase==='final'?Object.fromEntries(results.filter(r=>r.target==='seeded').map(r=>[r.target,Object.fromEntries(['dev','holdout'].map(split=>{const expected=readExpected(r.target).findings.filter(e=>e.split===split),files=new Set(expected.map(e=>e.location.replace(/:\d+$/,''))),actual=r.actual.filter(e=>files.has(e.location.replace(/:\d+$/,'')));return [split,reportScore(expected,actual,r.unmeasuredCategories)];}))])):undefined;
    const report = { schema: 'aegis-benchmark-v1', scannerVersion: '0.12.0', sourceBase: 'b2fcb2f', generatedAt: new Date().toISOString(), profile: 'local-repository-snapshot-and-optional-isolated-http', liveOsv,osvMode,phase,splitMetrics, partial: results.some(r => r.status !== 'completed'), results, aggregate: summarize(results), limitations: ['No Docker target is reported clean when it did not run.', 'Empty Docker expected arrays are pending annotations, not clean negative sets.', 'LocalReader hashes a content snapshot; it does not scan git history.', 'Quality metrics exclude explicitly unmeasured dependency rows; raw target metrics retain all expected counts.', 'Location matching is category plus normalized file:line; it does not establish exploitability.'] };
    const json = JSON.stringify(report, null, 2) + '\n';
    for (const secret of Object.values(fakeCredentials()))
        if (json.includes(secret))
            throw new Error('Benchmark output would disclose a fixture credential');
    const output = resolve(flag('--output', resolve(benchmarkRoot, 'runs', 'latest.json')));
    mkdirSync(dirname(output), { recursive: true });
    writeFileSync(output, json);
    console.log(JSON.stringify({ output, aggregate: report.aggregate }));
    return report;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
    main().then(report=>{if(report.results.some(r=>r.unmeasuredCategories.includes('dependency')&&r.expected.some(e=>e.category==='dependency')))process.exitCode=2;}).catch(() => { console.error('Benchmark failed; check BENCHMARK_MODE/NODE_ENV, fixture prerequisites and output path. No raw target content printed.'); process.exitCode = 1; });
