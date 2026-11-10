import type { Finding } from '../src/lib/types';
import type { BenchmarkFinding, BenchmarkCategory } from './score';
export function benchmarkCategory(rule: string): BenchmarkCategory | null {
    if (['repo.secret', 'repo.public-secret', 'security.secret'].includes(rule))
        return 'secret';
    if (rule.startsWith('repo.osv.'))
        return 'dependency';
    if (['repo.eval', 'repo.html-sink', 'repo.sql-concat', 'repo.shell', 'repo.weak-hash'].includes(rule))
        return 'code';
    if (/^(repo\.jwt-|repo\.cors-|security\.api-|security\.supabase-)/.test(rule))
        return 'api';
    if (rule.startsWith('repo.') || rule.startsWith('security.'))
        return 'config';
    return null;
}
export function adaptFindings(findings: Finding[]): BenchmarkFinding[] {
    return findings.flatMap(f => {
        const category = benchmarkCategory(f.rule);
        if (!category)
            return [];
        const location = f.file ? f.file + ':' + (f.line ?? 1) : new URL(f.url).pathname;
        return [{ id: f.id, category, location, severity: f.severity, rule: f.rule }];
    });
}
