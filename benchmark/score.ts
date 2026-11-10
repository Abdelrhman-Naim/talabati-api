export const categories = ['secret', 'api', 'code', 'dependency', 'config'] as const;
export type BenchmarkCategory = typeof categories[number];
export type ExpectedFinding = {
    id: string;
    category: BenchmarkCategory;
    location: string;
    severity: string;
};
export type BenchmarkFinding = ExpectedFinding & {
    rule?: string;
};
export function normalizeLocation(location: string) { let text = location.replaceAll('\\', '/').replace(/^\.\//, ''); text = text.replace(/#L(\d+)$/, ':$1').replace(/\/+/g, '/'); return text; }
export function scoreRun(expected: ExpectedFinding[], actual: BenchmarkFinding[]) {
    const available = expected.map(e => ({ ...e, location: normalizeLocation(e.location) })), used = new Set<number>();
    let truePositives = 0, highCorrect = 0;
    for (const a of actual) {
        const index = available.findIndex((e, i) => !used.has(i) && e.category === a.category && e.location === normalizeLocation(a.location));
        if (index >= 0) {
            used.add(index);
            truePositives++;
            if (['high', 'critical'].includes(a.severity))
                highCorrect++;
        }
    }
    const highTotal = actual.filter(a => ['high', 'critical'].includes(a.severity)).length;
    const byCategory = Object.fromEntries(categories.map(category => { const e = expected.filter(f => f.category === category), a = actual.filter(f => f.category === category), matched = [...used].filter(i => available[i].category === category).length; return [category, { expected: e.length, actual: a.length, truePositives: matched, falseNegatives: e.length - matched, falsePositives: a.length - matched, recall: e.length ? matched / e.length : 0, precision: a.length ? matched / a.length : 0 }]; }));
    return { expected: expected.length, actual: actual.length, truePositives, falseNegatives: expected.length - truePositives, falsePositives: actual.length - truePositives, recall: expected.length ? truePositives / expected.length : 0, precision: actual.length ? truePositives / actual.length : 0, highCriticalPrecision: highTotal ? highCorrect / highTotal : null, byCategory };
}
