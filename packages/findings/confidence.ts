// Calibration metadata only: never changes detector severity or pass/fail.
export const confidenceTable: Record<string, Record<string, number>> = { custom: { '*': 0.45, 'repo.secret': 0.65, 'repo.public-secret': 0.65 }, gitleaks: { '*': 0.8 }, semgrep: { '*': 0.75 }, osv: { '*': 0.95 } };
export function confidenceFor(tool: string, rule: string, context = false) { const table = confidenceTable[tool] ?? confidenceTable.custom; return Math.min(1, (table[rule] ?? table['*']) + (context && tool === 'custom' ? 0.1 : 0)); }
