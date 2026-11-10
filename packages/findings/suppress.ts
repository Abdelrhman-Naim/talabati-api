import type { Finding, Suppression } from './schema';
export function suppress(findings: Finding[], suppressions: Suppression[], now = Date.now()) { const active = new Set(suppressions.filter(s => s.reason.trim() && (!s.expiresAt || s.expiresAt > now)).map(s => s.fingerprint)); return findings.map(f => ({ ...f, status: active.has(f.fingerprint) ? 'suppressed' as const : 'open' as const })); }
