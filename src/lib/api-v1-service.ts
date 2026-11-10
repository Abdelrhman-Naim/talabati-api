import { analyze } from './audit';
import { analyzeSource } from './repository/analyzer';
import { collect, validateTarget } from './network';
import { summarizeChecks, SCORE_VERSION } from './scoring';
import type { AuditCheck, Finding, Severity } from './types';

export interface CodeScanRequest {
  code: string;
  filename?: string;
  language?: string;
}

export interface UrlScanRequest {
  url: string;
  mode?: 'quick' | 'full';
}

export interface UniversalScanRequest {
  url?: string;
  code?: string;
  filename?: string;
  language?: string;
  mode?: 'quick' | 'full';
}

export interface ScanResultResponse {
  success: boolean;
  type: 'url' | 'code';
  target: string;
  score: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  summary: {
    passed: number;
    failed: number;
    totalFindings: number;
    severityCounts: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
  findings: Array<{
    id: string;
    rule: string;
    severity: Severity;
    title: string;
    description?: string;
    evidence?: string;
    recommendation?: string;
    line?: number;
    file?: string;
  }>;
  securityHeaders?: Record<string, boolean | string>;
  checks: Array<{
    rule: string;
    title: string;
    status: string;
    severity?: Severity;
    evidence?: string;
  }>;
  durationMs: number;
  timestamp: string;
}

function calculateGrade(score: number): 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

export function scanCodeSnippet(code: string, filename = 'snippet.js'): ScanResultResponse {
  const start = Date.now();
  const cleanFilename = filename.trim() || 'snippet.js';
  const result = analyzeSource(cleanFilename, code, 'direct-api-input');
  const summary = summarizeChecks(result.checks);
  
  const score = summary.overall.score ?? 100;
  const grade = calculateGrade(score);

  const severityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  for (const f of result.findings) {
    if (f.rule === 'repo.secret' || (f.severity === 'high' && f.rule.includes('injection'))) {
      severityCounts.critical++;
    } else if (f.severity === 'high') {
      severityCounts.high++;
    } else if (f.severity === 'medium') {
      severityCounts.medium++;
    } else {
      severityCounts.low++;
    }
  }

  return {
    success: true,
    type: 'code',
    target: cleanFilename,
    score,
    grade,
    summary: {
      passed: summary.overall.passed,
      failed: summary.overall.failed,
      totalFindings: result.findings.length,
      severityCounts,
    },
    findings: result.findings.map(f => ({
      id: f.id,
      rule: f.rule,
      severity: f.severity,
      title: f.title,
      description: f.description,
      evidence: f.evidence,
      recommendation: f.recommendation,
      line: f.line,
      file: f.file,
    })),
    checks: result.checks.map(c => ({
      rule: c.rule,
      title: c.title,
      status: c.status,
      severity: c.severity,
      evidence: c.evidence,
    })),
    durationMs: Date.now() - start,
    timestamp: new Date().toISOString(),
  };
}

export async function scanUrlTarget(rawUrl: string, signal?: AbortSignal): Promise<ScanResultResponse> {
  const start = Date.now();
  const validated = validateTarget(rawUrl);
  const targetHref = validated.href;
  const targetOrigin = validated.origin;

  const page = await collect(targetHref, targetOrigin, 0, { signal });
  const audit = analyze(page);
  const summary = summarizeChecks(audit.checks);

  const score = summary.overall.score ?? 100;
  const grade = calculateGrade(score);

  const severityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  for (const f of audit.findings) {
    if (f.rule === 'security.secret') {
      severityCounts.critical++;
    } else if (f.severity === 'high') {
      severityCounts.high++;
    } else if (f.severity === 'medium') {
      severityCounts.medium++;
    } else {
      severityCounts.low++;
    }
  }

  const h = page.headers;
  const securityHeaders = {
    contentSecurityPolicy: Boolean(h['content-security-policy']),
    strictTransportSecurity: Boolean(h['strict-transport-security']),
    xFrameOptions: h['x-frame-options'] || false,
    xContentTypeOptions: Boolean(h['x-content-type-options']),
    cors: h['access-control-allow-origin'] || 'not-set',
    server: h['server'] || 'hidden',
  };

  return {
    success: true,
    type: 'url',
    target: targetHref,
    score,
    grade,
    summary: {
      passed: summary.overall.passed,
      failed: summary.overall.failed,
      totalFindings: audit.findings.length,
      severityCounts,
    },
    findings: audit.findings.map(f => ({
      id: f.id,
      rule: f.rule,
      severity: f.severity,
      title: f.title,
      description: f.description,
      evidence: f.evidence,
      recommendation: f.recommendation,
    })),
    securityHeaders,
    checks: audit.checks.map(c => ({
      rule: c.rule,
      title: c.title,
      status: c.status,
      severity: c.severity,
      evidence: c.evidence,
    })),
    durationMs: Date.now() - start,
    timestamp: new Date().toISOString(),
  };
}
