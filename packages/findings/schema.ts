import { z } from 'zod';
export const SeveritySchema = z.enum(['info', 'low', 'medium', 'high', 'critical']);
export const FindingSchema = z.object({ id: z.string().min(1), tool: z.string().min(1), rule: z.string().min(1), category: z.string().min(1), severity: SeveritySchema, confidence: z.number().finite().min(0).max(1), location: z.string(), redactedEvidence: z.string(), fingerprint: z.string().regex(/^[a-f0-9]{64}$/), fix: z.string(), status: z.enum(['open', 'suppressed']) });
export type Finding = z.infer<typeof FindingSchema>;
export const RawFindingSchema = z.object({ rule: z.string().min(1), category: z.string().min(1), severity: SeveritySchema, location: z.string(), evidence: z.string(), fix: z.string(), context: z.boolean().optional(), secrets: z.array(z.string().min(1)).optional() });
export type RawFinding = z.infer<typeof RawFindingSchema>;
export type RawToolResult = {
    tool: string;
    state: 'ok' | 'incomplete' | 'failed';
    findings: RawFinding[];
};
export type Suppression = {
    fingerprint: string;
    reason: string;
    expiresAt?: number;
};
