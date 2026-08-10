import { describe, it, expect } from 'vitest';
import { createOperator } from '../operators/index.js';
import type { Finding } from '../types/index.js';

// ─────────────────────────────────────────────────────────────────────────────
// HONESTY SPINE — LOAD-BEARING IN THE LIVE PATH.
//
// The provenance gate (gateLiveFinding) must run where findings are CREATED, not as
// an opt-in verifyFinding(id) call nothing invokes. This test pins that invariant to
// the operator's recordFinding chokepoint — the same path executeTask() uses to record
// every agent finding. A model-asserted finding (no tool evidence) must be recorded
// UNVERIFIED; a tool-backed finding must verify. If this regresses, a model can assert a
// "critical" into the record for free again — the exact failure the whole project prevents.
// ─────────────────────────────────────────────────────────────────────────────

function baseFinding(over: Partial<Finding>): Finding {
  return {
    id: '',
    title: 'x',
    description: 'x',
    severity: 'high',
    targetId: 't',
    operatorId: 'o',
    phase: 'exploitation',
    evidence: [],
    discoveredAt: Date.now(),
    ...over,
  } as Finding;
}

describe('honesty spine is load-bearing at finding creation (operator.recordFinding)', () => {
  it('a model-asserted finding (no tool evidence) is recorded UNVERIFIED with gate reasons', () => {
    const op = createOperator('test-recon', 'recon');
    let blocked: { reasons: string[] } | undefined;
    op.on('finding:gate-blocked', (e) => { blocked = e; });

    const f = baseFinding({ title: 'model says critical', severity: 'critical', evidence: [] });
    op.recordFinding(f);

    expect(f.verifyGate?.passed).toBe(false);
    expect(f.verifiedAt).toBeUndefined();
    expect(f.verifyGate?.provenance).toBe('none');
    expect(blocked, 'a gate-blocked event must fire for an unbacked finding').toBeDefined();
    expect(blocked!.reasons.join(' ')).toMatch(/provenance|evidence/i);
  });

  it('a tool-backed finding whose evidence supports the category verifies (capability)', () => {
    const op = createOperator('test-recon2', 'recon');
    const f = baseFinding({
      title: 'SQL injection confirmed via database error',
      severity: 'high',
      cwe: ['CWE-89'],
      evidence: [{ type: 'output', content: 'ERROR: SQL syntax error near ... MySQL server version for the right syntax', timestamp: Date.now() }],
    });
    op.recordFinding(f);

    expect(f.verifyGate?.passed).toBe(true);
    expect(f.verifyGate?.provenance).toBe('tool');
    expect(f.claimSupport?.supportLevel).toBe('supported');
    expect(f.verifiedAt).toBeTypeOf('number');
  });

  it('a tool-backed observation whose category outruns its evidence is tool-proven but NOT capability-verified', () => {
    const op = createOperator('test-recon2b', 'recon');
    const f = baseFinding({
      title: 'cleartext HTTP available',
      category: 'rce',
      severity: 'critical',
      evidence: [{ type: 'output', content: 'HTTP/1.1 200 OK — server responded over plain http:// (no TLS)', timestamp: Date.now() }],
    });
    op.recordFinding(f);

    // provenance passes (real tool output), but the RCE claim is unsupported → not capability verified
    expect(f.verifyGate?.provenance).toBe('tool');
    expect(f.claimSupport?.category).toBe('rce');
    expect(f.claimSupport?.supportLevel).toBe('unsupported');
    expect(f.verifiedAt).toBeUndefined();
  });

  it('getVerified-style filter surfaces tool-proven findings via verifyGate.passed', () => {
    const op = createOperator('test-recon3', 'recon');
    op.recordFinding(baseFinding({ title: 'prose claim', evidence: [] }));
    op.recordFinding(baseFinding({ title: 'tool claim', evidence: [{ type: 'output', content: 'x'.repeat(20), timestamp: Date.now() }] }));
    const toolProven = op.getFindings().filter((f) => f.verifyGate?.passed);
    expect(toolProven.map((f) => f.title)).toEqual(['tool claim']);
    // but capability verification is a stricter bar — the bare "tool claim" has no capability signal
    const capabilityVerified = op.getFindings().filter((f) => f.verifiedAt);
    expect(capabilityVerified.map((f) => f.title)).toEqual([]);
  });
});
