import { describe, it, expect } from 'vitest';
import { MissionControl, detectObjectiveClass, createAuthorizationObjectiveTasks, deriveObjectiveOutcome } from '../mission/index.js';
import { gateLiveFinding } from '../evidence/gate.js';
import { assessClaimSupport, auditedSeverity, capabilitySupported, findingFingerprint } from '../evidence/classification.js';
import { EvidenceVault } from '../evidence/index.js';
import { KillChainPhase, type Finding } from '../types/index.js';

// ─────────────────────────────────────────────────────────────────────────────
// MISSION-FIDELITY REGRESSION — the generic equivalent of the review scenario:
//   Directive: "Focus on authenticated authorization lifecycle testing. Avoid generic
//   configuration findings unless they directly enable the authorization objective."
// Pins the invariants the Danalock run violated: objective-driven tasking, bounded recon,
// explicit blocked prerequisites, evidence/category consistency, truthful verifyGate, dedup,
// and an honest objective outcome. NO Danalock/target-specific logic anywhere.
// ─────────────────────────────────────────────────────────────────────────────

function authzFinding(over: Partial<Finding>): Finding {
  return {
    id: '',
    title: 'x',
    description: 'x',
    severity: 'high',
    targetId: 'https://staging.api.example.test',
    operatorId: 'op',
    phase: KillChainPhase.EXPLOIT,
    evidence: [],
    discoveredAt: Date.now(),
    ...over,
  } as Finding;
}

describe('objective class detection is orthogonal to mission family', () => {
  it('recognizes an authorization-lifecycle objective from generic authz language', () => {
    expect(detectObjectiveClass('Test authenticated BOLA / cross-user authorization lifecycle and revocation')).toBe('authorization_lifecycle');
    expect(detectObjectiveClass('Verify role boundaries and permission downgrade handling')).toBe('authorization_lifecycle');
  });
  it('does NOT widen into authz for an unrelated objective', () => {
    expect(detectObjectiveClass('Map the external attack surface and find XSS')).toBe('general');
    expect(detectObjectiveClass('')).toBe('general');
  });
});

describe('objective lane — narrow authorization directive does NOT produce generic recon', () => {
  it('seeds the authorization objective lane (bounded prereq + baseline + blocked prerequisites), not the recon battery', () => {
    const mc = new MissionControl();
    const m = mc.createMission({ name: 'authz', objectives: ['authenticated authorization lifecycle testing'], objectiveClass: 'authorization_lifecycle' });
    mc.startMission(m.id);
    mc.generateTasksForTarget('https://staging.api.example.test');

    const tasks = mc.getTaskQueue().getForMission(m.id);
    const names = tasks.map((t) => t.name).join('\n');
    // Objective lane present
    expect(names).toContain('current-principal access map');
    expect(names).toContain('BLOCKED prerequisite: cross-principal');
    expect(names).toContain('BLOCKED prerequisite: authorization lifecycle');
    // Generic recon battery NOT seeded
    expect(names).not.toContain('DNS Enumeration');
    expect(names).not.toContain('Port Scanning & Service Detection');
    expect(names).not.toContain('Content Discovery');
    // All objective tasks carry the lane tag
    for (const t of tasks) expect(t.description).toContain('[objective:authorization_lifecycle]');
  });

  it('a general objective still seeds the standard recon battery (no regression)', () => {
    const mc = new MissionControl();
    const m = mc.createMission({ name: 'gen', objectives: ['enumerate attack surface'], objectiveClass: 'general' });
    mc.startMission(m.id);
    mc.generateTasksForTarget('https://target.test');
    const names = mc.getTaskQueue().getForMission(m.id).map((t) => t.name).join('\n');
    expect(names).toContain('DNS Enumeration');
    expect(names).toContain('Port Scanning & Service Detection');
  });

  it('does not advance into generic vuln/exploit batteries for an authorization mission', () => {
    const mc = new MissionControl();
    const m = mc.createMission({ name: 'authz2', objectives: ['authorization lifecycle'], objectiveClass: 'authorization_lifecycle' });
    mc.startMission(m.id);
    mc.generateNextPhaseTasks('https://staging.api.example.test'); // currentPhase = recon -> no-op
    const names = mc.getTaskQueue().getForMission(m.id).map((t) => t.name).join('\n');
    expect(names).not.toContain('Automated Vulnerability Scan');
    expect(names).not.toContain('Exploit Confirmed Vulnerabilities');
  });
});

describe('objective outcome — completion is not merely "tasks drained"', () => {
  it('reports BLOCKED when the differential prerequisites never ran', () => {
    const mc = new MissionControl();
    const m = mc.createMission({ name: 'authz3', objectives: ['authorization lifecycle'], objectiveClass: 'authorization_lifecycle' });
    mc.startMission(m.id);
    mc.generateTasksForTarget('https://staging.api.example.test');
    const tasks = mc.getTaskQueue().getForMission(m.id);
    // Only the prerequisite lane completed; the blocked prerequisites stayed pending.
    const outcome = deriveObjectiveOutcome(m, tasks);
    expect(['blocked', 'untested', 'partial']).toContain(outcome);
    expect(outcome).not.toBe('met');
  });
});

describe('evidence/category consistency — a claim must not outrun its evidence', () => {
  it('cleartext-HTTP evidence can NEVER satisfy an RCE claim', () => {
    const f = authzFinding({
      title: 'cleartext http available',
      category: 'rce',
      severity: 'critical',
      evidence: [{ type: 'output', content: 'HTTP/1.1 200 OK over plain http:// (no TLS)', timestamp: Date.now() }],
    });
    const support = assessClaimSupport(f);
    expect(support.category).toBe('rce');
    expect(support.supportLevel).toBe('unsupported');
    expect(support.severityCap).toBe('info');
    expect(auditedSeverity(f)).toBe('info');
    expect(capabilitySupported(f)).toBe(false);
  });

  it('permissive CORS reflection does not become a credential finding', () => {
    const f = authzFinding({
      title: 'CORS Misconfiguration',
      category: 'credential',
      severity: 'high',
      evidence: [{ type: 'response', content: 'access-control-allow-origin: https://evil.com\naccess-control-allow-credentials: true', timestamp: Date.now() }],
    });
    const support = assessClaimSupport(f);
    // claimed as credential but evidence is a CORS reflection -> unsupported as credential
    expect(support.supportLevel).toBe('unsupported');
    expect(capabilitySupported(f)).toBe(false);
  });

  it('a genuine SQLi signal IS supported (gate is not a blanket down-scorer)', () => {
    const f = authzFinding({
      title: 'SQL injection',
      category: 'sqli',
      severity: 'critical',
      evidence: [{ type: 'output', content: "MySQL server version for the right syntax to use near '' at line 1", timestamp: Date.now() }],
    });
    const support = assessClaimSupport(f);
    expect(support.supportLevel).toBe('supported');
    expect(capabilitySupported(f)).toBe(true);
  });

  it('the live gate: provenance passes but capability is denied for an outrunning claim', () => {
    const f = authzFinding({
      title: 'cleartext http',
      category: 'rce',
      severity: 'critical',
      evidence: [{ type: 'output', content: 'plain http reachable', timestamp: Date.now() }],
    });
    const gate = gateLiveFinding(f);
    expect(gate.provenance).toBe('tool');        // provenance present
    expect(gate.capabilityVerified).toBe(false); // but capability not demonstrated
    expect(gate.support.supportLevel).toBe('unsupported');
  });
});

describe('dedup fingerprint — repeated evidence consolidates, distinct authz failures never merge', () => {
  const ev = (route: string, extra = '') => [{ type: 'response' as const, content: `GET https://staging.api.example.test${route} 200 ${extra}`, timestamp: Date.now() }];

  it('same origin+route+method+property consolidates into one record', () => {
    const vault = new EvidenceVault();
    const a = authzFinding({ title: 'CORS Misconfiguration', category: 'cors', evidence: ev('/api/users') });
    const b = authzFinding({ title: 'CORS Misconfiguration', category: 'cors', evidence: ev('/api/users') });
    const ra = vault.addFinding(a);
    const rb = vault.addFinding(b);
    expect(rb.id).toBe(ra.id); // merged
    expect(vault.getAllFindings()).toHaveLength(1);
    expect(vault.consolidatedFindings).toBe(1);
  });

  it('different routes do NOT merge', () => {
    const vault = new EvidenceVault();
    const a = vault.addFinding(authzFinding({ title: 'authz', category: 'authz', evidence: ev('/api/users/1/ekey') }));
    const b = vault.addFinding(authzFinding({ title: 'authz', category: 'authz', evidence: ev('/api/users/1/profile') }));
    expect(b.id).not.toBe(a.id);
    expect(vault.getAllFindings()).toHaveLength(2);
  });

  it('numeric/UUID route segments collapse (same route shape), so /users/1 and /users/2 consolidate', () => {
    const fa = findingFingerprint({ targetId: 'api', category: 'authz', evidence: [{ type: 'response', content: 'https://api.test/users/1', timestamp: 0 }] });
    const fb = findingFingerprint({ targetId: 'api', category: 'authz', evidence: [{ type: 'response', content: 'https://api.test/users/2', timestamp: 0 }] });
    expect(fa).toBe(fb);
  });

  it('a distinct principal->resource boundary never collapses onto another', () => {
    const fa = findingFingerprint({ targetId: 'api', category: 'authz', evidence: [{ type: 'response', content: 'https://api.test/x', timestamp: 0, metadata: { boundary: 'B->A:ekey' } }] });
    const fb = findingFingerprint({ targetId: 'api', category: 'authz', evidence: [{ type: 'response', content: 'https://api.test/x', timestamp: 0, metadata: { boundary: 'A->B:ekey' } }] });
    expect(fa).not.toBe(fb);
  });
});

describe('authorization lane tasks are honest about prerequisites', () => {
  it('the blocked prerequisites explicitly refuse to fabricate A/B coverage', () => {
    const tasks = createAuthorizationObjectiveTasks('m', 'https://staging.api.example.test');
    const crossPrincipal = tasks.find((t) => t.name.includes('cross-principal'));
    expect(crossPrincipal).toBeDefined();
    expect(crossPrincipal!.description).toMatch(/CANNOT be executed/i);
    expect(crossPrincipal!.description).toMatch(/DO NOT substitute generic recon/i);
  });
});
