import { describe, it, expect, vi } from 'vitest';

// The test sandbox's undici build throws on import (webidl.util.markAsUncloneable) — a pre-existing
// environment issue that breaks every index.js-importing test. The report/sitrep logic under test
// never touches the network, so stub undici's exports before any transitive import of index.js.
vi.mock('undici', () => ({
  Agent: class { },
  buildConnector: () => ({}),
  setGlobalDispatcher: () => { },
  fetch: (..._a: unknown[]) => Promise.reject(new Error('undici mocked in test')),
}));

import { readFileSync } from 'fs';
import { join } from 'path';
import {
  MissionControl,
  createReconTasks,
  deriveObjectiveCompletion,
} from '../mission/index.js';
import { EvidenceVault } from '../evidence/index.js';
import { sanitizeExternalFlags, scopeViolation } from '../arsenal/index.js';
import { findingFingerprint, auditedSeverity, capabilitySupported } from '../evidence/classification.js';
import { OpGeneral } from '../general/index.js';
import { LLMBackbone } from '../llm/index.js';
import {
  KillChainPhase,
  type Finding,
  type Mission,
  type PhaseDisposition,
  type Task,
} from '../types/index.js';

// ─────────────────────────────────────────────────────────────────────────────
// POST-COMPLETION CONSUMER / GENERAL OUTCOME RELIABILITY regression coverage.
//
// Pinned invariants from the completed general-mission integration run:
//   1. Report generation uses the TERMINAL mission (name, human target, real duration,
//      objective outcome, phase dispositions, task summary) — never stale "STANDBY"/00:00:00.
//   2. SITREP reasons from the terminal snapshot after completion — never "phase unknown".
//   3. A general mission with no_eligible_work phases never claims "full kill-chain coverage".
//   4. Evidence objects serialize intentionally (tool/timestamp/redacted content) — never
//      "[object Object]".
//   5. Reworded duplicate observations consolidate; unverified CORS cannot render as mature HIGH.
//   6. A general web_api mission WITH an auth context gains an additive bounded authenticated
//      baseline task WITHOUT becoming authorization_lifecycle.
//   7. curl_request safely represents "-D -" (and similar) argv forms.
//   8. ScopeGuard behavior is unchanged.
// ─────────────────────────────────────────────────────────────────────────────

const TARGET = 'https://api.example.test';

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: overrides.id ?? `f-${Math.random().toString(36).slice(2, 10)}`,
    title: 'Finding',
    description: 'Finding description',
    severity: 'medium',
    targetId: TARGET,
    operatorId: 'op-1',
    phase: KillChainPhase.RECON,
    evidence: [],
    discoveredAt: Date.now(),
    ...overrides,
  };
}

function makeTask(overrides: Partial<Task>): Task {
  return {
    id: overrides.id ?? `t-${Math.random().toString(36).slice(2, 10)}`,
    missionId: 'm-1',
    name: 'task',
    description: 'task',
    phase: KillChainPhase.RECON,
    operatorType: 'scanner',
    status: 'completed',
    priority: 5,
    dependencies: [],
    createdAt: Date.now(),
    ...overrides,
  };
}

function disposition(phase: KillChainPhase, d: PhaseDisposition['disposition'], total: number, completed: number): PhaseDisposition {
  return { phase, disposition: d, total, completed, failed: 0, blocked: 0, skipped: 0, recordedAt: Date.now() };
}

// ═══════════════════════════ 3. GENERAL OBJECTIVE OUTCOME SEMANTICS ═══════════════════════════

describe('general objective outcome — execution completed ≠ objective met', () => {
  const base = { objectiveClass: 'general' } as Mission;

  it('no_eligible_work phases with all planned work done → MET (empty phases are a legitimate negative result)', () => {
    const mission = {
      ...base,
      phaseDispositions: [
        disposition(KillChainPhase.RECON, 'executed', 4, 4),
        disposition(KillChainPhase.WEAPONIZE, 'executed', 1, 1),
        disposition(KillChainPhase.DELIVER, 'executed', 1, 1),
        disposition(KillChainPhase.EXPLOIT, 'no_eligible_work', 0, 0),
        disposition(KillChainPhase.INSTALL, 'no_eligible_work', 0, 0),
        disposition(KillChainPhase.C2, 'no_eligible_work', 0, 0),
        disposition(KillChainPhase.ACTIONS, 'executed', 2, 2),
      ],
    } as Mission;
    const tasks = [makeTask({}), makeTask({})];
    const c = deriveObjectiveCompletion(mission, tasks);
    // Recon found no exploit path — the broad research objective COMPLETED, truthfully.
    expect(c.outcome).toBe('met');
    expect(c.reason).toContain('all planned/eligible work completed');
    // Empty phases are named for transparency — but never downgrade the outcome…
    expect(c.reason).toContain('[exploitation, installation, command_and_control]');
    expect(c.reason).toContain('legitimate empty result');
    expect(c.reason).not.toContain('full kill-chain');
  });

  it('skipped planned work → PARTIAL (planned work not done degrades the outcome, not empty phases)', () => {
    const mission = {
      ...base,
      phaseDispositions: [
        disposition(KillChainPhase.RECON, 'executed', 4, 4),
        disposition(KillChainPhase.EXPLOIT, 'no_eligible_work', 0, 0),
      ],
    } as Mission;
    const c = deriveObjectiveCompletion(mission, [makeTask({}), makeTask({ status: 'skipped', required: false })]);
    expect(c.outcome).toBe('partial');
    expect(c.reason).toContain('1 task(s) skipped');
    expect(c.reason).not.toContain('full kill-chain');
  });

  it('failed optional planned work → PARTIAL', () => {
    const mission = {
      ...base,
      phaseDispositions: [disposition(KillChainPhase.RECON, 'executed', 4, 4)],
    } as Mission;
    const c = deriveObjectiveCompletion(mission, [makeTask({}), makeTask({ status: 'failed', required: false })]);
    expect(c.outcome).toBe('partial');
    expect(c.reason).toContain('1 optional task(s) failed');
  });

  it('all phases executed, no failures → MET with evidence-scoped reason (not blanket coverage)', () => {
    const mission = {
      ...base,
      phaseDispositions: [
        disposition(KillChainPhase.RECON, 'executed', 4, 4),
        disposition(KillChainPhase.ACTIONS, 'executed', 1, 1),
      ],
    } as Mission;
    const c = deriveObjectiveCompletion(mission, [makeTask({})]);
    expect(c.outcome).toBe('met');
    expect(c.reason).toContain('all planned/eligible work completed');
    expect(c.reason).toContain('evidence-backed findings');
    expect(c.reason).not.toContain('full kill-chain');
  });

  it('failed required work → UNRESOLVED (execution finished, objective not met)', () => {
    const mission = {
      ...base,
      phaseDispositions: [disposition(KillChainPhase.RECON, 'executed', 4, 3)],
    } as Mission;
    const c = deriveObjectiveCompletion(mission, [makeTask({}), makeTask({ status: 'failed' })]);
    expect(c.outcome).toBe('unresolved');
    expect(c.reason).toContain('1 failed required task(s)');
  });

  it('no eligible work anywhere → EXHAUSTED, no coverage claimed', () => {
    const mission = {
      ...base,
      phaseDispositions: [
        disposition(KillChainPhase.RECON, 'no_eligible_work', 0, 0),
        disposition(KillChainPhase.ACTIONS, 'no_eligible_work', 0, 0),
      ],
    } as Mission;
    const c = deriveObjectiveCompletion(mission, []);
    expect(c.outcome).toBe('exhausted');
    expect(c.reason).toContain('no coverage claimed');
  });

  it('legacy missions (no dispositions) keep the previous all-completed → MET behavior', () => {
    const mission = { ...base, phaseDispositions: undefined } as Mission;
    const c = deriveObjectiveCompletion(mission, [makeTask({})]);
    expect(c.outcome).toBe('met');
  });
});

// ═══════════════════════════ 5. FINDING DEDUP / MATURITY ═══════════════════════════

describe('finding dedup — reworded same-category observations consolidate', () => {
  it('three reworded CORS observations on one origin merge into ONE finding with merged evidence', () => {
    const vault = new EvidenceVault();
    vault.addFinding(makeFinding({ title: 'CORS Misconfiguration', category: 'cors', evidence: [{ type: 'output', content: 'ACAO reflects the request origin', timestamp: Date.now() }] }));
    vault.addFinding(makeFinding({ title: 'Credentialed CORS origin reflection', category: 'cors', evidence: [{ type: 'output', content: 'access-control-allow-credentials: true present', timestamp: Date.now() }] }));
    vault.addFinding(makeFinding({ title: 'Permissive credentialed CORS policy requires authenticated impact validation', category: 'cors', evidence: [{ type: 'output', content: 'arbitrary origin echoed with credentials', timestamp: Date.now() }] }));
    const all = vault.getAllFindings();
    expect(all.length).toBe(1);
    expect(vault.consolidatedFindings).toBe(2);
    expect(all[0].evidence.length).toBe(3);
  });

  it('fingerprint fallback: explicit category consolidates; derived category keeps distinct titles separate', () => {
    const base = { targetId: TARGET, evidence: [{ type: 'output' as const, content: 'probe output', timestamp: 1 }] };
    const explicitA = findingFingerprint({ ...base, title: 'CORS Misconfiguration', category: 'cors' });
    const explicitB = findingFingerprint({ ...base, title: 'Credentialed CORS origin reflection', category: 'cors' });
    expect(explicitA).toBe(explicitB);
    // No explicit category → title-derived → distinct titles stay distinct (no over-merge).
    const derivedA = findingFingerprint({ ...base, title: 'Reflected XSS in search' });
    const derivedB = findingFingerprint({ ...base, title: 'Stored XSS in comments' });
    expect(derivedA).not.toBe(derivedB);
  });

  it('distinct categories on the same origin never over-merge', () => {
    const base = { targetId: TARGET, evidence: [{ type: 'output' as const, content: 'probe', timestamp: 1 }] };
    expect(findingFingerprint({ ...base, title: 'CORS Misconfiguration', category: 'cors' }))
      .not.toBe(findingFingerprint({ ...base, title: 'Version disclosure', category: 'info_disclosure' }));
  });

  it('same-category observations on DIFFERENT routes stay distinct; the SAME route consolidates', () => {
    const vault = new EvidenceVault();
    vault.addFinding(makeFinding({
      title: 'CORS Misconfiguration', category: 'cors',
      evidence: [{ type: 'output', content: 'acao reflection observed at https://api.example.test/', timestamp: Date.now() }],
    }));
    vault.addFinding(makeFinding({
      title: 'Credentialed CORS on OAuth authorization endpoint', category: 'cors',
      evidence: [{ type: 'output', content: 'acao reflection observed at https://api.example.test/oauth2/authorize', timestamp: Date.now() }],
    }));
    // `/` vs `/oauth2/authorize` are genuinely different boundaries — never consolidated.
    expect(vault.getAllFindings().length).toBe(2);
    // A reworded third observation on the SAME route consolidates into the first.
    vault.addFinding(makeFinding({
      title: 'Permissive credentialed CORS policy', category: 'cors',
      evidence: [{ type: 'output', content: 'different prose, same boundary: https://api.example.test/ shows ACAO:*', timestamp: Date.now() }],
    }));
    expect(vault.getAllFindings().length).toBe(2);
    expect(vault.consolidatedFindings).toBe(1);
  });

  it('REAL ingestion path: nuclei CORS on / + second-tool CORS on / merge into ONE candidate; /oauth2/authorize stays DISTINCT', async () => {
    // Exercises the actual new ingestion path end-to-end:
    //   nuclei JSONL → parseToolOutput (canonical category) → operator-style Finding conversion
    //   → EvidenceVault.addFinding fingerprint merge.
    const { parseToolOutput } = await import('../arsenal/parsers.js');

    // ── Tool/Nuclei observation: CORS on / ──────────────────────────────────────
    const nucleiLine = JSON.stringify({
      'template-id': 'cors-misconfig',
      host: 'https://api.example.test',
      'matched-at': 'https://api.example.test/',
      info: { name: 'CORS Misconfiguration', severity: 'medium', tags: ['cors', 'misconfig'] },
    });
    const nucleiFindings = parseToolOutput('nuclei', nucleiLine);
    expect(nucleiFindings.length).toBe(1);
    expect(nucleiFindings[0].category).toBe('cors'); // canonical category derived, not title-slug

    // Operator conversion (mirrors src/operators/index.ts: tool-backed finding → Finding).
    const toFinding = (tf: ReturnType<typeof parseToolOutput>[number], tool: string) => makeFinding({
      title: tf.title,
      severity: tf.severity,
      category: tf.category,
      evidence: [{ type: 'output', content: tf.details, timestamp: Date.now(), metadata: { tool } }],
    });
    const stored1 = toFinding(nucleiFindings[0], 'nuclei');
    const vault = new EvidenceVault(); // (single vault for the whole scenario)
    vault.addFinding(stored1);
    expect(vault.getAllFindings().length).toBe(1);

    // ── Second tool observation: SAME CORS condition on / (reworded template) ──
    const nucleiLine2 = JSON.stringify({
      'template-id': 'cors-any-origin-with-credentials',
      host: 'https://api.example.test',
      'matched-at': 'https://api.example.test/',
      info: { name: 'Credentialed arbitrary-origin CORS', severity: 'high', tags: ['cors'], description: 'Reflected origin with ACAC:true observed' },
    });
    const second = parseToolOutput('nuclei', nucleiLine2);
    expect(second.length).toBe(1);
    expect(second[0].category).toBe('cors');
    vault.addFinding(toFinding(second[0], 'nuclei'));
    // ONE canonical candidate, both evidence observations attached, asserted severity deflated.
    expect(vault.getAllFindings().length).toBe(1);
    expect(vault.consolidatedFindings).toBe(1);
    expect(vault.getAllFindings()[0].evidence.length).toBe(2);

    // ── Same category on a GENUINELY different route stays a DISTINCT candidate ──
    const nucleiLine3 = JSON.stringify({
      'template-id': 'cors-misconfig',
      host: 'https://api.example.test',
      'matched-at': 'https://api.example.test/oauth2/authorize',
      info: { name: 'CORS Misconfiguration', severity: 'medium', tags: ['cors'] },
    });
    const third = parseToolOutput('nuclei', nucleiLine3);
    vault.addFinding(toFinding(third[0], 'nuclei'));
    expect(vault.getAllFindings().length).toBe(2);
    expect(vault.consolidatedFindings).toBe(1); // unchanged — the /oauth2/authorize row is new
  });
});

describe('finding maturity — unverified CORS cannot be mature HIGH', () => {
  it('asserted-HIGH CORS with NO evidence caps to info and cannot capability-verify', () => {
    const vault = new EvidenceVault();
    const stored = vault.addFinding(makeFinding({
      title: 'Credentialed arbitrary-origin CORS on OAuth authorization endpoint',
      severity: 'high',
      category: 'cors',
      evidence: [],
    }));
    expect(stored.claimSupport?.supportLevel).toBe('unverifiable');
    expect(auditedSeverity(stored)).toBe('info');
    expect(capabilitySupported(stored)).toBe(false);
  });

  it('reflected ACAO + ACAC:true WITHOUT a demonstrated sensitive cross-origin read caps at LOW (never medium/high/critical)', () => {
    const vault = new EvidenceVault();
    const stored = vault.addFinding(makeFinding({
      title: 'Credentialed CORS origin reflection',
      severity: 'high',
      category: 'cors',
      evidence: [{ type: 'response', content: 'HTTP/1.1 200 OK\naccess-control-allow-origin: https://attacker.example\naccess-control-allow-credentials: true', timestamp: Date.now() }],
    }));
    expect(stored.claimSupport?.supportLevel).toBe('supported');
    expect(capabilitySupported(stored)).toBe(false); // observation category — never a demonstrated capability
    // Required semantics: arbitrary/reflected ACAO + ACAC:true is a supported CONFIGURATION
    // observation, not demonstrated authenticated impact — INFO/LOW maximum. The scanner calling
    // the probe "with credentials" is NOT a demonstrated victim-browser sensitive read.
    expect(stored.claimSupport?.severityCap).toBe('low');
    expect(auditedSeverity(stored)).toBe('low');
    // Asserted severity is preserved separately (never rewritten away)…
    expect(stored.severity).toBe('high');
    // …and an asserted-CRITICAL observation of the same condition caps identically. (Evidence
    // origins differ — attacker.example vs evil.example — so these are two distinct boundaries
    // and MUST NOT merge; each is independently capped.)
    const critical = vault.addFinding(makeFinding({
      title: 'CORS reflection with credentials (critical asserted)',
      severity: 'critical',
      category: 'cors',
      evidence: [{ type: 'response', content: 'access-control-allow-origin: https://evil.example\naccess-control-allow-credentials: true', timestamp: Date.now() }],
    }));
    expect(critical.claimSupport?.supportLevel).toBe('supported');
    expect(critical.claimSupport?.severityCap).toBe('low');
    expect(auditedSeverity(critical)).toBe('low');
    expect(critical.severity).toBe('critical'); // asserted preserved
    expect(vault.getAllFindings().length).toBe(2);
  });

  it('plain CORS reflection/config evidence caps at low; swagger/version exposure caps at info', () => {
    const vault = new EvidenceVault();
    const cors = vault.addFinding(makeFinding({
      title: 'CORS Misconfiguration',
      severity: 'high',
      category: 'cors',
      evidence: [{ type: 'response', content: 'access-control-allow-origin: *', timestamp: Date.now() }],
    }));
    expect(cors.claimSupport?.supportLevel).toBe('supported');
    expect(auditedSeverity(cors)).toBe('low');

    const swagger = vault.addFinding(makeFinding({
      title: 'OpenAPI specification exposed',
      severity: 'critical',
      category: 'info_disclosure',
      evidence: [{ type: 'response', content: 'GET /swagger.json → {"openapi":"3.0.0"}', timestamp: Date.now() }],
    }));
    expect(swagger.claimSupport?.supportLevel).toBe('supported');
    expect(auditedSeverity(swagger)).toBe('info'); // exposure ≠ critical impact
    expect(swagger.severity).toBe('critical'); // asserted severity preserved separately
  });
});

// ═══════════════════════════ 6. AUTHENTICATED BASELINE IN GENERAL MISSIONS ═══════════════════════════

describe('general mission + auth context — additive bounded baseline, never authorization_lifecycle', () => {
  it('authContextAvailable adds the single-principal baseline task to the broad battery', () => {
    const tasks = createReconTasks('m-1', TARGET, { authContextAvailable: true });
    expect(tasks.length).toBe(5);
    expect(tasks.map(t => t.name)).toEqual(expect.arrayContaining([
      'DNS Enumeration', 'Port Scanning & Service Detection',
      'Web Probing & Technology Fingerprinting', 'Content Discovery',
      'Authenticated Surface Baseline (current principal)',
    ]));
    const baseline = tasks.find(t => t.name === 'Authenticated Surface Baseline (current principal)')!;
    expect(baseline.description).toContain('lane:baseline');
    expect(baseline.description).toContain('authContextApplied');
    expect(baseline.description).toContain('single-principal');
    expect(baseline.description).toContain('do NOT attempt cross-principal');
  });

  it('no auth context → unchanged broad battery (no baseline task)', () => {
    const tasks = createReconTasks('m-1', TARGET);
    expect(tasks.length).toBe(4);
    expect(tasks.find(t => t.name.includes('Authenticated Surface Baseline'))).toBeUndefined();
  });

  it('mission-level: general objectiveClass is preserved and the broad battery is retained', () => {
    const mc = new MissionControl();
    const mission = mc.createMission({ name: 'gen-auth', objectives: ['broad coverage'], objectiveClass: 'general' });
    mc.startMission(mission.id);
    mc.generateTasksForTarget(TARGET, { authContextAvailable: true });
    expect(mission.objectiveClass).toBe('general');
    const names = mc.getTaskQueue().getForMission(mission.id).map(t => t.name);
    expect(names).toContain('Authenticated Surface Baseline (current principal)');
    expect(names).toContain('DNS Enumeration');
  });
});

// ═══════════════════════════ 7. CURL ARGV SAFETY ═══════════════════════════

describe('sanitizeExternalFlags — curl "-D -" and attached-value safety', () => {
  it('drops a dangerous flag AND its bare "-" value (the reported malformed argv)', () => {
    // "-D -" is dropped together (no orphan "-" argv element); "-o /dev/null" is ALSO dropped —
    // output-file flags are file-write dangerous by the same policy. What remains is safe.
    expect(sanitizeExternalFlags('curl', '-sS -D - -o /dev/null --max-time 15'))
      .toEqual(['-sS', '--max-time', '15']);
  });

  it('drops attached dangerous values like "-Dfile" (pre-existing injection hole)', () => {
    expect(sanitizeExternalFlags('curl', '-sS -D/tmp/evil https://x'))
      .toEqual(['-sS', 'https://x']);
  });

  it('drops "--dump-header=-" style attached long-flag values', () => {
    expect(sanitizeExternalFlags('curl', '-sS --dump-header=- https://x'))
      .toEqual(['-sS', 'https://x']);
  });

  it('keeps legitimate flags and values intact', () => {
    expect(sanitizeExternalFlags('curl', '-sS -H "Authorization: Bearer x" --max-time 15 https://x'))
      .toEqual(['-sS', '-H', '"Authorization:', 'Bearer', 'x"', '--max-time', '15', 'https://x']);
  });

  it('orphan bare "-" tokens are never passed through as argv', () => {
    expect(sanitizeExternalFlags('curl', '-sS - https://x')).toEqual(['-sS', 'https://x']);
  });

  it('nmap: dangerous script flags consume their values; safe flags survive', () => {
    expect(sanitizeExternalFlags('nmap', '-sV --script /tmp/x --top-ports 100'))
      .toEqual(['-sV', '--top-ports', '100']);
  });
});

// ═══════════════ 1c. CURL END-TO-END ADAPTER REGRESSION (P7) ═══════════════
// The sanitizer unit tests above prove argv shape; this proves the REAL adapter path
// (Arsenal.execute → handler → real curl → local HTTP server) never surfaces the
// reported failure mode, and that a thrown tool error always carries its real message.

describe('curl_request end-to-end — real curl through Arsenal.execute', () => {
  it('executes "-sS -D - -o /dev/null --max-time 15" against a live server without an execution error', async () => {
    const { createServer } = await import('http');
    const { Arsenal, EXTERNAL_TOOLS, createToolContext } = await import('../arsenal/index.js');
    const server = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const arsenal = new Arsenal();
      const curl = EXTERNAL_TOOLS.find((t) => t.name === 'curl_request')!;
      arsenal.register(curl);
      const result = await arsenal.execute('curl_request', createToolContext(undefined, {
        url: `http://127.0.0.1:${port}/`,
        flags: '-sS -D - -o /dev/null --max-time 15',
      }));
      expect(result.success).toBe(true);
      expect(String(result.output)).toContain('200');
      expect(String(result.output)).toContain('"ok":true');
      expect(String(result.error ?? '')).not.toContain('option -');
    } finally {
      server.close();
    }
  });

  it('a non-zero curl exit returns a diagnostic error (exit code + stderr), never a bare throw', async () => {
    const { createServer } = await import('http');
    const { Arsenal, EXTERNAL_TOOLS, createToolContext } = await import('../arsenal/index.js');
    // Server that accepts then stalls — curl --max-time 2 forces exit 28 (timeout).
    const server = createServer(() => { /* never respond */ });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const arsenal = new Arsenal();
      arsenal.register(EXTERNAL_TOOLS.find((t) => t.name === 'curl_request')!);
      const result = await arsenal.execute('curl_request', createToolContext(undefined, {
        url: `http://127.0.0.1:${port}/hang`,
        flags: '-sS --max-time 2',
      }));
      expect(result.success).toBe(false);
      // Diagnostic: names the exit condition — NOT the destroyed generic "execution_error".
      expect(String(result.error)).toMatch(/curl exited|internal failure/);
    } finally {
      server.close();
    }
  }, 15000);

  it('P7 contract: thrown tool errors stay category-only (secret-safe); curl internal failures surface as diagnostic RESULTS', async () => {
    // Thrown-error text is untrusted (may carry arbitrary secrets) — the agent loop must never
    // forward it verbatim (pinned by agent-error-feedback.test.ts). The curl handler therefore
    // converts any internal throw into a redacted diagnostic RESULT instead of throwing.
    const agentSrc = readFileSync(join(__dirname, '..', 'agent', 'index.ts'), 'utf8');
    expect(agentSrc).toContain('message: `Tool execution failed: ${err.category}`');
    expect(agentSrc).not.toContain('message: err.message');
    const arsenalSrc = readFileSync(join(__dirname, '..', 'arsenal', 'index.ts'), 'utf8');
    expect(arsenalSrc).toContain('curl_request internal failure:');
  });
});

// ═══════════════════════════ 1b. NMAP FULL-RANGE POLICY SEAM ═══════════════════════════

describe('nmap full-range — bounded by default, authorized through the planning/ROE seam', () => {
  it('detectFullRangeScanIntent matches explicit full-range language only', async () => {
    const { detectFullRangeScanIntent } = await import('../mission/index.js');
    // Explicit authorization language:
    expect(detectFullRangeScanIntent('perform a full port scan of all 65535 ports')).toBe(true);
    expect(detectFullRangeScanIntent('run a full-range port sweep')).toBe(true);
    expect(detectFullRangeScanIntent('scan all ports on the host')).toBe(true);
    expect(detectFullRangeScanIntent('enumerate every port')).toBe(true);
    expect(detectFullRangeScanIntent('use -p- for the sweep')).toBe(true);
    expect(detectFullRangeScanIntent('ports 1-65535')).toBe(true);
    // Broad vocabulary that must NOT authorize a sweep:
    expect(detectFullRangeScanIntent('comprehensive assessment of the target')).toBe(false);
    expect(detectFullRangeScanIntent('full-spectrum coverage across all vulnerability classes')).toBe(false);
    expect(detectFullRangeScanIntent('broad reconnaissance and service detection')).toBe(false);
    expect(detectFullRangeScanIntent('')).toBe(false);
  });

  it('createMission authorizes full-range from explicit directive language; broad directives stay bounded', async () => {
    const mc = new MissionControl();
    const authorized = mc.createMission({
      name: 'full-range', objectives: ['broad assessment; perform a full port scan of all 65535 ports'],
    });
    expect(authorized.allowFullRangeScans).toBe(true);
    const bounded = mc.createMission({
      name: 'bounded', objectives: ['comprehensive assessment; enumerate attack surface'],
    });
    expect(bounded.allowFullRangeScans).toBeUndefined();
    // Explicit param wins either way.
    const explicit = mc.createMission({ name: 'x', objectives: ['broad'], allowFullRangeScans: true });
    expect(explicit.allowFullRangeScans).toBe(true);
  });

  it('TempestCommand syncs the runtime scan policy with the active mission and clears it on stop', async () => {
    const mod = await import('../index.js');
    const arsenal = await import('../arsenal/index.js');
    const command = new mod.TempestCommand({
      name: 'Scan Policy Op', llm: { provider: 'mock', model: 'mock-model' }, allowFullRangeScans: true,
    }) as any;
    command.targetEnv.addTarget({
      id: 'target-1', name: 'api', type: 'api', zone: 'external', status: 'identified',
      address: TARGET, discoveredAt: Date.now(),
    });
    command.start();
    // The auto-created mission carries the authorization.
    expect(command.mission.getActiveMission()?.allowFullRangeScans).toBe(true);
    // Sync runs every tick; invoke it directly for a deterministic unit assertion.
    command.syncRuntimeScanPolicy(command.mission.getActiveMission());
    expect(arsenal.runtimeScanPolicy().fullRangeAuthorized).toBe(true);
    expect(arsenal.runtimeScanPolicy().authorizedBy).toContain('pacing/ROE');
    command.stop();
    // Authorization never leaks past the run that granted it.
    expect(arsenal.runtimeScanPolicy().fullRangeAuthorized).toBe(false);
  });

  it('a mission WITHOUT authorization leaves the bounded default in place', async () => {
    const mod = await import('../index.js');
    const arsenal = await import('../arsenal/index.js');
    const command = new mod.TempestCommand({
      name: 'Bounded Op', llm: { provider: 'mock', model: 'mock-model' },
    }) as any;
    command.targetEnv.addTarget({
      id: 'target-1', name: 'api', type: 'api', zone: 'external', status: 'identified',
      address: TARGET, discoveredAt: Date.now(),
    });
    command.start();
    expect(command.mission.getActiveMission()?.allowFullRangeScans).toBeUndefined();
    command.syncRuntimeScanPolicy(command.mission.getActiveMission());
    expect(arsenal.runtimeScanPolicy().fullRangeAuthorized).toBe(false);
    command.stop();
  });
});

// ═══════════════════════════ 8. SCOPEGUARD UNCHANGED ═══════════════════════════

describe('ScopeGuard — unchanged by the adapter/policy work', () => {
  it('still blocks out-of-scope hosts and allows the configured origin', () => {
    const scope = { allowedHosts: ['api.example.test'] } as any;
    expect(scopeViolation(scope, { target: { address: 'https://api.example.test' } } as any)).toBeNull();
    // Out-of-scope hosts (sibling host, derived IP) are still blocked — the violation names the host.
    expect(scopeViolation(scope, { target: { address: 'https://sibling.example.test' } } as any)).toBe('sibling.example.test');
    expect(scopeViolation(scope, { target: { address: 'https://203.0.113.9' } } as any)).toBe('203.0.113.9');
  });
});

// ═══════════════════════════ 1/2/4. REPORT + SITREP TERMINAL TRUTH (runtime) ═══════════════════════════

describe('post-completion report + SITREP — terminal mission is the authoritative source', () => {
  async function completedGeneralCommand() {
    const mod = await import('../index.js');
    const command = new mod.TempestCommand({ name: 'Report Op', llm: { provider: 'mock', model: 'mock-model' } }) as any;
    command.targetEnv.addTarget({
      id: 'target-1', name: 'api', type: 'api', zone: 'external', status: 'identified',
      address: TARGET, discoveredAt: Date.now(),
    });
    const mission = command.mission.createMission({
      name: 'Broad Coverage Op', objectives: ['comprehensive assessment'], objectiveClass: 'general', missionFamily: 'web_api',
    });
    command.mission.startMission(mission.id);
    command.mission.generateTasksForTarget(TARGET);
    // Non-zero duration: backdate the start by 65s.
    mission.startedAt = Date.now() - 65_000;
    const tq = command.mission.getTaskQueue();
    for (const t of tq.getForMission(mission.id)) tq.complete(t.id, { success: true, output: 'done' });
    command.mission.completeMission(mission.id);
    return { command, mission };
  }

  it('report uses terminal metadata: name, human target, non-zero duration, objective, phases, tasks', async () => {
    const { command } = await completedGeneralCommand();
    const report = command.generateReport();
    expect(report).toContain('# Broad Coverage Op — Mission Report');
    expect(report).toContain('**Target:** https://api.example.test');
    expect(report).not.toContain('target-1'); // never the internal UUID
    expect(report).toContain('**Duration:** 00:01:'); // 65s → 00:01:05
    expect(report).toContain('**Objective class:** general');
    expect(report).toContain('**Objective outcome:**');
    expect(report).toContain('**Completion reason:**');
    expect(report).toContain('**Phase dispositions:**');
    expect(report).toContain('**Tasks:** 4 total — 4 completed');
    expect(report).not.toContain('STANDBY');
  });

  it('report evidence blocks serialize intentionally — never "[object Object]"', async () => {
    const { command } = await completedGeneralCommand();
    command.vault.addFinding(makeFinding({
      title: 'Permissive CORS policy',
      category: 'cors',
      severity: 'high',
      evidence: [{
        type: 'response',
        content: 'HTTP/1.1 200 OK\naccess-control-allow-origin: *',
        timestamp: Date.now(),
        metadata: { tool: 'curl_request' },
      }],
    }));
    const report = command.generateReport();
    expect(report).not.toContain('[object Object]');
    expect(report).toContain('tool: curl_request');
    expect(report).toContain('access-control-allow-origin: *');
    // A supported CORS observation is reported as exactly that — never as a demonstrated capability.
    expect(report).toContain('**Verification:** evidence-supported observation — not a demonstrated capability');
  });

  it('report caps asserted severity that outruns evidence (audited severity in the summary)', async () => {
    const { command } = await completedGeneralCommand();
    command.vault.addFinding(makeFinding({
      title: 'Credentialed arbitrary-origin CORS',
      category: 'cors',
      severity: 'high',
      evidence: [], // no evidence → cap to info
    }));
    const report = command.generateReport();
    expect(report).toContain('(asserted HIGH');
    expect(report).toContain('**Verification:** unverified — no tool-backed evidence');
    // The audited summary table buckets by evidence-capped severity: zero HIGH, one INFO.
    expect(report).toContain('| High | 0 |');
    expect(report).toContain('| Info | 1 |');
  });

  it('SITREP after completion reasons from the terminal mission — never "phase unknown"', async () => {
    const { command } = await completedGeneralCommand();
    let captured = '';
    const llm = {
      prompt: async (p: string) => {
        captured = p;
        return '```json\n{"assessment":"complete","findingsSummary":"none","needsAdaptation":false,"adaptation":null,"confidence":90,"nextActions":["archive"]}\n```';
      },
    } as unknown as LLMBackbone;
    const general = new OpGeneral(llm);
    const sitrep = await general.produceSitrep(command);
    expect(sitrep.assessment).toBe('complete');
    expect(captured).toContain('"terminal": true');
    expect(captured).toContain('"status": "completed"');
    expect(captured).toContain('"objectiveClass": "general"');
    expect(captured).toContain('TERMINAL MISSION');
    expect(captured).not.toContain('"phase": "unknown"');
  });
});

// ═══════════════════════════ STATIC WIRING ASSERTIONS ═══════════════════════════

describe('static wiring — server, general, UI, arsenal', () => {
  const serverSource = readFileSync(join(__dirname, '../server.ts'), 'utf-8');
  const indexSource = readFileSync(join(__dirname, '../index.ts'), 'utf-8');
  const generalSource = readFileSync(join(__dirname, '../general/index.ts'), 'utf-8');
  const uiSource = readFileSync(join(__dirname, '../../docs/index.html'), 'utf-8');
  const arsenalSource = readFileSync(join(__dirname, '../arsenal/index.ts'), 'utf-8');

  it('generateReport falls back to the latest terminal mission and prepends metadata', () => {
    expect(indexSource).toContain('getLatestTerminalMission()');
    expect(indexSource).toContain('buildMissionReportPreamble');
  });

  it('/api/mission/findings resolves human target addresses and passes through central redaction', () => {
    const route = serverSource.slice(serverSource.indexOf("app.get('/api/mission/findings'"));
    expect(route.slice(0, 1200)).toContain('targetAddress');
    expect(route.slice(0, 1200)).toContain('redactSecrets');
  });

  it('the findings ledger mirror dedupes on the shared fingerprint', () => {
    expect(serverSource).toContain('findingFingerprint');
    expect(serverSource).toContain('record.fingerprint === fingerprint');
  });

  it('OpGeneral SITREP falls back to the terminal mission with an explicit terminal instruction', () => {
    expect(generalSource).toContain('getActiveMission() ?? command.mission.getLatestTerminalMission()');
    expect(generalSource).toContain('TERMINAL MISSION');
    expect(generalSource).toContain('objectiveOutcome: mission?.objectiveOutcome');
  });

  it('UI report exporter is terminal-aware with intentional evidence serialization', () => {
    expect(uiSource).toContain('async function exportMissionReport()');
    expect(uiSource).toContain('serializeEvidenceForReport');
    expect(uiSource).toContain('auditedSeverityForReport');
    expect(uiSource).toContain('st.terminalMission');
    expect(uiSource).toContain('term.phaseDispositions');
  });

  it('UI SITREP renders the completed mission from terminalMission (COMPLETE state)', () => {
    expect(uiSource).toContain("term = m.terminalMission || null");
    expect(uiSource).toContain("'COMPLETE'");
    expect(uiSource).toContain('Mission complete');
  });

  it('nmap full-range is bounded by default and authorized via the runtime scan policy seam', () => {
    // Default autonomous posture: clamp + loud annotation with the authorization path named.
    expect(arsenalSource).toContain("finalArgs.unshift('--top-ports', '1000')");
    expect(arsenalSource).toContain('[policy] Full-range (1-65535) scan requested');
    expect(arsenalSource).toContain('allowFullRangeScans');
    // The capability is preserved through the policy seam — not a hidden/manual hatch.
    expect(arsenalSource).toContain('runtimeScanPolicy()');
    expect(arsenalSource).toContain('sweep authorized by');
    expect(arsenalSource).toContain('export function setRuntimeScanPolicy');
    expect(arsenalSource).toContain('export function clearRuntimeScanPolicy');
  });

  it('server launch routes accept the explicit allowFullRangeScans pacing/ROE flag', () => {
    const executeRoute = serverSource.slice(serverSource.indexOf("app.post('/api/general/execute'"));
    expect(executeRoute.slice(0, 4000)).toContain('allowFullRangeScans');
    const autoRoute = serverSource.slice(serverSource.indexOf("app.post('/api/general/auto'"));
    expect(autoRoute.slice(0, 6000)).toContain('allowFullRangeScans');
  });

  it('the engine syncs the scan policy from the active mission every tick and clears on stop', () => {
    expect(indexSource).toContain('this.syncRuntimeScanPolicy(mission);');
    expect(indexSource).toContain('clearRuntimeScanPolicy();');
    expect(indexSource).toContain('allowFullRangeScans: this.allowFullRangeScans');
  });
});
