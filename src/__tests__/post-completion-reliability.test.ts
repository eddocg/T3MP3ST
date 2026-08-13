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
    // New storage contract: severity is EFFECTIVE (audited at the vault boundary); the source's
    // assertion is preserved separately in assertedSeverity.
    expect(stored.severity).toBe('low');
    expect(stored.assertedSeverity).toBe('high');
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
    expect(critical.severity).toBe('low'); // effective (clamped at storage)
    expect(critical.assertedSeverity).toBe('critical'); // asserted preserved
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
    expect(swagger.severity).toBe('info'); // effective (clamped at storage)
    expect(swagger.assertedSeverity).toBe('critical'); // asserted severity preserved separately
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

// ═════════════════ RUNTIME TRUTH II — CANONICAL STORE / AUDITED SSE / AUTHMODE ═════════════════

describe('canonical finding identity — one store, audited severity everywhere', () => {
  async function liveCommand() {
    const mod = await import('../index.js');
    const command = new mod.TempestCommand({ name: 'Truth Op', llm: { provider: 'mock', model: 'mock-model' } }) as any;
    command.targetEnv.addTarget({
      id: 'target-1', name: 'api', type: 'api', zone: 'external', status: 'identified',
      address: TARGET, discoveredAt: Date.now(),
    });
    const mission = command.mission.createMission({
      name: 'Truth Op', objectives: ['broad coverage'], objectiveClass: 'general', missionFamily: 'web_api',
    });
    command.mission.startMission(mission.id);
    // addTarget may assign its own id — resolve the STORED target id for finding attribution.
    const targetId = command.targetEnv.getAllTargets()[0].id;
    return { command, mission, targetId };
  }

  const corsFinding = (targetId: string, over: Partial<Finding>): Finding => makeFinding({
    title: 'CORS Misconfiguration',
    description: 'ACAO reflection observed',
    severity: 'high', // asserted by the source — must NOT survive as the effective severity
    targetId,
    category: 'cors',
    evidence: [{
      type: 'response',
      content: 'GET https://api.example.test/ 200\naccess-control-allow-origin: https://attacker.example\naccess-control-allow-credentials: true',
      timestamp: Date.now(),
      metadata: { tool: 'cors_check' },
    }],
    ...over,
  });

  it('P3: asserted-HIGH CORS + config-only evidence → stored low + assertedSeverity high; event + SSE broadcast carry AUDITED low; report shows low', async () => {
    const { command, targetId } = await liveCommand();
    const broadcastEvents: Array<{ event: string; data: any }> = [];
    command.connectBroadcast((event: string, data: any) => broadcastEvents.push({ event, data }));
    const emitted: any[] = [];
    command.on('finding:discovered', (d: any) => emitted.push(d));

    // Real operator ingestion path: gate + emit → vault (canonical) → broadcast of the STORED row.
    const op = command.spawnOperator('Ghost-1', 'recon');
    op.recordFinding(corsFinding(targetId, {}));

    // Canonical store: ONE finding; effective severity audited to low; assertion preserved.
    const all = command.vault.getAllFindings();
    expect(all.length).toBe(1);
    expect(all[0].severity).toBe('low'); // audited/effective
    expect(all[0].assertedSeverity).toBe('high'); // source claim preserved for audit
    expect(all[0].claimSupport?.severityCap).toBe('low');

    // The finding:discovered event carries the STORED canonical record — audited severity,
    // not the raw assertion (this is what drives UI alerts).
    expect(emitted.length).toBe(1);
    expect(emitted[0].finding.severity).toBe('low');
    expect(emitted[0].finding.assertedSeverity).toBe('high');

    // The SSE broadcast payload (what the War Room consumes) — audited severity + human target.
    const findingBroadcast = broadcastEvents.find((e) => e.event === 'finding');
    expect(findingBroadcast).toBeTruthy();
    expect(findingBroadcast!.data.finding.severity).toBe('low');
    expect(findingBroadcast!.data.finding.severity).not.toBe('high'); // no CRITICAL/HIGH alert can fire
    expect(findingBroadcast!.data.finding.targetAddress).toBe(TARGET);

    // The final report agrees: audited low in the summary, no HIGH row; assertion shown as capped.
    command.mission.completeMission(command.mission.getActiveMission()!.id);
    const report = command.generateReport();
    expect(report).toContain('| High | 0 |');
    expect(report).toContain('(asserted HIGH');
    command.stop();
  });

  it('P2 e2e (final-report data path): same CORS root observation from two operators/times → ONE report row with both evidence items; weak-cipher dup → one row; /oauth2/authorize → distinct', async () => {
    const { command, targetId } = await liveCommand();
    const opA = command.spawnOperator('Ghost-1', 'recon');
    const opB = command.spawnOperator('Ghost-2', 'recon');

    // Same CORS condition on / from TWO operators at two times (reworded titles).
    opA.recordFinding(corsFinding(targetId, { title: 'CORS Misconfiguration' }));
    opB.recordFinding(corsFinding(targetId, {
      title: 'Credentialed CORS origin reflection',
      evidence: [{
        type: 'response',
        content: 'GET https://api.example.test/ 200 (second observation)\naccess-control-allow-origin: https://attacker.example',
        timestamp: Date.now() + 1000,
        metadata: { tool: 'curl_request' },
      }],
    }));

    // Same weak-cipher template twice for the same host:443.
    const cipher = (): Finding => makeFinding({
      title: 'Weak Cipher Suites Detection',
      targetId,
      category: 'tls',
      severity: 'medium',
      evidence: [{
        type: 'output',
        content: 'nuclei: weak-cipher-suites at https://api.example.test:443',
        timestamp: Date.now(),
        metadata: { tool: 'nuclei' },
      }],
    });
    opA.recordFinding(cipher());
    opB.recordFinding(cipher());

    // Genuinely different boundary: same CORS category on /oauth2/authorize.
    opA.recordFinding(corsFinding(targetId, {
      title: 'CORS Misconfiguration on OAuth authorization endpoint',
      evidence: [{
        type: 'response',
        content: 'GET https://api.example.test/oauth2/authorize 200\naccess-control-allow-origin: https://attacker.example',
        timestamp: Date.now(),
        metadata: { tool: 'cors_check' },
      }],
    }));

    // ONE canonical identity per boundary: 3 findings total, not 5.
    const all = command.vault.getAllFindings();
    expect(all.length).toBe(3);
    const corsRoot = all.find((f: Finding) => f.title === 'CORS Misconfiguration')!;
    expect(corsRoot.evidence.length).toBe(2); // both observations attached to the canonical row
    expect(corsRoot.assertedSeverity).toBe('high'); // highest assertion kept for audit
    expect(command.vault.consolidatedFindings).toBe(2);

    // The FINAL REPORT renders exactly one row per canonical finding.
    command.mission.completeMission(command.mission.getActiveMission()!.id);
    const report = command.generateReport();
    // Heading-exact matches: "### CORS Misconfiguration" must appear once (the merged root row),
    // and the genuinely different boundary keeps its own distinct row.
    expect(report.match(/^### CORS Misconfiguration$/gm)!.length).toBe(1);
    expect(report.match(/^### Weak Cipher Suites Detection$/gm)!.length).toBe(1);
    expect(report.match(/^### CORS Misconfiguration on OAuth authorization endpoint$/gm)!.length).toBe(1);
    // Exactly 3 finding rows in the report body (one **Severity:** line per canonical finding).
    expect(report.match(/\*\*Severity:\*\*/g)!.length).toBe(3);
    command.stop();
  });
});

describe('P4 — authMode public contract', () => {
  it('only inherit|none are accepted; unknown values throw a validation error (never silently inherit)', async () => {
    const { resolveAuthMode, AUTH_MODES } = await import('../arsenal/index.js');
    expect(resolveAuthMode(undefined)).toBe('inherit');
    expect(resolveAuthMode('')).toBe('inherit');
    expect(resolveAuthMode('inherit')).toBe('inherit');
    expect(resolveAuthMode('none')).toBe('none');
    for (const bad of ['suppress', 'suppressed', 'NONE', 'off', 'false']) {
      let threw: any = null;
      try { resolveAuthMode(bad); } catch (e) { threw = e; }
      expect(threw).toBeTruthy();
      expect(threw.category).toBe('validation_error');
      expect(String(threw.message)).toContain(bad);
      expect(String(threw.message)).toContain(AUTH_MODES.join(', '));
    }
  });

  it('an unknown authMode surfaces as a returned validation payload through Arsenal.execute (curl_request)', async () => {
    const { Arsenal, EXTERNAL_TOOLS, createToolContext } = await import('../arsenal/index.js');
    const arsenal = new Arsenal();
    arsenal.register(EXTERNAL_TOOLS.find((t) => t.name === 'curl_request')!);
    const result = await arsenal.execute('curl_request', createToolContext(undefined, {
      url: 'https://api.example.test/',
      authMode: 'suppressed', // observed in the wild — must NOT silently become inherit/none
    }));
    expect(result.success).toBe(false);
    const payload = JSON.parse(result.error!);
    expect(payload.code).toBe('invalid_auth_mode');
    expect(payload.allowedValues).toEqual(['inherit', 'none']);
    expect(payload.message).toContain('inherit');
    expect(JSON.stringify(payload)).not.toMatch(/Bearer |password=/i);
  });

  it('cors_check output never labels a configuration-only observation CRITICAL', () => {
    const arsenalSource = readFileSync(join(__dirname, '..', 'arsenal', 'index.ts'), 'utf8');
    expect(arsenalSource).not.toContain('WITH credentials - CRITICAL');
    expect(arsenalSource).not.toContain('Wildcard ACAO with credentials - CRITICAL');
    expect(arsenalSource).toContain('NOT demonstrated');
  });

  it('UI: findings carry the canonical identity; the report renders the canonical store', () => {
    const uiSource = readFileSync(join(__dirname, '..', '..', 'docs', 'index.html'), 'utf8');
    expect(uiSource).toContain('findingId: finding.id'); // canonical identity upsert (SSE)
    expect(uiSource).toContain('finding.assertedSeverity');
    expect(uiSource).toContain("fetch(base + '/api/mission/findings')"); // report = canonical store
    expect(uiSource).toContain('reportRows');
  });
});

// ═════════════════ FINAL RUNTIME TRUTH CLOSURE — P1..P4 ═════════════════

describe('FINAL CLOSURE P1 — control-plane capability + authorization context reaches agents', () => {
  async function liveCommand() {
    const mod = await import('../index.js');
    const command = new mod.TempestCommand({ name: 'Context Op', llm: { provider: 'mock', model: 'mock-model' } }) as any;
    command.targetEnv.addTarget({
      id: 'target-1', name: 'api', type: 'api', zone: 'external', status: 'identified',
      address: TARGET, discoveredAt: Date.now(),
    });
    const mission = command.mission.createMission({
      name: 'Context Op', objectives: ['broad coverage'], objectiveClass: 'general', missionFamily: 'web_api',
    });
    command.mission.startMission(mission.id);
    return { command, mission };
  }

  it('agent prompt carries authorized origins, AUTHORIZED execution state, ROE, and the registered tool names', async () => {
    const { command } = await liveCommand();
    const { createAgentLoop } = await import('../agent/index.js');
    const { ARCHETYPE_PROFILES } = await import('../operators/index.js');
    const profile = ARCHETYPE_PROFILES['scanner'];
    const ctx = (command as any).buildControlContext(profile.defaultTools);

    // Names-only, non-secret shape.
    expect(ctx.missionAuthorized).toBe(true); // active mission = execution gate passed
    expect(ctx.authorizedOrigins).toContain(TARGET);
    expect(ctx.toolNames).toEqual(profile.defaultTools);
    expect(ctx.toolNames.length).toBeGreaterThan(0);
    expect(ctx.constraints.join(' ')).toContain('ScopeGuard');
    expect(JSON.stringify(ctx)).not.toMatch(/bearer|password|token|secret/i);

    // The prompt an agent actually receives — the false "tools unavailable" blocker cannot be
    // truthfully claimed: every registered tool is named as AVAILABLE.
    let seenPrompt = '';
    const llm = {
      getProvider: () => 'mock',
      chat: vi.fn().mockImplementation(async (messages: Array<{ role: string; content: string }>) => {
        seenPrompt = messages.map((m) => m.content).join('\n');
        return { content: 'done\n```json\n{"findings":[],"outcome":"no_eligible_work"}\n```', toolCalls: [] };
      }),
      chatWithTools: vi.fn().mockImplementation(async (messages: Array<{ role: string; content: string }>) => {
        seenPrompt = messages.map((m) => m.content).join('\n');
        return { content: 'done\n```json\n{"findings":[],"outcome":"no_eligible_work"}\n```', toolCalls: [] };
      }),
    } as unknown as LLMBackbone;
    const agent = createAgentLoop(llm, command.arsenal, {
      maxIterations: 2,
      tools: profile.defaultTools,
      controlContext: () => ctx,
    });
    await agent.run(makeTask({ name: 'Automated Vulnerability Scan' }), 'Execute.');

    expect(seenPrompt).toContain('Control-Plane Context');
    expect(seenPrompt).toContain('Mission execution: AUTHORIZED');
    expect(seenPrompt).toContain('must NOT block or refuse work for lack of one');
    expect(seenPrompt).toContain(`Authorized target origin(s)**: ${TARGET}`);
    expect(seenPrompt).toContain('Registered tools for THIS session');
    expect(seenPrompt).toContain('never claim a listed tool is unavailable');
    // The scanner toolkit (incl. nuclei_scan) is named as registered — the exact false blocker
    // from the integration run ("nuclei_scan and other Arsenal functions are unavailable").
    if (profile.defaultTools.includes('nuclei_scan')) {
      expect(seenPrompt).toContain('nuclei_scan');
    }
    command.stop();
  });

  it('spawned operators receive the control-context provider wired to the live command', async () => {
    const { command } = await liveCommand();
    // Swap the backbone BEFORE spawning so the operator's agent loop is built on the capture mock.
    let seenPrompt = '';
    const capturing = {
      getProvider: () => 'mock',
      chat: vi.fn().mockImplementation(async (messages: Array<{ role: string; content: string }>) => {
        seenPrompt = messages.map((m) => m.content).join('\n');
        return { content: 'done\n```json\n{"findings":[],"outcome":"no_eligible_work"}\n```', toolCalls: [] };
      }),
      chatWithTools: vi.fn().mockImplementation(async (messages: Array<{ role: string; content: string }>) => {
        seenPrompt = messages.map((m) => m.content).join('\n');
        return { content: 'done\n```json\n{"findings":[],"outcome":"no_eligible_work"}\n```', toolCalls: [] };
      }),
    } as unknown as LLMBackbone;
    (command as any).llm = capturing;
    const op = command.spawnOperator('Scanner-G2', 'scanner');
    await op.executeTask(makeTask({ name: 'Exploit Confirmed Vulnerabilities', missionId: (command.mission.getActiveMission() as any).id }));
    expect(seenPrompt).toContain('Mission execution: AUTHORIZED');
    expect(seenPrompt).toContain('Registered tools for THIS session');
    command.stop();
  });

  it('without an active mission the context honestly reports NOT-authorized (blocking stays valid)', async () => {
    const mod = await import('../index.js');
    const command = new mod.TempestCommand({ name: 'Idle Op', llm: { provider: 'mock', model: 'mock-model' } }) as any;
    const ctx = (command as any).buildControlContext(['curl_request']);
    expect(ctx.missionAuthorized).toBe(false);
    command.stop();
  });
});

describe('FINAL CLOSURE P2 — partial is first-class in status / snapshot / report / UI', () => {
  async function partialCommand() {
    const mod = await import('../index.js');
    const command = new mod.TempestCommand({ name: 'Partial Op', llm: { provider: 'mock', model: 'mock-model' } }) as any;
    command.targetEnv.addTarget({
      id: 'target-1', name: 'api', type: 'api', zone: 'external', status: 'identified',
      address: TARGET, discoveredAt: Date.now(),
    });
    const mission = command.mission.createMission({
      name: 'Partial Op', objectives: ['broad coverage'], objectiveClass: 'general', missionFamily: 'web_api',
    });
    command.mission.startMission(mission.id);
    const tq = command.mission.getTaskQueue();
    const partial = makeTask({
      missionId: mission.id, name: 'Web Application Security Testing', status: 'pending',
    });
    const done = makeTask({ missionId: mission.id, name: 'Recon', status: 'pending' });
    tq.add(partial);
    tq.add(done);
    tq.complete(partial.id, {
      success: true, output: 'executed battery',
      disposition: 'partial', dispositionReason: 'authenticated differential unverified',
    });
    tq.complete(done.id, { success: true, output: 'done', disposition: 'completed' });
    return { command, mission };
  }

  it('status API serializes the structured disposition on the task result', async () => {
    const { command } = await partialCommand();
    const status = command.getStatus();
    const row = status.tasks.find((t: any) => t.name === 'Web Application Security Testing');
    expect(row).toBeTruthy();
    expect(row.status).toBe('completed'); // execution state
    expect(row.result.disposition).toBe('partial'); // coverage state — distinct
    expect(row.result.dispositionReason).toContain('unverified');
    command.stop();
  });

  it('terminal snapshot taskSummary counts partial separately from completed and blocked', async () => {
    const { command } = await partialCommand();
    command.mission.completeMission(command.mission.getActiveMission()!.id);
    const status = command.getStatus();
    expect(status.terminalMission).toBeTruthy();
    expect(status.terminalMission!.taskSummary.completed).toBe(2);
    expect(status.terminalMission!.taskSummary.partial).toBe(1);
    expect(status.terminalMission!.taskSummary.blocked).toBe(0); // partial ≠ blocked
    command.stop();
  });

  it('report preamble distinguishes partial coverage', async () => {
    const { command } = await partialCommand();
    command.mission.completeMission(command.mission.getActiveMission()!.id);
    const report = command.generateReport();
    expect(report).toContain('2 completed (1 partial coverage)');
    command.stop();
  });

  it('UI: completed+partial renders a PARTIAL badge with "Executed · incomplete coverage", never blocked', () => {
    const uiSource = readFileSync(join(__dirname, '..', '..', 'docs', 'index.html'), 'utf8');
    expect(uiSource).toContain("task.result?.disposition === 'partial'");
    expect(uiSource).toContain("isPartial ? 'PARTIAL'");
    expect(uiSource).toContain('Executed · incomplete coverage');
    expect(uiSource).toContain('partial coverage');
  });
});

describe('FINAL CLOSURE P3 — synthesized candidates canonicalize before final storage', () => {
  async function liveCommand() {
    const mod = await import('../index.js');
    const command = new mod.TempestCommand({ name: 'Synth Op', llm: { provider: 'mock', model: 'mock-model' } }) as any;
    command.targetEnv.addTarget({
      id: 'target-1', name: 'api', type: 'api', zone: 'external', status: 'identified',
      address: TARGET, discoveredAt: Date.now(),
    });
    const mission = command.mission.createMission({
      name: 'Synth Op', objectives: ['broad coverage'], objectiveClass: 'general', missionFamily: 'web_api',
    });
    command.mission.startMission(mission.id);
    const targetId = command.targetEnv.getAllTargets()[0].id;
    return { command, mission, targetId };
  }

  const synth = (targetId: string, title: string, severity: Finding['severity'] = 'medium'): Finding => makeFinding({
    title,
    description: `${title} — model synthesis`,
    severity,
    targetId,
    evidence: [], // NO tool-grade evidence — provenance-none synthesis
  });

  const toolCors = (targetId: string, route: string): Finding => makeFinding({
    title: route === '/' ? 'CORS Misconfiguration' : `CORS Misconfiguration on ${route}`,
    targetId, category: 'cors', severity: 'high',
    evidence: [{
      type: 'response',
      content: `GET https://api.example.test${route} 200\naccess-control-allow-origin: https://attacker.example\naccess-control-allow-credentials: true`,
      timestamp: Date.now(), metadata: { tool: 'cors_check' },
    }],
  });

  it('A: tool-backed CORS on / + synthesis explicitly describing / → merges into the root candidate', async () => {
    const { command, targetId } = await liveCommand();
    const op = command.spawnOperator('Ghost-1', 'recon');
    op.recordFinding(toolCors(targetId, '/'));
    // Explicit root boundary in the synthesis (bare-origin URL) — confidently resolved.
    op.recordFinding(synth(targetId, 'Credentialed arbitrary-origin CORS reflection at https://api.example.test/', 'high'));
    const all = command.vault.getAllFindings();
    expect(all.length).toBe(1);
    expect(all[0].description).toContain('also reported as');
    command.stop();
  });

  it('B: tool-backed CORS on / + synthesis describing /oauth2/authorize → distinct candidate', async () => {
    const { command, targetId } = await liveCommand();
    const op = command.spawnOperator('Ghost-1', 'recon');
    op.recordFinding(toolCors(targetId, '/'));
    op.recordFinding(synth(targetId, 'Credentialed CORS reflection on /oauth2/authorize', 'high'));
    const all = command.vault.getAllFindings();
    expect(all.length).toBe(2); // different boundary — never merged into /
    expect(all.some((f: Finding) => /oauth2\/authorize/.test(f.title))).toBe(true);
    command.stop();
  });

  it('C: route-ambiguous CORS synthesis (no recoverable path) does NOT merge to / — stays an unverifiable candidate', async () => {
    const { command, targetId } = await liveCommand();
    const op = command.spawnOperator('Ghost-1', 'recon');
    op.recordFinding(toolCors(targetId, '/'));
    // Pure prose, no URL/path — the actual boundary cannot be resolved.
    op.recordFinding(synth(targetId, 'Credentialed arbitrary-origin CORS reflection', 'high'));
    const all = command.vault.getAllFindings();
    expect(all.length).toBe(2); // NOT absorbed into the root candidate
    const root = all.find((f: Finding) => f.title === 'CORS Misconfiguration')!;
    expect(root.description).not.toContain('also reported as'); // root row unpolluted
    const ambiguous = all.find((f: Finding) => f.title === 'Credentialed arbitrary-origin CORS reflection')!;
    expect(ambiguous.evidence.length).toBe(0);
    expect(ambiguous.claimSupport?.supportLevel).toBe('unverifiable'); // labeled, not evidence-backed
    expect(ambiguous.verifyGate?.passed ?? false).toBe(false);
    command.stop();
  });

  it('D: origin-wide category synthesis (TLS/DNS/version) consolidates at origin level', async () => {
    const { command, targetId } = await liveCommand();
    const op = command.spawnOperator('Ghost-1', 'recon');
    // Tool-backed TLS posture (host:443 service-level) + route-less TLS synthesis → merge.
    op.recordFinding(makeFinding({
      title: 'Weak Cipher Suites Detection', targetId, category: 'tls', severity: 'medium',
      evidence: [{
        type: 'output', content: 'nuclei: weak-cipher-suites at https://api.example.test:443',
        timestamp: Date.now(), metadata: { tool: 'nuclei' },
      }],
    }));
    op.recordFinding(synth(targetId, 'Deprecated TLS cipher suites accepted by the service', 'low'));
    // Tool-backed version exposure + route-less version synthesis → merge via version selector.
    op.recordFinding(makeFinding({
      title: 'Server Version Disclosed', targetId, category: 'info_disclosure', severity: 'low',
      evidence: [{
        type: 'response', content: 'HTTP/1.1 200 OK\nserver: nginx/1.24.0\nhttps://api.example.test/',
        timestamp: Date.now(), metadata: { tool: 'http_request' },
      }],
    }));
    op.recordFinding(synth(targetId, 'nginx version exposed in response banner', 'low'));
    const all = command.vault.getAllFindings();
    expect(all.length).toBe(2); // both syntheses consolidated at origin level
    expect(all.find((f: Finding) => f.title === 'Weak Cipher Suites Detection')!.description).toContain('also reported as');
    expect(all.find((f: Finding) => f.title === 'Server Version Disclosed')!.description).toContain('also reported as');
    command.stop();
  });

  it('e2e (final-report path): explicit-root CORS synthesis merges; selector-resolved swagger syntheses merge; ambiguous CORS synthesis stays a separate candidate', async () => {
    const { command, targetId } = await liveCommand();
    const op = command.spawnOperator('Ghost-1', 'recon');

    // Tool-backed canonical observations.
    op.recordFinding(toolCors(targetId, '/'));
    op.recordFinding(makeFinding({
      title: 'API Documentation Exposed', targetId, category: 'info_disclosure', severity: 'medium',
      evidence: [{
        type: 'response',
        content: 'GET https://api.example.test/swagger.json 200\n{"openapi":"3.0.0"}',
        timestamp: Date.now(), metadata: { tool: 'http_request' },
      }],
    }));
    op.recordFinding(toolCors(targetId, '/oauth2/authorize'));

    // Later LLM syntheses — reworded, provenance-none, no evidence.
    op.recordFinding(synth(targetId, 'Arbitrary Origin Reflected in Credentialed CORS Policy at https://api.example.test/', 'high')); // explicit / → merges
    op.recordFinding(synth(targetId, 'Credentialed arbitrary-origin CORS reflection', 'high')); // ambiguous → stays
    op.recordFinding(synth(targetId, 'Public OpenAPI specification exposed', 'low')); // api-docs selector → merges
    op.recordFinding(synth(targetId, 'Swagger API documentation publicly accessible', 'low')); // api-docs selector → merges

    const all = command.vault.getAllFindings();
    // 3 tool-backed + 1 ambiguous CORS candidate = 4 — NOT 7, and NOT 3 (ambiguous must not merge).
    expect(all.length).toBe(4);
    const corsRoot = all.find((f: Finding) => f.title === 'CORS Misconfiguration')!;
    expect(corsRoot.description).toContain('also reported as'); // explicit-root synthesis attached
    const swagger = all.find((f: Finding) => f.title === 'API Documentation Exposed')!;
    expect(swagger.description).toContain('also reported as'); // both swagger syntheses attached
    // The distinct tool-backed boundary was never merged into the root CORS row.
    expect(all.some((f: Finding) => f.title === 'CORS Misconfiguration on /oauth2/authorize')).toBe(true);
    // The route-ambiguous synthesis survived as its own unverifiable candidate.
    const ambiguous = all.find((f: Finding) => f.title === 'Credentialed arbitrary-origin CORS reflection')!;
    expect(ambiguous.claimSupport?.supportLevel).toBe('unverifiable');

    // Final report: exactly 4 finding rows.
    command.mission.completeMission(command.mission.getActiveMission()!.id);
    const report = command.generateReport();
    expect(report.match(/\*\*Severity:\*\*/g)!.length).toBe(4);
    command.stop();
  });

  it('a genuinely NEW no-evidence hypothesis is stored as a labeled candidate, not silently merged', async () => {
    const { command, targetId } = await liveCommand();
    const op = command.spawnOperator('Ghost-1', 'recon');
    op.recordFinding(synth(targetId, 'Public DNS TXT record discloses staging deployment metadata', 'low'));
    op.recordFinding(synth(targetId, 'Public DNS record discloses staging deployment metadata', 'low'));
    op.recordFinding(synth(targetId, 'Server version disclosed in response banner', 'low'));

    const all = command.vault.getAllFindings();
    // The two reworded DNS syntheses consolidate (dns selector); the unrelated version observation stays distinct.
    expect(all.length).toBe(2);
    const dns = all.find((f: Finding) => /DNS/.test(f.title))!;
    // Labeled as an observation — never masquerading as evidence-backed.
    expect(dns.evidence.length).toBe(0);
    expect(dns.claimSupport?.supportLevel).toBe('unverifiable');
    expect(dns.verifyGate?.passed ?? false).toBe(false);
    command.stop();
  });
});

describe('FINAL CLOSURE P4 — SITREP uses canonical counts, labels telemetry', () => {
  it('SITREP payload presents canonicalFindings as authoritative and raw counts as telemetry', async () => {
    const mod = await import('../index.js');
    const command = new mod.TempestCommand({ name: 'Sitrep Op', llm: { provider: 'mock', model: 'mock-model' } }) as any;
    command.targetEnv.addTarget({
      id: 'target-1', name: 'api', type: 'api', zone: 'external', status: 'identified',
      address: TARGET, discoveredAt: Date.now(),
    });
    const mission = command.mission.createMission({
      name: 'Sitrep Op', objectives: ['broad coverage'], objectiveClass: 'general', missionFamily: 'web_api',
    });
    command.mission.startMission(mission.id);
    command.vault.addFinding(makeFinding({ title: 'CORS Misconfiguration', category: 'cors', severity: 'high' }));

    let captured = '';
    const llm = {
      prompt: async (p: string) => {
        captured = p;
        return '```json\n{"assessment":"ok","findingsSummary":"1 canonical candidate","needsAdaptation":false,"adaptation":null,"confidence":80,"nextActions":["continue"]}\n```';
      },
    } as unknown as LLMBackbone;
    const general = new OpGeneral(llm);
    await general.produceSitrep(command);

    // Canonical block present with the vault totals…
    expect(captured).toContain('"canonicalFindings"');
    expect(captured).toContain('"total": 1');
    expect(captured).toContain('"verified": 0');
    // …raw operator counts present but explicitly labeled telemetry…
    expect(captured).toContain('"rawOperatorObservations"');
    expect(captured).toContain('telemetry only, NOT a findings total');
    // …and the LLM is instructed never to present competing "findings" totals.
    expect(captured).toContain('ONLY authoritative finding total');
    expect(captured).toContain('NEVER call them "findings"');
    command.stop();
  });
});
