import { describe, it, expect, vi } from 'vitest';

// The test sandbox's undici build throws on import (webidl.util.markAsUncloneable) — pre-existing
// environment issue affecting every index.js-importing test. Nothing under test touches undici.
vi.mock('undici', () => ({
  Agent: class { },
  buildConnector: () => ({}),
  setGlobalDispatcher: () => { },
  fetch: (..._a: unknown[]) => Promise.reject(new Error('undici mocked in test')),
}));

import { readFileSync } from 'fs';
import { join } from 'path';
import { createAgentLoop } from '../agent/index.js';
import { Arsenal } from '../arsenal/index.js';
import { MissionControl, deriveObjectiveCompletion } from '../mission/index.js';
import type { LLMBackbone } from '../llm/index.js';
import type { LLMResponse, LLMToolCall, Task } from '../types/index.js';
import { KillChainPhase } from '../types/index.js';

// ─────────────────────────────────────────────────────────────────────────────
// FINDING INGESTION AND TASK-OUTCOME INTEGRITY (the 8-priority pass).
//
// Pinned invariants:
//   P1 — Narrative prose (SITREPs, progress summaries, operator narration) NEVER creates
//        findings. No severity word in prose can manufacture a finding row.
//   P2 — "The agent returned normally" is not success. Structured dispositions
//        (completed/blocked/no_eligible_work/failed) drive task state and mission outcome.
//   P8 — Consumers render the human target + structured evidence; SITREP honors terminal state.
// ─────────────────────────────────────────────────────────────────────────────

const UI = readFileSync(join(__dirname, '..', '..', 'docs', 'index.html'), 'utf8');
const AGENT_SRC = readFileSync(join(__dirname, '..', 'agent', 'index.ts'), 'utf8');

function makeLLMResponse(toolCalls: LLMToolCall[], content?: string): LLMResponse {
  return {
    content: content || '',
    model: 'test-model',
    toolCalls,
    usage: { promptTokens: 100, completionTokens: 50, totalTokens: 150 },
  };
}

function makeTask(): Task {
  return {
    id: 'task-1',
    missionId: 'mission-1',
    name: 'Authenticated Surface Baseline (current principal)',
    description: 'baseline task',
    phase: KillChainPhase.RECON,
    operatorType: 'recon',
    status: 'in_progress',
    priority: 5,
    dependencies: [],
    createdAt: Date.now(),
  };
}

function createMockLLM(responses: LLMResponse[]): LLMBackbone {
  let callIndex = 0;
  return {
    getProvider: vi.fn().mockReturnValue('mock'),
    chat: vi.fn().mockImplementation(async () => responses[Math.min(callIndex++, responses.length - 1)]),
    chatWithTools: vi.fn().mockImplementation(async () => responses[Math.min(callIndex++, responses.length - 1)]),
  } as unknown as LLMBackbone;
}

// ═══════════════════════════════ P1 — PROSE NEVER CREATES FINDINGS ═══════════

describe('P1 — narrative prose never creates findings', () => {
  it('a final message with critical/RCE/credential/SQLi/SSRF prose and NO fenced block yields zero findings', async () => {
    const arsenal = new Arsenal();
    const prose =
      'SITREP: mission progress nominal. We observed potential CRITICAL RCE and credential exposure, ' +
      'plus signs of SQL injection and SSRF across the API. HIGH confidence. ' +
      '{"findings":[{"title":"smuggled","severity":"critical"}]}'; // bare JSON in prose — NOT fenced
    const agent = createAgentLoop(createMockLLM([makeLLMResponse([], prose)]), arsenal, { maxIterations: 3 });
    const result = await agent.run(makeTask(), 'Execute the task.');
    expect(result.findings).toHaveLength(0); // no fenced debrief → NO findings. Contract.
  });

  it('only a fenced ```json debrief block carries findings', async () => {
    const arsenal = new Arsenal();
    const fenced =
      'Work complete.\n```json\n{"findings":[{"title":"Permissive CORS","severity":"low","details":"acao:*"}],"outcome":"completed"}\n```';
    const agent = createAgentLoop(createMockLLM([makeLLMResponse([], fenced)]), arsenal, { maxIterations: 3 });
    const result = await agent.run(makeTask(), 'Execute the task.');
    expect(result.findings.map((f) => f.title)).toEqual(['Permissive CORS']);
    expect(result.findings[0].provenance).toBe('model'); // asserted, gate will downgrade
  });

  it('the UI prose-extraction factory (_extractFindings) is gone — findings arrive via structured channels only', () => {
    expect(UI).not.toContain('_extractFindings');
    expect(UI).not.toContain('AUTO-EXTRACT FINDINGS');
  });
});

// ═══════════════════════ P2 — STRUCTURED TASK DISPOSITIONS ═══════════════════

describe('P2 — structured OperatorAgent dispositions drive task state', () => {
  it('debrief outcome:"blocked" → disposition blocked + success false (returning normally ≠ completed)', async () => {
    const arsenal = new Arsenal();
    const debrief =
      'Unable to start the baseline.\n```json\n{"findings":[],"outcome":"blocked","outcomeReason":"tool contract provides no way to suppress the configured credential context"}\n```';
    const agent = createAgentLoop(createMockLLM([makeLLMResponse([], debrief)]), arsenal, { maxIterations: 3 });
    const result = await agent.run(makeTask(), 'Execute the task.');
    expect(result.disposition).toBe('blocked');
    expect(result.dispositionReason).toContain('suppress');
    expect(result.success).toBe(false);
  });

  it('debrief outcome:"no_eligible_work" → disposition no_eligible_work', async () => {
    const arsenal = new Arsenal();
    const debrief = 'Nothing eligible here.\n```json\n{"findings":[],"outcome":"no_eligible_work","outcomeReason":"target exposes no writable surface"}\n```';
    const agent = createAgentLoop(createMockLLM([makeLLMResponse([], debrief)]), arsenal, { maxIterations: 3 });
    const result = await agent.run(makeTask(), 'Execute the task.');
    expect(result.disposition).toBe('no_eligible_work');
    expect(result.success).toBe(true); // ran legitimately, found nothing eligible
  });

  it('a missing outcome leaves disposition undefined (legacy success-flag fallback)', async () => {
    const arsenal = new Arsenal();
    const debrief = 'Done.\n```json\n{"findings":[]}\n```';
    const agent = createAgentLoop(createMockLLM([makeLLMResponse([], debrief)]), arsenal, { maxIterations: 3 });
    const result = await agent.run(makeTask(), 'Execute the task.');
    expect(result.disposition).toBeUndefined();
    expect(result.success).toBe(true);
  });

  it('dispatcher mapping: blocked disposition → task blocked (terminal), attempt history preserved', () => {
    const mc = new MissionControl();
    const mission = mc.createMission({
      name: 'Disposition Test',
      objectives: ['broad coverage'],
      objectiveClass: 'general',
      phases: [KillChainPhase.RECON],
    });
    const tq = mc.getTaskQueue();
    const task: Task = {
      id: 'task-blocked-1',
      missionId: mission.id,
      name: 'Authenticated Surface Baseline (current principal)',
      description: 'lane:baseline',
      phase: KillChainPhase.RECON,
      operatorType: 'recon',
      status: 'pending',
      priority: 5,
      dependencies: [],
      createdAt: Date.now(),
    };
    tq.add(task);
    tq.updateStatus(task.id, 'in_progress');
    // What the TempestCommand dispatcher does with result.disposition === 'blocked':
    tq.block(task.id, 'tool contract provides no way to select or suppress configured credential context');
    tq.recordAttempt(task.id, 'blocked', 'tool contract provides no way to select or suppress configured credential context');
    const stored = tq.getForMission(mission.id).find((t) => t.id === task.id)!;
    expect(stored.status).toBe('blocked');
    expect(stored.result?.disposition).toBe('blocked');
    expect(stored.attempts?.at(-1)?.outcome).toBe('blocked');
  });

  it('mission outcome: a runtime-blocked planned task degrades general outcome to partial and names it', () => {
    const mc = new MissionControl();
    const mission = mc.createMission({
      name: 'Blocked Baseline Mission',
      objectives: ['broad coverage'],
      objectiveClass: 'general',
      phases: [KillChainPhase.RECON],
    });
    const tq = mc.getTaskQueue();
    const mk = (id: string, name: string, lane: string): Task => ({
      id, missionId: mission.id, name, description: lane, phase: KillChainPhase.RECON,
      operatorType: 'recon', status: 'pending', priority: 5, dependencies: [], createdAt: Date.now(),
    });
    const executed = mk('task-ok-1', 'Broad recon', 'recon');
    const blocked = mk('task-blocked-2', 'Authenticated Surface Baseline (current principal)', 'lane:baseline');
    tq.add(executed);
    tq.add(blocked);
    tq.complete(executed.id, { success: true, output: 'done' });
    tq.block(blocked.id, 'cannot suppress credential context');
    mc.recordPhaseDisposition(mission.id);
    const completion = deriveObjectiveCompletion(
      { ...mc.getMission(mission.id)! },
      tq.getForMission(mission.id),
    );
    expect(completion.outcome).toBe('partial');
    expect(completion.reason).toContain('could not execute');
    expect(completion.reason).toContain('Authenticated Surface Baseline');
  });

  it('phase truth: a task completed with disposition no_eligible_work does not read as executed coverage', () => {
    const mc = new MissionControl();
    const mission = mc.createMission({
      name: 'NoWork Mission',
      objectives: ['broad coverage'],
      objectiveClass: 'general',
      phases: [KillChainPhase.RECON],
    });
    const tq = mc.getTaskQueue();
    const t: Task = {
      id: 'task-nowork-1',
      missionId: mission.id,
      name: 'Assess exploitation surface',
      description: 'lane:objective',
      phase: KillChainPhase.RECON,
      operatorType: 'recon',
      status: 'pending',
      priority: 5,
      dependencies: [],
      createdAt: Date.now(),
    };
    tq.add(t);
    tq.complete(t.id, { success: true, output: 'nothing eligible', disposition: 'no_eligible_work', dispositionReason: 'no viable path' });
    mc.recordPhaseDisposition(mission.id);
    const disp = mc.getMission(mission.id)!.phaseDispositions!.find((d) => d.phase === KillChainPhase.RECON)!;
    expect(disp.disposition).toBe('no_eligible_work');
  });

  it('the agent prompt contract documents the outcome field and its semantics', () => {
    expect(AGENT_SRC).toContain('"outcome":"completed|blocked|no_eligible_work|failed"');
    expect(AGENT_SRC).toContain('returning normally is NOT treated as success');
  });
});

// ═══════════════════ P8 — PRESENTATION CONSUMER CONSISTENCY ══════════════════

describe('P8 — findings consumers render human target + structured evidence + terminal truth', () => {
  it('SSE finding handler prefers targetAddress over the internal UUID', () => {
    const handler = UI.slice(UI.indexOf("addEventListener('finding'"), UI.indexOf("addEventListener('credential'"));
    expect(handler).toContain('finding.targetAddress || finding.targetId');
    expect(handler).not.toContain("target: finding.targetId || 'unknown'");
  });

  it('SSE finding handler carries structured evidenceItems, not an "N evidence item(s)" blob', () => {
    const handler = UI.slice(UI.indexOf("addEventListener('finding'"), UI.indexOf("addEventListener('credential'"));
    expect(handler).toContain('evidenceItems');
    expect(handler).not.toContain('evidence item(s)');
  });

  it('finding detail modal renders structured evidence items (tool + timestamp + content)', () => {
    const modal = UI.slice(UI.indexOf('function showFindingDetail'), UI.indexOf('function exportFindings'));
    expect(modal).toContain('f.evidenceItems');
    expect(modal).toContain('ev.metadata.tool');
  });

  it('status-poll ingestion prefers targetAddress over targetId', () => {
    expect(UI).toContain('target: f.targetAddress || f.targetId || target');
  });

  it('server status findings include the human targetAddress', () => {
    const server = readFileSync(join(__dirname, '..', 'server.ts'), 'utf8');
    const statusFindings = server.slice(server.indexOf('findings: findings.map'), server.indexOf('findings: findings.map') + 700);
    expect(statusFindings).toContain('targetAddress');
  });

  it('a late SITREP event for a terminal mission cannot flip the widget back to ACTIVE', () => {
    const handler = UI.slice(UI.indexOf("addEventListener('general:sitrep'"), UI.indexOf("addEventListener('general:adapting'"));
    expect(handler).toContain("chip.textContent === 'COMPLETE'");
    expect(handler).toContain("terminal ? undefined : 'ACTIVE'");
  });

  it('terminal poll reconciles the kill-chain counters from authoritative phase dispositions', () => {
    expect(UI).toContain('term.phaseDispositions');
    expect(UI).toContain('updateKillChain(mapped, 100)');
  });
});
