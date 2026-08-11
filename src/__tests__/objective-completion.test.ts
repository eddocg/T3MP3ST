import { describe, it, expect, vi } from 'vitest';

// The test sandbox's undici build throws on import (webidl.util.markAsUncloneable) — a pre-existing
// environment issue that breaks every index.js-importing test. The completion/snapshot logic under
// test never touches the network, so stub undici's exports before any transitive import of index.js.
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
  deriveObjectiveCompletion,
} from '../mission/index.js';
import { KillChainPhase, type Task } from '../types/index.js';
import { redactSecrets } from '../redact.js';

// ─────────────────────────────────────────────────────────────────────────────
// OBJECTIVE COMPLETION / BLOCKED-PREREQUISITE regression coverage.
//
// Scenario pinned (the generic form of the staging-API run):
//   Directive: "Focus on authenticated authorization lifecycle testing. Avoid unrelated generic
//   configuration testing." Available: ONE authenticated principal + target origin + API/OpenAPI
//   structure. Missing: controlled Principal B, B-owned resource, lifecycle/state fixture.
//
// Invariants: the objective lane bounds recon (no generic battery), missing fixtures become
// EXPLICIT terminal blocked prerequisites (never dispatched, never fabricated into A/B coverage),
// the mission terminates cleanly with an honest objectiveOutcome, the terminal snapshot and
// mission-context retain the outcome, and empty phases are recorded truthfully — while broad
// general missions keep their existing behavior.
// ─────────────────────────────────────────────────────────────────────────────

const TARGET = 'https://staging.api.example.test';

function seedAuthzMission(mc: MissionControl) {
  const mission = mc.createMission({
    name: 'authz-lifecycle',
    objectives: ['authenticated authorization lifecycle testing'],
    objectiveClass: 'authorization_lifecycle',
    missionFamily: 'web_api',
  });
  mc.startMission(mission.id);
  mc.generateTasksForTarget(TARGET);
  return mission;
}

describe('blocked prerequisites are terminal records, never dispatched work', () => {
  it('seeds the missing Principal B / state fixtures as status blocked (terminal at creation)', () => {
    const mc = new MissionControl();
    const mission = seedAuthzMission(mc);
    const tasks = mc.getTaskQueue().getForMission(mission.id);
    const blocked = tasks.filter((t) => t.status === 'blocked');
    expect(blocked.length).toBe(2);
    expect(blocked.map((t) => t.name).join('\n')).toContain('cross-principal differential');
    expect(blocked.map((t) => t.name).join('\n')).toContain('lifecycle differential');
    for (const t of blocked) expect(t.completedAt).toBeDefined();
  });

  it('blocked tasks NEVER enter the dispatchable pending set (no fake A/B execution)', () => {
    const mc = new MissionControl();
    seedAuthzMission(mc);
    const pending = mc.getTaskQueue().getPending();
    expect(pending.every((t) => t.status === 'pending')).toBe(true);
    expect(pending.map((t) => t.name).join('\n')).not.toContain('BLOCKED prerequisite');
    // The legitimate bounded prerequisites + current-principal baseline ARE dispatchable.
    expect(pending.map((t) => t.name).join('\n')).toContain('authenticated API surface map');
    expect(pending.map((t) => t.name).join('\n')).toContain('current-principal access map');
  });

  it('a blocked task cannot be resurrected into work (updateStatus/retry/skip all refuse)', () => {
    const mc = new MissionControl();
    const mission = seedAuthzMission(mc);
    const tq = mc.getTaskQueue();
    const blocked = tq.getForMission(mission.id).find((t) => t.status === 'blocked')!;
    expect(tq.updateStatus(blocked.id, 'pending')).toBeUndefined();
    expect(tq.retry(blocked.id)).toBeUndefined();
    expect(tq.skip(blocked.id)).toBeUndefined();
    expect(tq.getTask(blocked.id)!.status).toBe('blocked');
  });

  it('current-principal baseline work remains executable without Principal B', () => {
    const mc = new MissionControl();
    const mission = seedAuthzMission(mc);
    const baseline = mc.getTaskQueue().getForMission(mission.id)
      .find((t) => t.name.includes('current-principal access map'))!;
    expect(baseline.status).toBe('pending');
    expect(baseline.description).toContain('lane:objective');
  });
});

describe('objective completion — outcome, reason, and prerequisite breakdown', () => {
  it('is BLOCKED when only bounded prerequisites ran and no objective work completed', () => {
    const mc = new MissionControl();
    const mission = seedAuthzMission(mc);
    const tq = mc.getTaskQueue();
    const tasks = tq.getForMission(mission.id);
    // Only the prerequisite (non-objective) lane completes.
    const prereq = tasks.find((t) => t.description.includes('lane:prerequisite'))!;
    tq.complete(prereq.id, { success: true, output: 'mapped 12 routes' });
    const completion = deriveObjectiveCompletion(
      { ...mission }, tq.getForMission(mission.id),
    );
    expect(completion.outcome).toBe('blocked');
    expect(completion.reason).toContain('fixture');
    expect(completion.blockedPrerequisites.length).toBe(2);
    expect(completion.completedPrerequisites.map((p) => p.name)).toContain('Prerequisite: authenticated API surface map');
  });

  it('is PARTIAL when the current-principal baseline ran but differentials stayed blocked — and claims NO cross-principal coverage', () => {
    const mc = new MissionControl();
    const mission = seedAuthzMission(mc);
    const tq = mc.getTaskQueue();
    for (const t of tq.getForMission(mission.id)) {
      if (t.status === 'pending') tq.complete(t.id, { success: true, output: 'baseline recorded' });
    }
    const completion = deriveObjectiveCompletion({ ...mission }, tq.getForMission(mission.id));
    expect(completion.outcome).toBe('partial');
    expect(completion.reason).toContain('no multi-principal coverage claimed');
    expect(completion.blockedPrerequisites.length).toBe(2);
  });

  it('a general mission reports met and carries no blocked prerequisites (no narrowing of broad behavior)', () => {
    const mc = new MissionControl();
    const mission = mc.createMission({ name: 'gen', objectives: ['enumerate attack surface'], objectiveClass: 'general' });
    mc.startMission(mission.id);
    mc.generateTasksForTarget(TARGET);
    const tasks = mc.getTaskQueue().getForMission(mission.id);
    expect(tasks.some((t) => t.status === 'blocked')).toBe(false);
    const completion = deriveObjectiveCompletion({ ...mission }, tasks);
    expect(completion.outcome).toBe('met');
    expect(completion.blockedPrerequisites.length).toBe(0);
  });
});

describe('mission termination — clean completion with durable outcome + truthful phases', () => {
  it('completeMission stores objectiveOutcome + completionReason on the mission (execution finished ≠ objective met)', () => {
    const mc = new MissionControl();
    const mission = seedAuthzMission(mc);
    const tq = mc.getTaskQueue();
    for (const t of tq.getForMission(mission.id)) {
      if (t.status === 'pending') tq.complete(t.id, { success: true, output: 'done' });
    }
    const completed = mc.completeMission(mission.id);
    expect(completed.status).toBe('completed');
    expect(completed.objectiveOutcome).toBe('partial');
    expect(completed.completionReason).toBeTruthy();
    expect(completed.completedAt).toBeDefined();
  });

  it('the terminal mission remains retrievable after leaving the active slot', () => {
    const mc = new MissionControl();
    const mission = seedAuthzMission(mc);
    mc.completeMission(mission.id);
    expect(mc.getActiveMission()).toBeUndefined();
    const terminal = mc.getLatestTerminalMission();
    expect(terminal?.id).toBe(mission.id);
    expect(terminal?.objectiveClass).toBe('authorization_lifecycle');
    expect(terminal?.objectiveOutcome).toBeTruthy();
  });

  it('records truthful phase dispositions — executed vs blocked_prerequisite vs no_eligible_work', () => {
    const mc = new MissionControl();
    const mission = seedAuthzMission(mc);
    const tq = mc.getTaskQueue();
    // RECON: the two runnable lane tasks complete → executed.
    for (const t of tq.getForMission(mission.id)) {
      if (t.status === 'pending') tq.complete(t.id, { success: true, output: 'done' });
    }
    mc.recordPhaseDisposition(mission.id); // currentPhase = recon
    // WEAPONIZE: only the two blocked prerequisites live there → blocked_prerequisite.
    mc.advancePhase(mission.id);
    mc.recordPhaseDisposition(mission.id);
    // DELIVER: nothing seeded for the objective lane → no_eligible_work (NOT "executed").
    mc.advancePhase(mission.id);
    mc.recordPhaseDisposition(mission.id);

    const dispositions = mc.getMission(mission.id)!.phaseDispositions!;
    const byPhase = Object.fromEntries(dispositions.map((d) => [d.phase, d]));
    expect(byPhase[KillChainPhase.RECON]?.disposition).toBe('executed');
    expect(byPhase[KillChainPhase.RECON]?.completed).toBe(2);
    expect(byPhase[KillChainPhase.WEAPONIZE]?.disposition).toBe('blocked_prerequisite');
    expect(byPhase[KillChainPhase.WEAPONIZE]?.blocked).toBe(2);
    expect(byPhase[KillChainPhase.DELIVER]?.disposition).toBe('no_eligible_work');
    expect(byPhase[KillChainPhase.DELIVER]?.total).toBe(0);
  });

  it('blocked prerequisites do NOT stall the mission and are not recovery blockers', async () => {
    const mod = await import('../index.js');
    const command = new mod.TempestCommand({ name: 'Objective Op', llm: { provider: 'mock', model: 'mock-model' } }) as any;
    const mission = command.mission.createMission({
      name: 'authz', objectives: ['authorization lifecycle'], objectiveClass: 'authorization_lifecycle',
    });
    command.mission.startMission(mission.id);
    command.mission.generateTasksForTarget(TARGET);
    const recovery = command.recoverMission();
    // Blocked prerequisites are missing-fixture records, not retryable failures: no blockers.
    expect(recovery.blocking.length).toBe(0);
    expect(command.getStatus().stallReason).toBeNull();
    expect(command.getRunState()).not.toBe('stalled');
  });
});

describe('terminal snapshot via getStatus — completed missions stay auditable', () => {
  const makeCommand = async () => {
    const mod = await import('../index.js');
    return new mod.TempestCommand({ name: 'Snapshot Op', llm: { provider: 'mock', model: 'mock-model' } }) as any;
  };

  it('retains objectiveClass/objectiveOutcome/reason/tasks AFTER completion, with active false', async () => {
    const command = await makeCommand();
    const mission = command.mission.createMission({
      name: 'authz-snap', objectives: ['authorization lifecycle'],
      objectiveClass: 'authorization_lifecycle', missionFamily: 'web_api',
    });
    command.mission.startMission(mission.id);
    command.mission.generateTasksForTarget(TARGET);
    const tq = command.mission.getTaskQueue();
    for (const t of tq.getForMission(mission.id)) {
      if (t.status === 'pending') tq.complete(t.id, { success: true, output: 'done' });
    }
    command.mission.completeMission(mission.id);

    const status = command.getStatus();
    expect(status.state).toBe('completed');
    expect(status.activeMission).toBeNull();
    // Tasks remain visible after completion (no more tasks: []).
    expect(status.tasks.length).toBeGreaterThan(0);
    const term = status.terminalMission;
    expect(term).toBeTruthy();
    expect(term.id).toBe(mission.id);
    expect(term.status).toBe('completed');
    expect(term.objectiveClass).toBe('authorization_lifecycle');
    expect(term.objectiveOutcome).toBe('partial');
    expect(term.completionReason).toContain('no multi-principal coverage claimed');
    expect(term.family).toBe('web_api');
    expect(term.taskSummary.blocked).toBe(2);
    expect(term.taskSummary.completed).toBe(2);
    expect(term.blockedPrerequisites.map((p: any) => p.name).join('\n')).toContain('cross-principal differential');
    expect(term.completedPrerequisites.length).toBe(2);
    expect(Array.isArray(term.phaseDispositions)).toBe(true);
  });

  it('a terminal snapshot never resurrects the mission as live', async () => {
    const command = await makeCommand();
    const mission = command.mission.createMission({ name: 'snap2', objectives: ['authorization lifecycle'], objectiveClass: 'authorization_lifecycle' });
    command.mission.startMission(mission.id);
    command.mission.generateTasksForTarget(TARGET);
    command.mission.completeMission(mission.id);
    const status = command.getStatus();
    expect(status.running).toBe(false);
    expect(status.state).toBe('completed');
    expect(status.activeMission).toBeNull();
    expect(status.terminalMission.status).toBe('completed');
  });

  it('no live mission and no history → terminalMission is null (idle stays distinguishable)', async () => {
    const command = await makeCommand();
    const status = command.getStatus();
    expect(status.state).toBe('idle');
    expect(status.terminalMission).toBeNull();
  });

  it('forwards task:created (the seam the server uses to materialize durable blocked-prerequisite records)', async () => {
    const command = await makeCommand();
    const created: Task[] = [];
    command.on('task:created', (t: Task) => created.push(t));
    const mission = command.mission.createMission({ name: 'authz-events', objectives: ['authorization lifecycle'], objectiveClass: 'authorization_lifecycle' });
    command.mission.startMission(mission.id);
    command.mission.generateTasksForTarget(TARGET);
    const blocked = created.filter((t) => t.status === 'blocked');
    expect(blocked.length).toBe(2);
    expect(blocked.every((t) => t.missionId === mission.id)).toBe(true);
  });

  it('emits mission:completed with the mission (the seam the server uses to persist the terminal snapshot)', async () => {
    const command = await makeCommand();
    let completedMission: any = null;
    command.on('mission:completed', (m: any) => { completedMission = m; });
    const mission = command.mission.createMission({ name: 'authz-complete-event', objectives: ['authorization lifecycle'], objectiveClass: 'authorization_lifecycle' });
    command.mission.startMission(mission.id);
    command.mission.generateTasksForTarget(TARGET);
    command.mission.completeMission(mission.id);
    expect(completedMission?.id).toBe(mission.id);
    expect(completedMission?.objectiveOutcome).toBeTruthy();
    expect(command.getRunState()).toBe('completed');
  });
});

describe('secret containment — terminal snapshot fields pass through central redaction', () => {
  it('redactSecrets scrubs credential material from snapshot-shaped payloads', () => {
    const snapshot = {
      objectiveClass: 'authorization_lifecycle',
      objectiveOutcome: 'partial',
      completionReason: 'saw Bearer abcdef1234567890TOKEN in a log line',
      blockedPrerequisites: [{ id: 't1', name: 'x', reason: 'api_key=abcdef1234567890TOKEN' }],
    };
    const redacted = redactSecrets(snapshot) as typeof snapshot;
    expect(JSON.stringify(redacted)).not.toContain('abcdef1234567890TOKEN');
    expect(redacted.objectiveOutcome).toBe('partial'); // structure preserved
  });

  it('auth-context metadata exposes header NAMES only — never values', async () => {
    const arsenal = await import('../arsenal/index.js');
    const names = arsenal.setRuntimeTargetHeaders('https://staging.api.example.test', JSON.stringify({
      authorization: 'Bearer super-secret-token-value-123456',
      'x-api-key': 'another-secret-value-7890',
    }));
    expect(names).toBeTruthy();
    const meta = arsenal.runtimeTargetHeaderMetadata();
    expect(meta.present).toBe(true);
    expect(meta.origin).toBe('https://staging.api.example.test');
    expect(meta.headerNames.sort()).toEqual(['authorization', 'x-api-key']);
    // The whole point: no secret VALUE anywhere in the metadata.
    expect(JSON.stringify(meta)).not.toContain('super-secret-token-value-123456');
    expect(JSON.stringify(meta)).not.toContain('another-secret-value-7890');
    arsenal.clearRuntimeTargetHeaders();
    expect(arsenal.runtimeTargetHeaderMetadata().present).toBe(false);
  });
});

// ── Server/API surface invariants (static — importing server.ts would start the listener) ──
const serverSource = readFileSync(join(process.cwd(), 'src/server.ts'), 'utf8');

describe('API surface — terminal snapshot + mission-context objective block', () => {
  it('/api/mission/status falls back to the latest terminal mission and redacts the response', () => {
    const route = serverSource.slice(
      serverSource.indexOf("app.get('/api/mission/status'"),
      serverSource.indexOf("app.post('/api/operators/spawn'"),
    );
    expect(route).toContain('getLatestTerminalMission');
    expect(route).toContain('terminalMission');
    expect(route).toContain('objectiveOutcome');
    expect(route).toContain('redactSecrets');
  });

  it('mission-context exposes the objective block (class/outcome/reason/prerequisites/phases)', () => {
    const fn = serverSource.slice(
      serverSource.indexOf('function latestMissionContext'),
      serverSource.indexOf('function workOrderSquadForFamily'),
    );
    expect(fn).toContain('objective');
    expect(fn).toContain('blockedPrerequisites');
    expect(fn).toContain('completedPrerequisites');
    expect(fn).toContain('phaseDispositions');
    expect(fn).toContain('redactSecrets');
  });

  it('blocked prerequisite tasks are materialized into the durable ledgers (hypothesis + blocked work order)', () => {
    expect(serverSource).toContain("tempestCommand.on('task:created'");
    expect(serverSource).toContain('materializeBlockedPrerequisite');
    const fn = serverSource.slice(
      serverSource.indexOf('function materializeBlockedPrerequisite'),
      serverSource.indexOf('function upsertMissionFindingToLedger'),
    );
    expect(fn).toContain("status: 'blocked'");
    expect(fn).toContain('hypothesisLedger.set');
    expect(fn).toContain('workOrderLedger.set');
    // The blocked work order is a ledger record, NEVER a vulnerability finding.
    expect(fn).not.toContain('findingsLedger.set');
  });

  it('mirrored live findings persist their tool evidence (no more findings without evidence)', () => {
    const fn = serverSource.slice(
      serverSource.indexOf('function upsertMissionFindingToLedger'),
      serverSource.indexOf('const ROUTE_SCORECARDS'),
    );
    expect(fn).toContain('evidenceLedger.set');
    expect(fn).toContain('provenanceStrength');
    expect(fn).toContain('redactLedgerText');
  });

  it('terminal mission snapshots are persisted + restored (objective outcome survives restart)', () => {
    expect(serverSource).toContain('terminalMissionLedger');
    expect(serverSource).toContain('recordTerminalMissionSnapshot');
    // Wired to BOTH terminal events.
    expect(serverSource).toContain("tempestCommand.on('mission:completed'");
    expect(serverSource).toContain("tempestCommand.on('mission:aborted'");
    // Included in the state snapshot AND the restore path.
    const snapshot = serverSource.slice(
      serverSource.indexOf('function buildStateSnapshot'),
      serverSource.indexOf('async function persistState'),
    );
    expect(snapshot).toContain('terminalMissionLedger');
    const restore = serverSource.slice(
      serverSource.indexOf('async function loadPersistedState'),
      serverSource.indexOf('function normalizeTargetValue'),
    );
    expect(restore).toContain('replaceMapContents(terminalMissionLedger');
    // Snapshot carries auth-context metadata (names only) — the builder never touches values.
    const builder = serverSource.slice(
      serverSource.indexOf('function recordTerminalMissionSnapshot'),
      serverSource.indexOf('function materializeBlockedPrerequisite'),
    );
    expect(builder).toContain('runtimeTargetHeaderMetadata');
    expect(builder).toContain('headerNames');
    expect(builder).not.toContain('headers.values()');
  });
});
