import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// The test sandbox's undici build throws on import (webidl.util.markAsUncloneable) — a pre-existing
// environment issue that breaks every index.js-importing test. The recovery/state logic under test
// never touches the network, so stub undici's exports before any transitive import of index.js.
vi.mock('undici', () => ({
  Agent: class { },
  buildConnector: () => ({}),
  setGlobalDispatcher: () => { },
  fetch: (..._a: unknown[]) => Promise.reject(new Error('undici mocked in test')),
}));

import {
  TIMEOUT_REGISTRY,
  resolveTimeout,
  validateTimeoutValue,
  validateTimeoutHierarchy,
  getTimeoutSpec,
  DISPATCH_RECONCILE_GRACE_MS,
} from '../config/timeouts.js';
import { TaskQueue } from '../mission/index.js';
import { KillChainPhase, type Task } from '../types/index.js';

// ─────────────────────────────────────────────────────────────────────────────
// TIMEOUT MODEL + STALLED-MISSION RECOVERY regression coverage.
// Pins: hierarchy safety (parent >= child + grace), precedence/reset, attempt-preserving retry,
// unsafe-duplicate suppression, and a complete distinguishable mission state model.
// ─────────────────────────────────────────────────────────────────────────────

const ENV_KEYS = ['T3MP3ST_TASK_TIMEOUT_MS', 'T3MP3ST_TOOL_TIMEOUT_MS', 'T3MP3ST_HTTP_TIMEOUT_MS', 'T3MP3ST_LLM_RETRY_ATTEMPTS', 'T3MP3ST_LLM_RETRY_DELAY_MS'];
const savedEnv: Record<string, string | undefined> = {};
beforeEach(() => { for (const k of ENV_KEYS) { savedEnv[k] = process.env[k]; delete process.env[k]; } });
afterEach(() => { for (const k of ENV_KEYS) { if (savedEnv[k] === undefined) delete process.env[k]; else process.env[k] = savedEnv[k]; } });

describe('timeout registry — defaults verified from source', () => {
  it('dispatch backstop default is 300000ms (5 min), NOT 30 min', () => {
    expect(getTimeoutSpec('dispatchTimeoutMs')!.defaultMs).toBe(300000);
  });
  it('every Class-A setting has sane bounds and no 0=infinite', () => {
    for (const s of TIMEOUT_REGISTRY.filter((x) => x.class === 'A')) {
      expect(s.minMs).toBeGreaterThan(0);
      expect(s.maxMs).toBeGreaterThan(s.minMs);
      expect(s.defaultMs).toBeGreaterThanOrEqual(s.minMs);
      expect(s.defaultMs).toBeLessThanOrEqual(s.maxMs);
    }
  });
});

describe('timeout validation', () => {
  it('rejects non-finite, zero, negative, and out-of-bounds values (fail closed, never infinite)', () => {
    expect(validateTimeoutValue('dispatchTimeoutMs', NaN).ok).toBe(false);
    expect(validateTimeoutValue('dispatchTimeoutMs', 0).ok).toBe(false);
    expect(validateTimeoutValue('dispatchTimeoutMs', -5000).ok).toBe(false);
    expect(validateTimeoutValue('dispatchTimeoutMs', 999_999_999).ok).toBe(false); // over max
    expect(validateTimeoutValue('no-such-key', 5000).ok).toBe(false);
  });
  it('accepts a valid in-bounds value', () => {
    const r = validateTimeoutValue('dispatchTimeoutMs', 420000);
    expect(r.ok).toBe(true);
  });
});

describe('timeout precedence — UI > env > default', () => {
  it('env overrides default when no UI value', () => {
    process.env.T3MP3ST_TASK_TIMEOUT_MS = '450000';
    const r = resolveTimeout('dispatchTimeoutMs', undefined);
    expect(r.valueMs).toBe(450000);
    expect(r.source).toBe('env');
  });
  it('UI override beats env and reports envOverridden', () => {
    process.env.T3MP3ST_TASK_TIMEOUT_MS = '450000';
    const r = resolveTimeout('dispatchTimeoutMs', 500000);
    expect(r.valueMs).toBe(500000);
    expect(r.source).toBe('ui');
    expect(r.envPresent).toBe(true);
  });
  it('falls back to default when neither UI nor env set', () => {
    const r = resolveTimeout('dispatchTimeoutMs', undefined);
    expect(r.valueMs).toBe(300000);
    expect(r.source).toBe('default');
  });
  it('a UI override of undefined (reset) re-exposes env precedence', () => {
    process.env.T3MP3ST_TASK_TIMEOUT_MS = '450000';
    // after reset -> ui undefined -> env wins again
    const r = resolveTimeout('dispatchTimeoutMs', undefined);
    expect(r.source).toBe('env');
    expect(r.valueMs).toBe(450000);
  });
});

describe('timeout hierarchy — a supervisor cannot be shorter than the work it supervises', () => {
  it('flags dispatchTimeoutMs shorter than toolExecTimeoutMs + grace', () => {
    const conflicts = validateTimeoutHierarchy({
      dispatchTimeoutMs: 60_000,        // 1 min backstop
      toolExecTimeoutMs: 600_000,       // 10 min tool window
      llmTimeoutMs: 60_000,
    });
    expect(conflicts.length).toBeGreaterThan(0);
    const c = conflicts.find((x) => x.supervisor === 'dispatchTimeoutMs' && x.child === 'toolExecTimeoutMs');
    expect(c).toBeDefined();
    expect(c!.requiredMinMs).toBe(600_000 + DISPATCH_RECONCILE_GRACE_MS);
    expect(c!.message).toMatch(/late-success race|reconciliation grace/i);
  });
  it('no conflict when the backstop comfortably exceeds the child windows', () => {
    const conflicts = validateTimeoutHierarchy({
      dispatchTimeoutMs: 900_000,
      toolExecTimeoutMs: 120_000,
      llmTimeoutMs: 60_000,
    });
    expect(conflicts).toHaveLength(0);
  });
});

describe('attempt-preserving retry (history is never rewritten)', () => {
  const mkTask = (over: Partial<Task> = {}): Task => ({
    id: 't1', missionId: 'm1', name: 'Scan', description: 'scan x', phase: KillChainPhase.RECON,
    operatorType: 'recon', status: 'pending', priority: 1, dependencies: [], createdAt: Date.now(),
    ...over,
  });

  it('a retry appends a new attempt and keeps the prior failed/timeout attempt', () => {
    const tq = new TaskQueue();
    const t = mkTask();
    tq.add(t);
    tq.beginAttempt(t.id);
    tq.fail(t.id, 'timeout: backstop fired');
    tq.recordAttempt(t.id, 'timeout_pending', 'timeout: backstop fired');

    // Retry -> pending, history intact
    const retried = tq.retry(t.id)!;
    expect(retried.status).toBe('pending');
    expect(retried.attempts!.length).toBe(1);
    expect(retried.attempts![0].outcome).toBe('timeout_pending');
    expect(retried.attempts![0].error).toContain('backstop');

    // New attempt begins -> second entry
    tq.beginAttempt(t.id);
    expect(tq.getTask(t.id)!.attempts!.length).toBe(2);
    expect(tq.getTask(t.id)!.attempts![1].n).toBe(2);
  });

  it('retry is a no-op for a task not currently failed', () => {
    const tq = new TaskQueue();
    const t = mkTask({ status: 'completed' });
    tq.add(t);
    expect(tq.retry(t.id)).toBeUndefined();
  });

  it('skip marks an OPTIONAL failed task skipped (terminal, never completed)', () => {
    const tq = new TaskQueue();
    const t = mkTask({ required: false, status: 'failed' });
    tq.add(t);
    const skipped = tq.skip(t.id)!;
    expect(skipped.status).toBe('skipped');
    expect(skipped.status).not.toBe('completed');
  });

  it('a REQUIRED task is never skippable', () => {
    const tq = new TaskQueue();
    const t = mkTask({ required: true, status: 'failed' });
    tq.add(t);
    expect(tq.skip(t.id)).toBeUndefined();
    expect(tq.getTask(t.id)!.status).toBe('failed');
  });

  it('legacy tasks (no required field) default to required and are not skippable', () => {
    const tq = new TaskQueue();
    const t = mkTask({ status: 'failed' });
    delete (t as any).required;
    tq.add(t);
    expect(tq.skip(t.id)).toBeUndefined();
  });
});

describe('stalled-mission recovery (recoverMission) — re-evaluates, never blindly resumes', () => {
  const makeCommand = async () => {
    const mod = await import('../index.js');
    return new mod.TempestCommand({ name: 'Recovery Op', llm: { provider: 'mock', model: 'mock-model' } }) as any;
  };
  const seedStalledMission = (command: any, taskOver: Partial<Task> = {}) => {
    const mission = command.mission.createMission({ name: 'm', objectives: ['test'] });
    command.mission.startMission(mission.id);
    const tq = command.mission.getTaskQueue();
    const task: Task = {
      id: 'req-1', missionId: mission.id, name: 'Required Scan', description: 'scan t', phase: mission.currentPhase,
      operatorType: 'recon', status: 'failed', priority: 1, dependencies: [], createdAt: Date.now(), ...taskOver,
    };
    tq.add(task);
    (command as any).stallReason = 'stalled: 1 required task(s) failed';
    (command as any).stallSince = Date.now();
    (command as any).paused = true;
    return { mission, tq, task };
  };

  it('refuses to resume while a required blocker remains, exposing the blocker', async () => {
    const command = await makeCommand();
    command.start();
    const { task } = seedStalledMission(command, { status: 'failed' });
    command.mission.getTaskQueue().fail(task.id, 'hard refusal: out of scope');

    const outcome = command.recoverMission();
    expect(outcome.resumed).toBe(false);
    expect(outcome.blocking.length).toBe(1);
    expect(outcome.blocking[0].id).toBe('req-1');
    expect(outcome.blocking[0].state).toBe('non_retryable');
    expect(command.getStatus().stallReason).not.toBeNull(); // still stalled
    command.stop();
  });

  it('resumes when the only failed task is reconciled to completed (late success)', async () => {
    const command = await makeCommand();
    command.start();
    const { tq, task } = seedStalledMission(command);
    // Simulate the late-success reconcile having flipped it to completed.
    tq.complete(task.id, { success: true, output: 'late success' });
    const outcome = command.recoverMission();
    expect(outcome.resumed).toBe(true);
    expect(command.getStatus().stallReason).toBeNull();
    expect(command.getStatus().paused).toBe(false);
    command.stop();
  });

  it('an unresolved timeout_pending attempt cannot be retried into a duplicate execution', async () => {
    const command = await makeCommand();
    command.start();
    const { tq, task } = seedStalledMission(command);
    tq.beginAttempt(task.id);
    tq.fail(task.id, 'timeout: dispatch timed out');
    tq.recordAttempt(task.id, 'timeout_pending', 'timeout');
    command.timedOutDispatches.add(task.id); // underlying promise still live

    const r = command.retryTask(task.id);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/still in flight|duplicate/i);
    expect(tq.getTask(task.id)!.status).toBe('failed'); // not requeued
    command.stop();
  });

  it('a retryable failed task requeues as a new attempt', async () => {
    const command = await makeCommand();
    command.start();
    const { tq, task } = seedStalledMission(command);
    tq.beginAttempt(task.id);
    tq.fail(task.id, 'transient network error');
    tq.recordAttempt(task.id, 'failed', 'transient network error');

    const r = command.retryTask(task.id);
    expect(r.ok).toBe(true);
    expect(tq.getTask(task.id)!.status).toBe('pending');
    // original attempt preserved
    expect(tq.getTask(task.id)!.attempts![0].outcome).toBe('failed');
    command.stop();
  });
});

describe('complete mission state model (idle/running/paused/stalled/completed/aborted)', () => {
  it('distinguishes all states; active:false is NOT auto-completed', async () => {
    const mod = await import('../index.js');
    const command = new mod.TempestCommand({ name: 'State Op', llm: { provider: 'mock', model: 'mock-model' } }) as any;
    expect(command.getRunState()).toBe('idle'); // not started

    command.start();
    expect(command.getRunState()).toBe('running');

    command.pause();
    expect(command.getRunState()).toBe('paused');

    // Stall
    (command as any).stallReason = 'stalled: required failed';
    (command as any).stallSince = Date.now();
    expect(command.getRunState()).toBe('stalled');

    // Abort
    command.stop();
    expect(command.getRunState()).toBe('aborted'); // NOT 'completed'
  });

  it('completed is a distinct terminal state (not collapsed from active:false)', async () => {
    const mod = await import('../index.js');
    const command = new mod.TempestCommand({ name: 'Complete Op', llm: { provider: 'mock', model: 'mock-model' } }) as any;
    command.start();
    const mission = command.mission.getActiveMission()!;
    command.mission.completeMission(mission.id);
    // Completion is a genuine terminal state — NOT collapsed into 'aborted' or a bare 'idle'.
    expect(command.getRunState()).toBe('completed');
    expect(command.getRunState()).not.toBe('aborted');
  });
});

describe('settings endpoints never expose secrets', () => {
  it('the timeout registry contains no credential/secret fields', () => {
    for (const s of TIMEOUT_REGISTRY) {
      expect(JSON.stringify(s).toLowerCase()).not.toMatch(/apikey|api_key|secret|password|token|credential/);
    }
  });
});
