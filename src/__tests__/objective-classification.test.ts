import { describe, it, expect, vi } from 'vitest';

// The test sandbox's undici build throws on import (webidl.util.markAsUncloneable) — a pre-existing
// environment issue that breaks every index.js-importing test. The classification logic under test
// never touches the network, so stub undici's exports before any transitive import of index.js.
vi.mock('undici', () => ({
  Agent: class { },
  buildConnector: () => ({}),
  setGlobalDispatcher: () => { },
  fetch: (..._a: unknown[]) => Promise.reject(new Error('undici mocked in test')),
}));

import { readFileSync } from 'fs';
import { join } from 'path';
import { MissionControl, detectObjectiveClass, parseObjectiveClassOverride } from '../mission/index.js';

// ─────────────────────────────────────────────────────────────────────────────
// BROAD-MISSION CLASSIFICATION regression coverage.
//
// The regression: a directive that explicitly requested COMPREHENSIVE reconnaissance and merely
// LISTED authorization/BOLA/lifecycle among many families was classified
// `authorization_lifecycle`, and the runtime executed ONLY the bounded authorization lane.
//
// Invariants pinned here:
//   - a specialized objective requires AFFIRMATIVE specialized intent (focus phrasing or
//     exclusively-specialized content), never the mere presence of security vocabulary;
//   - explicit breadth intent and multi-family listings classify `general`;
//   - `general` missions retain the original FULL T3MP3ST workflow (generic recon battery,
//     phase advancement through the kill chain — no objective-lane task substitution);
//   - explicit structural intent (brief slot / launch body) wins over the text heuristic.
// ─────────────────────────────────────────────────────────────────────────────

const TARGET = 'https://staging.api.example.test';

describe('detectObjectiveClass — dominant intent, not vocabulary presence', () => {
  it('broad/comprehensive directives that LIST authorization among many families classify general', () => {
    // The exact regression shape: comprehensive + no restriction + authz listed among families.
    expect(detectObjectiveClass(
      'Conduct comprehensive reconnaissance against the target. Do not restrict to one vulnerability family. ' +
      'Investigate authorization/BOLA, injection, SSRF, session fixation, lifecycle issues, and other relevant classes; ' +
      'broad discovery and research prioritization.',
    )).toBe('general');
    // The operator's literal examples.
    expect(detectObjectiveClass(
      'Comprehensive assessment; investigate authorization, injection, SSRF, sessions, lifecycle and other relevant classes',
    )).toBe('general');
    expect(detectObjectiveClass('Broad recon and let evidence determine the next vector')).toBe('general');
    expect(detectObjectiveClass(
      'Do not restrict testing to one vulnerability family; include authorization lifecycle among the families in scope',
    )).toBe('general');
  });

  it('authorization LISTED alongside other vuln families (no focus language) classifies general', () => {
    expect(detectObjectiveClass('Enumerate the API and test authorization boundaries plus XSS and SSRF')).toBe('general');
    // Mixed intent: "focus" language does not narrow a mission that also names other families.
    expect(detectObjectiveClass('Focus on authorization lifecycle, then also test injection and SSRF')).toBe('general');
  });

  it('affirmative narrow focus on the authorization lane classifies authorization_lifecycle', () => {
    expect(detectObjectiveClass('Focus exclusively on authorization lifecycle testing')).toBe('authorization_lifecycle');
    // The original focused directive this lane was built for.
    expect(detectObjectiveClass(
      'Focus on authenticated authorization lifecycle testing. Avoid unrelated generic configuration testing.',
    )).toBe('authorization_lifecycle');
    expect(detectObjectiveClass(
      'Conduct a guided, hypothesis-driven authorization assessment of the exact staging API origin using only ' +
      'controlled identities and resources. Concentrate on differential BOLA, function-level authorization, ' +
      'lifecycle invalidation, property authorization, and OAuth boundaries.',
    )).toBe('authorization_lifecycle');
  });

  it('exclusively-authorization content (no other family named) remains authorization_lifecycle', () => {
    // Existing behavior preserved — exclusivity is weak-affirmative intent.
    expect(detectObjectiveClass('Test authenticated BOLA / cross-user authorization lifecycle and revocation')).toBe('authorization_lifecycle');
    expect(detectObjectiveClass('Verify role boundaries and permission downgrade handling')).toBe('authorization_lifecycle');
    // "multiple roles" is enumeration WITHIN the lane, not breadth across families.
    expect(detectObjectiveClass('test authorization across multiple roles and tenants')).toBe('authorization_lifecycle');
  });

  it('non-authorization objectives are untouched', () => {
    expect(detectObjectiveClass('Map the external attack surface and find XSS')).toBe('general');
    expect(detectObjectiveClass('')).toBe('general');
  });
});

describe('parseObjectiveClassOverride — structural intent validation', () => {
  it('accepts the two known classes and rejects everything else (safe fallback to heuristic)', () => {
    expect(parseObjectiveClassOverride('general')).toBe('general');
    expect(parseObjectiveClassOverride('authorization_lifecycle')).toBe('authorization_lifecycle');
    expect(parseObjectiveClassOverride('')).toBeUndefined();
    expect(parseObjectiveClassOverride('bola')).toBeUndefined();
    expect(parseObjectiveClassOverride(undefined)).toBeUndefined();
    expect(parseObjectiveClassOverride({ class: 'general' })).toBeUndefined();
  });
});

describe('broad missions retain the FULL T3MP3ST workflow', () => {
  it('a broad directive mentioning authorization seeds the GENERAL recon battery, not the objective lane', () => {
    const mc = new MissionControl();
    const mission = mc.createMission({
      name: 'broad',
      objectives: ['Conduct comprehensive reconnaissance; investigate authorization, injection, SSRF, sessions, lifecycle and other relevant classes'],
    });
    expect(mission.objectiveClass).toBe('general');
    mc.startMission(mission.id);
    mc.generateTasksForTarget(TARGET);
    const tasks = mc.getTaskQueue().getForMission(mission.id);
    const names = tasks.map((t) => t.name).join('\n');
    // The standard recon battery — the original workflow.
    expect(names).toContain('DNS Enumeration');
    expect(names).toContain('Port Scanning & Service Detection');
    // No objective-lane substitution: no blocked fixture records, no lane-tagged tasks.
    expect(tasks.some((t) => t.status === 'blocked')).toBe(false);
    expect(tasks.every((t) => !t.description.includes('[objective:authorization_lifecycle]'))).toBe(true);
  });

  it('a general mission advances into the generic kill-chain batteries (vuln scan etc.)', () => {
    const mc = new MissionControl();
    const mission = mc.createMission({
      name: 'broad-2',
      objectives: ['Broad recon and let evidence determine the next vector'],
    });
    expect(mission.objectiveClass).toBe('general');
    mc.startMission(mission.id);
    mc.generateTasksForTarget(TARGET);
    // Complete the recon phase, then advance — the general lane must keep generating work.
    const tq = mc.getTaskQueue();
    for (const t of tq.getForMission(mission.id)) tq.complete(t.id, { success: true, output: 'done' });
    mc.advancePhase(mission.id);
    mc.generateNextPhaseTasks(TARGET);
    const names = tq.getForMission(mission.id).map((t) => t.name).join('\n');
    expect(names).toContain('Web Application Security Testing');
  });

  it('an affirmatively focused directive seeds the BOUNDED objective lane instead', () => {
    const mc = new MissionControl();
    const mission = mc.createMission({
      name: 'focused',
      objectives: ['Focus exclusively on authorization lifecycle testing'],
    });
    expect(mission.objectiveClass).toBe('authorization_lifecycle');
    mc.startMission(mission.id);
    mc.generateTasksForTarget(TARGET);
    const tasks = mc.getTaskQueue().getForMission(mission.id);
    const names = tasks.map((t) => t.name).join('\n');
    expect(tasks.filter((t) => t.status === 'blocked').length).toBe(2);
    expect(names).toContain('authenticated API surface map');
    expect(names).not.toContain('DNS Enumeration');
  });

  it('an explicit structural objectiveClass beats the text heuristic entirely', () => {
    const mc = new MissionControl();
    // Focus PHRASING in the text, but the operator structurally declared a broad mission —
    // structural intent wins and the full battery is seeded.
    const broad = mc.createMission({
      name: 'override-broad',
      objectives: ['Focus exclusively on authorization lifecycle testing'],
      objectiveClass: 'general',
    });
    expect(broad.objectiveClass).toBe('general');
    mc.startMission(broad.id);
    mc.generateTasksForTarget(TARGET);
    expect(mc.getTaskQueue().getForMission(broad.id).map((t) => t.name).join('\n')).toContain('DNS Enumeration');

    // And the inverse: broad-sounding text, structural narrow intent.
    const mc2 = new MissionControl();
    const narrow = mc2.createMission({
      name: 'override-narrow',
      objectives: ['Comprehensive assessment including authorization lifecycle'],
      objectiveClass: 'authorization_lifecycle',
    });
    expect(narrow.objectiveClass).toBe('authorization_lifecycle');
    mc2.startMission(narrow.id);
    mc2.generateTasksForTarget(TARGET);
    expect(mc2.getTaskQueue().getForMission(narrow.id).some((t) => t.status === 'blocked')).toBe(true);
  });

  it('TempestCommand auto-mission from a broad directive classifies general (end-to-end wiring)', async () => {
    const mod = await import('../index.js');
    const command = new mod.TempestCommand({
      name: 'Broad Op',
      objectiveDirective: 'Comprehensive assessment; investigate authorization, injection, SSRF, sessions, lifecycle and other relevant classes',
      llm: { provider: 'mock', model: 'mock-model' },
    }) as any;
    command.ensureMission();
    const mission = command.mission.getActiveMission();
    expect(mission).toBeTruthy();
    expect(mission.objectiveClass).toBe('general');
  });

  it('TempestCommand auto-mission from a focused directive classifies authorization_lifecycle', async () => {
    const mod = await import('../index.js');
    const command = new mod.TempestCommand({
      name: 'Focused Op',
      objectiveDirective: 'Focus exclusively on authorization lifecycle testing',
      llm: { provider: 'mock', model: 'mock-model' },
    }) as any;
    command.ensureMission();
    expect(command.mission.getActiveMission()?.objectiveClass).toBe('authorization_lifecycle');
  });
});

// ── Server/Admiral surface invariants (static — importing server.ts would start the listener) ──
const serverSource = readFileSync(join(process.cwd(), 'src/server.ts'), 'utf8');
const admiralSource = readFileSync(join(process.cwd(), 'src/admiral/index.ts'), 'utf8');
const uiSource = readFileSync(join(process.cwd(), 'docs/index.html'), 'utf8');

describe('structural intent plumbing — explicit objectiveClass wins over text detection', () => {
  it('the Admiral launch route resolves body > brief > text-heuristic, in that order', () => {
    const route = serverSource.slice(
      serverSource.indexOf("app.post('/api/admiral/launch'"),
      serverSource.indexOf('BOUNTY PLATFORM INTEGRATIONS'),
    );
    expect(route).toContain('parseObjectiveClassOverride((req.body as Record<string, unknown>).objectiveClass)');
    expect(route).toContain('?? parseObjectiveClassOverride(brief.objectiveClass)');
    expect(route).toContain('?? detectObjectiveClass(');
    // Both dry-run and live responses echo the effective classification (transparency).
    expect(route).toContain("mode: 'dry_run', plan, directive, objectiveClass");
    expect(route).toContain("mode: 'live', plan, review: execConfig.review, objectiveClass");
  });

  it('/api/general/execute and /api/general/auto accept the explicit structural override', () => {
    const executeRoute = serverSource.slice(
      serverSource.indexOf("app.post('/api/general/execute'"),
      serverSource.indexOf("app.post('/api/general/auto'"),
    );
    expect(executeRoute).toContain('parseObjectiveClassOverride');
    const autoRoute = serverSource.slice(
      serverSource.indexOf("app.post('/api/general/auto'"),
      serverSource.indexOf("app.post('/api/admiral/converse'"),
    );
    expect(autoRoute).toContain('parseObjectiveClassOverride');
  });

  it('the Admiral brief carries the optional structural slot, documented + coerced safely', () => {
    expect(admiralSource).toContain('objectiveClass?: MissionObjectiveClass');
    // The prompt documents the slot AND the vocabulary-is-not-intent rule.
    expect(admiralSource).toContain('objective_class');
    expect(admiralSource).toContain('Vocabulary is not intent');
    // coerceTurn validates against the known classes (anything else falls back to heuristic).
    expect(admiralSource).toContain("rawClass === 'authorization_lifecycle' || rawClass === 'general'");
  });

  it('Guided Hunt exposes the structural focus control and sends it on the brief', () => {
    // Step-3 control with broad coverage as the default choice (options rendered via map).
    expect(uiSource).toContain('Objective focus');
    expect(uiSource).toContain('Broad coverage');
    expect(uiSource).toContain("{id:'authorization_lifecycle',label:'Authorization lifecycle'");
    expect(uiSource).toContain("admiralSet(\\'focus\\',\\''+x.id+'\\')");
    // The brief builder forwards the structural slot (and only when explicitly chosen).
    expect(uiSource).toContain('if (S.focus) brief.objectiveClass = S.focus;');
    // Wizard state initializes the focus slot to broad ('').
    expect(uiSource).toContain("focus:''");
  });
});

describe('auth-context metadata naming — headerCount is not principalCount', () => {
  it('mission-context exposes headerCount + principalCount, never a bare ambiguous count', () => {
    const live = serverSource.slice(
      serverSource.indexOf('function liveObjectiveBlock'),
      serverSource.indexOf('function snapshotObjectiveBlock'),
    );
    expect(live).toContain('headerCount: auth.headerCount');
    expect(live).toContain('principalCount: auth.principalCount');
    expect(live).not.toContain('count: auth.headerNames.length,');
    const snapshotBlock = serverSource.slice(
      serverSource.indexOf('function snapshotObjectiveBlock'),
      serverSource.indexOf('function workOrderSquadForFamily'),
    );
    expect(snapshotBlock).toContain('headerCount');
    expect(snapshotBlock).toContain('principalCount');
  });

  it('the terminal snapshot schema + builder carry the explicit counts (redaction-safe)', () => {
    expect(serverSource).toContain('authContext: { present: boolean; origin: string | null; headerNames: string[]; headerCount: number; principalCount: number }');
    const builder = serverSource.slice(
      serverSource.indexOf('function recordTerminalMissionSnapshot'),
      serverSource.indexOf('function materializeBlockedPrerequisite'),
    );
    expect(builder).toContain('headerCount: auth.headerCount');
    expect(builder).toContain('principalCount: auth.principalCount');
    // Secrets invariant: the builder still touches header NAMES only.
    expect(builder).toContain('snapshotAuthContext');
    expect(builder).not.toContain('headers.values()');
  });
});
