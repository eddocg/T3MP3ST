import { describe, it, expect, vi } from 'vitest';

// The test sandbox's undici build throws on import (webidl.util.markAsUncloneable) — pre-existing
// environment issue affecting every index.js-importing test. Nothing under test touches undici.
vi.mock('undici', () => ({
  Agent: class { },
  buildConnector: () => ({}),
  setGlobalDispatcher: () => { },
  fetch: (..._a: unknown[]) => Promise.reject(new Error('undici mocked in test')),
}));

import { maybeIngestOpenApiArtifact, buildSurfaceContext } from '../surface/context.js';
import type { LLMBackbone } from '../llm/index.js';
import type { Task } from '../types/index.js';
import { KillChainPhase } from '../types/index.js';

const ORIGIN = 'https://api.surface.test';

const SPEC = JSON.stringify({
  openapi: '3.0.3',
  info: { title: 'Live Surface', version: '1.0.0' },
  servers: [{ url: 'https://declared.only.example/v9' }],
  security: [{ ApiKeyAuth: [] }],
  paths: {
    '/accounts/{id}': { get: { operationId: 'getAccount', parameters: [{ name: 'id', in: 'path' }], responses: { '200': {} } } },
    '/health': { get: { operationId: 'health', security: [], responses: { '200': {} } } },
  },
  components: { securitySchemes: { ApiKeyAuth: { type: 'apiKey', in: 'header', name: 'X-API-Key' } } },
});

function makeTask(over: Partial<Task> = {}): Task {
  return {
    id: 'task-surface', name: 'Web Application Security Testing', description: 'test the surface',
    phase: KillChainPhase.RECON, status: 'pending', priority: 'high',
    createdAt: Date.now(), dependencies: [], ...over,
  } as Task;
}

async function liveCommand() {
  const mod = await import('../index.js');
  const command = new mod.TempestCommand({ name: 'Surface Op', llm: { provider: 'mock', model: 'mock-model' } }) as any;
  command.targetEnv.addTarget({
    id: 'target-1', name: 'api', type: 'api', zone: 'external', status: 'identified',
    address: ORIGIN, discoveredAt: Date.now(),
  });
  const mission = command.mission.createMission({
    name: 'Surface Op', objectives: ['broad coverage'], objectiveClass: 'general', missionFamily: 'web_api',
  });
  command.mission.startMission(mission.id);
  return { command, mission };
}

describe('P1A lifecycle — mission-scoped surface, terminal snapshot, teardown', () => {
  it('arms the pre-truncation sink on start(); a discovered spec ingests into the LIVE surface', async () => {
    const { command } = await liveCommand();
    command.start(); // arms the module sink to route into this command's active mission
    try {
      // Simulate a ScopeGuard-protected fetch handing the COMPLETE spec body to the sink.
      maybeIngestOpenApiArtifact(`${ORIGIN}/openapi.json`, 'application/json', SPEC);

      const view = command.getSurfaceView();
      expect(view).not.toBeNull();
      expect(view.source).toBe('live');
      expect(view.stats.operationCount).toBe(2);
      // Operations bind to the authorized fetch origin, not the declared server.
      expect(view.snapshot.operations.every((o: any) => o.origin === ORIGIN)).toBe(true);
      expect(view.stats.origins).toEqual([ORIGIN]);
      expect(JSON.stringify(view)).toContain('declared.only.example'); // metadata only
    } finally {
      command.stop();
    }
  });

  it('completion freezes an immutable terminal snapshot; getSurfaceView serves it post-completion', async () => {
    const { command, mission } = await liveCommand();
    command.start();
    maybeIngestOpenApiArtifact(`${ORIGIN}/openapi.json`, 'application/json', SPEC);
    expect(command.getSurfaceView().source).toBe('live');

    // Complete the mission — the completed listener snapshots BEFORE stop() tears state down.
    command.mission.completeMission(mission.id);

    const view = command.getSurfaceView();
    expect(view).not.toBeNull();
    expect(view.source).toBe('terminal');
    expect(view.missionId).toBe(mission.id);
    expect(view.stats.operationCount).toBe(2);
    // No raw document body is ever retained in terminal state.
    expect(JSON.stringify(view)).not.toContain('"openapi"');
  });

  it('abort/stop destroys mutable surface state and retains NO terminal snapshot', async () => {
    const { command } = await liveCommand();
    command.start();
    maybeIngestOpenApiArtifact(`${ORIGIN}/openapi.json`, 'application/json', SPEC);
    expect(command.getSurfaceView().source).toBe('live');

    command.stop(); // operator abort — not a completion
    expect(command.getSurfaceView()).toBeNull();
  });

  it('a post-teardown fetch cannot mutate a torn-down mission (sink disarmed)', async () => {
    const { command } = await liveCommand();
    command.start();
    command.stop();
    maybeIngestOpenApiArtifact(`${ORIGIN}/openapi.json`, 'application/json', SPEC);
    expect(command.getSurfaceView()).toBeNull();
  });
});

describe('P1A agent prompt — bounded surface context', () => {
  it('injects the redacted API-surface inventory so agents do not claim a missing path inventory', async () => {
    const { command } = await liveCommand();
    command.start();
    maybeIngestOpenApiArtifact(`${ORIGIN}/openapi.json`, 'application/json', SPEC);

    const { createAgentLoop } = await import('../agent/index.js');
    let seenPrompt = '';
    const capture = async (messages: Array<{ role: string; content: string }>) => {
      seenPrompt = messages.map((m) => m.content).join('\n');
      return { content: 'done\n```json\n{"findings":[],"outcome":"no_eligible_work"}\n```', toolCalls: [] };
    };
    const llm = { getProvider: () => 'mock', chat: vi.fn(capture), chatWithTools: vi.fn(capture) } as unknown as LLMBackbone;

    const agent = createAgentLoop(llm, command.arsenal, {
      maxIterations: 2,
      tools: ['http_request'],
      surfaceContext: () => buildSurfaceContext((command as any).getActiveSurfaceModel()),
    });
    await agent.run(makeTask(), 'Execute.');
    command.stop();

    expect(seenPrompt).toContain('API Surface');
    expect(seenPrompt).toContain(`${ORIGIN}/accounts/{id}`);
    expect(seenPrompt).toContain('INTELLIGENCE ONLY');
    expect(seenPrompt).not.toContain('X-API-Key: '); // no secret values
  });

  it('spawned operators receive the surface-context provider wired to the live command', async () => {
    const { command } = await liveCommand();
    command.start();
    maybeIngestOpenApiArtifact(`${ORIGIN}/openapi.json`, 'application/json', SPEC);

    let seenPrompt = '';
    const capture = async (messages: Array<{ role: string; content: string }>) => {
      seenPrompt = messages.map((m) => m.content).join('\n');
      return { content: 'done\n```json\n{"findings":[],"outcome":"no_eligible_work"}\n```', toolCalls: [] };
    };
    (command as any).llm = { getProvider: () => 'mock', chat: vi.fn(capture), chatWithTools: vi.fn(capture) };

    const operator = command.spawnOperator('Ghost-1', 'recon');
    await operator.executeTask(makeTask());
    command.stop();

    expect(seenPrompt).toContain('API Surface');
    expect(seenPrompt).toContain(`${ORIGIN}/accounts/{id}`);
  });
});
