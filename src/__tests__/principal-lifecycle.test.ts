import { afterEach, describe, expect, it, vi } from 'vitest';

// The test sandbox's undici build throws on import (webidl.util.markAsUncloneable) — pre-existing
// environment issue affecting every index.js-importing test. Nothing under test needs undici.
vi.mock('undici', () => ({
  Agent: class { },
  buildConnector: () => ({}),
  setGlobalDispatcher: () => { },
  fetch: (..._a: unknown[]) => Promise.reject(new Error('undici mocked in test')),
}));

import { TempestCommand, teardownAuthRuntime } from '../index.js';
import {
  Arsenal,
  BUILTIN_TOOLS,
  createToolContext,
  setRuntimeTargetHeaders,
  clearRuntimeTargetHeaders,
  peekRuntimeTargetHeaders,
} from '../arsenal/index.js';
import { listPrincipals, putPrincipals, teardownAllPrincipals } from '../principals/index.js';
import { clearRuntimeSecrets } from '../redact.js';

const ORIGIN = 'https://api.example';
const TOKEN = 'lifecycle-secret-token-zzzzzzzz';

function response(status = 200, body = '{}'): Response {
  const normalized = new Map<string, string>();
  return {
    status,
    statusText: 'OK',
    headers: {
      entries: () => normalized.entries(),
      get: (name: string) => normalized.get(name.toLowerCase()) ?? null,
    },
    text: async () => body,
    json: async () => JSON.parse(body),
  } as unknown as Response;
}

function sentAuthorization(mockFetch: ReturnType<typeof vi.fn>): string | null {
  const call = mockFetch.mock.calls[0];
  if (!call) return '__no_fetch__';
  return new Headers(call[1]?.headers).get('authorization');
}

async function executeOn(missionId?: string): Promise<{ auth: string | null; fetchCount: number }> {
  const arsenal = new Arsenal();
  arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
  const mockFetch = vi.fn().mockResolvedValue(response());
  vi.stubGlobal('fetch', mockFetch);
  await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, missionId));
  return { auth: sentAuthorization(mockFetch), fetchCount: mockFetch.mock.calls.length };
}

function liveCommand() {
  const command = new TempestCommand({ name: 'Auth Lifecycle', llm: { provider: 'mock', model: 'mock-model' } });
  command.targetEnv.addTarget({
    name: 'api', type: 'api', zone: 'external', address: ORIGIN,
  });
  const mission = command.mission.createMission({
    name: 'Auth Lifecycle', objectives: ['broad coverage'], objectiveClass: 'general', missionFamily: 'web_api',
  });
  command.mission.startMission(mission.id);
  putPrincipals(mission.id, [{
    id: 'a',
    label: 'A',
    origin: ORIGIN,
    auth: { type: 'static_bearer', token: TOKEN },
  }]);
  return { command, mission };
}

const originalOrigin = process.env.TEMPEST_TARGET_ORIGIN;
const originalHeaders = process.env.TEMPEST_TARGET_HEADERS;

afterEach(() => {
  if (originalOrigin === undefined) delete process.env.TEMPEST_TARGET_ORIGIN;
  else process.env.TEMPEST_TARGET_ORIGIN = originalOrigin;
  if (originalHeaders === undefined) delete process.env.TEMPEST_TARGET_HEADERS;
  else process.env.TEMPEST_TARGET_HEADERS = originalHeaders;
  teardownAllPrincipals();
  clearRuntimeTargetHeaders();
  clearRuntimeSecrets();
  vi.unstubAllGlobals();
});

describe('principal/OAuth lifecycle teardown', () => {
  it('complete clears runtime material; legacy singleton cannot reappear on that mission', async () => {
    delete process.env.TEMPEST_TARGET_ORIGIN;
    delete process.env.TEMPEST_TARGET_HEADERS;
    const { command, mission } = liveCommand();
    command.start();
    try {
      const before = await executeOn(mission.id);
      expect(before.auth).toBe(`Bearer ${TOKEN}`);
      command.mission.completeMission(mission.id);
      expect(listPrincipals(mission.id)).toEqual([]);
      expect(peekRuntimeTargetHeaders()).toBeNull();
      const afterClear = await executeOn(mission.id);
      expect(afterClear.auth).toBeNull();
      const anonClear = await executeOn();
      expect(anonClear.auth).toBeNull();
      setRuntimeTargetHeaders(ORIGIN, JSON.stringify({ Authorization: `Bearer ${TOKEN}` }));
      const afterRearm = await executeOn(mission.id);
      expect(afterRearm.auth).toBeNull();
    } finally {
      if (command.isRunning()) command.stop();
    }
  });

  it('abort clears runtime material and the legacy singleton', async () => {
    delete process.env.TEMPEST_TARGET_ORIGIN;
    delete process.env.TEMPEST_TARGET_HEADERS;
    const { command, mission } = liveCommand();
    setRuntimeTargetHeaders(ORIGIN, JSON.stringify({ Authorization: `Bearer ${TOKEN}` }));
    command.start();
    try {
      command.mission.abortMission(mission.id, 'operator abort');
      expect(listPrincipals(mission.id)).toEqual([]);
      expect(peekRuntimeTargetHeaders()).toBeNull();
      const after = await executeOn(mission.id);
      expect(after.auth).toBeNull();
      const anon = await executeOn();
      expect(anon.auth).toBeNull();
    } finally {
      if (command.isRunning()) command.stop();
    }
  });

  it('stop clears runtime material and the legacy singleton', async () => {
    delete process.env.TEMPEST_TARGET_ORIGIN;
    delete process.env.TEMPEST_TARGET_HEADERS;
    const { command, mission } = liveCommand();
    setRuntimeTargetHeaders(ORIGIN, JSON.stringify({ Authorization: `Bearer ${TOKEN}` }));
    command.start();
    command.stop();
    expect(listPrincipals(mission.id)).toEqual([]);
    expect(peekRuntimeTargetHeaders()).toBeNull();
    const after = await executeOn(mission.id);
    expect(after.auth).toBeNull();
    const anon = await executeOn();
    expect(anon.auth).toBeNull();
  });

  it('shutdown teardownAuthRuntime clears principals and the legacy singleton', async () => {
    delete process.env.TEMPEST_TARGET_ORIGIN;
    delete process.env.TEMPEST_TARGET_HEADERS;
    const { mission } = liveCommand();
    setRuntimeTargetHeaders(ORIGIN, JSON.stringify({ Authorization: `Bearer ${TOKEN}` }));
    expect(listPrincipals(mission.id).length).toBe(1);
    expect(peekRuntimeTargetHeaders()).not.toBeNull();
    teardownAuthRuntime();
    expect(listPrincipals(mission.id)).toEqual([]);
    expect(peekRuntimeTargetHeaders()).toBeNull();
    const after = await executeOn(mission.id);
    expect(after.auth).toBeNull();
    const anon = await executeOn();
    expect(anon.auth).toBeNull();
  });

  it('attachAuthToMission compiles legacy headers into one principal', async () => {
    delete process.env.TEMPEST_TARGET_ORIGIN;
    delete process.env.TEMPEST_TARGET_HEADERS;
    const command = new TempestCommand({ name: 'Compile', llm: { provider: 'mock', model: 'mock-model' } });
    const mission = command.mission.createMission({
      name: 'Compile', objectives: ['broad coverage'], objectiveClass: 'general', missionFamily: 'web_api',
    });
    command.mission.startMission(mission.id);
    setRuntimeTargetHeaders(ORIGIN, JSON.stringify({ Authorization: `Bearer ${TOKEN}` }));
    command.attachAuthToMission(mission.id);
    expect(listPrincipals(mission.id).map((p) => p.id)).toEqual(['legacy-headers']);
    clearRuntimeTargetHeaders();
    const sent = await executeOn(mission.id);
    expect(sent.auth).toBe(`Bearer ${TOKEN}`);
  });
});
