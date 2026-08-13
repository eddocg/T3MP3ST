import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { createServer } from 'node:http';
import { request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';
import vm from 'node:vm';
import { Arsenal, BUILTIN_TOOLS, createToolContext, clearRuntimeTargetHeaders } from '../arsenal/index.js';
import {
  putPrincipals,
  listPrincipals,
  getStoredPrincipal,
  acquireOAuth,
  refreshOAuth,
  ensureOAuthAccess,
  fetchOAuthDiscovery,
  setPrincipalOauthMaterial,
  compilePrincipalHeaders,
  oauthHeadersAttachable,
  principalsListBody,
  oauthActionBody,
  teardownAllPrincipals,
} from '../principals/index.js';
import { redactString, clearRuntimeSecrets } from '../redact.js';

const ORIGIN = 'https://api.example';
const LAB_SCOPE = { allowedHosts: ['api.example'], allowLoopback: true, allowPrivate: true };

function response(status = 200, body = '{}', headers: Record<string, string> = {}): Response {
  const normalized = new Map(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]));
  return {
    status,
    statusText: status === 200 ? 'OK' : 'ERR',
    headers: {
      entries: () => normalized.entries(),
      get: (name: string) => normalized.get(name.toLowerCase()) ?? null,
    },
    text: async () => body,
    json: async () => JSON.parse(body),
    arrayBuffer: async () => Buffer.from(body),
  } as unknown as Response;
}

function tokenBody(call: unknown[]): URLSearchParams {
  const init = call[1] as RequestInit | undefined;
  return new URLSearchParams(String(init?.body || ''));
}

afterEach(() => {
  teardownAllPrincipals();
  clearRuntimeTargetHeaders();
  clearRuntimeSecrets();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('P2B.1 password grant + clientAuth', () => {
  it.each(['none', 'basic', 'body'] as const)('password grant with clientAuth %s', async (clientAuth) => {
    putPrincipals('m1', [{
      id: 'pw',
      label: 'Password',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        flow: 'password',
        tokenUrl: `${ORIGIN}/token`,
        clientId: 'cid',
        clientSecret: clientAuth === 'none' ? undefined : 'oauth-client-secret-value',
        clientAuth,
        username: 'operator',
        password: 'pw-secret-value-zzzzzzzz',
      },
    }]);
    const mockFetch = vi.fn().mockResolvedValue(response(200, JSON.stringify({
      access_token: 'access-password-zzzzzzzz',
      token_type: 'Bearer',
      expires_in: 3600,
    })));
    vi.stubGlobal('fetch', mockFetch);
    const result = await acquireOAuth('m1', 'pw', LAB_SCOPE);
    expect(result.ok).toBe(true);
    const body = tokenBody(mockFetch.mock.calls[0]);
    expect(body.get('grant_type')).toBe('password');
    expect(body.get('username')).toBe('operator');
    expect(body.get('password')).toBe('pw-secret-value-zzzzzzzz');
    const headers = new Headers(mockFetch.mock.calls[0][1]?.headers);
    if (clientAuth === 'basic') {
      expect(headers.get('authorization')).toMatch(/^Basic /);
      expect(body.get('client_secret')).toBeNull();
    } else if (clientAuth === 'body') {
      expect(body.get('client_id')).toBe('cid');
      expect(body.get('client_secret')).toBe('oauth-client-secret-value');
    } else {
      expect(headers.get('authorization')).toBeNull();
      expect(body.get('client_secret')).toBeNull();
    }
    expect(JSON.stringify(listPrincipals('m1'))).not.toContain('pw-secret-value-zzzzzzzz');
  });

  it('password expiry refreshes when refresh_token exists else reacquires', async () => {
    putPrincipals('m1', [{
      id: 'pw',
      label: 'Password',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        grantType: 'password',
        tokenUrl: `${ORIGIN}/token`,
        clientAuth: 'none',
        username: 'operator',
        password: 'pw-secret-value-zzzzzzzz',
      },
    }]);
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(response(200, JSON.stringify({
        access_token: 'access-old-yyyyyyyy', token_type: 'Bearer', refresh_token: 'refresh-old-yyyyyyyy', expires_in: 1,
      })))
      .mockResolvedValueOnce(response(200, JSON.stringify({
        access_token: 'access-new-xxxxxxxx', token_type: 'Bearer', refresh_token: 'refresh-new-xxxxxxxx', expires_in: 3600,
      }))));
    await acquireOAuth('m1', 'pw', LAB_SCOPE);
    const refreshed = await refreshOAuth('m1', 'pw', LAB_SCOPE);
    expect(refreshed.ok).toBe(true);
    expect(getStoredPrincipal('m1', 'pw')!.oauth?.accessToken).toBe('access-new-xxxxxxxx');

    putPrincipals('m2', [{
      id: 'pw2',
      label: 'Password',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        grantType: 'password',
        tokenUrl: `${ORIGIN}/token`,
        clientAuth: 'none',
        username: 'operator',
        password: 'pw-secret-value-zzzzzzzz',
      },
    }]);
    setPrincipalOauthMaterial('m2', 'pw2', {
      accessToken: 'access-old-yyyyyyyy',
      tokenType: 'Bearer',
      expiresAt: Date.now() - 1000,
      runtimeStatus: 'live',
    });
    const mockFetch = vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).includes('/token')) {
        const body = new URLSearchParams(String(init?.body || ''));
        expect(body.get('grant_type')).toBe('password');
        return response(200, JSON.stringify({ access_token: 'access-reacq-zzzzzzzz', token_type: 'Bearer', expires_in: 3600 }));
      }
      return response();
    });
    vi.stubGlobal('fetch', mockFetch);
    await ensureOAuthAccess('m2', 'pw2', LAB_SCOPE);
    expect(getStoredPrincipal('m2', 'pw2')!.oauth?.accessToken).toBe('access-reacq-zzzzzzzz');
  });

  it('password acquisition invalid_grant does not loop', async () => {
    putPrincipals('m1', [{
      id: 'pw',
      label: 'Password',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        grantType: 'password',
        tokenUrl: `${ORIGIN}/token`,
        clientAuth: 'none',
        username: 'operator',
        password: 'pw-secret-value-zzzzzzzz',
      },
    }]);
    const mockFetch = vi.fn().mockResolvedValue(response(400, JSON.stringify({ error: 'invalid_grant' })));
    vi.stubGlobal('fetch', mockFetch);
    const first = await acquireOAuth('m1', 'pw', LAB_SCOPE);
    expect(first.ok).toBe(false);
    expect(first.code).toBe('oauth_invalid_grant');
    await ensureOAuthAccess('m1', 'pw', LAB_SCOPE);
    expect(mockFetch.mock.calls.length).toBe(1);
  });
});

describe('P2B.1 client_credentials auto-reacquire', () => {
  it('CC expiry without refresh reacquires once', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    setPrincipalOauthMaterial('m1', 'oauth', {
      accessToken: 'access-old-yyyyyyyy',
      tokenType: 'Bearer',
      expiresAt: Date.now() - 1000,
      runtimeStatus: 'live',
    });
    const mockFetch = vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).includes('/token')) {
        const body = new URLSearchParams(String(init?.body || ''));
        expect(body.get('grant_type')).toBe('client_credentials');
        return response(200, JSON.stringify({ access_token: 'access-reacq-zzzzzzzz', token_type: 'Bearer', expires_in: 3600 }));
      }
      return response();
    });
    vi.stubGlobal('fetch', mockFetch);
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    expect(mockFetch.mock.calls.filter((c) => String(c[0]).includes('/token'))).toHaveLength(1);
    expect(getStoredPrincipal('m1', 'oauth')!.oauth?.accessToken).toBe('access-reacq-zzzzzzzz');
  });
});

describe('P2B.1 multi-principal isolation', () => {
  it('parallel A/B acquire and A renewal does not mutate B', async () => {
    putPrincipals('m1', [
      { id: 'a', label: 'A', origin: ORIGIN, default: true, auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid-a', clientSecret: 'secret-a-zzzzzzzz' } },
      { id: 'b', label: 'B', origin: ORIGIN, auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid-b', clientSecret: 'secret-b-zzzzzzzz' } },
    ]);
    const mockFetch = vi.fn(async (_url: string, init?: RequestInit) => {
      const body = new URLSearchParams(String(init?.body || ''));
      const id = body.get('client_id');
      return response(200, JSON.stringify({
        access_token: id === 'cid-a' ? 'access-a-zzzzzzzz' : 'access-b-zzzzzzzz',
        token_type: 'Bearer',
        refresh_token: id === 'cid-a' ? 'refresh-a-zzzzzzzz' : 'refresh-b-zzzzzzzz',
        expires_in: 3600,
      }));
    });
    vi.stubGlobal('fetch', mockFetch);
    const [ra, rb] = await Promise.all([acquireOAuth('m1', 'a', LAB_SCOPE), acquireOAuth('m1', 'b', LAB_SCOPE)]);
    expect(ra.ok && rb.ok).toBe(true);
    expect(getStoredPrincipal('m1', 'a')!.oauth?.accessToken).toBe('access-a-zzzzzzzz');
    expect(getStoredPrincipal('m1', 'b')!.oauth?.accessToken).toBe('access-b-zzzzzzzz');
    await refreshOAuth('m1', 'a', LAB_SCOPE);
    expect(getStoredPrincipal('m1', 'b')!.oauth?.accessToken).toBe('access-b-zzzzzzzz');
    expect(getStoredPrincipal('m1', 'b')!.oauth?.refreshToken).toBe('refresh-b-zzzzzzzz');
  });
});

describe('P2B.1 extension grant + reserved collision', () => {
  it('posts custom URN with safe and secret params', async () => {
    putPrincipals('m1', [{
      id: 'ext',
      label: 'Ext',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        grantType: 'extension',
        tokenUrl: `${ORIGIN}/token`,
        extensionGrantType: 'urn:ietf:params:oauth:grant-type:token-exchange',
        safeParams: { requested_token_type: 'access_token' },
        secretParams: { subject_token: 'subject-token-zzzzzzzz' },
        renewalPolicy: 'repeat_grant',
        clientAuth: 'none',
      },
    }]);
    const mockFetch = vi.fn().mockResolvedValue(response(200, JSON.stringify({
      access_token: 'access-ext-zzzzzzzz', token_type: 'Bearer', expires_in: 3600,
    })));
    vi.stubGlobal('fetch', mockFetch);
    const result = await acquireOAuth('m1', 'ext', LAB_SCOPE);
    expect(result.ok).toBe(true);
    const body = tokenBody(mockFetch.mock.calls[0]);
    expect(body.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(body.get('requested_token_type')).toBe('access_token');
    expect(body.get('subject_token')).toBe('subject-token-zzzzzzzz');
    expect(JSON.stringify(listPrincipals('m1'))).not.toContain('subject-token-zzzzzzzz');
  });

  it('rejects reserved parameter collision', () => {
    const put = putPrincipals('m1', [{
      id: 'ext',
      label: 'Ext',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        grantType: 'extension',
        tokenUrl: `${ORIGIN}/token`,
        extensionGrantType: 'urn:example:custom',
        extraTokenParams: { grant_type: 'hijack' },
        renewalPolicy: 'never',
        clientAuth: 'none',
      },
    }]);
    expect(put.ok).toBe(false);
    if (!put.ok) expect(put.error).toBe('oauth_reserved_parameter_collision');
  });
});

describe('P2B.1 unified single-flight', () => {
  it('20 concurrent ensure calls share one token operation', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    setPrincipalOauthMaterial('m1', 'oauth', {
      accessToken: 'access-old-yyyyyyyy',
      refreshToken: 'refresh-old-yyyyyyyy',
      tokenType: 'Bearer',
      expiresAt: Date.now() - 1000,
      runtimeStatus: 'live',
    });
    let tokenPosts = 0;
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (String(url).includes('/token')) {
        tokenPosts += 1;
        await new Promise((r) => setTimeout(r, 20));
        return response(200, JSON.stringify({
          access_token: 'access-new-xxxxxxxx', token_type: 'Bearer', refresh_token: 'refresh-new-xxxxxxxx', expires_in: 3600,
        }));
      }
      return response();
    }));
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    await Promise.all(Array.from({ length: 20 }, () =>
      arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'))));
    expect(tokenPosts).toBe(1);
  });

  it('concurrent refresh vs reacquire results in one token operation', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    setPrincipalOauthMaterial('m1', 'oauth', {
      accessToken: 'access-old-yyyyyyyy',
      refreshToken: 'refresh-old-yyyyyyyy',
      tokenType: 'Bearer',
      expiresAt: Date.now() - 1000,
      runtimeStatus: 'live',
    });
    const grantTypes: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).includes('/token')) {
        grantTypes.push(new URLSearchParams(String(init?.body || '')).get('grant_type') || '');
        await new Promise((r) => setTimeout(r, 20));
        return response(200, JSON.stringify({
          access_token: 'access-new-xxxxxxxx', token_type: 'Bearer', refresh_token: 'refresh-new-xxxxxxxx', expires_in: 3600,
        }));
      }
      return response();
    }));
    await Promise.all([
      ensureOAuthAccess('m1', 'oauth', LAB_SCOPE),
      refreshOAuth('m1', 'oauth', LAB_SCOPE),
      ensureOAuthAccess('m1', 'oauth', LAB_SCOPE, { forceRenewal: true }),
    ]);
    expect(grantTypes).toHaveLength(1);
    expect(grantTypes[0]).toBe('refresh_token');
  });
});

describe('P2B.1 principal PUT revision', () => {
  it('LIVE principal + label-only PUT preserves token/runtime', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(200, JSON.stringify({
      access_token: 'access-live-zzzzzzzz', token_type: 'Bearer', expires_in: 3600,
    }))));
    await acquireOAuth('m1', 'oauth', LAB_SCOPE);
    const before = getStoredPrincipal('m1', 'oauth')!;
    const put = putPrincipals('m1', [{
      id: 'oauth',
      label: 'Renamed',
      roleHint: 'operator',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid' },
    }]);
    expect(put.ok).toBe(true);
    const after = getStoredPrincipal('m1', 'oauth')!;
    expect(after.label).toBe('Renamed');
    expect(after.runtimeStatus).toBe('live');
    expect(after.oauth?.accessToken).toBe(before.oauth?.accessToken);
    expect(after.authConfigRevision).toBe(before.authConfigRevision);
  });

  it('omitted write-only password preserves stored password', async () => {
    putPrincipals('m1', [{
      id: 'pw',
      label: 'Password',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        grantType: 'password',
        tokenUrl: `${ORIGIN}/token`,
        clientAuth: 'none',
        username: 'operator',
        password: 'pw-secret-value-zzzzzzzz',
      },
    }]);
    putPrincipals('m1', [{
      id: 'pw',
      label: 'Password',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        grantType: 'password',
        tokenUrl: `${ORIGIN}/token`,
        clientAuth: 'none',
        username: 'operator',
      },
    }]);
    const stored = getStoredPrincipal('m1', 'pw')!;
    expect(stored.auth.type).toBe('oauth2');
    if (stored.auth.type === 'oauth2') expect(stored.auth.password).toBe('pw-secret-value-zzzzzzzz');
    const mockFetch = vi.fn().mockResolvedValue(response(200, JSON.stringify({
      access_token: 'access-password-zzzzzzzz', token_type: 'Bearer', expires_in: 3600,
    })));
    vi.stubGlobal('fetch', mockFetch);
    await acquireOAuth('m1', 'pw', LAB_SCOPE);
    expect(tokenBody(mockFetch.mock.calls[0]).get('password')).toBe('pw-secret-value-zzzzzzzz');
  });

  it('auth-semantic edit invalidates runtime and old token cannot attach', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(200, JSON.stringify({
      access_token: 'access-live-zzzzzzzz', token_type: 'Bearer', expires_in: 3600,
    }))));
    await acquireOAuth('m1', 'oauth', LAB_SCOPE);
    const oldToken = getStoredPrincipal('m1', 'oauth')!.oauth?.accessToken;
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token2`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    const after = getStoredPrincipal('m1', 'oauth')!;
    expect(after.runtimeStatus).toBe('unknown');
    expect(after.oauth?.accessToken).toBeUndefined();
    expect(oauthHeadersAttachable(after)).toBe(false);
    expect(compilePrincipalHeaders(after)).toBeNull();
    expect(oldToken).toBe('access-live-zzzzzzzz');
  });
});

describe('P2B.1 short secret containment', () => {
  it('short explicit secrets do not serialize and do not corrupt unrelated output', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        flow: 'client_credentials',
        tokenUrl: `${ORIGIN}/token`,
        clientId: 'cid',
        clientSecret: 'ab',
        extraTokenParams: { hint: 'public-hint' },
      },
    }]);
    const listed = JSON.stringify(listPrincipals('m1'));
    expect(listed).not.toMatch(/"clientSecret"/);
    expect(listed).not.toContain('"ab"');
    expect(redactString('status: ok, host api.example')).toContain('api.example');
    expect(redactString('ab')).toBe('ab');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(200, JSON.stringify({
      access_token: 'xy', token_type: 'Bearer', expires_in: 3600,
    }))));
    const acquired = await acquireOAuth('m1', 'oauth', LAB_SCOPE);
    expect(JSON.stringify(acquired)).not.toContain('"xy"');
    expect(JSON.stringify(acquired.principal)).not.toMatch(/"clientSecret"\s*:/);
    expect(JSON.stringify(acquired.principal)).not.toContain('"clientSecret"');
  });
});

describe('P2B.1 resource indicators', () => {
  it('serializes repeated resource parameters and keeps audience separate', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        flow: 'client_credentials',
        tokenUrl: `${ORIGIN}/token`,
        clientId: 'cid',
        clientSecret: 'oauth-client-secret-value',
        resource: ['https://api.example/one', 'https://api.example/two'],
        audience: 'vendor-aud',
      },
    }]);
    const mockFetch = vi.fn().mockResolvedValue(response(200, JSON.stringify({
      access_token: 'access-live-zzzzzzzz', token_type: 'Bearer', expires_in: 3600,
    })));
    vi.stubGlobal('fetch', mockFetch);
    await acquireOAuth('m1', 'oauth', LAB_SCOPE);
    const raw = String(mockFetch.mock.calls[0][1]?.body || '');
    expect(raw.match(/resource=/g)?.length).toBe(2);
    expect(raw).toContain('audience=vendor-aud');
    expect(listPrincipals('m1')[0].oauth?.resource).toEqual(['https://api.example/one', 'https://api.example/two']);
    expect(listPrincipals('m1')[0].oauth?.audience).toBe('vendor-aud');
  });
});

describe('P2B.1 scoped HTTP redirects', () => {
  it('metadata redirect to unauthorized origin performs zero request there', async () => {
    const mockFetch = vi.fn(async (url: string) => {
      if (String(url) === `${ORIGIN}/.well-known/oauth-authorization-server`) {
        return response(302, '', { location: 'https://evil.example/metadata' });
      }
      return response(200, '{}');
    });
    vi.stubGlobal('fetch', mockFetch);
    const result = await fetchOAuthDiscovery(`${ORIGIN}/.well-known/oauth-authorization-server`, {
      allowedHosts: ['api.example'], allowLoopback: false, allowPrivate: false,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('oauth_scope_denied');
    expect(mockFetch.mock.calls.map((c) => String(c[0]))).not.toContain('https://evil.example/metadata');
  });

  it('token POST redirect is not followed and credentials are not forwarded', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    const mockFetch = vi.fn().mockResolvedValue(response(302, '', { location: 'https://evil.example/token' }));
    vi.stubGlobal('fetch', mockFetch);
    const result = await acquireOAuth('m1', 'oauth', LAB_SCOPE);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('oauth_unexpected_redirect');
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(String(mockFetch.mock.calls[0][0])).toBe(`${ORIGIN}/token`);
    expect(mockFetch.mock.calls[0][1]).toMatchObject({ redirect: 'manual' });
  });
});

describe('P2B.1 401/403 renewal provenance', () => {
  it('401 without actual OAuth attachment triggers zero renewal', async () => {
    putPrincipals('m1', [{
      id: 'bearer',
      label: 'Bearer',
      origin: ORIGIN,
      auth: { type: 'static_bearer', token: 'static-bearer-token-zzzzzzzz' },
    }]);
    const mockFetch = vi.fn().mockResolvedValue(response(401));
    vi.stubGlobal('fetch', mockFetch);
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    expect(mockFetch.mock.calls.every((c) => !String(c[0]).includes('/token'))).toBe(true);
  });

  it('403 never triggers OAuth renewal', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    setPrincipalOauthMaterial('m1', 'oauth', {
      accessToken: 'access-live-zzzzzzzz',
      refreshToken: 'refresh-old-yyyyyyyy',
      tokenType: 'Bearer',
      expiresAt: Date.now() + 3600_000,
      runtimeStatus: 'live',
    });
    const mockFetch = vi.fn().mockResolvedValue(response(403));
    vi.stubGlobal('fetch', mockFetch);
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    expect(mockFetch.mock.calls.filter((c) => String(c[0]).includes('/token'))).toHaveLength(0);
  });

  it('authMode none does not renew OAuth on 401', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    setPrincipalOauthMaterial('m1', 'oauth', {
      accessToken: 'access-live-zzzzzzzz',
      refreshToken: 'refresh-old-yyyyyyyy',
      tokenType: 'Bearer',
      expiresAt: Date.now() + 3600_000,
      runtimeStatus: 'live',
    });
    const mockFetch = vi.fn().mockResolvedValue(response(401));
    vi.stubGlobal('fetch', mockFetch);
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1`, authMode: 'none' }, 'm1'));
    expect(mockFetch.mock.calls.filter((c) => String(c[0]).includes('/token'))).toHaveLength(0);
  });
});

describe('P2B.1 full HTTP DTO round-trip', () => {
  it('PUT/GET principal public DTO over a local HTTP server', async () => {
    const secret = 'roundtrip-client-secret-zzzz';
    const server = createServer((req, res) => {
      const url = new URL(req.url || '/', 'http://127.0.0.1');
      res.setHeader('content-type', 'application/json');
      void (async () => {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        const raw = Buffer.concat(chunks).toString('utf8');
        if (req.method === 'PUT' && url.pathname === '/api/mission/principals') {
          const body = JSON.parse(raw) as { principals: Parameters<typeof putPrincipals>[1] };
          const result = putPrincipals('m1', body.principals);
          res.statusCode = result.ok ? 200 : 400;
          res.end(JSON.stringify(result.ok ? principalsListBody('m1') : { error: result.error }));
          return;
        }
        if (req.method === 'GET' && url.pathname === '/api/mission/principals') {
          res.end(JSON.stringify(principalsListBody('m1')));
          return;
        }
        if (req.method === 'POST' && url.pathname.endsWith('/auth/acquire')) {
          const result = await acquireOAuth('m1', 'oauth', LAB_SCOPE);
          res.statusCode = result.ok ? 200 : 400;
          res.end(JSON.stringify(oauthActionBody(result)));
          return;
        }
        res.statusCode = 404;
        res.end('{}');
      })();
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${port}`;
    const httpJson = (path: string, opts?: { method?: string; body?: string }) => new Promise<{ status: number; json: Record<string, unknown> }>((resolve, reject) => {
      const parsed = new URL(path);
      const req = httpRequest({
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        method: opts?.method || 'GET',
        headers: { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(opts?.body || '')) },
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => resolve({ status: res.statusCode || 0, json: data ? JSON.parse(data) as Record<string, unknown> : {} }));
      });
      req.on('error', reject);
      if (opts?.body) req.write(opts.body);
      req.end();
    });
    try {
      const put = await httpJson(`${base}/api/mission/principals`, {
        method: 'PUT',
        body: JSON.stringify({
          principals: [{
            id: 'oauth',
            label: 'OAuth',
            origin: ORIGIN,
            auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: secret },
          }],
        }),
      });
      expect(put.status).toBe(200);
      expect(JSON.stringify(put.json)).not.toContain(secret);
      const principal = (put.json.principals as Array<Record<string, unknown>>)[0];
      const oauth = principal.oauth as Record<string, unknown>;
      expect(oauth.grantType).toBe('client_credentials');
      expect(oauth.tokenUrl).toBe(`${ORIGIN}/token`);
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(200, JSON.stringify({
        access_token: 'roundtrip-access-zzzzzzzz', token_type: 'Bearer', expires_in: 3600,
      }))));
      const acquired = await httpJson(`${base}/api/mission/principals/oauth/auth/acquire`, { method: 'POST', body: '{}' });
      expect(acquired.status).toBe(200);
      expect(JSON.stringify(acquired.json)).not.toContain('roundtrip-access-zzzzzzzz');
      expect(JSON.stringify(acquired.json)).not.toContain(secret);
      const listed = await httpJson(`${base}/api/mission/principals`);
      expect((listed.json.principals as Array<Record<string, unknown>>)[0].runtimeStatus).toBe('live');
    } finally {
      await new Promise<void>((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
    }
  });
});

function extractNamedFunction(source: string, name: string): string {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`missing ${name}`);
  const brace = source.indexOf('{', start);
  let depth = 0;
  for (let i = brace; i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}') {
      depth--;
      if (depth === 0) return source.slice(start, i + 1);
    }
  }
  throw new Error(`unclosed ${name}`);
}

function extractWindowFunction(source: string, name: string): string {
  const start = source.indexOf(`window.${name} = function`);
  if (start < 0) throw new Error(`missing window.${name}`);
  const brace = source.indexOf('{', start);
  let depth = 0;
  for (let i = brace; i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}') {
      depth--;
      if (depth === 0) return source.slice(start, i + 1) + ';';
    }
  }
  throw new Error(`unclosed window.${name}`);
}

function selectEl(pk: string, value: string) {
  return { getAttribute: (k: string) => (k === 'data-pk' ? pk : null), type: 'select-one', value };
}

function assertNoDirectInlineRender(html: string) {
  expect(html).not.toMatch(/\bon(?:change|click|input)\s*=\s*"[^"]*\brender\s*\(/);
  expect(html).not.toContain(';render();');
}

type PrincipalUiSandbox = {
  S: { principals: Array<Record<string, unknown>> };
  window: Record<string, (...args: unknown[]) => void>;
  admiralPrincipalCard: (p: Record<string, unknown>, i: number, mode: string) => string;
};

function loadPrincipalUi(principal: Record<string, unknown>) {
  const ui = readFileSync(join(process.cwd(), 'docs/index.html'), 'utf8');
  const admiralSrc = ui.slice(ui.indexOf('// ═══════════ ⚓ OP ADMIRAL'));
  const renderState = { calls: 0 };
  const sandbox: Record<string, unknown> = {
    S: { target: 'https://api.example', principals: [principal] },
    window: {},
    URL,
    render: () => { renderState.calls += 1; },
  };
  vm.runInNewContext(
    [
      extractNamedFunction(admiralSrc, 'esc'),
      extractNamedFunction(admiralSrc, '_admOrigin'),
      extractNamedFunction(admiralSrc, 'secretPlaceholder'),
      extractNamedFunction(admiralSrc, '_admIn'),
      extractNamedFunction(admiralSrc, 'admiralOAuthFields'),
      extractNamedFunction(admiralSrc, 'admiralPrincipalCard'),
      extractWindowFunction(admiralSrc, 'admiralPatchPrincipal'),
      extractWindowFunction(admiralSrc, 'admiralSetPrincipalAuthType'),
      extractWindowFunction(admiralSrc, 'admiralSetOAuthGrant'),
      'admiralPatchPrincipal = window.admiralPatchPrincipal;',
      'admiralSetPrincipalAuthType = window.admiralSetPrincipalAuthType;',
      'admiralSetOAuthGrant = window.admiralSetOAuthGrant;',
    ].join('\n'),
    sandbox,
  );
  const ctx = sandbox as unknown as PrincipalUiSandbox;
  return {
    sandbox: ctx,
    renderState,
    card() {
      return ctx.admiralPrincipalCard(ctx.S.principals[0], 0, 'single');
    },
  };
}

describe('P2B.1 UI + source invariants', () => {
  it('Guided Hunt exposes password LEGACY, clientAuth none, and omit-vs-clear', () => {
    const ui = readFileSync(join(process.cwd(), 'docs/index.html'), 'utf8');
    expect(ui).toContain('LEGACY OAUTH FLOW');
    expect(ui).toContain("['none','none']");
    expect(ui).toContain('Clear stored client secret');
    expect(ui).toContain('clearClientSecret');
    expect(ui).toContain('Provide callback / code+state');
    expect(ui).toContain('Discover Metadata');
    expect(ui).not.toMatch(/danalock/i);
  });

  it('auth/grant selects use dedicated window handlers, not inline render()', () => {
    const ui = readFileSync(join(process.cwd(), 'docs/index.html'), 'utf8');
    const admiralSrc = ui.slice(ui.indexOf('// ═══════════ ⚓ OP ADMIRAL'));
    expect(admiralSrc).toContain('window.admiralSetPrincipalAuthType');
    expect(admiralSrc).toContain('window.admiralSetOAuthGrant');
    expect(admiralSrc).toContain("onchange=\"admiralSetPrincipalAuthType('+i+',this)\"");
    expect(admiralSrc).toContain("onchange=\"admiralSetOAuthGrant('+i+',this)\"");
    expect(admiralSrc).not.toContain("admiralPatchPrincipal('+i+',this);render();");
    expect(admiralSrc).not.toMatch(/\bonchange="[^"]*;render\(\)/);
    expect(admiralSrc).not.toMatch(/window\.render\s*=/);
  });

  it('custom_headers -> OAuth2 patches state, re-renders, and swaps principal fields', () => {
    const ui = loadPrincipalUi({
      label: 'p1',
      origin: 'https://api.example',
      authType: 'custom_headers',
      headersJson: '',
      flow: 'client_credentials',
      tokenUrl: '',
    });
    const before = ui.card();
    expect(before).toContain('data-pk="headersJson"');
    expect(before).toMatch(/placeholder="\{\}"/);
    expect(before).not.toContain('data-pk="flow"');
    expect(before).not.toContain('data-pk="tokenUrl"');
    expect(before).toContain('admiralSetPrincipalAuthType(0,this)');
    assertNoDirectInlineRender(before);

    ui.sandbox.window.admiralSetPrincipalAuthType(0, selectEl('authType', 'oauth2'));
    expect(ui.sandbox.S.principals[0].authType).toBe('oauth2');
    expect(ui.renderState.calls).toBe(1);

    const after = ui.card();
    expect(after).toContain('data-pk="flow"');
    expect(after).toContain('admiralSetOAuthGrant(0,this)');
    expect(after).toContain('data-pk="tokenUrl"');
    expect(after).not.toContain('data-pk="headersJson"');
    expect(after).not.toMatch(/data-pk="headersJson"[\s\S]*placeholder="\{\}"/);
    assertNoDirectInlineRender(after);
  });

  it('OAuth2 -> Basic shows HTTP Basic fields and drops OAuth fields', () => {
    const ui = loadPrincipalUi({
      label: 'p1',
      origin: 'https://api.example',
      authType: 'oauth2',
      flow: 'client_credentials',
      tokenUrl: 'https://api.example/token',
    });
    expect(ui.card()).toContain('data-pk="tokenUrl"');

    ui.sandbox.window.admiralSetPrincipalAuthType(0, selectEl('authType', 'http_basic'));
    expect(ui.sandbox.S.principals[0].authType).toBe('http_basic');
    expect(ui.renderState.calls).toBe(1);

    const after = ui.card();
    expect(after).toContain('placeholder="Username"');
    expect(after).toContain('data-pk="username"');
    expect(after).toContain('data-pk="password"');
    expect(after).toContain('type="password"');
    expect(after).not.toContain('data-pk="flow"');
    expect(after).not.toContain('data-pk="tokenUrl"');
    expect(after).not.toContain('admiralSetOAuthGrant');
    assertNoDirectInlineRender(after);
  });

  it('client_credentials -> password shows ROPC fields and LEGACY warning', () => {
    const ui = loadPrincipalUi({
      label: 'p1',
      origin: 'https://api.example',
      authType: 'oauth2',
      flow: 'client_credentials',
      tokenUrl: 'https://api.example/token',
      username: '',
      password: '',
    });
    const before = ui.card();
    expect(before).not.toContain('color:#f6c');
    expect(before).not.toContain('data-pk="username"');
    expect(before).not.toContain('data-pk="password"');

    ui.sandbox.window.admiralSetOAuthGrant(0, selectEl('flow', 'password'));
    expect(ui.sandbox.S.principals[0].flow).toBe('password');
    expect(ui.renderState.calls).toBe(1);

    const after = ui.card();
    expect(after).toContain('data-pk="username"');
    expect(after).toContain('placeholder="username"');
    expect(after).toContain('data-pk="password"');
    expect(after).toContain('type="password"');
    expect(after).toContain('color:#f6c');
    expect(after).toContain('LEGACY OAUTH FLOW — supported for interoperability; not recommended for new deployments.');
    assertNoDirectInlineRender(after);
  });

  it('password -> client_credentials drops username/password grant fields', () => {
    const ui = loadPrincipalUi({
      label: 'p1',
      origin: 'https://api.example',
      authType: 'oauth2',
      flow: 'password',
      tokenUrl: 'https://api.example/token',
      username: 'alice',
      password: '',
    });
    expect(ui.card()).toContain('data-pk="username"');

    ui.sandbox.window.admiralSetOAuthGrant(0, selectEl('flow', 'client_credentials'));
    expect(ui.sandbox.S.principals[0].flow).toBe('client_credentials');
    expect(ui.renderState.calls).toBe(1);

    const after = ui.card();
    expect(after).not.toContain('data-pk="username"');
    expect(after).not.toContain('data-pk="password"');
    expect(after).not.toContain('color:#f6c');
    expect(after).toContain('data-pk="tokenUrl"');
    expect(after).toContain('data-pk="clientSecret"');
    assertNoDirectInlineRender(after);
  });

  it('source has no Danalock-specific OAuth strings', () => {
    const oauth = readFileSync(join(process.cwd(), 'src/principals/oauth.ts'), 'utf8');
    expect(oauth).not.toMatch(/danalock/i);
  });

  it('no central grant switch in the engine', () => {
    const engine = readFileSync(join(process.cwd(), 'src/principals/oauth/engine.ts'), 'utf8');
    expect(engine).not.toContain("=== 'client_credentials'");
    expect(engine).not.toContain("=== 'password'");
  });
});
