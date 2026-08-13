import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { createServer } from 'node:http';
import { request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Arsenal, BUILTIN_TOOLS, createToolContext, clearRuntimeTargetHeaders, setRuntimeTargetHeaders } from '../arsenal/index.js';
import {
  putPrincipals,
  listPrincipals,
  deletePrincipal,
  teardownAllPrincipals,
  teardownMissionPrincipals,
  selectPrincipal,
  compilePrincipalHeaders,
  acquireOAuth,
  refreshOAuth,
  exchangeOAuthCode,
  parseAuthMode,
  getStoredPrincipal,
  principalsListBody,
  oauthActionBody,
  oauthImportBody,
  importOAuthFromOpenApi,
  EXPIRY_SKEW_MS,
  setPrincipalOauthMaterial,
  upsertLegacyHeadersPrincipal,
  isExpired,
  oauthHeadersAttachable,
} from '../principals/index.js';
import {
  redactString,
  replaceRuntimeSecretSource,
  clearRuntimeSecretSource,
  clearRuntimeSecrets,
  registerRuntimeSecrets,
} from '../redact.js';
import { parseOpenApi } from '../surface/openapi.js';

const ORIGIN = 'https://api.example';
const TOKEN_A = 'principalA-secret-token-aaaaaaa';
const TOKEN_B = 'principalB-secret-token-bbbbbbb';
const TOKEN_C = 'principalC-secret-token-ccccccc';

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

afterEach(() => {
  teardownAllPrincipals();
  clearRuntimeTargetHeaders();
  clearRuntimeSecrets();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('principal runtime store — selection', () => {
  it('0 principals + inherit on execute attaches nothing even if the legacy singleton is armed', async () => {
    expect(listPrincipals('m1')).toEqual([]);
    setRuntimeTargetHeaders(ORIGIN, JSON.stringify({ Authorization: `Bearer ${TOKEN_A}`, Cookie: 'sid=stale-legacy-cookie-value', 'X-API-Key': 'stale-legacy-apikey-value' }));
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);
    const result = await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    expect(result.success).toBe(true);
    const sent = new Headers(mockFetch.mock.calls[0][1]?.headers);
    expect(sent.get('authorization')).toBeNull();
    expect(sent.get('cookie')).toBeNull();
    expect(sent.get('x-api-key')).toBeNull();
    expect(JSON.stringify(result)).not.toContain(TOKEN_A);
  });

  it('1 principal: omitted principalId selects that principal', () => {
    const put = putPrincipals('m1', [{
      label: 'Operator',
      origin: ORIGIN,
      auth: { type: 'static_bearer', token: TOKEN_A },
    }]);
    expect(put.ok).toBe(true);
    const selected = selectPrincipal('m1', undefined);
    expect(selected.ok).toBe(true);
    if (selected.ok) {
      expect(selected.principal.label).toBe('Operator');
      expect(compilePrincipalHeaders(selected.principal)?.get('authorization')).toBe(`Bearer ${TOKEN_A}`);
    }
  });

  it('3 principals without default: omitted principalId is principal_id_required', () => {
    putPrincipals('m1', [
      { id: 'a', label: 'A', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_A } },
      { id: 'b', label: 'B', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_B } },
      { id: 'c', label: 'C', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_C } },
    ]);
    const selected = selectPrincipal('m1', undefined);
    expect(selected.ok).toBe(false);
    if (!selected.ok) {
      expect(selected.code).toBe('principal_id_required');
      expect(selected.principalIds).toEqual(['a', 'b', 'c']);
    }
  });

  it('3 principals with default: omitted principalId uses default; explicit id wins', () => {
    putPrincipals('m1', [
      { id: 'a', label: 'A', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_A } },
      { id: 'b', label: 'B', origin: ORIGIN, default: true, auth: { type: 'static_bearer', token: TOKEN_B } },
      { id: 'c', label: 'C', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_C } },
    ]);
    const def = selectPrincipal('m1', undefined);
    expect(def.ok && def.principal.id).toBe('b');
    const explicit = selectPrincipal('m1', 'c');
    expect(explicit.ok && explicit.principal.id).toBe('c');
  });

  it('unknown principalId fails closed', () => {
    putPrincipals('m1', [{ id: 'a', label: 'A', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_A } }]);
    const selected = selectPrincipal('m1', 'nope');
    expect(selected.ok).toBe(false);
    if (!selected.ok) expect(selected.code).toBe('unknown_principal');
  });

  it('query api_key is rejected', () => {
    const put = putPrincipals('m1', [{
      label: 'Key',
      origin: ORIGIN,
      auth: { type: 'api_key', headerName: 'X-API-Key', location: 'query', value: 'query-secret-value' },
    }]);
    expect(put.ok).toBe(false);
    if (!put.ok) expect(put.error).toBe('query_api_key_unsupported');
  });

  it('two missions cannot attach each other\'s principals', async () => {
    putPrincipals('m1', [{ id: 'a', label: 'A', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_A } }]);
    putPrincipals('m2', [{ id: 'b', label: 'B', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_B } }]);
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    const result = await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1`, principalId: 'b' }, 'm1'));
    expect(result.success).toBe(false);
    expect(JSON.parse(result.error!).code).toBe('unknown_principal');
  });
});

describe('principal apply — exact origin, authMode, direct methods', () => {
  it('exact-origin: wrong origin attaches nothing', async () => {
    putPrincipals('m1', [{ label: 'A', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_A } }]);
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);
    await arsenal.execute('http_request', createToolContext(undefined, { url: 'https://other.example/v1' }, 'm1'));
    expect(new Headers(mockFetch.mock.calls[0][1]?.headers).has('authorization')).toBe(false);
  });

  it('authMode none attaches nothing even with a principal', async () => {
    putPrincipals('m1', [{ label: 'A', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_A } }]);
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);
    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1`, authMode: 'none' }, 'm1'));
    expect(new Headers(mockFetch.mock.calls[0][1]?.headers).has('authorization')).toBe(false);
  });

  it('direct methods: bearer, api_key header, basic, cookie, custom headers', async () => {
    putPrincipals('m1', [
      { id: 'bearer', label: 'Bearer', origin: ORIGIN, default: true, auth: { type: 'static_bearer', token: TOKEN_A } },
      { id: 'key', label: 'Key', origin: ORIGIN, auth: { type: 'api_key', headerName: 'X-API-Key', value: 'opaque-api-key-value' } },
      { id: 'basic', label: 'Basic', origin: ORIGIN, auth: { type: 'http_basic', username: 'alice', password: 'super-secret-pass' } },
      { id: 'cookie', label: 'Cookie', origin: ORIGIN, auth: { type: 'cookie_session', cookies: { sid: 'sessionblob_9f8e7d6c5b4a3210' } } },
      { id: 'hdr', label: 'Hdr', origin: ORIGIN, auth: { type: 'custom_headers', headers: { 'X-Tenant': 'acme-tenant-value' } } },
    ]);
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);

    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1`, principalId: 'key' }, 'm1'));
    expect(new Headers(mockFetch.mock.calls.at(-1)![1].headers).get('x-api-key')).toBe('opaque-api-key-value');

    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1`, principalId: 'basic' }, 'm1'));
    expect(new Headers(mockFetch.mock.calls.at(-1)![1].headers).get('authorization')).toMatch(/^Basic /);

    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1`, principalId: 'cookie' }, 'm1'));
    expect(new Headers(mockFetch.mock.calls.at(-1)![1].headers).get('cookie')).toContain('sid=');

    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1`, principalId: 'hdr' }, 'm1'));
    expect(new Headers(mockFetch.mock.calls.at(-1)![1].headers).get('x-tenant')).toBe('acme-tenant-value');
  });

  it('invalid authMode returns safe JSON (configured/authenticated/suppress) with allowedValues', async () => {
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    for (const bad of ['configured', 'authenticated', 'suppress', 'suppressed']) {
      const result = await arsenal.execute('http_request', createToolContext(undefined, {
        url: `${ORIGIN}/v1`,
        authMode: bad,
      }, 'm1'));
      expect(result.success).toBe(false);
      const payload = JSON.parse(result.error!);
      expect(payload.code).toBe('invalid_auth_mode');
      expect(payload.allowedValues).toEqual(['inherit', 'none']);
      expect(payload.message).toContain('inherit, none');
      expect(JSON.stringify(payload)).not.toContain(TOKEN_A);
    }
  });

  it('2+ principals without default returns principal_id_required as a tool result', async () => {
    putPrincipals('m1', [
      { id: 'a', label: 'A', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_A } },
      { id: 'b', label: 'B', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_B } },
    ]);
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    const result = await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    expect(result.success).toBe(false);
    const payload = JSON.parse(result.error!);
    expect(payload.code).toBe('principal_id_required');
    expect(payload.principalIds).toEqual(['a', 'b']);
  });
});

describe('namespaced secrets + teardown', () => {
  it('clearing one source does not drop another', () => {
    replaceRuntimeSecretSource('mission:m1:principals', [TOKEN_A]);
    replaceRuntimeSecretSource('mission:m2:principals', [TOKEN_B]);
    expect(redactString(TOKEN_A)).toBe('[redacted]');
    expect(redactString(TOKEN_B)).toBe('[redacted]');
    clearRuntimeSecretSource('mission:m1:principals');
    expect(redactString(TOKEN_A)).toContain(TOKEN_A);
    expect(redactString(TOKEN_B)).toBe('[redacted]');
  });

  it('legacy registerRuntimeSecrets does not clobber principal sources', () => {
    putPrincipals('m1', [{ label: 'A', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_A } }]);
    registerRuntimeSecrets([TOKEN_B]);
    expect(redactString(TOKEN_A)).toBe('[redacted]');
    expect(redactString(TOKEN_B)).toBe('[redacted]');
  });

  it('teardown clears the mission source; GET metadata never includes secrets', () => {
    putPrincipals('m1', [{ label: 'A', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_A } }]);
    expect(redactString(`saw ${TOKEN_A}`)).not.toContain(TOKEN_A);
    const listed = JSON.stringify(listPrincipals('m1'));
    expect(listed).not.toContain(TOKEN_A);
    expect(listed).toContain('"authMethod":"static_bearer"');
    teardownMissionPrincipals('m1');
    expect(listPrincipals('m1')).toEqual([]);
    expect(redactString(TOKEN_A)).toContain(TOKEN_A);
  });

  it('process restart semantics: teardownAll leaves an empty store', () => {
    putPrincipals('m1', [{ label: 'A', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_A } }]);
    teardownAllPrincipals();
    expect(listPrincipals('m1')).toEqual([]);
  });
});

describe('oauth runtime', () => {
  it('client_credentials acquire is fail-closed on missing token_type', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    const mockFetch = vi.fn().mockResolvedValue(response(200, JSON.stringify({ access_token: 'tok-without-type-xxxxxxxx' })));
    vi.stubGlobal('fetch', mockFetch);
    const result = await acquireOAuth('m1', 'oauth', { allowedHosts: ['api.example'], allowLoopback: true, allowPrivate: true });
    expect(result.ok).toBe(false);
    expect(result.code).toBe('malformed_token_response');
    expect(listPrincipals('m1')[0].runtimeStatus).toBe('failed');
  });

  it('unsupported token_type fails closed (no silent Bearer default)', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(200, JSON.stringify({ access_token: 'mac-token-value-xxxxxx', token_type: 'mac' }))));
    const result = await acquireOAuth('m1', 'oauth', { allowedHosts: ['api.example'], allowLoopback: true, allowPrivate: true });
    expect(result.ok).toBe(false);
    expect(result.code).toBe('unsupported_token_type');
  });

  it('Bearer token_type attaches after acquire; token URL out of scope is oauth_scope_denied before any fetch', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: 'https://login.other/token', clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    const scope = { allowedHosts: ['api.example'], allowLoopback: false, allowPrivate: false };
    const arsenal = new Arsenal();
    arsenal.setScope(scope);
    const before = structuredClone(arsenal.getScope());
    const mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
    const result = await acquireOAuth('m1', 'oauth', arsenal.getScope());
    expect(result.ok).toBe(false);
    expect(result.code).toBe('oauth_scope_denied');
    expect(mockFetch).not.toHaveBeenCalled();
    expect(arsenal.getScope()).toEqual(before);
  });

  it('successful client_credentials is LIVE and redacts the access token', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    const access = 'access-token-live-zzzzzzzz';
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(200, JSON.stringify({
      access_token: access,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'read write',
    }))));
    const result = await acquireOAuth('m1', 'oauth', { allowedHosts: ['api.example'], allowLoopback: true, allowPrivate: true });
    expect(result.ok).toBe(true);
    expect(result.principal?.runtimeStatus).toBe('live');
    expect(JSON.stringify(result)).not.toContain(access);
    expect(redactString(access)).toBe('[redacted]');
  });

  it('authorization code state mismatch does not exchange', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        flow: 'authorization_code_pkce',
        authorizationUrl: `${ORIGIN}/authorize`,
        tokenUrl: `${ORIGIN}/token`,
        clientId: 'cid',
        pkce: true,
      },
    }]);
    const start = await acquireOAuth('m1', 'oauth', { allowedHosts: ['api.example'], allowLoopback: true, allowPrivate: true });
    expect(start.ok).toBe(true);
    expect(start.authorizationUrl).toContain('state=');
    expect(start.authorizationUrl).toContain('code_challenge');
    const planted = 'authz-code-mismatch-zzzzzz';
    const exchanged = await exchangeOAuthCode('m1', 'oauth', { code: planted, state: 'wrong-state-value' }, { allowedHosts: ['api.example'], allowLoopback: true, allowPrivate: true });
    expect(exchanged.ok).toBe(false);
    expect(exchanged.code).toBe('oauth_state_mismatch');
    expect(redactString(planted)).toBe('[redacted]');
    expect(getStoredPrincipal('m1', 'oauth')!.oauth?.state).toBeTruthy();
  });

  it('refresh rotates material and keeps old values in the redactor until teardown', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(response(200, JSON.stringify({ access_token: 'access-old-yyyyyyyy', token_type: 'Bearer', refresh_token: 'refresh-old-yyyyyyyy', expires_in: 1 })))
      .mockResolvedValueOnce(response(200, JSON.stringify({ access_token: 'access-new-xxxxxxxx', token_type: 'Bearer', refresh_token: 'refresh-new-xxxxxxxx', expires_in: 3600 }))));
    await acquireOAuth('m1', 'oauth', { allowedHosts: ['api.example'], allowLoopback: true, allowPrivate: true });
    const refreshed = await refreshOAuth('m1', 'oauth', { allowedHosts: ['api.example'], allowLoopback: true, allowPrivate: true });
    expect(refreshed.ok).toBe(true);
    expect(redactString('access-old-yyyyyyyy')).toBe('[redacted]');
    expect(redactString('access-new-xxxxxxxx')).toBe('[redacted]');
  });
});

describe('openapi oauth URL extraction is intelligence only', () => {
  it('extracts authorizationUrl/tokenUrl/refreshUrl from flows', () => {
    const art = parseOpenApi(JSON.stringify({
      openapi: '3.0.3',
      info: { title: 't', version: '1' },
      paths: {},
      components: {
        securitySchemes: {
          OAuth2: {
            type: 'oauth2',
            flows: {
              authorizationCode: {
                authorizationUrl: 'https://login.example/authorize',
                tokenUrl: 'https://login.example/token',
                refreshUrl: 'https://login.example/refresh',
                scopes: { read: 'r' },
              },
            },
          },
        },
      },
    }));
    const oauth = art.securitySchemes.find((s) => s.name === 'OAuth2')!;
    expect(oauth.authorizationUrl).toBe('https://login.example/authorize');
    expect(oauth.tokenUrl).toBe('https://login.example/token');
    expect(oauth.refreshUrl).toBe('https://login.example/refresh');
  });
});

describe('parseAuthMode', () => {
  it('defaults empty to inherit and rejects unknown values without throwing', () => {
    const inherit = parseAuthMode(undefined);
    expect(inherit.ok).toBe(true);
    if (inherit.ok) expect(inherit.mode).toBe('inherit');
    const bad = parseAuthMode('configured');
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.allowedValues).toEqual(['inherit', 'none']);
  });
});

describe('subprocess scanners stay argv-safe', () => {
  it('nuclei/ffuf never interpolate header values onto argv', () => {
    const source = readFileSync(join(__dirname, '..', 'arsenal', 'index.ts'), 'utf8');
    const nuclei = source.slice(source.indexOf("name: 'nuclei_scan'"), source.indexOf("name: 'ffuf_fuzz'"));
    const ffuf = source.slice(source.indexOf("name: 'ffuf_fuzz'"), source.indexOf("name: 'curl_request'"));
    expect(nuclei).toContain('unappliedAuthNote');
    expect(ffuf).toContain('unappliedAuthNote');
    expect(nuclei).not.toContain('TEMPEST_TARGET_HEADERS');
    expect(nuclei).not.toMatch(/args\.push\([^)]*authorization/i);
    expect(ffuf).not.toMatch(/args\.push\([^)]*authorization/i);
  });
});

describe('delete principal + max cap', () => {
  it('deletePrincipal drops one identity', () => {
    putPrincipals('m1', [
      { id: 'a', label: 'A', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_A } },
      { id: 'b', label: 'B', origin: ORIGIN, default: true, auth: { type: 'static_bearer', token: TOKEN_B } },
    ]);
    expect(deletePrincipal('m1', 'a')).toBe(true);
    expect(listPrincipals('m1').map((p) => p.id)).toEqual(['b']);
  });
});

describe('control-plane principals API is metadata-only', () => {
  it('exposes GET/PUT/DELETE and OAuth acquire/refresh/code/import without echoing secrets', () => {
    const source = readFileSync(join(__dirname, '..', 'server.ts'), 'utf8');
    expect(source).toContain("app.get('/api/mission/principals'");
    expect(source).toContain("app.put('/api/mission/principals'");
    expect(source).toContain("app.delete('/api/mission/principals/:id'");
    expect(source).toContain("app.post('/api/mission/principals/:id/auth/acquire'");
    expect(source).toContain("app.post('/api/mission/principals/:id/auth/refresh'");
    expect(source).toContain("app.post('/api/mission/principals/:id/auth/code'");
    expect(source).toContain("app.get('/api/mission/oauth/import'");
    expect(source).toContain("app.post('/api/mission/oauth/discover'");
    const getBlock = source.slice(source.indexOf("app.get('/api/mission/principals'"), source.indexOf("app.put('/api/mission/principals'"));
    expect(getBlock).toContain('principalsListBody');
    expect(getBlock).not.toContain('redactSecrets');
    expect(getBlock).not.toContain('accessToken');
    expect(getBlock).not.toContain('clientSecret');
    expect(source).toContain('teardownAuthRuntime');
    for (const marker of [
      "app.post('/api/mission/principals/:id/auth/acquire'",
      "app.post('/api/mission/principals/:id/auth/refresh'",
      "app.post('/api/mission/principals/:id/auth/code'",
      "app.get('/api/mission/oauth/import'",
    ]) {
      const start = source.indexOf(marker);
      const block = source.slice(start, start + 700);
      expect(block).toMatch(/oauthActionBody|oauthImportBody/);
      expect(block).not.toContain('redactSecrets');
    }
  });

  it('OAuth token HTTP uses the ScopeGuard primitive, not a raw globalThis.fetch after a separate check', () => {
    const oauthDir = join(__dirname, '..', 'principals', 'oauth');
    const engine = readFileSync(join(oauthDir, 'engine.ts'), 'utf8');
    const http = readFileSync(join(oauthDir, 'http.ts'), 'utf8');
    const arsenal = readFileSync(join(__dirname, '..', 'arsenal', 'index.ts'), 'utf8');
    expect(engine).not.toContain('globalThis.fetch');
    expect(http).toContain('scopedHttp(');
    expect(arsenal).toContain('export async function scopedInternalFetch');
    expect(arsenal).toContain('setOAuthScopedHttp((url, init, scope) => scopedInternalFetch(scope, url, init))');
  });
});

const LAB_SCOPE = { allowedHosts: ['api.example'], allowLoopback: true, allowPrivate: true };

function httpJson(url: string, opts?: { method?: string; body?: string }): Promise<{ status: number; json: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = httpRequest({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: opts?.method || 'GET',
      headers: { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(opts?.body || '')) },
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        resolve({ status: res.statusCode || 0, json: data ? JSON.parse(data) as Record<string, unknown> : {} });
      });
    });
    req.on('error', reject);
    if (opts?.body) req.write(opts.body);
    req.end();
  });
}

function readReq(req: { on: (event: string, cb: (chunk?: Buffer | string) => void) => void }): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk) => { chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk || '')); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

async function withDtoServer(missionId: string, fn: (base: string) => Promise<void>): Promise<void> {
  const server = createServer((req, res) => {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    res.setHeader('content-type', 'application/json');
    const principalId = url.pathname.split('/')[4];
    void (async () => {
      const raw = req.method === 'POST' ? await readReq(req) : '';
      let parsedBody: Record<string, unknown> = {};
      if (raw) {
        try { parsedBody = JSON.parse(raw) as Record<string, unknown>; } catch { parsedBody = {}; }
      }
      if (req.method === 'GET' && url.pathname === '/api/mission/principals') {
        res.end(JSON.stringify(principalsListBody(missionId)));
        return;
      }
      if (req.method === 'GET' && url.pathname === '/api/mission/oauth/import') {
        res.end(JSON.stringify(oauthImportBody(importOAuthFromOpenApi([{
          name: 'OAuth2',
          type: 'oauth2',
          flows: ['authorizationCode'],
          authorizationUrl: `${ORIGIN}/authorize`,
          tokenUrl: `${ORIGIN}/token`,
          refreshUrl: `${ORIGIN}/refresh`,
          scopes: ['read'],
        }]))));
        return;
      }
      if (req.method === 'POST' && url.pathname.endsWith('/auth/acquire')) {
        const result = await acquireOAuth(missionId, principalId, LAB_SCOPE);
        res.statusCode = result.ok ? 200 : 400;
        res.end(JSON.stringify(oauthActionBody(result)));
        return;
      }
      if (req.method === 'POST' && url.pathname.endsWith('/auth/refresh')) {
        const result = await refreshOAuth(missionId, principalId, LAB_SCOPE);
        res.statusCode = result.ok ? 200 : 400;
        res.end(JSON.stringify(oauthActionBody(result)));
        return;
      }
      if (req.method === 'POST' && url.pathname.endsWith('/auth/code')) {
        const result = await exchangeOAuthCode(
          missionId,
          principalId,
          { code: parsedBody.code as string | undefined, state: parsedBody.state as string | undefined, callbackUrl: parsedBody.callbackUrl as string | undefined },
          LAB_SCOPE,
        );
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
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
  }
}

describe('oauth state-gated attachment', () => {
  it('UNKNOWN oauth inherit returns auth_state and does not send Authorization', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'authorization_code', authorizationUrl: `${ORIGIN}/authorize`, tokenUrl: `${ORIGIN}/token`, clientId: 'cid' },
    }]);
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);
    const result = await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    expect(result.success).toBe(false);
    const payload = JSON.parse(result.error!);
    expect(payload.category).toBe('auth_state');
    expect(payload.code).toBe('oauth_not_live');
    expect(payload.message).toContain('not authorization denial');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('FAILED oauth does not attach a leftover access token', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'authorization_code', authorizationUrl: `${ORIGIN}/authorize`, tokenUrl: `${ORIGIN}/token`, clientId: 'cid' },
    }]);
    setPrincipalOauthMaterial('m1', 'oauth', {
      accessToken: 'leftover-access-token-zzzzzz',
      tokenType: 'Bearer',
      runtimeStatus: 'failed',
      lastError: 'boom',
    });
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);
    const result = await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    expect(result.success).toBe(false);
    expect(JSON.parse(result.error!).code).toBe('oauth_not_live');
    expect(mockFetch).not.toHaveBeenCalled();
    const compiled = compilePrincipalHeaders(getStoredPrincipal('m1', 'oauth')!);
    expect(compiled).toBeNull();
  });

  it('STALE oauth does not attach a leftover access token', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'authorization_code', authorizationUrl: `${ORIGIN}/authorize`, tokenUrl: `${ORIGIN}/token`, clientId: 'cid' },
    }]);
    setPrincipalOauthMaterial('m1', 'oauth', {
      accessToken: 'stale-access-token-zzzzzz',
      tokenType: 'Bearer',
      runtimeStatus: 'stale',
      lastError: 'access token expired',
    });
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);
    const result = await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    expect(result.success).toBe(false);
    expect(JSON.parse(result.error!).code).toBe('oauth_not_live');
    expect(JSON.parse(result.error!).category).toBe('auth_state');
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe('oauth expiry skew (once) and refresh correctness', () => {
  it('applies expiry skew exactly once: before window, inside window, after expiry', () => {
    vi.useFakeTimers();
    const t0 = Date.parse('2026-06-01T00:00:00.000Z');
    vi.setSystemTime(t0);
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    const expiresAt = t0 + 3600_000;
    setPrincipalOauthMaterial('m1', 'oauth', {
      accessToken: 'access-live-zzzzzzzz',
      refreshToken: 'refresh-old-yyyyyyyy',
      tokenType: 'Bearer',
      expiresAt,
      runtimeStatus: 'live',
    });
    const stored = () => getStoredPrincipal('m1', 'oauth')!;

    vi.setSystemTime(t0 + 30 * 60_000);
    expect(isExpired(stored())).toBe(false);
    expect(oauthHeadersAttachable(stored())).toBe(true);

    vi.setSystemTime(expiresAt - EXPIRY_SKEW_MS + 1);
    expect(isExpired(stored())).toBe(true);
    expect(oauthHeadersAttachable(stored())).toBe(true);

    vi.setSystemTime(expiresAt + 1);
    expect(isExpired(stored())).toBe(true);
    expect(oauthHeadersAttachable(stored())).toBe(false);
  });

  it('expiry inside the refresh window triggers one refresh before the original request', async () => {
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
      expiresAt: Date.now() + EXPIRY_SKEW_MS - 5_000,
      runtimeStatus: 'live',
    });
    const mockFetch = vi.fn(async (url: string) => {
      if (String(url).includes('/token')) {
        return response(200, JSON.stringify({
          access_token: 'access-new-xxxxxxxx',
          token_type: 'Bearer',
          refresh_token: 'refresh-new-xxxxxxxx',
          expires_in: 3600,
        }));
      }
      return response();
    });
    vi.stubGlobal('fetch', mockFetch);
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    const tokenCalls = mockFetch.mock.calls.filter((c) => String(c[0]).includes('/token'));
    const apiCalls = mockFetch.mock.calls.filter((c) => !String(c[0]).includes('/token'));
    expect(tokenCalls).toHaveLength(1);
    expect(apiCalls).toHaveLength(1);
    const apiCall = apiCalls[0] as unknown as [string, RequestInit | undefined];
    expect(new Headers(apiCall[1]?.headers).get('authorization')).toBe('Bearer access-new-xxxxxxxx');
  });

  it('rotated refresh_token atomically replaces the store value; old token cannot be used', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: { type: 'oauth2', flow: 'client_credentials', tokenUrl: `${ORIGIN}/token`, clientId: 'cid', clientSecret: 'oauth-client-secret-value' },
    }]);
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(response(200, JSON.stringify({ access_token: 'access-old-yyyyyyyy', token_type: 'Bearer', refresh_token: 'refresh-old-yyyyyyyy', expires_in: 3600 })))
      .mockResolvedValueOnce(response(200, JSON.stringify({ access_token: 'access-new-xxxxxxxx', token_type: 'Bearer', refresh_token: 'refresh-new-xxxxxxxx', expires_in: 3600 }))));
    await acquireOAuth('m1', 'oauth', LAB_SCOPE);
    await refreshOAuth('m1', 'oauth', LAB_SCOPE);
    const stored = getStoredPrincipal('m1', 'oauth')!;
    expect(stored.oauth?.refreshToken).toBe('refresh-new-xxxxxxxx');
    expect(stored.oauth?.refreshToken).not.toBe('refresh-old-yyyyyyyy');
    expect(stored.oauth?.accessToken).toBe('access-new-xxxxxxxx');
    expect(stored.oauth?.accessToken).not.toBe('access-old-yyyyyyyy');
    expect(redactString('refresh-old-yyyyyyyy')).toBe('[redacted]');
    expect(redactString('refresh-new-xxxxxxxx')).toBe('[redacted]');
  });

  it('concurrent expired requests share a single refresh', async () => {
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
      expiresAt: Date.now() - 1000,
      runtimeStatus: 'live',
    });
    let tokenPosts = 0;
    let inflight = 0;
    let maxInflight = 0;
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (String(url).includes('/token')) {
        tokenPosts += 1;
        inflight += 1;
        maxInflight = Math.max(maxInflight, inflight);
        await new Promise((r) => setTimeout(r, 30));
        inflight -= 1;
        return response(200, JSON.stringify({ access_token: 'access-new-xxxxxxxx', token_type: 'Bearer', refresh_token: 'refresh-new-xxxxxxxx', expires_in: 3600 }));
      }
      return response();
    }));
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    await Promise.all([
      arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1')),
      arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1')),
    ]);
    expect(tokenPosts).toBe(1);
    expect(maxInflight).toBe(1);
  });

  it('original request retries at most once after successful refresh; failed refresh does not loop', async () => {
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
    let apiCalls = 0;
    let tokenPosts = 0;
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (String(url).includes('/token')) {
        tokenPosts += 1;
        return response(200, JSON.stringify({ access_token: 'access-new-xxxxxxxx', token_type: 'Bearer', refresh_token: 'refresh-new-xxxxxxxx', expires_in: 3600 }));
      }
      apiCalls += 1;
      return response(401);
    }));
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    expect(apiCalls).toBe(2);
    expect(tokenPosts).toBe(1);

    apiCalls = 0;
    tokenPosts = 0;
    setPrincipalOauthMaterial('m1', 'oauth', {
      accessToken: 'access-live-zzzzzzzz',
      refreshToken: 'refresh-old-yyyyyyyy',
      tokenType: 'Bearer',
      expiresAt: Date.now() + 3600_000,
      runtimeStatus: 'live',
      refreshAttempts: 0,
      acquireAttempts: 0,
      lastAttemptAt: 0,
    });
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (String(url).includes('/token')) {
        tokenPosts += 1;
        return response(401, JSON.stringify({ error: 'invalid_grant' }));
      }
      apiCalls += 1;
      return response(401);
    }));
    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    expect(apiCalls).toBe(1);
    expect(tokenPosts).toBe(2);
    expect(getStoredPrincipal('m1', 'oauth')!.runtimeStatus).toBe('failed');
  });
});

describe('authorization code registration and one-use', () => {
  it('registers submitted code before processing; clears one-use material after successful exchange', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        flow: 'authorization_code_pkce',
        authorizationUrl: `${ORIGIN}/authorize`,
        tokenUrl: `${ORIGIN}/token`,
        clientId: 'cid',
        pkce: true,
      },
    }]);
    const start = await acquireOAuth('m1', 'oauth', LAB_SCOPE);
    const authUrl = new URL(start.authorizationUrl!);
    const state = authUrl.searchParams.get('state')!;
    const code = 'authz-code-planted-zzzzzzzz';
    expect(redactString(state)).toBe('[redacted]');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(200, JSON.stringify({
      access_token: 'access-code-live-zzzzzzzz',
      token_type: 'Bearer',
      refresh_token: 'refresh-code-zzzzzzzz',
      expires_in: 3600,
    }))));
    const exchanged = await exchangeOAuthCode('m1', 'oauth', { code, state }, LAB_SCOPE);
    expect(exchanged.ok).toBe(true);
    expect(redactString(code)).toBe('[redacted]');
    const stored = getStoredPrincipal('m1', 'oauth')!;
    expect(stored.oauth?.authorizationCode).toBeUndefined();
    expect(stored.oauth?.state).toBeUndefined();
    expect(stored.oauth?.codeVerifier).toBeUndefined();
    const again = await exchangeOAuthCode('m1', 'oauth', { code, state }, LAB_SCOPE);
    expect(again.ok).toBe(false);
    expect(again.code).toBe('oauth_state_mismatch');
  });
});

describe('principal HTTP DTOs', () => {
  it('GET /api/mission/principals returns usable OAuth metadata and never secret values', async () => {
    const secret = 'http-dto-secret-token-zzzzzzzz';
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        flow: 'client_credentials',
        authorizationUrl: `${ORIGIN}/authorize`,
        tokenUrl: `${ORIGIN}/token`,
        clientId: 'cid',
        clientSecret: 'oauth-client-secret-value',
      },
    }]);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(200, JSON.stringify({
      access_token: secret,
      token_type: 'Bearer',
      refresh_token: 'refresh-http-zzzzzzzz',
      expires_in: 3600,
      scope: 'read',
    }))));
    await acquireOAuth('m1', 'oauth', LAB_SCOPE);
    await withDtoServer('m1', async (base) => {
      const listed = await httpJson(`${base}/api/mission/principals`);
      expect(listed.status).toBe(200);
      const body = JSON.stringify(listed.json);
      expect(body).not.toContain(secret);
      expect(body).not.toContain('oauth-client-secret-value');
      expect(body).not.toContain('refresh-http-zzzzzzzz');
      const principal = (listed.json.principals as Array<Record<string, unknown>>)[0];
      const oauth = principal.oauth as Record<string, unknown>;
      expect(oauth.authorizationUrl).toBe(`${ORIGIN}/authorize`);
      expect(oauth.tokenUrl).toBe(`${ORIGIN}/token`);
      expect(oauth.tokenType).toBe('Bearer');
      expect(oauth.hasRefreshToken).toBe(true);
      expect(oauth.scopes).toEqual(['read']);
      expect(principal.runtimeStatus).toBe('live');
      expect(typeof oauth.expiresAt).toBe('string');
      expect(body).not.toMatch(/accessToken|clientSecret|refreshToken|authorizationCode|codeVerifier/);

      const refreshed = await httpJson(`${base}/api/mission/principals/oauth/auth/refresh`, { method: 'POST', body: '{}' });
      expect(JSON.stringify(refreshed.json)).not.toContain(secret);
      expect(JSON.stringify(refreshed.json)).not.toContain('refresh-http-zzzzzzzz');
      expect((refreshed.json.principal as Record<string, unknown> | undefined)?.runtimeStatus).toBe('live');

      const imported = await httpJson(`${base}/api/mission/oauth/import`);
      const suggestions = imported.json.suggestions as Array<Record<string, unknown>>;
      expect(suggestions[0].authorizationUrl).toBe(`${ORIGIN}/authorize`);
      expect(suggestions[0].tokenUrl).toBe(`${ORIGIN}/token`);
      expect(JSON.stringify(imported.json)).not.toContain(secret);
    });
  });

  it('POST /auth/acquire HTTP DTO keeps authorizationUrl usable and omits secrets', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        flow: 'authorization_code_pkce',
        authorizationUrl: `${ORIGIN}/authorize`,
        tokenUrl: `${ORIGIN}/token`,
        clientId: 'cid',
        pkce: true,
      },
    }]);
    await withDtoServer('m1', async (base) => {
      const acquired = await httpJson(`${base}/api/mission/principals/oauth/auth/acquire`, { method: 'POST', body: '{}' });
      expect(acquired.status).toBe(200);
      expect(typeof acquired.json.authorizationUrl).toBe('string');
      expect(String(acquired.json.authorizationUrl)).toContain(`${ORIGIN}/authorize`);
      expect(JSON.stringify(acquired.json)).not.toMatch(/codeVerifier|clientSecret|accessToken/);
    });
  });

  it('POST /auth/code HTTP DTO never includes the submitted code or tokens', async () => {
    putPrincipals('m1', [{
      id: 'oauth',
      label: 'OAuth',
      origin: ORIGIN,
      auth: {
        type: 'oauth2',
        flow: 'authorization_code_pkce',
        authorizationUrl: `${ORIGIN}/authorize`,
        tokenUrl: `${ORIGIN}/token`,
        clientId: 'cid',
        pkce: true,
      },
    }]);
    const start = await acquireOAuth('m1', 'oauth', LAB_SCOPE);
    const state = new URL(start.authorizationUrl!).searchParams.get('state')!;
    const code = 'http-dto-authz-code-zzzzzzzz';
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(200, JSON.stringify({
      access_token: 'http-dto-code-access-zzzzzzzz',
      token_type: 'Bearer',
      refresh_token: 'http-dto-code-refresh-zzzzzz',
      expires_in: 3600,
    }))));
    await withDtoServer('m1', async (base) => {
      const exchanged = await httpJson(`${base}/api/mission/principals/oauth/auth/code`, {
        method: 'POST',
        body: JSON.stringify({ code, state }),
      });
      expect(exchanged.status).toBe(200);
      const text = JSON.stringify(exchanged.json);
      expect(text).not.toContain(code);
      expect(text).not.toContain(state);
      expect(text).not.toContain('http-dto-code-access-zzzzzzzz');
      expect(text).not.toContain('http-dto-code-refresh-zzzzzz');
      expect((exchanged.json.principal as Record<string, unknown>).runtimeStatus).toBe('live');
    });
  });
});

describe('legacy compile is compatibility input only', () => {
  it('compiled legacy principal still attaches after the singleton is cleared', async () => {
    upsertLegacyHeadersPrincipal('m1', ORIGIN, { Authorization: `Bearer ${TOKEN_A}` });
    clearRuntimeTargetHeaders();
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);
    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    expect(new Headers(mockFetch.mock.calls[0][1]?.headers).get('authorization')).toBe(`Bearer ${TOKEN_A}`);
    expect(listPrincipals('m1').map((p) => p.id)).toEqual(['legacy-headers']);
  });
});

describe('delete/replace cannot revive the legacy header slot', () => {
  it('deleting the last principal then inherit on that mission sends no credentials', async () => {
    setRuntimeTargetHeaders(ORIGIN, JSON.stringify({ Authorization: `Bearer ${TOKEN_A}` }));
    putPrincipals('m1', [{ id: 'a', label: 'A', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_A } }]);
    deletePrincipal('m1', 'a');
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);
    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    expect(new Headers(mockFetch.mock.calls[0][1]?.headers).get('authorization')).toBeNull();
  });

  it('replacing with an empty set then inherit on that mission sends no credentials', async () => {
    setRuntimeTargetHeaders(ORIGIN, JSON.stringify({ Authorization: `Bearer ${TOKEN_B}` }));
    putPrincipals('m1', [{ id: 'a', label: 'A', origin: ORIGIN, auth: { type: 'static_bearer', token: TOKEN_B } }]);
    putPrincipals('m1', []);
    const arsenal = new Arsenal();
    arsenal.register(BUILTIN_TOOLS.find((t) => t.name === 'http_request')!);
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);
    await arsenal.execute('http_request', createToolContext(undefined, { url: `${ORIGIN}/v1` }, 'm1'));
    expect(new Headers(mockFetch.mock.calls[0][1]?.headers).get('authorization')).toBeNull();
  });
});
