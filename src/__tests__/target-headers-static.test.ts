import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import vm from 'node:vm';
import { Arsenal, BUILTIN_TOOLS, createToolContext, setRuntimeTargetHeaders, clearRuntimeTargetHeaders } from '../arsenal/index.js';

const httpTool = BUILTIN_TOOLS.find(tool => tool.name === 'http_request');
const technologyTool = BUILTIN_TOOLS.find(tool => tool.name === 'technology_detect');
if (!httpTool || !technologyTool) throw new Error('Required HTTP tools are not registered');
const originalOrigin = process.env.TEMPEST_TARGET_ORIGIN;
const originalHeaders = process.env.TEMPEST_TARGET_HEADERS;

function response(status = 200, headers: Record<string, string> = {}): Response {
  const normalized = new Map(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]));
  return {
    status,
    statusText: status === 200 ? 'OK' : 'Found',
    headers: {
      entries: () => normalized.entries(),
      get: (name: string) => normalized.get(name.toLowerCase()) ?? null,
    },
    text: async () => '<html></html>',
  } as unknown as Response;
}

function configure(origin = 'https://target.example') {
  process.env.TEMPEST_TARGET_ORIGIN = origin;
  process.env.TEMPEST_TARGET_HEADERS = JSON.stringify({
    Authorization: 'Bearer configured-secret',
    'X-Tenant': 'acme',
  });
}

beforeEach(() => configure());

afterEach(() => {
  if (originalOrigin === undefined) delete process.env.TEMPEST_TARGET_ORIGIN;
  else process.env.TEMPEST_TARGET_ORIGIN = originalOrigin;
  if (originalHeaders === undefined) delete process.env.TEMPEST_TARGET_HEADERS;
  else process.env.TEMPEST_TARGET_HEADERS = originalHeaders;
  clearRuntimeTargetHeaders();
  vi.unstubAllGlobals();
});

describe('target header binding', () => {
  it('injects configured headers only into the exact origin', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example/api' }));
    await httpTool.handler(createToolContext(undefined, { url: 'https://other.example/api' }));
    await httpTool.handler(createToolContext(undefined, { url: 'http://target.example/api' }));

    expect(new Headers(mockFetch.mock.calls[0][1].headers).get('authorization')).toBe('Bearer configured-secret');
    expect(new Headers(mockFetch.mock.calls[1][1]?.headers).has('authorization')).toBe(false);
    expect(new Headers(mockFetch.mock.calls[2][1]?.headers).has('authorization')).toBe(false);
  });

  it('requires both the origin binding and a valid non-empty string header map', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);

    delete process.env.TEMPEST_TARGET_ORIGIN;
    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example' }));
    process.env.TEMPEST_TARGET_ORIGIN = 'https://target.example';
    process.env.TEMPEST_TARGET_HEADERS = JSON.stringify({ Authorization: 123 });
    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example' }));

    expect(new Headers(mockFetch.mock.calls[0][1].headers).has('authorization')).toBe(false);
    expect(new Headers(mockFetch.mock.calls[1][1].headers).has('authorization')).toBe(false);
  });

  it('rejects origins with paths and transport-level headers', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);

    configure('https://target.example/api');
    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example/api' }));
    configure();
    process.env.TEMPEST_TARGET_HEADERS = JSON.stringify({ Host: 'other.example' });
    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example/api' }));

    expect(new Headers(mockFetch.mock.calls[0][1].headers).has('authorization')).toBe(false);
    expect(new Headers(mockFetch.mock.calls[1][1].headers).has('host')).toBe(false);
  });

  it('lets explicit tool headers override configured headers case-insensitively', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, {
      url: 'https://target.example',
      headers: { authorization: 'Bearer request-secret' },
    }));

    const sent = new Headers(mockFetch.mock.calls[0][1].headers);
    expect(sent.get('authorization')).toBe('Bearer request-secret');
    expect([...sent.keys()].filter(name => name === 'authorization')).toHaveLength(1);
    expect(sent.get('x-tenant')).toBe('acme');
  });

  it('applies configured headers to built-in probes beyond http_request', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);

    await technologyTool.handler(createToolContext(undefined, { url: 'https://target.example' }));

    expect(new Headers(mockFetch.mock.calls[0][1].headers).get('authorization')).toBe('Bearer configured-secret');
  });
});

describe('target header redirect safety', () => {
  it('removes every configured header before a cross-origin redirect', async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(response(302, { location: 'https://external.example/landing' }))
      .mockResolvedValueOnce(response());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example/start' }));

    expect(new Headers(mockFetch.mock.calls[0][1].headers).get('x-tenant')).toBe('acme');
    expect(new Headers(mockFetch.mock.calls[1][1].headers).has('authorization')).toBe(false);
    expect(new Headers(mockFetch.mock.calls[1][1].headers).has('x-tenant')).toBe(false);
    expect(String(mockFetch.mock.calls[1][0])).toBe('https://external.example/landing');
  });

  it('keeps configured headers on same-origin redirects', async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(response(302, { location: '/next' }))
      .mockResolvedValueOnce(response());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example/start' }));

    expect(new Headers(mockFetch.mock.calls[1][1].headers).get('authorization')).toBe('Bearer configured-secret');
  });
});

describe('target header secret handling', () => {
  it('redacts configured values from persisted tool output and findings', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response(200, {
      'x-reflected-value': 'Bearer configured-secret',
    }));
    vi.stubGlobal('fetch', mockFetch);
    const arsenal = new Arsenal();
    arsenal.register(httpTool);

    const result = await arsenal.execute('http_request', createToolContext(undefined, {
      url: 'https://target.example',
    }));

    expect(result.output).toContain('[REDACTED]');
    expect(result.output).not.toContain('configured-secret');
    expect(arsenal.getExecutions()[0].result?.output).not.toContain('configured-secret');
  });

  it('keeps configured curl headers out of argv and disables redirect-following flags', () => {
    const source = readFileSync(join(process.cwd(), 'src/arsenal/index.ts'), 'utf8');
    const curl = source.slice(source.indexOf("name: 'curl_request'"));
    expect(curl).toContain("writeFile(configPath");
    expect(curl).toContain("mode: 0o600");
    expect(curl).toContain('withoutCurlRedirectFlags');
    expect(curl).not.toContain("args.push('-H', `${name}: ${value}`)");
  });

  it('routes every built-in fetch call through the target-aware helper', () => {
    const source = readFileSync(join(process.cwd(), 'src/arsenal/index.ts'), 'utf8');
    const builtins = source.slice(source.indexOf('export const BUILTIN_TOOLS'), source.indexOf('export const EXTERNAL_TOOLS'));
    expect(builtins).not.toMatch(/\bfetch\s*\(/);
    expect(builtins).toContain('targetFetch(');
  });
});

describe('per-mission runtime target headers (UI-supplied, no env, no persistence)', () => {
  it('accepts a valid JSON object and returns only the header NAMES (never values)', () => {
    delete process.env.TEMPEST_TARGET_ORIGIN;
    delete process.env.TEMPEST_TARGET_HEADERS;
    const names = setRuntimeTargetHeaders('https://api.example', JSON.stringify({
      Authorization: 'Bearer ui-secret', 'X-API-Key': 'ui-key',
    }));
    // Names come back through the WHATWG Headers object, which normalizes them to lowercase.
    expect(names).toEqual(['authorization', 'x-api-key']);
    // The value is never surfaced by the binder — only names come back.
    expect(JSON.stringify(names)).not.toContain('ui-secret');
  });

  it('rejects malformed JSON, non-string values, transport headers, and bad origins (fail closed)', () => {
    expect(setRuntimeTargetHeaders('https://api.example', '{ not json')).toBeNull();
    expect(setRuntimeTargetHeaders('https://api.example', JSON.stringify({ Authorization: 123 }))).toBeNull();
    expect(setRuntimeTargetHeaders('https://api.example', JSON.stringify({ Host: 'evil.example' }))).toBeNull();
    expect(setRuntimeTargetHeaders('https://api.example', JSON.stringify([]))).toBeNull();
    expect(setRuntimeTargetHeaders('https://api.example/path', JSON.stringify({ Authorization: 'Bearer x' }))).toBeNull();
    expect(setRuntimeTargetHeaders('ftp://api.example', JSON.stringify({ Authorization: 'Bearer x' }))).toBeNull();
  });

  it('injects the UI headers into the exact origin only — a UI override wins over the env default', async () => {
    // env default points at target.example; the UI override binds a DIFFERENT origin.
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);
    setRuntimeTargetHeaders('https://api.example', JSON.stringify({ Authorization: 'Bearer ui-secret' }));

    await httpTool.handler(createToolContext(undefined, { url: 'https://api.example/v1' }));
    await httpTool.handler(createToolContext(undefined, { url: 'https://other.example/v1' }));
    // The env-configured origin no longer applies while the override is active.
    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example/v1' }));

    expect(new Headers(mockFetch.mock.calls[0][1].headers).get('authorization')).toBe('Bearer ui-secret');
    expect(new Headers(mockFetch.mock.calls[1][1]?.headers).has('authorization')).toBe(false);
    expect(new Headers(mockFetch.mock.calls[2][1]?.headers).has('authorization')).toBe(false);
  });

  it('falls back to the environment default after the override is cleared', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);
    setRuntimeTargetHeaders('https://api.example', JSON.stringify({ Authorization: 'Bearer ui-secret' }));
    clearRuntimeTargetHeaders();

    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example/v1' }));
    expect(new Headers(mockFetch.mock.calls[0][1].headers).get('authorization')).toBe('Bearer configured-secret');
  });

  it('strips UI-supplied credentials across a cross-origin redirect', async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(response(302, { location: 'https://third-party.com/landing' }))
      .mockResolvedValueOnce(response());
    vi.stubGlobal('fetch', mockFetch);
    setRuntimeTargetHeaders('https://api.example', JSON.stringify({ Authorization: 'Bearer ui-secret' }));

    await httpTool.handler(createToolContext(undefined, { url: 'https://api.example/start' }));

    expect(new Headers(mockFetch.mock.calls[0][1].headers).get('authorization')).toBe('Bearer ui-secret');
    expect(new Headers(mockFetch.mock.calls[1][1].headers).has('authorization')).toBe(false);
    expect(String(mockFetch.mock.calls[1][0])).toBe('https://third-party.com/landing');
  });

  it('redacts UI-supplied header values from persisted tool output', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response(200, { 'x-reflected-value': 'Bearer ui-secret' }));
    vi.stubGlobal('fetch', mockFetch);
    setRuntimeTargetHeaders('https://api.example', JSON.stringify({ Authorization: 'Bearer ui-secret' }));
    const arsenal = new Arsenal();
    arsenal.register(httpTool);

    const result = await arsenal.execute('http_request', createToolContext(undefined, { url: 'https://api.example' }));
    expect(result.output).toContain('[REDACTED]');
    expect(result.output).not.toContain('ui-secret');
    expect(arsenal.getExecutions()[0].result?.output).not.toContain('ui-secret');
  });
});

describe('runtime target-header wiring (server + UI, static)', () => {
  const serverSource = readFileSync(join(process.cwd(), 'src/server.ts'), 'utf8');
  const uiSource = readFileSync(join(process.cwd(), 'docs/index.html'), 'utf8');

  it('server binds per-mission headers without mutating process.env and never serializes them', () => {
    // Uses the arsenal runtime binder, not a process.env write.
    expect(serverSource).toContain("import { setRuntimeTargetHeaders, clearRuntimeTargetHeaders } from './arsenal/index.js'");
    expect(serverSource).toMatch(/function bindMissionTargetHeaders\(/);
    expect(serverSource).not.toMatch(/process\.env\.TEMPEST_TARGET_(ORIGIN|HEADERS)\s*=/);
    // Header values are never part of the on-disk state snapshot (only names ever leave the binder).
    const snapshot = serverSource.slice(serverSource.indexOf('function buildStateSnapshot('), serverSource.indexOf('async function persistState('));
    expect(snapshot).not.toMatch(/targetHeaders|runtimeTargetHeader/);
  });

  it('both launch paths validate headers up front and clear them when no mission starts', () => {
    const launch = serverSource.slice(serverSource.indexOf("app.post('/api/admiral/launch'"), serverSource.indexOf('// BOUNTY PLATFORM INTEGRATIONS'));
    expect(launch).toMatch(/bindMissionTargetHeaders\(req\.body[^)]*, brief\.target\)/);
    expect(launch).toMatch(/if \(headerNames === null\)/);
    expect(launch).toMatch(/clearRuntimeTargetHeaders\(\);/);
    expect(launch).toMatch(/blockForApproval/);
    const execute = serverSource.slice(serverSource.indexOf("app.post('/api/general/execute'"), serverSource.indexOf("app.post('/api/general/auto'"));
    expect(execute).toMatch(/bindMissionTargetHeaders\(req\.body[^)]*, headerTarget\)/);
    expect(execute).toMatch(/clearRuntimeTargetHeaders\(\);\s*blockForApproval/);
    // Only header names are ever broadcast/returned — never the values.
    expect(launch).toMatch(/authenticatedHeaderNames: headerNames/);
    expect(execute).toMatch(/authenticatedHeaderNames: execHeaderNames/);
  });

  it('Guided Hunt exposes the optional headers field for Web/API only, validated and masked', () => {
    // Field is gated on the web target type.
    expect(uiSource).toMatch(/S\.type==='web'[\s\S]*?id="admHeaders"/);
    // Validation + masking helpers exist and the masker never returns the raw value.
    expect(uiSource).toMatch(/function admiralValidateHeaders\(/);
    expect(uiSource).toMatch(/function admiralMaskHeaderValue\(/);
    expect(uiSource).toMatch(/return '\[redacted\]'/);
    // Malformed headers block advancing; only names (values hidden) are echoed to the operator.
    expect(uiSource).toMatch(/headersOk = \(S\.type!=='web'\) \|\| admiralValidateHeaders/);
    expect(uiSource).toContain('(values hidden)');
    // Headers ride the launch body as targetHeaders (web only) — server re-validates + binds them.
    expect(uiSource).toMatch(/function _admHeaders\(\)/);
    expect(uiSource).toMatch(/\{ targetHeaders: v\.headers \}/);
    expect(uiSource).toMatch(/Object\.assign\(\{ brief: brief, confirmed: true \}, bb, _admHeaders\(\)/);
  });

  it('Guided Hunt Authentication & Principals is web-only, write-only secrets, and launch-wired', () => {
    expect(uiSource).toContain('Authentication &amp; Principals');
    expect(uiSource).toContain('admiralSetPrincipalMode');
    expect(uiSource).toContain("{id:'none'");
    expect(uiSource).toContain("{id:'single'");
    expect(uiSource).toContain("{id:'multiple'");
    expect(uiSource).toContain('+ Add Principal');
    expect(uiSource).toContain('value set (write-only)');
    expect(uiSource).toMatch(/function _admPrincipals\(\)/);
    expect(uiSource).toContain('_admPrincipals()');
    expect(uiSource).toContain('(secrets not shown)');
    expect(uiSource).toContain("type=\"password\"");
    expect(uiSource).not.toMatch(/step===4[\s\S]{0,800}p\.token/);
    expect(uiSource).not.toContain('esc(S.headers)');
    expect(uiSource).not.toContain('esc(p.headersJson)');
    expect(uiSource).not.toContain('esc(p.cookiesJson)');
    expect(uiSource).not.toContain('esc(p.token)');
    expect(uiSource).not.toContain('esc(p.apiKey)');
    expect(uiSource).not.toContain('esc(p.password)');
    expect(uiSource).not.toContain('esc(p.clientSecret)');
    expect(uiSource).toContain('admiralDisposeBoundSecrets()');
    expect(uiSource).toContain('window.admiralSetPrincipalAuthType');
    expect(uiSource).toContain('window.admiralSetOAuthGrant');
    expect(uiSource).not.toContain("admiralPatchPrincipal('+i+',this);render();");
  });
});

function extractFunction(source: string, name: string): string {
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

describe('Guided Hunt JS-state secret disposal', () => {
  const uiSource = readFileSync(join(process.cwd(), 'docs/index.html'), 'utf8');

  it('successful-launch disposal clears wizard secrets and preview stays metadata-only', () => {
    const headerSecret = '{"Authorization":"Bearer wizard-header-secret-zzzzzz"}';
    const cookieSecret = '{"sid":"wizard-cookie-secret-zzzzzz"}';
    const tokenSecret = 'wizard-bearer-secret-zzzzzz';
    const sandbox = {
      S: {
        headers: headerSecret,
        principals: [{
          label: 'Admin',
          authType: 'custom_headers',
          default: true,
          headersJson: headerSecret,
          cookiesJson: cookieSecret,
          token: tokenSecret,
          apiKey: 'wizard-apikey-secret-zzzzzz',
          password: 'wizard-password-secret-zzzz',
          clientSecret: 'wizard-client-secret-zzzzzz',
        }],
      },
      window: {} as { admiralDisposeBoundSecrets?: () => void; admiralPrincipalPreview?: () => string },
    };
    vm.runInNewContext(
      `${extractFunction(uiSource, 'admiralDisposeBoundSecrets')}\n`
      + `${extractFunction(uiSource, 'admiralPrincipalPreview')}\n`
      + 'window.admiralDisposeBoundSecrets = admiralDisposeBoundSecrets;\n'
      + 'window.admiralPrincipalPreview = admiralPrincipalPreview;\n'
      + 'admiralDisposeBoundSecrets();',
      sandbox,
    );
    expect(sandbox.S.headers).toBe('');
    expect(sandbox.S.principals[0].headersJson).toBe('');
    expect(sandbox.S.principals[0].cookiesJson).toBe('');
    expect(sandbox.S.principals[0].token).toBe('');
    expect(sandbox.S.principals[0].apiKey).toBe('');
    expect(sandbox.S.principals[0].password).toBe('');
    expect(sandbox.S.principals[0].clientSecret).toBe('');
    const serialized = JSON.stringify(sandbox.S);
    expect(serialized).not.toContain('wizard-header-secret-zzzzzz');
    expect(serialized).not.toContain('wizard-cookie-secret-zzzzzz');
    expect(serialized).not.toContain('wizard-bearer-secret-zzzzzz');
    expect(serialized).not.toContain('wizard-apikey-secret-zzzzzz');
    expect(serialized).not.toContain('wizard-password-secret-zzzz');
    expect(serialized).not.toContain('wizard-client-secret-zzzzzz');
    const preview = sandbox.window.admiralPrincipalPreview!();
    expect(preview).toBe('Admin (custom_headers, default)');
    expect(preview).not.toContain('secret');
    expect(preview).not.toContain('Bearer');
    const headerPlaceholder = sandbox.S.headers ? 'value set (write-only)' : '{"Authorization":"Bearer <token>"}';
    expect(headerPlaceholder).not.toContain('wizard-header-secret-zzzzzz');
    const customPlaceholder = sandbox.S.principals[0].headersJson ? 'value set (write-only)' : '{}';
    expect(customPlaceholder).toBe('{}');
    const cookiePlaceholder = sandbox.S.principals[0].cookiesJson ? 'value set (write-only)' : '{}';
    expect(cookiePlaceholder).toBe('{}');
  });

  it('launch success path disposes secrets only after a successful live launch', () => {
    const start = uiSource.indexOf('window.admiralLaunch = async function');
    const disposeAt = uiSource.indexOf('admiralDisposeBoundSecrets();', start);
    expect(start).toBeGreaterThan(0);
    expect(disposeAt).toBeGreaterThan(start);
    const launch = uiSource.slice(start, disposeAt + 'admiralDisposeBoundSecrets();'.length);
    const successGuard = launch.lastIndexOf('if (!res.ok || d.error)');
    expect(successGuard).toBeGreaterThan(0);
    expect(successGuard).toBeLessThan(launch.indexOf('admiralDisposeBoundSecrets();'));
  });
});
