/**
 * OAuth2 runtime — client_credentials, refresh_token, operator-assisted authorization_code + PKCE.
 * Tokens, codes, state, and verifiers are runtime-only. Token HTTP is ScopeGuard-gated.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { config } from '../config/index.js';
import type { OpenApiSecurityScheme } from '../surface/openapi.js';
import {
  getStoredPrincipal,
  listPrincipals,
  registerMissionSecretValues,
  setPrincipalOauthMaterial,
  type StoredPrincipal,
} from './store.js';
import {
  validationToolError,
  type AuthValidationFailure,
  type OAuth2Flow,
  type PrincipalPublic,
} from './types.js';

const MAX_ACQUIRE_ATTEMPTS = 3;
const MAX_REFRESH_ATTEMPTS = 3;
const ATTEMPT_COOLDOWN_MS = 5_000;
export const EXPIRY_SKEW_MS = 30_000;

export type ScopeLike = { allowedHosts: string[]; allowLoopback: boolean; allowPrivate: boolean } | null;

export type ScopedHttp = (url: string, init: RequestInit, scope: ScopeLike) => Promise<Response>;

let scopedHttp: ScopedHttp = async () => {
  const err = new Error('oauth_scope_denied');
  (err as Error & { code: string }).code = 'oauth_scope_denied';
  throw err;
};

/** Inject the canonical ScopeGuard-backed HTTP primitive. Fail-closed until wired. */
export function setOAuthScopedHttp(fn: ScopedHttp): void {
  scopedHttp = fn;
}

const refreshInflight = new Map<string, Promise<OAuthAcquireResult>>();

function inflightKey(missionId: string, principalId: string): string {
  return `${missionId}::${principalId}`;
}

function httpTimeoutMs(): number {
  try {
    return config.getTimeout('httpRequestTimeoutMs').valueMs;
  } catch {
    return 5_000;
  }
}

function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

function randomToken(bytes = 32): string {
  return b64url(randomBytes(bytes));
}

function pkceChallenge(verifier: string): string {
  return b64url(createHash('sha256').update(verifier).digest());
}

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function tokenUrlOf(p: StoredPrincipal): string | null {
  if (p.auth.type !== 'oauth2') return null;
  return p.auth.tokenUrl || null;
}

function refreshUrlOf(p: StoredPrincipal): string | null {
  if (p.auth.type !== 'oauth2') return null;
  return p.auth.refreshUrl || p.auth.tokenUrl || null;
}

export function isExpired(p: StoredPrincipal): boolean {
  const exp = p.oauth?.expiresAt;
  if (!exp) return false;
  return Date.now() >= exp - EXPIRY_SKEW_MS;
}

function budgetExceeded(p: StoredPrincipal, kind: 'acquire' | 'refresh'): AuthValidationFailure | null {
  const attempts = kind === 'acquire' ? (p.oauth?.acquireAttempts ?? 0) : (p.oauth?.refreshAttempts ?? 0);
  const max = kind === 'acquire' ? MAX_ACQUIRE_ATTEMPTS : MAX_REFRESH_ATTEMPTS;
  if (attempts >= max) {
    return { ok: false, code: 'malformed_token_response' };
  }
  const last = p.oauth?.lastAttemptAt ?? 0;
  if (last && Date.now() - last < ATTEMPT_COOLDOWN_MS && attempts > 0) {
    return { ok: false, code: 'malformed_token_response' };
  }
  return null;
}

export interface OAuthAcquireResult {
  ok: boolean;
  principal?: PrincipalPublic;
  authorizationUrl?: string;
  error?: string;
  code?: string;
}

function fail(
  missionId: string,
  principalId: string,
  failure: AuthValidationFailure,
  lastError: string,
  extras?: { clearOneUse?: boolean },
): OAuthAcquireResult {
  const patch: Parameters<typeof setPrincipalOauthMaterial>[2] = { runtimeStatus: 'failed', lastError };
  if (extras?.clearOneUse) {
    patch.authorizationCode = undefined;
    patch.state = undefined;
    patch.codeVerifier = undefined;
    patch.codeChallenge = undefined;
  }
  setPrincipalOauthMaterial(missionId, principalId, patch);
  return { ok: false, error: validationToolError(failure), code: failure.code };
}

async function scopedTokenPost(url: string, body: URLSearchParams, extraHeaders: Record<string, string>, scope: ScopeLike): Promise<{ status: number; json: unknown; text: string }> {
  const response = await scopedHttp(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
      ...extraHeaders,
    },
    body: body.toString(),
    redirect: 'manual',
    signal: AbortSignal.timeout(httpTimeoutMs()),
  }, scope);
  const text = await response.text();
  let json: unknown = null;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: response.status, json, text };
}

function parseTokenJson(json: unknown, status: number): {
  ok: true;
  accessToken: string;
  tokenType: string;
  refreshToken?: string;
  expiresAt?: number;
  scope?: string[];
} | AuthValidationFailure {
  if (status === 401 || status === 403) return { ok: false, code: 'malformed_token_response' };
  if (!json || typeof json !== 'object' || Array.isArray(json)) return { ok: false, code: 'malformed_token_response' };
  const obj = json as Record<string, unknown>;
  if (typeof obj.error === 'string') return { ok: false, code: 'malformed_token_response' };
  const accessToken = obj.access_token;
  if (typeof accessToken !== 'string' || !accessToken) return { ok: false, code: 'malformed_token_response' };
  if (typeof obj.token_type !== 'string' || !obj.token_type) return { ok: false, code: 'malformed_token_response' };
  if (obj.token_type.toLowerCase() !== 'bearer') return { ok: false, code: 'unsupported_token_type' };
  const expiresIn = typeof obj.expires_in === 'number' ? obj.expires_in : Number(obj.expires_in);
  const expiresAt = Number.isFinite(expiresIn) ? Date.now() + expiresIn * 1000 : undefined;
  const scope = typeof obj.scope === 'string' ? obj.scope.split(/\s+/).filter(Boolean) : undefined;
  const refreshToken = typeof obj.refresh_token === 'string' ? obj.refresh_token : undefined;
  return { ok: true, accessToken, tokenType: 'Bearer', refreshToken, expiresAt, scope };
}

function clientAuthHeadersAndBody(p: StoredPrincipal, body: URLSearchParams): Record<string, string> {
  if (p.auth.type !== 'oauth2') return {};
  const id = p.auth.clientId || '';
  const secret = p.auth.clientSecret || p.oauth?.clientSecret || '';
  const mode = p.auth.clientAuth || (secret ? 'body' : 'none');
  if (mode === 'basic' && id) {
    return { authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}` };
  }
  if (mode === 'body') {
    if (id) body.set('client_id', id);
    if (secret) body.set('client_secret', secret);
  } else if (id) {
    body.set('client_id', id);
  }
  return {};
}

function applyExtraParams(p: StoredPrincipal, body: URLSearchParams): void {
  if (p.auth.type !== 'oauth2' || !p.auth.extraTokenParams) return;
  for (const [k, v] of Object.entries(p.auth.extraTokenParams)) {
    if (k && typeof v === 'string') body.set(k, v);
  }
  if (p.auth.audience && !body.has('audience')) body.set('audience', p.auth.audience);
}

async function exchangeAt(missionId: string, p: StoredPrincipal, url: string, body: URLSearchParams, scope: ScopeLike, kind: 'acquire' | 'refresh'): Promise<OAuthAcquireResult> {
  const over = budgetExceeded(p, kind);
  if (over) return fail(missionId, p.id, over, 'oauth attempt budget exceeded');
  const attempts = kind === 'acquire' ? (p.oauth?.acquireAttempts ?? 0) + 1 : (p.oauth?.refreshAttempts ?? 0) + 1;
  setPrincipalOauthMaterial(missionId, p.id, {
    runtimeStatus: 'refreshing',
    lastError: '',
    ...(kind === 'acquire' ? { acquireAttempts: attempts } : { refreshAttempts: attempts }),
    lastAttemptAt: Date.now(),
  });
  const headers = clientAuthHeadersAndBody(p, body);
  applyExtraParams(p, body);
  let posted: { status: number; json: unknown; text: string };
  try {
    posted = await scopedTokenPost(url, body, headers, scope);
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === 'oauth_scope_denied') {
      return fail(missionId, p.id, { ok: false, code: 'oauth_scope_denied' }, 'token URL is not in authorized scope', { clearOneUse: true });
    }
    return fail(missionId, p.id, { ok: false, code: 'malformed_token_response' }, 'token request failed', { clearOneUse: true });
  }
  const parsed = parseTokenJson(posted.json, posted.status);
  if (!parsed.ok) {
    return fail(
      missionId,
      p.id,
      parsed,
      parsed.code === 'unsupported_token_type' ? 'unsupported token_type' : 'malformed token response',
      { clearOneUse: true },
    );
  }
  const previousRefresh = p.oauth?.refreshToken;
  setPrincipalOauthMaterial(missionId, p.id, {
    accessToken: parsed.accessToken,
    refreshToken: parsed.refreshToken ?? previousRefresh,
    tokenType: parsed.tokenType,
    expiresAt: parsed.expiresAt,
    scope: parsed.scope,
    authorizationCode: undefined,
    state: undefined,
    codeVerifier: undefined,
    codeChallenge: undefined,
    runtimeStatus: 'live',
    lastError: '',
  });
  return { ok: true, principal: listPrincipals(missionId).find((x) => x.id === p.id) };
}

export function buildAuthorizationUrl(p: StoredPrincipal): { url: string; state: string; verifier?: string; challenge?: string } | AuthValidationFailure {
  if (p.auth.type !== 'oauth2' || !p.auth.authorizationUrl) {
    return { ok: false, code: 'malformed_token_response' };
  }
  const state = randomToken();
  const params = new URLSearchParams();
  params.set('response_type', 'code');
  if (p.auth.clientId) params.set('client_id', p.auth.clientId);
  if (p.auth.redirectUri) params.set('redirect_uri', p.auth.redirectUri);
  if (p.auth.scopes?.length) params.set('scope', p.auth.scopes.join(' '));
  params.set('state', state);
  let verifier: string | undefined;
  let challenge: string | undefined;
  const pkce = p.auth.pkce || p.auth.flow === 'authorization_code_pkce';
  if (pkce) {
    verifier = randomToken(48);
    challenge = pkceChallenge(verifier);
    params.set('code_challenge', challenge);
    params.set('code_challenge_method', 'S256');
  }
  const url = `${p.auth.authorizationUrl}${p.auth.authorizationUrl.includes('?') ? '&' : '?'}${params.toString()}`;
  return { url, state, verifier, challenge };
}

export async function acquireOAuth(missionId: string, principalId: string, scope: ScopeLike): Promise<OAuthAcquireResult> {
  const p = getStoredPrincipal(missionId, principalId);
  if (!p || p.auth.type !== 'oauth2') {
    return { ok: false, error: validationToolError({ ok: false, code: 'unknown_principal' }), code: 'unknown_principal' };
  }
  const flow: OAuth2Flow = p.auth.flow;
  if (flow === 'authorization_code' || flow === 'authorization_code_pkce') {
    const built = buildAuthorizationUrl(p);
    if ('ok' in built && built.ok === false) return { ok: false, error: validationToolError(built), code: built.code };
    const { url, state, verifier, challenge } = built as { url: string; state: string; verifier?: string; challenge?: string };
    setPrincipalOauthMaterial(missionId, p.id, {
      state,
      codeVerifier: verifier,
      codeChallenge: challenge,
      runtimeStatus: 'unknown',
      lastError: '',
    });
    return {
      ok: true,
      authorizationUrl: url,
      principal: listPrincipals(missionId).find((x) => x.id === p.id),
    };
  }
  const tokenUrl = tokenUrlOf(p);
  if (!tokenUrl) return fail(missionId, p.id, { ok: false, code: 'malformed_token_response' }, 'tokenUrl missing');
  const body = new URLSearchParams();
  if (flow === 'refresh_token') {
    const refresh = p.oauth?.refreshToken;
    if (!refresh) return fail(missionId, p.id, { ok: false, code: 'malformed_token_response' }, 'refresh_token missing');
    body.set('grant_type', 'refresh_token');
    body.set('refresh_token', refresh);
    return exchangeAt(missionId, p, refreshUrlOf(p) || tokenUrl, body, scope, 'refresh');
  }
  body.set('grant_type', 'client_credentials');
  if (p.auth.scopes?.length) body.set('scope', p.auth.scopes.join(' '));
  return exchangeAt(missionId, p, tokenUrl, body, scope, 'acquire');
}

export async function refreshOAuth(missionId: string, principalId: string, scope: ScopeLike): Promise<OAuthAcquireResult> {
  const key = inflightKey(missionId, principalId);
  const existing = refreshInflight.get(key);
  if (existing) return existing;
  const run = (async () => {
    const p = getStoredPrincipal(missionId, principalId);
    if (!p || p.auth.type !== 'oauth2') {
      return { ok: false, error: validationToolError({ ok: false, code: 'unknown_principal' }), code: 'unknown_principal' };
    }
    const refresh = p.oauth?.refreshToken;
    const url = refreshUrlOf(p);
    if (!refresh || !url) {
      setPrincipalOauthMaterial(missionId, p.id, { runtimeStatus: 'stale', lastError: 'refresh material missing' });
      return { ok: false, error: validationToolError({ ok: false, code: 'malformed_token_response' }), code: 'malformed_token_response' };
    }
    const body = new URLSearchParams();
    body.set('grant_type', 'refresh_token');
    body.set('refresh_token', refresh);
    return exchangeAt(missionId, p, url, body, scope, 'refresh');
  })();
  refreshInflight.set(key, run);
  try {
    return await run;
  } finally {
    refreshInflight.delete(key);
  }
}

function extractCodeState(input: { code?: string; state?: string; callbackUrl?: string }): { code: string; state: string } | AuthValidationFailure {
  let code = typeof input.code === 'string' ? input.code : '';
  let state = typeof input.state === 'string' ? input.state : '';
  if (input.callbackUrl) {
    try {
      const u = new URL(input.callbackUrl);
      code = u.searchParams.get('code') || code;
      state = u.searchParams.get('state') || state;
    } catch {
      return { ok: false, code: 'malformed_token_response' };
    }
  }
  if (!code || !state) return { ok: false, code: 'malformed_token_response' };
  return { code, state };
}

export async function exchangeOAuthCode(
  missionId: string,
  principalId: string,
  input: { code?: string; state?: string; callbackUrl?: string },
  scope: ScopeLike,
): Promise<OAuthAcquireResult> {
  const p = getStoredPrincipal(missionId, principalId);
  if (!p || p.auth.type !== 'oauth2') {
    return { ok: false, error: validationToolError({ ok: false, code: 'unknown_principal' }), code: 'unknown_principal' };
  }
  const extracted = extractCodeState(input);
  if ('ok' in extracted && extracted.ok === false) {
    if (typeof input.code === 'string') registerMissionSecretValues(missionId, [input.code]);
    if (typeof input.state === 'string') registerMissionSecretValues(missionId, [input.state]);
    return { ok: false, error: validationToolError(extracted), code: extracted.code };
  }
  const { code, state } = extracted as { code: string; state: string };
  registerMissionSecretValues(missionId, [code, state, p.oauth?.codeVerifier ?? '']);
  setPrincipalOauthMaterial(missionId, p.id, { authorizationCode: code });
  const expected = p.oauth?.state;
  if (!expected || !safeEqual(expected, state)) {
    return fail(missionId, p.id, { ok: false, code: 'oauth_state_mismatch' }, 'OAuth state mismatch');
  }
  const tokenUrl = tokenUrlOf(p);
  if (!tokenUrl) return fail(missionId, p.id, { ok: false, code: 'malformed_token_response' }, 'tokenUrl missing', { clearOneUse: true });
  const body = new URLSearchParams();
  body.set('grant_type', 'authorization_code');
  body.set('code', code);
  if (p.auth.redirectUri) body.set('redirect_uri', p.auth.redirectUri);
  if (p.oauth?.codeVerifier) body.set('code_verifier', p.oauth.codeVerifier);
  return exchangeAt(missionId, p, tokenUrl, body, scope, 'acquire');
}

/**
 * Called from targetFetch on inherit. Refreshes a LIVE-but-expired oauth principal (single-flight).
 * Does not auto-acquire client_credentials; operator acquire is required for first token.
 */
export async function ensureOAuthAccess(missionId: string, principalId: string, scope: ScopeLike): Promise<void> {
  const p = getStoredPrincipal(missionId, principalId);
  if (!p || p.auth.type !== 'oauth2') return;
  if (p.runtimeStatus === 'failed') return;
  if (p.oauth?.accessToken && p.oauth.tokenType?.toLowerCase() === 'bearer' && !isExpired(p)) return;
  if (p.oauth?.refreshToken) {
    await refreshOAuth(missionId, principalId, scope);
  } else if (p.oauth?.accessToken && isExpired(p)) {
    setPrincipalOauthMaterial(missionId, p.id, { runtimeStatus: 'stale', lastError: 'access token expired' });
  }
}

export interface OpenApiOAuthSuggestion {
  schemeName: string;
  flow?: string;
  authorizationUrl?: string;
  tokenUrl?: string;
  refreshUrl?: string;
  scopes?: string[];
  type: string;
}

function resolveAgainstSource(url: string | undefined, sourceOrigin: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    if (/^https?:\/\//i.test(url)) return url;
    if (!sourceOrigin) return url;
    return new URL(url, sourceOrigin).toString();
  } catch {
    return url;
  }
}

export function importOAuthFromOpenApi(
  schemes: OpenApiSecurityScheme[],
  sourceOrigin?: string,
): OpenApiOAuthSuggestion[] {
  return schemes
    .filter((s) => s && (s.type === 'oauth2' || s.authorizationUrl || s.tokenUrl || (s.flows && s.flows.length)))
    .map((s) => ({
      schemeName: s.name,
      type: s.type,
      flow: s.flows?.[0],
      authorizationUrl: resolveAgainstSource(s.authorizationUrl, sourceOrigin),
      tokenUrl: resolveAgainstSource(s.tokenUrl, sourceOrigin),
      refreshUrl: resolveAgainstSource(s.refreshUrl, sourceOrigin),
      scopes: s.scopes,
    }));
}
