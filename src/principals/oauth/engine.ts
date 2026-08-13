/**
 * OAuth token lifecycle engine. Grant/client-auth adapters own request construction;
 * this module owns single-flight, refresh-then-reacquire, budgets, and token HTTP.
 */

import {
  getStoredPrincipal,
  listPrincipals,
  registerMissionSecretValues,
  setPrincipalOauthMaterial,
  type StoredPrincipal,
} from '../store.js';
import {
  TERMINAL_OAUTH_CONFIG_CODES,
  validationToolError,
  type AuthValidationCode,
  type AuthValidationFailure,
  type PrincipalPublic,
} from '../types.js';
import type { GrantTokenRequest, ScopeLike } from './contracts.js';
import { classifyStandardOAuthError, oauthErrorFromJson } from './errors.js';
import { scopedTokenPost } from './http.js';
import { applyResources, resolvedClientAuth, resolvedGrantType } from './normalize.js';
import { collidingReservedKeys, reservedParamSet } from './reserved.js';
import { getClientAuth, getGrant } from './registry.js';
import { authorizationCodeGrant, buildAuthorizationRequest, safeEqual } from './grants/authorization-code.js';

export type { ScopeLike };
export { setOAuthScopedHttp, getOAuthScopedHttp } from './http.js';
export type { ScopedHttp } from './http.js';

const MAX_ACQUIRE_ATTEMPTS = 3;
const MAX_REFRESH_ATTEMPTS = 3;
const MAX_REACQUIRE_ATTEMPTS = 3;
const ATTEMPT_COOLDOWN_MS = 5_000;
export const EXPIRY_SKEW_MS = 30_000;

const tokenInflight = new Map<string, Promise<OAuthAcquireResult>>();

function inflightKey(missionId: string, principalId: string): string {
  return `${missionId}::${principalId}`;
}

export async function withTokenFlight(
  missionId: string,
  principalId: string,
  fn: () => Promise<OAuthAcquireResult>,
): Promise<OAuthAcquireResult> {
  const key = inflightKey(missionId, principalId);
  const existing = tokenInflight.get(key);
  if (existing) return existing;
  const run = fn();
  tokenInflight.set(key, run);
  try {
    return await run;
  } finally {
    tokenInflight.delete(key);
  }
}

export function isExpired(p: StoredPrincipal): boolean {
  const exp = p.oauth?.expiresAt;
  if (!exp) return false;
  return Date.now() >= exp - EXPIRY_SKEW_MS;
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
  extras?: { clearOneUse?: boolean; refreshUnusable?: boolean; lastErrorCode?: AuthValidationCode },
): OAuthAcquireResult {
  const patch: Parameters<typeof setPrincipalOauthMaterial>[2] = {
    runtimeStatus: 'failed',
    lastError,
    lastErrorCode: extras?.lastErrorCode ?? failure.code,
  };
  if (extras?.clearOneUse) {
    patch.authorizationCode = undefined;
    patch.state = undefined;
    patch.codeVerifier = undefined;
    patch.codeChallenge = undefined;
  }
  if (extras?.refreshUnusable) {
    patch.refreshToken = undefined;
    patch.refreshUnusable = true;
  }
  setPrincipalOauthMaterial(missionId, principalId, patch);
  return { ok: false, error: validationToolError(failure), code: failure.code };
}

function budgetExceeded(p: StoredPrincipal, kind: 'acquire' | 'refresh' | 'reacquire'): AuthValidationFailure | null {
  const attempts = kind === 'acquire'
    ? (p.oauth?.acquireAttempts ?? 0)
    : kind === 'refresh'
      ? (p.oauth?.refreshAttempts ?? 0)
      : (p.oauth?.reacquireAttempts ?? 0);
  const max = kind === 'refresh' ? MAX_REFRESH_ATTEMPTS : kind === 'reacquire' ? MAX_REACQUIRE_ATTEMPTS : MAX_ACQUIRE_ATTEMPTS;
  if (attempts >= max) return { ok: false, code: 'oauth_renewal_budget_exceeded' };
  const last = p.oauth?.lastAttemptAt ?? 0;
  if (last && Date.now() - last < ATTEMPT_COOLDOWN_MS && attempts > 0) {
    return { ok: false, code: 'oauth_renewal_budget_exceeded' };
  }
  return null;
}

function parseTokenJson(json: unknown, status: number, phase: 'acquire' | 'refresh' | 'reacquire'): {
  ok: true;
  accessToken: string;
  tokenType: string;
  refreshToken?: string;
  expiresAt?: number;
  scope?: string[];
} | AuthValidationFailure {
  if (status >= 300 && status < 400) return { ok: false, code: 'oauth_unexpected_redirect' };
  const classified = classifyStandardOAuthError(phase, json, status);
  if (classified) return { ok: false, code: classified };
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

function prePostSecrets(missionId: string, p: StoredPrincipal, body: URLSearchParams): void {
  const values: string[] = [];
  if (p.auth.type === 'oauth2') {
    if (typeof p.auth.clientSecret === 'string') values.push(p.auth.clientSecret);
    if (typeof p.auth.password === 'string') values.push(p.auth.password);
    if (p.auth.secretParams) values.push(...Object.values(p.auth.secretParams));
  }
  const o = p.oauth;
  if (o) {
    for (const v of [o.refreshToken, o.authorizationCode, o.state, o.codeVerifier, o.clientSecret]) {
      if (v) values.push(v);
    }
  }
  for (const key of ['password', 'client_secret', 'code', 'code_verifier', 'refresh_token', 'assertion', 'client_assertion']) {
    const v = body.get(key);
    if (v) values.push(v);
  }
  registerMissionSecretValues(missionId, values);
}

function mergeClientAuthAndExtras(
  p: StoredPrincipal,
  request: GrantTokenRequest,
): { ok: true; body: URLSearchParams; headers: Record<string, string> } | AuthValidationFailure {
  if (p.auth.type !== 'oauth2') return { ok: false, code: 'malformed_token_response' };
  const method = resolvedClientAuth(p.auth);
  if (method === 'client_secret_jwt' || method === 'private_key_jwt' || method === 'tls_client_auth') {
    return { ok: false, code: 'oauth_unsupported_client_auth' };
  }
  const adapter = getClientAuth(method);
  if (!adapter) return { ok: false, code: 'oauth_unsupported_client_auth' };
  const grant = getGrant(resolvedGrantType(p.auth));
  const reserved = [
    ...((grant?.reservedTokenParams() ?? [])),
    ...adapter.reservedTokenParams(),
  ];
  const collisions = collidingReservedKeys(
    [p.auth.extraTokenParams, p.auth.safeParams, p.auth.secretParams && typeof p.auth.secretParams === 'object' ? p.auth.secretParams : undefined],
    reserved,
  );
  if (collisions.length) return { ok: false, code: 'oauth_reserved_parameter_collision' };
  const body = request.body;
  const applied = adapter.apply({ principal: p }, body);
  if (p.auth.extraTokenParams) {
    for (const [k, v] of Object.entries(p.auth.extraTokenParams)) {
      if (!k || typeof v !== 'string') continue;
      if (reservedParamSet(reserved).has(k) || body.has(k)) return { ok: false, code: 'oauth_reserved_parameter_collision' };
      body.set(k, v);
    }
  }
  return { ok: true, body, headers: { ...(request.extraHeaders || {}), ...(applied.headers || {}) } };
}

async function exchangeAt(
  missionId: string,
  p: StoredPrincipal,
  request: GrantTokenRequest,
  scope: ScopeLike,
  kind: 'acquire' | 'refresh' | 'reacquire',
): Promise<OAuthAcquireResult> {
  const over = budgetExceeded(p, kind);
  if (over) return fail(missionId, p.id, over, 'oauth attempt budget exceeded', { lastErrorCode: 'oauth_renewal_budget_exceeded' });
  const attempts = kind === 'acquire'
    ? (p.oauth?.acquireAttempts ?? 0) + 1
    : kind === 'refresh'
      ? (p.oauth?.refreshAttempts ?? 0) + 1
      : (p.oauth?.reacquireAttempts ?? 0) + 1;
  setPrincipalOauthMaterial(missionId, p.id, {
    runtimeStatus: 'refreshing',
    lastError: '',
    lastErrorCode: undefined,
    ...(kind === 'acquire' ? { acquireAttempts: attempts } : kind === 'refresh' ? { refreshAttempts: attempts } : { reacquireAttempts: attempts }),
    lastAttemptAt: Date.now(),
  });
  const merged = mergeClientAuthAndExtras(p, request);
  if (!merged.ok) {
    return fail(missionId, p.id, merged, merged.code, { clearOneUse: true, lastErrorCode: merged.code });
  }
  prePostSecrets(missionId, p, merged.body);
  let posted: { status: number; json: unknown; text: string };
  try {
    posted = await scopedTokenPost(request.url, merged.body, merged.headers, scope);
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === 'oauth_scope_denied') {
      return fail(missionId, p.id, { ok: false, code: 'oauth_scope_denied' }, 'token URL is not in authorized scope', { clearOneUse: true });
    }
    if (code === 'oauth_oversized_response') {
      return fail(missionId, p.id, { ok: false, code: 'oauth_oversized_response' }, 'token response oversized', { clearOneUse: true });
    }
    return fail(missionId, p.id, { ok: false, code: 'malformed_token_response' }, 'token request failed', { clearOneUse: true });
  }
  if (posted.status >= 300 && posted.status < 400) {
    return fail(missionId, p.id, { ok: false, code: 'oauth_unexpected_redirect' }, 'token endpoint redirected', { clearOneUse: true });
  }
  const grant = getGrant(p.auth.type === 'oauth2' ? resolvedGrantType(p.auth) : '');
  const adapterCode = grant?.classifyError(kind, posted.json, posted.status);
  const parsed = parseTokenJson(posted.json, posted.status, kind);
  if (!parsed.ok) {
    const code = adapterCode && adapterCode !== 'malformed_token_response' ? adapterCode : parsed.code;
    const refreshUnusable = kind === 'refresh' && (code === 'oauth_invalid_grant' || oauthErrorFromJson(posted.json) === 'invalid_grant');
    grant?.clearOneUse?.(p);
    return fail(
      missionId,
      p.id,
      { ok: false, code },
      code === 'unsupported_token_type' ? 'unsupported token_type' : `oauth ${kind} failed`,
      { clearOneUse: true, refreshUnusable, lastErrorCode: code },
    );
  }
  const previousRefresh = p.oauth?.refreshToken;
  grant?.clearOneUse?.(p);
  grant?.onTokenSuccess?.({ missionId, principal: p });
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
    refreshUnusable: false,
    runtimeStatus: 'live',
    lastError: '',
    lastErrorCode: undefined,
  });
  registerMissionSecretValues(missionId, [parsed.accessToken, parsed.refreshToken ?? '']);
  return { ok: true, principal: listPrincipals(missionId).find((x) => x.id === p.id) };
}

function refreshRequest(p: StoredPrincipal): GrantTokenRequest | AuthValidationFailure {
  if (p.auth.type !== 'oauth2') return { ok: false, code: 'malformed_token_response' };
  const refresh = p.oauth?.refreshToken;
  const url = p.auth.refreshUrl || p.auth.tokenUrl;
  if (!refresh || p.oauth?.refreshUnusable || !url) return { ok: false, code: 'malformed_token_response' };
  const body = new URLSearchParams();
  body.set('grant_type', 'refresh_token');
  body.set('refresh_token', refresh);
  if (p.auth.scopes?.length) body.set('scope', p.auth.scopes.join(' '));
  applyResources(body, p.auth.resource);
  if (p.auth.audience) body.set('audience', p.auth.audience);
  return { url, body };
}

async function acquireInner(
  missionId: string,
  p: StoredPrincipal,
  scope: ScopeLike,
  kind: 'acquire' | 'reacquire',
): Promise<OAuthAcquireResult> {
  const grantType = p.auth.type === 'oauth2' ? resolvedGrantType(p.auth) : '';
  const grant = getGrant(grantType);
  if (!grant) return fail(missionId, p.id, { ok: false, code: 'oauth_unsupported_grant' }, 'unsupported grant', { lastErrorCode: 'oauth_unsupported_grant' });
  if (kind === 'acquire' && grant.beginInteractive) {
    const built = await grant.beginInteractive({ missionId, principal: p });
    if ('ok' in built && built.ok === false) return { ok: false, error: validationToolError(built), code: built.code };
    const interactive = built as { authorizationUrl: string; state: string; verifier?: string; challenge?: string };
    setPrincipalOauthMaterial(missionId, p.id, {
      state: interactive.state,
      codeVerifier: interactive.verifier,
      codeChallenge: interactive.challenge,
      runtimeStatus: 'unknown',
      lastError: '',
      lastErrorCode: undefined,
    });
    registerMissionSecretValues(missionId, [interactive.state, interactive.verifier ?? '']);
    return {
      ok: true,
      authorizationUrl: interactive.authorizationUrl,
      principal: listPrincipals(missionId).find((x) => x.id === p.id),
    };
  }
  const request = grant.acquire({ principal: p });
  if ('ok' in request && request.ok === false) {
    return fail(missionId, p.id, request, request.code, { lastErrorCode: request.code });
  }
  return exchangeAt(missionId, p, request as GrantTokenRequest, scope, kind);
}

async function refreshInner(missionId: string, p: StoredPrincipal, scope: ScopeLike): Promise<OAuthAcquireResult> {
  const request = refreshRequest(p);
  if ('ok' in request && request.ok === false) {
    setPrincipalOauthMaterial(missionId, p.id, { runtimeStatus: 'stale', lastError: 'refresh material missing' });
    return { ok: false, error: validationToolError(request), code: request.code };
  }
  return exchangeAt(missionId, p, request as GrantTokenRequest, scope, 'refresh');
}

export function buildAuthorizationUrl(p: StoredPrincipal): { url: string; state: string; verifier?: string; challenge?: string } | AuthValidationFailure {
  return buildAuthorizationRequest(p);
}

export async function acquireOAuth(missionId: string, principalId: string, scope: ScopeLike): Promise<OAuthAcquireResult> {
  return withTokenFlight(missionId, principalId, async () => {
    const p = getStoredPrincipal(missionId, principalId);
    if (!p || p.auth.type !== 'oauth2') {
      return { ok: false, error: validationToolError({ ok: false, code: 'unknown_principal' }), code: 'unknown_principal' };
    }
    return acquireInner(missionId, p, scope, 'acquire');
  });
}

export async function refreshOAuth(missionId: string, principalId: string, scope: ScopeLike): Promise<OAuthAcquireResult> {
  return withTokenFlight(missionId, principalId, async () => {
    const p = getStoredPrincipal(missionId, principalId);
    if (!p || p.auth.type !== 'oauth2') {
      return { ok: false, error: validationToolError({ ok: false, code: 'unknown_principal' }), code: 'unknown_principal' };
    }
    const refreshed = await refreshInner(missionId, p, scope);
    if (refreshed.ok) return refreshed;
    if (refreshed.code === 'oauth_invalid_grant') {
      const fresh = getStoredPrincipal(missionId, principalId);
      if (fresh && canReacquire(fresh)) {
        return acquireInner(missionId, fresh, scope, 'reacquire');
      }
    }
    return refreshed;
  });
}

function canReacquire(p: StoredPrincipal): boolean {
  if (p.auth.type !== 'oauth2') return false;
  const grant = getGrant(resolvedGrantType(p.auth));
  if (!grant?.canRepeatNonInteractive(p)) return false;
  const code = p.oauth?.lastErrorCode as AuthValidationCode | undefined;
  if (code && TERMINAL_OAUTH_CONFIG_CODES.has(code)) return false;
  return true;
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
  return withTokenFlight(missionId, principalId, async () => {
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
    const fresh = getStoredPrincipal(missionId, principalId)!;
    const request = authorizationCodeGrant.acquire({ principal: fresh });
    if ('ok' in request && request.ok === false) {
      return fail(missionId, p.id, request, request.code, { clearOneUse: true });
    }
    return exchangeAt(missionId, fresh, request as GrantTokenRequest, scope, 'acquire');
  });
}

export async function ensureOAuthAccess(
  missionId: string,
  principalId: string,
  scope: ScopeLike,
  opts?: { forceRenewal?: boolean },
): Promise<OAuthAcquireResult | void> {
  return withTokenFlight(missionId, principalId, async () => {
    const p = getStoredPrincipal(missionId, principalId);
    if (!p || p.auth.type !== 'oauth2') {
      return { ok: false, code: 'unknown_principal' };
    }
    const lastCode = p.oauth?.lastErrorCode as AuthValidationCode | undefined;
    if (!opts?.forceRenewal && p.oauth?.accessToken && p.oauth.tokenType?.toLowerCase() === 'bearer' && !isExpired(p) && p.runtimeStatus === 'live') {
      return { ok: true, principal: listPrincipals(missionId).find((x) => x.id === p.id) };
    }
    if (lastCode && TERMINAL_OAUTH_CONFIG_CODES.has(lastCode) && !opts?.forceRenewal) {
      return { ok: false, error: validationToolError({ ok: false, code: lastCode, runtimeStatus: p.runtimeStatus }), code: lastCode };
    }

    const refreshUsable = !!p.oauth?.refreshToken && !p.oauth.refreshUnusable;
    if (refreshUsable && (opts?.forceRenewal || isExpired(p) || p.runtimeStatus !== 'live' || !p.oauth?.accessToken)) {
      const refreshed = await refreshInner(missionId, p, scope);
      if (refreshed.ok) return refreshed;
      if (refreshed.code && TERMINAL_OAUTH_CONFIG_CODES.has(refreshed.code as AuthValidationCode)) return refreshed;
      if (refreshed.code === 'oauth_invalid_grant' || refreshed.code === 'malformed_token_response' || refreshed.code === 'oauth_refresh_failed') {
        const after = getStoredPrincipal(missionId, principalId);
        if (after && canReacquire(after)) {
          const again = await acquireInner(missionId, after, scope, 'reacquire');
          return again;
        }
        if (!getGrant(resolvedGrantType(p.auth))?.canRepeatNonInteractive(p)) {
          setPrincipalOauthMaterial(missionId, p.id, {
            runtimeStatus: 'stale',
            lastError: 'oauth_interaction_required',
            lastErrorCode: 'oauth_interaction_required',
          });
          return { ok: false, error: validationToolError({ ok: false, code: 'oauth_interaction_required', runtimeStatus: 'stale' }), code: 'oauth_interaction_required' };
        }
      }
      return refreshed;
    }

    const grant = getGrant(resolvedGrantType(p.auth));
    if (grant?.canRepeatNonInteractive(p)) {
      if (lastCode === 'oauth_invalid_grant' && !opts?.forceRenewal && p.runtimeStatus === 'failed') {
        return { ok: false, error: validationToolError({ ok: false, code: 'oauth_invalid_grant', runtimeStatus: 'failed' }), code: 'oauth_invalid_grant' };
      }
      return acquireInner(missionId, p, scope, p.oauth?.accessToken ? 'reacquire' : 'acquire');
    }

    if (p.oauth?.accessToken && isExpired(p)) {
      setPrincipalOauthMaterial(missionId, p.id, {
        runtimeStatus: 'stale',
        lastError: 'access token expired',
        lastErrorCode: 'oauth_interaction_required',
      });
      return { ok: false, error: validationToolError({ ok: false, code: 'oauth_interaction_required', runtimeStatus: 'stale' }), code: 'oauth_interaction_required' };
    }
    return { ok: false, error: validationToolError({ ok: false, code: 'oauth_not_live', runtimeStatus: p.runtimeStatus }), code: 'oauth_not_live' };
  });
}
