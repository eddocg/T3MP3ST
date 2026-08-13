/**
 * Mission-scoped PrincipalRuntimeStore. Keyed only by missionId + principalId.
 * No process-global "active mission" auth selector.
 */

import { randomUUID } from 'node:crypto';
import { replaceRuntimeSecretSource, clearRuntimeSecretSource } from '../redact.js';
import {
  FORBIDDEN_AUTH_HEADERS,
  MAX_PRINCIPALS_PER_MISSION,
  normalizeHttpOrigin,
  principalSecretSourceId,
  type AuthProfileWrite,
  type AuthValidationFailure,
  type PrincipalPublic,
  type PrincipalRuntimeStatus,
  type PrincipalWrite,
} from './types.js';

export interface OAuthRuntimeMaterial {
  accessToken?: string;
  refreshToken?: string;
  tokenType?: string;
  expiresAt?: number;
  scope?: string[];
  authorizationCode?: string;
  state?: string;
  codeVerifier?: string;
  codeChallenge?: string;
  clientSecret?: string;
  acquireAttempts?: number;
  refreshAttempts?: number;
  lastAttemptAt?: number;
}

export interface StoredPrincipal {
  id: string;
  label: string;
  roleHint?: string;
  origin: string;
  default: boolean;
  auth: AuthProfileWrite;
  runtimeStatus: PrincipalRuntimeStatus;
  lastStatusAt?: string;
  lastError?: string;
  oauth?: OAuthRuntimeMaterial;
}

interface MissionBucket {
  defaultPrincipalId?: string;
  principals: Map<string, StoredPrincipal>;
}

const missions = new Map<string, MissionBucket>();
/** Rotated-out / dropped secrets stay registered until mission teardown. */
const historicalSecrets = new Map<string, Set<string>>();

function collectSecrets(p: StoredPrincipal): string[] {
  const out: string[] = [];
  const auth = p.auth;
  if (auth.type === 'custom_headers') out.push(...Object.values(auth.headers));
  else if (auth.type === 'static_bearer') out.push(auth.token);
  else if (auth.type === 'api_key') out.push(auth.value);
  else if (auth.type === 'http_basic') {
    out.push(auth.password);
    if (auth.username.length >= 6) out.push(auth.username);
    out.push(Buffer.from(`${auth.username}:${auth.password}`).toString('base64'));
  } else if (auth.type === 'cookie_session') out.push(...Object.values(auth.cookies));
  else if (auth.type === 'oauth2') {
    if (auth.clientSecret) out.push(auth.clientSecret);
    const o = p.oauth;
    if (o) {
      for (const v of [o.accessToken, o.refreshToken, o.authorizationCode, o.state, o.codeVerifier, o.clientSecret]) {
        if (v) out.push(v);
      }
    }
    if (auth.extraTokenParams) out.push(...Object.values(auth.extraTokenParams));
  }
  return out.filter(Boolean);
}

function syncMissionSecrets(missionId: string): void {
  const bucket = missions.get(missionId);
  const source = principalSecretSourceId(missionId);
  if (!bucket || bucket.principals.size === 0) {
    // Keep historical values registered until teardown so rotated tokens/codes stay redacted.
    const hist = historicalSecrets.get(missionId);
    if (hist && hist.size > 0) replaceRuntimeSecretSource(source, hist);
    else clearRuntimeSecretSource(source);
    return;
  }
  let hist = historicalSecrets.get(missionId);
  if (!hist) {
    hist = new Set();
    historicalSecrets.set(missionId, hist);
  }
  for (const p of bucket.principals.values()) {
    for (const v of collectSecrets(p)) {
      if (v && v.length >= 6) hist.add(v);
    }
  }
  replaceRuntimeSecretSource(source, hist);
}

function headerNamesOf(p: StoredPrincipal): string[] {
  const auth = p.auth;
  if (auth.type === 'custom_headers') return Object.keys(auth.headers).map((n) => n.toLowerCase());
  if (auth.type === 'static_bearer' || auth.type === 'http_basic') return ['authorization'];
  if (auth.type === 'api_key') return [auth.headerName.toLowerCase()];
  if (auth.type === 'cookie_session') return ['cookie'];
  if (auth.type === 'oauth2') return ['authorization'];
  return [];
}

function cookieNamesOf(p: StoredPrincipal): string[] {
  return p.auth.type === 'cookie_session' ? Object.keys(p.auth.cookies) : [];
}

function toPublic(p: StoredPrincipal): PrincipalPublic {
  const oauthMeta = p.auth.type === 'oauth2'
    ? {
        flow: p.auth.flow,
        authorizationUrl: p.auth.authorizationUrl,
        tokenUrl: p.auth.tokenUrl,
        refreshUrl: p.auth.refreshUrl,
        clientId: p.auth.clientId,
        audience: p.auth.audience,
        redirectUri: p.auth.redirectUri,
        tokenType: p.oauth?.tokenType,
        expiresAt: p.oauth?.expiresAt ? new Date(p.oauth.expiresAt).toISOString() : undefined,
        hasRefreshToken: !!p.oauth?.refreshToken,
        scopes: (p.oauth?.scope && p.oauth.scope.length > 0) ? p.oauth.scope : p.auth.scopes,
      }
    : undefined;
  return {
    id: p.id,
    label: p.label,
    roleHint: p.roleHint,
    origin: p.origin,
    default: p.default,
    authMethod: p.auth.type,
    runtimeStatus: p.runtimeStatus,
    headerNames: headerNamesOf(p),
    cookieNames: cookieNamesOf(p),
    lastStatusAt: p.lastStatusAt,
    lastError: p.lastError,
    oauth: oauthMeta,
  };
}

function validateAuth(auth: AuthProfileWrite): string | null {
  if (!auth || typeof auth !== 'object' || !('type' in auth)) return 'auth.type is required';
  switch (auth.type) {
    case 'custom_headers': {
      if (!auth.headers || typeof auth.headers !== 'object' || Array.isArray(auth.headers)) return 'custom_headers.headers must be an object';
      const entries = Object.entries(auth.headers);
      if (entries.length === 0) return 'custom_headers.headers must not be empty';
      for (const [name, value] of entries) {
        if (typeof value !== 'string' || FORBIDDEN_AUTH_HEADERS.has(name.toLowerCase())) return 'invalid or forbidden header';
      }
      return null;
    }
    case 'static_bearer':
      return typeof auth.token === 'string' && auth.token.length > 0 ? null : 'static_bearer.token is required';
    case 'api_key':
      if (typeof auth.headerName !== 'string' || !auth.headerName.trim()) return 'api_key.headerName is required';
      if (typeof auth.value !== 'string' || !auth.value) return 'api_key.value is required';
      if (FORBIDDEN_AUTH_HEADERS.has(auth.headerName.toLowerCase())) return 'invalid or forbidden header';
      if (auth.location === 'query') return 'query_api_key_unsupported';
      if (auth.location && auth.location !== 'header') return 'api_key.location must be header';
      return null;
    case 'http_basic':
      if (typeof auth.username !== 'string' || !auth.username) return 'http_basic.username is required';
      if (typeof auth.password !== 'string' || !auth.password) return 'http_basic.password is required';
      return null;
    case 'cookie_session': {
      if (!auth.cookies || typeof auth.cookies !== 'object' || Array.isArray(auth.cookies)) return 'cookie_session.cookies must be an object';
      const entries = Object.entries(auth.cookies);
      if (entries.length === 0) return 'cookie_session.cookies must not be empty';
      for (const [, value] of entries) {
        if (typeof value !== 'string') return 'cookie values must be strings';
      }
      return null;
    }
    case 'oauth2':
      if (!auth.flow) return 'oauth2.flow is required';
      if (typeof auth.tokenUrl !== 'string' || !auth.tokenUrl) return 'oauth2.tokenUrl is required';
      return null;
    default:
      return 'unsupported auth type';
  }
}

function initialStatus(auth: AuthProfileWrite): PrincipalRuntimeStatus {
  if (auth.type === 'oauth2') return 'unknown';
  return 'live';
}

/** Register extra runtime secrets (e.g. a submitted authorization code) into the mission source. */
export function registerMissionSecretValues(missionId: string, values: Iterable<string>): void {
  if (!missionId) return;
  let hist = historicalSecrets.get(missionId);
  if (!hist) {
    hist = new Set();
    historicalSecrets.set(missionId, hist);
  }
  for (const v of values) {
    if (v && v.length >= 6) hist.add(v);
  }
  syncMissionSecrets(missionId);
}

export function putPrincipals(missionId: string, writes: PrincipalWrite[]): { ok: true; principals: PrincipalPublic[] } | { ok: false; error: string } {
  if (!missionId) return { ok: false, error: 'missionId is required' };
  if (!Array.isArray(writes)) return { ok: false, error: 'principals must be an array' };
  if (writes.length === 0) {
    missions.delete(missionId);
    syncMissionSecrets(missionId);
    return { ok: true, principals: [] };
  }
  if (writes.length > MAX_PRINCIPALS_PER_MISSION) return { ok: false, error: `at most ${MAX_PRINCIPALS_PER_MISSION} principals per mission` };

  const next = new Map<string, StoredPrincipal>();
  let defaultId: string | undefined;
  for (const w of writes) {
    if (!w || typeof w.label !== 'string' || !w.label.trim()) return { ok: false, error: 'each principal needs a label' };
    const origin = normalizeHttpOrigin(w.origin);
    if (!origin) return { ok: false, error: 'each principal needs an exact http(s) origin' };
    const authErr = validateAuth(w.auth);
    if (authErr === 'query_api_key_unsupported') return { ok: false, error: 'query_api_key_unsupported' };
    if (authErr) return { ok: false, error: authErr };
    const id = (typeof w.id === 'string' && w.id.trim()) ? w.id.trim() : `principal-${randomUUID().slice(0, 8)}`;
    if (next.has(id)) return { ok: false, error: `duplicate principal id ${id}` };
    const stored: StoredPrincipal = {
      id,
      label: w.label.trim(),
      roleHint: typeof w.roleHint === 'string' ? w.roleHint.trim() || undefined : undefined,
      origin,
      default: !!w.default,
      auth: w.auth,
      runtimeStatus: initialStatus(w.auth),
      lastStatusAt: new Date().toISOString(),
    };
    next.set(id, stored);
    if (stored.default) defaultId = id;
  }
  if (next.size === 1 && !defaultId) {
    const only = [...next.values()][0];
    only.default = true;
    defaultId = only.id;
  }

  missions.set(missionId, { defaultPrincipalId: defaultId, principals: next });
  syncMissionSecrets(missionId);
  return { ok: true, principals: [...next.values()].map(toPublic) };
}

export function upsertLegacyHeadersPrincipal(missionId: string, origin: string, headers: Record<string, string>): PrincipalPublic | null {
  const normalized = normalizeHttpOrigin(origin);
  if (!normalized || !headers || Object.keys(headers).length === 0) return null;
  const existing = missions.get(missionId);
  const writes: PrincipalWrite[] = [];
  if (existing) {
    for (const p of existing.principals.values()) {
      if (p.id === 'legacy-headers') continue;
      writes.push({
        id: p.id,
        label: p.label,
        roleHint: p.roleHint,
        origin: p.origin,
        default: p.default,
        auth: p.auth,
      });
    }
  }
  writes.unshift({
    id: 'legacy-headers',
    label: 'Request Headers',
    origin: normalized,
    default: writes.length === 0 || writes.every((w) => !w.default),
    auth: { type: 'custom_headers', headers },
  });
  const result = putPrincipals(missionId, writes);
  return result.ok ? result.principals.find((p) => p.id === 'legacy-headers') ?? null : null;
}

export function deletePrincipal(missionId: string, principalId: string): boolean {
  const bucket = missions.get(missionId);
  if (!bucket || !bucket.principals.has(principalId)) return false;
  bucket.principals.delete(principalId);
  if (bucket.defaultPrincipalId === principalId) {
    bucket.defaultPrincipalId = bucket.principals.size === 1
      ? [...bucket.principals.keys()][0]
      : undefined;
    if (bucket.defaultPrincipalId) {
      const d = bucket.principals.get(bucket.defaultPrincipalId);
      if (d) d.default = true;
    }
  }
  if (bucket.principals.size === 0) missions.delete(missionId);
  syncMissionSecrets(missionId);
  return true;
}

export function listPrincipals(missionId: string): PrincipalPublic[] {
  const bucket = missions.get(missionId);
  if (!bucket) return [];
  return [...bucket.principals.values()].map(toPublic);
}

export function getStoredPrincipal(missionId: string, principalId: string): StoredPrincipal | undefined {
  return missions.get(missionId)?.principals.get(principalId);
}

export function missionPrincipalCount(missionId: string): number {
  return missions.get(missionId)?.principals.size ?? 0;
}

export function anyMissionHasMultiplePrincipals(): boolean {
  for (const bucket of missions.values()) {
    if (bucket.principals.size >= 2) return true;
  }
  return false;
}

export function teardownMissionPrincipals(missionId: string): void {
  missions.delete(missionId);
  historicalSecrets.delete(missionId);
  clearRuntimeSecretSource(principalSecretSourceId(missionId));
}

export function teardownAllPrincipals(): void {
  const ids = new Set([...missions.keys(), ...historicalSecrets.keys()]);
  missions.clear();
  historicalSecrets.clear();
  for (const id of ids) clearRuntimeSecretSource(principalSecretSourceId(id));
}

export function setPrincipalOauthMaterial(missionId: string, principalId: string, patch: Partial<OAuthRuntimeMaterial> & { runtimeStatus?: PrincipalRuntimeStatus; lastError?: string }): boolean {
  const p = getStoredPrincipal(missionId, principalId);
  if (!p || p.auth.type !== 'oauth2') return false;
  p.oauth = { ...(p.oauth || {}), ...patch };
  for (const [key, value] of Object.entries(patch)) {
    if (value === undefined && p.oauth && key in p.oauth) {
      delete (p.oauth as Record<string, unknown>)[key];
    }
  }
  if (patch.runtimeStatus) p.runtimeStatus = patch.runtimeStatus;
  if (patch.lastError !== undefined) p.lastError = patch.lastError;
  p.lastStatusAt = new Date().toISOString();
  syncMissionSecrets(missionId);
  return true;
}

export function missionAuthSnapshot(missionId?: string): {
  present: boolean;
  origin: string | null;
  headerNames: string[];
  headerCount: number;
  principalCount: number;
} {
  if (!missionId) {
    return { present: false, origin: null, headerNames: [], headerCount: 0, principalCount: 0 };
  }
  const principals = listPrincipals(missionId);
  const headerNames = [...new Set(principals.flatMap((p) => p.headerNames))];
  const defaultOrFirst = principals.find((p) => p.default) ?? principals[0];
  return {
    present: principals.length > 0,
    origin: defaultOrFirst?.origin ?? null,
    headerNames,
    headerCount: headerNames.length,
    principalCount: principals.length,
  };
}

export function preflightPrincipalSelection(missionId: string | undefined, authMode: unknown, principalId: unknown): AuthValidationFailure | null {
  const requested = typeof principalId === 'string' && principalId.trim() ? principalId.trim() : '';
  if (requested) {
    if (!missionId) return { ok: false, code: 'unknown_principal', principalIds: [] };
    const selected = selectPrincipal(missionId, requested);
    return selected.ok ? null : selected;
  }
  if (authMode === 'none') return null;
  if (!missionId) return null;
  const count = missionPrincipalCount(missionId);
  if (count < 2) return null;
  const selected = selectPrincipal(missionId, undefined);
  return selected.ok ? null : selected;
}

/** True when an OAuth principal has usable LIVE material (hard expiry, no skew). */
export function oauthHeadersAttachable(p: StoredPrincipal): boolean {
  if (p.auth.type !== 'oauth2') return false;
  if (p.runtimeStatus !== 'live') return false;
  const token = p.oauth?.accessToken;
  const tokenType = p.oauth?.tokenType;
  if (!token || !tokenType || tokenType.toLowerCase() !== 'bearer') return false;
  const exp = p.oauth?.expiresAt;
  if (exp && Date.now() >= exp) return false;
  return true;
}

export function compilePrincipalHeaders(p: StoredPrincipal): Headers | null {
  const headers = new Headers();
  const auth = p.auth;
  if (auth.type === 'custom_headers') {
    for (const [name, value] of Object.entries(auth.headers)) headers.set(name, value);
  } else if (auth.type === 'static_bearer') {
    headers.set('authorization', `Bearer ${auth.token}`);
  } else if (auth.type === 'api_key') {
    if (auth.location === 'query') return null;
    headers.set(auth.headerName, auth.value);
  } else if (auth.type === 'http_basic') {
    headers.set('authorization', `Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString('base64')}`);
  } else if (auth.type === 'cookie_session') {
    const cookie = Object.entries(auth.cookies).map(([k, v]) => `${k}=${v}`).join('; ');
    headers.set('cookie', cookie);
  } else if (auth.type === 'oauth2') {
    if (!oauthHeadersAttachable(p)) return null;
    headers.set('authorization', `Bearer ${p.oauth!.accessToken!}`);
  }
  return headers.keys().next().done ? null : headers;
}

export function selectPrincipal(missionId: string, principalId: unknown): { ok: true; principal: StoredPrincipal } | AuthValidationFailure {
  const bucket = missions.get(missionId);
  const ids = bucket ? [...bucket.principals.keys()] : [];
  const requested = typeof principalId === 'string' && principalId.trim() ? principalId.trim() : '';

  if (requested) {
    const p = bucket?.principals.get(requested);
    if (!p) return { ok: false, code: 'unknown_principal', principalIds: ids };
    return { ok: true, principal: p };
  }

  const count = bucket?.principals.size ?? 0;
  if (count === 0) return { ok: false, code: 'unknown_principal', principalIds: [] };
  if (count === 1) return { ok: true, principal: [...bucket!.principals.values()][0] };
  if (bucket?.defaultPrincipalId) {
    const d = bucket.principals.get(bucket.defaultPrincipalId);
    if (d) return { ok: true, principal: d };
  }
  return { ok: false, code: 'principal_id_required', principalIds: ids };
}
