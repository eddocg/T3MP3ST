/**
 * Resolve request authentication from ToolContext.mission + principalId + authMode.
 * Never uses a process-global active-mission selector.
 */

import type { ToolContext } from '../types/index.js';
import {
  anyMissionHasMultiplePrincipals,
  compilePrincipalHeaders,
  listPrincipals,
  oauthHeadersAttachable,
  selectPrincipal,
} from './store.js';
import type { AuthValidationFailure, PrincipalRuntimeStatus } from './types.js';
import { validationToolError } from './types.js';

export type AuthMode = 'inherit' | 'none';
export const AUTH_MODES: readonly AuthMode[] = ['inherit', 'none'];

export interface ResolvedAuth {
  ok: true;
  authMode: AuthMode;
  headers?: Headers;
  applied: boolean;
  principalId?: string;
  authStatusAtRequest?: PrincipalRuntimeStatus;
  oauthAttached?: boolean;
}

export type AuthResolveResult = ResolvedAuth | AuthValidationFailure;

export function parseAuthMode(value: unknown): { ok: true; mode: AuthMode } | AuthValidationFailure {
  if (value === undefined || value === null || value === '') return { ok: true, mode: 'inherit' };
  if (value === 'inherit' || value === 'none') return { ok: true, mode: value };
  return { ok: false, code: 'invalid_auth_mode', allowedValues: [...AUTH_MODES] };
}

/**
 * Legacy 0–1 header map supplied by the arsenal singleton. Injected to avoid a store→arsenal cycle.
 */
let legacyHeadersForUrl: ((url: string | URL, authMode: AuthMode) => Headers | undefined) | null = null;

export function setLegacyHeaderProvider(
  provider: ((url: string | URL, authMode: AuthMode) => Headers | undefined) | null,
): void {
  legacyHeadersForUrl = provider;
}

export function resolveRequestAuth(context: ToolContext | undefined, url: string | URL): AuthResolveResult {
  const parsed = parseAuthMode(context?.parameters?.authMode);
  if (!parsed.ok) return parsed;
  const authMode = parsed.mode;
  if (authMode === 'none') return { ok: true, authMode, applied: false };

  const missionId = typeof context?.mission === 'string' && context.mission ? context.mission : '';
  const principalId = context?.parameters?.principalId;

  if (missionId) {
    const principals = listPrincipals(missionId);
    // Principal-aware mission: the store is the only authority. An empty store
    // attaches nothing — never the process-global legacy header singleton.
    if (principals.length === 0) {
      return { ok: true, authMode, applied: false };
    }
    const selected = selectPrincipal(missionId, principalId);
    if (!selected.ok) return selected;
    try {
      if (new URL(url).origin !== selected.principal.origin) {
        return {
          ok: true,
          authMode,
          applied: false,
          principalId: selected.principal.id,
          authStatusAtRequest: selected.principal.runtimeStatus,
        };
      }
    } catch {
      return {
        ok: true,
        authMode,
        applied: false,
        principalId: selected.principal.id,
        authStatusAtRequest: selected.principal.runtimeStatus,
      };
    }
    if (selected.principal.auth.type === 'oauth2' && !oauthHeadersAttachable(selected.principal)) {
      return {
        ok: false,
        code: 'oauth_not_live',
        principalIds: [selected.principal.id],
        runtimeStatus: selected.principal.runtimeStatus,
      };
    }
    const headers = compilePrincipalHeaders(selected.principal);
    const oauthAttached = selected.principal.auth.type === 'oauth2' && !!headers && headers.has('authorization');
    return {
      ok: true,
      authMode,
      headers: headers ?? undefined,
      applied: !!headers && [...headers.keys()].length > 0,
      principalId: selected.principal.id,
      authStatusAtRequest: selected.principal.runtimeStatus,
      oauthAttached,
    };
  }

  // No mission on the tool context: legacy 0–1 anonymous header path only.
  // If any mission already has 2+ principals, do not silently pick among them.
  if (anyMissionHasMultiplePrincipals()) {
    return { ok: true, authMode, applied: false };
  }
  const legacy = legacyHeadersForUrl?.(url, authMode);
  return {
    ok: true,
    authMode,
    headers: legacy,
    applied: !!legacy && [...legacy.keys()].length > 0,
  };
}

export function mergeExplicitHeaders(configured: Headers | undefined, explicit?: RequestInit['headers']): Headers | undefined {
  const merged = new Headers();
  if (configured) configured.forEach((value, name) => merged.set(name, value));
  new Headers(explicit).forEach((value, name) => merged.set(name, value));
  return merged.keys().next().done ? undefined : merged;
}

export function authValidationResult(failure: AuthValidationFailure): { success: false; error: string } {
  return { success: false, error: validationToolError(failure) };
}
