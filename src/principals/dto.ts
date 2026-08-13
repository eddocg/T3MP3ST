/**
 * Explicit metadata-only public DTOs for principal/OAuth HTTP responses.
 * Secret fields never enter these objects. Callers must serialize these
 * directly — do not wrap them in key-name redactSecrets (that would blank
 * safe fields such as authorizationUrl / tokenUrl / tokenType).
 */

import { listPrincipals } from './store.js';
import type { OAuthAcquireResult, OpenApiOAuthSuggestion } from './oauth.js';
import type { PrincipalPublic } from './types.js';

const PUBLIC_OAUTH_KEYS = [
  'flow',
  'authorizationUrl',
  'tokenUrl',
  'refreshUrl',
  'clientId',
  'scopes',
  'audience',
  'redirectUri',
  'tokenType',
  'expiresAt',
  'hasRefreshToken',
] as const;

function publicOAuth(oauth: PrincipalPublic['oauth']): PrincipalPublic['oauth'] | undefined {
  if (!oauth) return undefined;
  const out: NonNullable<PrincipalPublic['oauth']> = {
    flow: oauth.flow,
    hasRefreshToken: !!oauth.hasRefreshToken,
  };
  if (oauth.authorizationUrl) out.authorizationUrl = oauth.authorizationUrl;
  if (oauth.tokenUrl) out.tokenUrl = oauth.tokenUrl;
  if (oauth.refreshUrl) out.refreshUrl = oauth.refreshUrl;
  if (oauth.clientId) out.clientId = oauth.clientId;
  if (oauth.scopes) out.scopes = oauth.scopes;
  if (oauth.audience) out.audience = oauth.audience;
  if (oauth.redirectUri) out.redirectUri = oauth.redirectUri;
  if (oauth.tokenType) out.tokenType = oauth.tokenType;
  if (oauth.expiresAt) out.expiresAt = oauth.expiresAt;
  return out;
}

/** Copy only the documented public principal fields. */
export function publicPrincipalDto(p: PrincipalPublic): PrincipalPublic {
  return {
    id: p.id,
    label: p.label,
    roleHint: p.roleHint,
    origin: p.origin,
    default: p.default,
    authMethod: p.authMethod,
    runtimeStatus: p.runtimeStatus,
    headerNames: [...p.headerNames],
    cookieNames: [...p.cookieNames],
    lastStatusAt: p.lastStatusAt,
    lastError: p.lastError,
    oauth: publicOAuth(p.oauth),
  };
}

export function principalsListBody(missionId: string | null): { principals: PrincipalPublic[] } {
  return { principals: missionId ? listPrincipals(missionId).map(publicPrincipalDto) : [] };
}

export function oauthActionBody(result: OAuthAcquireResult): Record<string, unknown> {
  if (!result.ok) {
    if (result.error) {
      try {
        const parsed = JSON.parse(result.error) as Record<string, unknown>;
        return {
          error: true,
          category: parsed.category ?? 'validation_error',
          code: result.code ?? parsed.code,
          message: parsed.message,
        };
      } catch {
        /* fall through */
      }
    }
    return { error: true, code: result.code ?? 'malformed_token_response' };
  }
  const body: Record<string, unknown> = {};
  if (result.principal) body.principal = publicPrincipalDto(result.principal);
  if (result.authorizationUrl) body.authorizationUrl = result.authorizationUrl;
  return body;
}

export function oauthImportBody(suggestions: OpenApiOAuthSuggestion[]): { suggestions: OpenApiOAuthSuggestion[] } {
  return {
    suggestions: suggestions.map((s) => ({
      schemeName: s.schemeName,
      type: s.type,
      flow: s.flow,
      authorizationUrl: s.authorizationUrl,
      tokenUrl: s.tokenUrl,
      refreshUrl: s.refreshUrl,
      scopes: s.scopes,
    })),
  };
}

export { PUBLIC_OAUTH_KEYS };
