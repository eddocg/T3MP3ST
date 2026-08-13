import type { OpenApiSecurityScheme } from '../../surface/openapi.js';
import type { ScopeLike } from './contracts.js';
import { scopedMetadataGet } from './http.js';

export interface OpenApiOAuthSuggestion {
  schemeName: string;
  flow?: string;
  grantType?: string;
  authorizationUrl?: string;
  tokenUrl?: string;
  refreshUrl?: string;
  scopes?: string[];
  type: string;
  legacy?: boolean;
}

export interface OAuthDiscoverySuggestion {
  issuer?: string;
  authorizationUrl?: string;
  tokenUrl?: string;
  refreshUrl?: string;
  grantTypesSupported?: string[];
  tokenEndpointAuthMethodsSupported?: string[];
  codeChallengeMethodsSupported?: string[];
  scopes?: string[];
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

const FLOW_TO_GRANT: Record<string, string> = {
  authorizationCode: 'authorization_code',
  clientCredentials: 'client_credentials',
  password: 'password',
  implicit: 'implicit',
};

export function importOAuthFromOpenApi(
  schemes: OpenApiSecurityScheme[],
  sourceOrigin?: string,
): OpenApiOAuthSuggestion[] {
  return schemes
    .filter((s) => s && (s.type === 'oauth2' || s.authorizationUrl || s.tokenUrl || (s.flows && s.flows.length)))
    .map((s) => {
      const flow = s.flows?.[0];
      const grantType = flow ? FLOW_TO_GRANT[flow] || flow : undefined;
      return {
        schemeName: s.name,
        type: s.type,
        flow,
        grantType,
        authorizationUrl: resolveAgainstSource(s.authorizationUrl, sourceOrigin),
        tokenUrl: resolveAgainstSource(s.tokenUrl, sourceOrigin),
        refreshUrl: resolveAgainstSource(s.refreshUrl, sourceOrigin),
        scopes: s.scopes,
        legacy: grantType === 'implicit' || grantType === 'password' || flow === 'implicit' || flow === 'password',
      };
    });
}

function asStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out = value.filter((v): v is string => typeof v === 'string' && v.length > 0);
  return out.length ? out : undefined;
}

export async function fetchOAuthDiscovery(
  metadataUrl: string,
  scope: ScopeLike,
): Promise<{ ok: true; suggestion: OAuthDiscoverySuggestion } | { ok: false; code: string }> {
  try {
    const posted = await scopedMetadataGet(metadataUrl, scope);
    if (!posted.json || typeof posted.json !== 'object' || Array.isArray(posted.json)) {
      return { ok: false, code: 'malformed_token_response' };
    }
    const obj = posted.json as Record<string, unknown>;
    const suggestion: OAuthDiscoverySuggestion = {
      issuer: typeof obj.issuer === 'string' ? obj.issuer : undefined,
      authorizationUrl: typeof obj.authorization_endpoint === 'string' ? obj.authorization_endpoint : undefined,
      tokenUrl: typeof obj.token_endpoint === 'string' ? obj.token_endpoint : undefined,
      refreshUrl: typeof obj.token_endpoint === 'string' ? obj.token_endpoint : undefined,
      grantTypesSupported: asStringArray(obj.grant_types_supported),
      tokenEndpointAuthMethodsSupported: asStringArray(obj.token_endpoint_auth_methods_supported),
      codeChallengeMethodsSupported: asStringArray(obj.code_challenge_methods_supported),
      scopes: asStringArray(obj.scopes_supported),
    };
    return { ok: true, suggestion };
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === 'oauth_scope_denied') return { ok: false, code: 'oauth_scope_denied' };
    if (code === 'oauth_oversized_response') return { ok: false, code: 'oauth_oversized_response' };
    if (code === 'oauth_unexpected_redirect') return { ok: false, code: 'oauth_unexpected_redirect' };
    return { ok: false, code: 'malformed_token_response' };
  }
}
