/**
 * Principal / AuthProfile types — P2A-core (+ oauth2 discriminant reserved for P2B).
 *
 * Metadata is safe for API/SSE after redaction. Credential material is runtime-only and is
 * never written to state.json (persistence is deferred to optional P2C).
 */

export type PrincipalRuntimeStatus = 'unknown' | 'live' | 'stale' | 'refreshing' | 'failed';

export type OAuth2Flow =
  | 'authorization_code'
  | 'authorization_code_pkce'
  | 'client_credentials'
  | 'refresh_token';

export type OAuth2ClientAuth = 'none' | 'basic' | 'body';

export const FORBIDDEN_AUTH_HEADERS = new Set([
  'connection', 'content-length', 'host', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

export const MAX_PRINCIPALS_PER_MISSION = 16;

export type AuthProfileWrite =
  | { type: 'custom_headers'; headers: Record<string, string> }
  | { type: 'static_bearer'; token: string }
  | { type: 'api_key'; headerName: string; location?: 'header' | 'query'; value: string }
  | { type: 'http_basic'; username: string; password: string }
  | { type: 'cookie_session'; cookies: Record<string, string> }
  | {
      type: 'oauth2';
      flow: OAuth2Flow;
      authorizationUrl?: string;
      tokenUrl: string;
      refreshUrl?: string;
      clientId?: string;
      clientSecret?: string;
      scopes?: string[];
      audience?: string;
      redirectUri?: string;
      extraTokenParams?: Record<string, string>;
      clientAuth?: OAuth2ClientAuth;
      pkce?: boolean;
    };

export interface PrincipalWrite {
  id?: string;
  label: string;
  roleHint?: string;
  origin: string;
  default?: boolean;
  auth: AuthProfileWrite;
}

/** Safe API/SSE view — no credential values. */
export interface PrincipalPublic {
  id: string;
  label: string;
  roleHint?: string;
  origin: string;
  default: boolean;
  authMethod: AuthProfileWrite['type'];
  runtimeStatus: PrincipalRuntimeStatus;
  headerNames: string[];
  cookieNames: string[];
  lastStatusAt?: string;
  lastError?: string;
  oauth?: {
    flow: OAuth2Flow;
    authorizationUrl?: string;
    tokenUrl?: string;
    refreshUrl?: string;
    clientId?: string;
    scopes?: string[];
    audience?: string;
    redirectUri?: string;
    tokenType?: string;
    expiresAt?: string;
    hasRefreshToken: boolean;
  };
}

export type AuthValidationCode =
  | 'invalid_auth_mode'
  | 'principal_id_required'
  | 'unknown_principal'
  | 'oauth_not_supported'
  | 'query_api_key_unsupported'
  | 'unsupported_token_type'
  | 'malformed_token_response'
  | 'oauth_state_mismatch'
  | 'oauth_scope_denied'
  | 'oauth_not_live';

export interface AuthValidationFailure {
  ok: false;
  code: AuthValidationCode;
  allowedValues?: string[];
  principalIds?: string[];
  runtimeStatus?: PrincipalRuntimeStatus;
}

export function principalSecretSourceId(missionId: string): string {
  return `mission:${missionId}:principals`;
}

export function normalizeHttpOrigin(raw: string): string | null {
  try {
    const target = new URL(raw.trim());
    if (!['http:', 'https:'].includes(target.protocol)
      || target.username || target.password
      || target.pathname !== '/' || target.search || target.hash) {
      return null;
    }
    return target.origin;
  } catch {
    return null;
  }
}

export function validationToolError(failure: AuthValidationFailure): string {
  const category = failure.code === 'oauth_not_live' ? 'auth_state' : 'validation_error';
  const payload: Record<string, unknown> = {
    error: true,
    category,
    code: failure.code,
  };
  if (failure.allowedValues) payload.allowedValues = failure.allowedValues;
  if (failure.principalIds) payload.principalIds = failure.principalIds;
  if (failure.runtimeStatus) payload.runtimeStatus = failure.runtimeStatus;
  const messages: Record<AuthValidationCode, string> = {
    invalid_auth_mode: 'invalid authMode — supported values: inherit, none',
    principal_id_required: 'principalId is required when multiple principals are configured and no default is set',
    unknown_principal: 'unknown principalId',
    oauth_not_supported: 'oauth2 principals cannot acquire tokens in this slice',
    query_api_key_unsupported: 'API keys in query strings are not supported',
    unsupported_token_type: 'unsupported OAuth token_type — only Bearer is supported',
    malformed_token_response: 'malformed OAuth token response',
    oauth_state_mismatch: 'OAuth state mismatch — authorization code was not exchanged',
    oauth_scope_denied: 'OAuth token/authorization URL is not in authorized scope',
    oauth_not_live: 'OAuth principal is not LIVE — credentials were not attached (authentication state, not authorization denial)',
  };
  payload.message = messages[failure.code];
  return JSON.stringify(payload);
}
