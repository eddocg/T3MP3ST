/**
 * Principal / AuthProfile types — P2A + P2B.1 OAuth grant/client-auth adapters.
 *
 * Metadata is safe for API/SSE after classification. Credential material is runtime-only and is
 * never written to state.json (persistence is deferred to optional P2C).
 */

export type PrincipalRuntimeStatus = 'unknown' | 'live' | 'stale' | 'refreshing' | 'failed';

/** Compat alias — prefer grantType. */
export type OAuth2Flow =
  | 'authorization_code'
  | 'authorization_code_pkce'
  | 'client_credentials'
  | 'refresh_token'
  | 'password'
  | 'extension';

export type OAuth2ClientAuth =
  | 'none'
  | 'basic'
  | 'body'
  | 'client_secret_basic'
  | 'client_secret_post';

export type OAuthRenewalPolicy = 'repeat_grant' | 'interactive' | 'never';
export type OAuthProof = 'none' | 'dpop' | 'mtls_bound';
export type OAuthRenewalCapability = 'automatic' | 'interactive' | 'unavailable';

export const FORBIDDEN_AUTH_HEADERS = new Set([
  'connection', 'content-length', 'host', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

export const MAX_PRINCIPALS_PER_MISSION = 16;

/** Write-only secret: omit to preserve, null to clear, string to replace (never compare plaintext). */
export type WriteOnlySecret = string | null | undefined;

export interface OAuth2AuthWrite {
  type: 'oauth2';
  grantType?: string;
  flow?: string;
  authorizationUrl?: string;
  tokenUrl: string;
  refreshUrl?: string;
  clientId?: string;
  clientSecret?: WriteOnlySecret;
  username?: string;
  password?: WriteOnlySecret;
  scopes?: string[];
  resource?: string[];
  audience?: string;
  redirectUri?: string;
  extraTokenParams?: Record<string, string>;
  clientAuth?: string;
  pkce?: boolean;
  proof?: OAuthProof;
  extensionGrantType?: string;
  safeParams?: Record<string, string>;
  secretParams?: Record<string, string> | null;
  renewalPolicy?: OAuthRenewalPolicy;
}

export type AuthProfileWrite =
  | { type: 'custom_headers'; headers: Record<string, string> }
  | { type: 'static_bearer'; token: string }
  | { type: 'api_key'; headerName: string; location?: 'header' | 'query'; value: string }
  | { type: 'http_basic'; username: string; password: string }
  | { type: 'cookie_session'; cookies: Record<string, string> }
  | OAuth2AuthWrite;

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
  lastErrorCode?: string;
  authConfigRevision?: number;
  oauth?: {
    flow: string;
    grantType: string;
    clientAuth?: string;
    authorizationUrl?: string;
    tokenUrl?: string;
    refreshUrl?: string;
    clientId?: string;
    scopes?: string[];
    resource?: string[];
    audience?: string;
    redirectUri?: string;
    tokenType?: string;
    expiresAt?: string;
    hasRefreshToken: boolean;
    renewalCapability?: OAuthRenewalCapability;
    pkce?: boolean;
    renewalPolicy?: OAuthRenewalPolicy;
    extensionGrantType?: string;
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
  | 'oauth_not_live'
  | 'oauth_interaction_required'
  | 'oauth_refresh_failed'
  | 'oauth_reacquire_failed'
  | 'oauth_invalid_grant'
  | 'oauth_invalid_client'
  | 'oauth_unauthorized_client'
  | 'oauth_unsupported_grant'
  | 'oauth_unsupported_client_auth'
  | 'oauth_reserved_parameter_collision'
  | 'oauth_assertion_required'
  | 'oauth_device_authorization_required'
  | 'oauth_renewal_budget_exceeded'
  | 'oauth_unexpected_redirect'
  | 'oauth_oversized_response';

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

const AUTH_STATE_CODES = new Set<AuthValidationCode>([
  'oauth_not_live',
  'oauth_interaction_required',
]);

const CODE_MESSAGES: Record<AuthValidationCode, string> = {
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
  oauth_interaction_required: 'OAuth principal requires operator interaction — credentials were not attached (authentication state, not authorization denial)',
  oauth_refresh_failed: 'OAuth refresh failed',
  oauth_reacquire_failed: 'OAuth reacquisition failed',
  oauth_invalid_grant: 'OAuth invalid_grant',
  oauth_invalid_client: 'OAuth invalid_client — configuration must change before retry',
  oauth_unauthorized_client: 'OAuth unauthorized_client — configuration must change before retry',
  oauth_unsupported_grant: 'OAuth unsupported_grant_type — configuration must change before retry',
  oauth_unsupported_client_auth: 'OAuth client authentication method is not supported',
  oauth_reserved_parameter_collision: 'OAuth extra/extension parameter collides with a reserved token parameter',
  oauth_assertion_required: 'OAuth assertion grant requires operator-supplied assertion material',
  oauth_device_authorization_required: 'OAuth device authorization is not available in this slice',
  oauth_renewal_budget_exceeded: 'OAuth renewal attempt budget exceeded',
  oauth_unexpected_redirect: 'OAuth token endpoint returned a redirect — configure the canonical tokenUrl (credentials were not forwarded)',
  oauth_oversized_response: 'OAuth endpoint response exceeded the size bound',
};

export function validationToolError(failure: AuthValidationFailure): string {
  const category = AUTH_STATE_CODES.has(failure.code) ? 'auth_state' : 'validation_error';
  const payload: Record<string, unknown> = {
    error: true,
    category,
    code: failure.code,
    message: CODE_MESSAGES[failure.code],
  };
  if (failure.allowedValues) payload.allowedValues = failure.allowedValues;
  if (failure.principalIds) payload.principalIds = failure.principalIds;
  if (failure.runtimeStatus) payload.runtimeStatus = failure.runtimeStatus;
  return JSON.stringify(payload);
}

export const TERMINAL_OAUTH_CONFIG_CODES: ReadonlySet<AuthValidationCode> = new Set([
  'oauth_invalid_client',
  'oauth_unauthorized_client',
  'oauth_unsupported_grant',
  'oauth_unsupported_client_auth',
]);

export const NO_AUTO_ACQUIRE_CODES: ReadonlySet<AuthValidationCode> = new Set([
  ...TERMINAL_OAUTH_CONFIG_CODES,
  'oauth_invalid_grant',
  'oauth_renewal_budget_exceeded',
]);
