import type { AuthValidationCode } from '../types.js';
import type { OAuthPhase } from './contracts.js';

export function oauthErrorFromJson(json: unknown): string | undefined {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return undefined;
  const err = (json as Record<string, unknown>).error;
  return typeof err === 'string' ? err : undefined;
}

export function classifyStandardOAuthError(
  _phase: OAuthPhase,
  tokenJson: unknown,
  httpStatus: number,
): AuthValidationCode | null {
  const err = oauthErrorFromJson(tokenJson);
  if (err === 'invalid_grant') return 'oauth_invalid_grant';
  if (err === 'invalid_client') return 'oauth_invalid_client';
  if (err === 'unauthorized_client') return 'oauth_unauthorized_client';
  if (err === 'unsupported_grant_type') return 'oauth_unsupported_grant';
  if (httpStatus >= 300 && httpStatus < 400) return 'oauth_unexpected_redirect';
  return null;
}
