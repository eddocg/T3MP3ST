import type { GrantAdapter } from '../contracts.js';
import { applyResources } from '../normalize.js';
import { classifyStandardOAuthError } from '../errors.js';

/** Compat: flow refresh_token bootstraps with stored refresh material. Refresh itself is lifecycle. */
export const refreshBootstrapGrant: GrantAdapter = {
  grantType: 'refresh_token',
  fields: () => [
    { name: 'tokenUrl', secret: false, tokenAffecting: true },
    { name: 'refreshUrl', secret: false, tokenAffecting: true },
    { name: 'scopes', secret: false, tokenAffecting: true },
    { name: 'resource', secret: false, tokenAffecting: true },
    { name: 'audience', secret: false, tokenAffecting: true },
  ],
  reservedTokenParams: () => ['grant_type', 'refresh_token', 'scope', 'resource', 'audience'],
  validate: (write) => {
    if (typeof write.tokenUrl !== 'string' || !write.tokenUrl) return { ok: false, code: 'tokenUrl is required' };
    return { ok: true };
  },
  projectPublic: (p) => {
    if (p.auth.type !== 'oauth2') return {};
    return {
      grantType: 'refresh_token',
      tokenUrl: p.auth.tokenUrl,
      refreshUrl: p.auth.refreshUrl,
    };
  },
  classifyError: classifyStandardOAuthError,
  canRepeatNonInteractive: (p) => !!p.oauth?.refreshToken && !p.oauth.refreshUnusable,
  renewalCapability: (p) => (p.oauth?.refreshToken && !p.oauth.refreshUnusable ? 'automatic' : 'unavailable'),
  acquire: ({ principal }) => {
    if (principal.auth.type !== 'oauth2') return { ok: false, code: 'malformed_token_response' };
    const refresh = principal.oauth?.refreshToken;
    const url = principal.auth.refreshUrl || principal.auth.tokenUrl;
    if (!refresh || !url) return { ok: false, code: 'malformed_token_response' };
    const body = new URLSearchParams();
    body.set('grant_type', 'refresh_token');
    body.set('refresh_token', refresh);
    applyResources(body, principal.auth.resource);
    if (principal.auth.audience) body.set('audience', principal.auth.audience);
    return { url, body };
  },
};
