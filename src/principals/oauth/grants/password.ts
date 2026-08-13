import type { GrantAdapter } from '../contracts.js';
import { applyResources } from '../normalize.js';
import { classifyStandardOAuthError } from '../errors.js';

export const passwordGrant: GrantAdapter = {
  grantType: 'password',
  fields: () => [
    { name: 'tokenUrl', secret: false, tokenAffecting: true },
    { name: 'username', secret: false, tokenAffecting: true },
    { name: 'password', secret: true, tokenAffecting: true, writeOnly: true },
    { name: 'scopes', secret: false, tokenAffecting: true },
    { name: 'resource', secret: false, tokenAffecting: true },
    { name: 'audience', secret: false, tokenAffecting: true },
    { name: 'extraTokenParams', secret: false, tokenAffecting: true },
  ],
  reservedTokenParams: () => ['grant_type', 'username', 'password', 'scope', 'resource', 'audience'],
  validate: (write) => {
    if (typeof write.tokenUrl !== 'string' || !write.tokenUrl) return { ok: false, code: 'tokenUrl is required' };
    if (typeof write.username !== 'string' || !write.username) return { ok: false, code: 'username is required' };
    return { ok: true };
  },
  projectPublic: (p) => {
    if (p.auth.type !== 'oauth2') return {};
    return {
      grantType: 'password',
      tokenUrl: p.auth.tokenUrl,
      scopes: p.auth.scopes,
      resource: p.auth.resource,
      audience: p.auth.audience,
    };
  },
  classifyError: classifyStandardOAuthError,
  canRepeatNonInteractive: (p) => {
    if (p.auth.type !== 'oauth2') return false;
    return !!p.auth.username && typeof p.auth.password === 'string' && p.auth.password.length > 0;
  },
  renewalCapability: (p) => (passwordGrant.canRepeatNonInteractive(p) ? 'automatic' : 'unavailable'),
  acquire: ({ principal }) => {
    if (principal.auth.type !== 'oauth2') return { ok: false, code: 'malformed_token_response' };
    const url = principal.auth.tokenUrl;
    if (!url) return { ok: false, code: 'malformed_token_response' };
    if (!principal.auth.username || typeof principal.auth.password !== 'string' || !principal.auth.password) {
      return { ok: false, code: 'malformed_token_response' };
    }
    const body = new URLSearchParams();
    body.set('grant_type', 'password');
    body.set('username', principal.auth.username);
    body.set('password', principal.auth.password);
    if (principal.auth.scopes?.length) body.set('scope', principal.auth.scopes.join(' '));
    applyResources(body, principal.auth.resource);
    if (principal.auth.audience) body.set('audience', principal.auth.audience);
    return { url, body };
  },
};
