import type { GrantAdapter } from '../contracts.js';
import { applyResources } from '../normalize.js';
import { classifyStandardOAuthError } from '../errors.js';

export const clientCredentialsGrant: GrantAdapter = {
  grantType: 'client_credentials',
  fields: () => [
    { name: 'tokenUrl', secret: false, tokenAffecting: true },
    { name: 'scopes', secret: false, tokenAffecting: true },
    { name: 'resource', secret: false, tokenAffecting: true },
    { name: 'audience', secret: false, tokenAffecting: true },
    { name: 'extraTokenParams', secret: false, tokenAffecting: true },
  ],
  reservedTokenParams: () => ['grant_type', 'scope', 'resource', 'audience'],
  validate: (write) => {
    if (typeof write.tokenUrl !== 'string' || !write.tokenUrl) return { ok: false, code: 'tokenUrl is required' };
    return { ok: true };
  },
  projectPublic: (p) => {
    if (p.auth.type !== 'oauth2') return {};
    return {
      grantType: 'client_credentials',
      tokenUrl: p.auth.tokenUrl,
      scopes: p.auth.scopes,
      resource: p.auth.resource,
      audience: p.auth.audience,
    };
  },
  classifyError: classifyStandardOAuthError,
  canRepeatNonInteractive: () => true,
  renewalCapability: () => 'automatic',
  acquire: ({ principal }) => {
    if (principal.auth.type !== 'oauth2') return { ok: false, code: 'malformed_token_response' };
    const url = principal.auth.tokenUrl;
    if (!url) return { ok: false, code: 'malformed_token_response' };
    const body = new URLSearchParams();
    body.set('grant_type', 'client_credentials');
    if (principal.auth.scopes?.length) body.set('scope', principal.auth.scopes.join(' '));
    applyResources(body, principal.auth.resource);
    if (principal.auth.audience) body.set('audience', principal.auth.audience);
    return { url, body };
  },
};
