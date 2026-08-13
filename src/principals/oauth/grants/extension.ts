import type { GrantAdapter } from '../contracts.js';
import { applyResources } from '../normalize.js';
import { classifyStandardOAuthError } from '../errors.js';
import { collidingReservedKeys } from '../reserved.js';

export const extensionGrant: GrantAdapter = {
  grantType: 'extension',
  fields: () => [
    { name: 'tokenUrl', secret: false, tokenAffecting: true },
    { name: 'extensionGrantType', secret: false, tokenAffecting: true },
    { name: 'safeParams', secret: false, tokenAffecting: true },
    { name: 'secretParams', secret: true, tokenAffecting: true, writeOnly: true },
    { name: 'renewalPolicy', secret: false, tokenAffecting: true },
    { name: 'scopes', secret: false, tokenAffecting: true },
    { name: 'resource', secret: false, tokenAffecting: true },
    { name: 'audience', secret: false, tokenAffecting: true },
    { name: 'extraTokenParams', secret: false, tokenAffecting: true },
  ],
  reservedTokenParams: () => ['grant_type', 'scope', 'resource', 'audience'],
  validate: (write) => {
    if (typeof write.tokenUrl !== 'string' || !write.tokenUrl) return { ok: false, code: 'tokenUrl is required' };
    const urn = typeof write.extensionGrantType === 'string' ? write.extensionGrantType : '';
    if (!urn) return { ok: false, code: 'extensionGrantType is required' };
    const collisions = collidingReservedKeys([
      write.safeParams as Record<string, string> | undefined,
      write.secretParams as Record<string, string> | undefined,
      write.extraTokenParams as Record<string, string> | undefined,
    ]);
    if (collisions.length) return { ok: false, code: 'oauth_reserved_parameter_collision' };
    return { ok: true };
  },
  projectPublic: (p) => {
    if (p.auth.type !== 'oauth2') return {};
    return {
      grantType: 'extension',
      tokenUrl: p.auth.tokenUrl,
      extensionGrantType: p.auth.extensionGrantType,
      renewalPolicy: p.auth.renewalPolicy,
      scopes: p.auth.scopes,
      resource: p.auth.resource,
      audience: p.auth.audience,
      safeParams: p.auth.safeParams,
    };
  },
  classifyError: classifyStandardOAuthError,
  canRepeatNonInteractive: (p) => p.auth.type === 'oauth2' && p.auth.renewalPolicy === 'repeat_grant',
  renewalCapability: (p) => {
    if (p.auth.type !== 'oauth2') return 'unavailable';
    if (p.auth.renewalPolicy === 'repeat_grant') return 'automatic';
    if (p.auth.renewalPolicy === 'interactive') return 'interactive';
    return 'unavailable';
  },
  acquire: ({ principal }) => {
    if (principal.auth.type !== 'oauth2') return { ok: false, code: 'malformed_token_response' };
    const url = principal.auth.tokenUrl;
    const urn = principal.auth.extensionGrantType;
    if (!url || !urn) return { ok: false, code: 'malformed_token_response' };
    const collisions = collidingReservedKeys([
      principal.auth.safeParams,
      principal.auth.secretParams && typeof principal.auth.secretParams === 'object' ? principal.auth.secretParams : undefined,
      principal.auth.extraTokenParams,
    ]);
    if (collisions.length) return { ok: false, code: 'oauth_reserved_parameter_collision' };
    const body = new URLSearchParams();
    body.set('grant_type', urn);
    if (principal.auth.scopes?.length) body.set('scope', principal.auth.scopes.join(' '));
    applyResources(body, principal.auth.resource);
    if (principal.auth.audience) body.set('audience', principal.auth.audience);
    if (principal.auth.safeParams) {
      for (const [k, v] of Object.entries(principal.auth.safeParams)) {
        if (k && typeof v === 'string') body.set(k, v);
      }
    }
    const secrets = principal.auth.secretParams;
    if (secrets && typeof secrets === 'object') {
      for (const [k, v] of Object.entries(secrets)) {
        if (k && typeof v === 'string') body.set(k, v);
      }
    }
    return { url, body };
  },
};
