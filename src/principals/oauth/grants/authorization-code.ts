import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { GrantAdapter } from '../contracts.js';
import { applyResources, usesPkce } from '../normalize.js';
import { classifyStandardOAuthError } from '../errors.js';
import type { AuthValidationFailure } from '../../types.js';
import type { StoredPrincipal } from '../../store.js';

function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

function randomToken(bytes = 32): string {
  return b64url(randomBytes(bytes));
}

function pkceChallenge(verifier: string): string {
  return b64url(createHash('sha256').update(verifier).digest());
}

export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export function buildAuthorizationRequest(principal: StoredPrincipal): { url: string; state: string; verifier?: string; challenge?: string } | AuthValidationFailure {
  if (principal.auth.type !== 'oauth2' || !principal.auth.authorizationUrl) {
    return { ok: false, code: 'malformed_token_response' };
  }
  const state = randomToken();
  const params = new URLSearchParams();
  params.set('response_type', 'code');
  if (principal.auth.clientId) params.set('client_id', principal.auth.clientId);
  if (principal.auth.redirectUri) params.set('redirect_uri', principal.auth.redirectUri);
  if (principal.auth.scopes?.length) params.set('scope', principal.auth.scopes.join(' '));
  params.set('state', state);
  let verifier: string | undefined;
  let challenge: string | undefined;
  if (usesPkce(principal.auth)) {
    verifier = randomToken(48);
    challenge = pkceChallenge(verifier);
    params.set('code_challenge', challenge);
    params.set('code_challenge_method', 'S256');
  }
  const url = `${principal.auth.authorizationUrl}${principal.auth.authorizationUrl.includes('?') ? '&' : '?'}${params.toString()}`;
  return { url, state, verifier, challenge };
}

export const authorizationCodeGrant: GrantAdapter = {
  grantType: 'authorization_code',
  fields: () => [
    { name: 'authorizationUrl', secret: false, tokenAffecting: true },
    { name: 'tokenUrl', secret: false, tokenAffecting: true },
    { name: 'redirectUri', secret: false, tokenAffecting: true },
    { name: 'pkce', secret: false, tokenAffecting: true },
    { name: 'scopes', secret: false, tokenAffecting: true },
    { name: 'resource', secret: false, tokenAffecting: true },
    { name: 'audience', secret: false, tokenAffecting: true },
    { name: 'extraTokenParams', secret: false, tokenAffecting: true },
    { name: 'state', secret: true, tokenAffecting: false },
    { name: 'codeVerifier', secret: true, tokenAffecting: false },
    { name: 'authorizationCode', secret: true, tokenAffecting: false },
  ],
  reservedTokenParams: () => ['grant_type', 'code', 'code_verifier', 'redirect_uri', 'scope', 'resource', 'audience'],
  validate: (write) => {
    if (typeof write.tokenUrl !== 'string' || !write.tokenUrl) return { ok: false, code: 'tokenUrl is required' };
    return { ok: true };
  },
  projectPublic: (p) => {
    if (p.auth.type !== 'oauth2') return {};
    return {
      grantType: usesPkce(p.auth) ? 'authorization_code_pkce' : 'authorization_code',
      authorizationUrl: p.auth.authorizationUrl,
      tokenUrl: p.auth.tokenUrl,
      redirectUri: p.auth.redirectUri,
      pkce: usesPkce(p.auth),
      scopes: p.auth.scopes,
      resource: p.auth.resource,
      audience: p.auth.audience,
    };
  },
  classifyError: classifyStandardOAuthError,
  canRepeatNonInteractive: () => false,
  renewalCapability: (p) => (p.oauth?.refreshToken ? 'automatic' : 'interactive'),
  beginInteractive: async ({ principal }) => {
    const built = buildAuthorizationRequest(principal);
    if ('ok' in built && built.ok === false) return built;
    const { url, state, verifier, challenge } = built as { url: string; state: string; verifier?: string; challenge?: string };
    return { authorizationUrl: url, state, verifier, challenge };
  },
  acquire: ({ principal }) => {
    if (principal.auth.type !== 'oauth2') return { ok: false, code: 'malformed_token_response' };
    const url = principal.auth.tokenUrl;
    const code = principal.oauth?.authorizationCode;
    if (!url || !code) return { ok: false, code: 'malformed_token_response' };
    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('code', code);
    if (principal.auth.redirectUri) body.set('redirect_uri', principal.auth.redirectUri);
    if (principal.oauth?.codeVerifier) body.set('code_verifier', principal.oauth.codeVerifier);
    applyResources(body, principal.auth.resource);
    if (principal.auth.audience) body.set('audience', principal.auth.audience);
    return { url, body };
  },
  clearOneUse: (p: StoredPrincipal) => {
    if (p.oauth) {
      delete p.oauth.authorizationCode;
      delete p.oauth.state;
      delete p.oauth.codeVerifier;
      delete p.oauth.codeChallenge;
    }
  },
};
