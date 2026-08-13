import type { ClientAuthAdapter } from '../contracts.js';
import { resolvedClientAuth } from '../normalize.js';

export const postClientAuth: ClientAuthAdapter = {
  method: 'client_secret_post',
  fields: () => [
    { name: 'clientSecret', secret: true, tokenAffecting: true, writeOnly: true },
  ],
  reservedTokenParams: () => ['client_id', 'client_secret'],
  validate: () => ({ ok: true }),
  projectPublic: (p) => (p.auth.type === 'oauth2' ? { clientAuth: resolvedClientAuth(p.auth) } : {}),
  apply: (ctx, body) => {
    if (ctx.principal.auth.type !== 'oauth2') return {};
    const id = ctx.principal.auth.clientId || '';
    const secret = (typeof ctx.principal.auth.clientSecret === 'string' ? ctx.principal.auth.clientSecret : '')
      || ctx.principal.oauth?.clientSecret
      || '';
    if (id) body.set('client_id', id);
    if (secret) body.set('client_secret', secret);
    return {};
  },
};
