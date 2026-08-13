import type { ClientAuthAdapter } from '../contracts.js';
import { resolvedClientAuth } from '../normalize.js';

export const noneClientAuth: ClientAuthAdapter = {
  method: 'none',
  fields: () => [],
  reservedTokenParams: () => ['client_id'],
  validate: () => ({ ok: true }),
  projectPublic: (p) => (p.auth.type === 'oauth2' ? { clientAuth: resolvedClientAuth(p.auth) } : {}),
  apply: (ctx, body) => {
    if (ctx.principal.auth.type === 'oauth2' && ctx.principal.auth.clientId) {
      body.set('client_id', ctx.principal.auth.clientId);
    }
    return {};
  },
};
