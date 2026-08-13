/**
 * OAuth2 runtime — grant + client-auth adapter registry and engine re-exports.
 * Token HTTP is ScopeGuard-gated. Adapters never call fetch.
 */

import { ensureOAuthAdaptersRegistered, setAdapterBootstrap, registerGrant, registerClientAuth } from './oauth/registry.js';
import { noneClientAuth } from './oauth/clientAuth/none.js';
import { basicClientAuth } from './oauth/clientAuth/basic.js';
import { postClientAuth } from './oauth/clientAuth/post.js';
import { clientCredentialsGrant } from './oauth/grants/client-credentials.js';
import { authorizationCodeGrant } from './oauth/grants/authorization-code.js';
import { passwordGrant } from './oauth/grants/password.js';
import { extensionGrant } from './oauth/grants/extension.js';
import { refreshBootstrapGrant } from './oauth/grants/refresh-bootstrap.js';

setAdapterBootstrap(() => {
  registerClientAuth(noneClientAuth);
  registerClientAuth(basicClientAuth);
  registerClientAuth(postClientAuth);
  registerGrant(clientCredentialsGrant);
  registerGrant(authorizationCodeGrant);
  registerGrant(passwordGrant);
  registerGrant(extensionGrant);
  registerGrant(refreshBootstrapGrant);
});

ensureOAuthAdaptersRegistered();

export {
  acquireOAuth,
  refreshOAuth,
  exchangeOAuthCode,
  ensureOAuthAccess,
  buildAuthorizationUrl,
  setOAuthScopedHttp,
  isExpired,
  EXPIRY_SKEW_MS,
  type OAuthAcquireResult,
  type ScopedHttp,
  type ScopeLike,
} from './oauth/engine.js';

export {
  importOAuthFromOpenApi,
  fetchOAuthDiscovery,
  type OpenApiOAuthSuggestion,
  type OAuthDiscoverySuggestion,
} from './oauth/discovery.js';
