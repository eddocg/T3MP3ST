import type { ClientAuthAdapter, GrantAdapter } from './contracts.js';

const grants = new Map<string, GrantAdapter>();
const clientAuth = new Map<string, ClientAuthAdapter>();

let bootstrapped = false;
let bootstrap: () => void = () => {};

export function setAdapterBootstrap(fn: () => void): void {
  bootstrap = fn;
}

export function ensureOAuthAdaptersRegistered(): void {
  if (bootstrapped) return;
  bootstrapped = true;
  bootstrap();
}

export function registerGrant(adapter: GrantAdapter): void {
  grants.set(adapter.grantType, adapter);
}

export function registerClientAuth(adapter: ClientAuthAdapter): void {
  clientAuth.set(adapter.method, adapter);
}

export function getGrant(grantType: string): GrantAdapter | undefined {
  ensureOAuthAdaptersRegistered();
  return grants.get(grantType);
}

export function getClientAuth(method: string): ClientAuthAdapter | undefined {
  ensureOAuthAdaptersRegistered();
  return clientAuth.get(method);
}

export function knownGrantTypes(): string[] {
  ensureOAuthAdaptersRegistered();
  return [...grants.keys()];
}
