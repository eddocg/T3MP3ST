import type { OAuth2AuthWrite } from '../types.js';

export function resolvedGrantType(auth: OAuth2AuthWrite): string {
  const raw = (auth.grantType || auth.flow || '').trim();
  if (raw === 'authorization_code_pkce') return 'authorization_code';
  return raw;
}

export function publicGrantType(auth: OAuth2AuthWrite): string {
  const grant = resolvedGrantType(auth);
  if (grant === 'authorization_code' && (auth.pkce || auth.flow === 'authorization_code_pkce')) {
    return 'authorization_code_pkce';
  }
  return grant || 'client_credentials';
}

export function usesPkce(auth: OAuth2AuthWrite): boolean {
  return !!auth.pkce || auth.flow === 'authorization_code_pkce' || auth.grantType === 'authorization_code_pkce';
}

export function resolvedClientAuth(auth: OAuth2AuthWrite): string {
  const raw = (auth.clientAuth || '').trim();
  if (raw === 'basic') return 'client_secret_basic';
  if (raw === 'body') return 'client_secret_post';
  if (raw) return raw;
  return auth.clientSecret ? 'client_secret_post' : 'none';
}

export function normalizeResourceList(value: unknown): string[] {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.filter((v): v is string => typeof v === 'string' && v.length > 0);
  }
  if (typeof value === 'string' && value.trim()) return [value.trim()];
  return [];
}

export function applyResources(body: URLSearchParams, resources: string[] | undefined): void {
  if (!resources?.length) return;
  for (const resource of resources) {
    if (resource) body.append('resource', resource);
  }
}
