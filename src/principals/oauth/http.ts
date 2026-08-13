/**
 * ScopeGuard-backed OAuth HTTP. Adapters never fetch.
 *
 * Token POST: redirect:manual, any 3xx → oauth_unexpected_redirect (no credential forwarding).
 * Metadata GET: bounded redirects, ScopeGuard every hop before network.
 */

import { config } from '../../config/index.js';
import type { ScopeLike } from './contracts.js';

export type ScopedHttp = (url: string, init: RequestInit, scope: ScopeLike) => Promise<Response>;

export const MAX_OAUTH_RESPONSE_BYTES = 256_000;
export const MAX_METADATA_REDIRECTS = 5;

let scopedHttp: ScopedHttp = async () => {
  const err = new Error('oauth_scope_denied');
  (err as Error & { code: string }).code = 'oauth_scope_denied';
  throw err;
};

export function setOAuthScopedHttp(fn: ScopedHttp): void {
  scopedHttp = fn;
}

export function getOAuthScopedHttp(): ScopedHttp {
  return scopedHttp;
}

function httpTimeoutMs(): number {
  try {
    return config.getTimeout('httpRequestTimeoutMs').valueMs;
  } catch {
    return 5_000;
  }
}

export function isRedirectStatus(status: number): boolean {
  return status >= 300 && status < 400;
}

export async function readBoundedText(response: Response, maxBytes = MAX_OAUTH_RESPONSE_BYTES): Promise<string> {
  const cl = response.headers.get('content-length');
  if (cl && Number(cl) > maxBytes) {
    const err = new Error('oauth_oversized_response');
    (err as Error & { code: string }).code = 'oauth_oversized_response';
    throw err;
  }
  const text = typeof response.arrayBuffer === 'function'
    ? Buffer.from(await response.arrayBuffer()).toString('utf8')
    : await response.text();
  if (Buffer.byteLength(text) > maxBytes) {
    const err = new Error('oauth_oversized_response');
    (err as Error & { code: string }).code = 'oauth_oversized_response';
    throw err;
  }
  return text;
}

function looksLikeJson(contentType: string | null, text: string): boolean {
  const ct = (contentType || '').toLowerCase();
  if (ct.includes('json')) return true;
  const trimmed = text.trim();
  return trimmed.startsWith('{') || trimmed.startsWith('[');
}

export async function scopedTokenPost(
  url: string,
  body: URLSearchParams,
  extraHeaders: Record<string, string>,
  scope: ScopeLike,
): Promise<{ status: number; json: unknown; text: string; location?: string }> {
  const response = await scopedHttp(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
      ...extraHeaders,
    },
    body: body.toString(),
    redirect: 'manual',
    signal: AbortSignal.timeout(httpTimeoutMs()),
  }, scope);
  if (isRedirectStatus(response.status)) {
    return { status: response.status, json: null, text: '', location: response.headers.get('location') || undefined };
  }
  const text = await readBoundedText(response);
  let json: unknown = null;
  if (looksLikeJson(response.headers.get('content-type'), text)) {
    try { json = JSON.parse(text); } catch { json = null; }
  }
  return { status: response.status, json, text };
}

export async function scopedMetadataGet(
  url: string,
  scope: ScopeLike,
): Promise<{ status: number; json: unknown; text: string }> {
  let current = url;
  for (let hop = 0; hop <= MAX_METADATA_REDIRECTS; hop++) {
    const response = await scopedHttp(current, {
      method: 'GET',
      headers: { accept: 'application/json' },
      redirect: 'manual',
      signal: AbortSignal.timeout(httpTimeoutMs()),
    }, scope);
    if (isRedirectStatus(response.status)) {
      const location = response.headers.get('location');
      if (!location) {
        return { status: response.status, json: null, text: '' };
      }
      const next = new URL(location, current).toString();
      current = next;
      continue;
    }
    const text = await readBoundedText(response);
    let json: unknown = null;
    if (looksLikeJson(response.headers.get('content-type'), text)) {
      try { json = JSON.parse(text); } catch { json = null; }
    }
    return { status: response.status, json, text };
  }
  const err = new Error('oauth_unexpected_redirect');
  (err as Error & { code: string }).code = 'oauth_unexpected_redirect';
  throw err;
}
