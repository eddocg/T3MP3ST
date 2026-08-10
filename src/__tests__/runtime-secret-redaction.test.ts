/**
 * Central runtime-secret redaction (defense-in-depth for the per-mission authenticated target headers).
 *
 * Regression coverage for the bearer-token leak: the value-aware arsenal redactor
 * (redactConfiguredSecrets) only scrubs arsenal TOOL RESULTS. Any raw configured header value that
 * (a) is NOT "Bearer "-prefixed, (b) matches no provider SECRET_PATTERN, and (c) is NOT under an
 * object key named authorization/cookie/token/... would otherwise sail through the pattern-only
 * redactString/redactSecrets used at EVERY persistence/export/SSE/ledger boundary — landing in
 * state.json and /api/evidence in the clear (e.g. an opaque Cookie/X-API-Key/session value entering
 * via the server ledger/report path, which never calls redactConfiguredSecrets).
 *
 * registerRuntimeSecrets makes the central redactor value-AWARE: these tests prove literal
 * Authorization bearer values, Cookie values, X-API-Key values, client secrets and session tokens
 * cannot appear in exported/persisted/event-visible artifacts once the mission binding is registered.
 * This does NOT rely on UI masking or prompt instructions.
 */

import { afterEach, describe, expect, it } from 'vitest';
import {
  redactString,
  redactSecrets,
  redactLedgerText,
  registerRuntimeSecrets,
  clearRuntimeSecrets,
} from '../redact.js';

// Deliberately opaque values that trip NONE of the pattern rules: no "Bearer " prefix, not a JWT,
// not a provider signature, not in `key=value` form, and not under a matching object key.
const BEARER_TOKEN = 'abc123def456ghi789jkl012mno345pqr678';         // raw Authorization token, no "Bearer "
const COOKIE_VALUE = 'sessionblob_9f8e7d6c5b4a3210fedcba9876543210';  // opaque cookie value
const APIKEY_VALUE = 'opaqueapikey_ZXhhbXBsZUtleVZhbHVl';            // opaque X-API-Key value
const CLIENT_SECRET = 'cs_livelikevalue_but_not_stripe_0123456789';   // "client secret"
const SESSION_TOKEN = 'sesh.7c9a1b2d3e4f5061';                        // short-ish session token (>= 6)

const ALL_SECRETS = [BEARER_TOKEN, COOKIE_VALUE, APIKEY_VALUE, CLIENT_SECRET, SESSION_TOKEN];

afterEach(() => clearRuntimeSecrets());

describe('registered runtime secrets are stripped by the central pattern-blind redactors', () => {
  it('baseline: WITHOUT registration these opaque values leak through redactString (proving the gap is real)', () => {
    // No pattern matches → the value survives. This is exactly the pre-fix leak.
    expect(redactString(`Authorization: ${BEARER_TOKEN}`)).toContain(BEARER_TOKEN);
    expect(redactString(`Set-Cookie value observed: ${COOKIE_VALUE}`)).toContain(COOKIE_VALUE);
  });

  it('redactString strips every registered literal value, wherever it appears in the text', () => {
    registerRuntimeSecrets(ALL_SECRETS);
    for (const secret of ALL_SECRETS) {
      // In prose (report description), in a reflected header line, and mid-sentence.
      expect(redactString(`The endpoint reflected ${secret} in its body.`)).not.toContain(secret);
      expect(redactString(`Authorization: ${secret}`)).not.toContain(secret);
      expect(redactString(secret)).toBe('[redacted]');
    }
  });

  it('redactSecrets scrubs registered values in nested objects/arrays even under innocuous keys', () => {
    registerRuntimeSecrets(ALL_SECRETS);
    // Key "detail"/"note" does NOT match the key-name net — only the value-aware layer catches these.
    const payload = {
      finding: { detail: `Observed token ${BEARER_TOKEN} echoed back` },
      notes: [`cookie was ${COOKIE_VALUE}`, { deep: `x-api-key=${APIKEY_VALUE}-tail` }],
    };
    const out = JSON.stringify(redactSecrets(payload));
    for (const secret of ALL_SECRETS.filter((s) => [BEARER_TOKEN, COOKIE_VALUE, APIKEY_VALUE].includes(s))) {
      expect(out).not.toContain(secret);
    }
  });

  it('redactLedgerText (the /api/evidence + /api/findings ingestion path) strips registered values', () => {
    registerRuntimeSecrets(ALL_SECRETS);
    const summary = `PoC: GET /admin with cookie ${COOKIE_VALUE} and key ${APIKEY_VALUE} returned 200`;
    const out = redactLedgerText(summary);
    expect(out).not.toContain(COOKIE_VALUE);
    expect(out).not.toContain(APIKEY_VALUE);
  });

  it('longest-first ordering: an overlapping shorter value cannot leave a tail of a longer one', () => {
    const long = 'tokenAAAAAAAAAAAA';
    const short = 'tokenAAAA'; // prefix of `long`
    registerRuntimeSecrets([short, long]);
    // If short ran first it would blank its prefix and leave "AAAAAAAA"; longest-first avoids that.
    expect(redactString(long)).toBe('[redacted]');
    expect(redactString(long)).not.toMatch(/A{4,}/);
  });

  it('clearRuntimeSecrets restores pattern-only behavior (mission teardown)', () => {
    registerRuntimeSecrets(ALL_SECRETS);
    expect(redactString(BEARER_TOKEN)).toBe('[redacted]');
    clearRuntimeSecrets();
    expect(redactString(BEARER_TOKEN)).toContain(BEARER_TOKEN);
  });

  it('ignores too-short values so a common substring cannot nuke unrelated text', () => {
    registerRuntimeSecrets(['abc']); // below MIN_RUNTIME_SECRET_LEN (6)
    expect(redactString('the abc of security is abc')).toBe('the abc of security is abc');
  });

  it('registration replaces the prior set (does not accumulate across missions)', () => {
    registerRuntimeSecrets([BEARER_TOKEN]);
    registerRuntimeSecrets([COOKIE_VALUE]);
    expect(redactString(BEARER_TOKEN)).toContain(BEARER_TOKEN); // first mission's secret no longer tracked
    expect(redactString(COOKIE_VALUE)).toBe('[redacted]');
  });

  it('the standing pattern rules still fire alongside registered values (no regression)', () => {
    registerRuntimeSecrets([COOKIE_VALUE]);
    const text = `Bearer sometokenthatislongenough1234 and cookie ${COOKIE_VALUE} and AKIA${'A'.repeat(16)}`;
    const out = redactString(text);
    expect(out).toContain('Bearer [redacted]');
    expect(out).not.toContain(COOKIE_VALUE);
    expect(out).not.toContain('AKIAAAAAAAAAAAAAAAAA');
  });
});
