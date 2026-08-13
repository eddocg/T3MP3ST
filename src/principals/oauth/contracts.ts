/**
 * GrantAdapter / ClientAuthAdapter contracts. New grants register here; the store,
 * selection, and protected-resource tools do not switch on grantType.
 */

import type { AuthValidationCode, AuthValidationFailure, PrincipalPublic } from '../types.js';
import type { StoredPrincipal } from '../store.js';

export type ScopeLike = { allowedHosts: string[]; allowLoopback: boolean; allowPrivate: boolean } | null;

export interface FieldClass {
  name: string;
  /** Never serialize/log, at any length. */
  secret: boolean;
  /** Included in authConfigRevision public hash (non-secret) or secret-bump (secret). */
  tokenAffecting?: boolean;
  /** Omitted on edit → preserve; null → clear; string → replace without comparing. */
  writeOnly?: boolean;
}

export interface GrantTokenRequest {
  url: string;
  body: URLSearchParams;
  extraHeaders?: Record<string, string>;
}

export type OAuthPhase = 'acquire' | 'refresh' | 'reacquire' | 'interactive';

export type RenewalCapability = 'automatic' | 'interactive' | 'unavailable';

export interface GrantAdapter {
  grantType: string;
  fields(): FieldClass[];
  reservedTokenParams(): readonly string[];
  validate(write: Record<string, unknown>): { ok: true } | { ok: false; code: string };
  projectPublic(p: StoredPrincipal): Record<string, unknown>;
  classifyError(phase: OAuthPhase, tokenJson: unknown, httpStatus: number): AuthValidationCode | null;
  canRepeatNonInteractive(p: StoredPrincipal): boolean;
  renewalCapability(p: StoredPrincipal): RenewalCapability;
  beginInteractive?(ctx: { missionId: string; principal: StoredPrincipal }): Promise<{
    authorizationUrl: string;
    state: string;
    verifier?: string;
    challenge?: string;
  } | AuthValidationFailure>;
  acquire(ctx: { principal: StoredPrincipal }): GrantTokenRequest | AuthValidationFailure;
  onTokenSuccess?(ctx: { missionId: string; principal: StoredPrincipal }): void;
  clearOneUse?(p: StoredPrincipal): void;
}

export interface ClientAuthAdapter {
  method: string;
  fields(): FieldClass[];
  reservedTokenParams(): readonly string[];
  validate(write: Record<string, unknown>): { ok: true } | { ok: false; code: string };
  projectPublic(p: StoredPrincipal): Record<string, unknown>;
  apply(ctx: { principal: StoredPrincipal }, body: URLSearchParams): { headers?: Record<string, string> };
}

export type { PrincipalPublic, StoredPrincipal };
