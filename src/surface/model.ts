/**
 * Mission-scoped Web/API surface model — P1A.
 *
 * A `SurfaceModel` accumulates structured knowledge of a target's API surface for the lifetime of
 * ONE mission. In P1A it is populated exclusively from parsed OpenAPI artifacts (P1B will add
 * observed-route capture). Key invariants:
 *
 *   - Operations are bound to `sourceOrigin` — the AUTHORIZED origin the document was actually
 *     fetched from — NOT to the spec's `servers[]` (which are metadata/intelligence only and must
 *     never become executable origins or mutate scope).
 *   - Ingestion is IDEMPOTENT: operations are keyed by `METHOD sourceOrigin path`, so re-ingesting
 *     the same artifact (or a spec with duplicate method/path entries) never multiplies rows.
 *   - The mutable model is destroyed on mission teardown; a terminal mission keeps only an
 *     immutable, redacted, bounded `SurfaceSnapshot` — never the raw document body.
 */

import { redactString } from '../redact.js';
import type { OpenApiArtifact, OpenApiOperation, OpenApiSecurityScheme } from './openapi.js';

/** Max operations retained in a bounded summary / terminal snapshot (full counts live in stats). */
const SNAPSHOT_OPERATION_CAP = 300;

export interface SurfaceOperation {
  /** sourceOrigin — the authorized origin the artifact was fetched from. NOT servers[0]. */
  origin: string;
  path: string;
  method: string; // upper-case
  operationId?: string;
  source: 'openapi';
  parameters: { path: string[]; query: string[]; header: string[]; body?: boolean };
  requestContentTypes: string[];
  securityRequired: boolean;
  securitySchemes: string[];
  oauthScopes: string[];
  deprecated?: boolean;
  tags: string[];
}

export interface SurfaceStats {
  origins: string[];
  operationCount: number;
  authRequiredCount: number;
  publicCount: number;
  deprecatedCount: number;
  declaredServers: string[];
  ingestCount: number;
  warnings: string[];
}

/** Immutable, redacted, bounded projection stored with terminal mission state. No raw document. */
export interface SurfaceSnapshot {
  capturedAt: string;
  stats: SurfaceStats;
  securitySchemes: OpenApiSecurityScheme[];
  operations: Array<{
    origin: string;
    method: string;
    path: string;
    operationId?: string;
    securityRequired: boolean;
    oauthScopes: string[];
    deprecated?: boolean;
    tags: string[];
  }>;
  operationsTruncated: boolean;
}

function opKey(method: string, origin: string, path: string): string {
  return `${method.toUpperCase()} ${origin}${path}`;
}

function normalizeOrigin(origin: string): string {
  try {
    return new URL(origin).origin;
  } catch {
    return redactString(String(origin || '').trim());
  }
}

export class SurfaceModel {
  private operations = new Map<string, SurfaceOperation>();
  private schemes = new Map<string, OpenApiSecurityScheme>();
  private declaredServers = new Set<string>();
  private warnings: string[] = [];
  private ingestCount = 0;

  constructor(public readonly missionId: string) {}

  /**
   * Ingest a parsed OpenAPI artifact, binding every operation to `sourceOrigin`. Declared servers
   * are recorded as metadata only. Idempotent by `METHOD origin path`.
   */
  ingestOpenApi(artifact: OpenApiArtifact, sourceOrigin: string): number {
    if (!artifact || !artifact.ok || !artifact.supported) return 0;
    const origin = normalizeOrigin(sourceOrigin);
    this.ingestCount++;

    for (const srv of artifact.declaredServers) {
      if (this.declaredServers.size < 100) this.declaredServers.add(redactString(srv));
    }
    for (const w of artifact.stats.warnings) {
      if (this.warnings.length < 50 && !this.warnings.includes(w)) this.warnings.push(w);
    }
    for (const s of artifact.securitySchemes) {
      if (!this.schemes.has(s.name)) this.schemes.set(s.name, s);
    }

    let added = 0;
    for (const op of artifact.operations) {
      const key = opKey(op.method, origin, op.path);
      if (!this.operations.has(key)) added++;
      this.operations.set(key, this.toSurfaceOperation(op, origin));
    }
    return added;
  }

  private toSurfaceOperation(op: OpenApiOperation, origin: string): SurfaceOperation {
    return {
      origin,
      path: redactString(op.path),
      method: op.method.toUpperCase(),
      operationId: op.operationId ? redactString(op.operationId) : undefined,
      source: 'openapi',
      parameters: {
        path: op.parameters.path.map(redactString),
        query: op.parameters.query.map(redactString),
        header: op.parameters.header.map(redactString),
        body: op.parameters.body,
      },
      requestContentTypes: op.requestContentTypes.map(redactString),
      securityRequired: op.securityRequired,
      securitySchemes: op.securitySchemes.map(redactString),
      oauthScopes: op.oauthScopes.map(redactString),
      deprecated: op.deprecated,
      tags: op.tags.map(redactString),
    };
  }

  getOperations(): SurfaceOperation[] {
    return [...this.operations.values()];
  }

  get size(): number {
    return this.operations.size;
  }

  stats(): SurfaceStats {
    const ops = this.getOperations();
    const origins = [...new Set(ops.map((o) => o.origin))];
    let authRequired = 0;
    let deprecated = 0;
    for (const o of ops) {
      if (o.securityRequired) authRequired++;
      if (o.deprecated) deprecated++;
    }
    return {
      origins,
      operationCount: ops.length,
      authRequiredCount: authRequired,
      publicCount: ops.length - authRequired,
      deprecatedCount: deprecated,
      declaredServers: [...this.declaredServers],
      ingestCount: this.ingestCount,
      warnings: [...this.warnings],
    };
  }

  /** Build the immutable, redacted, bounded terminal snapshot. */
  snapshot(): SurfaceSnapshot {
    const ops = this.getOperations();
    const bounded = ops.slice(0, SNAPSHOT_OPERATION_CAP).map((o) => ({
      origin: o.origin,
      method: o.method,
      path: o.path,
      operationId: o.operationId,
      securityRequired: o.securityRequired,
      oauthScopes: o.oauthScopes,
      deprecated: o.deprecated,
      tags: o.tags,
    }));
    return {
      capturedAt: new Date().toISOString(),
      stats: this.stats(),
      securitySchemes: [...this.schemes.values()],
      operations: bounded,
      operationsTruncated: ops.length > SNAPSHOT_OPERATION_CAP,
    };
  }

  /** Drop all accumulated state (mission teardown). */
  destroy(): void {
    this.operations.clear();
    this.schemes.clear();
    this.declaredServers.clear();
    this.warnings = [];
    this.ingestCount = 0;
  }
}
