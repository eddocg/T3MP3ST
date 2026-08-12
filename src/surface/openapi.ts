/**
 * OpenAPI / Swagger artifact parser — P1A.
 *
 * HARD INVARIANT: this module performs ZERO network access. It is a pure function over
 * already-fetched bytes. Existing ScopeGuard-protected HTTP tooling fetches documents; this parser
 * only consumes their content. `servers[]` and external `$ref` URLs are treated as INTELLIGENCE
 * ONLY — they never mutate scope, create targets, or trigger a fetch.
 *
 * Hostile-input posture (OpenAPI/YAML is untrusted target-controlled input):
 *   - Oversize documents FAIL SAFE: over the byte cap → typed oversize result, NEVER a parse of a
 *     truncated raw prefix (a broken-prefix parse would silently drop operations).
 *   - YAML uses JSON_SCHEMA (no custom/`!!js`/timestamp/binary tags) and a preflight anchor/alias
 *     cap that fails closed on alias-bomb ("billion laughs") input BEFORE js-yaml expands it.
 *   - After a valid COMPLETE parse: operation-count, nesting-depth and per-string caps bound the
 *     extracted model. No `example`/`default`/`x-*` blobs are ever retained.
 *   - Only LOCAL `#/` `$ref`s are resolved (cycle-guarded, budgeted). Remote `$ref`s are recorded
 *     as a warning and skipped — never resolved, never fetched.
 */

import jsYaml from 'js-yaml';
import { redactString } from '../redact.js';

const { load: yamlLoad, JSON_SCHEMA } = jsYaml;

// ── Bounded-input limits (target-controlled input is hostile by default) ──
const DEFAULT_MAX_BYTES = 5_000_000; // 5 MB — a legitimate large spec (e.g. 353 KB) is well under this.
const DEFAULT_MAX_OPERATIONS = 5_000;
const DEFAULT_MAX_DEPTH = 40; // $ref-resolution + structural walk depth guard.
const DEFAULT_MAX_STRING = 512; // per extracted string (operationId, path, tag, scheme name, …).
const MAX_REF_RESOLUTIONS = 20_000; // total local $ref derefs across a document.
// YAML anchor/alias caps: a legitimate OpenAPI YAML uses `$ref`, not YAML anchors, so these are
// generous yet still fail closed on a billion-laughs bomb (classic bomb ≈ 9 anchors / 72 aliases).
const MAX_YAML_ANCHORS = 30;
const MAX_YAML_ALIASES = 50;

const HTTP_METHODS = ['get', 'put', 'post', 'delete', 'patch', 'options', 'head', 'trace'] as const;

export interface OpenApiParseOptions {
  /** Reject (do not parse) documents larger than this many UTF-8 bytes. Default 5 MB. */
  maxBytes?: number;
  /** Cap the number of extracted operations. Default 5000. */
  maxOperations?: number;
  /** $ref-resolution / structural depth guard. Default 40. */
  maxDepth?: number;
  /** Per-extracted-string length cap. Default 512. */
  maxStringLen?: number;
}

export interface OpenApiOperation {
  path: string;
  method: string; // upper-case
  operationId?: string;
  parameters: { path: string[]; query: string[]; header: string[]; body?: boolean };
  requestContentTypes: string[];
  securityRequired: boolean;
  securitySchemes: string[];
  oauthScopes: string[];
  deprecated?: boolean;
  tags: string[];
}

export interface OpenApiSecurityScheme {
  name: string;
  type: string;
  in?: string;
  flows?: string[];
  scopes?: string[];
}

export interface OpenApiArtifact {
  /** True only when a supported spec was parsed into a usable operation set. */
  ok: boolean;
  version: 'openapi-3' | 'swagger-2' | 'unknown';
  /** False for detected-but-unmapped specs (Swagger 2 in P1A) — graceful, never a throw. */
  supported: boolean;
  /** Specification metadata ONLY — never an executable origin, never scope. */
  declaredServers: string[];
  operations: OpenApiOperation[];
  securitySchemes: OpenApiSecurityScheme[];
  stats: {
    byteLength: number;
    pathCount: number;
    operationCount: number;
    /** Operation set was capped at maxOperations. */
    truncated: boolean;
    /** Document exceeded maxBytes and was rejected WITHOUT parsing. */
    oversized: boolean;
    warnings: string[];
  };
  errors: string[];
}

/** Typed error for callers that want to distinguish parser failure; `parseOpenApi` itself never throws. */
export class OpenApiParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OpenApiParseError';
  }
}

function emptyArtifact(byteLength: number): OpenApiArtifact {
  return {
    ok: false,
    version: 'unknown',
    supported: false,
    declaredServers: [],
    operations: [],
    securitySchemes: [],
    stats: { byteLength, pathCount: 0, operationCount: 0, truncated: false, oversized: false, warnings: [] },
    errors: [],
  };
}

function cap(value: unknown, n: number): string {
  // Strip C0/DEL control characters (incl. CR/LF/TAB) at the source: OpenAPI text is attacker-
  // controlled, and an embedded newline in an identifier could otherwise forge a line in any
  // consumer (agent prompt, API response). Legitimate paths/ids/tags never contain control chars.
  const s = (typeof value === 'string' ? value : String(value ?? ''))
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]+/g, ' ');
  return s.length > n ? s.slice(0, n) : s;
}

function asObject(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

/**
 * Content-structure detection used by the pre-truncation ingest hook. Structure-primary: an
 * OpenAPI/Swagger document declares a top-level `openapi:`/`swagger:` version. Content-type and
 * URL path hints are secondary corroboration. Deliberately conservative — it must NOT green-light
 * arbitrary JSON responses.
 */
export function looksLikeOpenApiDocument(body: string, contentType?: string, url?: string): boolean {
  if (!body || body.length < 16 || body.length > DEFAULT_MAX_BYTES) return false;
  const head = body.slice(0, 4096);
  // Structure signal (JSON or YAML top-level version key).
  const structural =
    /["']openapi["']\s*:\s*["']3\./.test(head) ||
    /["']swagger["']\s*:\s*["']2\./.test(head) ||
    /^\s*openapi\s*:\s*["']?3\./m.test(head) ||
    /^\s*swagger\s*:\s*["']?2\./m.test(head);
  if (structural) return true;
  // Secondary: a spec-ish content-type or URL path hint plus a plausible top-level `paths` object.
  const ctHint = /json|yaml|yml/i.test(contentType || '');
  const urlHint = /openapi|swagger|api-?docs/i.test(url || '');
  if ((ctHint || urlHint) && /["']paths["']\s*:/.test(head)) return true;
  return false;
}

/** Preflight guard: reject YAML with unbounded alias/anchor use or non-JSON custom tags. */
function yamlHostileGuard(content: string): string | null {
  if (/!!(?:js|python|ruby|perl)\//i.test(content) || /!<tag:/.test(content)) {
    return 'custom/unsafe YAML tag rejected';
  }
  const anchors = (content.match(/(?:^|[\s{[,])&[A-Za-z0-9][\w-]*/g) || []).length;
  const aliases = (content.match(/(?:^|[\s{[,])\*[A-Za-z0-9][\w-]*/g) || []).length;
  if (anchors > MAX_YAML_ANCHORS || aliases > MAX_YAML_ALIASES) {
    return `YAML anchor/alias budget exceeded (anchors=${anchors}, aliases=${aliases}) — refusing potential alias-expansion bomb`;
  }
  return null;
}

/** Build a cycle-guarded, budgeted LOCAL `#/`-only $ref resolver bound to a root document. */
function makeResolver(root: Record<string, unknown>, warnings: string[]) {
  let budget = MAX_REF_RESOLUTIONS;
  const resolve = (node: unknown, depth: number, seen: Set<string>): unknown => {
    if (depth > DEFAULT_MAX_DEPTH) return undefined;
    const obj = asObject(node);
    if (!obj) return node;
    const ref = obj.$ref;
    if (typeof ref === 'string') {
      if (!ref.startsWith('#/')) {
        // Remote / external $ref — intelligence only. NEVER fetched or resolved.
        warnings.push('remote $ref skipped (not resolved, not fetched)');
        return undefined;
      }
      if (seen.has(ref) || budget-- <= 0) return undefined;
      const next = new Set(seen).add(ref);
      let cur: unknown = root;
      for (const seg of ref.slice(2).split('/')) {
        const key = seg.replace(/~1/g, '/').replace(/~0/g, '~');
        cur = asObject(cur)?.[key];
        if (cur === undefined) return undefined;
      }
      return resolve(cur, depth + 1, next);
    }
    return obj;
  };
  return (node: unknown): Record<string, unknown> | undefined => asObject(resolve(node, 0, new Set()));
}

function detectVersion(doc: Record<string, unknown>): OpenApiArtifact['version'] {
  if (typeof doc.openapi === 'string' && /^3\./.test(doc.openapi)) return 'openapi-3';
  if (doc.swagger !== undefined && /^2\./.test(String(doc.swagger))) return 'swagger-2';
  return 'unknown';
}

/** Whether a security requirement list mandates auth: present, non-empty, with a non-empty requirement. */
function securityRequirementMandatesAuth(sec: unknown): boolean {
  return Array.isArray(sec) && sec.length > 0 && sec.some((r) => asObject(r) && Object.keys(asObject(r)!).length > 0);
}

function schemesAndScopes(sec: unknown, maxStr: number): { names: string[]; scopes: string[] } {
  const names = new Set<string>();
  const scopes = new Set<string>();
  if (Array.isArray(sec)) {
    for (const req of sec) {
      const o = asObject(req);
      if (!o) continue;
      for (const [k, v] of Object.entries(o)) {
        names.add(cap(k, maxStr));
        if (Array.isArray(v)) for (const s of v) scopes.add(cap(s, maxStr));
      }
    }
  }
  return { names: [...names], scopes: [...scopes] };
}

function extractSecuritySchemes(doc: Record<string, unknown>, maxStr: number): OpenApiSecurityScheme[] {
  const comps = asObject(doc.components);
  const schemes = asObject(comps?.securitySchemes);
  if (!schemes) return [];
  const out: OpenApiSecurityScheme[] = [];
  for (const [name, raw] of Object.entries(schemes)) {
    const s = asObject(raw);
    if (!s) continue;
    const flowsObj = asObject(s.flows);
    const flows = flowsObj ? Object.keys(flowsObj).map((f) => cap(f, maxStr)) : undefined;
    const scopeSet = new Set<string>();
    if (flowsObj) {
      for (const flow of Object.values(flowsObj)) {
        const scopes = asObject(asObject(flow)?.scopes);
        if (scopes) for (const sc of Object.keys(scopes)) scopeSet.add(cap(sc, maxStr));
      }
    }
    out.push({
      name: cap(name, maxStr),
      type: cap(s.type, maxStr),
      in: typeof s.in === 'string' ? cap(s.in, maxStr) : undefined,
      flows,
      scopes: scopeSet.size ? [...scopeSet] : undefined,
    });
    if (out.length >= 200) break;
  }
  return out;
}

/**
 * Parse an already-fetched OpenAPI/Swagger document. NEVER throws — malformed/oversize/unsupported
 * input returns a typed artifact with `ok:false` and diagnostic `errors`/`warnings`.
 */
export function parseOpenApi(content: string, contentType?: string, opts?: OpenApiParseOptions): OpenApiArtifact {
  const maxBytes = opts?.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxOperations = opts?.maxOperations ?? DEFAULT_MAX_OPERATIONS;
  const maxStr = opts?.maxStringLen ?? DEFAULT_MAX_STRING;

  const byteLength = typeof content === 'string' ? Buffer.byteLength(content, 'utf8') : 0;
  const artifact = emptyArtifact(byteLength);

  if (typeof content !== 'string' || content.trim().length === 0) {
    artifact.errors.push('empty or non-string content');
    return artifact;
  }

  // FAIL-SAFE oversize: reject WITHOUT parsing. Never parse a byte-truncated prefix.
  if (byteLength > maxBytes) {
    artifact.stats.oversized = true;
    artifact.stats.warnings.push(`document ${byteLength} bytes exceeds cap ${maxBytes} — rejected without parsing`);
    artifact.errors.push('oversize document rejected');
    return artifact;
  }

  // ── Parse (full, complete document) ──
  let doc: Record<string, unknown> | undefined;
  const trimmed = content.trimStart();
  const looksJson = trimmed.startsWith('{') || /json/i.test(contentType || '');
  try {
    if (looksJson && trimmed.startsWith('{')) {
      doc = asObject(JSON.parse(content));
    } else {
      const hostile = yamlHostileGuard(content);
      if (hostile) {
        artifact.stats.warnings.push(hostile);
        artifact.errors.push('hostile YAML rejected');
        return artifact;
      }
      doc = asObject(yamlLoad(content, { schema: JSON_SCHEMA }));
    }
  } catch (err) {
    artifact.errors.push(`parse failed: ${cap(err instanceof Error ? err.message : String(err), 200)}`);
    return artifact;
  }

  if (!doc) {
    artifact.errors.push('document is not a JSON/YAML object');
    return artifact;
  }

  artifact.version = detectVersion(doc);

  // Declared servers — METADATA ONLY. Recorded for intelligence; never an executable origin.
  if (artifact.version === 'openapi-3' && Array.isArray(doc.servers)) {
    for (const s of doc.servers) {
      const url = asObject(s)?.url;
      if (typeof url === 'string') artifact.declaredServers.push(cap(url, maxStr));
      if (artifact.declaredServers.length >= 50) break;
    }
  }

  if (artifact.version === 'swagger-2') {
    // Detected but intentionally NOT mapped in P1A. Graceful, typed, no throw.
    artifact.supported = false;
    artifact.stats.warnings.push('Swagger/OpenAPI 2.0 detected — not mapped in P1A (operations omitted)');
    return artifact;
  }
  if (artifact.version === 'unknown') {
    artifact.errors.push('not a recognized OpenAPI 3.x or Swagger 2.0 document');
    return artifact;
  }

  // ── OpenAPI 3.x extraction ──
  const resolve = makeResolver(doc, artifact.stats.warnings);
  const paths = asObject(doc.paths);
  artifact.securitySchemes = extractSecuritySchemes(doc, maxStr);
  const globalSecurity = doc.security;
  const globalRequiresAuth = securityRequirementMandatesAuth(globalSecurity);

  if (paths) {
    for (const [rawPath, rawItem] of Object.entries(paths)) {
      artifact.stats.pathCount++;
      const item = resolve(rawItem);
      if (!item) continue;
      const path = cap(rawPath, maxStr);

      // Path-level parameters apply to every operation on the path.
      const pathParams = Array.isArray(item.parameters) ? item.parameters : [];

      for (const method of HTTP_METHODS) {
        const rawOp = item[method];
        if (rawOp === undefined) continue;
        const op = resolve(rawOp);
        if (!op) continue;
        if (artifact.operations.length >= maxOperations) {
          artifact.stats.truncated = true;
          break;
        }

        const params = { path: [] as string[], query: [] as string[], header: [] as string[], body: undefined as boolean | undefined };
        const opParams = Array.isArray(op.parameters) ? op.parameters : [];
        for (const rawParam of [...pathParams, ...opParams]) {
          const p = resolve(rawParam);
          if (!p) continue;
          const inLoc = typeof p.in === 'string' ? p.in : '';
          const name = typeof p.name === 'string' ? cap(p.name, maxStr) : '';
          if (!name) continue;
          if (inLoc === 'path') params.path.push(name);
          else if (inLoc === 'query') params.query.push(name);
          else if (inLoc === 'header') params.header.push(name);
        }

        const requestContentTypes: string[] = [];
        const requestBody = resolve(op.requestBody);
        if (requestBody) {
          params.body = true;
          const contentMap = asObject(requestBody.content);
          if (contentMap) for (const ct of Object.keys(contentMap)) requestContentTypes.push(cap(ct, maxStr));
        }

        // Security: own `security` overrides global. `security: []` is an explicit PUBLIC override.
        const hasOwnSecurity = Object.prototype.hasOwnProperty.call(op, 'security');
        const effectiveSecurity = hasOwnSecurity ? op.security : globalSecurity;
        const securityRequired = hasOwnSecurity
          ? securityRequirementMandatesAuth(op.security)
          : globalRequiresAuth;
        const { names, scopes } = schemesAndScopes(effectiveSecurity, maxStr);

        const tags = Array.isArray(op.tags)
          ? op.tags.filter((t): t is string => typeof t === 'string').slice(0, 20).map((t) => cap(t, maxStr))
          : [];

        artifact.operations.push({
          path,
          method: method.toUpperCase(),
          operationId: typeof op.operationId === 'string' ? cap(op.operationId, maxStr) : undefined,
          parameters: params,
          requestContentTypes,
          securityRequired,
          securitySchemes: names,
          oauthScopes: scopes,
          deprecated: op.deprecated === true ? true : undefined,
          tags,
        });
      }
      if (artifact.operations.length >= maxOperations) break;
    }
  }

  artifact.stats.operationCount = artifact.operations.length;
  // Redact any target-controlled text that could carry a planted secret before exposure/persistence.
  artifact.declaredServers = artifact.declaredServers.map((s) => redactString(s));
  artifact.ok = true;
  artifact.supported = true;
  return artifact;
}
