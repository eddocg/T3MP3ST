/**
 * Evidence ⇄ claim consistency — the deterministic "category must not outrun its evidence" gate.
 *
 * This module is the audit layer the live pipeline was missing. The pipeline preserves the
 * SOURCE-ASSERTED `category`/`severity` on a Finding verbatim; this module produces a separate,
 * deterministic `ClaimSupport` verdict describing whether the ATTACHED EVIDENCE actually supports
 * that claim. It can BLOCK capability verification or CAP severity — it never rewrites the
 * operator-visible source claim, so both the claim and the audit of it stay on the record.
 *
 * Design rules:
 *  - CONSERVATIVE: absence of supporting evidence caps/blocks; it never invents support.
 *  - AUDITABLE: every verdict carries a human-readable rationale.
 *  - GENERIC: a category→required-evidence table, not target- or vendor-specific logic.
 *  - STRUCTURE-FIRST: prefer structured tool signals (status codes, header presence, parser
 *    fields) over prose. Text matching is a last-resort heuristic for free-form tool output.
 */

import type { ClaimSupport, Evidence, Finding, Severity } from '../types/index.js';

const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
function capSeverity(asserted: Severity, cap: Severity): Severity {
  return SEVERITY_ORDER.indexOf(asserted) > SEVERITY_ORDER.indexOf(cap) ? cap : asserted;
}

/**
 * Category → evidence contract. `signals` are substrings that, when present in TOOL evidence,
 * indicate the category is genuinely demonstrated. `capWhenUnsupported` is the highest severity
 * the claim may keep when no supporting signal is found. `observation` marks categories that are
 * inherently scanner observations (they should not present as proven vulnerabilities).
 *
 * The bar is deliberately high for capability categories (rce, credential, sqli, …): the evidence
 * must show the CAPABILITY, not merely a condition that could lead to it.
 */
interface CategoryRule {
  signals: string[];
  capWhenUnsupported: Severity;
  /**
   * OBSERVATION categories only: the ceiling when the evidence DOES carry the category signal.
   * "Supported" for an observation means "the configuration/exposure is real" — it says nothing
   * about attacker IMPACT, so it must never uncap to critical. Impact-bearing categories leave
   * this unset (a demonstrated capability is allowed to carry high/critical).
   */
  capWhenSupported?: Severity;
  observation?: boolean;
  note: string;
}

const CATEGORY_RULES: Record<string, CategoryRule> = {
  rce: {
    signals: ['uid=', 'gid=', 'command executed', 'shell', 'whoami', 'rce confirmed', 'code execution', 'exec output'],
    capWhenUnsupported: 'info',
    note: 'RCE requires evidence of attacker-controlled code/command execution, not a reachable service.',
  },
  credential: {
    signals: ['password=', 'secret', 'token leaked', 'credential disclosed', 'set-cookie:', 'authorization:', 'api_key', 'private key'],
    capWhenUnsupported: 'low',
    note: 'Credential compromise requires evidence of credential disclosure/capture/replay — not a config observation.',
  },
  cors: {
    signals: ['access-control-allow-origin', 'acao', 'access-control-allow-credentials'],
    capWhenUnsupported: 'low',
    // ACAO reflection + ACAC:true is a supported CONFIGURATION observation — never demonstrated
    // authenticated impact by itself (a scanner labeling a probe "with credentials" is not a
    // demonstrated victim-browser sensitive cross-origin read). INFO/LOW maximum until a real
    // read/action capability is evidenced — which would be a separate capability claim with its
    // own evidence, not a header observation.
    capWhenSupported: 'low',
    observation: true,
    note: 'CORS reflection is a configuration observation until authenticated sensitive cross-origin impact is demonstrated.',
  },
  sqli: {
    signals: ['sql syntax', 'mysql', 'psql', 'sqlite', 'ora-', 'sqlstate', 'database error', 'query failed', 'union select'],
    capWhenUnsupported: 'medium',
    note: 'SQLi requires a database-error / differential response signal, not a reachable parameter.',
  },
  xss: {
    signals: ['<script', 'alert(', 'onerror=', 'reflected', 'javascript:', 'xss'],
    capWhenUnsupported: 'medium',
    note: 'XSS requires a reflected/executed payload signal in the response.',
  },
  authz: {
    // A cross-principal / privilege boundary FAILURE. Requires a differential signal.
    signals: ['cross-principal', 'bola', 'idor', 'forbidden->ok', '200 ok', 'escalat', 'unauthorized access', 'boundary fail'],
    capWhenUnsupported: 'medium',
    note: 'An authorization finding requires a differential: a principal reached a resource/action it should not.',
  },
  cleartext: {
    signals: ['http://', 'cleartext', 'no tls', 'plain http'],
    capWhenUnsupported: 'low',
    capWhenSupported: 'low',
    observation: true,
    note: 'Cleartext HTTP is a transport observation; it is not RCE or credential compromise on its own.',
  },
  info_disclosure: {
    signals: ['version', 'server:', 'x-powered-by', 'swagger', 'openapi', 'banner'],
    capWhenUnsupported: 'info',
    // Version/banner/spec exposure is informational unless the exposed material is itself
    // sensitive (that re-categorizes as credential). "Supported" here means "the exposure is
    // real", not "impact demonstrated".
    capWhenSupported: 'info',
    observation: true,
    note: 'Version/banner/spec exposure is reconnaissance context, not a vulnerability by itself.',
  },
  headers: {
    signals: ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'missing', 'security header'],
    capWhenUnsupported: 'info',
    capWhenSupported: 'info',
    observation: true,
    note: 'Missing/weak security headers are a hardening observation — they set up no exploit by themselves.',
  },
  tls: {
    signals: ['cipher', 'tls', 'ssl', 'certificate', 'x.509'],
    capWhenUnsupported: 'info',
    capWhenSupported: 'low',
    observation: true,
    note: 'Weak TLS/cipher/certificate posture is a configuration observation absent a demonstrated interception/downgrade.',
  },
};

/** Generic/default rule for an unrecognized category: cap hard, require explicit support. */
const DEFAULT_RULE: CategoryRule = {
  signals: [],
  capWhenUnsupported: 'low',
  note: 'Unrecognized category — severity capped until supporting evidence is attached.',
};

/** Categories that are inherently scanner OBSERVATIONS — never a demonstrated capability on their own. */
export const CATEGORY_OBSERVATION: ReadonlySet<string> = new Set(
  Object.entries(CATEGORY_RULES)
    .filter(([, r]) => r.observation)
    .map(([k]) => k),
);

/**
 * Derive the effective category for a finding. Preserves the source-asserted `category` if set;
 * otherwise derives a best-effort category from CWE / title heuristics. This is the value the
 * assessment evaluates — it never overwrites `finding.category`.
 */
export function deriveCategory(f: { category?: string; cwe?: string[]; title?: string }): string {
  if (f.category && f.category.trim()) return f.category.trim().toLowerCase();
  const cwe = (f.cwe?.[0] || '').toLowerCase();
  const title = (f.title || '').toLowerCase();
  const text = `${cwe} ${title}`;
  if (/cwe-?(78|94|95)\b|\brce\b|remote code|command injection|code execution/.test(text)) return 'rce';
  // CORS before credential: CORS findings routinely mention "credentials" incidentally (ACAC),
  // e.g. nuclei "cors-any-origin-with-credentials" — they are CORS observations, not credential
  // disclosures. A real credential finding carries disclosure vocabulary and no CORS token.
  if (/cors|cross-origin|access-control/.test(text)) return 'cors';
  if (/cwe-?(798|522|312|319)\b|credential|password|secret|token/.test(text)) return 'credential';
  if (/cwe-?89\b|sql.?injection|\bsqli\b/.test(text)) return 'sqli';
  if (/cwe-?79\b|xss|cross-site scripting/.test(text)) return 'xss';
  if (/cwe-?(639|862|863|285)\b|bola|bfla|idor|authorization|access control|privilege/.test(text)) return 'authz';
  if (/cleartext|http only|no tls|plain http|insecure transport/.test(text)) return 'cleartext';
  // Order matters: headers/TLS hardening observations before the generic info_disclosure bucket.
  if (/security.?headers?|missing.?headers?|strict-transport|content-security-policy|x-frame-options|x-content-type|\bhsts\b/.test(text)) return 'headers';
  if (/weak.?cipher|cipher.?suite|deprecated.?(tls|ssl)|\btls\b.?1\.[01]|sslv\d|certificate|x\.509|\btls\b|\bssl\b/.test(text)) return 'tls';
  if (/version|banner|swagger|openapi|server header|fingerprint|disclosure/.test(text)) return 'info_disclosure';
  return 'general';
}

/** Concatenated tool-output evidence text for signal matching (structure-first: only tool types). */
function toolEvidenceText(evidence: Evidence[]): string {
  return evidence
    .filter((e) => e && ['output', 'command', 'response', 'request', 'log', 'file'].includes(e.type))
    .map((e) => String(e.content || ''))
    .join('\n')
    .toLowerCase();
}

/**
 * Assess whether the attached evidence supports the asserted claim category.
 * Conservative and auditable. Does NOT mutate the finding — returns a verdict the gate/ledger use
 * to block capability verification or cap severity.
 */
export function assessClaimSupport(f: Finding): ClaimSupport {
  const category = deriveCategory(f);
  const rule = CATEGORY_RULES[category] ?? DEFAULT_RULE;
  const evidence = Array.isArray(f.evidence) ? f.evidence : [];
  const corpus = toolEvidenceText(evidence);
  const checkedAt = Date.now();

  if (evidence.length === 0 || corpus.trim().length === 0) {
    return {
      category,
      supportLevel: 'unverifiable',
      severityCap: rule.observation ? 'info' : 'low',
      rationale: `no tool evidence attached — ${rule.note}`,
      checkedAt,
    };
  }

  const hit = rule.signals.find((sig) => corpus.includes(sig));
  if (hit) {
    // CAPABILITY-AWARE CEILING: a category signal means "the condition is real", not "impact is
    // demonstrated". Impact categories (rce/sqli/xss/authz/credential) may carry full severity
    // when their signal is present; OBSERVATION categories (cors/headers/tls/info_disclosure/
    // cleartext) stay capped — a real configuration observation is not a demonstrated capability.
    // CORS explicitly gets NO credentialed-reflection promotion: reflected ACAO + ACAC:true is
    // still a configuration observation; only a demonstrated authenticated sensitive cross-origin
    // read/action (a separate capability claim with its own evidence) can carry real severity.
    const cap: Severity = rule.observation ? (rule.capWhenSupported ?? 'low') : 'critical';
    return {
      category,
      supportLevel: 'supported',
      severityCap: cap,
      rationale: `evidence contains a ${category} signal ("${hit}") consistent with the claim` +
        (rule.observation ? `; observation-category ceiling ${cap} (configuration support ≠ impact)` : ''),
      checkedAt,
    };
  }

  return {
    category,
    supportLevel: 'unsupported',
    severityCap: rule.capWhenUnsupported,
    rationale: `evidence does not demonstrate ${category} (no ${category} capability signal found) — ${rule.note}`,
    checkedAt,
  };
}

/**
 * The severity a finding may actually carry, given its evidence. Preserves the source claim on the
 * record; this returns the AUDITED severity for presentation/promotion decisions.
 */
export function auditedSeverity(f: Finding): Severity {
  const support = f.claimSupport ?? assessClaimSupport(f);
  return capSeverity(f.severity, support.severityCap);
}

/**
 * Whether this finding's claim is evidence-supported well enough to be treated as a demonstrated
 * capability (the gate's "verified" bar). Provenance alone is NOT sufficient — the evidence must
 * also support the asserted category.
 */
export function capabilitySupported(f: Finding): boolean {
  const support = f.claimSupport ?? assessClaimSupport(f);
  return support.supportLevel === 'supported' && !CATEGORY_RULES[support.category]?.observation;
}

// =============================================================================
// DEDUP FINGERPRINT
// =============================================================================

export interface FindingFingerprintParts {
  origin?: string;
  route?: string;
  method?: string;
  /** security property / category */
  property: string;
  /** parameter / selector when known */
  selector?: string;
  /** principal → resource boundary when known (kept distinct; never over-merged) */
  boundary?: string;
}

/**
 * Build a dedup fingerprint that distinguishes origin + route + method + security property +
 * parameter/selector + principal/resource boundary. Two DIFFERENT authorization failures (different
 * principal→resource pairs, or different routes) NEVER share a fingerprint; repeated evidence for the
 * SAME boundary from different tools/tasks/phases DOES, so it consolidates instead of duplicating.
 *
 * Inputs are best-effort — a scanner finding may only have target + title. Missing dimensions fall
 * back to a normalized title slug so unrelated findings on the same target still stay separate.
 */
export function findingFingerprint(f: {
  targetId?: string;
  title?: string;
  category?: string;
  cwe?: string[];
  evidence?: Evidence[];
  metadata?: Record<string, unknown>;
}): string {
  const rawProperty = f.category ?? f.cwe?.[0] ?? deriveCategory({ title: f.title, cwe: f.cwe });
  const property = String(rawProperty || 'general').toLowerCase();

  // Try to pull origin/route/method/selector out of evidence metadata or content.
  let origin = '';
  let route = '';
  let method = '';
  let selector = '';
  let boundary = '';
  for (const e of f.evidence ?? []) {
    const meta = (e?.metadata ?? {}) as Record<string, unknown>;
    origin = origin || String(meta.origin ?? '');
    route = route || String(meta.route ?? meta.path ?? '');
    method = method || String(meta.method ?? '').toUpperCase();
    selector = selector || String(meta.selector ?? meta.parameter ?? meta.param ?? '');
    boundary = boundary || String(meta.boundary ?? '');
    // Derive origin/route from a request/response evidence URL if not explicitly tagged.
    // The path group must be OPTIONAL — a bare origin ("https://host" with no trailing slash,
    // common in header evidence like ACAO) must still extract the origin or every header-only
    // observation collapses onto the targetId fallback and over-merges across real boundaries.
    // When MULTIPLE URLs appear (e.g. nuclei "host: <origin> | matched-at: <origin>/oauth2/…"),
    // prefer the FIRST URL carrying a real path for the route — the bare host URL is origin-only
    // and must not mask the actual boundary the observation fired on.
    if (!origin || !route) {
      const urls = String(e?.content ?? '').matchAll(/https?:\/\/([^\s/"'/)]+)(\/[^\s"')]*)?/gi);
      for (const m of urls) {
        if (!origin) origin = m[1].toLowerCase();
        const path = (m[2] || '').split('?')[0];
        if (!route && path && path !== '/') route = path;
      }
      if (!route && origin) route = '/';
    }
  }
  if (!origin) origin = String(f.targetId ?? 'unknown').toLowerCase();

  // Normalize route: strip trailing slash; collapse numeric/UUID path segments to a param token so
  // /users/1 and /users/2 (same route shape, same property) consolidate, while /users/{id}/ekey vs
  // /users/{id}/profile (different selectors/operations) stay distinct.
  const normRoute = route
    .replace(/\/+$/, '')
    .replace(/\/(\d{1,})(?=\/|$)/g, '/{n}')
    .replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}(?=\/|$)/gi, '/{id}');

  const parts = [origin, normRoute, method, property, selector, boundary]
    .map((p) => p.trim())
    .filter((p) => p.length > 0);

  // Fallback: if we only have origin+property (a bare scanner/LLM finding), decide whether a
  // title slug is needed to keep DISTINCT issues apart:
  //  - EXPLICIT category (tool-asserted, e.g. cors / headers / openapi / version exposure):
  //    origin+category IS the consolidation key. Reworded titles for the same underlying
  //    observation ("CORS Misconfiguration" vs "Credentialed CORS origin reflection") must merge
  //    into ONE candidate with multiple evidence records — not separate vulnerability rows.
  //  - DERIVED/coarse property ('general'): keep a normalized title slug so unrelated findings
  //    on the same target still stay separate.
  const hasExplicitCategory = !!(f.category && f.category.trim()) && property !== 'general';
  if (parts.length <= 2 && !hasExplicitCategory) {
    const slug = String(f.title ?? '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, ' ')
      .trim()
      .split(' ')
      .filter(Boolean)
      .slice(0, 6)
      .join('-');
    if (slug) parts.push(slug);
  }
  return parts.join('::');
}
