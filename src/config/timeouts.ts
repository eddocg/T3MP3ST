/**
 * Consolidated mission-execution timeout model.
 *
 * Single source of truth for every operator-tunable timeout: its label, units, default, bounds,
 * env-var override, class, restart requirement, and — critically — its place in the parent/child
 * hierarchy. A supervising backstop must never be configurable SHORTER than the maximum legitimate
 * execution window of the operation it supervises (plus a reconciliation grace), or every slow-but-
 * healthy task becomes a false timeout + late-success race.
 *
 * Classes:
 *   A — operator-tunable runtime setting (exposed in Settings).
 *   B — advanced (documented, not exposed as a free-form knob).
 *   C — security/safety invariant: FIXED, never operator-tunable.
 *
 * Precedence (per value): UI/runtime override > environment variable > default.
 * A UI override is ONLY persisted when explicitly set; "reset" REMOVES the override so env/default
 * precedence becomes active again — reset never writes the default back as a UI value.
 */

export type TimeoutClass = 'A' | 'B' | 'C';
export type TimeoutUnit = 'seconds' | 'minutes' | 'count';

export interface TimeoutSpec {
  /** Stable key used in settings + API. */
  key: string;
  label: string;
  unit: TimeoutUnit;
  /** Default in MILLISECONDS (or a count when unit==='count'). */
  defaultMs: number;
  minMs: number;
  maxMs: number;
  class: TimeoutClass;
  /** Env var that overrides the default when no UI value is set. */
  envVar?: string;
  /** True when a change only takes effect for NEW dispatches/processes (not retroactive). */
  restartRequired: boolean;
  blurb: string;
  /**
   * Child keys whose execution window this value must exceed (supervisor invariant). Enforced at
   * config time: a supervisor must be >= max(child windows) + graceMs.
   */
  supervises?: string[];
  /** Minimum gap a supervisor must keep above its largest child window. */
  graceMs?: number;
}

/** Grace a dispatch backstop must keep above the work it supervises (lets late results reconcile). */
export const DISPATCH_RECONCILE_GRACE_MS = 60_000; // 1 minute

export const TIMEOUT_REGISTRY: readonly TimeoutSpec[] = [
  {
    key: 'dispatchTimeoutMs',
    label: 'Dispatch backstop timeout',
    unit: 'minutes',
    // Source-verified: src/index.ts resolveTaskTimeoutMs -> 300000 general / 1800000 local-agent.
    defaultMs: 300_000, // 5 minutes (general provider)
    minMs: 60_000,
    maxMs: 3_600_000,
    class: 'A',
    envVar: 'T3MP3ST_TASK_TIMEOUT_MS',
    restartRequired: false,
    blurb: 'Wall-clock backstop that force-fails a wedged dispatch so the phase can advance. Supervises tool + LLM execution windows; late successes reconcile.',
    supervises: ['toolExecTimeoutMs', 'llmTimeoutMs'],
    graceMs: DISPATCH_RECONCILE_GRACE_MS,
  },
  {
    key: 'toolExecTimeoutMs',
    label: 'Tool / subprocess execution timeout',
    unit: 'minutes',
    defaultMs: 120_000, // 2 minutes (adapter default for most CLI tools)
    minMs: 30_000,
    maxMs: 1_800_000,
    class: 'A',
    envVar: 'T3MP3ST_TOOL_TIMEOUT_MS',
    restartRequired: false,
    blurb: 'Default wall clock for an external CLI tool (nmap/nuclei/ffuf/…). Per-tool adapters may still specify a longer bound (e.g. garak) — those are derived, not global knobs.',
  },
  {
    key: 'llmTimeoutMs',
    label: 'LLM response timeout',
    unit: 'seconds',
    defaultMs: 60_000, // cloud default; local is floored to >=120s at the provider layer
    minMs: 15_000,
    maxMs: 600_000,
    class: 'A',
    envVar: 'TEMPEST_LOCAL_TIMEOUT', // applies to the local provider only; preserved
    restartRequired: false,
    blurb: 'Per-call LLM wall clock. Local inference is floored higher automatically; a single LLM call must stay well under the dispatch backstop.',
  },
  {
    key: 'llmRetryAttempts',
    label: 'LLM retry count',
    unit: 'count',
    defaultMs: 3,
    minMs: 1, // at least one attempt (0 would mean "never call the model"); not a timeout
    maxMs: 6,
    class: 'A',
    envVar: 'T3MP3ST_LLM_RETRY_ATTEMPTS',
    restartRequired: false,
    blurb: 'Same-model retry attempts before escalating. The first attempt is the call itself; retries add on top.',
  },
  {
    key: 'llmRetryDelayMs',
    label: 'LLM retry delay (base)',
    unit: 'seconds',
    defaultMs: 1_000,
    minMs: 500,
    maxMs: 30_000,
    class: 'A',
    envVar: 'T3MP3ST_LLM_RETRY_DELAY_MS',
    restartRequired: false,
    blurb: 'Base backoff between retries (exponential). A server Retry-After header is honored but hard-capped (security invariant, not tunable).',
  },
  {
    key: 'plannerTimeoutMs',
    label: 'Planner timeout',
    unit: 'minutes',
    defaultMs: 300_000, // 5 minutes (cloud); local-agent chained higher at the call site
    minMs: 60_000,
    maxMs: 1_200_000,
    class: 'A',
    envVar: 'TEMPEST_GENERAL_TIMEOUT_MS', // T3MP3ST_GENERAL_TIMEOUT_MS alias preserved at call site
    restartRequired: false,
    blurb: 'OpGeneral planning LLM wall clock. Planning needs more room than a 60s chat call.',
  },
  {
    key: 'httpRequestTimeoutMs',
    label: 'HTTP request timeout (global probe default)',
    unit: 'seconds',
    defaultMs: 5_000,
    minMs: 2_000,
    maxMs: 30_000,
    class: 'A',
    envVar: 'T3MP3ST_HTTP_TIMEOUT_MS',
    restartRequired: false,
    blurb: 'Default per-request budget for HTTP recon/vuln probes. Bounded per-operation overrides (shorter health probes, longer downloads) remain derived/fixed where source semantics justify them.',
  },
] as const;

const BY_KEY = new Map(TIMEOUT_REGISTRY.map((s) => [s.key, s]));

export function getTimeoutSpec(key: string): TimeoutSpec | undefined {
  return BY_KEY.get(key);
}

/** Read a positive finite env override, else undefined. Never returns 0/negative/NaN. */
export function readEnvTimeout(envVar: string | undefined): number | undefined {
  if (!envVar) return undefined;
  const raw = process.env[envVar];
  if (raw == null || raw.trim() === '') return undefined;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

/**
 * Resolve the EFFECTIVE value for a key with precedence UI override > env > default, clamped to the
 * spec bounds. `uiValue` is the persisted UI override (ms), or undefined when unset.
 * Returns the value plus its source for honest display.
 */
export function resolveTimeout(
  key: string,
  uiValue?: number,
): { valueMs: number; source: 'ui' | 'env' | 'default'; envPresent: boolean } {
  const spec = BY_KEY.get(key);
  if (!spec) throw new Error(`Unknown timeout setting: ${key}`);
  const envMs = readEnvTimeout(spec.envVar);

  if (uiValue != null && Number.isFinite(uiValue)) {
    return { valueMs: clamp(spec, uiValue), source: 'ui', envPresent: envMs != null };
  }
  if (envMs != null) {
    return { valueMs: clamp(spec, envMs), source: 'env', envPresent: true };
  }
  return { valueMs: spec.defaultMs, source: 'default', envPresent: false };
}

function clamp(spec: TimeoutSpec, ms: number): number {
  return Math.min(spec.maxMs, Math.max(spec.minMs, Math.round(ms)));
}

/**
 * Validate a proposed value for a key. Rejects unknown keys, non-finite / out-of-bounds values,
 * and Class-C (fixed) settings. Never permits 0 = infinite.
 */
export function validateTimeoutValue(key: string, ms: number): { ok: true; clamped: number } | { ok: false; error: string } {
  const spec = BY_KEY.get(key);
  if (!spec) return { ok: false, error: `Unknown timeout setting: ${key}` };
  if (spec.class === 'C') return { ok: false, error: `${spec.label} is a fixed safety invariant and is not configurable` };
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return { ok: false, error: `${spec.label} must be a finite number` };
  if (ms <= 0) return { ok: false, error: `${spec.label} must be > 0 (no "0 = infinite")` };
  if (ms < spec.minMs || ms > spec.maxMs) {
    return { ok: false, error: `${spec.label} must be between ${spec.minMs}ms and ${spec.maxMs}ms` };
  }
  return { ok: true, clamped: clamp(spec, ms) };
}

export interface HierarchyConflict {
  supervisor: string;
  supervisorLabel: string;
  child: string;
  childLabel: string;
  supervisorMs: number;
  childMs: number;
  requiredMinMs: number;
  message: string;
}

/**
 * Cross-validate the parent/child timeout hierarchy. A supervisor (e.g. dispatch backstop) must be
 * >= max(child execution windows) + its grace interval, otherwise it will false-timeout healthy
 * work and manufacture late-success races. `values` maps key -> proposed/effective ms (defaults
 * filled in by the caller for unspecified keys).
 */
export function validateTimeoutHierarchy(values: Record<string, number>): HierarchyConflict[] {
  const conflicts: HierarchyConflict[] = [];
  for (const spec of TIMEOUT_REGISTRY) {
    if (!spec.supervises || spec.supervises.length === 0) continue;
    const supMs = values[spec.key] ?? spec.defaultMs;
    const grace = spec.graceMs ?? 0;
    for (const childKey of spec.supervises) {
      const child = BY_KEY.get(childKey);
      if (!child) continue;
      const childMs = values[childKey] ?? child.defaultMs;
      const requiredMin = childMs + grace;
      if (supMs < requiredMin) {
        conflicts.push({
          supervisor: spec.key,
          supervisorLabel: spec.label,
          child: childKey,
          childLabel: child.label,
          supervisorMs: supMs,
          childMs,
          requiredMinMs: requiredMin,
          message:
            `${spec.label} (${Math.round(supMs / 1000)}s) must be at least ${child.label} ` +
            `(${Math.round(childMs / 1000)}s) + ${Math.round(grace / 1000)}s reconciliation grace = ` +
            `${Math.round(requiredMin / 1000)}s. Otherwise every slow-but-healthy task becomes a ` +
            `false timeout + late-success race.`,
        });
      }
    }
  }
  return conflicts;
}

/** Convert ms to a friendly display string in the spec's unit. */
export function formatTimeout(spec: TimeoutSpec, ms: number): string {
  if (spec.unit === 'count') return `${Math.round(ms)} attempts`;
  if (spec.unit === 'minutes') return `${(ms / 60000).toFixed(ms % 60000 === 0 ? 0 : 1)} min`;
  return `${(ms / 1000).toFixed(ms % 1000 === 0 ? 0 : 1)} s`;
}
