/**
 * The live verification gate — the honesty spine, IN the engine path.
 *
 * The disclosure-grade gates (scripts/verify-finding.mjs: anchors, poc ladder,
 * refuter panel, novelty) run on hand-authored finding JSON at the CLI. This is
 * their in-process counterpart for live, operator-produced findings: it refuses
 * to let a Finding be marked `verified` unless it is actually backed by real tool
 * output — provenance-strict, applied to the autonomous swarm, not beside it.
 *
 * The principle is the same one disclosure-gen enforces: a claim is only as strong
 * as its provenance. Prose is not evidence. A severity assertion with no evidence
 * is an overclaim. This is the door — not a decoration next to it.
 */

import type { Finding } from '../types/index.js';
import { assessClaimSupport, CATEGORY_OBSERVATION } from './classification.js';

/** Evidence types that represent real machine/tool output (vs a human note). */
const TOOL_EVIDENCE = new Set(['output', 'command', 'response', 'request', 'log', 'file']);

export type LiveProvenance = 'none' | 'context' | 'tool';

export interface LiveGateResult {
  passed: boolean;
  provenance: LiveProvenance;
  reasons: string[];
  checkedAt: number;
  /** Deterministic evidence-vs-claim verdict — separate axis from provenance. */
  support: ReturnType<typeof assessClaimSupport>;
  /**
   * TRUE only when the finding is BOTH tool-proven AND its asserted category is supported by that
   * evidence (and is not an inherently observation-only category). This is the bar for calling a
   * finding a demonstrated capability. `passed` alone means only "has tool provenance".
   */
  capabilityVerified: boolean;
}

/**
 * Gate a live finding. PASS only when the claim is backed by real tool output.
 * Honest by construction: it never invents provenance, and it states WHY it blocked.
 *
 * Two independent honesty axes are now enforced:
 *   1. PROVENANCE — is there real tool output attached? (the original gate)
 *   2. SUPPORT    — does that evidence actually demonstrate the asserted category? (new)
 * A "CRITICAL rce" whose only evidence is a cleartext-HTTP observation now fails support even when
 * it passes provenance, so it is NOT stamped verified and its severity is capped by the audit.
 */
export function gateLiveFinding(f: Finding): LiveGateResult {
  const reasons: string[] = [];
  const evidence = Array.isArray(f.evidence) ? f.evidence : [];
  const toolEv = evidence.filter((e) => e && TOOL_EVIDENCE.has(e.type) && String(e.content || '').trim().length > 0);

  if (toolEv.length === 0) {
    reasons.push('no tool-output evidence (output/command/response/log/file) — provenance-strict requires a finding be backed by real tool output, not prose');
  }
  if ((f.severity === 'critical' || f.severity === 'high') && evidence.length === 0) {
    reasons.push(`${f.severity} severity asserted with zero evidence — severity must be backed by evidence`);
  }

  // Axis 2 — evidence-vs-claim support. SEPARATE verdict from provenance; attached to the finding
  // for the operator and surfaced via `support`/`capabilityVerified`, NOT folded into `passed`
  // (which stays a pure provenance signal). The support rationale is recorded in `reasons` for
  // visibility but does not by itself fail provenance when tool output exists.
  const support = assessClaimSupport(f);
  f.claimSupport = support;

  const provenance: LiveProvenance = toolEv.length > 0 ? 'tool' : (evidence.length > 0 ? 'context' : 'none');
  // passed === provenance gate only (tool output present, and no zero-evidence high/critical claim).
  const passed = reasons.length === 0;
  if (support.supportLevel === 'unsupported') {
    reasons.push(`claim category '${support.category}' not demonstrated by the attached evidence — ${support.rationale}`);
  }
  const capabilityVerified =
    provenance === 'tool' &&
    support.supportLevel === 'supported' &&
    !CATEGORY_OBSERVATION.has(support.category);
  return { passed, provenance, reasons, checkedAt: Date.now(), support, capabilityVerified };
}
