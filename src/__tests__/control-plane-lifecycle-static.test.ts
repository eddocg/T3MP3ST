import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { briefToDirective, type MissionBrief } from '../admiral/index.js';

const uiSource = readFileSync(join(process.cwd(), 'docs/index.html'), 'utf8');
const generalSource = readFileSync(join(process.cwd(), 'src/general/index.ts'), 'utf8');
const missionSource = readFileSync(join(process.cwd(), 'src/mission/index.ts'), 'utf8');

function baseBrief(overrides: Partial<MissionBrief> = {}): MissionBrief {
  return {
    objective: 'Assess the staging API',
    target: 'https://staging.api.example.com',
    family: 'pentest',
    scope: 'exact origin only',
    fidelity: 'live',
    ...overrides,
  };
}

describe('operator directives materially reach the planner Directive', () => {
  it('folds free-text operator directives into Directive.constraints (not a cosmetic field)', () => {
    const directive = briefToDirective(baseBrief({
      directives: 'Cap requests to 2/sec. Do not attempt account takeover.',
    }));
    // The planner prompt inlines directive.constraints verbatim, so this is the material seam.
    expect(directive.constraints).toContain('OPERATOR DIRECTIVES:');
    expect(directive.constraints).toContain('Cap requests to 2/sec.');
    expect(directive.constraints).toContain('Do not attempt account takeover.');
  });

  it('omits the directives clause entirely when none are supplied', () => {
    const directive = briefToDirective(baseBrief());
    expect(directive.constraints).not.toContain('OPERATOR DIRECTIVES');
    // The existing family/fidelity constraints must still be present (no regression).
    expect(directive.constraints).toContain('mission_family=pentest');
    expect(directive.constraints).toContain('fidelity=live');
  });

  it('trims blank directives so whitespace-only input adds nothing', () => {
    const directive = briefToDirective(baseBrief({ directives: '   \n  ' }));
    expect(directive.constraints).not.toContain('OPERATOR DIRECTIVES');
  });
});

describe('Guided Hunt wizard captures + threads operator directives', () => {
  it('has an optional directives field, captures keystrokes, and rides the brief', () => {
    expect(uiSource).toContain('id="admDirectives"');
    expect(uiSource).toMatch(/window\.admiralDirectivesInput = function\(\)/);
    // admiralSet syncs the textarea before a re-render so a depth/autonomy click never drops it.
    expect(uiSource).toMatch(/window\.admiralSet\s*=\s*function\(k,v\)\{ const d=document\.getElementById\('admDirectives'\)/);
    // _admBrief attaches directives onto the brief object that is POSTed to /api/admiral/launch.
    expect(uiSource).toMatch(/if \(directives\) brief\.directives = directives/);
    // Honest labeling: the field is advisory-to-planner, not a scope-gate change.
    expect(uiSource).toContain('does <b>not</b> change the enforced target scope');
  });
});

describe('single mission-state authority reconciles the War Room from the backend', () => {
  it('exposes one reconcile function driven by /api/mission/status .active', () => {
    expect(uiSource).toMatch(/async function t3mpReconcileMissionState\(/);
    expect(uiSource).toContain("window.t3mpReconcileMissionState = t3mpReconcileMissionState");
    // Reconcile is fed by the authoritative poll AND the lifecycle SSE transitions.
    expect(uiSource).toMatch(/try \{ t3mpReconcileMissionState\(m\); \} catch/);
    expect(uiSource).toMatch(/mission:started[\s\S]*?window\.t3mpReconcileMissionState\?\.\(\)/);
    expect(uiSource).toMatch(/mission:stopped[\s\S]*?window\.t3mpReconcileMissionState\?\.\(\)/);
  });

  it('clears the stale PLANNING chip while a backend mission is live', () => {
    const fn = uiSource.slice(
      uiSource.indexOf('async function t3mpReconcileMissionState('),
      uiSource.indexOf('window.t3mpReconcileMissionState = t3mpReconcileMissionState'),
    );
    // Active: header + banner + chip reflect a running mission; EXECUTE reflects "already running".
    expect(fn).toMatch(/if \(badge && badge\.textContent === 'PLANNING'\)/);
    expect(fn).toMatch(/MISSION RUNNING/);
    // Terminal: finalize only when a backend mission was actually seen (don't stomp the sim flow).
    expect(fn).toMatch(/__t3mpBackendMissionSeen/);
    expect(fn).toMatch(/__t3mpBackendMissionFinalized/);
    expect(fn).toMatch(/COMPLETE/);
  });
});

describe('honest labeling where backend behavior is correct but was mislabeled', () => {
  it('renames the analyst phase to verification/synthesis and states re-tests are confirmatory', () => {
    expect(missionSource).toContain('Finding Verification & Report Synthesis');
    expect(missionSource).toMatch(/CONFIRMATORY re-tests/);
    expect(missionSource).toMatch(/does not open new discovery or broaden scope/);
  });

  it('frames SITREP receipt/readiness counts as advisory, not hard gates', () => {
    expect(generalSource).toContain('readinessIsAdvisory: true');
    expect(generalSource).toMatch(/ADVISORY evidence-maturity signals, not hard gates/);
    expect(generalSource).toMatch(/Do NOT claim the board is "blocked from closure"/);
  });

  it('labels the plan RoE scope prose as intent, with host-level enforcement noted', () => {
    expect(uiSource).toContain('planner intent, not the exact gate');
  });
});

describe('evidence-maturity ladder distinguishes observation from verified capability', () => {
  it('classifies findings from backend gate/retest signals, not the model severity claim', () => {
    expect(uiSource).toMatch(/function findingMaturity\(f\)/);
    for (const rung of ['observation', 'candidate', 'finding', 'verified', 'report-ready']) {
      expect(uiSource).toContain(`'${rung}'`);
    }
    // The SSE finding handler must carry the verification signals through (else the ladder is blind).
    expect(uiSource).toMatch(/verifyGate: finding\.verifyGate \|\| null/);
    expect(uiSource).toMatch(/verifiedAt: finding\.verifiedAt \|\| null/);
    // report-ready requires BOTH tool-verification AND a passed retest.
    expect(uiSource).toMatch(/if \(verified && retestPassed\) return \{ key:'report-ready'/);
  });

  it('distinguishes tool-PROVENANCE from demonstrated CAPABILITY (verifyGate.passed != verified)', () => {
    // A tool-backed observation whose category outruns its evidence is "tool-proven", NOT "verified".
    expect(uiSource).toContain("'tool-proven'");
    // verified (capability) requires evidence-supported category, not merely tool output present.
    expect(uiSource).toMatch(/verified = capabilityVerified/);
    // The tool-proven rung must warn that provenance is not a demonstrated capability.
    expect(uiSource).toMatch(/NOT the same as a demonstrated attacker capability/);
  });
});
