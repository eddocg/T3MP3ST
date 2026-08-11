/**
 * T3MP3ST Analysis Engine
 *
 * Report generation and findings analysis.
 */

import type {
  Report,
  Finding,
  ExecutiveSummary,
  AttackPath,
  Recommendation,
  Severity,
} from '../types/index.js';
import type { EvidenceVault } from '../evidence/index.js';
import type { TargetEnvironment } from '../target/index.js';
import type { MissionControl } from '../mission/index.js';
import type { OpsecController } from '../opsec/index.js';
import { randomUUID } from 'crypto';
import { SEVERITY_SCORES } from '../evidence/index.js';
import { auditedSeverity, capabilitySupported } from '../evidence/classification.js';
import { redactString } from '../redact.js';

// =============================================================================
// ANALYSIS ENGINE
// =============================================================================

export class AnalysisEngine {
  private vault: EvidenceVault;
  private targetEnv: TargetEnvironment;

  constructor(
    vault: EvidenceVault,
    targetEnv: TargetEnvironment,
    _mission: MissionControl,
    _opsec: OpsecController
  ) {
    this.vault = vault;
    this.targetEnv = targetEnv;
    // mission and opsec are available for future threat modeling and risk analysis
  }

  /**
   * Generate a report
   */
  generateReport(
    missionId: string,
    type: Report['type'] = 'full_report'
  ): Report {
    const findings = this.vault.getAllFindings();
    const targetStats = this.targetEnv.getStats();
    const vaultStats = this.vault.getStats();

    const summary = this.generateExecutiveSummary(findings, targetStats, vaultStats);
    const attackPaths = this.generateAttackPaths(findings);
    const recommendations = this.generateRecommendations(findings);

    return {
      id: randomUUID(),
      missionId,
      type,
      generatedAt: Date.now(),
      summary,
      findings,
      attackPaths,
      recommendations,
    };
  }

  /**
   * Generate executive summary
   */
  private generateExecutiveSummary(
    findings: Finding[],
    targetStats: ReturnType<TargetEnvironment['getStats']>,
    vaultStats: ReturnType<EvidenceVault['getStats']>
  ): ExecutiveSummary {
    // Bucket by AUDITED severity (asserted severity capped by what the attached evidence
    // demonstrates) — report severity must never outrun the evidence-support model.
    const auditedCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) auditedCounts[auditedSeverity(f)]++;

    // Determine overall risk rating
    let riskRating: Severity = 'info';
    if (auditedCounts.critical > 0) riskRating = 'critical';
    else if (auditedCounts.high > 0) riskRating = 'high';
    else if (auditedCounts.medium > 0) riskRating = 'medium';
    else if (auditedCounts.low > 0) riskRating = 'low';

    const overview = this.generateOverviewText(findings, targetStats, riskRating);

    return {
      overview,
      riskRating,
      criticalFindings: auditedCounts.critical,
      highFindings: auditedCounts.high,
      mediumFindings: auditedCounts.medium,
      lowFindings: auditedCounts.low,
      infoFindings: auditedCounts.info,
      successfulExploits: findings.filter(f => f.exploitedAt).length,
      credentialsHarvested: vaultStats.totalCredentials,
      systemsCompromised: targetStats.owned,
    };
  }

  /**
   * Generate overview text
   */
  private generateOverviewText(
    findings: Finding[],
    targetStats: ReturnType<TargetEnvironment['getStats']>,
    riskRating: Severity
  ): string {
    const totalFindings = findings.length;
    const criticalHigh = findings.filter(
      f => ['critical', 'high'].includes(auditedSeverity(f))
    ).length;

    if (totalFindings === 0) {
      return 'No security vulnerabilities were identified during this assessment.';
    }

    let overview = `During the security assessment, ${totalFindings} finding${totalFindings === 1 ? ' was' : 's were'} identified`;

    if (criticalHigh > 0) {
      overview += `, including ${criticalHigh} critical or high-severity issue${criticalHigh === 1 ? '' : 's'} that require immediate attention`;
    }

    overview += `. The overall risk rating for this assessment is ${riskRating.toUpperCase()}.`;

    if (targetStats.owned > 0) {
      overview += ` ${targetStats.owned} system${targetStats.owned === 1 ? ' was' : 's were'} successfully compromised during testing.`;
    }

    return overview;
  }

  /**
   * Generate attack paths from findings
   */
  private generateAttackPaths(findings: Finding[]): AttackPath[] {
    const paths: AttackPath[] = [];

    // Group findings by target
    const byTarget = new Map<string, Finding[]>();
    for (const finding of findings) {
      const existing = byTarget.get(finding.targetId) || [];
      existing.push(finding);
      byTarget.set(finding.targetId, existing);
    }

    // Create attack paths for targets with multiple findings
    for (const [targetId, targetFindings] of byTarget) {
      if (targetFindings.length >= 2) {
        const sortedFindings = targetFindings.sort(
          (a, b) => a.discoveredAt - b.discoveredAt
        );

        const maxSeverity = sortedFindings.reduce((max, f) => {
          return SEVERITY_SCORES[f.severity] > SEVERITY_SCORES[max]
            ? f.severity
            : max;
        }, 'info' as Severity);

        paths.push({
          id: randomUUID(),
          name: `Attack Chain - ${targetId.substring(0, 8)}`,
          description: `Attack path through ${targetFindings.length} findings on target`,
          steps: sortedFindings.map(
            f => `${f.title} (${f.severity})`
          ),
          findings: sortedFindings.map(f => f.id),
          impactLevel: maxSeverity,
        });
      }
    }

    return paths;
  }

  /**
   * Generate recommendations from findings
   */
  private generateRecommendations(findings: Finding[]): Recommendation[] {
    const recommendations: Recommendation[] = [];

    // Group by severity for prioritization
    const criticalFindings = findings.filter(f => f.severity === 'critical');
    const highFindings = findings.filter(f => f.severity === 'high');
    const mediumFindings = findings.filter(f => f.severity === 'medium');

    // Critical findings get immediate priority
    for (const finding of criticalFindings) {
      recommendations.push({
        id: randomUUID(),
        findingId: finding.id,
        priority: 'immediate',
        title: `Remediate: ${finding.title}`,
        description: finding.remediation || `Address the critical vulnerability: ${finding.description}`,
        effort: this.estimateEffort(finding),
        impact: 'high',
      });
    }

    // High findings get short-term priority
    for (const finding of highFindings) {
      recommendations.push({
        id: randomUUID(),
        findingId: finding.id,
        priority: 'short_term',
        title: `Remediate: ${finding.title}`,
        description: finding.remediation || `Address the high-severity vulnerability: ${finding.description}`,
        effort: this.estimateEffort(finding),
        impact: 'high',
      });
    }

    // Medium findings get long-term priority
    for (const finding of mediumFindings) {
      recommendations.push({
        id: randomUUID(),
        findingId: finding.id,
        priority: 'long_term',
        title: `Address: ${finding.title}`,
        description: finding.remediation || `Mitigate the medium-severity issue: ${finding.description}`,
        effort: this.estimateEffort(finding),
        impact: 'medium',
      });
    }

    return recommendations;
  }

  /**
   * Estimate remediation effort
   */
  private estimateEffort(finding: Finding): 'low' | 'medium' | 'high' {
    // Simple heuristic based on severity and evidence complexity
    if (finding.severity === 'critical') return 'high';
    if (finding.severity === 'high') return 'medium';
    if (finding.evidence.length > 3) return 'medium';
    return 'low';
  }

  /**
   * Export report to Markdown
   */
  exportToMarkdown(report: Report): string {
    const lines: string[] = [];

    // Header
    lines.push('# Security Assessment Report');
    lines.push('');
    lines.push(`**Generated:** ${new Date(report.generatedAt).toISOString()}`);
    lines.push(`**Report Type:** ${report.type}`);
    lines.push('');

    // Executive Summary
    lines.push('## Executive Summary');
    lines.push('');
    lines.push(redactString(report.summary.overview));
    lines.push('');
    lines.push('### Risk Overview');
    lines.push('');
    lines.push(`| Severity | Count |`);
    lines.push(`|----------|-------|`);
    lines.push(`| Critical | ${report.summary.criticalFindings} |`);
    lines.push(`| High | ${report.summary.highFindings} |`);
    lines.push(`| Medium | ${report.summary.mediumFindings} |`);
    lines.push(`| Low | ${report.summary.lowFindings} |`);
    lines.push(`| Info | ${report.summary.infoFindings} |`);
    lines.push('');

    // Key Metrics
    lines.push('### Key Metrics');
    lines.push('');
    lines.push(`- **Overall Risk Rating:** ${report.summary.riskRating.toUpperCase()}`);
    lines.push(`- **Successful Exploits:** ${report.summary.successfulExploits}`);
    lines.push(`- **Credentials Harvested:** ${report.summary.credentialsHarvested}`);
    lines.push(`- **Systems Compromised:** ${report.summary.systemsCompromised}`);
    lines.push('');

    // Findings
    lines.push('## Findings');
    lines.push('');

    const sortedFindings = [...report.findings].sort(
      (a, b) => SEVERITY_SCORES[auditedSeverity(b)] - SEVERITY_SCORES[auditedSeverity(a)]
    );

    for (const finding of sortedFindings) {
      lines.push(`### ${redactString(finding.title)}`);
      lines.push('');
      // Severity presentation follows the evidence-support model: the AUDITED severity (asserted
      // capped by what the attached evidence demonstrates) is the headline; the asserted claim is
      // preserved alongside when the evidence does not bear it. An unverified claim NEVER renders
      // as a mature high-severity row.
      const audited = auditedSeverity(finding);
      lines.push(`**Severity:** ${audited.toUpperCase()}${audited !== finding.severity ? ` (asserted ${finding.severity.toUpperCase()} — capped: ${finding.claimSupport?.rationale ?? 'evidence does not support the claimed severity'})` : ''}`);
      const gate = finding.verifyGate;
      const verified = finding.verifiedAt != null;
      // Truthful verification vocabulary: an evidence-SUPPORTED observation (e.g. reflected ACAO)
      // is reported as exactly that — never as a demonstrated capability, and never as
      // "no tool-backed evidence" when evidence is attached but the gate has not run.
      const verificationLabel = verified
        ? 'verified (capability demonstrated)'
        : gate?.capabilityVerified
          ? 'capability-verified'
          : finding.claimSupport?.supportLevel === 'supported'
            ? (capabilitySupported(finding) ? 'evidence-supported' : 'evidence-supported observation — not a demonstrated capability')
            : gate?.passed
              ? 'unverified — provenance only'
              : finding.evidence.length > 0
                ? 'unverified — evidence present, not yet gated'
                : 'unverified — no tool-backed evidence';
      lines.push(`**Verification:** ${verificationLabel}`);
      if (finding.cvss) lines.push(`**CVSS:** ${finding.cvss}`);
      if (finding.cve?.length) lines.push(`**CVE:** ${finding.cve.join(', ')}`);
      lines.push('');
      lines.push('**Description:**');
      lines.push(redactString(finding.description));
      lines.push('');

      if (finding.remediation) {
        lines.push('**Remediation:**');
        lines.push(redactString(finding.remediation));
        lines.push('');
      }

      if (finding.evidence.length > 0) {
        lines.push('**Evidence:**');
        for (const evidence of finding.evidence) {
          // Serialize intentionally — tool, timestamp, redacted content summary. Never implicit
          // object stringification.
          const tool = evidence.metadata?.tool ? ` · tool: ${evidence.metadata.tool}` : '';
          const when = evidence.timestamp ? ` · ${new Date(evidence.timestamp).toISOString()}` : '';
          const content = redactString(String(evidence.content ?? ''));
          lines.push(`- [${evidence.type}]${tool}${when}: \`${content.substring(0, 100)}${content.length > 100 ? '...' : ''}\``);
        }
        lines.push('');
      }
    }

    // Attack Paths
    if (report.attackPaths.length > 0) {
      lines.push('## Attack Paths');
      lines.push('');

      for (const path of report.attackPaths) {
        lines.push(`### ${redactString(path.name)}`);
        lines.push('');
        lines.push(`**Impact Level:** ${path.impactLevel.toUpperCase()}`);
        lines.push('');
        lines.push(redactString(path.description));
        lines.push('');
        lines.push('**Steps:**');
        for (let i = 0; i < path.steps.length; i++) {
          lines.push(`${i + 1}. ${redactString(path.steps[i])}`);
        }
        lines.push('');
      }
    }

    // Recommendations
    if (report.recommendations.length > 0) {
      lines.push('## Recommendations');
      lines.push('');

      const byPriority = {
        immediate: report.recommendations.filter(r => r.priority === 'immediate'),
        short_term: report.recommendations.filter(r => r.priority === 'short_term'),
        long_term: report.recommendations.filter(r => r.priority === 'long_term'),
      };

      if (byPriority.immediate.length > 0) {
        lines.push('### Immediate Priority');
        lines.push('');
        for (const rec of byPriority.immediate) {
          lines.push(`- **${redactString(rec.title)}** (Effort: ${rec.effort})`);
          lines.push(`  ${redactString(rec.description)}`);
        }
        lines.push('');
      }

      if (byPriority.short_term.length > 0) {
        lines.push('### Short-Term Priority');
        lines.push('');
        for (const rec of byPriority.short_term) {
          lines.push(`- **${redactString(rec.title)}** (Effort: ${rec.effort})`);
          lines.push(`  ${redactString(rec.description)}`);
        }
        lines.push('');
      }

      if (byPriority.long_term.length > 0) {
        lines.push('### Long-Term Priority');
        lines.push('');
        for (const rec of byPriority.long_term) {
          lines.push(`- **${redactString(rec.title)}** (Effort: ${rec.effort})`);
          lines.push(`  ${redactString(rec.description)}`);
        }
        lines.push('');
      }
    }

    return lines.join('\n');
  }
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

export function createAnalysisEngine(
  vault: EvidenceVault,
  targetEnv: TargetEnvironment,
  mission: MissionControl,
  opsec: OpsecController
): AnalysisEngine {
  return new AnalysisEngine(vault, targetEnv, mission, opsec);
}
