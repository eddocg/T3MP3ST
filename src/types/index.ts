/**
 * T3MP3ST Core Type Definitions
 */

// =============================================================================
// LLM CONFIGURATION
// =============================================================================

export type LLMProvider = 'openrouter' | 'venice' | 'anthropic' | 'openai' | 'xai' | 'gemini' | 'litellm' | 'deepseek' | 'huggingface' | 'nanogpt' | 'codex' | 'mock' | 'local' | 'local-agent';

export interface LLMConfig {
  provider: LLMProvider;
  model: string;
  apiKey?: string;
  baseUrl?: string;
  maxTokens?: number;
  temperature?: number;
  timeout?: number;
  /**
   * When true, force native Ollama / OpenAI-compatible function calling. When
   * false, always use text-based tool contract injection. When unset, probe
   * on the first call and cache per-model.
   */
  nativeTools?: boolean;
  /**
   * Ordered model/provider ladder to fall back to when the PRIMARY model fails for
   * ANY reason it can't self-recover from — hard errors after same-model retries
   * (rate-limit, 5xx, timeout, auth, unavailable model, context-length) AND soft
   * failures (a refusal, or an empty/contentless 200). Empty/unset = no fallback.
   * Each entry overrides the primary config's matching fields.
   *
   * On a *refusal* specifically, the operation's REAL authorization context (scope
   * + human-approved gate + responsible disclosure) is restated before the next
   * model is tried — honest escalation, NO jailbreak / guardrail-bypass prompts.
   * A refusal that survives honest context + a model swap is respected.
   */
  fallbackChain?: FallbackEntry[];
}

/** One hop in an LLMConfig.fallbackChain ladder. */
export interface FallbackEntry {
  provider: LLMProvider;
  model: string;
  apiKey?: string;
  baseUrl?: string;
}

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  /** Tool calls requested by the assistant */
  toolCalls?: LLMToolCall[];
  /** ID of the tool call this message is a result for (role=tool) */
  toolCallId?: string;
  /** Tool name for tool result messages */
  name?: string;
}

export interface LLMResponse {
  content: string;
  model: string;
  /** Tool calls the model wants to make */
  toolCalls?: LLMToolCall[];
  usage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  finishReason?: string;
}

// =============================================================================
// LLM TOOL CALLING
// =============================================================================

/** Definition of a tool the LLM can invoke */
export interface LLMToolDefinition {
  name: string;
  description: string;
  parameters: {
    type: 'object';
    properties: Record<string, {
      type: string;
      description?: string;
      enum?: string[];
      items?: { type: string };
      default?: unknown;
      properties?: Record<string, {
        type: string;
        description?: string;
        enum?: string[];
      }>;
      required?: string[];
      additionalProperties?: boolean;
    }>;
    required?: string[];
  };
}

/** A tool call from the LLM response */
export interface LLMToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

// =============================================================================
// OPERATOR TYPES
// =============================================================================

export type OperatorArchetype =
  | 'recon'
  | 'scanner'
  | 'exploiter'
  | 'infiltrator'
  | 'exfiltrator'
  | 'ghost'
  | 'coordinator'
  | 'analyst';

export type OperatorStatus =
  | 'idle'
  | 'tasked'
  | 'executing'
  | 'cooldown'
  | 'burned'
  | 'exfiltrated';

export interface OperatorState {
  status: OperatorStatus;
  currentTask: string | null;
  completedTasks: number;
  failedTasks: number;
  findingsCount: number;
  credentialsCount: number;
  detectionRisk: number;
  lastActivityTime: number;
}

export interface OperatorConfig {
  maxDetectionRisk: number;
  cooldownMs: number;
  maxRetries: number;
  preferredTechniques: string[];
  avoidTechniques: string[];
  toolPreferences: string[];
}

// =============================================================================
// KILL CHAIN PHASES
// =============================================================================

export enum KillChainPhase {
  RECON = 'reconnaissance',
  WEAPONIZE = 'weaponization',
  DELIVER = 'delivery',
  EXPLOIT = 'exploitation',
  INSTALL = 'installation',
  C2 = 'command_and_control',
  ACTIONS = 'actions_on_objectives',
}

// =============================================================================
// TARGET TYPES
// =============================================================================

export type TargetType =
  | 'web_application'
  | 'api'
  | 'network'
  | 'host'
  | 'database'
  | 'cloud'
  | 'mobile'
  | 'iot'
  | 'container';

export type TargetZone =
  | 'external'
  | 'dmz'
  | 'internal'
  | 'restricted'
  | 'airgapped';

export type TargetStatus =
  | 'discovered'
  | 'scanning'
  | 'vulnerable'
  | 'exploited'
  | 'owned'
  | 'exfiltrated';

export interface Target {
  id: string;
  name: string;
  type: TargetType;
  zone: TargetZone;
  status: TargetStatus;
  address: string;
  port?: number;
  protocol?: string;
  services?: Service[];
  vulnerabilities?: Vulnerability[];
  credentials?: Credential[];
  metadata?: Record<string, unknown>;
  discoveredAt: number;
  lastScannedAt?: number;
  ownedAt?: number;
}

export interface Service {
  name: string;
  port: number;
  protocol: string;
  version?: string;
  banner?: string;
  vulnerabilities?: string[];
}

// =============================================================================
// FINDING TYPES
// =============================================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  title: string;
  description: string;
  /**
   * EFFECTIVE severity — audited at EvidenceVault storage/merge time against the deterministic
   * evidence-support cap (claimSupport.severityCap). This is the value SSE events, alerts,
   * reports, and severity counts consume. A source can never out-assert what its evidence bears.
   */
  severity: Severity;
  /**
   * The severity the SOURCE (scanner template / builtin heuristic / model debrief) originally
   * asserted, preserved verbatim for audit/debugging — never consumed for alerts or reporting.
   * Captured at first storage; on merge the highest assertion seen is retained.
   */
  assertedSeverity?: Severity;
  targetId: string;
  operatorId: string;
  phase: KillChainPhase;
  cvss?: number;
  cve?: string[];
  cwe?: string[];
  evidence: Evidence[];
  remediation?: string;
  references?: string[];
  discoveredAt: number;
  verifiedAt?: number;
  exploitedAt?: number;
  /** Result of the live verification gate — present once verifyFinding() has run. */
  verifyGate?: { passed: boolean; provenance: 'none' | 'context' | 'tool'; reasons: string[]; checkedAt: number; capabilityVerified?: boolean };
  /**
   * Vulnerability family / claim category asserted by the SOURCE (scanner template, builtin
   * heuristic, or model debrief) — e.g. 'rce', 'credential', 'cors', 'sqli'. This is preserved
   * verbatim and NEVER rewritten by the support assessment; the deterministic check in
   * evidence/classification.ts judges whether the attached evidence actually supports it.
   */
  category?: string;
  /**
   * What kind of record this is: 'observation' (scanner/lead — a header, version, reflected ACAO,
   * open port) vs 'vulnerability' (evidence of a security-boundary failure or attacker capability).
   * Scanner output starts as an observation; it is promoted only by demonstrated impact.
   */
  observationClass?: 'observation' | 'vulnerability';
  /**
   * Provenance: were the configured target credentials/headers actually attached to the request
   * that produced this finding? Means "credential headers were applied" — NOT that authentication
   * or authorization succeeded. Absent/undefined = unknown.
   */
  authContextApplied?: boolean;
  /** Principal id attached for this request, if any. Never a secret. */
  principalId?: string;
  authMode?: 'inherit' | 'none';
  authStatusAtRequest?: 'unknown' | 'live' | 'stale' | 'refreshing' | 'failed';
  /**
   * Deterministic evidence-vs-claim support assessment (see evidence/classification.ts). Present
   * once the claim has been evaluated. `supportLevel` is the gate's verdict on whether the
   * attached evidence supports the asserted `category`; `severityCap` is the highest severity the
   * evidence will bear. The source-asserted `severity`/`category` above are left untouched so the
   * operator can see both the claim and the audit of it.
   */
  claimSupport?: ClaimSupport;
}

/** Result of the deterministic claim-vs-evidence assessment. Pure audit; never mutates the claim. */
export interface ClaimSupport {
  /** The category the assessment evaluated (echoed from the asserted/derived category). */
  category: string;
  /** Does the attached evidence support the asserted category? 'supported' | 'unsupported' | 'unverifiable'. */
  supportLevel: 'supported' | 'unsupported' | 'unverifiable';
  /** Highest severity the attached evidence will bear for this category. */
  severityCap: Severity;
  /** Human/auditor-readable reason for the verdict. */
  rationale: string;
  checkedAt: number;
}

export interface Evidence {
  type: 'screenshot' | 'log' | 'request' | 'response' | 'file' | 'command' | 'output';
  content: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

// =============================================================================
// VULNERABILITY TYPES
// =============================================================================

export interface Vulnerability {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  cvss?: number;
  cve?: string[];
  cwe?: string[];
  affected?: string;
  exploitAvailable?: boolean;
  patchAvailable?: boolean;
  references?: string[];
}

// =============================================================================
// CREDENTIAL TYPES
// =============================================================================

export type CredentialType =
  | 'password'
  | 'hash'
  | 'token'
  | 'api_key'
  | 'ssh_key'
  | 'certificate'
  | 'session'
  | 'cookie';

export interface Credential {
  id: string;
  type: CredentialType;
  username?: string;
  secret: string;
  domain?: string;
  targetId?: string;
  source: string;
  discoveredAt: number;
  validatedAt?: number;
  privilegeLevel?: 'user' | 'admin' | 'system' | 'root';
}

// =============================================================================
// MISSION TYPES
// =============================================================================

export interface Mission {
  id: string;
  name: string;
  description?: string;
  objectives: string[];
  phases: KillChainPhase[];
  rules: RulesOfEngagement;
  status: 'planning' | 'active' | 'paused' | 'completed' | 'aborted';
  startedAt?: number;
  completedAt?: number;
  currentPhase: KillChainPhase;
  progress: number;
  /**
   * The operator's research objective class — ORTHOGONAL to the routed MissionFamily. A mission
   * can be family `web_api` while its objective class is `authorization_lifecycle`. This steers
   * which tasks are seeded (objective work vs. bounded prerequisite recon) and how completion is
   * reported. 'general' = no narrow objective (default; broad coverage across all phases with
   * eligible work — never auto-claimed as "full kill-chain coverage" at completion).
   */
  objectiveClass?: MissionObjectiveClass;
  /**
   * Whether the objective actually received evidence — distinct from "all tasks drained". Set at
   * completion. `untested` means the objective lane never ran; `blocked` means a required
   * prerequisite (second principal, owned resource, state fixture) was missing; `partial`/`met`
   * reflect how much of the objective hypothesis space was exercised.
   */
  objectiveOutcome?: MissionObjectiveOutcome;
  /** Why the mission terminated the way it did (plain-language, redaction-safe). Set at completion. */
  completionReason?: string;
  /**
   * The routed MissionFamily at launch (e.g. 'web_api'). Informational only — used so durable
   * ledger records (hypotheses/work orders) land in the correct lane. Optional for backward compat.
   */
  missionFamily?: MissionFamily;
  /**
   * Truthful per-phase disposition recorded as the mission LEAVES each phase. A phase with no
   * eligible work in the mission's objective lane is recorded `no_eligible_work` — never presented
   * as if it were normally executed. Phases whose objective work was blocked on a missing fixture
   * are recorded `blocked_prerequisite`.
   */
  phaseDispositions?: PhaseDisposition[];
  /**
   * PACING/ROE AUTHORIZATION: the operator (via launch flag or explicit directive language such
   * as "full port scan of all 65535 ports") authorized full-range (1-65535 / -p-) port sweeps for
   * this mission. When absent/false, autonomous operators are bounded to top-1000 windows and any
   * full-range request is clamped with a loud annotation. This is the normal planning/ROE seam
   * for the capability — not a hidden escape hatch.
   */
  allowFullRangeScans?: boolean;
}

/** Truthful record of how a kill-chain phase concluded for a mission. */
export interface PhaseDisposition {
  phase: KillChainPhase;
  /** executed = real tasks ran; blocked_prerequisite = objective work blocked on missing fixture;
   *  no_eligible_work = the objective lane had no work for this phase (NOT a successful execution);
   *  failed = required work failed (mission stalled). */
  disposition: 'executed' | 'blocked_prerequisite' | 'no_eligible_work' | 'failed';
  total: number;
  completed: number;
  failed: number;
  blocked: number;
  skipped: number;
  recordedAt: number;
}

export type MissionObjectiveClass = 'general' | 'authorization_lifecycle';

/**
 * The routed mission family taxonomy (canonical home — re-exported by resources/index.ts for
 * backward compatibility). Orthogonal to MissionObjectiveClass: a `web_api` mission may carry an
 * `authorization_lifecycle` objective.
 */
export type MissionFamily =
  | 'web_api'
  | 'ai_red_team'
  | 'cloud_infra'
  | 'smart_contract'
  | 'code_supply_chain'
  | 'crypto_secrets'
  | 'reverse_binary'
  | 'agent_warfare'
  | 'social_osint'
  | 'reporting_remediation';

export type MissionObjectiveOutcome =
  | 'untested'
  | 'blocked'
  | 'partial'
  | 'met'
  | 'exhausted'
  | 'unresolved';

/**
 * Complete derived mission/execution state for status + UI. NOT collapsed to "active means live".
 *  - idle:      no TempestCommand / no active mission (standby)
 *  - running:   active, not paused, no unresolved stall
 *  - paused:    operator-paused (paused=true, no stallReason)
 *  - stalled:   active:true AND paused:true AND stallReason set (blocked on failed required work)
 *  - completed: mission reached terminal success
 *  - aborted:   explicitly stopped/aborted by the operator (terminal, distinct from completed)
 */
export type MissionRunState = 'idle' | 'running' | 'paused' | 'stalled' | 'completed' | 'aborted';

export interface RulesOfEngagement {
  scope: string[];
  excludedTargets: string[];
  allowedTechniques: string[];
  forbiddenTechniques: string[];
  maxDetectionEvents: number;
  requireManualApproval: string[];
  timeWindow?: { start: number; end: number };
}

/**
 * One execution attempt of a task. Retries are NEW attempts appended here — the prior
 * timed-out/failed attempt is preserved verbatim for audit; history is never rewritten.
 */
export interface TaskAttempt {
  attemptId: string;
  /** 1-based attempt number. */
  n: number;
  startedAt: number;
  endedAt?: number;
  /** terminal outcome of THIS attempt only. */
  outcome: 'completed' | 'failed' | 'timeout' | 'timeout_late_success' | 'timeout_pending' | 'blocked';
  error?: string;
}

export interface Task {
  id: string;
  missionId: string;
  name: string;
  description: string;
  phase: KillChainPhase;
  operatorType: OperatorArchetype;
  /**
   * Lifecycle. `blocked` is a TERMINAL record state: the task represents objective work that cannot
   * execute because a required fixture (e.g. a second controlled principal / owned resource / state
   * transition) is unavailable. Blocked tasks are NEVER dispatched to operators, never hold a phase
   * open, and never become `completed` — they exist so the blocker is durable and auditable.
   */
  status: 'pending' | 'assigned' | 'in_progress' | 'completed' | 'failed' | 'skipped' | 'blocked';
  priority: number;
  dependencies: string[];
  assignedTo?: string;
  result?: TaskResult;
  createdAt: number;
  startedAt?: number;
  completedAt?: number;
  /**
   * Whether this task blocks phase advancement. Required (default true) tasks stall the mission on
   * failure and are NEVER skippable. Optional tasks may be explicitly skipped (terminal 'skipped',
   * never rewritten to 'completed'). Defaulted to true at creation; legacy tasks stay required.
   */
  required?: boolean;
  /** Immutable attempt history — attempt 1 failure/timeout stays visible after a retry. */
  attempts?: TaskAttempt[];
}

/**
 * Structured task disposition — reported by the operator's agent loop via the debrief contract,
 * NOT inferred from "the agent returned normally":
 *  - completed:        the planned work actually executed (findings or legitimate empty result)
 *  - partial:          the work EXECUTED and produced real coverage, but the operator declares a
 *                      required sub-objective could not be satisfied/verified — execution ≠ full
 *                      coverage; degrades the mission objectiveOutcome, never reads as "blocked"
 *  - blocked:          the planned work COULD NOT execute (missing capability / fixture / tool
 *                      contract) — terminal, never counted as coverage
 *  - no_eligible_work: the task ran and legitimately found nothing eligible to do (truthful
 *                      negative; does not count as executed coverage for its phase)
 *  - failed:           attempted but errored
 */
export type TaskDisposition = 'completed' | 'partial' | 'blocked' | 'no_eligible_work' | 'failed';

export interface TaskResult {
  success: boolean;
  output?: string;
  findings?: string[];
  credentials?: string[];
  nextTasks?: string[];
  error?: string;
  /** Structured outcome of the attempt — see TaskDisposition. Absent = legacy (success flag only). */
  disposition?: TaskDisposition;
  /** Human-readable reason for blocked/no_eligible_work/failed dispositions. */
  dispositionReason?: string;
}

// =============================================================================
// OPSEC TYPES
// =============================================================================

export type OpsecLevel = 'silent' | 'covert' | 'loud';

export interface OpsecConfig {
  level: OpsecLevel;
  maxDetectionEvents: number;
  cooldownAfterDetection: number;
  cleanupOnComplete: boolean;
  avoidDetection: boolean;
  jitterRange: [number, number];
  trafficBlending: boolean;
  loggingSanitization: boolean;
}

export interface DetectionEvent {
  id: string;
  type: 'waf' | 'ids' | 'edr' | 'siem' | 'honeypot' | 'manual' | 'unknown';
  severity: Severity;
  source: string;
  description: string;
  operatorId?: string;
  targetId?: string;
  timestamp: number;
  mitigated: boolean;
}

// =============================================================================
// COMMS TYPES
// =============================================================================

export interface Message {
  id: string;
  from: string;
  to: string | string[];
  channel: string;
  type: 'intel' | 'task' | 'alert' | 'status' | 'finding' | 'coordination';
  priority: 'low' | 'normal' | 'high' | 'critical';
  content: string;
  metadata?: Record<string, unknown>;
  timestamp: number;
}

// =============================================================================
// TOOL TYPES
// =============================================================================

/** A tool's risk tier — the catalog's `risk` vocabulary. Drives the approval + spicy-warning gate
 *  (see src/arsenal/approval.ts): intrusive/credential/dangerous require approval; credential/dangerous
 *  additionally fire a loud warning. Absent/safe/active tools are ungated. */
export type RiskTier = 'local_read' | 'passive' | 'active' | 'intrusive' | 'credential' | 'dangerous';

/** Structured error categories for tool failures — enables LLM feedback without leaking internals. */
export enum ToolErrorCategory {
  ScopeDenied = 'scope_denied',
  ToolNotFound = 'tool_not_found',
  Timeout = 'timeout',
  ExecutionError = 'execution_error',
  ValidationError = 'validation_error',
}

/** Structured error thrown by tool execution — carries category for LLM feedback and optional tool name. */
export class ToolError extends Error {
  constructor(
    public readonly category: ToolErrorCategory,
    message: string,
    public readonly toolName?: string,
  ) {
    super(message);
    this.name = 'ToolError';
  }
}

export interface CustomTool {
  name: string;
  description: string;
  category: string;
  handler: (context: ToolContext) => Promise<ToolResult>;
  parameters?: ToolParameter[];
  requiredPermissions?: string[];
  /** Risk tier carried from the catalog when the tool is a minted adapter — gates approval. */
  riskTier?: RiskTier;
}

export interface ToolParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  description: string;
  required: boolean;
  default?: unknown;
  /** Allowed values — constrains the parameter to a fixed set. */
  enum?: (string | number)[];
  /** Schema for array items (when type === 'array'). */
  items?: {
    type: string;
    description?: string;
    properties?: Record<string, ToolParameter>;
  };
  /** Nested object properties (when type === 'object'). */
  properties?: Record<string, ToolParameter>;
  /** Whether additional properties are allowed on object parameters. */
  additionalProperties?: boolean;
}

/** A single validation error produced by validateToolArgs. */
export interface ToolValidationError {
  field: string;
  message: string;
  received: unknown;
  expected: string;
}

export interface ToolContext {
  target?: Target;
  operator?: string;
  mission?: string;
  parameters: Record<string, unknown>;
}

/**
 * Simplified finding for tool results (tools don't have full context)
 */
export interface ToolFinding {
  title: string;
  severity: Severity;
  details: string;
  cvss?: number;
  cve?: string[];
  cwe?: string[];
  remediation?: string;
  /**
   * How this finding was produced — the provenance flag the honesty gate keys on:
   *  'tool'  = parsed from real tool output (has provenance, can be verified)
   *  'model' = asserted by the model in its debrief prose (NO provenance — the gate
   *            records it but refuses to mark it verified; prose is not evidence).
   */
  provenance?: 'tool' | 'model';
  /** For 'tool' provenance: the tool that produced it + the raw output backing the claim. */
  toolName?: string;
  toolOutput?: string;
  /** Source-asserted vulnerability category (e.g. 'cors', 'sqli'). Audited, never rewritten. */
  category?: string;
  /** 'observation' (scanner lead) vs 'vulnerability' (demonstrated boundary failure). */
  observationClass?: 'observation' | 'vulnerability';
  /** Provenance: were configured credential headers applied to the request? (Not "auth succeeded".) */
  authContextApplied?: boolean;
  /** Principal id attached for this request, if any. Never a secret. */
  principalId?: string;
  authMode?: 'inherit' | 'none';
  authStatusAtRequest?: 'unknown' | 'live' | 'stale' | 'refreshing' | 'failed';
}

export interface ToolResult {
  success: boolean;
  output?: string;
  findings?: ToolFinding[];
  credentials?: Credential[];
  error?: string;
  duration?: number;
}

// =============================================================================
// CONFIG TYPES
// =============================================================================

export interface TempestConfig {
  name: string;
  llm: LLMConfig;
  opsec?: Partial<OpsecConfig>;
  /**
   * Optional research objective class (orthogonal to MissionFamily) that steers task seeding and
   * completion reporting — e.g. 'authorization_lifecycle'. Defaults to 'general'.
   */
  objectiveClass?: MissionObjectiveClass;
  /** Free-text operator directive emphasis that steers the objective lane (advisory). */
  objectiveDirective?: string;
  /**
   * PACING/ROE authorization for full-range (1-65535 / -p-) port sweeps on the auto-created
   * mission. Explicit config wins; otherwise the mission detects explicit full-range language
   * in the objective directive. Absent = bounded top-1000 autonomous scans.
   */
  allowFullRangeScans?: boolean;
  /**
   * The routed MissionFamily for this run (e.g. 'web_api') — informational; stored on the Mission so
   * durable ledger records (hypotheses/work orders) are filed in the correct lane. Does NOT steer
   * task seeding (that is objectiveClass's job).
   */
  missionFamily?: MissionFamily;
  operators?: {
    maxConcurrent?: number;
    defaultConfig?: Partial<OperatorConfig>;
  };
  targets?: {
    maxConcurrent?: number;
  };
  tools?: CustomTool[];
  hooks?: RuntimeHooks;
}

export interface RuntimeHooks {
  onOperatorSpawned?: (operator: { id: string; archetype: OperatorArchetype }) => void;
  onOperatorStateChange?: (operator: { id: string }, newState: OperatorState) => void;
  onFindingDiscovered?: (finding: Finding, operator: { id: string }) => void;
  onCredentialHarvested?: (credential: Credential, operator: { id: string }) => void;
  onDetectionEvent?: (event: DetectionEvent) => void;
  onMissionPhaseChange?: (missionId: string, phase: KillChainPhase) => void;
  onTaskCompleted?: (task: Task) => void;
}

// =============================================================================
// REPORT TYPES
// =============================================================================

export interface Report {
  id: string;
  missionId: string;
  type: 'executive' | 'technical' | 'full_report' | 'findings_only';
  generatedAt: number;
  summary: ExecutiveSummary;
  findings: Finding[];
  attackPaths: AttackPath[];
  recommendations: Recommendation[];
  appendices?: Appendix[];
}

export interface ExecutiveSummary {
  overview: string;
  riskRating: Severity;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  infoFindings: number;
  successfulExploits: number;
  credentialsHarvested: number;
  systemsCompromised: number;
}

export interface AttackPath {
  id: string;
  name: string;
  description: string;
  steps: string[];
  findings: string[];
  impactLevel: Severity;
}

export interface Recommendation {
  id: string;
  findingId?: string;
  priority: 'immediate' | 'short_term' | 'long_term';
  title: string;
  description: string;
  effort: 'low' | 'medium' | 'high';
  impact: 'low' | 'medium' | 'high';
}

export interface Appendix {
  title: string;
  content: string;
}

// =============================================================================
// EVENT TYPES
// =============================================================================

export interface ScanProgressEvent {
  id: string;
  timestamp: number;
  kind: 'task_started' | 'thinking' | 'tool_call' | 'tool_result' | 'task_completed' | 'task_failed';
  operatorId: string;
  callsign: string;
  archetype: OperatorArchetype;
  taskId?: string;
  taskName?: string;
  toolName?: string;
  source?: 'agent' | 'backend_seeded';
  detail: string;
  success?: boolean;
}

export interface CommandEvents {
  'command:started': void;
  'command:stopped': void;
  'command:paused': void;
  'command:resumed': void;
  /** Resume was refused because required blockers remain (recovery gate). */
  'command:resume-refused': { blocking: Array<{ id: string; name: string; detail: string }>; note: string };
  /** A failed task was requeued as a new attempt. */
  'command:task-retried': { taskId: string };
  /** An optional failed task was explicitly skipped (terminal, not completed). */
  'command:task-skipped': { taskId: string };
  'tick': number;
  'operator:spawned': { id: string; archetype: OperatorArchetype };
  'operator:burned': { id: string };
  'finding:discovered': { finding: Finding; operatorId: string };
  'credential:harvested': { credential: Credential; operatorId: string };
  'target:owned': { target: Target; operatorId: string };
  'detection:triggered': DetectionEvent;
  'mission:phase_changed': { missionId: string; phase: KillChainPhase };
  /** Mission reached a terminal completed state — carries the mission so the server can persist a
   *  redaction-safe terminal snapshot for post-completion audit. */
  'mission:completed': Mission;
  /** Mission was aborted/stopped by the operator — terminal, distinct from completed. */
  'mission:aborted': { mission: Mission; reason: string };
  /** A mission task was created (including terminal `blocked` prerequisite records) — lets the
   *  server materialize durable ledger entries for blockers without inventing a parallel system. */
  'task:created': Task;
  'scan:progress': ScanProgressEvent;
  'abort:recommended': string;
  /** A capability-approval gate decision (allowed/denied) on an intrusive/dangerous tool — bridged to
   *  the dashboard's live approval/audit feed. Structural match for arsenal/approval.ts ApprovalRecord. */
  'approval:decision': {
    tool: string;
    risk: RiskTier;
    operator?: string;
    target?: string;
    action: string;
    outcome: string;
    spicy: boolean;
    at: number;
  };
}

// =============================================================================
// UTILITY TYPES
// =============================================================================

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type RequireAtLeastOne<T, Keys extends keyof T = keyof T> =
  Pick<T, Exclude<keyof T, Keys>> &
  { [K in Keys]-?: Required<Pick<T, K>> & Partial<Pick<T, Exclude<Keys, K>>> }[Keys];
