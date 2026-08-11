/**
 * T3MP3ST (TEMPEST)
 * Tactical Execution Multi-agent Platform for Elite Security Testing
 *
 * A sophisticated multi-agent framework for penetration testing and red team operations.
 *
 * @example
 * ```typescript
 * import { createTempest } from 't3mp3st';
 *
 * const tempest = createTempest({
 *   name: 'Operation Midnight',
 *   llm: { provider: 'openrouter', model: 'anthropic/claude-opus-4-8' },
 *   opsec: { level: 'covert' },
 * });
 *
 * // Spawn operators
 * const recon = tempest.cell.spawnOperator('Ghost-1', 'recon');
 *
 * // Start operations
 * tempest.command.start();
 * ```
 */

import { EventEmitter } from 'eventemitter3';

// =============================================================================
// TYPE EXPORTS
// =============================================================================

export * from './types/index.js';

// =============================================================================
// MODULE EXPORTS
// =============================================================================

// Configuration
export { config, getApiKey, setApiKey, hasApiKey, getLLMConfig, getConfiguredProviders, AVAILABLE_MODELS } from './config/index.js';
export type { TempestSettings, ModelInfo } from './config/index.js';

// LLM
export {
  LLMBackbone,
  createAnthropicBackbone,
  createOpenRouterBackbone,
  createOpenAIBackbone,
  createLiteLLMBackbone,
  createMockBackbone,
  createLocalBackbone,
  createBestAvailableBackbone,
} from './llm/index.js';
export type { LLMEvents, LLMProviderAdapter, ChatOptions } from './llm/index.js';

// Operators
export {
  OperatorAgent,
  OperatorCell,
  createOperator,
  createBalancedTeam,
  createStealthTeam,
  createBreachTeam,
  ARCHETYPE_PROFILES,
  ARCHETYPE_CAPABILITIES,
  ARCHETYPE_TECHNIQUES,
  PHASE_ARCHETYPES,
  KILL_CHAIN_ORDER,
  PHASE_DESCRIPTIONS,
} from './operators/index.js';
export type { OperatorEvents, CellEvents, ArchetypeProfile } from './operators/index.js';

// Mission
export {
  MissionControl,
  TaskQueue,
  createDefaultRoE,
  createStrictRoE,
  createReconTasks,
  createVulnScanTasks,
} from './mission/index.js';
export type { MissionEvents, TaskQueueEvents } from './mission/index.js';

// Target
export {
  TargetEnvironment,
  createTargetFromUrl,
  createTargetFromIP,
  createDMZArchitecture,
} from './target/index.js';
export type { TargetEvents } from './target/index.js';

// Evidence
export {
  EvidenceVault,
  createFindingFromVuln,
  createMisconfigFinding,
  SEVERITY_SCORES,
  cvssToSeverity,
} from './evidence/index.js';
export type { EvidenceVaultEvents } from './evidence/index.js';

// Arsenal
export { Arsenal, successResult, failResult, createToolContext, BUILTIN_TOOLS, EXTERNAL_TOOLS, isToolAvailable, runSubprocess } from './arsenal/index.js';
export type { ArsenalEvents, ToolExecution } from './arsenal/index.js';

// Agent Loop
export { AgentLoop, createAgentLoop, runAgentTask } from './agent/index.js';
export type { AgentLoopOptions, AgentStep, AgentResult, AgentEvents } from './agent/index.js';

// OPSEC
export {
  OpsecController,
  createSilentOpsecConfig,
  createAggressiveOpsecConfig,
  createBalancedOpsecConfig,
} from './opsec/index.js';
export type { OpsecEvents, IOC } from './opsec/index.js';

// Comms
export {
  CommsChannel,
  createMissionComms,
  initializeTeamChannels,
  MESSAGE_FORMATS,
  PRIORITY_INDICATORS,
} from './comms/index.js';
export type { CommsEvents, Channel } from './comms/index.js';

// Analysis
export { AnalysisEngine, createAnalysisEngine } from './analysis/index.js';

// Benchmark
export {
  Benchmark,
  createBenchmark,
  scoreBenchmark,
  matchFinding,
  aggregateMetrics,
  BENCHMARK_CHALLENGES,
} from './benchmark/index.js';
export type {
  BenchmarkChallenge,
  BenchmarkMetrics,
  BenchmarkRunResult,
  BenchmarkSuiteResult,
  BenchmarkEvents,
  GroundTruthVuln,
} from './benchmark/index.js';

// Prompts
export {
  OPERATOR_SYSTEM_PROMPTS,
  COGNITION_PROMPTS,
  REASONING_PROMPTS,
  WORKFLOW_PROMPTS,
  SPECIALIZED_PROMPTS,
  PROMPT_TEMPLATES,
  GENERAL_SYSTEM_PROMPT,
  GENERAL_REPLAN_PROMPT,
} from './prompts/index.js';

// General (Autonomous Op Orchestrator)
export { OpGeneral } from './general/index.js';
export type {
  Directive,
  OpPlan,
  OpPlanTarget,
  OpPlanObjective,
  OpPlanOperator,
  OpPlanPhaseStrategy,
  OpPlanRoE,
  OpPlanContingency,
  OpPlanHuntLane,
  OpPlanAuthorityReceipt,
  OpPlanEvidenceContract,
  OpPlanWorkOrder,
  OpPlanToolPlan,
  OpPlanCritique,
  OpPlanMissionGate,
  OpPlanLearningDirective,
  GeneralPlanReview,
  GeneralSitrep,
  StrategicAssessment,
  GeneralEvents,
} from './general/index.js';

// Decomposition Orchestrator (multi-model task decomposition)
export { DecompositionOrchestrator } from './orchestration/index.js';
export type {
  DecompositionConfig,
  DecompositionResult,
  DecomposedQuery,
  QueryResult,
  SynthesisResult,
  DecompositionEvents,
} from './orchestration/index.js';

// Stubs (advanced modules)
export * from './stubs/index.js';

// =============================================================================
// TYPE IMPORTS
// =============================================================================

import {
  KillChainPhase,
} from './types/index.js';

import type {
  TempestConfig,
  LLMConfig,
  RuntimeHooks,
  LLMProvider,
  OperatorArchetype,
  CommandEvents,
  Finding,
  ScanProgressEvent,
  Task,
  TaskResult,
  MissionRunState,
} from './types/index.js';

// Re-export commonly used types
export { KillChainPhase } from './types/index.js';
export type { OpsecConfig, Finding, Credential, Target, DetectionEvent } from './types/index.js';

import { OperatorCell, OperatorAgent, ARCHETYPE_PROFILES, PHASE_ARCHETYPES, KILL_CHAIN_ORDER } from './operators/index.js';
import { PackBoard } from './pack/board.js';
import { randomUUID } from 'node:crypto';
import { createPrivateReportWorkspace, readPrivateToolReport } from './arsenal/report-workspace.js';
import { MissionControl, TaskQueue, deriveObjectiveCompletion } from './mission/index.js';
import { TargetEnvironment } from './target/index.js';
import { EvidenceVault } from './evidence/index.js';
import {
  Arsenal,
  BUILTIN_TOOLS,
  EXTERNAL_TOOLS,
  stampSpicyBuiltin,
  hostFromTargetValue,
  scopeViolation,
  runSubprocess,
  isToolAvailable,
} from './arsenal/index.js';
import { buildAdapterTools } from './arsenal/adapter-tools.js';
import { buildPostExTools } from './arsenal/post-ex.js';
import { ApprovalController, type ApprovalRequest } from './arsenal/approval.js';
import { TOOL_ADAPTERS } from './arsenal/catalog.js';
import { OpsecController, createBalancedOpsecConfig } from './opsec/index.js';
import { CommsChannel } from './comms/index.js';
import { AnalysisEngine } from './analysis/index.js';
import { LLMBackbone } from './llm/index.js';
import { getLLMConfig, config } from './config/index.js';
import { AgentLoop } from './agent/index.js';
import { OpGeneral } from './general/index.js';

// Stubs for advanced modules
import {
  ExploitEngine,
  ScannerOrchestrator,
  BrowserAutomation,
  BenchmarkRunner,
  ReasoningEngine,
  CognitionEngine,
  SwarmController,
  CloudSecurityEngine,
  PersistenceController,
  LearningEngine,
  KnowledgeBase,
  ProtocolHandler,
  EvasionEngine,
  ReportingEngine,
  WorkflowOrchestrator,
} from './stubs/index.js';

// =============================================================================
// TEMPEST COMMAND
// =============================================================================

const DEFAULT_AGENT_MAX_ITERATIONS = 15;
const LOCAL_AGENT_MAX_ITERATIONS = Number(process.env.T3MP3ST_LOCAL_AGENT_MAX_ITERATIONS || 30);
const MAX_PROGRESS_EVENTS = 300;

/**
 * TEMPEST Command - Main orchestration controller
 */
export class TempestCommand extends EventEmitter<CommandEvents> {
  public readonly name: string;
  public readonly cell: OperatorCell;
  public readonly mission: MissionControl;
  public readonly targetEnv: TargetEnvironment;
  public readonly vault: EvidenceVault;
  public readonly arsenal: Arsenal;
  /** Capability approval + spicy-action warning gate for intrusive/dangerous tools. */
  public readonly approval: ApprovalController;
  public readonly opsec: OpsecController;
  public readonly comms: CommsChannel;
  public readonly analysis: AnalysisEngine;
  public readonly llm: LLMBackbone;

  /**
   * Stub modules (interface-only).
   *
   * @stub Not implemented - interface stub, see src/stubs/index.ts. These members
   * expose the intended surface for future modules but do NOT perform real work;
   * their methods return honest not-implemented/failure shapes. Do not treat any
   * of the following as a capability the framework actually has.
   */
  // Stub modules (interface-only) — reconnaissance/exploitation surface
  public readonly exploit: ExploitEngine;
  public readonly scanner: ScannerOrchestrator;
  public readonly browser: BrowserAutomation;
  public readonly benchmark: BenchmarkRunner;
  public readonly reasoning: ReasoningEngine;

  // Stub modules (interface-only) — cognition/swarm/cloud surface
  public readonly cognition: CognitionEngine;
  public readonly swarm: SwarmController;
  public readonly cloud: CloudSecurityEngine;
  public readonly persistence: PersistenceController;
  public readonly learning: LearningEngine;

  // Stub modules (interface-only) — knowledge/protocol/reporting surface
  public readonly knowledge: KnowledgeBase;
  public readonly protocols: ProtocolHandler;
  public readonly evasion: EvasionEngine;
  public readonly reporting: ReportingEngine;
  public readonly workflow: WorkflowOrchestrator;

  // Autonomous Op General
  public readonly general: OpGeneral;

  private running: boolean = false;
  private paused: boolean = false;
  private tickInterval: NodeJS.Timeout | null = null;
  private tickCount: number = 0;
  private hooks: RuntimeHooks;
  private readonly taskTimeoutMs: number;
  private readonly objectiveClass?: import('./types/index.js').MissionObjectiveClass;
  private readonly objectiveDirective?: string;
  private readonly missionFamily?: import('./types/index.js').MissionFamily;

  /**
   * White-box source context (security-prioritized code excerpt), set by the
   * large-repo analysis pipeline via setWhiteboxSource(). When present it is
   * threaded into every operator's agent loop so the model sees the source
   * alongside its task. Empty/unset = black-box operation (unchanged behavior).
   */
  private whiteboxSource: string = '';

  /**
   * The swarm's shared, verifiable blackboard (Phase-2 coordination). One board per mission run:
   * every finding posts a lead here, carrying its tool-vs-model-asserted provenance — the verifiable
   * feedback signal that will drive the refinement loop (findings → targeted follow-up tasks).
   */
  private readonly packBoard = new PackBoard();

  /**
   * Swarm coordination (Phase-2), OPT-IN so the swarm-vs-single-agent bake-off can toggle it: set
   * `T3MP3ST_SWARM_COORD=on` to enable the finding→follow-up refinement loop. Off = the legacy
   * phase-sequenced queue (the single-agent-equivalent baseline). Default OFF until it's proven.
   */
  private readonly coordinationEnabled = /^(1|true|on)$/i.test(process.env.T3MP3ST_SWARM_COORD ?? '');
  /** Findings that already spawned a follow-up (dedup — a finding chases exactly once). */
  private readonly spawnedFollowups = new Set<string>();
  /** Per-run cap on follow-up tasks so the refinement loop can never explode. */
  private readonly maxFollowups = Number(process.env.T3MP3ST_SWARM_MAX_FOLLOWUPS) || 24;
  /** Coordination telemetry — the artifact that distinguishes a coordinated run from N solo agents. */
  private leadsPosted = 0;
  private followupsSpawned = 0;

  constructor(config: TempestConfig) {
    super();
    this.name = config.name;
    this.hooks = config.hooks || {};
    this.objectiveClass = config.objectiveClass;
    this.objectiveDirective = config.objectiveDirective;
    this.missionFamily = config.missionFamily;
    this.taskTimeoutMs = TempestCommand.resolveTaskTimeoutMs(config.llm.provider);

    // Initialize LLM backbone
    this.llm = new LLMBackbone(config.llm);

    // Initialize core subsystems
    this.cell = new OperatorCell(config.operators?.maxConcurrent || 10, this.llm);
    this.mission = new MissionControl();
    this.targetEnv = new TargetEnvironment();
    this.vault = new EvidenceVault();
    this.arsenal = new Arsenal();
    this.opsec = new OpsecController(config.opsec);
    this.comms = new CommsChannel();

    // Register built-in tools and external CLI wrappers. The built-in intrusive/credential probes
    // (sqli_scan, password_spray, …) are the pre-existing honest baseline and stay UNGATED by default —
    // zero regression: the headline benchmark and every prior run keep firing them freely. Opt in with
    // T3MP3ST_GATE_BUILTINS=1 to stamp the spicy ones with a riskTier so the same approval gate that
    // fences the specialist arsenal (metasploit/hydra) also fences them.
    const gateBuiltins = /^(1|true|yes|on)$/i.test(process.env.T3MP3ST_GATE_BUILTINS ?? '');
    this.arsenal.registerMany(gateBuiltins ? BUILTIN_TOOLS.map(stampSpicyBuiltin) : BUILTIN_TOOLS);
    this.arsenal.registerMany(EXTERNAL_TOOLS);

    // Capability approval + spicy-action warning gate. An intrusive/credential/dangerous tool is
    // INERT until it's approved. Two ways in: (1) headless — a pre-authorization allowlist up front
    // via T3MP3ST_APPROVED_TOOLS (comma list) runs those tools free; (2) interactive — a host wires an
    // approver so the operator approves a tool once, then it's free. No approver + not pre-approved =
    // fail-safe DENY (an unattended run never self-fires an exploit). Every gated call is audited; the
    // spicy ones (exploits / cred attacks) surface a loud warning. Wired onto the arsenal below so the
    // gate runs inside Arsenal.execute() alongside the egress scope gate.
    const preApprovedTools = (process.env.T3MP3ST_APPROVED_TOOLS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    this.approval = new ApprovalController({
      preApprovedTools,
      onWarning: (req: ApprovalRequest) => {
        // Loud, non-blocking warning so a spicy action is always SEEN. A host UI can also read
        // this.approval.getAudit() or replace the controller for a richer surface.
        // eslint-disable-next-line no-console
        console.warn(`⚠️  SPICY ACTION [${req.risk}] ${req.operator ? req.operator + ' → ' : ''}${req.action}`);
      },
      // Bridge every gated decision to the dashboard's live approval/audit feed (connectBroadcast
      // forwards this engine event to the SSE channel as `arsenal.approval`).
      onDecision: (record) => this.emit('approval:decision', record),
    });
    this.arsenal.setApprovalController(this.approval);

    // Phase-1 (OPT-IN): arm the specialist arsenal. Gated behind T3MP3ST_FULL_ARSENAL so the honest
    // bash-only benchmark baseline (built-ins only) stays uncontaminated — a full-power / pack hunt
    // sets it. The generic factory NEVER mints catalog_only/import_only adapters; the post-ex drivers
    // (metasploit/hydra) are hand-written and each carries a riskTier so the approval gate above fences
    // them. The egress scope gate in Arsenal.execute() still fences every target; the in-handler
    // scopeOk here is a second belt-and-braces check on the resolved per-adapter target.
    if (/^(1|true|on)$/i.test(process.env.T3MP3ST_FULL_ARSENAL ?? '')) {
      const deps = {
        runSubprocess,
        isToolAvailable,
        scopeOk: (target: string) => scopeViolation(this.arsenal.getScope(), { parameters: { target } }) === null,
        // Report-FILE tools (garak) may emit prompt/response transcripts. Node's mkdtemp creates a
        // mode-0700 per-run directory; the handler removes it in a finally path on every outcome.
        createReportWorkspace: createPrivateReportWorkspace,
        readToolReport: readPrivateToolReport,
      };
      const existing = new Set(this.arsenal.getAllTools().map((t) => t.name));
      this.arsenal.registerMany(buildAdapterTools(TOOL_ADAPTERS, deps, existing));
      this.arsenal.registerMany(buildPostExTools(deps)); // metasploit_module (dangerous) + hydra_bruteforce (credential)
    }

    // Advanced modules
    this.exploit = new ExploitEngine();
    this.scanner = new ScannerOrchestrator();
    this.browser = new BrowserAutomation();
    // STUB by design, not an oversight: the real benchmark implementation lives in
    // src/benchmark (class `Benchmark`) but is NOT a drop-in here — it exposes a
    // different, scoring-oriented API (scoreRun/challengeToTasks/listChallenges,
    // it does not run agents itself) and different Challenge/Metrics shapes than
    // the `BenchmarkRunner` type this field is declared as. Wiring it in would
    // require changing this field's type plus the `Tempest` interface/factory, so
    // it is intentionally left as the stub. The real benchmark is currently
    // CLI-only (see scripts/ + src/benchmark).
    this.benchmark = new BenchmarkRunner();
    this.reasoning = new ReasoningEngine(this.llm);

    // Elite modules
    this.cognition = new CognitionEngine(this.llm);
    this.swarm = new SwarmController();
    this.cloud = new CloudSecurityEngine();
    this.persistence = new PersistenceController();
    this.learning = new LearningEngine();

    // Foundational modules
    this.knowledge = new KnowledgeBase();
    this.protocols = new ProtocolHandler();
    this.evasion = new EvasionEngine();
    this.reporting = new ReportingEngine();
    this.workflow = new WorkflowOrchestrator(this.llm.getClient());

    // Autonomous Op General
    this.general = new OpGeneral(this.llm);

    // Analysis depends on other subsystems
    this.analysis = new AnalysisEngine(
      this.vault,
      this.targetEnv,
      this.mission,
      this.opsec
    );

    // Wire up events
    this.setupEventForwarding();

    // Register custom tools
    if (config.tools) {
      for (const tool of config.tools) {
        this.arsenal.register(tool);
      }
    }
  }

  /**
   * Setup event forwarding from subsystems
   */
  private setupEventForwarding(): void {
    // Forward operator events
    this.cell.on('operator:spawned', (op) => {
      this.emit('operator:spawned', { id: op.id, archetype: op.archetype });
      this.hooks.onOperatorSpawned?.({ id: op.id, archetype: op.archetype });
    });

    this.cell.on('operator:burned', (op) => {
      this.emit('operator:burned', { id: op.id });
    });

    // Forward detection events
    this.opsec.on('detection:triggered', (event) => {
      this.emit('detection:triggered', event);
      this.hooks.onDetectionEvent?.(event);
    });

    this.opsec.on('opsec:abort_recommended', ({ reason }) => {
      this.emit('abort:recommended', reason);
    });

    // Forward mission events
    this.mission.on('mission:completed', (mission) => {
      // Mark completion BEFORE stop() flips running=false, so getRunState() can distinguish a
      // genuine 'completed' terminal state from a bare 'idle'/stopped command (never collapse
      // active:false into completed, and never collapse completed into aborted).
      this.completedFlag = true;
      this.emit('mission:completed', mission);
      this.stop();
    });

    this.mission.on('mission:aborted', ({ mission, reason }) => {
      this.emit('mission:aborted', { mission, reason });
      this.stop();
    });

    this.mission.on('mission:phase_changed', ({ mission, newPhase }) => {
      this.emit('mission:phase_changed', { missionId: mission.id, phase: newPhase });
      this.hooks.onMissionPhaseChange?.(mission.id, newPhase);
    });

    // Forward task creation so the server can materialize durable ledger records for terminal
    // `blocked` prerequisite tasks (the blocker must outlive the ephemeral task queue).
    this.mission.on('task:created', (task) => {
      this.emit('task:created', task);
    });

    // Auto-generate tasks when a target is added to an active mission.
    // Only mark "seeded" if a mission actually exists — otherwise generateTasksForTarget
    // no-ops and we'd falsely suppress the tick-loop seeding (leaving operators idle).
    this.targetEnv.on('target:added', (target) => {
      this.syncArsenalScope();
      if (this.mission.getActiveMission()) {
        this.mission.generateTasksForTarget(target.address);
        this.taskSeeded = true;
      }
    });
  }

  /**
   * Recompute the arsenal's authorized egress scope from the mission's targets. Operators can only
   * reach the authorized target hosts (+ loopback + lab/private ranges); every other host is refused
   * at arsenal.execute() before the handler runs. Called whenever a target is added, so a keyless
   * operator can never point a networked tool at an off-target host.
   */
  private syncArsenalScope(): void {
    const allowedHosts = this.targetEnv.getAllTargets()
      .map((t) => hostFromTargetValue(t.address))
      .filter((h): h is string => !!h);
    this.arsenal.setScope({ allowedHosts, allowLoopback: true, allowPrivate: true });
  }

  /**
   * Setup event forwarding for an operator
   */
  private setupOperatorEvents(operator: OperatorAgent): void {
    operator.on('task:started', ({ task }) => {
      this.recordProgress('task_started', operator, task, `Started ${task.name}`);
    });

    operator.on('task:completed', ({ task, result }) => {
      const findings = result.findings?.length ? ` Findings: ${result.findings.join(', ')}` : '';
      this.recordProgress(
        'task_completed',
        operator,
        task,
        `${result.success === false ? 'Finished unsuccessfully' : 'Completed'} ${task.name}.${findings}`,
        { success: result.success !== false }
      );
    });

    operator.on('task:failed', ({ task, error }) => {
      this.recordProgress('task_failed', operator, task, error, { success: false });
    });

    operator.on('agent:thinking', ({ task, content }) => {
      this.recordProgress('thinking', operator, task, content);
    });

    operator.on('agent:tool_call', ({ task, name, args, source }) => {
      this.recordProgress('tool_call', operator, task, `${name} ${JSON.stringify(args || {})}`, { toolName: name, source });
    });

    operator.on('agent:tool_result', ({ task, name, result, source }) => {
      const detail = result.success
        ? (result.output || 'Tool completed')
        : (result.error || result.output || 'Tool failed');
      this.recordProgress('tool_result', operator, task, detail, { toolName: name, success: result.success, source });
    });

    operator.on('finding:discovered', ({ finding }) => {
      this.vault.addFinding(finding);
      this.emit('finding:discovered', { finding, operatorId: operator.id });
      this.hooks.onFindingDiscovered?.(finding, { id: operator.id });

      // Sync finding intelligence back to the target object
      this.syncFindingToTarget(finding);

      // Post the finding to the shared board as a lead — the swarm's verifiable blackboard.
      // `provenance` carries the tool-vs-model-asserted signal (the refinement loop's feedback);
      // dedup + provenance-endorsement are the board's job. Best-effort: never break the mission.
      // Gated on coordination so the baseline (coordination off) leaves the board fully inert.
      if (this.coordinationEnabled) try {
        const prov = finding.verifyGate?.provenance ?? 'none';
        this.packBoard.postLead(operator.id, {
          kind: 'lead',
          title: finding.title,
          where: { targetId: finding.id },
          vulnClass: finding.cwe?.[0] ?? 'unclassified',
          confidence: prov === 'tool' ? 'high' : prov === 'context' ? 'medium' : 'low',
          provenance: prov,
          cwe: finding.cwe?.[0],
          severity: finding.severity,
        });
        this.leadsPosted++;
      } catch { /* best-effort */ }

      // [Phase-2 refinement loop] A TOOL-VERIFIED finding spawns a targeted follow-up task for the
      // NEXT kill-chain phase's operator — chase the verifiable feedback signal (the research's
      // load-bearing condition). Model-asserted findings spawn NO work (no chasing hallucinations).
      // Dedup + a per-run cap keep the loop bounded. Gated by T3MP3ST_SWARM_COORD for the bake-off.
      if (
        this.coordinationEnabled &&
        finding.verifyGate?.provenance === 'tool' &&
        !this.spawnedFollowups.has(finding.id) &&
        this.spawnedFollowups.size < this.maxFollowups
      ) {
        const mission = this.mission.getActiveMission();
        const queue = this.mission.getTaskQueue();
        const idx = KILL_CHAIN_ORDER.indexOf(finding.phase);
        const nextPhase = idx >= 0 && idx < KILL_CHAIN_ORDER.length - 1 ? KILL_CHAIN_ORDER[idx + 1] : undefined;
        const nextOp = nextPhase ? PHASE_ARCHETYPES[nextPhase]?.[0] : undefined;
        if (mission && queue && nextPhase && nextOp) {
          this.spawnedFollowups.add(finding.id);
          const cwe = finding.cwe?.length ? `, ${finding.cwe.join('/')}` : '';
          queue.add({
            id: randomUUID(),
            missionId: mission.id,
            name: `Chase: ${finding.title}`.slice(0, 120),
            description:
              `A prior operator TOOL-VERIFIED this lead: "${finding.title}" (${finding.severity}${cwe}) on ${finding.targetId}. ` +
              `${finding.description} Focus this ${nextPhase} step on THIS specific surface — confirm and advance it; do not re-scan broadly.`,
            phase: nextPhase,
            operatorType: nextOp,
            status: 'pending',
            priority: 20,
            dependencies: [],
            createdAt: Date.now(),
          });
          this.followupsSpawned++;
        }
      }
    });

    operator.on('credential:harvested', ({ credential }) => {
      this.vault.addCredential(credential);
      this.emit('credential:harvested', { credential, operatorId: operator.id });
      this.hooks.onCredentialHarvested?.(credential, { id: operator.id });

      // Sync credential to the target
      if (credential.targetId) {
        const target = this.targetEnv.getTarget(credential.targetId);
        if (target) {
          target.credentials = target.credentials || [];
          target.credentials.push(credential);
        }
      }
    });

    operator.on('status:changed', ({ oldStatus: _oldStatus }) => {
      this.hooks.onOperatorStateChange?.({ id: operator.id }, operator.state);
    });
  }

  private recordProgress(
    kind: ScanProgressEvent['kind'],
    operator: OperatorAgent,
    task: Task | undefined,
    detail: string,
    extra: Partial<Pick<ScanProgressEvent, 'toolName' | 'success' | 'source'>> = {}
  ): void {
    const compact = String(detail || '').replace(/\s+/g, ' ').trim().slice(0, 2000);
    const event: ScanProgressEvent = {
      id: `progress-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      timestamp: Date.now(),
      kind,
      operatorId: operator.id,
      callsign: operator.callsign,
      archetype: operator.archetype,
      taskId: task?.id,
      taskName: task?.name,
      detail: compact,
      ...extra,
    };

    this.progressEvents.push(event);
    if (this.progressEvents.length > MAX_PROGRESS_EVENTS) {
      this.progressEvents.splice(0, this.progressEvents.length - MAX_PROGRESS_EVENTS);
    }
    this.emit('scan:progress', event);
  }

  /**
   * Parse a finding and update the target's services/vulnerabilities.
   * This is the intelligence pipeline that feeds data between phases.
   */
  private syncFindingToTarget(finding: Finding): void {
    // Find the target this finding belongs to
    let target = this.targetEnv.getTarget(finding.targetId);
    if (!target) {
      // Try to match by scanning all targets
      const allTargets = this.targetEnv.getAllTargets();
      target = allTargets.find(t => finding.description.includes(t.address)) || allTargets[0] || null;
    }
    if (!target) return;

    const desc = finding.description.toLowerCase();
    const title = finding.title.toLowerCase();

    // Detect service-related findings and add to target.services
    if (title.includes('open port') || title.includes('service') || desc.includes('open port')) {
      this.extractServicesFromFinding(target.id, finding);
    }

    // Detect vulnerability findings and add to target.vulnerabilities
    if (finding.severity !== 'info' || title.includes('vuln') || title.includes('cve') ||
        title.includes('injection') || title.includes('xss') || title.includes('ssrf')) {
      this.targetEnv.addVulnerability(target.id, {
        id: finding.id,
        name: finding.title,
        description: finding.description,
        severity: finding.severity,
        cvss: finding.cvss,
        cve: finding.cve,
        cwe: finding.cwe,
        exploitAvailable: finding.exploitedAt != null,
        references: finding.references,
      });
    }

    // Update target status based on severity
    if (finding.severity === 'critical' || finding.severity === 'high') {
      this.targetEnv.setStatus(target.id, 'vulnerable');
    }
    if (finding.exploitedAt) {
      this.targetEnv.setStatus(target.id, 'exploited');
    }
  }

  /**
   * Extract service info from port/service findings and add to target
   */
  private extractServicesFromFinding(targetId: string, finding: Finding): void {
    // Try to parse port numbers from the finding description
    const portMatches = finding.description.matchAll(/(\d+)\/(tcp|udp)\s+(open)\s+(\S+)/gi);
    for (const match of portMatches) {
      const port = parseInt(match[1], 10);
      const protocol = match[2];
      const name = match[4];
      this.targetEnv.addService(targetId, { name, port, protocol });
    }

    // Also try simpler pattern: "port 80", "port 443 open"
    const simpleMatches = finding.description.matchAll(/port[s]?\s*[:=]?\s*(\d+(?:\s*,\s*\d+)*)/gi);
    for (const match of simpleMatches) {
      const ports = match[1].split(',').map(p => parseInt(p.trim(), 10));
      for (const port of ports) {
        if (!isNaN(port)) {
          const existing = this.targetEnv.getTarget(targetId);
          const alreadyHas = existing?.services?.some(s => s.port === port);
          if (!alreadyHas) {
            const knownServices: Record<number, string> = {
              21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
              80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
              3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 6379: 'redis',
              8080: 'http-proxy', 8443: 'https-alt', 27017: 'mongodb',
            };
            this.targetEnv.addService(targetId, {
              name: knownServices[port] || 'unknown',
              port,
              protocol: 'tcp',
            });
          }
        }
      }
    }
  }

  // ===========================================================================
  // LIFECYCLE
  // ===========================================================================

  /**
   * Start command operations.
   * Automatically creates and starts a mission if none is active.
   */
  public start(): void {
    if (this.running) return;

    // Auto-create a mission if none exists
    this.ensureMission();

    // Reset the seed flag so the first tick generates tasks for targets added
    // BEFORE start(). A pre-mission target:added event leaves taskSeeded stale-true
    // (generateTasksForTarget no-ops with no active mission), which would otherwise
    // skip seeding forever and leave every operator idle.
    this.taskSeeded = false;

    this.running = true;
    this.paused = false;
    this.emit('command:started');

    // Start tick loop (1 second interval). Catch any tick error so a single bad tick
    // (e.g. a spawn hitting the pool cap) can never take down the whole server process.
    this.tickInterval = setInterval(() => {
      this.tick().catch(err => console.error('[T3MP3ST] tick error (mission continues):', err instanceof Error ? err.message : err));
    }, 1000);
  }

  /**
   * Ensure an active mission exists. Creates and starts one if needed.
   */
  private ensureMission(): void {
    if (this.mission.getActiveMission()) return;

    const targets = this.targetEnv.getAllTargets();
    const targetNames = targets.map(t => t.address).join(', ') || 'pending targets';

    const mission = this.mission.createMission({
      name: `${this.name} — Auto Mission`,
      description: `Automated mission for ${targetNames}`,
      objectives: this.objectiveDirective
        ? [this.objectiveDirective, 'Enumerate attack surface', 'Identify vulnerabilities', 'Validate findings']
        : ['Enumerate attack surface', 'Identify vulnerabilities', 'Validate findings'],
      objectiveClass: this.objectiveClass,
      missionFamily: this.missionFamily,
    });
    this.mission.startMission(mission.id);
  }

  /**
   * Stop command operations
   */
  public stop(): void {
    if (!this.running) return;

    this.running = false;
    this.taskSeeded = false;
    // An explicit operator stop/abort is a TERMINAL state distinct from "completed" — but only when
    // the mission didn't just complete (completedFlag is set first by the mission:completed listener).
    if (!this.completedFlag) this.abortedFlag = true;
    // Drop any pending timeout-reconciliation markers — a promise that never
    // settles must not leave its id lingering across missions.
    this.timedOutDispatches.clear();
    if (this.tickInterval) {
      clearInterval(this.tickInterval);
      this.tickInterval = null;
    }
    this.emit('command:stopped');
  }

  /**
   * Pause operations
   */
  public pause(): void {
    if (!this.running || this.paused) return;
    this.paused = true;
    this.emit('command:paused');
  }

  /**
   * Resume operations. When the pause was caused by a STALL (required work failed), resume is
   * recovery-gated: it re-evaluates authoritative task state and REFUSES to resume while blockers
   * remain, rather than blindly clearing the stall and hiding the failure. A plain operator pause
   * (no stallReason) resumes immediately.
   */
  public resume(): void {
    if (!this.running || !this.paused) return;
    if (this.stallReason) {
      const outcome = this.recoverMission();
      if (!outcome.resumed) {
        // Stay stalled; the caller surfaces outcome.blocking to the operator.
        this.emit('command:resume-refused', outcome);
        return;
      }
      return; // recoverMission already cleared stall + unpaused
    }
    this.paused = false;
    this.stallReason = null;
    this.stallSince = null;
    this.emit('command:resumed');
  }

  /**
   * Check if running
   */
  public isRunning(): boolean {
    return this.running && !this.paused;
  }

  /** Track in-flight task promises so we don't double-dispatch */
  private activeDispatches: Set<string> = new Set();

  /**
   * Wall-clock start time (ms epoch) for each in-flight dispatch, keyed by task id.
   * Populated alongside activeDispatches.add and cleared everywhere activeDispatches
   * is cleared. Drives the per-dispatch timeout backstop in checkDispatchTimeouts().
   */
  private dispatchStartTimes: Map<string, number> = new Map();

  /** The operator each in-flight dispatch was assigned to, keyed by task id — so a
   * timed-out dispatch can reset the exact wedged operator back to idle. */
  private dispatchOperators: Map<string, OperatorAgent> = new Map();

  /**
   * Task ids the backstop force-failed as a timeout WHILE their operator promise
   * was still in flight. When such a promise later settles, its completion handler
   * consults this set to reconcile the task instead of silently discarding the
   * result (a late success flips failed→completed; a late failure stays failed).
   * Membership is consumed (deleted) on the first settle, so at most one
   * reconciliation happens per timed-out dispatch. Cleared wholesale in stop().
   */
  private timedOutDispatches: Set<string> = new Set();

  /**
   * GENEROUS per-dispatch wall-clock backstop (ms). If a single task dispatch stays
   * in-flight longer than this, the tick loop force-resolves it as a timeout so
   * pendingOrActive can reach 0 and the mission can advance/complete even when an
   * operator promise wedges. Deliberately large (default 5 min for API models,
   * 30 min for local-agent backends) so it does not kill legitimately slow local
   * CLI work; it only fires on truly-hung dispatches. Override via
   * T3MP3ST_TASK_TIMEOUT_MS.
   */
  private progressEvents: ScanProgressEvent[] = [];

  /**
   * Resolve the dispatch timeout from the environment, falling back to the
   * provider-specific default. Guards against a non-numeric / non-positive override.
   */
  private static resolveTaskTimeoutMs(provider?: LLMProvider): number {
    // Consolidated timeout model: UI override > env (T3MP3ST_TASK_TIMEOUT_MS) > default.
    // The local-agent provider runs multi-turn CLI work that legitimately needs a much larger
    // backstop, so when no explicit override is set we floor the effective value at 30m for it.
    const resolved = config.getTimeout('dispatchTimeoutMs').valueMs;
    if (provider === 'local-agent') {
      const LOCAL_AGENT_FLOOR_MS = 1800000; // 30 minutes — local CLI agents need multiple slow turns
      return Math.max(resolved, LOCAL_AGENT_FLOOR_MS);
    }
    return resolved;
  }

  /** Track whether we've seeded initial tasks for the current mission */
  private taskSeeded: boolean = false;

  /** Human-readable reason a mission was paused because required work failed. */
  private stallReason: string | null = null;

  /** When the current stall began (ms epoch). Null when not stalled. */
  private stallSince: number | null = null;

  /** Last recovery action taken (for status/diagnostics). */
  private lastRecoveryAction: string | null = null;

  /** Whether the mission was explicitly aborted/stopped by the operator (terminal, ≠ completed). */
  private abortedFlag: boolean = false;

  /** Whether the active mission reached a completed terminal state (distinct from idle/aborted). */
  private completedFlag: boolean = false;

  /**
   * Main tick loop — seeds tasks, dispatches to operators, advances phases
   */
  private async tick(): Promise<void> {
    if (this.paused) return;

    this.tickCount++;
    this.emit('tick', this.tickCount);

    // Check OPSEC status
    if (this.opsec.isAbortRecommended()) {
      this.pause();
      return;
    }

    // Get active mission
    const mission = this.mission.getActiveMission();
    if (!mission) return;

    // Get the task queue
    const taskQueue = this.mission.getTaskQueue();
    if (!taskQueue) return;

    // ── Auto-seed tasks from targets if queue is empty ──
    if (!this.taskSeeded) {
      const targets = this.targetEnv.getAllTargets();
      if (targets.length > 0) {
        for (const target of targets) {
          this.mission.generateTasksForTarget(target.address);
        }
        this.taskSeeded = true;

        // Auto-spawn a recon operator if none exists
        const recon = this.cell.getAvailableOperator('recon');
        if (!recon) {
          this.spawnOperator('Recon-Auto', 'recon');
        }
      }
    }

    // ── Backstop: force-resolve any wedged dispatch so the phase can advance ──
    // Runs BEFORE the phase/completion check below so a timed-out task drops out of
    // pendingOrActive/inFlight in the SAME tick it is reaped.
    this.checkDispatchTimeouts(taskQueue);

    // ── Check for phase advancement ──
    const allMissionTasks = taskQueue.getForMission(mission.id);
    const pendingOrActive = allMissionTasks.filter(
      t => t.status === 'pending' || t.status === 'assigned' || t.status === 'in_progress'
    );
    const inFlight = allMissionTasks.filter(t => this.activeDispatches.has(t.id));

    // If we have tasks, all are done, and nothing is in-flight → advance phase.
    // Failed required tasks are terminal, but they are not successful progress.
    // Stall instead of walking the phase bar forward with no backend/model work.
    if (allMissionTasks.length > 0 && pendingOrActive.length === 0 && inFlight.length === 0) {
      const failedCurrentPhase = allMissionTasks.filter(
        t => t.phase === mission.currentPhase && t.status === 'failed'
      );
      if (failedCurrentPhase.length > 0) {
        const firstError = failedCurrentPhase[0].result?.error;
        this.stallReason = `stalled in ${mission.currentPhase}: ${failedCurrentPhase.length} required task(s) failed` +
          (firstError ? ` — ${firstError}` : '');
        this.stallSince = this.stallSince ?? Date.now();
        this.paused = true;
        this.emit('command:paused');
        return;
      }

      const phaseIndex = mission.phases.indexOf(mission.currentPhase);
      if (phaseIndex === -1) return; // Guard: phase not found (race condition)
      if (phaseIndex < mission.phases.length - 1) {
        // Record how the phase we're LEAVING actually concluded (executed vs blocked vs no eligible
        // work) BEFORE advancing — empty phases must not be presented as normally executed.
        this.mission.recordPhaseDisposition(mission.id);
        // Advance to next phase and generate tasks
        this.mission.advancePhase(mission.id);
        this.stallReason = null;
        const targets = this.targetEnv.getAllTargets();
        for (const target of targets) {
          this.mission.generateNextPhaseTasks(target.address);
        }

        // Auto-spawn operators for the new phase
        const nextPhase = mission.currentPhase;
        this.autoSpawnForPhase(nextPhase);
      } else {
        // All phases complete — finish the mission
        this.mission.completeMission(mission.id);
        return;
      }
    }

    // ── Dispatch pending tasks to idle operators ──
    const pendingTasks = taskQueue.getPending();
    if (pendingTasks.length === 0) return;

    for (const task of pendingTasks) {
      // Skip if already being dispatched
      if (this.activeDispatches.has(task.id)) continue;

      // Find ALL idle operators matching the task's archetype, pick the first unused
      const availableOps = this.cell.getAllOperators()
        .filter(op => op.archetype === task.operatorType && op.isAvailable());
      let operator = availableOps[0];

      // Auto-spawn an operator if none exists for this archetype
      if (!operator) {
        if (this.llm.getProvider() === 'local-agent') continue;
        const allOps = this.cell.getAllOperators();
        const archetypeCount = allOps.filter(op => op.archetype === task.operatorType).length;
        // Spawn up to 3 operators per archetype for parallelism
        if (archetypeCount < 3) {
          const callsign = `${task.operatorType.charAt(0).toUpperCase() + task.operatorType.slice(1)}-${archetypeCount + 1}`;
          // spawnOperator throws when the pool is at capacity or the callsign collides —
          // treat that as "no operator available right now" and defer (operator stays unset),
          // never crash the tick.
          try { operator = this.spawnOperator(callsign, task.operatorType); }
          catch { /* pool full / dup callsign — dispatch skipped by the !operator guard below */ }
        }
        if (!operator) continue;
      }

      // Check task dependencies are met
      if (task.dependencies.length > 0) {
        const allDepsComplete = task.dependencies.every(depId => {
          const dep = taskQueue.getTask(depId);
          return dep?.status === 'completed';
        });
        if (!allDepsComplete) continue;
      }

      // Match task to target by address in the task description.
      // Resolve the target BEFORE assigning/marking dispatched — a missing target
      // must leave the task pending (not permanently assigned + stuck in
      // activeDispatches with no completion path to clear it).
      const allTargets = this.targetEnv.getAllTargets();
      const target = allTargets.find(t => task.description.includes(t.address)) || allTargets[0];
      if (!target) continue; // No targets available — leave task pending, skip dispatch

      // Dispatch task (fire and forget — don't block the tick loop)
      this.activeDispatches.add(task.id);
      // Record wall-clock start + owning operator so checkDispatchTimeouts() can reap
      // this exact dispatch if its promise never settles.
      this.dispatchStartTimes.set(task.id, Date.now());
      this.dispatchOperators.set(task.id, operator);
      taskQueue.assign(task.id, operator.id);
      // Begin a new attempt in the task's immutable history (retries append, never rewrite).
      taskQueue.beginAttempt(task.id);

      // Execute asynchronously
      operator.assignTask(task, target).then((result) => {
        // If the backstop already reaped this dispatch, activeDispatches no longer
        // has it. Rather than discard the late result (which left the event ledger
        // saying "completed" while the task stayed "failed"), reconcile it.
        if (!this.activeDispatches.has(task.id)) {
          this.reconcileLateResult(taskQueue, task, result);
          return;
        }
        this.clearDispatch(task.id);
        if (result.success === false) {
          taskQueue.fail(task.id, result.error || result.output || 'task returned unsuccessful result');
          taskQueue.recordAttempt(task.id, 'failed', result.error || result.output);
        } else {
          taskQueue.complete(task.id, result);
          taskQueue.recordAttempt(task.id, 'completed');
          this.hooks.onTaskCompleted?.(task);
        }
      }).catch((_error) => {
        // Late rejection after a timeout: the backstop already marked the task
        // failed, which is the correct terminal state — just consume the timeout
        // marker so it can't reconcile a later phantom settle.
        if (!this.activeDispatches.has(task.id)) {
          this.timedOutDispatches.delete(task.id);
          return;
        }
        this.clearDispatch(task.id);
        try {
          taskQueue.fail(task.id, _error instanceof Error ? _error.message : String(_error));
        } catch (failErr) {
          // Swallow — task may already be in a terminal state
        }
      });
    }
  }

  /**
   * Clear all bookkeeping for an in-flight dispatch (the single place that keeps
   * activeDispatches, dispatchStartTimes, and dispatchOperators in lockstep).
   */
  private clearDispatch(taskId: string): void {
    this.activeDispatches.delete(taskId);
    this.dispatchStartTimes.delete(taskId);
    this.dispatchOperators.delete(taskId);
  }

  /**
   * Reconcile a dispatch result that arrived AFTER the backstop already reaped it.
   *
   * The backstop force-fails a timed-out dispatch and removes it from
   * activeDispatches so the mission can advance. But the operator promise is not
   * cancelled — the tools keep running and may still finish. When they do, the
   * completion handler finds the id gone from activeDispatches. Previously it just
   * returned, leaving the task permanently `failed` even though the event ledger
   * recorded `task_completed success:true`. This bridges that split.
   *
   * Reconciliation is deliberately conservative:
   *  - It only acts on a task THIS backstop timed out (tracked in
   *    timedOutDispatches); an unrelated stale/duplicate settle is ignored.
   *  - Membership is consumed here, so at most one reconciliation runs per timeout.
   *  - It only overwrites a task still in `failed` — if something else already
   *    moved it to a terminal `completed`, we don't touch it.
   *  - Late SUCCESS ⇒ failed → completed (annotated as reconciled-after-timeout,
   *    original evidence preserved). Late FAILURE ⇒ stays failed (correct already).
   */
  private reconcileLateResult(taskQueue: TaskQueue, task: Task, result: TaskResult): void {
    // Only reconcile a dispatch that WE timed out. delete() both tests membership
    // and consumes it, so a second settle of the same promise can't re-run this.
    if (!this.timedOutDispatches.delete(task.id)) return;

    const current = taskQueue.getTask(task.id);
    // If it isn't sitting in the failed state the backstop put it in, leave it be —
    // don't resurrect a task that was legitimately re-driven or completed elsewhere.
    if (!current || current.status !== 'failed') return;

    // A late failure is already reflected by the timeout's failed state.
    if (result.success === false) return;

    // Late success: promote to completed, keeping a breadcrumb that it landed after
    // the timeout backstop had already fired (so the audit trail is honest).
    const priorError = current.result?.error;
    const reconciled: TaskResult = {
      ...result,
      output: [
        result.output,
        `[reconciled] completed after dispatch timeout backstop fired${priorError ? ` (prior: ${priorError})` : ''}`,
      ].filter(Boolean).join('\n'),
    };
    taskQueue.complete(task.id, reconciled);
    taskQueue.recordAttempt(task.id, 'timeout_late_success', priorError);
    this.hooks.onTaskCompleted?.(task);
    console.warn(`[T3MP3ST] task ${task.id} reconciled failed→completed — operator finished after the timeout backstop fired`);
  }

  /**
   * BACKSTOP for wedged dispatches.
   *
   * The normal completion path (assignTask().then/.catch) clears a dispatch when
   * its promise settles. But if that promise NEVER settles — a hung LLM call, a
   * stuck subprocess, an operator pinned in `executing` with `currentTask: null`
   * making no progress — the task stays `assigned`/`in_progress` and its id stays
   * in activeDispatches forever. pendingOrActive/inFlight never reach 0, the phase
   * never advances, and completeMission() is never called: the mission HANGS.
   *
   * On every tick we scan the in-flight dispatches and force-resolve any that have
   * exceeded the GENEROUS wall-clock backstop (taskTimeoutMs), or that exhibit
   * the exact wedge symptom (owning operator is `executing`/`tasked`
   * but its currentTask is null — i.e. it has silently dropped the task). For each
   * we: (1) mark the task failed/timed-out in the queue, (2) clear its dispatch
   * bookkeeping, and (3) reset the owning operator back to idle so it can take new
   * work. That lets pendingOrActive reach 0 and the phase advance / mission finish.
   *
   * This is a backstop, not a deadline: the timeout is large enough that a slow but
   * genuinely-working task is never killed. Normal completion is untouched — if the
   * wedged promise later settles, its then/catch sees the dispatch already gone and
   * no-ops (see the guards in tick()).
   */
  private checkDispatchTimeouts(taskQueue: TaskQueue): void {
    if (this.activeDispatches.size === 0) return;
    const now = Date.now();

    // Snapshot ids first — we mutate the maps inside the loop.
    for (const taskId of [...this.activeDispatches]) {
      const startedAt = this.dispatchStartTimes.get(taskId);
      const operator = this.dispatchOperators.get(taskId);

      const elapsed = startedAt != null ? now - startedAt : Number.POSITIVE_INFINITY;
      const overTime = elapsed >= this.taskTimeoutMs;

      // Wedge symptom: operator claims to be working (executing/tasked) but has no
      // current task — the promise silently dropped it. Only treat this as a wedge
      // once the backstop window has elapsed, so a normal in-between-status tick
      // (e.g. the brief gap before currentTask is set) is never misread as hung.
      const wedged = operator != null &&
        (operator.status === 'executing' || operator.status === 'tasked') &&
        operator.state.currentTask == null &&
        overTime;

      if (!overTime && !wedged) continue;

      const reason = wedged
        ? `dispatch wedged: operator ${operator?.id ?? 'unknown'} stuck in '${operator?.status}' with no current task for ${Math.round(elapsed / 1000)}s`
        : `dispatch timed out after ${Math.round(elapsed / 1000)}s (backstop ${Math.round(this.taskTimeoutMs / 1000)}s)`;

      // Clear a CLEAR event/log so a timed-out dispatch is never silent.
      console.warn(`[T3MP3ST] task ${taskId} force-resolved as timeout — ${reason}`);

      // 1) Mark the task failed/timed-out via the queue (idempotent enough: fail()
      //    just stamps status:'failed'; if it somehow already completed, this is a
      //    no-op-ish overwrite that still lets the phase advance).
      try {
        taskQueue.fail(taskId, `timeout: ${reason}`);
        // Record the timeout as this attempt's outcome WITHOUT erasing it — history is auditable.
        taskQueue.recordAttempt(taskId, overTime ? 'timeout_pending' : 'failed', reason);
      } catch {
        // Swallow — task may already be terminal.
      }

      // 2) Drop it from in-flight bookkeeping so inFlight/activeDispatches shrink,
      //    and remember it timed out so a LATE settle of the still-running promise
      //    can be reconciled (a late success flips failed→completed) rather than
      //    silently discarded. Only track a genuine timeout, not the wedge case
      //    where the promise has already been severed from any real work.
      this.clearDispatch(taskId);
      if (overTime) {
        this.timedOutDispatches.add(taskId);
      }

      // 3) Reset the wedged operator back to idle so it can pick up new work.
      operator?.abortActiveTask(reason);
    }
  }

  // ===========================================================================
  // STALLED-MISSION RECOVERY — re-evaluate authoritative state, never blindly resume
  // ===========================================================================

  /**
   * Recovery disposition for a single task, distinguishing timeout/late-settle races from hard
   * failures. Drives both recovery decisions and operator-facing diagnostics.
   */
  public describeTaskRecovery(task: Task): {
    id: string; name: string; required: boolean; retryable: boolean;
    state: 'timeout_pending' | 'timeout_late_success' | 'timeout_late_failure' | 'retryable' | 'non_retryable' | 'ok';
    detail: string;
  } {
    const required = task.required !== false;
    const timedOut = this.timedOutDispatches.has(task.id);
    const lastAttempt = task.attempts?.[task.attempts.length - 1];
    const errText = task.result?.error || lastAttempt?.error || '';

    // A task that the backstop force-failed but whose underlying promise has NOT settled is
    // genuinely still running — re-dispatching it now would create an unsafe duplicate execution.
    if (timedOut && lastAttempt?.outcome === 'timeout_pending' && task.status === 'failed') {
      return { id: task.id, name: task.name, required, retryable: false, state: 'timeout_pending', detail: `timed out but underlying operation still in flight — retry deferred to avoid a duplicate execution (${errText})` };
    }
    if (lastAttempt?.outcome === 'timeout_late_success') {
      return { id: task.id, name: task.name, required, retryable: false, state: 'timeout_late_success', detail: 'timed out, then reconciled to completed by a late success' };
    }
    if (task.status === 'failed') {
      // Non-retryable: a failed dependency blocks it, or an objective-prerequisite blocked lane,
      // or a hard (non-timeout) error like a refused approval.
      const depFailed = task.dependencies.some((d) => this.mission.getTaskQueue().getTask(d)?.status === 'failed');
      const objectiveBlocked = /status:blocked-prerequisite/.test(task.description);
      const hardRefusal = /approv|scope|denied|unauthorized|out of scope/i.test(errText);
      if (depFailed || objectiveBlocked || hardRefusal) {
        return { id: task.id, name: task.name, required, retryable: false, state: 'non_retryable', detail: errText || 'failed (non-retryable)' };
      }
      return { id: task.id, name: task.name, required, retryable: true, state: timedOut ? 'timeout_late_failure' : 'retryable', detail: errText || 'failed' };
    }
    return { id: task.id, name: task.name, required, retryable: false, state: 'ok', detail: '' };
  }

  /**
   * Reconcile + re-evaluate the authoritative mission state, then resume ONLY if no required
   * blocker remains. Never blindly clears a stall; never fabricates a success; never creates an
   * unsafe duplicate of a still-running timed-out task. Returns the full diagnostic picture.
   */
  public recoverMission(): {
    resumed: boolean;
    state: MissionRunState;
    blocking: Array<ReturnType<TempestCommand['describeTaskRecovery']>>;
    retryableTaskIds: string[];
    note: string;
  } {
    const taskQueue = this.mission.getTaskQueue();
    const mission = this.mission.getActiveMission();
    if (!taskQueue || !mission) {
      return { resumed: false, state: this.getRunState(), blocking: [], retryableTaskIds: [], note: 'no active mission' };
    }

    // 1) Re-reap any newly-wedged dispatches and reconcile authoritative current state.
    //    (reconcileLateResult already flips known late successes failed→completed as they arrive;
    //    we do NOT claim to synchronously drain late settles that have not arrived yet.)
    this.checkDispatchTimeouts(taskQueue);

    // 2) Recompute the current phase's required blockers from authoritative task state.
    const phaseTasks = taskQueue.getForMission(mission.id).filter((t) => t.phase === mission.currentPhase);
    const failed = phaseTasks.filter((t) => t.status === 'failed');
    const described = failed.map((t) => this.describeTaskRecovery(t));
    const blocking = described.filter((d) => d.required);
    const retryableTaskIds = described.filter((d) => d.retryable).map((d) => d.id);

    // 3) Blockers remain → refuse to resume, expose them.
    if (blocking.length > 0) {
      this.lastRecoveryAction = `recover: refused — ${blocking.length} required blocker(s)`;
      return { resumed: false, state: this.getRunState(), blocking, retryableTaskIds, note: 'required blockers remain — resolve via retry/skip before resume' };
    }

    // 4) No required blockers → clear stale stall + resume phase advancement.
    this.stallReason = null;
    this.stallSince = null;
    this.paused = false;
    this.lastRecoveryAction = 'recover: resumed (no required blockers)';
    this.emit('command:resumed');
    return { resumed: true, state: this.getRunState(), blocking: [], retryableTaskIds, note: 'no required blockers — resumed' };
  }

  /**
   * Retry a failed task as a NEW attempt (history preserved). Refuses to retry a task whose
   * underlying operation may still be running (timeout_pending) to avoid a duplicate execution,
   * and refuses non-retryable failures. Returns the updated disposition.
   */
  public retryTask(taskId: string): { ok: boolean; error?: string; attempts?: number } {
    const taskQueue = this.mission.getTaskQueue();
    const task = taskQueue.getTask(taskId);
    if (!task) return { ok: false, error: 'task not found' };
    const d = this.describeTaskRecovery(task);
    if (d.state === 'timeout_pending') {
      return { ok: false, error: 'underlying operation still in flight after timeout — retry deferred to avoid a duplicate execution' };
    }
    if (!d.retryable) {
      return { ok: false, error: `task is not retryable (${d.state}): ${d.detail}` };
    }
    const updated = taskQueue.retry(taskId);
    if (!updated) return { ok: false, error: 'task is not in a failed state' };
    this.lastRecoveryAction = `retry: requeued task ${taskId} as attempt #${(updated.attempts?.length ?? 0) + 1}`;
    this.emit('command:task-retried', { taskId });
    return { ok: true, attempts: (updated.attempts?.length ?? 0) + 1 };
  }

  /**
   * Skip a genuinely OPTIONAL failed task → terminal 'skipped' (never 'completed'). Required tasks
   * are not skippable.
   */
  public skipTask(taskId: string): { ok: boolean; error?: string } {
    const taskQueue = this.mission.getTaskQueue();
    const task = taskQueue.getTask(taskId);
    if (!task) return { ok: false, error: 'task not found' };
    if (task.required !== false) return { ok: false, error: 'required tasks cannot be skipped' };
    const updated = taskQueue.skip(taskId);
    if (!updated) return { ok: false, error: 'task cannot be skipped from its current state' };
    this.lastRecoveryAction = `skip: optional task ${taskId} marked skipped`;
    this.emit('command:task-skipped', { taskId });
    return { ok: true };
  }

  /**
   * Complete derived mission/execution state. NOT collapsed to "active = live": idle (no mission),
   * running, paused, stalled, completed, and aborted are all distinguishable.
   */
  public getRunState(): MissionRunState {
    const mission = this.mission.getActiveMission();
    if (!this.running) {
      // Terminal/not-running states are distinguishable: completed ≠ aborted ≠ idle.
      if (this.completedFlag) return 'completed';
      if (this.abortedFlag) return 'aborted';
      return 'idle';
    }
    if (mission?.status === 'completed') return 'completed';
    if (this.stallReason) return 'stalled';
    if (this.paused) return 'paused';
    return 'running';
  }

  /**
   * Auto-spawn operators needed for a given kill chain phase
   */
  private autoSpawnForPhase(phase: KillChainPhase): void {
    if (this.llm.getProvider() === 'local-agent') {
      return;
    }
    const phaseOperators: Record<string, OperatorArchetype[]> = {
      [KillChainPhase.RECON]: ['recon'],
      [KillChainPhase.WEAPONIZE]: ['scanner'],
      [KillChainPhase.DELIVER]: ['exploiter'],
      [KillChainPhase.EXPLOIT]: ['exploiter'],
      [KillChainPhase.INSTALL]: ['infiltrator'],
      [KillChainPhase.C2]: ['ghost'],
      [KillChainPhase.ACTIONS]: ['analyst'],
    };

    const needed = phaseOperators[phase] || [];
    for (const archetype of needed) {
      const existing = this.cell.getAvailableOperator(archetype);
      if (!existing) {
        const allOps = this.cell.getAllOperators();
        const hasArchetype = allOps.some(op => op.archetype === archetype);
        if (!hasArchetype) {
          const callsign = `${archetype.charAt(0).toUpperCase() + archetype.slice(1)}-Auto`;
          this.spawnOperator(callsign, archetype);
        }
      }
    }
  }

  // ===========================================================================
  // SSE BROADCAST
  // ===========================================================================

  /**
   * Connect a broadcast function (e.g., from the server's SSE endpoint)
   * so all events stream to the web UI in real-time.
   */
  public connectBroadcast(broadcast: (event: string, data: Record<string, unknown>) => void): void {
    this.on('finding:discovered', (data) => broadcast('finding', data));
    this.on('operator:spawned', (data) => broadcast('operator:spawned', data));
    this.on('operator:burned', (data) => broadcast('operator:burned', data));
    this.on('credential:harvested', (data) => broadcast('credential', data));
    this.on('detection:triggered', (data) => broadcast('detection', data));
    this.on('mission:phase_changed', (data) => broadcast('phase_changed', data));
    this.on('approval:decision', (data) => broadcast('arsenal.approval', data));
    this.on('scan:progress', (data) => broadcast('scan:progress', data));
    this.on('tick', (count) => {
      // Broadcast status every 5 ticks to avoid flooding
      if (typeof count === 'number' && count % 5 === 0) {
        broadcast('status', this.getStatus());
      }
    });
  }

  // ===========================================================================
  // CONVENIENCE METHODS
  // ===========================================================================

  /**
   * Spawn an operator with forwarding setup and agent loop
   */
  public spawnOperator(
    callsign: string,
    archetype: OperatorArchetype
  ): OperatorAgent {
    const operator = this.cell.spawnOperator(callsign, archetype);
    this.setupOperatorEvents(operator);

    // Attach the agent loop scoped to this archetype's SPECIALIZED role toolkit (defaultTools =
    // the curated per-operator tool allowlist). toolCategories stays as a coarse fallback.
    const profile = ARCHETYPE_PROFILES[archetype];
    const maxIterations = this.llm.getProvider() === 'local-agent'
      ? LOCAL_AGENT_MAX_ITERATIONS
      : DEFAULT_AGENT_MAX_ITERATIONS;
    const agentLoop = new AgentLoop(this.llm, this.arsenal, {
      maxIterations,
      maxTokens: 50000,
      toolCategories: profile.toolCategories,
      tools: profile.defaultTools,
    });
    operator.attachArsenal(this.arsenal, agentLoop);
    // [Phase-2] Give the operator the shared board ONLY when swarm coordination is on — so the
    // baseline (coordination off) keeps the solo-operator prompt with zero shared context.
    if (this.coordinationEnabled) operator.attachBoard(this.packBoard);

    // If a white-box source was already set (repo ingested before this operator
    // spawned), hand it to the new operator so it also sees the source excerpt.
    if (this.whiteboxSource) {
      operator.setWhiteboxSource(this.whiteboxSource);
    }

    return operator;
  }

  /**
   * Set the white-box source context for the whole command.
   *
   * Called by the large-repo analysis pipeline (code-ingest → context-pack)
   * with a security-prioritized excerpt of the target's source. Stored, and
   * propagated to every already-spawned operator; operators spawned afterward
   * pick it up in spawnOperator(). Threaded through to each operator's agent
   * loop so the model analyzes the target against its real source.
   */
  public setWhiteboxSource(sourceContext: string): void {
    this.whiteboxSource = sourceContext;
    for (const operator of this.cell.getAllOperators()) {
      operator.setWhiteboxSource(sourceContext);
    }
  }

  /**
   * Coordination telemetry — the machine-readable artifact that distinguishes a coordinated swarm
   * run from N independent agents: how many findings became shared leads, how many spawned targeted
   * follow-up work, and how many distinct findings were chased. Zero across the board (with
   * `enabled:false`) is the single-agent-equivalent baseline.
   */
  public getCoordinationStats(): { enabled: boolean; leadsPosted: number; followupsSpawned: number; uniqueFindingsChased: number } {
    return {
      enabled: this.coordinationEnabled,
      leadsPosted: this.leadsPosted,
      followupsSpawned: this.followupsSpawned,
      uniqueFindingsChased: this.spawnedFollowups.size,
    };
  }

  /**
   * Get command status
   */
  public getStatus(): {
    name: string;
    running: boolean;
    paused: boolean;
    tickCount: number;
    operators: ReturnType<OperatorCell['getStatus']>;
    targets: ReturnType<TargetEnvironment['getStats']>;
    vault: ReturnType<EvidenceVault['getStats']>;
    opsec: ReturnType<OpsecController['getStats']>;
    activeMission: string | null;
    stallReason: string | null;
    stallSince: number | null;
    lastRecoveryAction: string | null;
    /** Complete derived state — 'active:true' never alone means "live". */
    state: MissionRunState;
    blockingTaskIds: string[];
    retryableTaskIds: string[];
    /**
     * Redaction-safe terminal snapshot of the last completed/aborted mission — retained AFTER the
     * mission leaves the active slot so a finished run remains auditable (objective, outcome, why,
     * what was blocked). Null while a mission is live or when none has terminated. Never resurrects
     * the mission as active.
     */
    terminalMission: {
      id: string;
      name: string;
      status: 'completed' | 'aborted';
      family?: string;
      objectiveClass: string;
      objectiveOutcome?: string;
      completionReason?: string;
      finalPhase: string;
      progress: number;
      startedAt?: number;
      completedAt?: number;
      phaseDispositions: Array<{ phase: string; disposition: string; total: number; completed: number; failed: number; blocked: number; skipped: number }>;
      taskSummary: { total: number; completed: number; failed: number; skipped: number; blocked: number; retried: number };
      blockedPrerequisites: Array<{ id: string; name: string; reason: string }>;
      completedPrerequisites: Array<{ id: string; name: string }>;
    } | null;
    progress: ScanProgressEvent[];
    tasks: Array<{
      id: string;
      name: string;
      phase: string;
      status: string;
      operatorType: string;
      required: boolean;
      attempts: number;
      assignedTo?: string;
      result?: { success: boolean; output?: string; error?: string; findings?: string[] };
    }>;
  } {
    const activeMission = this.mission.getActiveMission();
    const taskQueue = this.mission.getTaskQueue();
    // After completion the mission leaves the active slot — fall back to the latest terminal
    // mission so its tasks/outcome remain auditable instead of vanishing.
    const displayMission = activeMission ?? this.mission.getLatestTerminalMission();
    const missionTasks = displayMission ? taskQueue.getForMission(displayMission.id) : [];
    const failedRequired = missionTasks.filter((t) => t.status === 'failed' && t.required !== false);
    const blockingTaskIds = activeMission ? failedRequired.map((t) => t.id) : [];
    const retryableTaskIds = activeMission
      ? missionTasks
        .filter((t) => t.status === 'failed')
        .map((t) => this.describeTaskRecovery(t))
        .filter((d) => d.retryable)
        .map((d) => d.id)
      : [];

    // Build the terminal snapshot (only when nothing is live).
    let terminalMission: ReturnType<TempestCommand['getStatus']>['terminalMission'] = null;
    if (!activeMission && displayMission && (displayMission.status === 'completed' || displayMission.status === 'aborted')) {
      const count = (s: string) => missionTasks.filter((t) => t.status === s).length;
      const objectiveCompletion = deriveObjectiveCompletion(displayMission, missionTasks);
      terminalMission = {
        id: displayMission.id,
        name: displayMission.name,
        status: displayMission.status,
        family: displayMission.missionFamily,
        objectiveClass: displayMission.objectiveClass ?? 'general',
        objectiveOutcome: displayMission.objectiveOutcome,
        completionReason: displayMission.completionReason,
        finalPhase: displayMission.currentPhase,
        progress: displayMission.progress,
        startedAt: displayMission.startedAt,
        completedAt: displayMission.completedAt,
        phaseDispositions: (displayMission.phaseDispositions ?? []).map((d) => ({
          phase: d.phase, disposition: d.disposition, total: d.total,
          completed: d.completed, failed: d.failed, blocked: d.blocked, skipped: d.skipped,
        })),
        taskSummary: {
          total: missionTasks.length,
          completed: count('completed'),
          failed: count('failed'),
          skipped: count('skipped'),
          blocked: count('blocked'),
          retried: missionTasks.filter((t) => (t.attempts?.length ?? 0) > 1).length,
        },
        blockedPrerequisites: objectiveCompletion.blockedPrerequisites,
        completedPrerequisites: objectiveCompletion.completedPrerequisites,
      };
    }

    return {
      name: this.name,
      running: this.running,
      paused: this.paused,
      tickCount: this.tickCount,
      operators: this.cell.getStatus(),
      targets: this.targetEnv.getStats(),
      vault: this.vault.getStats(),
      opsec: this.opsec.getStats(),
      activeMission: activeMission?.id || null,
      stallReason: this.stallReason,
      stallSince: this.stallSince,
      lastRecoveryAction: this.lastRecoveryAction,
      state: this.getRunState(),
      blockingTaskIds,
      retryableTaskIds,
      terminalMission,
      progress: [...this.progressEvents],
      tasks: missionTasks.map(task => ({
            id: task.id,
            name: task.name,
            phase: task.phase,
            status: task.status,
            operatorType: task.operatorType,
            required: task.required !== false,
            attempts: task.attempts?.length ?? 0,
            assignedTo: task.assignedTo,
            result: task.result ? {
              success: task.result.success,
              output: task.result.output,
              error: task.result.error,
              findings: task.result.findings,
            } : undefined,
          })),
    };
  }

  /**
   * Generate engagement report
   */
  public generateReport(missionId?: string): string {
    const mission = missionId
      ? this.mission.getMission(missionId)
      : this.mission.getActiveMission();

    if (!mission) {
      throw new Error('No mission found for reporting');
    }

    const report = this.analysis.generateReport(mission.id, 'full_report');
    return this.analysis.exportToMarkdown(report);
  }
}

// =============================================================================
// TEMPEST INSTANCE
// =============================================================================

/**
 * Full T3MP3ST instance with all components
 */
export interface Tempest {
  command: TempestCommand;
  cell: OperatorCell;
  mission: MissionControl;
  targetEnv: TargetEnvironment;
  vault: EvidenceVault;
  arsenal: Arsenal;
  approval: ApprovalController;
  opsec: OpsecController;
  comms: CommsChannel;
  analysis: AnalysisEngine;
  llm: LLMBackbone;
  // Autonomous Op General
  general: OpGeneral;
  // Advanced modules
  exploit: ExploitEngine;
  scanner: ScannerOrchestrator;
  browser: BrowserAutomation;
  benchmark: BenchmarkRunner;
  reasoning: ReasoningEngine;
  // Elite modules
  cognition: CognitionEngine;
  swarm: SwarmController;
  cloud: CloudSecurityEngine;
  persistence: PersistenceController;
  learning: LearningEngine;
  // Foundational modules
  knowledge: KnowledgeBase;
  protocols: ProtocolHandler;
  evasion: EvasionEngine;
  reporting: ReportingEngine;
  workflow: WorkflowOrchestrator;
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

/**
 * Create a TEMPEST instance
 */
export function createTempest(config: TempestConfig): Tempest {
  const command = new TempestCommand(config);

  return {
    command,
    cell: command.cell,
    mission: command.mission,
    targetEnv: command.targetEnv,
    vault: command.vault,
    arsenal: command.arsenal,
    approval: command.approval,
    opsec: command.opsec,
    comms: command.comms,
    analysis: command.analysis,
    llm: command.llm,
    // Autonomous Op General
    general: command.general,
    // Advanced modules
    exploit: command.exploit,
    scanner: command.scanner,
    browser: command.browser,
    benchmark: command.benchmark,
    reasoning: command.reasoning,
    // Elite modules
    cognition: command.cognition,
    swarm: command.swarm,
    cloud: command.cloud,
    persistence: command.persistence,
    learning: command.learning,
    // Foundational modules
    knowledge: command.knowledge,
    protocols: command.protocols,
    evasion: command.evasion,
    reporting: command.reporting,
    workflow: command.workflow,
  };
}

/**
 * Create a minimal TEMPEST instance for testing
 */
export function createTestTempest(name: string = 'Test Operation'): Tempest {
  return createTempest({
    name,
    llm: {
      provider: 'mock',
      model: 'mock-model',
      maxTokens: 4096,
      temperature: 0.7,
    },
    opsec: createBalancedOpsecConfig(),
    operators: {
      maxConcurrent: 10,
      defaultConfig: {
        maxDetectionRisk: 0.8,
        cooldownMs: 5000,
        maxRetries: 3,
        preferredTechniques: [],
        avoidTechniques: [],
        toolPreferences: [],
      },
    },
    targets: {
      maxConcurrent: 20,
    },
  });
}

/**
 * Create a TEMPEST instance with the best available LLM provider
 */
export function createAutoTempest(name: string = 'Auto Operation'): Tempest {
  const llmConfig = getLLMConfig();

  return createTempest({
    name,
    llm: llmConfig,
    opsec: createBalancedOpsecConfig(),
  });
}

/**
 * Quick start for a stealth operation
 */
export function createStealthOperation(name: string, llmConfig?: LLMConfig): Tempest {
  const config = llmConfig || getLLMConfig();

  return createTempest({
    name,
    llm: config,
    opsec: {
      level: 'silent',
      maxDetectionEvents: 1,
      cooldownAfterDetection: 300000,
      cleanupOnComplete: true,
      avoidDetection: true,
      jitterRange: [5000, 15000],
      trafficBlending: true,
      loggingSanitization: true,
    },
    operators: {
      maxConcurrent: 5,
      defaultConfig: {
        maxDetectionRisk: 0.3,
        cooldownMs: 30000,
        maxRetries: 2,
        preferredTechniques: [],
        avoidTechniques: [],
        toolPreferences: [],
      },
    },
    targets: {
      maxConcurrent: 10,
    },
  });
}

/**
 * Quick start for an aggressive operation
 */
export function createAggressiveOperation(name: string, llmConfig?: LLMConfig): Tempest {
  const config = llmConfig || getLLMConfig();

  return createTempest({
    name,
    llm: config,
    opsec: {
      level: 'loud',
      maxDetectionEvents: 20,
      cooldownAfterDetection: 2000,
      cleanupOnComplete: false,
      avoidDetection: false,
      jitterRange: [100, 500],
      trafficBlending: false,
      loggingSanitization: false,
    },
    operators: {
      maxConcurrent: 15,
      defaultConfig: {
        maxDetectionRisk: 0.95,
        cooldownMs: 1000,
        maxRetries: 5,
        preferredTechniques: [],
        avoidTechniques: [],
        toolPreferences: [],
      },
    },
    targets: {
      maxConcurrent: 50,
    },
  });
}

// =============================================================================
// BANNER
// =============================================================================

/**
 * Get ASCII banner
 */
export function getBanner(): string {
  return `
 ▄▄▄█████▓▓█████  ███▄ ▄███▓ ██▓███  ▓█████   ██████ ▄▄▄█████▓
 ▓  ██▒ ▓▒▓█   ▀ ▓██▒▀█▀ ██▒▓██░  ██▒▓█   ▀ ▒██    ▒ ▓  ██▒ ▓▒
 ▒ ▓██░ ▒░▒███   ▓██    ▓██░▓██░ ██▓▒▒███   ░ ▓██▄   ▒ ▓██░ ▒░
 ░ ▓██▓ ░ ▒▓█  ▄ ▒██    ▒██ ▒██▄█▓▒ ▒▒▓█  ▄   ▒   ██▒░ ▓██▓ ░
   ▒██▒ ░ ░▒████▒▒██▒   ░██▒▒██▒ ░  ░░▒████▒▒██████▒▒  ▒██▒ ░
   ▒ ░░   ░░ ▒░ ░░ ▒░   ░  ░▒▓▒░ ░  ░░░ ▒░ ░▒ ▒▓▒ ▒ ░  ▒ ░░
     ░     ░ ░  ░░  ░      ░░▒ ░      ░ ░  ░░ ░▒  ░ ░    ░
   ░         ░   ░      ░   ░░          ░   ░  ░  ░    ░
             ░  ░       ░               ░  ░      ░

  T3MP3ST - Tactical Execution Multi-agent Platform
            for Elite Security Testing

  Multi-Agent Red Team / Penetration Testing Framework
`;
}

// Default export
export default createTempest;
