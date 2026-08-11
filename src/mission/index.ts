/**
 * T3MP3ST Mission Control
 *
 * Manages missions, tasks, and rules of engagement.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import {
  KillChainPhase,
  type Mission,
  type MissionFamily,
  type MissionObjectiveClass,
  type MissionObjectiveOutcome,
  type Task,
  type TaskAttempt,
  type TaskResult,
  type PhaseDisposition,
  type RulesOfEngagement,
  type OperatorArchetype,
} from '../types/index.js';
import { KILL_CHAIN_ORDER } from '../operators/index.js';

/**
 * Detect the operator's research objective class from the objective + directive text.
 * ORTHOGONAL to the routed MissionFamily (a `web_api` mission can carry an
 * `authorization_lifecycle` objective). No Danalock/target-specific terms.
 *
 * DOMINANT-INTENT MODEL (not keyword counting). A specialized objective requires
 * AFFIRMATIVE specialized intent; the mere presence of authorization vocabulary is a
 * listing, not a focus. Intent signals, in precedence order:
 *   1. BROAD intent (explicit breadth: "comprehensive", "not limited to", "and other
 *      relevant classes", ...) is DECISIVE for `general` — the operator asked for wide
 *      coverage, so a mentioned family is one concern of many.
 *   2. OTHER-family vocabulary alongside authz vocabulary — authorization was LISTED as
 *      one of several families -> `general` ("focus on X, then also test injection" is
 *      mixed intent, and broad is the safe reading).
 *   3. FOCUS intent ("focus on", "exclusively", "concentrate on", "avoid unrelated", ...)
 *      is affirmative narrow intent -> `authorization_lifecycle`.
 *   4. EXCLUSIVITY — authorization is the ONLY security-family vocabulary present — is
 *      weak-affirmative: the operator chose to talk about nothing else, so the lane is
 *      the mission.
 * Ambiguity biases to `general`: misclassifying broad-as-narrow silently skips coverage
 * (the regression this fixes); misclassifying narrow-as-broad only runs extra coverage.
 * An explicit structural override (Guided Hunt brief / launch body `objectiveClass`) is
 * always preferred over this text heuristic — see parseObjectiveClassOverride.
 */
// Authorization-lane vocabulary (the specialized objective family).
const AUTHZ_LANE_VOCAB = /\b(authorization|authorisation|access control|bola|bfla|idor|privilege escalation|role (escalation|boundary)|permission boundar|ownership|cross-(user|tenant|principal)|revocation|downgrade|stale access|session revocation|object.?level|function.?level)\b/i;
// Distinct OTHER vulnerability families — authz mentioned alongside these is a listing.
// NOTE: bare "session" is deliberately absent ("session revocation" is authz-lane); the
// generic "vulnerabilities" is absent (it appears in every mission's default objectives).
const OTHER_FAMILY_VOCAB = /\b(inject\w*|sqli|xss|cross-site scripting|ssrf|csrf|xxe|\brce\b|remote code execution|deserializ\w*|path traversal|file inclusion|file upload|open redirect|clickjack\w*|cors|misconfig\w*|tls|ssl|subdomain( takeover)?|port scan|dns\b|directory (brute|discovery|listing)|content discovery|fuzz\w*|brute.?force|credential stuffing|session (fixation|hijack)|jwt\b|supply chain|dependenc\w+|secret (scan|exposure|leak)|rate limit|template injection|prototype pollution|buffer overflow|malware|phishing|osint|cryptograph\w*|weak cipher|security header|waf)\b/i;
// Explicit breadth intent — decisive for 'general' even when specialized vocabulary appears.
const BROAD_INTENT = /\b(comprehensive|broad|full[- ]?(spectrum|coverage)|wide[- ]ranging|not limited|(?:not?|never|do not|don't) (?:be )?restrict\w*|unrestrict\w*|and other|other (relevant|classes|families|vectors|areas)|any (?:relevant )?(vector|class|family|area)|etc\b\.?|everything|let (?:the )?evidence (?:determine|decide|guide|drive)|wherever (?:the )?evidence|whatever (?:the )?evidence|all (?:vulnerability|vuln) (?:classes|families)|each (?:class|family)|research[- ]prioriti\w+|discovery[- ](?:first|driven))\b/i;
// Affirmative narrow-focus intent — the operator explicitly scopes the mission down.
const FOCUS_INTENT = /\b(focus(?:ed|es|ing)? (?:on|exclusively|specifically|primarily)|exclusively|specifically|primarily|concentrat\w+ on|prioriti[sz]e|narrow(?:ly|ed)? (?:to|on)|deep[- ]dive|limited to|restrict(?:ed)? to|avoid (?:unrelated|generic|other)|instead of (?:generic|broad)|rather than (?:generic|broad)|do not (?:run|perform|do) (?:generic|unrelated))\b/i;

export function detectObjectiveClass(text: string): MissionObjectiveClass {
  const t = String(text || '');
  if (!AUTHZ_LANE_VOCAB.test(t)) return 'general';
  if (BROAD_INTENT.test(t)) return 'general';
  if (OTHER_FAMILY_VOCAB.test(t)) return 'general';
  if (FOCUS_INTENT.test(t)) return 'authorization_lifecycle';
  return 'authorization_lifecycle';
}

/**
 * Validate an explicit STRUCTURAL objective-class override (Guided Hunt brief slot or
 * launch-body field). Structural operator intent always wins over the text heuristic;
 * anything unrecognized is ignored (returns undefined) so detection falls back safely.
 */
export function parseObjectiveClassOverride(value: unknown): MissionObjectiveClass | undefined {
  return value === 'authorization_lifecycle' || value === 'general' ? value : undefined;
}

// =============================================================================
// EVENTS
// =============================================================================

export interface MissionEvents {
  'mission:created': Mission;
  'mission:started': Mission;
  'mission:paused': Mission;
  'mission:resumed': Mission;
  'mission:completed': Mission;
  'mission:aborted': { mission: Mission; reason: string };
  'mission:phase_changed': { mission: Mission; oldPhase: KillChainPhase; newPhase: KillChainPhase };
  'task:created': Task;
  'task:assigned': { task: Task; operatorId: string };
  'task:completed': { task: Task; result: TaskResult };
  'task:failed': { task: Task; error: string };
}

export interface TaskQueueEvents {
  'task:added': Task;
  'task:removed': Task;
  'queue:empty': void;
}

// =============================================================================
// RULES OF ENGAGEMENT
// =============================================================================

export function createDefaultRoE(): RulesOfEngagement {
  return {
    scope: [],
    excludedTargets: [],
    allowedTechniques: [],
    forbiddenTechniques: [],
    maxDetectionEvents: 5,
    requireManualApproval: ['T1078', 'T1059', 'T1548'], // Credential use, command exec, privilege escalation
  };
}

export function createStrictRoE(): RulesOfEngagement {
  return {
    scope: [],
    excludedTargets: [],
    allowedTechniques: [],
    forbiddenTechniques: [
      'T1485', // Data Destruction
      'T1489', // Service Stop
      'T1490', // Inhibit System Recovery
      'T1499', // Endpoint DoS
    ],
    maxDetectionEvents: 2,
    requireManualApproval: ['T1078', 'T1059', 'T1548', 'T1055', 'T1134'],
  };
}

// =============================================================================
// TASK QUEUE
// =============================================================================

export class TaskQueue extends EventEmitter<TaskQueueEvents> {
  private tasks: Task[] = [];

  /**
   * Add a task to the queue
   */
  add(task: Task): void {
    this.tasks.push(task);
    this.sortByPriority();
    this.emit('task:added', task);
  }

  /**
   * Add multiple tasks
   */
  addMany(tasks: Task[]): void {
    for (const task of tasks) {
      this.add(task);
    }
  }

  /**
   * Get the next pending task
   */
  getNext(): Task | undefined {
    return this.tasks.find(t => t.status === 'pending');
  }

  /**
   * Get the next pending task for a specific operator type
   */
  getNextForArchetype(archetype: OperatorArchetype): Task | undefined {
    return this.tasks.find(t => t.status === 'pending' && t.operatorType === archetype);
  }

  /**
   * Get all pending tasks
   */
  getPending(): Task[] {
    // Priority-ordered (desc): tool-verified follow-up tasks carry a higher priority than the static
    // seed tasks, so the swarm chases its hottest verified leads first — light orchestration.
    return this.tasks.filter(t => t.status === 'pending').sort((a, b) => b.priority - a.priority);
  }

  /**
   * Get all tasks for a mission
   */
  getForMission(missionId: string): Task[] {
    return this.tasks.filter(t => t.missionId === missionId);
  }

  /**
   * Update a task's status
   */
  updateStatus(taskId: string, status: Task['status'], result?: TaskResult): Task | undefined {
    const task = this.tasks.find(t => t.id === taskId);
    if (task) {
      // `blocked` is a TERMINAL record (missing-fixture prerequisite): it must never transition
      // back into dispatchable work — that would fabricate coverage the runtime cannot perform.
      // When the operator supplies the fixture, the honest path is a NEW mission/attempt.
      if (task.status === 'blocked') return undefined;
      task.status = status;
      if (result) task.result = result;
      if (status === 'in_progress') task.startedAt = Date.now();
      if (status === 'completed' || status === 'failed' || status === 'blocked' || status === 'skipped') task.completedAt = Date.now();
    }
    return task;
  }

  /**
   * Close out the current execution attempt in the task's immutable attempt history.
   * Called on terminal transitions (complete/fail/timeout). History is never rewritten — a retry
   * appends a NEW attempt; the prior attempt's outcome stays visible for audit/recovery.
   */
  recordAttempt(taskId: string, outcome: TaskAttempt['outcome'], error?: string): void {
    const task = this.tasks.find(t => t.id === taskId);
    if (!task) return;
    if (!task.attempts) task.attempts = [];
    const open = task.attempts[task.attempts.length - 1];
    if (open && open.endedAt == null) {
      open.endedAt = Date.now();
      open.outcome = outcome;
      if (error) open.error = error;
    } else {
      // No open attempt (e.g. direct fail without a dispatch) — record a closed one.
      task.attempts.push({ attemptId: randomUUID(), n: task.attempts.length + 1, startedAt: task.startedAt ?? Date.now(), endedAt: Date.now(), outcome, error });
    }
  }

  /** Begin a new attempt (called on dispatch). */
  beginAttempt(taskId: string): void {
    const task = this.tasks.find(t => t.id === taskId);
    if (!task) return;
    if (!task.attempts) task.attempts = [];
    task.attempts.push({ attemptId: randomUUID(), n: task.attempts.length + 1, startedAt: Date.now(), outcome: 'timeout_pending' });
  }

  /**
   * Retry a FAILED task: requeue as pending WITHOUT erasing its attempt history. The prior
   * timeout/failure stays recorded in `attempts`; this creates a new legitimate attempt.
   * Returns false if the task is not currently failed (nothing to retry) — never retries a task
   * whose underlying operation may still be running (the caller checks timedOutDispatches first).
   */
  retry(taskId: string): Task | undefined {
    const task = this.tasks.find(t => t.id === taskId);
    if (!task || task.status !== 'failed') return undefined;
    task.status = 'pending';
    task.completedAt = undefined;
    // Keep task.result (the prior attempt's error) until the new attempt produces a result —
    // it is the audit trail for why a retry was needed. attempts[] already holds the history.
    return task;
  }

  /**
   * Skip a genuinely OPTIONAL failed task → terminal 'skipped'. NEVER rewrites it as 'completed'.
   * Required tasks are not skippable (returns undefined).
   */
  skip(taskId: string): Task | undefined {
    const task = this.tasks.find(t => t.id === taskId);
    if (!task) return undefined;
    const isRequired = task.required !== false; // default true
    if (isRequired) return undefined;
    if (task.status !== 'failed' && task.status !== 'pending') return undefined;
    task.status = 'skipped';
    task.completedAt = Date.now();
    this.recordAttempt(taskId, 'failed', 'skipped by operator (optional task)');
    return task;
  }

  /**
   * Get a task by ID
   */
  getTask(taskId: string): Task | undefined {
    return this.tasks.find(t => t.id === taskId);
  }

  /**
   * Mark a task as assigned to an operator
   */
  assign(taskId: string, operatorId: string): void {
    const task = this.tasks.find(t => t.id === taskId);
    if (task) {
      task.status = 'assigned';
      task.assignedTo = operatorId;
      task.startedAt = Date.now();
    }
  }

  /**
   * Mark a task as completed with result
   */
  complete(taskId: string, result: TaskResult): void {
    this.updateStatus(taskId, 'completed', result);
  }

  /**
   * Mark a task as failed with error message
   */
  fail(taskId: string, error: string): void {
    this.updateStatus(taskId, 'failed', { success: false, error });
  }

  /**
   * Remove a task
   */
  remove(taskId: string): Task | undefined {
    const index = this.tasks.findIndex(t => t.id === taskId);
    if (index !== -1) {
      const [task] = this.tasks.splice(index, 1);
      this.emit('task:removed', task);
      if (this.tasks.length === 0) {
        this.emit('queue:empty');
      }
      return task;
    }
    return undefined;
  }

  /**
   * Sort tasks by priority
   */
  private sortByPriority(): void {
    this.tasks.sort((a, b) => b.priority - a.priority);
  }

  /**
   * Get queue size
   */
  get size(): number {
    return this.tasks.length;
  }

  /**
   * Get pending count
   */
  get pendingCount(): number {
    return this.tasks.filter(t => t.status === 'pending').length;
  }

  /**
   * Clear the queue
   */
  clear(): void {
    this.tasks = [];
  }
}

// =============================================================================
// MISSION CONTROL
// =============================================================================

export class MissionControl extends EventEmitter<MissionEvents> {
  private missions: Map<string, Mission> = new Map();
  private taskQueue: TaskQueue;
  private activeMissionId: string | null = null;

  constructor() {
    super();
    this.taskQueue = new TaskQueue();

    // Forward task queue events
    this.taskQueue.on('task:added', task => this.emit('task:created', task));
  }

  /**
   * Create a new mission
   */
  createMission(params: {
    name: string;
    description?: string;
    objectives: string[];
    phases?: KillChainPhase[];
    rules?: RulesOfEngagement;
    objectiveClass?: MissionObjectiveClass;
    missionFamily?: MissionFamily;
  }): Mission {
    const mission: Mission = {
      id: randomUUID(),
      name: params.name,
      description: params.description,
      objectives: params.objectives,
      phases: params.phases || KILL_CHAIN_ORDER,
      rules: params.rules || createDefaultRoE(),
      status: 'planning',
      currentPhase: params.phases?.[0] || KillChainPhase.RECON,
      progress: 0,
      // Objective class is orthogonal to MissionFamily: detect from the objective text when not
      // explicitly supplied, so a narrow authorization directive binds which tasks get seeded.
      objectiveClass: params.objectiveClass ?? detectObjectiveClass(params.objectives.join(' ')),
      missionFamily: params.missionFamily,
    };

    this.missions.set(mission.id, mission);
    this.emit('mission:created', mission);

    return mission;
  }

  /**
   * Start a mission
   */
  startMission(missionId: string): Mission {
    const mission = this.missions.get(missionId);
    if (!mission) {
      throw new Error(`Mission ${missionId} not found`);
    }

    if (mission.status !== 'planning' && mission.status !== 'paused') {
      throw new Error(`Cannot start mission in ${mission.status} status`);
    }

    mission.status = 'active';
    mission.startedAt = Date.now();
    this.activeMissionId = missionId;

    this.emit('mission:started', mission);

    return mission;
  }

  /**
   * Generate initial tasks for a target under the active mission.
   * Called when a target is added or when a mission starts with existing targets.
   *
   * OBJECTIVE FIDELITY: when the mission carries a narrow objectiveClass (e.g.
   * authorization_lifecycle), this seeds the OBJECTIVE lane (bounded prerequisite recon +
   * current-principal baselines + explicit blocked prerequisites) instead of the full generic
   * recon battery. Generic recon is reduced to a labeled prerequisite subset so prerequisites
   * never silently become the entire mission.
   */
  generateTasksForTarget(targetAddress: string): void {
    const mission = this.getActiveMission();
    if (!mission) return;

    // Check if we already have tasks for this target (avoid duplicates)
    const existingTasks = this.taskQueue.getForMission(mission.id);
    const alreadyHasTasksForTarget = existingTasks.some(t =>
      t.description.includes(targetAddress)
    );
    if (alreadyHasTasksForTarget) return;

    if (mission.objectiveClass === 'authorization_lifecycle') {
      this.taskQueue.addMany(createAuthorizationObjectiveTasks(mission.id, targetAddress));
      return;
    }

    // Default: general coverage — start with recon tasks.
    const reconTasks = createReconTasks(mission.id, targetAddress);
    this.taskQueue.addMany(reconTasks);
  }

  /**
   * Generate next-phase tasks based on the current mission phase and target.
   * Called by the tick loop when current phase tasks are all done.
   */
  generateNextPhaseTasks(targetAddress: string): void {
    const mission = this.getActiveMission();
    if (!mission) return;

    // OBJECTIVE FIDELITY: a narrow objective mission does NOT advance into the generic
    // vuln-scan/exploit batteries. The authorization objective lane is self-contained; generic
    // phase templates would re-introduce the exact off-objective recon the directive forbids.
    // Only the confirmatory analysis/synthesis step is allowed to run at the end.
    if (mission.objectiveClass === 'authorization_lifecycle') {
      if (mission.currentPhase === KillChainPhase.ACTIONS) {
        this.taskQueue.addMany(createAnalysisTasks(mission.id, targetAddress));
      }
      return;
    }

    const phase = mission.currentPhase;
    let tasks: Task[] = [];

    switch (phase) {
      case KillChainPhase.WEAPONIZE:
        tasks = createVulnScanTasks(mission.id, targetAddress);
        break;
      case KillChainPhase.DELIVER:
        tasks = createExploitTasks(mission.id, targetAddress);
        break;
      case KillChainPhase.ACTIONS:
        tasks = createAnalysisTasks(mission.id, targetAddress);
        break;
    }

    if (tasks.length > 0) {
      this.taskQueue.addMany(tasks);
    }
  }

  /**
   * Pause a mission
   */
  pauseMission(missionId: string): Mission {
    const mission = this.missions.get(missionId);
    if (!mission) {
      throw new Error(`Mission ${missionId} not found`);
    }

    if (mission.status !== 'active') {
      throw new Error(`Cannot pause mission in ${mission.status} status`);
    }

    mission.status = 'paused';
    this.emit('mission:paused', mission);

    return mission;
  }

  /**
   * Resume a mission
   */
  resumeMission(missionId: string): Mission {
    const mission = this.missions.get(missionId);
    if (!mission) {
      throw new Error(`Mission ${missionId} not found`);
    }

    if (mission.status !== 'paused') {
      throw new Error(`Cannot resume mission in ${mission.status} status`);
    }

    mission.status = 'active';
    this.emit('mission:resumed', mission);

    return mission;
  }

  /**
   * Complete a mission
   */
  completeMission(missionId: string): Mission {
    const mission = this.missions.get(missionId);
    if (!mission) {
      throw new Error(`Mission ${missionId} not found`);
    }

    // Record the FINAL phase's truthful disposition before closing out.
    this.recordPhaseDisposition(missionId);

    mission.status = 'completed';
    mission.completedAt = Date.now();
    mission.progress = 100;
    // Objective fidelity: completion is more than "task queue drained" — record whether the
    // objective actually received evidence (tested/blocked/unresolved), derived from the lane tasks.
    const completion = deriveObjectiveCompletion(mission, this.taskQueue.getForMission(missionId));
    mission.objectiveOutcome = completion.outcome;
    mission.completionReason = completion.reason;

    if (this.activeMissionId === missionId) {
      this.activeMissionId = null;
    }

    this.emit('mission:completed', mission);

    return mission;
  }

  /**
   * Record how the mission's CURRENT phase concluded — truthfully distinguishing real execution
   * from "the objective lane had no work here". Idempotent per phase (re-recording replaces the
   * prior entry for that phase). Called when leaving a phase (advance) and at completion.
   */
  recordPhaseDisposition(missionId: string): void {
    const mission = this.missions.get(missionId);
    if (!mission) return;
    const phaseTasks = this.taskQueue.getForMission(missionId).filter((t) => t.phase === mission.currentPhase);
    const count = (s: Task['status']) => phaseTasks.filter((t) => t.status === s).length;
    const completed = count('completed');
    const failed = count('failed');
    const blocked = count('blocked');
    const skipped = count('skipped');
    const disposition: PhaseDisposition['disposition'] =
      phaseTasks.length === 0 ? 'no_eligible_work'
        : failed > 0 ? 'failed'
          : completed > 0 ? 'executed'
            : blocked > 0 ? 'blocked_prerequisite'
              : 'no_eligible_work';
    if (!mission.phaseDispositions) mission.phaseDispositions = [];
    mission.phaseDispositions = [
      ...mission.phaseDispositions.filter((d) => d.phase !== mission.currentPhase),
      { phase: mission.currentPhase, disposition, total: phaseTasks.length, completed, failed, blocked, skipped, recordedAt: Date.now() },
    ];
  }

  /**
   * The most recently terminated (completed/aborted) mission — lets the status API keep serving a
   * truthful terminal snapshot after the mission leaves the active slot. Never resurrects it live.
   */
  getLatestTerminalMission(): Mission | undefined {
    return this.getAllMissions()
      .filter((m) => m.status === 'completed' || m.status === 'aborted')
      .sort((a, b) => (b.completedAt ?? 0) - (a.completedAt ?? 0))[0];
  }

  /**
   * Abort a mission
   */
  abortMission(missionId: string, reason: string): Mission {
    const mission = this.missions.get(missionId);
    if (!mission) {
      throw new Error(`Mission ${missionId} not found`);
    }

    mission.status = 'aborted';
    mission.completedAt = Date.now();

    if (this.activeMissionId === missionId) {
      this.activeMissionId = null;
    }

    this.emit('mission:aborted', { mission, reason });

    return mission;
  }

  /**
   * Advance to the next phase
   */
  advancePhase(missionId: string): Mission {
    const mission = this.missions.get(missionId);
    if (!mission) {
      throw new Error(`Mission ${missionId} not found`);
    }

    const currentIndex = mission.phases.indexOf(mission.currentPhase);
    if (currentIndex === -1 || currentIndex >= mission.phases.length - 1) {
      throw new Error('No more phases to advance to');
    }

    const oldPhase = mission.currentPhase;
    mission.currentPhase = mission.phases[currentIndex + 1];
    mission.progress = ((currentIndex + 1) / mission.phases.length) * 100;

    this.emit('mission:phase_changed', { mission, oldPhase, newPhase: mission.currentPhase });

    return mission;
  }

  /**
   * Get a mission by ID
   */
  getMission(missionId: string): Mission | undefined {
    return this.missions.get(missionId);
  }

  /**
   * Get the active mission
   */
  getActiveMission(): Mission | undefined {
    return this.activeMissionId ? this.missions.get(this.activeMissionId) : undefined;
  }

  /**
   * Get all missions
   */
  getAllMissions(): Mission[] {
    return Array.from(this.missions.values());
  }

  /**
   * Create a task for a mission
   */
  createTask(params: {
    missionId: string;
    name: string;
    description: string;
    phase: KillChainPhase;
    operatorType: OperatorArchetype;
    priority?: number;
    dependencies?: string[];
  }): Task {
    const task: Task = {
      id: randomUUID(),
      missionId: params.missionId,
      name: params.name,
      description: params.description,
      phase: params.phase,
      operatorType: params.operatorType,
      status: 'pending',
      priority: params.priority || 5,
      dependencies: params.dependencies || [],
      createdAt: Date.now(),
    };

    this.taskQueue.add(task);

    return task;
  }

  /**
   * Get the task queue
   */
  getTaskQueue(): TaskQueue {
    return this.taskQueue;
  }

  /**
   * Check if a technique is allowed by the RoE
   */
  isTechniqueAllowed(missionId: string, technique: string): boolean {
    const mission = this.missions.get(missionId);
    if (!mission) return false;

    const { rules } = mission;

    // Check if explicitly forbidden
    if (rules.forbiddenTechniques.includes(technique)) {
      return false;
    }

    // If allowedTechniques is specified and not empty, technique must be in it
    if (rules.allowedTechniques.length > 0 && !rules.allowedTechniques.includes(technique)) {
      return false;
    }

    return true;
  }

  /**
   * Check if a technique requires manual approval
   */
  requiresApproval(missionId: string, technique: string): boolean {
    const mission = this.missions.get(missionId);
    if (!mission) return true;

    return mission.rules.requireManualApproval.includes(technique);
  }

  /**
   * Get mission statistics
   */
  getStats(): {
    total: number;
    active: number;
    completed: number;
    aborted: number;
    planning: number;
    paused: number;
  } {
    const missions = this.getAllMissions();

    return {
      total: missions.length,
      active: missions.filter(m => m.status === 'active').length,
      completed: missions.filter(m => m.status === 'completed').length,
      aborted: missions.filter(m => m.status === 'aborted').length,
      planning: missions.filter(m => m.status === 'planning').length,
      paused: missions.filter(m => m.status === 'paused').length,
    };
  }
}

// =============================================================================
// TASK FACTORIES
// =============================================================================

export function createReconTasks(missionId: string, targetAddress: string): Task[] {
  const tasks: Task[] = [];

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'DNS Enumeration',
    description: `Enumerate all DNS record types (A, AAAA, MX, TXT, NS, SOA, CNAME) for ${targetAddress}. Identify hosting providers, mail servers, SPF/DKIM/DMARC configuration, and any related domains.`,
    phase: KillChainPhase.RECON,
    operatorType: 'recon',
    status: 'pending',
    priority: 10,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Port Scanning & Service Detection',
    description: `Scan ${targetAddress} for open ports and detect running services with version information. Start with top 1000 ports, then expand if significant results are found. Identify the full attack surface.`,
    phase: KillChainPhase.RECON,
    operatorType: 'recon',
    status: 'pending',
    priority: 9,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Web Probing & Technology Fingerprinting',
    description: `Probe all HTTP/HTTPS services on ${targetAddress}. Check response headers, server banners, technology stack, CMS detection, security headers, robots.txt, sitemap.xml, and common paths. Identify frameworks, libraries, and potential misconfigurations.`,
    phase: KillChainPhase.RECON,
    operatorType: 'recon',
    status: 'pending',
    priority: 8,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Content Discovery',
    description: `Discover hidden directories, files, API endpoints, admin panels, and backup files on ${targetAddress} using directory brute-forcing and common path checks.`,
    phase: KillChainPhase.RECON,
    operatorType: 'recon',
    status: 'pending',
    priority: 7,
    dependencies: [],
    createdAt: Date.now(),
  });

  return tasks;
}

export function createVulnScanTasks(missionId: string, targetAddress: string): Task[] {
  const tasks: Task[] = [];

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Automated Vulnerability Scan',
    description: `Run automated vulnerability scanning against ${targetAddress}. Check for known CVEs, common misconfigurations, and security issues. Start with critical/high severity checks, then medium/low.`,
    phase: KillChainPhase.WEAPONIZE,
    operatorType: 'scanner',
    status: 'pending',
    priority: 10,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Web Application Security Testing',
    description: `Test ${targetAddress} for OWASP Top 10 vulnerabilities: SQL injection, XSS, SSRF, broken authentication, access control issues, security misconfigurations. Validate all findings with manual confirmation.`,
    phase: KillChainPhase.WEAPONIZE,
    operatorType: 'scanner',
    status: 'pending',
    priority: 9,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Network Service Vulnerability Assessment',
    description: `Assess network services on ${targetAddress} for vulnerabilities: default credentials, known CVEs for detected versions, protocol weaknesses, and misconfigurations.`,
    phase: KillChainPhase.WEAPONIZE,
    operatorType: 'scanner',
    status: 'pending',
    priority: 8,
    dependencies: [],
    createdAt: Date.now(),
  });

  return tasks;
}

export function createExploitTasks(missionId: string, targetAddress: string): Task[] {
  const tasks: Task[] = [];

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Exploit Confirmed Vulnerabilities',
    description: `Review confirmed vulnerability findings for ${targetAddress} and exploit the highest-severity issues to demonstrate real-world impact. Prove code execution, data access, or authentication bypass with minimal-impact payloads. Document full evidence chain.`,
    phase: KillChainPhase.DELIVER,
    operatorType: 'exploiter',
    status: 'pending',
    priority: 10,
    dependencies: [],
    createdAt: Date.now(),
  });

  return tasks;
}

export function createAnalysisTasks(missionId: string, targetAddress: string): Task[] {
  const tasks: Task[] = [];

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Finding Verification & Report Synthesis',
    description: `Verify and synthesize the findings already gathered against ${targetAddress}. Validate severity ratings against demonstrated impact (a scanner observation is NOT a proven vulnerability), identify attack chains, calculate CVSS scores, prioritize remediation, and produce the report. Any live requests here are CONFIRMATORY re-tests of existing findings within the already-authorized scope — this phase re-verifies, it does not open new discovery or broaden scope.`,
    phase: KillChainPhase.ACTIONS,
    operatorType: 'analyst',
    status: 'pending',
    priority: 10,
    dependencies: [],
    createdAt: Date.now(),
  });

  return tasks;
}

/**
 * AUTHORIZATION-LIFECYCLE objective lane — seeded instead of the generic recon battery when the
 * operator's objective is authenticated authorization testing. Honest by construction: it runs the
 * legitimate bounded prerequisites and the CURRENT-principal baselines the runtime can actually
 * perform, and it surfaces the multi-principal / state fixtures the runtime CANNOT satisfy as
 * explicit blocked work — it does NOT fabricate A/B coverage.
 *
 * Every task carries `[objective:authorization_lifecycle]` and a `lane:` tag so downstream reporting
 * can distinguish objective work from prerequisite recon.
 */
export function createAuthorizationObjectiveTasks(missionId: string, targetAddress: string): Task[] {
  const mk = (name: string, description: string, phase: KillChainPhase, operatorType: OperatorArchetype, priority: number): Task => ({
    id: randomUUID(),
    missionId,
    name,
    description: `[objective:authorization_lifecycle] ${description}`,
    phase,
    operatorType,
    status: 'pending',
    priority,
    dependencies: [],
    createdAt: Date.now(),
  });
  // A BLOCKED prerequisite is a terminal RECORD, not executable work: it must never be dispatched
  // to an operator (an LLM narrating "this is blocked" is not a test, and a 'completed' terminal
  // state would falsely read as objective coverage). It seeds as status 'blocked' and stays there.
  const mkBlocked = (name: string, description: string, phase: KillChainPhase, priority: number): Task => ({
    ...mk(name, description, phase, 'analyst', priority),
    status: 'blocked',
    // `required` stays at its default (true): this IS required objective work — honestly blocked by
    // a missing fixture. The stall machinery keys on `failed`, and `blocked` is terminal, so this
    // never stalls the mission; it terminates cleanly with objectiveOutcome blocked/partial.
    completedAt: Date.now(),
    result: { success: false, error: 'blocked: required fixture unavailable (see description)' },
  });

  return [
    // ── Bounded prerequisite recon (labeled, minimal) — enumerate the API surface so authz
    //    probes have routes to target. This is a prerequisite, NOT the objective. ──
    mk(
      'Prerequisite: authenticated API surface map',
      `lane:prerequisite. Map the authenticated API surface of ${targetAddress} needed to scope authorization tests: enumerate routes/resources (including any OpenAPI/Swagger spec) using the configured authenticated context (http_request/api_endpoint_discovery/curl_request), record each route + method + owning-resource selector. This is prerequisite recon in service of the authorization objective — do NOT broaden into generic DNS/port/banner/TLS/CSP scanning.`,
      KillChainPhase.RECON,
      'recon',
      10,
    ),
    // ── Current-principal baseline (the only authenticated identity the runtime holds) ──
    mk(
      'Baseline: current-principal access map',
      `lane:objective. Using the configured authenticated context, establish the CURRENT principal's baseline on ${targetAddress}: which owned resources/routes it can read and mutate (list own resources, read own profile/role, perform a permitted state change). Record each as evidence with authContextApplied provenance. These baselines are the reference a cross-principal differential would be compared against.`,
      KillChainPhase.RECON,
      'scanner',
      9,
    ),
    // ── Explicit blocked prerequisite: second principal / differential cannot be fabricated ──
    mkBlocked(
      'BLOCKED prerequisite: cross-principal differential (Principal B)',
      `lane:objective status:blocked-prerequisite. Cross-principal authorization testing (BOLA/BFLA) on ${targetAddress} requires a SECOND controlled principal (Principal B) with its own authenticated session, plus a known resource owned by Principal A. The runtime currently holds a single authenticated identity and no Principal/Resource fixture model, so a true A->B differential CANNOT be executed here. DO NOT substitute generic recon. Report this prerequisite as BLOCKED and request Principal B credentials / an owned-resource fixture from the operator.`,
      KillChainPhase.WEAPONIZE,
      9,
    ),
    // ── Explicit blocked prerequisite: lifecycle/state-transition differential ──
    mkBlocked(
      'BLOCKED prerequisite: authorization lifecycle differential (revoke/downgrade -> replay)',
      `lane:objective status:blocked-prerequisite. Authorization-lifecycle testing on ${targetAddress} (authorized -> revoke/downgrade/expire -> replay identical request -> verify access disappears) requires a controlled state transition and a before/after differential executor. The runtime has no structured PRE->ACTION->STATE->RETEST->DIFF work order, so this cannot be executed here. Report as BLOCKED and request the state-change fixture (e.g. a revocable grant / role assignment) from the operator.`,
      KillChainPhase.WEAPONIZE,
      8,
    ),
  ];
}

/**
 * Derive the objective outcome for a mission at completion — "did the objective actually get
 * evidence?", NOT "did the task queue drain?". Conservative: a mission whose objective lane never
 * produced supporting evidence is reported honestly as blocked/untested rather than complete.
 */
export function deriveObjectiveOutcome(mission: Mission, tasks: Task[]): MissionObjectiveOutcome {
  return deriveObjectiveCompletion(mission, tasks).outcome;
}

export interface ObjectiveCompletion {
  outcome: MissionObjectiveOutcome;
  /** Plain-language, redaction-safe reason for the outcome (fixture names only — never secrets). */
  reason: string;
  /** Objective-lane tasks that could not execute because a required fixture is missing. */
  blockedPrerequisites: Array<{ id: string; name: string; reason: string }>;
  /** Prerequisite/objective-lane tasks that DID run to completion (e.g. API inventory, baselines). */
  completedPrerequisites: Array<{ id: string; name: string }>;
}

/**
 * Full objective-completion assessment: outcome + auditable reason + the blocked/completed
 * prerequisite breakdown. Single source of truth used by completeMission, the status endpoint,
 * and the mission-context ledger so all three tell the SAME story.
 */
export function deriveObjectiveCompletion(mission: Mission, tasks: Task[]): ObjectiveCompletion {
  const laneTasks = tasks.filter((t) => t.description.includes('[objective:authorization_lifecycle]'));
  const isBlocked = (t: Task) => t.status === 'blocked' || t.description.includes('status:blocked-prerequisite');
  const objectiveTasks = laneTasks.filter((t) => t.description.includes('lane:objective'));
  const blockedPrereqTasks = laneTasks.filter(isBlocked);
  const ranObjective = objectiveTasks.filter((t) => !isBlocked(t) && t.status === 'completed');
  const completedLane = laneTasks.filter((t) => !isBlocked(t) && t.status === 'completed');

  const blockedPrerequisites = blockedPrereqTasks.map((t) => ({
    id: t.id,
    name: t.name,
    reason: t.result?.error || 'required fixture unavailable (see task description)',
  }));
  const completedPrerequisites = completedLane.map((t) => ({ id: t.id, name: t.name }));

  if (mission.objectiveClass !== 'authorization_lifecycle') {
    return {
      outcome: 'met',
      reason: 'general mission — full kill-chain coverage (no narrow objective gate)',
      blockedPrerequisites,
      completedPrerequisites,
    };
  }

  // A missing second principal / state fixture means the central hypothesis could not be exercised.
  if (blockedPrerequisites.length > 0 && ranObjective.length === 0) {
    return {
      outcome: 'blocked',
      reason: 'objective blocked: missing controlled secondary principal / owned-resource / state-transition fixture — only bounded prerequisites ran',
      blockedPrerequisites,
      completedPrerequisites,
    };
  }
  if (ranObjective.length === 0) {
    return {
      outcome: 'untested',
      reason: 'objective lane never produced completed work',
      blockedPrerequisites,
      completedPrerequisites,
    };
  }
  // Current-principal baselines ran, but the differential/lifecycle prerequisites stayed blocked:
  // the objective was only partially exercised.
  if (blockedPrerequisites.length > 0) {
    return {
      outcome: 'partial',
      reason: 'current-principal baseline completed; cross-principal / lifecycle differentials blocked on missing fixtures — no multi-principal coverage claimed',
      blockedPrerequisites,
      completedPrerequisites,
    };
  }
  return {
    outcome: 'partial',
    reason: 'objective lane ran without a full differential matrix — single-principal coverage only',
    blockedPrerequisites,
    completedPrerequisites,
  };
}
