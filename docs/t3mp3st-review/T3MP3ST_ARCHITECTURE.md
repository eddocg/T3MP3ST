# T3MP3ST — Architecture

> **Audit basis.** Read-only static analysis of the repository at commit `afc9dad` (branch `develop`).
> Source code is treated as the ultimate authority. Every important claim carries a `file:line` citation.
> Labels used throughout: **[Confirmed]** = read directly in source · **[Inference]** = derived, not directly stated ·
> **[UNRESOLVED]** = could not be determined with confidence from the files reviewed.
> No source was modified, no dependencies installed, no tests run, no traffic sent to any target.

---

## 1. What T3MP3ST is (system identity)

T3MP3ST ("TEMPEST" — *Tactical Execution Multi-agent Platform for Elite Security Testing*, `package.json:1-3`) is a
**modular TypeScript monolith** that orchestrates LLM-driven, evidence-disciplined offensive-security testing against
**authorized** targets. It is delivered as three co-resident entrypoints over one shared core:

- an **HTTP server** (`src/server.ts`, ~8,078 lines, ~130 Express routes) that backs the browser "War Room" UI;
- a **CLI** (`src/cli.ts`, `bin: tempest`/`t3mp3st`, `package.json:102-105`);
- an **MCP server** (`src/mcp-server.ts`) exposing the same engine to MCP clients.

All three wrap the execution engine `TempestCommand` (`src/index.ts`). The project is ESM (`"type":"module"`), targets
Node ≥ 22.19 (`package.json:157-159`), builds with `tsc`, runs in dev via `tsx`, and tests with `vitest`. License is
AGPL-3.0-or-later (`package.json:115`).

**Design intent [Confirmed]:** keyless-by-default operation (a connected local coding agent — Claude Code / Codex /
Hermes / OpenCode / Oh My Pi — or an offline local model can drive the LLM role, `src/agent/local-agents.ts`), an
**evidence-first** research loop (claims are hypotheses until tool-proven), and **layered human-in-the-loop gates**
before any live action.

---

## 2. Component map (ports & adapters)

```
                    ┌──────────────────────────────────────────────────────────────┐
   Operator (human) │                     ENTRYPOINTS                               │
        │           │  War Room SPA (docs/index.html)  ── HTTP ──► src/server.ts    │
        │──────────►│  CLI (src/cli.ts)                                             │
                    │  MCP (src/mcp-server.ts)                                       │
                    └───────────────────────────────┬──────────────────────────────┘
                                                     │  (all wrap)
                                                     ▼
                    ┌──────────────────────────────────────────────────────────────┐
                    │            TempestCommand — execution engine (src/index.ts)   │
                    │  tick loop · TargetEnvironment · OpsecController · Arsenal     │
                    │  scope sync · ApprovalController wiring · OperatorAgent(s)     │
                    └───┬───────────────┬───────────────────┬──────────────────┬────┘
                        │               │                   │                  │
        ┌───────────────▼──┐   ┌────────▼────────┐   ┌──────▼───────┐   ┌──────▼────────┐
        │ Admiral          │   │ OpGeneral       │   │ Arsenal      │   │ Evidence /    │
        │ (intake/planner) │──►│ (planner/       │──►│ (tool gate + │   │ Findings /    │
        │ src/admiral      │   │  orchestrator)  │   │  execution)  │   │ Hypotheses    │
        │                  │   │ src/general     │   │ src/arsenal  │   │ ledgers       │
        └──────────────────┘   └─────────────────┘   └──────┬───────┘   │ (in server.ts)│
                                                            │           └───────────────┘
                                        ┌───────────────────▼─────────────────┐
                                        │ scopeViolation() gate → Approval-    │
                                        │ Controller.gate() → tool.handler →   │
                                        │ runSubprocess()/execFileAsync()      │
                                        └──────────────────────────────────────┘
```

### 2.1 Core modules

| Module | File(s) | Role | Evidence |
|---|---|---|---|
| **Execution engine** | `src/index.ts` | `TempestCommand`: owns the tick loop, `TargetEnvironment`, `OpsecController`, `Arsenal`, scope sync, approval-controller wiring, operator agents | `src/index.ts:283+` (class), `:415` (`setApprovalController`), `:545-550` (`syncArsenalScope`) [Confirmed] |
| **Admiral** | `src/admiral/index.ts` | Conversational **intake + planner-only**. Never executes. Converts a `MissionBrief` → `Directive` via `briefToDirective()` | `src/admiral/index.ts:1-19` (header), `:212-221` (`briefToDirective`) [Confirmed] |
| **Op General** | `src/general/index.ts` (~1,597 lines) | Planner/orchestrator. `planOperation()` builds an `OpPlan`; `reviewPlan()` scores plan quality and can force a hold; `executePlan()` runs it | `src/general/index.ts:341-383` (`planOperation`), `:1097-1220` (`reviewPlan`) [Confirmed] |
| **Arsenal** | `src/arsenal/index.ts` (~3,516 lines), `catalog.ts`, `adapter-tools.ts`, `post-ex.ts`, `parsers.ts`, `takeover.ts` | Tool registry + the two hard execution gates (scope, approval) + subprocess runner | `src/arsenal/index.ts:370-430` (`execute`), `:251-287` (`scopeViolation`) [Confirmed] |
| **Approval (tool tier)** | `src/arsenal/approval.ts` (197 lines) | `ApprovalController`: fail-safe deny for gated risk tiers | `src/arsenal/approval.ts` [Confirmed] |
| **Approval (server tier)** | `src/server.ts` | `ApprovalRequest` ("receipt") + `guardAction()`/`blockForApproval()` | `src/server.ts:1319-1332` [Confirmed] |
| **OPSEC** | `src/opsec/index.ts` | `OpsecController`: detection-count → auto-pause; jitter/blending config (mostly advisory) | `src/opsec/index.ts:55-156` [Confirmed] |
| **Evidence / research ledgers** | `src/server.ts` (in-memory Maps) + `src/evidence/gate.ts` | Hypotheses → work orders → evidence → findings → retests; honesty gate | `src/server.ts:566-836` (types), `src/evidence/gate.ts` (`gateLiveFinding`) [Confirmed] |
| **LLM abstraction** | `src/llm/index.ts` | Single provider dispatch switch; provider fallback ladder | `src/llm/index.ts:1529` [Confirmed] |
| **Config** | `src/config/index.ts` | `Conf`-backed settings store, env resolution, key resolution | `src/config/index.ts:693-1076` [Confirmed] |
| **Decomposition orchestrator** | `src/orchestration/` | **Separate** white-box source-analysis subsystem (blind master/worker LLM decomposition). NOT part of the Admiral/General mission path | `src/orchestration/types.ts` [Confirmed] |
| **Stubs** | `src/stubs/index.ts` (~40 KB) | 14 honest-placeholder "advanced module" classes returning `success:false`; wired onto `TempestCommand` but **no HTTP route calls them** | `src/stubs/index.ts:54-59, 448-452`; `src/index.ts:439-465` [Confirmed] |

### 2.2 Two subsystems people conflate

- **Decomposition orchestrator** (`src/orchestration/`) is a *code-analysis* engine (blind master-builder / worker LLM
  decomposition of source), reachable via the `decompose` scripts and cockpit button. It is **not** the mission
  planner. [Confirmed]
- **Stubs** (`src/stubs/index.ts`) are deliberately non-functional placeholders (`ExploitEngine`, `ScannerOrchestrator`,
  `SwarmController`, …) that return honest failure and are policed by `src/__tests__/stub-honesty.test.ts`. The one live
  export from that file is `CVE_DATABASE`, consumed by the `cve_lookup` built-in (`src/arsenal/index.ts:40-41,3106`). [Confirmed]

---

## 3. The command hierarchy (who plans, who executes)

**[Confirmed]** — Admiral and Op General are both live, distinct, and *intentionally layered* (planner vs.
executor/orchestrator); neither supersedes the other. Admiral imports the `Directive` type from General
(`src/admiral/index.ts:22`), proving an intake→planner relationship, not a fork.

```
   Human intent (chat / form)
        │
        ▼
   ADMIRAL  ── converse/suggest ──►  MissionBrief  ── briefToDirective() ──►  Directive
   (src/admiral)                                    (opsec: live→'covert',
                                                     dry_run→'silent')
        │
        ▼
   OP GENERAL  ── planOperation() ──►  OpPlan (huntLanes, workOrders, roe, missionGate)
   (src/general)  ── reviewPlan()  ──►  status: ready | degraded | hold
        │
        ▼
   TempestCommand  ── tick loop ──►  OperatorAgent (ReAct AgentLoop)
   (src/index.ts)                     │
                                      ▼
                                 Arsenal.execute(tool, ctx)
                                      │  scope gate (hard)
                                      │  approval gate (risk-tiered)
                                      ▼
                                 tool.handler → runSubprocess / fetch
```

> **Naming note [Confirmed]:** The UI labels the General page "**Op Admiral**" (`docs/index.html` nav "⭐ Op Admiral",
> and `/api/general/plan` is the button behind it). "Op Admiral" (UI) and "Admiral" (module) are **different things**:
> the UI's "Op Admiral" page drives `OpGeneral`, while the module `src/admiral` is the conversational intake layer.
> `WHITEPAPER.md:552` mislabels `/api/general/plan` as "Op Admiral" — a stale doc inconsistency vs.
> `API_REFERENCE.md:96`, which correctly attributes it to General. This naming collision is the single largest source
> of operator confusion (see OPERATOR_GUIDE §"Mental model").

---

## 4. The three gates before live execution

T3MP3ST enforces **three sequential, independent gates**. All three must pass for a live external action to run. [Confirmed]

| # | Gate | Where | What it checks | Failure mode |
|---|---|---|---|---|
| 1 | **Admiral authorization flag** | `/api/admiral/launch` requires `confirmed:true` | Operator explicitly authorized the hunt | Plan-only preview, no execution |
| 2 | **Plan-quality gate** (`OpGeneral.reviewPlan`) | `src/general/index.ts:1097-1220` | Plan structure: scope bound, work orders per lane, evidence contract, receipts named, `destructiveAllowed` off | `status:'hold'` → **HTTP 409** at `/api/general/execute` (`:7219-7224`) and `/api/admiral/launch` (`:7638-7684`) |
| 3 | **Server approval receipt** (`guardAction`) | `src/server.ts:1319-1332` | A fresh, matching `ApprovalRequest` exists for `action:target` | **HTTP 403** via `blockForApproval`, creates a pending receipt |

Below those, at the tool layer, sit the **two Arsenal gates** (both inside `Arsenal.execute`, `src/arsenal/index.ts:387-415`):

1. **Scope gate** (`scopeViolation`, `:251-287`) — hard host allowlist, fail-closed, cannot be overridden by any
   approval. Returns `SCOPE DENIED` as a normal tool failure.
2. **Approval-controller gate** (`ApprovalController.gate`, `src/arsenal/approval.ts`) — only fires for gated risk tiers
   (`intrusive`/`credential`/`dangerous`), fail-safe deny.

> There are therefore **two distinct "approval" systems** and **two distinct "mission gate" systems**. See §5–6.

---

## 5. Two approval systems (this is the #1 confusion)

| | **Server-tier approval** | **Tool-tier approval** |
|---|---|---|
| Type | `ApprovalRequest` a.k.a. "**receipt**" | `ApprovalController` in-process gate |
| File | `src/server.ts:1200-1333` | `src/arsenal/approval.ts` |
| Granularity | per `action` + `target` (target = host/URL string) | per tool call, by risk tier |
| Gated on | `mission_execution`, `autonomous_execution`, `command_execution`, `network_request`, `model_call` | `GATED_TIERS = {intrusive, credential, dangerous}` |
| Lifecycle | pending → approved (TTL, default 30 min) → expired | approve-once-then-free within a run |
| Created by | `guardAction()` when missing → 403 | evaluated at every `execute()` |
| Persisted? | **Yes** (survives graceful restart, `state.json`) | No (process-lifetime only) |

The server-tier `target` is a **hostname/URL**, *not* a mission id (`src/server.ts:1238-1249` `approvalMatches`). A single
approved receipt is reusable for the same action+target within its TTL. [Confirmed]

---

## 6. Two "mission gate" systems

| | **`buildMissionGate()`** (System A) | **`OpGeneral.reviewPlan()`** (System B) |
|---|---|---|
| File | `src/server.ts:1575-1733` | `src/general/index.ts:1097-1220` |
| Scope | cross-cutting server ledgers (evidence, findings, retests, receipts) | a single `OpPlan`'s structural quality |
| Output | `score = round(okCount/10*100)`, status `blocked`/`ready`/`hold` (10 checks) | `score` from 100 with blockers/warnings, status `hold`(<70)/`degraded`(<90)/`ready` |
| Enforced? | Advisory — surfaced via `POST /api/mission-gate` | **Enforced** — `hold` → HTTP 409 blocks execution |
| Surfaces UI strings | — | "Hunt lane(s) without work orders" (`:1184-1189`), "Receipts are named before active execution", `nextApproval = action:target` (`src/general/index.ts:666-675`) |

**[Confirmed]** They are not duplicates — different inputs, different scopes. But the shared "mission gate" vocabulary is
a real operator-confusion risk. The gate chip in the War Room (READY/DEGRADED/HOLD) is driven by System B's plan review;
the `/api/mission-gate` endpoint is System A.

---

## 7. Persistence & state

**[Confirmed]** All research state lives in **11 in-memory `Map`s** in `src/server.ts` (approvals, evidence, findings,
retests, hypotheses, work orders, watch cycles, memory capsule, memory proposals, mission drafts, improvement
proposals; declared ~`src/server.ts:566-836`).

- `stateRoot()` (`:926-929`) defaults to the literal string `'memory'` → **no persistence unless `T3MP3ST_STATE_DIR`
  is set**. All ledgers are lost on restart by default.
- When set: `state.json` + `events.jsonl` under that dir; writes debounced 1000 ms (`schedulePersist`, `:1131-1143`),
  secrets redacted before write; recovered by `loadPersistedState()` at boot (`:1164-1187`).
- **Quirk [Confirmed]:** `stateRoot()`'s nested ternary (`:927-928`) has a dead truthy branch — it effectively returns
  `T3MP3ST_STATE_DIR` or `'memory'`. And `currentMode()` (`:923`) forces `'t3mp3st'` mode for *any* truthy
  `T3MP3ST_STATE_DIR` due to operator precedence, not only `T3MP3ST_MODE=t3mp3st`.
- **Docker gap [Confirmed]:** `docker-compose.yml` mounts `./reports` and `./evidence` but does **not** set
  `T3MP3ST_STATE_DIR` → containerized mission/approval state is still in-memory-only.

---

## 8. Execution engine internals

**[Confirmed]** `TempestCommand` (`src/index.ts`):
- Registers built-in tools unconditionally (`:389-390`); arms the full specialist arsenal only under
  `T3MP3ST_FULL_ARSENAL=1` (`:423-436`); opt-in hardens built-ins under `T3MP3ST_GATE_BUILTINS=1` (`:388-389`).
- Wires the tool-tier `ApprovalController` at `:415` (`setApprovalController`) and injects a `scopeOk` predicate into
  adapter tools at `:427`.
- Recomputes the Arsenal scope from `TargetEnvironment` on every `target:added` event via `syncArsenalScope()`
  (`:545-550`), always allowing loopback + private ranges in addition to explicit targets.
- The tick loop checks `OpsecController.isAbortRecommended()` each tick and auto-pauses on detection-threshold breach
  (`:932-935`).

**OperatorAgent** runs a ReAct-style `AgentLoop`; each tool action flows through `Arsenal.execute` and thus both hard
gates. Subprocess execution goes through `runSubprocess` / `execFileAsync` (`src/arsenal/index.ts:3265+`), with external
tools (`nmap`, `nuclei`, `ffuf`, `curl`) gated by availability probes (`isToolAvailable`, `:3253-3260`) and flag
sanitizers (`sanitizeExternalFlags`, `:3301-3311`).

---

## 9. Data model (research lifecycle)

**[Confirmed]** The evidence-driven loop (types at `src/server.ts:566-836`):

```
Hypothesis (queued/…)  ── decompose ──►  Work Order(s)  ── complete (+evidence) ──►  shifts hypothesis status
     │                                    kind: prove | disprove | recon | …          for / against
     │                                    status: queued|ready|needs_receipt|
     │                                            running|completed|blocked
     ▼
   promote  ──►  Finding (with verifyGate)  ──►  Retest (queued/…)
```

- Work orders have **two origins [Confirmed]**: (a) hypothesis decomposition via
  `/api/hypotheses/:id/decompose`, and (b) the General's plan (`OpPlanWorkOrder[]`, `src/general/index.ts:94`; two per
  hunt lane — one `prove`, one `disprove`, `:927-961`). The second origin is undocumented in prose.
- Findings must be **tool-proven**: `gateLiveFinding()` (`src/evidence/gate.ts`) enforces that prose is not evidence,
  matching `docs/VERIFIED_PROVENANCE.md` almost verbatim. [Confirmed]

---

## 10. Hunt lanes, OPSEC, scope — enforcement reality

- **Hunt lanes** (`OpPlan.huntLanes`, `src/general/index.ts:82,101-110`) are a *planning* construct, **not** a runtime
  execution mechanism. Each lane = `{family, target, priority, pressureQuestion, strangeRouteHypothesis,
  specialistArchetypes, resourcePackIds, containment}`. The server-side `laneToolGrants()`/`allowed_tools`
  (`src/server.ts:1349-1443`) is explicitly advisory route-preview metadata — "no runtime enforcement reads it"
  (`:1367-1369`). [Confirmed]
- **OPSEC** (`src/opsec/index.ts`): the *only* code-enforced effect of the OPSEC level is
  `isAbortRecommended()` → auto-pause when `detectionEvents.length >= maxDetectionEvents` (`src/index.ts:932-935`).
  `getJitteredDelay()`, `trafficBlending`, `avoidDetection`, `loggingSanitization`, `cleanupOnComplete` have **no live
  callers** (confirmed by grep) — advisory only. Moreover `recordDetection()` has **no production caller**, so in the
  current wiring the abort mechanism has no live input. [Confirmed / UNRESOLVED whether a caller is intended]
- **Scope** (`scopeViolation`, `src/arsenal/index.ts:251-287`) is the one genuinely hard, code-level, fail-closed gate.
  `null` scope = enforcement off (library/test mode) — a real footgun if no target is ever added. Scope is derived at
  runtime from `TargetEnvironment`, never from a config file (`tenants.json` is unrelated docs-site config). [Confirmed]

---

## 11. Architectural risks (for the GAPS deliverable, summarized here)

1. **`src/server.ts` is a 8,078-line god-file** with ~130 routes and all state as module-level Maps — a maintainability
   and testability concern (not dead code). [Confirmed]
2. **Two approval systems + two mission-gate systems** share vocabulary → operator confusion. [Confirmed]
3. **No persistence by default**; Docker doesn't set the state dir. [Confirmed]
4. **`/api/approvals/:id/approve` lacks a status precondition** — can re-approve a rejected/expired receipt
   (`src/server.ts:5027-5042`); the sibling `authorize-target` correctly guards this (`:5087-5090`). [Confirmed]
5. **`operationAllowsLocalAction` trusts client-supplied `scope.authorized`** for local targets. [Confirmed]
6. **`model_call` GuardAction has no enforcement call site.** [Confirmed]
7. **OPSEC is largely scaffolding**; the one hard mechanism has no live detection input. [Confirmed]
8. **UI/backend drift:** Arsenal page renders a hardcoded 85-item client array, not `/api/arsenal/catalog`; operator
   "spawn" is client-only state; several backend routes (`authorize-target`, `/api/operators/*`, `/api/bounty/*`) have
   no UI. [Confirmed]

See `T3MP3ST_IMPLEMENTATION_GAPS.md` for classification and `T3MP3ST_FEATURE_BASELINE.md` for extension points.
