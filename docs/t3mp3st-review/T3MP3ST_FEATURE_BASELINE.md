# T3MP3ST — Feature Baseline & Extension Points

> This describes the **seams the system already exposes** for building on top of it — not a roadmap and not an
> implementation plan. It answers: "if I wanted to add X, where does the code already give me a hook?" All hooks are
> Confirmed against source (`file:line`, commit `afc9dad`).

---

## 1. How to extend the tool arsenal

### 1.1 Add a built-in probe (pure Node, no external binary)
- **Seam:** `BUILTIN_TOOLS` registry in `src/arsenal/index.ts` (~`:590+`). Register a tool with a `handler`, optional
  `riskTier`, and arg validation. It automatically inherits the scope gate; add a gated `riskTier` to also pull it
  through the approval gate.
- **Note:** built-ins are ungated by default; `T3MP3ST_GATE_BUILTINS=1` promotes the intrusive ones via
  `stampSpicyBuiltin()` (`:575-588`).

### 1.2 Add a specialist adapter (wraps an external binary)
- **Seam:** add a `TOOL_ADAPTERS` entry in `src/arsenal/catalog.ts` (binary, `riskTier`, `execution` mode) and — for
  correct invocation — an `ARG_TEMPLATE` in `src/arsenal/adapter-tools.ts` (otherwise it falls back to a bare positional
  arg, which is wrong for subcommand tools). Add a structured parser in `src/arsenal/parsers.ts` if you want
  `ToolResult.findings` populated instead of raw stdout.
- **Arming:** specialist tools only register under `T3MP3ST_FULL_ARSENAL=1` (`src/index.ts:423-436`).
- **Bespoke drivers:** for tools that need a session/console (e.g. metasploit, hydra), follow `src/arsenal/post-ex.ts`,
  which bypasses the generic factory.

### 1.3 Execution modes available
`ToolExecutionMode` (`catalog.ts:27`): `safe_command` (local, no approval) · `receipt_required` (approval if risk-gated)
· `catalog_only` (never minted) · `import_only` (evidence import only). Pick per tool.

---

## 2. How to extend planning & missions

- **Mission families:** `MissionFamily` (`src/resources/index.ts:1-10`) —
  `web_api | ai_red_team | cloud_infra | smart_contract | code_supply_chain | crypto_secrets | reverse_binary |
  agent_warfare | social_osint | reporting_remediation`. Add a family here, then wire `familyOperators()` /
  `adaptersForFamily()` (`src/server.ts:1349+`) and `toolIdsForFamily()` (`src/general/index.ts`).
- **Hunt lanes:** `OpPlan.huntLanes` (`general/index.ts:82,101-110`); lane→work-order synthesis at `:927-961`
  (one `prove` + one `disprove` per lane). Extend `normalizeHuntLanes` to change lane shape.
- **Plan-quality gate:** add checks/blockers/warnings in `OpGeneral.reviewPlan` (`:1097-1220`); the criteria strings the
  UI shows live in `enrichPlan` (`:666-672`).
- **Admiral intake:** `MissionBrief` families and `briefToDirective()` (`src/admiral/index.ts:212-221`); the system
  prompt and anti-fitting guards (`FORBIDDEN_TELLS`, `isFittingTell`) shape what the Admiral will and won't do.

---

## 3. How to extend the approval / gate model

- **Add a guarded action:** extend the `GuardAction` union (`src/server.ts:571`) **and** add an enforcement call site
  via `guardAction(action, target)` (`:1319-1332`). ⚠️ Adding the union member alone is inert — that's exactly why
  `model_call` currently does nothing (see GAPS H2).
- **Receipt lifecycle:** `ApprovalRequest` + `approvalMatches`/`approvalIsFresh` (`:1222-1249`). TTL and matching logic
  are here; the target is a host/URL.
- **Tool-tier gating:** `GATED_TIERS`/`SPICY_TIERS` and `ApprovalController.gate()` in `src/arsenal/approval.ts`;
  pre-authorization list via `T3MP3ST_APPROVED_TOOLS` (`src/index.ts:399`).
- **Scope policy:** `ArsenalScope` + `scopeViolation` (`src/arsenal/index.ts:210-287`); scope is derived from
  `TargetEnvironment` via `syncArsenalScope` (`src/index.ts:545-550`). This is the enforcement point to harden or extend
  (e.g. tightening the always-on loopback/private allowance).

---

## 4. How to extend the research ledger

- **Records:** hypotheses, work orders, evidence, findings, retests — all as in-memory Maps with typed records
  (`src/server.ts:566-836`) and matching REST routes (see `T3MP3ST_API_REFERENCE.md` §8).
- **Status machines:** `WorkOrderStatus` (`queued|ready|needs_receipt|running|completed|blocked`), `HypothesisStatus`,
  `FindingStatus`, `RetestStatus`. Extend these unions + the transition logic in the corresponding route handlers.
- **Evidence honesty gate:** `gateLiveFinding()` (`src/evidence/gate.ts`) is the hook enforcing "prose is not evidence."
  Extend here to add provenance rules.

---

## 5. How to extend LLM / provider support

- **Single dispatch point:** `src/llm/index.ts:1529` (provider switch). Add a provider case here.
- **Config/keys:** `getLLMConfig` / `getApiKey` (`src/config/index.ts:816-1039`), model catalog `AVAILABLE_MODELS`
  (`:265-683`), fallback ladder gated by `TEMPEST_MODEL_FALLBACK` (`:1051-1076`).
- **Local agents:** `src/agent/local-agents.ts` — add a local coding-agent integration alongside Claude Code / Codex /
  Hermes / OpenCode / Oh My Pi; routes at `/api/agents/local/*`.

---

## 6. How to extend the UI (War Room)

- **Reality:** `docs/index.html` is a **single ~1.6 MB hand-authored vanilla-JS file** (no framework, no build step). It
  is *not* produced by `scripts/pagenary-docsite.mjs` (that builds the separate `docs/*.md` docs site).
- **Seams:** nav items map 1:1 to `data-page` / `#page-*` divs; the API client is `T3MP3ST_API` (`:6110`) with
  `.get`/`.post` helpers. New pages = new nav entry + new `#page-*` div + handlers.
- **Known drift to fix if you build here:** the Arsenal page uses a hardcoded tool array (wire it to
  `/api/arsenal/catalog`); operator "spawn" is client-only (wire it to `/api/operators/spawn` if backend spawn is
  desired); several backend routes have no UI (`authorize-target`, `/api/bounty/*`).

---

## 7. Adjacent subsystems you can build on (already present)

- **Decomposition orchestrator** (`src/orchestration/`) — blind master/worker white-box source decomposition; reachable
  via `/api/whitebox/analyze` and the `decompose` scripts. A separate engine from mission planning; extend its
  `OrchestrationFinding` taxonomy (`orchestration/types.ts:123`) for new finding categories.
- **Pressure paths** (`/api/pressure-paths/*`: canary/chains/duel/mutate) — adversarial hypothesis-stress generation.
- **Watch loop** (`/api/watch-loop/*`), **self-heal** (`/api/self-heal/run`), **learning** (`/api/learning/*`),
  **memory** (`/api/memory/*`), **improvement proposals** (`/api/improvement/proposals`) — all have live routes and
  ledgers to extend.
- **Bug-bounty pipeline** (`/api/bounty/*`) — fully backend-implemented, just needs UI wiring.
- **Stubs** (`src/stubs/index.ts`) — 14 honest placeholders (ExploitEngine, ScannerOrchestrator, SwarmController, …)
  are pre-wired onto `TempestCommand` and awaiting real implementations + route exposure. These are the *intended*
  extension slots for "advanced modules."

---

## 8. Things to stabilize *before* building (pointers to GAPS)

Building features on the current base is reasonable, but these seams are fragile and worth hardening first (details and
severities in `T3MP3ST_IMPLEMENTATION_GAPS.md`):

1. Turn on persistence by default or make it loud when off (C1).
2. Close the `scope.authorized` client-trust bypass (C2) and the re-approve-non-pending path (H1).
3. Decide `model_call`'s fate — enforce it or remove it (H2).
4. Make OPSEC either real or clearly labeled advisory (H3); ensure scope can't be `null` during a live mission (H4).
5. Unify or clearly separate the two approval systems and two gate systems (M1) and the OPSEC vocab mismatch (M2).
6. Fix the specialist-adapter arg templates before advertising those tools (M5).

None of these are blockers for *reading* or *experimenting*; they are the load-bearing seams a feature would sit on.
