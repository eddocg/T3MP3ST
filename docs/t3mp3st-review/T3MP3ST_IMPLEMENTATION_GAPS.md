# T3MP3ST — Implementation Gaps

> Every gap below is **source-verified** (`file:line`, commit `afc9dad`) unless marked **[UNRESOLVED]**. Classified by
> severity for someone deciding what to fix before building on this codebase. This audit was **read-only** — nothing
> here has been changed.
>
> Severity key: **Critical** (security/correctness, exploitable or data-losing) · **High** (real defect or a gate that
> doesn't gate) · **Medium** (behavioral inconsistency / footgun) · **Low** (cosmetic/minor) ·
> **Documentation-only** (code is fine, docs are wrong/missing) · **UX-only** (UI/backend mismatch, no security impact).

---

## Critical

### C1 — No persistence by default; silent total state loss on restart
- **What:** `stateRoot()` returns the literal `'memory'` unless `T3MP3ST_STATE_DIR` is set; all 11 ledgers (missions,
  approvals, evidence, findings, hypotheses, work orders, …) are in-memory Maps.
- **Impact:** A restart wipes every mission, approval, and piece of evidence. In-flight engagements lose all provenance.
  Docker Compose doesn't set the state dir either.
- **Evidence:** `src/server.ts:926-929`; ledgers declared `src/server.ts:566-836`; `docker-compose.yml` (no
  `T3MP3ST_STATE_DIR`).
- **Classification:** Critical (data-loss). Not a code bug per se, but a default that will bite operators and is
  undocumented in `.env.example`.

### C2 — `operationAllowsLocalAction` trusts client-supplied `scope.authorized`
- **What:** For local targets, approval can be bypassed based on a client-provided `scope.authorized` flag.
- **Impact:** A malicious or mistaken client can assert authorization to skip the approval gate for local actions,
  weakening the human-in-the-loop guarantee for the local case.
- **Evidence:** `src/server.ts` `operationAllowsLocalAction` (client-trusted `scope.authorized`).
- **Classification:** Critical (trust boundary) for any deployment where the client isn't fully trusted; lower if the
  server is strictly single-operator loopback.

---

## High

### H1 — `POST /api/approvals/:id/approve` has no status precondition (re-approve rejected/expired)
- **What:** The per-id approve route flips **any** receipt to `approved` regardless of current status; a `rejected` or
  `expired` receipt can be resurrected. The sibling `authorize-target` route correctly enforces pending-only (409).
- **Impact:** Inconsistent enforcement; a previously-denied action can be re-approved through the weaker path.
- **Evidence:** `src/server.ts:5027-5042` (no precondition) vs. `:5087-5090` (409 on non-pending in `authorize-target`).
- **Classification:** High (authorization integrity).

### H2 — `model_call` GuardAction has no enforcement call site
- **What:** `model_call` is a valid `GuardAction` and `/api/approvals/request` accepts it, but nothing ever calls
  `guardAction('model_call', …)`.
- **Impact:** The action type is inert — any "model call approval" feature implied by its existence is not enforced.
- **Evidence:** `GuardAction` union `src/server.ts:571`; grep finds no `guardAction('model_call'`/`'model_call'`
  enforcement site.
- **Classification:** High (dead safety control — misleading if relied upon).

### H3 — OPSEC enforcement is effectively inert
- **What:** The only code-enforced OPSEC effect is auto-pause on `detectionEvents.length >= maxDetectionEvents`
  (`src/index.ts:932-935`). But `recordDetection()` has **no production caller**, so the counter never increments from
  real telemetry; and `getJitteredDelay()`, `trafficBlending`, `avoidDetection`, `loggingSanitization`,
  `cleanupOnComplete` have **no callers at all**.
- **Impact:** Selecting `silent`/`covert`/`loud` changes prompt guidance to the LLM but does **not** change runtime
  scanning behavior, pacing, or the abort mechanism in practice.
- **Evidence:** `src/opsec/index.ts:55-240`; grep across `src/` for the above names finds only definitions/tests.
- **Classification:** High (a advertised safety/stealth control that doesn't do what its name implies).
- **[UNRESOLVED]** whether a tool handler is *intended* to call `recordDetection()` — no such call exists today.

### H4 — Scope enforcement is off when no target has been added (`null` scope)
- **What:** `scopeViolation` returns `null` (allow) when scope is unset — "library/test mode." If a caller never adds a
  target via `TargetEnvironment`, there is **no scope enforcement at all**.
- **Impact:** A code path that executes tools before/without adding a target has an open egress boundary.
- **Evidence:** `src/arsenal/index.ts:252`; scope set only via `syncArsenalScope` on `target:added` (`src/index.ts:545-550`).
- **Classification:** High (fail-open under a specific but reachable condition).
- **[UNRESOLVED]** whether the server always adds ≥1 target before allowing tool calls in a live mission — not verified
  beyond the event trigger.

---

## Medium

### M1 — Two approval systems + two mission-gate systems share vocabulary
- **What:** Server-tier `ApprovalRequest`/`guardAction` vs. tool-tier `ApprovalController`; and `buildMissionGate`
  (ledger, advisory) vs. `OpGeneral.reviewPlan` (plan-quality, enforced). Same words, different mechanisms.
- **Impact:** Operators can't tell which gate blocked them or which "approval" they need. Documented at length in
  `T3MP3ST_APPROVAL_FLOW.md` precisely because it's confusing.
- **Evidence:** `src/server.ts:1200-1333, 1575-1733`; `src/arsenal/approval.ts`; `src/general/index.ts:1097-1220`.
- **Classification:** Medium (design clarity / operator error risk).

### M2 — `MissionDraft.opsecPreference` enum mismatches runtime `OpsecLevel`
- **What:** Mission drafts use `opsecPreference: 'overt'|'normal'|'covert'|'ghost'` (server.ts), while the engine uses
  `OpsecLevel: 'silent'|'covert'|'loud'` (`types/index.ts:357`). They are mapped for display, but `ghost` drives its own
  extra gating (`review_only` + `human_approval_for_external_actions`) independent of `OpsecLevel`.
- **Impact:** Two overlapping-but-different OPSEC vocabularies; `covert` is the only shared token, and it means different
  things in each. Confusing and error-prone.
- **Evidence:** `src/server.ts:1388,1396-1400`; `src/types/index.ts:357`.
- **Classification:** Medium (model inconsistency).

### M3 — `currentMode()` operator-precedence quirk
- **What:** `T3MP3ST_STATE_DIR || T3MP3ST_MODE === 't3mp3st'` forces `'t3mp3st'` mode for any truthy state dir, not only
  `T3MP3ST_MODE=t3mp3st`.
- **Evidence:** `src/server.ts:923`.
- **Classification:** Medium (surprising but harmless).

### M4 — Graceful shutdown flushes state but doesn't drain connections
- **What:** SIGTERM/SIGINT calls `flushPersist()` then `process.exit(0)`; never calls `server.close()`.
- **Impact:** In-flight HTTP requests can be cut off; not a full graceful drain.
- **Evidence:** `src/server.ts:8009-8017`.
- **Classification:** Medium (deployment robustness).

### M5 — Specialist arsenal: incomplete argument templates
- **What:** Many catalog tools lack a bespoke `ARG_TEMPLATE` and fall back to a bare positional arg — wrong for
  subcommand tools (cloud CLIs `aws`/`az`/`gcloud`, `ghidra` headless, `gdb`, `feroxbuster`, `openssl`, `john`/`hashcat`,
  `objection`/`drozer`, `foundry`/`echidna`, etc.).
- **Impact:** Those tools, when armed and installed, will likely be invoked incorrectly.
- **Evidence:** `src/arsenal/catalog.ts` + `adapter-tools.ts` DEFAULT_TEMPLATE fallback; see the arsenal inventory table
  below.
- **Classification:** Medium (Implemented-but-incomplete).

### M6 — Auto-approval for loopback/lab and AUTONOMOUS mode bypasses the human gate
- **What:** The UI silently auto-approves `mission_execution` receipts for loopback/lab targets and when AUTONOMOUS is
  checked, then retries.
- **Impact:** Intentional for local testing, but the human-in-the-loop gate is effectively bypassed for those cases;
  operators may not realize approval happened automatically.
- **Evidence:** `docs/index.html:19735-19745, 26794-26880`.
- **Classification:** Medium (intentional convenience with a safety trade-off; document prominently).

---

## Low

### L1 — `stateRoot()` dead-code ternary
- Nested ternary's truthy branch is unreachable; effectively returns `T3MP3ST_STATE_DIR || 'memory'`.
- **Evidence:** `src/server.ts:927-928`. **Classification:** Low.

### L2 — Dockerfile CMD runs the dev/tsx path
- `CMD ["npm","run","server"]` runs `tsx src/server.ts` inside the built image despite `tsc` having run — an
  inefficiency, not a correctness bug.
- **Evidence:** `Dockerfile:27,43`. **Classification:** Low.

### L3 — `src/server.ts` god-file (~8,078 lines, ~130 routes, all state module-global)
- Maintainability/testability concern; not dead code. **Classification:** Low (tech debt).

---

## Documentation-only

### D1 — `mission_execution` and the plan-quality 409 gate are undocumented in prose
- Both are real and enforced but appear only in code + the UI bundle, not README/API_REFERENCE/VISION/WHITEPAPER.
- **Evidence:** `GuardAction` `server.ts:571`; 409 at `:7219-7224`. **Classification:** Documentation-only.

### D2 — `WHITEPAPER.md:552` mislabels `/api/general/plan` as "Op Admiral"
- Contradicts `API_REFERENCE.md:96`, which correctly attributes it to General. **Classification:** Documentation-only.

### D3 — `.env.example` documents ~10 of ~45 real env vars
- Undocumented incl. security-relevant `T3MP3ST_APPROVED_TOOLS`, `T3MP3ST_HERMES_YOLO`, `T3MP3ST_FULL_ARSENAL`,
  `T3MP3ST_GATE_BUILTINS`, `T3MP3ST_STATE_DIR`, `T3MP3ST_HOST`. Dead entries: `LLM_MODEL`, `GROQ_API_KEY`,
  `TOGETHER_API_KEY`, `REPLICATE_API_TOKEN` (not read by the app).
- **Evidence:** `.env.example` vs. `src/config/index.ts`, `src/index.ts`, `src/server.ts`. **Classification:** Documentation-only.

### D4 — Work orders have a second, undocumented origin (General's plan)
- Docs describe only hypothesis-decomposition origin; `OpPlanWorkOrder[]` (`general/index.ts:94`, two per lane) is
  code-only. **Classification:** Documentation-only.

### D5 — Second env template (`createEnvTemplate`) is more complete than `.env.example`
- The setup wizard writes a richer `~/.t3mp3st/.env`; the root `.env.example` is stale by comparison.
- **Evidence:** `src/config/index.ts:1211-1271`. **Classification:** Documentation-only.

---

## UX-only (UI/backend drift)

### U1 — Arsenal page renders a hardcoded 85-item client array, not `/api/arsenal/catalog`
- The UI's tool list can drift from what's actually registered/installed.
- **Evidence:** `docs/index.html:7102`; backend route `src/server.ts:4914`. **Classification:** UX-only.

### U2 — Operator "spawn/deploy" is client-only state
- `/api/operators/spawn` and `/api/operators/:id/task` are never called by the UI; real spawn is inside
  `/api/mission/start`.
- **Evidence:** `docs/index.html:8062-8107`; backend routes `src/server.ts:6606, 6678`. **Classification:** UX-only.

### U3 — `/api/approvals/authorize-target` has no UI caller
- The UI always approves per-receipt-id. **Evidence:** `src/server.ts:5044` unreferenced in `docs/index.html`.
  **Classification:** UX-only.

### U4 — `/api/bounty/*` family has no UI
- platforms/format/submit/programs/credentials — backend-only. **[UNRESOLVED]** whether intentional.
  **Classification:** UX-only.

---

## Placeholders / not-implemented (honest stubs — not defects)

- **`src/stubs/index.ts`** — 14 "advanced module" classes (`ExploitEngine`, `ScannerOrchestrator`, `BrowserAutomation`,
  `SwarmController`, `WorkflowOrchestrator`, …) return honest `success:false`; wired onto `TempestCommand` but **no HTTP
  route calls them**. Policed by `stub-honesty.test.ts`. The one live export is `CVE_DATABASE`. `src/stubs/index.ts:54-59,
  448-452`; `src/index.ts:439-465`. **Not a defect** — deliberate honest scaffolding.
- **Arsenal catalog placeholders:** `pacu`, `frida` are `catalog_only` (never minted), `bloodhound` is `import_only`
  with **no import pipeline found** (Referenced-but-missing). `src/arsenal/catalog.ts`.
- **`RulesOfEngagement` (engine-level, `types/index.ts:317-325`)** — **[UNRESOLVED]** whether populated/consumed
  anywhere; no assignment site found in the files read (the *plan-level* `OpPlanRoE` in `general/index.ts` is the one
  actively enforced).

---

## Test-coverage gaps (safety-adjacent, unverified by any test)

| Area | Coverage | Evidence |
|---|---|---|
| `RulesOfEngagement` module | **None** | 0 hits in `src/__tests__` |
| `OpsecController` (detection/cooldown) | **None** | 0 hits |
| Server-side state persistence/recovery | **None/weak** | no direct test |
| Admiral module internals | **Weak** | only dispatch plumbing / static regex; no test imports `src/admiral/index.ts` |
| Mission helpers (`createReconTasks`, `TaskQueue`) | **Partial** | indirect only |

Strong coverage exists for: approvals (`approval.test.ts`), scope gate (`arsenal-scope-gate.test.ts`), tool-approval
gate (`arsenal-approval-gate.test.ts`), evidence honesty (`evidence-vault-integrity.test.ts`, `spine-live.test.ts`),
redaction, and OpGeneral plan/review/execute (`index.test.ts:289-362`).
