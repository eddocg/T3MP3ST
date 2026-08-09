# T3MP3ST — Troubleshooting

> Symptom → cause → fix, grounded in the code (`file:line`, commit `afc9dad`). Ordered by how often an operator will hit
> each one. "Cause" statements are Confirmed against source unless marked otherwise.

---

## A. Approval & gate problems (most common)

### A1. "Execution is blocked" / EXECUTE button says **HELD** / HTTP **409**
- **Cause:** Plan-quality gate (`OpGeneral.reviewPlan`) returned `status:'hold'` (`src/general/index.ts:1097-1220`).
  `/api/general/execute` and `/api/admiral/launch` return 409 (`server.ts:7219-7224, 7638-7684`).
- **Why (check blockers on the gate chip):**
  - Empty/unbound scope — `!roe.scope.length` (`:1115`).
  - `destructiveAllowed === true` — a hard blocker, −30 (`:1122`).
  - Low score from warnings (e.g. hunt lanes without work orders, −12, `:1184`).
- **Fix:** Bind the target into scope, ensure every hunt lane has its prove/disprove work orders (re-run **PLAN
  OPERATION**), and don't request destructive actions. Re-plan; the chip should move to READY/DEGRADED.

### A2. Launch returns HTTP **403** with a "pending receipt"
- **Cause:** `guardAction('mission_execution', target)` found no fresh approval (`server.ts:6311/7225/7373`) →
  `blockForApproval` created a pending `ApprovalRequest` and returned 403 (`:1319-1332`).
- **Fix:** Approve it. Go to **🧾 Scope Receipts** → **Approve** (or the inline modal if it appeared). The Admiral
  wizard auto-retries after approval. For loopback/lab targets or AUTONOMOUS mode the UI auto-approves silently.

### A3. I approved but it's still blocked
- **Possible causes:**
  1. You cleared the **403** (approval) but the **409** (plan hold) is separate — see A1. They are independent gates.
  2. The receipt **expired** — TTL default 30 min (`server.ts:5035`); `GET /api/approvals` flips expired ones on read
     (`:4986`). Re-approve.
  3. Target mismatch — the receipt's `target` is a **host/URL**, and `approvalMatches` compares the normalized target
     (`:1238-1249`). Approving `example.com` won't authorize `api.example.com`.
- **Fix:** Confirm both gates are green; re-approve if expired; approve the exact host.

### A4. Tool returns `SCOPE DENIED`
- **Cause:** `scopeViolation` blocked the target host — it isn't in the authorized scope
  (`src/arsenal/index.ts:251-287, 387-395`). This gate **cannot be approved around**.
- **Fix:** Add the target to the mission (scope is derived from `TargetEnvironment`, `src/index.ts:545-550`). Loopback
  and RFC-1918/private ranges are always allowed.

### A5. Gated tool (metasploit/hydra/sqlmap) returns `APPROVAL REQUIRED` / denied in headless mode
- **Cause:** Tool-tier `ApprovalController` fail-safe deny — gated risk tier with no approver and not pre-authorized
  (`src/arsenal/approval.ts:188-195`).
- **Fix:** Provide an interactive approver, or set `T3MP3ST_APPROVED_TOOLS=<tool names>` (use the minted tool names).
  ⚠️ This silently authorizes those tools — expert-only.

### A6. A rejected receipt somehow became approved
- **Cause (verified defect):** `POST /api/approvals/:id/approve` has **no status precondition** — it flips any receipt
  to `approved` regardless of prior state (`server.ts:5027-5042`). Use `authorize-target` (which enforces pending-only,
  `:5087-5090`) if you need the guard. Tracked in `T3MP3ST_IMPLEMENTATION_GAPS.md`.

---

## B. State & persistence

### B1. All my missions/approvals/evidence vanished after restart
- **Cause:** No persistence by default. `stateRoot()` returns the literal `'memory'` unless `T3MP3ST_STATE_DIR` is set
  (`server.ts:926-929`); all 11 ledgers are in-memory Maps.
- **Fix:** Start with `T3MP3ST_STATE_DIR=$HOME/.t3mp3st/state`. State is then written to `state.json` (debounced 1 s)
  and reloaded at boot (`loadPersistedState`, `:1164-1187`).

### B2. Running in Docker and state still doesn't persist
- **Cause:** `docker-compose.yml` mounts `./reports` and `./evidence` but **does not set `T3MP3ST_STATE_DIR`**.
- **Fix:** Add `T3MP3ST_STATE_DIR` to the compose environment and mount that path.

### B3. Setting `T3MP3ST_STATE_DIR` unexpectedly changed the "mode"
- **Cause (quirk):** `currentMode()` (`server.ts:923`) uses `T3MP3ST_STATE_DIR || T3MP3ST_MODE === 't3mp3st'`, which by
  operator precedence forces `'t3mp3st'` mode for *any* truthy `T3MP3ST_STATE_DIR`. Cosmetic, not harmful.

---

## C. Startup, connectivity, LLM

### C1. Server won't start / crashes on boot
- **Check:** Node ≥ 22.19 (`package.json:157`). Startup sequence: state load → proxy → LLM → grammars → listen
  (`server.ts:7976-8019`). `unhandledRejection`/`uncaughtException` are logged but don't exit (`:7969-7972`).

### C2. "No LLM configured" / provider errors
- **Cause:** No API key resolved and no local agent connected. Key resolution: env > stored `conf`
  (`config/index.ts:816-859`).
- **Fix:** `npm run setup`, or export a provider key, or connect a local coding agent (`/api/agents/local/connect`), or
  point at a local model (`TEMPEST_LOCAL_BASE_URL`). `T3MP3ST_FORCE_UNCONFIGURED=1` disables key lookup (smoke-test only).

### C3. UI loads but can't reach the backend
- **Cause:** The SPA's `T3MP3ST_API.baseUrl` defaults to `http://<host>:3333`; empty baseUrl = "standalone mode"
  (client-only, e.g. GitHub Pages hosting) with no backend.
- **Fix:** Serve the UI from the running server (`/ui`) so it talks to `:3333`.

### C4. Can't reach the server from another machine
- **Cause:** Binds to `127.0.0.1` by default (`server.ts:152`).
- **Fix:** `T3MP3ST_HOST=0.0.0.0` (or `DOCKER=true`). ⚠️ This exposes a **command-executing API** and disables the
  Host-header allowlist guard — only do this behind trusted network controls.

---

## D. Arsenal / tools

### D1. A tool listed in the Arsenal page doesn't actually run
- **Cause:** The Arsenal page renders a **hardcoded client array** (`docs/index.html:7102`), not the live catalog. The
  tool may not be registered, or the binary isn't installed, or the specialist arsenal isn't armed.
- **Fix:** Set `T3MP3ST_FULL_ARSENAL=1` for specialist adapters; install the binary (external tools degrade gracefully
  if absent via `isToolAvailable`, `arsenal/index.ts:3253-3260`).

### D2. A specialist tool runs but produces no structured findings
- **Cause:** Most adapters have `parserStatus:'planned'` — they return raw stdout only. Structured parsers exist only
  for nuclei, httpx, dalfox, ffuf, katana, semgrep, gitleaks, trivy, grype, garak (`arsenal/parsers.ts`).
- **Fix (expectation):** Treat other tools' output as raw text; findings won't auto-populate.

### D3. A specialist tool is invoked with wrong arguments
- **Cause:** Many catalog entries lack a bespoke `ARG_TEMPLATE` and fall back to a bare positional arg (e.g. cloud CLIs
  like `aws`/`az`/`gcloud`, `ghidra` headless, `gdb`). This is almost certainly wrong for subcommand-based tools.
- **Status:** Implemented-but-incomplete; see the arsenal table in `T3MP3ST_IMPLEMENTATION_GAPS.md`.

### D4. "Deploy All" operators does nothing on the backend
- **Cause:** The Operatives page's spawn/deploy is **client-only state** (`docs/index.html:8062-8107`) — it never calls
  `/api/operators/spawn`. Real operators spawn server-side inside `/api/mission/start`.
- **Fix (expectation):** Start a mission to actually spawn operators.

---

## E. OPSEC & mission control

### E1. OPSEC level ("silent/covert/loud") doesn't seem to change scan behavior
- **Cause:** OPSEC is largely advisory. The **only** code-enforced effect is auto-pause when
  `detectionEvents.length >= maxDetectionEvents` (`src/index.ts:932-935`). Jitter/blending/sanitization configs have no
  live callers.
- **Additional caveat:** `recordDetection()` has **no production caller**, so in the current wiring the auto-pause has
  no live input — it will essentially never fire from real telemetry. [Confirmed / UNRESOLVED whether a caller is
  intended]

### E2. Mission auto-paused unexpectedly
- **Cause (if it happens):** `OpsecController.isAbortRecommended()` returned true on the tick loop and called
  `pause()` (`src/index.ts:932-935`).
- **Fix:** Resume via `/api/mission/resume`; consider `loud` OPSEC (higher `maxDetectionEvents`) if appropriate and
  authorized.

---

## F. Reporting / bounty

### F1. I can't find a "submit to bug bounty" button
- **Cause:** The `/api/bounty/*` family (platforms/format/submit/programs/credentials) has **no War Room UI**. [Confirmed]
- **Fix:** Call the API directly (or via CLI/scripts). Confirm with the maintainers whether UI wiring is planned.

---

## G. Diagnostics quick-reference

| Want to check… | How |
|---|---|
| Server health / storage driver | `GET /api/health` |
| Whether persistence is on | Health `storage.driver`/`path`; or confirm `T3MP3ST_STATE_DIR` is set |
| Pending approvals | `GET /api/approvals?status=pending` or Scope Receipts page |
| Plan gate status | Gate chip in War Room / Op Admiral page; `POST /api/general/plan` response |
| Ledger gate | `POST /api/mission-gate` |
| Which tools are registered | `GET /api/arsenal/catalog` (backend truth, not the UI list) |
| LLM connectivity | `GET /api/llm/status` |
