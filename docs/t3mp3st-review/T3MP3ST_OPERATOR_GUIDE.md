# T3MP3ST — Operator Guide

> **Who this is for.** Someone who did *not* write T3MP3ST and needs to actually run a mission end-to-end.
> This guide describes **what the code does today** (commit `afc9dad`, branch `develop`), not what the marketing docs
> aspire to. Where behavior is surprising or under-documented, it says so. Citations are `file:line`.
> **Safety:** every example targets loopback/lab hosts. Do not point T3MP3ST at anything you are not authorized to test.

---

## 1. Mental model (read this first)

T3MP3ST is an **LLM-driven security-testing orchestrator** with a naval command metaphor. The pieces:

| Term | What it *actually* is | Where |
|---|---|---|
| **Admiral** | Conversational **intake**. You chat; it drafts a mission brief. It **plans only, never executes**. | `src/admiral/index.ts` |
| **Op General** | The **planner/orchestrator**. Turns a directive into an `OpPlan` (hunt lanes, work orders, RoE), scores plan quality, and runs it. | `src/general/index.ts` |
| **"Op Admiral" (UI page)** | ⚠️ A **UI label for the Op General**, not the Admiral module. The "Op Admiral" page's buttons call `/api/general/*`. | `docs/index.html` nav; `/api/general/plan` |
| **War Room** | The **browser UI itself** (`docs/index.html`). Not a backend concept. | served at `/ui` |
| **Mission** | A live run of the engine against targets. Started via `/api/mission/start` or `/api/admiral/launch`. | `src/server.ts:6267` |
| **Work Order** | A unit of investigative work (prove / disprove / recon…). Comes from hypothesis decomposition *or* the General's plan. | `src/server.ts` ledger + `src/general/index.ts:94` |
| **Receipt** | An **approval** (`ApprovalRequest`) for a specific `action:target`. The UI calls these "Scope Receipts". | `src/server.ts:1200-1333` |
| **Gate** | A readiness check. There are **two** (plan-quality vs. ledger-based) — see §7. | `general/index.ts:1097`, `server.ts:1575` |
| **Evidence / Finding / Hypothesis / Retest** | The research ledger. Claims start as hypotheses; only tool-proven evidence promotes a finding. | `src/server.ts:566-836` |

> **The single most important thing to internalize:** "Op Admiral" in the UI ≠ the Admiral module. The UI's "Op Admiral"
> page is the **General**. The Admiral is the separate chat-intake wizard ("⚓ Guided" button). This naming collision is
> the biggest trip-hazard in the whole product. [Confirmed — `docs/index.html` nav vs. `src/general/index.ts`]

---

## 2. Prerequisites & install

**[Confirmed — `package.json`, `docs/GETTING_STARTED.md`, `Dockerfile`]**

- Node **≥ 22.19.0** (`package.json:157-159`).
- `npm install`.
- **First-time setup:** `npm run setup` (interactive wizard, `tsx src/setup.ts`) — persists provider/API-key choices
  into a `conf` store at `~/.t3mp3st/` (*not* into `.env`).
- **Keyless option:** you don't strictly need an API key — a connected local coding agent (Claude Code / Codex / Hermes
  / OpenCode / Oh My Pi) or a local inference server (`TEMPEST_LOCAL_BASE_URL`) can fill the LLM role
  (`src/agent/local-agents.ts`, `src/config/index.ts:1008-1035`).

---

## 3. Starting the server

**[Confirmed — `package.json` scripts, `src/server.ts:7976-8019`]**

| Mode | Command | Binds |
|---|---|---|
| Dev | `npm run server` (`tsx src/server.ts`) | `127.0.0.1:3333` |
| Prod | `npm run build` then `npm run server:prod` (`node dist/server.js`) | `127.0.0.1:3333` |
| Docker | `docker compose up -d` | `127.0.0.1:3333` (compose maps the port) |

Then open **`http://127.0.0.1:3333/ui`** (the root `/` redirects there, `src/server.ts:7950-7952`).

Startup order (`startServer`, `:7976`): banner → `loadPersistedState()` → proxy init → LLM init → grammar init →
register SIGTERM/SIGINT flush → `app.listen`. Health check: `GET /api/health` (`:4862`).

> ⚠️ **Persistence is OFF by default.** Unless you set `T3MP3ST_STATE_DIR`, every mission, approval, and piece of
> evidence is lost when the server restarts (`src/server.ts:926-929`). For any real engagement, set it:
> `T3MP3ST_STATE_DIR=$HOME/.t3mp3st/state npm run server`. Docker Compose does **not** set it for you.

> ⚠️ **Binding.** `T3MP3ST_HOST` defaults to loopback. Setting it to `0.0.0.0` (or `DOCKER=true`) exposes a
> **command-executing local API** and disables the Host-header allowlist guard (`src/server.ts:152`). Keep it on
> loopback unless you fully understand the exposure.

---

## 4. The normal workflow (10–20 steps)

This is the **canonical happy path** for a single authorized target, using the guided Admiral flow. All step behaviors
are Confirmed against source; citations inline.

1. **Start the server** and open `http://127.0.0.1:3333/ui`. The **War Room** page loads by default. [`docs/index.html` nav]
2. **Confirm LLM connectivity** — the header/Settings shows provider status; `GET /api/health` reports `llm`
   connectivity (`src/server.ts:4399-4426`).
3. **Open the guided Admiral wizard** — click **"⚓ Guided"** in the War Room. This is the *Admiral* (intake), a 4-step
   modal: type → target + authorization checkbox → depth/autonomy → review (`openAdmiralWizard()`, `docs/index.html:26743`).
4. **Scout the target (optional)** — the wizard's target step can call `/api/admiral/converse`
   (`admiralPickTarget()`) to have the Admiral reason about the target. [`docs/index.html:26717`]
5. **Preview the plan (dry-run)** — click **"🧭 Preview Admiral's plan (dry-run)"** → `POST /api/admiral/launch` with
   `confirmed:false`. This plans **without executing** (Gate #1 not satisfied). [`docs/index.html:26801`]
6. **Review the plan and the gate** — the plan renders hunt lanes, work orders, and a **gate chip**
   (READY / DEGRADED / HOLD) with score, blockers, warnings, and `Next: <action>:<target>`
   (`docs/index.html:18560-18716`). The chip reflects **`OpGeneral.reviewPlan`** (plan-quality gate).
7. **Resolve HOLD if present** — if the gate says HOLD, execution is blocked (HTTP 409). Common causes and fixes in §7
   and TROUBLESHOOTING. Typically: re-plan so every hunt lane has work orders, or remove a `destructiveAllowed` request.
8. **Launch for real** — click **"⚓ Launch Hunt"** → `POST /api/admiral/launch` with `confirmed:true` (Gate #1).
   [`docs/index.html:26854`]
9. **Handle the approval (receipt)** — the backend returns **HTTP 403** with a pending receipt for
   `mission_execution:<target>` (Gate #3, `guardAction`, `src/server.ts:6311/7225/7373`). What the UI does:
   - **Loopback/lab target or AUTONOMOUS mode:** the UI **auto-approves** silently and retries
     (`docs/index.html:19735-19745, 26794-26880`).
   - **External target, non-autonomous:** the UI redirects you to the **Scope Receipts** page and asks you to approve
     there. [`docs/index.html:26860` → `navigateTo('receipts')`]
10. **Approve the receipt** — on **Scope Receipts** (nav "🧾 Scope Receipts"), click **Approve** on the pending row →
    `POST /api/approvals/:id/approve` (`docs/index.html:7566`). The launch auto-retries once approved
    (`retryPendingAdmiralLaunch`, `:7576`). See §5 for the full approval walk-through.
11. **Mission runs** — the engine ticks, spawns operator agents server-side, and executes tools through the scope +
    approval gates. Watch progress in the War Room (findings, work-order board, evidence). [`src/index.ts` tick loop]
12. **Monitor findings & evidence** — findings appear under War Room "🔓 Findings" and the **Evidence Vault**; each
    promoted finding requires tool-proven evidence (`gateLiveFinding`, `src/evidence/gate.ts`).
13. **Work the work orders** — the **Work Order Board** (inside the Mission Spine panel) shows queued/running/completed
    orders. Completing an order attaches evidence and shifts hypothesis status
    (`/api/work-orders/:id/complete`, `docs/index.html:25507`).
14. **Promote hypotheses → findings** — as evidence accrues, promote via the hypotheses flow
    (`/api/hypotheses/:id/promote`).
15. **Queue retests** — findings should have retests queued (part of the evidence contract).
16. **Pause / resume / stop** as needed — War Room controls call `/api/mission/pause|resume|stop`
    (`docs/index.html:6612-6626`). OPSEC may auto-pause on detection-threshold (rare in practice, §"OPSEC").
17. **Check the deterministic gate** — the gate chip tooltip explicitly notes it is the *authoritative* readiness signal
    and that SITREP prose is "subjective LLM narration" (`docs/index.html` tooltip). Trust the chip over the narrative.
18. **Export / report** — evidence and reports persist to the mounted `./reports` and `./evidence` dirs (Docker) or
    your state dir. Note: the `/api/bounty/*` submission family exists in the backend but has **no UI** (§"Gaps").
19. **Stop the mission** — `POST /api/mission/stop`.
20. **Shut down** — SIGTERM/SIGINT flushes state to `state.json` (only if `T3MP3ST_STATE_DIR` is set), then exits
    (`src/server.ts:8009-8017`).

### Alternate paths
- **Op General page directly** ("⭐ Op Admiral" nav): **PLAN OPERATION** (`/api/general/plan`) → review gate →
  **EXECUTE** (`/api/general/execute`, disabled/"HELD" when gate=hold) → optionally **FULL AUTO**
  (`/api/general/auto`). [`docs/index.html:17651, 18150, 18261`]
- **Quick hunt:** the War Room hero **"🎯 HUNT"** button (`startZeroDayHunt`, `docs/index.html:19328`) drives the
  `mission/start` pipeline directly.

---

## 5. How to approve (the part everyone gets stuck on)

There are **three UI surfaces** that all converge on the same backend call
(`POST /api/approvals/:id/approve`). [Confirmed — `docs/index.html`]

1. **Scope Receipts page** (canonical). Nav "🧾 Scope Receipts", badge = pending count. Per-row **Approve/Reject**
   (`approveReceipt`/`rejectReceipt`, `:7566/7583`), plus **"Approve Pending"** to bulk-approve
   (`approveAllPendingReceipts`, `:7589`). Auto-refreshes every 4 s.
2. **Inline "Approve target to continue" modal** on the ENGAGE flow (`confirmApproveTarget`, `:9484-9511`). Loopback/lab
   or AUTONOMOUS auto-approves; otherwise a modal with **"✅ Approve & run \<target\>"**.
3. **Admiral wizard retry loop** — on a 403, auto-approves for lab/autonomous, else sends you to Scope Receipts and
   re-fires the launch after you approve.

**What a receipt actually is:** an `ApprovalRequest` for a specific **`action` + `target`**, where `target` is a
hostname/URL (e.g. `mission_execution:example.com`), **not** a mission id. It's reusable for that action+target until it
expires (TTL default **30 minutes**, `src/server.ts:5035`). Approvals are persisted if you have a state dir. [Confirmed
— `src/server.ts:1238-1249`, `:5027-5042`]

> **The deep plan→approval→execution walk-through lives in `T3MP3ST_APPROVAL_FLOW.md`.** Read that if you need to know
> exactly what `mission_execution` means, why you got a 403 vs. a 409, or how to pre-authorize a target.

---

## 6. What each War Room page does

**[Confirmed — `docs/index.html` nav map]**

| Nav item | Page | Purpose |
|---|---|---|
| War Room | `page-warroom` (default) | Hero controls (ENGAGE/HUNT/Guided), Mission Spine (work-order board, gate snapshot), Findings, plus a power-user "Pliny" cockpit toolbar exposing nearly every backend capability |
| Live Scan | `page-live-scan` | Live scan view |
| 🧾 Scope Receipts | `page-receipts` | Approve/reject pending receipts (the approvals screen) |
| Operatives | `page-operators` | ⚠️ "Deploy"/"spawn" here is **client-only state** — it does not call the backend; real operators spawn inside `/api/mission/start` |
| Evidence Vault | `page-evidence` | Evidence entries |
| ⭐ Op Admiral | `page-general` | The **Op General** control page: PLAN / EXECUTE / FULL AUTO / SITREP / assessment |
| Arsenal | `page-arsenal` | ⚠️ Renders a **hardcoded 85-item client array**, not the live `/api/arsenal/catalog` — may drift from what's actually registered |
| Terminal / Config Library / Benchmarks / CTF Range / Self-Improvement / Settings / About | various | Supporting pages |

> **Note:** there is no separate "Mission Control", "Findings", "Work Orders", or "Approvals" nav item — Mission Control
> was merged into War Room (`docs/index.html:4471` comment), Findings/Work Orders live inside War Room, and "Approvals"
> is the Scope Receipts page.

---

## 7. The two gates, and how to clear a HOLD

**[Confirmed]** Two things are both called a "mission gate":

- **Plan-quality gate** (`OpGeneral.reviewPlan`, `src/general/index.ts:1097-1220`) — this is the one that **blocks
  execution**. Status `hold` (score < 70 or a hard blocker) → **HTTP 409**. This drives the READY/DEGRADED/HOLD chip and
  disables the EXECUTE button.
  - **Hard blockers:** empty scope (`!roe.scope.length`, `:1115`); `destructiveAllowed === true` (`:1122`, −30).
  - **Warnings (degrade, don't block):** "Hunt lane(s) without work orders" (`:1184-1189`, −12); missing
    `mission_execution` receipt requirement (`:1178`).
  - **To clear a HOLD:** ensure scope is set and target-bound; make sure every hunt lane has its prove/disprove work
    orders (re-run PLAN, or add them); do not request destructive actions. Then re-plan.
- **Ledger gate** (`buildMissionGate`, `src/server.ts:1575-1733`) — advisory, surfaced via `POST /api/mission-gate`;
  10 checks over evidence/findings/retests/receipts, `score = round(okCount/10*100)`. Does **not** block execution by
  itself.

**Trust the chip, not the SITREP.** The UI tooltip states the gate verdict is authoritative and the SITREP is
"subjective LLM narration" (`docs/index.html`).

---

## 8. Configuration you'll actually touch

**[Confirmed — `src/config/index.ts`, `src/server.ts`, `src/index.ts`]** Most operational flags are **undocumented in
`.env.example`** (it lists ~10 of ~45 real vars). Key ones:

| Variable | Effect | Default | Cite |
|---|---|---|---|
| `T3MP3ST_STATE_DIR` | Enables persistence (dir for `state.json`) | unset → in-memory | `server.ts:926` |
| `T3MP3ST_HOST` / `DOCKER` | Bind address; `0.0.0.0` exposes the API + drops Host guard | `127.0.0.1` | `server.ts:152` |
| `T3MP3ST_PORT` | Listen port | `3333` | `server.ts:143` |
| `T3MP3ST_FULL_ARSENAL=1` | Arms the full specialist adapter arsenal (incl. metasploit/hydra drivers) | off | `index.ts:423` |
| `T3MP3ST_GATE_BUILTINS=1` | Routes intrusive built-ins (sqli/xss/spray/hash) through the approval gate | off | `index.ts:388` |
| `T3MP3ST_APPROVED_TOOLS` | Pre-authorizes named tools (bypasses interactive approval) | '' | `index.ts:399` |
| `T3MP3ST_HERMES_YOLO=1` | Enables Hermes `--yolo` (auto-approve, unattended) | off | `local-agents.ts:205` |
| `TEMPEST_TARGET_ORIGIN` + `TEMPEST_TARGET_HEADERS` | Inject auth headers for the exact authorized origin (same-origin only) | none | `arsenal/index.ts:87` |
| `TEMPEST_PROXY_URL` | Outbound SOCKS5 proxy | none | `config/index.ts:803` |
| `TEMPEST_DEFAULT_PROVIDER` / `LLM_PROVIDER` | Default LLM provider | stored | `config/index.ts:747` |

> ⚠️ `T3MP3ST_APPROVED_TOOLS`, `T3MP3ST_HERMES_YOLO`, and `T3MP3ST_FULL_ARSENAL` are **safety-relevant** and
> **undocumented** — treat them as expert-only. `T3MP3ST_APPROVED_TOOLS` can silently authorize dangerous tools; in
> headless mode, a tool *not* on this list is denied outright (`src/arsenal/approval.ts:188-195`).

---

## 9. Understanding the arsenal (what actually runs)

**[Confirmed — `src/arsenal/index.ts`, `catalog.ts`, `post-ex.ts`]**

- **Built-in probes (~35, default):** DNS/port/subdomain/HTTP/TLS/XSS/SQLi/etc. Pure Node (no subprocess) except the
  four **external tools** (`nmap_scan`, `nuclei_scan`, `ffuf_fuzz`, `curl_request`) which shell out and **degrade
  gracefully if the binary is absent**. Built-ins are **ungated by default** — their only fence is the scope gate —
  unless you set `T3MP3ST_GATE_BUILTINS=1`.
- **Specialist arsenal (76 catalog entries, opt-in via `T3MP3ST_FULL_ARSENAL=1`):** wraps external binaries
  (httpx, nuclei, ffuf, sqlmap, semgrep, trivy, slither, …). Many have **incomplete argument templates** (fall back to a
  bare positional arg) or **`planned` parsers** (they run and return raw text but populate no structured findings).
  `pacu`/`frida` are catalog-only placeholders; `metasploit`/`hydra` have real hand-written drivers.
- **Every tool call passes the scope gate first**, then the approval gate if its risk tier is
  intrusive/credential/dangerous. Out-of-scope hosts get `SCOPE DENIED` and never spawn a subprocess.

> **Reality check:** the Arsenal UI page lists tools from a hardcoded array, not the live registry. Whether a specialist
> tool actually works depends on (a) `T3MP3ST_FULL_ARSENAL=1`, (b) the binary being installed, and (c) whether its
> adapter has a real argument template. Assume raw-text-only output for anything outside the structured-parser set
> (nuclei, httpx, dalfox, ffuf, katana, semgrep, gitleaks, trivy, grype, garak).

---

## 10. Quick reference — common tasks

| I want to… | Do this |
|---|---|
| Run a guided mission | War Room → "⚓ Guided" → preview → Launch Hunt → approve receipt |
| Plan without executing | Admiral wizard "🧭 Preview (dry-run)" (`confirmed:false`) or Op General "PLAN OPERATION" |
| Approve a pending action | Scope Receipts page → Approve (or Approve Pending for all) |
| See why execution is blocked | Read the gate chip: HOLD = plan-quality 409; 403 = missing receipt |
| Keep state across restarts | Set `T3MP3ST_STATE_DIR` before starting |
| Add tools like metasploit | `T3MP3ST_FULL_ARSENAL=1` (and install the binaries) |
| Test an authenticated API | `TEMPEST_TARGET_ORIGIN` + `TEMPEST_TARGET_HEADERS` |
| Pause a runaway mission | War Room pause control → `/api/mission/pause` |

For failure symptoms and fixes, see `T3MP3ST_TROUBLESHOOTING.md`. For the full route list, see
`T3MP3ST_API_REFERENCE.md`.
