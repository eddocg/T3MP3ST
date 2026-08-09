# T3MP3ST — API Reference (as-built)

> Generated from `src/server.ts` at commit `afc9dad`. This lists the routes **actually registered in code**
> (~130 handlers via `app.get/post/patch/delete`), grouped by function, with notes on what is UI-wired, what is
> backend-only, and where enforcement lives. This supersedes prose docs where they disagree.
>
> - **Base URL:** `http://127.0.0.1:3333` (configurable via `T3MP3ST_HOST` / `T3MP3ST_PORT`).
> - **UI-wired?** = called by the War Room SPA (`docs/index.html`). **Backend-only** = registered but no UI caller found.
> - Status codes noted where the audit confirmed them (`403` approval, `409` gate hold).

---

## 1. Health & system

| Method | Route | Notes |
|---|---|---|
| GET | `/health`, `/api/health` | `healthPayload()` — ok/status/llm/storage (`src/server.ts:4862`, array-form route) |
| GET | `/api/preflight` | Preflight checks (`:4870`) |
| GET | `/` | Redirect → `/ui/` (`:7950`); static UI mounted from `docs/` (`:7952`) |
| GET | `/api/events` | Event stream/log |
| GET | `/api/llm/status` | LLM connectivity |
| POST | `/api/llm/chat`, `/api/llm/local` | Direct LLM calls |
| POST | `/api/models` | Model listing (fetch-models button) |
| GET | `/api/net/ip`, `/api/net/proxy` · POST `/api/net/proxy` | Network/proxy status & config |

---

## 2. Admiral (intake / planner) — `src/admiral/index.ts`, routes ~`server.ts:7573+`

| Method | Route | Purpose | UI-wired? |
|---|---|---|---|
| POST | `/api/admiral/converse` | Conversational intake / target scouting | ✅ (`docs/index.html:26717`) |
| POST | `/api/admiral/suggest` | Prompt/archetype suggestion | ✅ (`:27008`) |
| POST | `/api/admiral/launch` | Plan+execute via Admiral. `confirmed:false` = dry-run preview (**Gate #1**); `confirmed:true` = real launch. Returns **403** with pending receipt if unapproved; **409** if plan gate = hold | ✅ (`:26801/26854`) |

---

## 3. Op General (planner/orchestrator) — `src/general/index.ts`, routes ~`server.ts:7116+`

> ⚠️ The War Room "**⭐ Op Admiral**" page drives these General routes — not the Admiral module.

| Method | Route | Purpose | Notes |
|---|---|---|---|
| GET/POST | `/api/general/plan` | Build an `OpPlan` (`planOperation`) | UI "PLAN OPERATION" (`:17651`). `WHITEPAPER.md:552` mislabels this "Op Admiral" |
| POST | `/api/general/execute` | Execute the plan | **HTTP 409** if `reviewPlan` status = `hold` (`:7219-7224`); guards `mission_execution` (`:7225`) |
| POST | `/api/general/auto` | One-shot plan+execute ("FULL AUTO") | Guards `mission_execution` (`:7373`) |
| POST | `/api/general/assess` | Generate assessment | UI (`:18503`) |
| POST | `/api/general/sitrep` · GET `/api/general/sitreps` | LLM SITREP narration (advisory; gate chip is authoritative) | |

---

## 4. Missions — routes ~`server.ts:6267+`

| Method | Route | Purpose | Notes |
|---|---|---|---|
| POST | `/api/mission/start` | Start a live mission | Guards `mission_execution` at `:6311` → **403** + pending receipt if unapproved |
| POST | `/api/mission/stop` | Stop mission | UI (`:6612`) |
| POST | `/api/mission/pause` | Pause mission | UI (`:6619`) |
| POST | `/api/mission/resume` | Resume mission | UI (`:6626`) |
| GET | `/api/mission/status` | Mission status | |
| GET | `/api/mission/findings`, `/api/mission/report`, `/api/mission/:id/report` | Findings & reports | |
| GET | `/api/mission-context/latest` | Latest mission context | |

> **No `GET/POST /api/missions` (plural).** `FEATURES.md:628-629` honestly lists it as planned/not-built. [Confirmed]

---

## 5. Mission drafts, bundles, gate

| Method | Route | Purpose |
|---|---|---|
| GET/POST | `/api/mission-drafts`, GET/PATCH/DELETE `/api/mission-drafts/:id` | CRUD on mission drafts |
| POST/GET | `/api/mission-bundles`, GET `/api/mission-bundles/:missionId` | Mission bundles |
| POST | `/api/mission-gate` | **Ledger-based** mission gate (`buildMissionGate`, `server.ts:1575-1733`) — advisory, 10 checks. **Distinct** from the plan-quality gate that blocks execution |

---

## 6. Approvals ("Scope Receipts") — `server.ts:4983-5116`

| Method | Route | Purpose | Notes |
|---|---|---|---|
| GET | `/api/approvals` | List receipts (lazily expires stale ones) | `:4983` |
| POST | `/api/approvals/request` | Create a pending receipt; rejects wildcard targets for active actions | `:4995` |
| POST | `/api/approvals/:id/approve` | Approve a receipt (TTL default 30 min) | ⚠️ **No status precondition** — can re-approve rejected/expired (`:5027`) |
| POST | `/api/approvals/:id/reject` | Reject a receipt | `:5106` |
| POST | `/api/approvals/authorize-target` | Pre-authorize concrete target across pending receipts | Stricter: **409** if any referenced receipt is non-pending (`:5044-5104`). ⚠️ **No UI caller** |

**Guarded actions** (`GuardAction`, `server.ts:571`): `command_execution`, `network_request`, `mission_execution`,
`autonomous_execution`, `model_call`. ⚠️ `model_call` has **no enforcement call site**. [Confirmed]

---

## 7. Arsenal & tools

| Method | Route | Purpose | Notes |
|---|---|---|---|
| GET | `/api/arsenal/catalog` | Live tool catalog | ⚠️ **UI does not call this** — Arsenal page uses a hardcoded 85-item client array |
| GET | `/api/arsenal/status`, `/api/arsenal/activation`, `/api/arsenal/approvals` | Arsenal state / tool-approval gate | `/api/arsenal/approvals` is UI-wired (`:25762`) |
| POST | `/api/arsenal/plan` | Plan tools for a family | |
| GET | `/api/tools` · POST `/api/tools/execute`, `/api/tools/recon` | Tool inventory & execution | `/api/tools/execute` UI-wired |

---

## 8. Research ledger (hypotheses / evidence / findings / retests / work orders)

| Method | Route | Purpose |
|---|---|---|
| GET/POST | `/api/hypotheses`, PATCH `/api/hypotheses/:id` | Hypothesis CRUD |
| POST | `/api/hypotheses/:id/decompose` | Decompose → work orders |
| POST | `/api/hypotheses/:id/work-orders`, `/api/hypotheses/:id/promote` | Attach work orders / promote to finding |
| GET/POST | `/api/work-orders`, PATCH `/api/work-orders/:id`, POST `/api/work-orders/:id/complete` | Work-order lifecycle |
| GET/POST | `/api/evidence` · GET `/api/evidence-graph` | Evidence entries & graph |
| GET/POST | `/api/findings`, PATCH `/api/findings/:id`, POST `/api/findings/:id/retest` | Findings; retest attach |
| GET | `/api/retests`, PATCH `/api/retests/:id` | Retests |
| POST | `/api/promotion/evaluate` | Promotion evaluation |

> Findings are gated by `gateLiveFinding()` (`src/evidence/gate.ts`) — prose is not evidence. [Confirmed]

---

## 9. Operators

| Method | Route | Purpose | Notes |
|---|---|---|---|
| GET | `/api/operators/list`, `/api/operators/prompts` | Operator inventory | |
| POST | `/api/operators/spawn` | Spawn an operator | ⚠️ **No UI caller** — UI "Deploy" is client-only state; real spawn is inside `/api/mission/start` |
| POST | `/api/operators/:id/task` | Task an operator | ⚠️ No UI caller |
| POST | `/api/operators/terminate`, `/api/operators/prompt`, `/api/operators/prompt/reset` | Manage operators/prompts | |
| GET | `/api/operator-doctrine`, `/api/operator-runbooks`, `/api/operator-runbooks/:family` | Doctrine & runbooks | |

---

## 10. Pressure paths, attack graph, whitebox, repro

| Method | Route | Purpose |
|---|---|---|
| GET/POST | `/api/pressure-paths`, `/canary`, `/chains`, `/duel`, `/mutate` | Adversarial pressure-path generation |
| POST | `/api/attack-graph`, `/api/attack-graph/ingest` | Attack-graph build/ingest |
| POST | `/api/whitebox/analyze` | White-box source analysis (decomposition subsystem) |
| GET/POST | `/api/repro-packs` | Reproduction packs |
| POST | `/api/route-preview` | Route preview (advisory lane/tool-grant metadata; not enforced) |

---

## 11. Watch loop, self-heal, learning, memory, improvement

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/watch-loop/status` · POST `/api/watch-loop/run` | Watch loop |
| POST | `/api/self-heal/run` | Self-heal (diagnose/repair) |
| GET | `/api/learning/status` · POST `/api/learning/run-review` | Learning subsystem |
| GET | `/api/memory/capsule`, `/api/memory/proposals` · POST `/api/memory/proposals`, `/:id/accept`, `/:id/reject` | Memory capsule & proposals |
| GET/POST | `/api/improvement/proposals` | Improvement proposals |
| GET | `/api/selfimprove/ledger` | Self-improvement ledger |

---

## 12. Local coding-agent integration

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/agents/local/detect`, `/api/agents/local/status` | Detect/inspect connected local coding agents |
| POST | `/api/agents/local/connect`, `/disconnect`, `/dispatch`, `/ping` | Connect/dispatch to a local agent (Claude Code / Codex / Hermes / OpenCode / Oh My Pi) |
| GET | `/api/codex/status` · POST `/api/codex/probe` | Codex-specific |

---

## 13. Bug bounty — ⚠️ backend-only (no UI)

| Method | Route |
|---|---|
| GET | `/api/bounty/platforms`, `/api/bounty/credentials`, `/api/bounty/programs/:platform` |
| POST | `/api/bounty/format`, `/api/bounty/submit` |

**No War Room UI references any `/api/bounty/*` route.** [Confirmed] Either intentionally API/CLI-only or unwired.

---

## 14. Reference / catalog reads

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/resource-packs`, `/api/resource-packs/:id` · POST `/api/resource-packs/search` | Resource packs |
| GET | `/api/agent-prompt-packs`, `/:id`, `/api/agent-context/:family` | Prompt packs & context |
| GET | `/api/operator-runbooks`, `/api/workflow-presets`, `/api/ai-redteam/playbook` | Runbooks/presets/playbooks |
| GET | `/api/forefront-radar`, `/:id`, `/api/routes/:routeId/scorecards` | Radar & scorecards |

---

## Enforcement summary (where the gates live in the API)

- **409 (plan hold):** `/api/general/execute`, `/api/general/auto`, `/api/admiral/launch` when `reviewPlan` = `hold`.
- **403 (needs approval):** any route calling `guardAction` — `/api/mission/start`, `/api/general/execute`,
  `/api/general/auto`, `/api/admiral/launch` — creates a pending receipt.
- **Scope + tool-approval gates** are inside `Arsenal.execute` and fire regardless of which route triggered the tool.
