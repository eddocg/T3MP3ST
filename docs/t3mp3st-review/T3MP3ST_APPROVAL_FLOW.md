# T3MP3ST — Plan → Approval → Execution (deep dive)

> This is the authoritative walk-through of everything between "I have a plan" and "a tool actually runs against a live
> target." It answers the exact questions operators keep asking. Source is authority; citations are `file:line` at
> commit `afc9dad`.

---

## 0. The questions this document answers

1. How do I approve an "OP Admiral" plan?
2. What is `mission_execution` approval, exactly?
3. Why did I get a **403** (approval) vs. a **409** (gate hold)?
4. What is a "receipt", and is its target a mission or a host?
5. Can an approval be reused? For how long? Does it survive a restart?
6. What are the *two* approval systems and the *two* gate systems, and which one just blocked me?
7. Where are the sharp edges (re-approving rejected receipts, client-trusted scope, unenforced `model_call`)?

---

## 1. The full pipeline

```
 Directive / Brief
     │
     ▼
 OpGeneral.planOperation() ─────────────► OpPlan { huntLanes, workOrders, roe, missionGate }
     │                                         │
     │                                         ▼
     │                            OpGeneral.reviewPlan()  ── GATE #2 (plan-quality) ──►  status
     │                                         │            ready | degraded | hold
     │                                         │
     ▼                                         ▼
 /api/general/execute      ◄── if status === 'hold' ──►  HTTP 409  (blocked, cannot execute)
 /api/general/auto
 /api/admiral/launch (needs confirmed:true = GATE #1)
     │
     ▼
 guardAction('mission_execution', target) ── GATE #3 (server approval) ──►  no fresh receipt?
     │                                                                       │
     │                                                                       ▼
     │                                                             blockForApproval() → HTTP 403
     │                                                             + creates pending ApprovalRequest ("receipt")
     ▼
 mission starts → TempestCommand tick loop → OperatorAgent → Arsenal.execute()
                                                                 │
                                                                 ▼
                                            scopeViolation()  ── GATE #4 (scope) ──►  out of scope? SCOPE DENIED
                                                                 │
                                                                 ▼
                                            ApprovalController.gate() ── GATE #5 (tool tier) ──►  gated risk? approve/deny
                                                                 │
                                                                 ▼
                                            tool.handler → runSubprocess / fetch
```

There are effectively **five** checkpoints. Three sit at the server/plan layer (Gates 1–3); two sit inside the tool
executor (Gates 4–5). All must pass. [Confirmed]

---

## 2. Gate #1 — Admiral authorization (`confirmed:true`)

**[Confirmed]** `/api/admiral/launch` distinguishes a **dry-run preview** (`confirmed:false`) from a **real launch**
(`confirmed:true`). The War Room "🧭 Preview" button sends `false`; "⚓ Launch Hunt" sends `true`
(`docs/index.html:26801` vs. `:26854`). Preview plans and scores without ever reaching execution. This is the operator's
explicit "yes, run it" flag.

---

## 3. Gate #2 — Plan-quality gate (`OpGeneral.reviewPlan`) → **HTTP 409**

**[Confirmed — `src/general/index.ts:1097-1220`]** This is a *structural quality* check on the `OpPlan`, scored from 100:

- **Hard blockers** (force `hold`):
  - Empty scope: `!roe.scope.length` (`:1115-1120`).
  - `roe.destructiveAllowed === true` (`:1122-1125`, `score -= 30`) — the only boolean toggle that alone forces a hold.
- **Warnings** (degrade, don't block):
  - "Hunt lane(s) without work orders: …" (`:1184-1189`, `score -= 12`) — a declared `huntLanes[].family` has no
    matching `workOrders[].family`.
  - "Missing mission_execution receipt requirement for …" (`:1178`).
- **Status thresholds:** `hold` if score < 70 or a hard blocker; `degraded` if score < 90; else `ready`.
- **`nextApproval`** is computed as `` `${requiredReceipts[0].action}:${requiredReceipts[0].target}` `` (`:673-675`) and
  is what the UI renders as `Next: mission_execution:<target>`.

**Enforcement:** `/api/general/execute` (`src/server.ts:7219-7224`) and `/api/admiral/launch` (`:7638-7684`) return
**HTTP 409** when `status === 'hold'`. The UI disables the EXECUTE button and labels it "HELD"
(`docs/index.html:18582-18587`).

**Gate criteria strings** (rendered in the UI) originate in `enrichPlan` (`src/general/index.ts:666-672`):
`Scope is explicit and target-bound` · `Specialist work orders exist for each active lane` ·
`Claims require evidence before promotion` · `Retests are queued for every finding` ·
`Receipts are named before active execution`.

> **This is what "HOLD" means and how to clear it.** A 409/HOLD is *not* about approvals — it's about plan quality.
> Fix the plan (bind scope, ensure lanes have work orders, drop destructive requests), re-plan, and the gate clears.

---

## 4. Gate #3 — Server approval / "receipt" (`guardAction`) → **HTTP 403**

This is the one people mean when they say "how do I approve the plan."

### 4.1 What `mission_execution` is

**[Confirmed]** `mission_execution` is a value of the `GuardAction` union (`src/server.ts:571`), alongside
`command_execution`, `network_request`, `autonomous_execution`, and `model_call`. It represents "authorization to run a
live mission against a specific target."

- It is checked by `guardAction('mission_execution', target)` at mission start (`src/server.ts:6311`), general execute
  (`:7225`), and general auto (`:7373`). [Confirmed]
- **The `target` is a hostname/URL string, not a mission id.** `approvalMatches` compares action + normalized target
  (`src/server.ts:1238-1249`). So an approved `mission_execution:example.com` receipt authorizes mission execution
  against `example.com` — reusable for any mission hitting that host within the TTL. [Confirmed]
- It appears **only in the UI bundle and code**, never in prose docs (README/API_REFERENCE/etc.) — a genuine
  documentation gap. [Confirmed]

### 4.2 What a "receipt" is

**[Confirmed]** A receipt = an `ApprovalRequest` record (`src/server.ts` interface): `{ id, action, target, reason,
status: 'pending'|'approved'|'rejected'|'expired', approvedBy?, expiresAt?, createdAt, updatedAt }`. The UI calls these
"**Scope Receipts**."

### 4.3 The 403 lifecycle

**[Confirmed]** When `guardAction` finds no fresh matching approval, `blockForApproval()` (`src/server.ts:1319-1332`):
1. creates a **pending** `ApprovalRequest` for that `action:target`,
2. returns **HTTP 403** with the pending receipt in the body.

The client then approves it and retries the original call.

### 4.4 How to approve — every path

All three UI surfaces call **`POST /api/approvals/:id/approve`** (`src/server.ts:5027`):

| Surface | Trigger | Behavior |
|---|---|---|
| **Scope Receipts page** | Manual **Approve** / **Approve Pending** | `approveReceipt(id)` / bulk (`docs/index.html:7566, 7589`) |
| **Inline ENGAGE modal** | Auto on 403 during mission-start | Auto-approves for loopback/lab or AUTONOMOUS; else modal "✅ Approve & run \<target\>" (`:9484-9511, 19735`) |
| **Admiral wizard** | Auto on 403 during launch | Auto for lab/autonomous (≤5 rounds); else redirect to Scope Receipts, then re-fire launch (`:26794-26880`) |

**Approve request body:** `{ ttlMinutes?, approvedBy? }`. On success the receipt becomes `approved` with
`expiresAt = now + ttlMinutes*60_000` (default 30 min, min 1). [Confirmed — `src/server.ts:5033-5041`]

### 4.5 Pre-authorizing a target (the endpoint the UI never uses)

**[Confirmed]** `POST /api/approvals/authorize-target` (`src/server.ts:5044-5104`) approves one or more existing pending
receipts for a concrete target in one call, with stricter guards than the per-id approve route:
- rejects wildcard `*` targets for active actions (400),
- requires `allowWildcard:true` for subdomain wildcards (400),
- **requires each referenced approval to be `pending`** — non-pending → **HTTP 409** (`:5087-5090`),
- verifies the target matches the approval (`approvalMatches`) → 400 on mismatch,
- clamps TTL to ≤ 30 min (`:5073`).

**The War Room UI never calls this endpoint** (`docs/index.html` has no reference) — it always approves per-receipt-id.
It exists for API/automation callers who want to pre-authorize a target. [Confirmed]

### 4.6 Freshness, reuse, persistence

**[Confirmed]**
- **Fresh** = `approvalIsFresh`: approved and (`!expiresAt` or `expiresAt > now`) (`src/server.ts:1222-1223`). Note a
  receipt with no `expiresAt` is treated as always fresh.
- **Reuse:** a fresh approved receipt matches any subsequent `guardAction` for the same action+target within TTL — you
  do not re-approve per tool call.
- **TTL default:** 30 minutes (`:5035`, `authorize-target` clamps to ≤30, `:5073`).
- **Expiry surfacing:** `GET /api/approvals` lazily flips approved-but-expired receipts to `expired` on read
  (`:4986-4989`).
- **Persistence:** approvals are part of the persisted `state.json` and **survive a graceful restart** — *if*
  `T3MP3ST_STATE_DIR` is set. With the default in-memory mode they are lost. [Confirmed]

---

## 5. Gate #4 — Scope (hard, cannot be overridden)

**[Confirmed — `src/arsenal/index.ts:251-287`, wired `:387-395`]** Before any tool handler runs, `scopeViolation`
checks the target host against the Arsenal scope (allowed hosts + always-on loopback/private ranges). Out-of-scope →
`{ success:false, error:'SCOPE DENIED: …' }`, no subprocess spawned. This gate:
- is **not** overridable by any approval,
- fails **closed** on host-normalization tricks (`file:///…`, `//evil.com`),
- guards against CIDR-mask-strip sweeps (`privateBlockMinMask`),
- is **off entirely if scope is `null`** (no target ever added = "library/test mode") — a real footgun.

Scope is derived at runtime from `TargetEnvironment` via `syncArsenalScope()` (`src/index.ts:545-550`), never from a
config file.

---

## 6. Gate #5 — Tool-tier approval (`ApprovalController`)

**[Confirmed — `src/arsenal/approval.ts`]** Independent of the server receipt. Fires only for gated risk tiers
(`GATED_TIERS = {intrusive, credential, dangerous}`). Fail-safe **deny**: if no approver is available and the tool isn't
pre-authorized (`T3MP3ST_APPROVED_TOOLS`), the call is denied. Built-in probes are ungated by default unless
`T3MP3ST_GATE_BUILTINS=1` promotes the intrusive ones. This is "approve once, then free" for the run — not per-target.

---

## 7. 403 vs. 409 — the decision table

| Symptom | Which gate | Meaning | Fix |
|---|---|---|---|
| **HTTP 409** on execute/launch | Gate #2 (`reviewPlan` `hold`) | Plan quality insufficient | Bind scope, give lanes work orders, drop `destructiveAllowed`, re-plan |
| **HTTP 403** + pending receipt | Gate #3 (`guardAction`) | No fresh approval for `action:target` | Approve the receipt (Scope Receipts / modal), retry |
| Tool returns `SCOPE DENIED` | Gate #4 (`scopeViolation`) | Target host not in authorized scope | Add the target to the mission scope; you cannot approve around this |
| Tool returns `APPROVAL REQUIRED`/denied | Gate #5 (`ApprovalController`) | Gated risk tier, no approver/pre-auth | Provide an approver, or add the tool to `T3MP3ST_APPROVED_TOOLS` |

---

## 8. Sharp edges (verified defects / trust boundaries)

**[Confirmed]** These are real, source-verified, and detailed in `T3MP3ST_IMPLEMENTATION_GAPS.md`:

1. **Re-approving non-pending receipts.** `POST /api/approvals/:id/approve` (`src/server.ts:5027-5042`) has **no status
   precondition** — it will flip a `rejected` or `expired` receipt back to `approved`. The sibling `authorize-target`
   route correctly returns 409 for non-pending (`:5087-5090`). Inconsistent; the per-id approve path is the weaker one.
2. **Client-trusted local authorization.** `operationAllowsLocalAction` trusts a client-supplied `scope.authorized`
   flag to bypass approval for local targets. A malicious/mistaken client could assert authorization.
3. **`model_call` has no enforcement call site.** It's a valid `GuardAction` and `/api/approvals/request` accepts it,
   but nothing calls `guardAction('model_call', …)` — the action type is inert.
4. **Auto-approve for "lab/loopback".** The UI silently auto-approves receipts for loopback/lab targets and in
   AUTONOMOUS mode (`docs/index.html:19735, 26794`). Intentional for local testing, but means the human-in-the-loop
   gate is effectively bypassed for those cases — operators should know it's happening.
5. **No persistence by default** means approvals (and all state) vanish on restart unless `T3MP3ST_STATE_DIR` is set.

---

## 9. Answering the headline questions directly

- **"How do I approve an OP Admiral plan?"** The "OP Admiral" page is the *General*. Planning it produces a plan-quality
  gate (Gate #2). If it says HOLD, that's a **409 plan problem** — you fix the plan, you don't "approve" it. When you
  EXECUTE/launch, you'll hit a **403** requiring a `mission_execution:<target>` **receipt** — you approve that on the
  **Scope Receipts** page (or via the auto/modal flow). Those are two different things people conflate.
- **"What is `mission_execution` approval?"** A server-tier `ApprovalRequest` authorizing live mission execution against
  a specific **host/URL** (not a mission id), reusable within a 30-minute TTL, created as `pending` by a 403 and
  approved via `POST /api/approvals/:id/approve`.
- **"Why 403 and not 409?"** 409 = plan-quality HOLD (Gate #2). 403 = missing approval receipt (Gate #3). They are
  independent checkpoints.
