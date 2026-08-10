# T3MP3ST — Research-Quality / Mission-Fidelity Assessment

**Date:** 2026-08-10 · **Scope:** control-plane → execution → findings pipeline, after the recent control-plane fixes. **Constraint honored:** no Danalock-specific logic; the run that motivated this is treated only as a counterexample exposing *general* methodology weaknesses.

This document records (a) the verdict on each area the review asked about, (b) the patch that landed, and (c) what is deliberately **not** claimed.

The single root finding: **mission intent loses authority at the planning→execution seam.** A narrow, authenticated authorization directive was parsed and reached the planner prompt verbatim, but the runtime then seeded a *hardcoded generic recon battery* and defined completion as *"the task queue drained."* Intent was advisory text; execution was hardcoded.

---

## A. Where mission intent loses authority (the traced chain)

| Hop | Component | What happens to intent | Fidelity |
|-----|-----------|------------------------|----------|
| 1 | Guided Hunt → `briefToDirective` | Objective text captured verbatim; operator guidance rides in `constraints`. | **Preserved** |
| 2 | Directive → OpGeneral `planOperation` | Full constraints inlined into `buildPlanningPrompt`; planner sees intent. | **Preserved** |
| 3 | OpGeneral `OpPlan` / workOrders | Rich plan produced, but `executePlan` only *returns* the plan; nothing binds `workOrders` to the runtime task queue. | **Diverges here** |
| 4 | TempestCommand tick → `MissionControl.generateTasksForTarget` | **Hardcoded** `createReconTasks/VulnScan/Exploit` battery seeds the queue regardless of objective. The OpPlan is bypassed. | **Lost** |
| 5 | OperatorAgent executes generic tasks | Runs nmap/ffuf/nuclei/etc. — generic recon, not the directive. | **Lost** |
| 6 | `Finding` pipeline → `verifyGate` | Gate checked only that *some* tool output existed (`passed`), never that the evidence *supported the asserted category*. | **Over-claims** |
| 7 | Completion (`completeMission`) | Triggered by task-queue drain; no check against the objective. | **Falsely "complete"** |

**Breach point = hops 3→4.** The patch closes it by making the objective a first-class input to task seeding and completion.

---

## B. Per-area verdicts

**1. Directive adherence.** *Existing but not wired.* Directives reached the planner but were dropped before execution. → **Fixed (P0):** objective class is now derived from the directive and drives task seeding + completion.

**2. Prerequisite/Blocker model.** *Missing.* No first-class "this needs Principal B / a state fixture" concept. → **Fixed (P0):** the objective lane emits explicit `status:blocked-prerequisite` tasks that *refuse* to substitute generic recon.

**3. Objective fidelity / mission completion.** *Implementation bug.* Completion = queue drain. → **Fixed (P0):** `objectiveOutcome` (untested/blocked/partial/met/exhausted) is derived from the objective lane at completion.

**4. Finding classification integrity.** *Implementation bug + overclaim.* Severity/category inherited from tools or hardcoded (`cors_check` minted `critical` on header reflection). → **Fixed (P0):** conservative, auditable `claimSupport` assessment caps severity and can deny capability verification; CORS/Swagger/methods softened to observations.

**5. `verifyGate` semantics.** *Misleading.* "verified" meant "has tool output," not "capability demonstrated." → **Fixed (P0):** two independent axes now — `passed` (provenance) vs `capabilityVerified` (evidence supports the category). UI renders both truthfully.

**6. Observation → Finding boundary.** *Blurred.* Scanner observations presented as findings. → **Fixed (P1):** `observationClass` + observation categories can never be capability-verified.

**7. Deduplication.** *Weak.* `title::target` only. → **Fixed (P0):** fingerprint = origin+route+method+property+selector+principal/resource boundary. Same-boundary consolidates; distinct authz failures never merge.

**8. Negative evidence.** *Missing.* → **Fixed (P1):** `boundary_held` records persisted on falsification/owner-control completion — **advisory only, never auto-suppress** a retest after a state change.

**9. Authenticated API coverage.** *Untracked.* → **Fixed (P1):** `authContextApplied` provenance (means "credential headers attached," **not** "authn/authz succeeded").

**10. OpenAPI/artifact-driven planning.** *Deferred (P2).* Lane lists spec discovery as a prerequisite; full artifact-first planning is follow-up.

**11. Authorization / multi-principal testing.** *Deferred (P2), honestly.* The runtime holds one principal and no Principal/Resource model. The lane **recognizes** the objective, runs legitimate current-principal baselines, and **reports the missing Principal-B / state fixtures as BLOCKED** rather than fabricating A/B coverage.

**12. State-transition / lifecycle security.** *Deferred (P2), honestly.* No structured PRE→ACTION→STATE→RETEST→DIFF work order exists yet; surfaced as a blocked prerequisite, not faked.

---

## C. The five architectural adjustments — how each was honored

1. **Objective class orthogonal to MissionFamily** — `Mission.objectiveClass` (`general | authorization_lifecycle`) added; `MissionFamily` untouched. A `web_api` mission can carry an authorization objective.
2. **`authContextApplied`, not `authenticated: boolean`** — provenance flag means *headers were attached*; the UI labels it "≠ authz succeeded."
3. **Conservative, auditable binding** — source `category`/`severity` preserved verbatim; a separate deterministic `claimSupport` verdict caps/blocks and carries a rationale. Never rewrites the claim. Structured signals preferred over prose.
4. **Strengthened fingerprint** — `origin::route::method::property::selector::boundary`; route shapes collapse (`/users/{n}`), distinct boundaries never merge.
5. **Negative evidence persisted, never auto-suppresses** — `boundaryHeldLedger` with a `stateMarker`; advisory context only.

**Scope contradiction resolved:** the patch does **not** claim true A/B authorization or structured revocation-lifecycle testing. For the bounded lane it recognizes the objective, runs bounded prerequisites + current-principal baselines, marks the differential/lifecycle work BLOCKED with an explicit operator request, and sets `objectiveOutcome` to `blocked`/`partial` — never `met` — when the central hypothesis could not be exercised.

---

## D. Files changed

| File | Change |
|------|--------|
| `src/evidence/classification.ts` *(new)* | Category→evidence contract, `assessClaimSupport`, `auditedSeverity`, `capabilitySupported`, `findingFingerprint`. |
| `src/evidence/gate.ts` | Two-axis gate: `passed` (provenance) + `capabilityVerified` (support). Attaches `claimSupport`. |
| `src/evidence/index.ts` | Fingerprint dedup/consolidation in `addFinding`; `verifyFinding` uses capability bar. |
| `src/mission/index.ts` | `detectObjectiveClass`, `createAuthorizationObjectiveTasks`, `deriveObjectiveOutcome`; objective-aware seeding + phase gating + completion. |
| `src/types/index.ts` | `Finding.category/observationClass/authContextApplied/claimSupport`, `ClaimSupport`, `MissionObjectiveClass/Outcome`, `TempestConfig.objectiveClass`. |
| `src/index.ts` | Command carries objective class/directive into auto-mission creation. |
| `src/operators/index.ts` | `recordFinding` stamps `verifiedAt` only on `capabilityVerified`; threads new ToolFinding fields. |
| `src/arsenal/index.ts` | `credentialHeadersAppliedFor` provenance; CORS/Swagger/methods softened to observations. |
| `src/server.ts` | Threads objective through bring-up; exposes objective on `/api/mission/status`; `boundary_held` ledger + `/api/boundary-held`; persistence. |
| `docs/index.html` | Truthful maturity ladder (adds `tool-proven` rung); finding detail shows category + evidence-support + audited severity + auth provenance. |
| `src/__tests__/mission-fidelity.test.ts` *(new)* | 15-test regression scenario. |
| `src/__tests__/{spine-live,control-plane-lifecycle-static,local-api-hardening-static}.test.ts` | Updated to the corrected two-axis semantics. |

**Tests:** 679 passing, 0 failing. The 11 "failed" *files* are a pre-existing undici import issue in the sandbox, identical on the pre-change baseline (662 passing there; +17 net-new from this patch).

---

## E. Explicitly NOT claimed

- No true A/B cross-principal authorization execution (needs a Principal/Resource model + second controlled identity).
- No structured revocation/downgrade lifecycle differential (needs a PRE→ACTION→STATE→RETEST→DIFF work order).
- No auto-suppression from negative evidence (deliberately deferred until principal/resource/state identity is structured).
- No Danalock- or vendor-specific logic anywhere; the category table and objective detector are generic.

These are the honest P2 follow-ups the patch *surfaces as blocked prerequisites* instead of fabricating.
