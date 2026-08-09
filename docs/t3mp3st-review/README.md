# T3MP3ST — Deep Project Audit & Operator Guide

Read-only reverse-engineering audit of T3MP3ST at commit `afc9dad` (branch `develop`). **Source code is treated as the
authority.** Every important claim carries a `file:line` citation; incomplete evidence is marked **[UNRESOLVED]**;
documented-intent, actual-implementation, observed-behavior, and inference are kept distinct.

**Constraints honored:** no source modified, no formatting, no dependency changes, no deletions, no DB migration, no
state reset, no traffic to external targets, no scanners/offensive execution. Static inspection and reading only.

## Deliverables

1. **[T3MP3ST_ARCHITECTURE.md](./T3MP3ST_ARCHITECTURE.md)** — system identity, component map, command hierarchy, the two
   approval systems, the two gate systems, persistence, data model, enforcement reality.
2. **[T3MP3ST_OPERATOR_GUIDE.md](./T3MP3ST_OPERATOR_GUIDE.md)** — *(most important)* mental model, install/start, the
   10–20-step normal workflow, approvals, page-by-page UI, config, arsenal reality.
3. **[T3MP3ST_APPROVAL_FLOW.md](./T3MP3ST_APPROVAL_FLOW.md)** — deep plan→approval→execution; answers "how do I approve
   an OP Admiral plan", "what is `mission_execution`", "403 vs 409".
4. **[T3MP3ST_API_REFERENCE.md](./T3MP3ST_API_REFERENCE.md)** — the ~130 as-built routes, grouped, with UI-wired vs.
   backend-only and enforcement notes.
5. **[T3MP3ST_TROUBLESHOOTING.md](./T3MP3ST_TROUBLESHOOTING.md)** — symptom → cause → fix.
6. **[T3MP3ST_IMPLEMENTATION_GAPS.md](./T3MP3ST_IMPLEMENTATION_GAPS.md)** — gaps classified
   Critical/High/Medium/Low/Documentation-only/UX-only, plus placeholders and test-coverage gaps.
7. **[T3MP3ST_FEATURE_BASELINE.md](./T3MP3ST_FEATURE_BASELINE.md)** — extension points (seams), not a roadmap.

The Final Executive Summary was delivered in the audit response.
