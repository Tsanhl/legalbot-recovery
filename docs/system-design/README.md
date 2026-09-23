# LegalBot working system design

This is the single working design folder. The design is edited when improvements
are needed; it is not frozen into a new pack for every change.

Latest development update, 23 September 2026: after the owner answered “both,” [GE shared backend and model routes](GE_PRE_BROWSER_IMPROVEMENT_PLAN.md#23-september-development-chat-implementation-and-exact-remaining-gates) now records a scoped owner-development implementation for local Qwen, linked local models, Codex and API answers through the common evidence/guidance/review/publication controls. Actual model-to-browser qualification remains open; prior dated execution observations below are historical.

Simple owner workflow:

1. The owner asks for a change or a new phase.
2. Codex investigates, improves the plan and prepares the complete proposed result.
3. Codex asks only for decisions that require owner judgment or authority.
4. The owner approves, then Codex completes the approved work.

Exact runtime inputs, evaluation runs and release artifacts still bind hashes and
versions so results can be reproduced. That evidence control does not require
archiving every design edit.

Working documents:

- `docs/system-design/GE_PRE_BROWSER_IMPROVEMENT_PLAN.md` — maintained shared-backend/model-route plan, implementation gaps, acceptance tests and preserved handoffs.
- `docs/V111_SYSTEM_DESIGN.md` — full current system design.
- `docs/system-design/ARCHITECTURE.md` — four-plane architecture, invariants and
  complete online/offline flow.
- `docs/system-design/CONTRACTS.md` — implementation/API/state/security contracts.
- `docs/system-design/DATA_MODEL.md` — logical aggregates, identity, fact and
  provenance rules.
- `docs/system-design/FAILURE_MODES.md` — deterministic failure, fallback and
  recovery behaviour.
- `docs/system-design/EVALUATION_AND_TRAINING.md` — factual-first evaluation,
  quality review, improvement/training and unseen sequence.
- `docs/system-design/GE_EVERYDAY_UNSEEN.md` — current UK/USA 420-legal/35-domain
  plus 23-system Codex diagnostic, location allocation, creation/review/one-pass
  authority and readiness rules.
- `docs/system-design/GE_KNOWLEDGE_GAP_AUTOMATION.md` — full bank-completion and
  automatic official-research/chunk/embedding/database plan, implementation gaps,
  private-reference isolation and the distinction from weight training.
- `docs/system-design/SCHEMA_REGISTRY.md` — one selected schema version per object.
- `docs/system-design/COVERAGE_MATRIX.md` — requested capability, implementation gap and conformance proof.
- `docs/system-design/OWNER_DECISIONS.md` — approved preparation decisions and
  safely deferred later scope.
- `docs/system-design/schemas/` — current typed contracts.

The design amendments and all three Phase-2 preparation recommendations are
owner-approved. Current GE state (5 September 2026):
`CODEX_UNSEEN_UK_US_CREATION_RUNNING` for
`LegalBot-GE-2026-09-05-codex-unseen-r1`, still in preseal working creation.
The owner directs UK and USA first, other countries later; see the recorded
[scope amendment](../../data/evaluations/general-enquiries/LegalBot-GE-2026-09-05-codex-unseen-r1/UK-USA-SCOPE-AMENDMENT.json). Plan 420 legal cases across 35 domains:
210 UK (England 70, Wales 70, Scotland 35, Northern Ireland 35) and 210 USA (all
50 states plus DC explicitly located, 4–5 cases each, federal/state applicability
per issue), plus 23 separate system cases. These limited samples do not prove
all legal areas in every state. Explicitly route or defer US territories, tribal
law and unsupported law. Current `cross-border-trade-regulation` retains the
historical `eu-internal-market-law` mapping.

"Create, review, then run once; no training" remains authorized with separate Codex
author/researcher/reviewer roles. After creation review and exact bank/runtime
hash binding, no further execution approval is needed. The UK/USA authoring pilot has started; no question creation or verified-source completion
is claimed. `bank_sealed=false`, `candidate_executed=false`, and no candidate
answers exist. This same-provider diagnostic is not professional assurance or
product deployment certification. Weight training, adapter activation, promotion
and live remain unauthorized; the r2 adapter stays inactive/excluded and the
retired 306 bank excluded. Prior stopped drafts remain preserved and excluded.
Historical question-free requests and verifiers are preserved.
