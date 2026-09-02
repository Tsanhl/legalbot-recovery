# LegalBot working system design

This is the single working design folder. The design is edited when improvements
are needed; it is not frozen into a new pack for every change.

Simple owner workflow:

1. The owner asks for a change or a new phase.
2. Codex investigates, improves the plan and prepares the complete proposed result.
3. Codex asks only for decisions that require owner judgment or authority.
4. The owner approves, then Codex completes the approved work.

Exact runtime inputs, evaluation runs and release artifacts still bind hashes and
versions so results can be reproduced. That evidence control does not require
archiving every design edit.

Working documents:

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
- `docs/system-design/SCHEMA_REGISTRY.md` — one selected schema version per object.
- `docs/system-design/COVERAGE_MATRIX.md` — requested capability, implementation gap and conformance proof.
- `docs/system-design/OWNER_DECISIONS.md` — approved preparation decisions and
  safely deferred later scope.
- `docs/system-design/schemas/` — current typed contracts.

The current design amendments and all three Phase-2 preparation recommendations
are owner-approved. Phase 2 execution, exact model/source/currentness/private-root
use, training, unseen testing, promotion and live activation still require their
applicable exact inputs and decisions.
