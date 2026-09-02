# LegalBot v1.11 checklist — three phases, GE first

Date: 1 September 2026. This is a current work tracker, not a signature or run
authorization. See the [system design](V111_SYSTEM_DESIGN.md),
[roadmap](V111_RELEASE_ROADMAP.md) and
[working design folder](system-design/README.md).

## Phase 1 — system design

**Status: owner-accepted; maintained in place.**

- [x] Define the three-phase lifecycle: design; evaluation →
  training/improvement → unseen; live last.
- [x] Make GE the first evaluation lane while retaining PB and Essay.
- [x] Define client/API/worker/WebSocket responsibilities and replayable job state.
- [x] Separate legal-authority retrieval, structured matter facts, messages and
  evaluation data.
- [x] Define query planning, chunking, embeddings, vector DB, lexical/hybrid
  ranking, reranking, evidence budgets and top-K selection.
- [x] Define prompt constraints, retrieval qualification, output validation,
  deterministic citations, fallback and honest human-referral language.
- [x] Define conversation storage, bounded context, privacy and no cross-user or
  cross-lane leakage.
- [x] Define failure behaviour, currentness, operations, capability and release
  boundaries.
- [x] Record the major implementation gaps and the technical rebuild prerequisite.
- [x] Preserve all 331 accepted visible GE cases and report the 32 synthetic system
  scenarios separately.
- [x] Keep all 306 unseen GE drafts in separate private custody and retain PB/Essay
  packages.
- [x] Define the factual-first review and the adapted 70+ PB/Essay quality target
  with a practical GE overlay.
- [x] Adopt the simple workflow: owner asks → Codex improves/prepares → necessary
  owner decision → completion.
- [x] Owner accepted the current full design amendments on 1 September 2026.
- [x] Consolidate the design into one editable current set of files.
- [x] Move only redundant design histories, frozen design packs and design-approval
  receipts to recoverable Trash under the owner’s scoped deletion instruction.
- [x] Complete a full design-improvement audit across architecture, contracts, data,
  failures, evaluation/training and typed schemas.
- [x] Select one schema per new object and mark QueryPlan v1/MatterFact v1 as
  legacy read-only.
- [x] Add ConversationSnapshot, MatterFact v2, AnswerJob, KnowledgeGeneration,
  ClaimSet, EvaluationCaseResult and TrainingExperiment contracts.
- [x] Bind the complete request-to-release digest chain and deterministic fallback
  precedence, including a unique terminal WebSocket event.
- [x] Reconcile retrieval, validation and evaluation schemas with the fields claimed
  by their written contracts.

## Phase 2 — evaluation → training/improvement → unseen

**Status: active technical rebuild and evaluation preparation; the 331+60
diagnostic pack was returned for revision on 2 September 2026; no authorizing
model evaluation, weight training, sealed unseen or live run.**

### Decisions and inputs

- [x] Owner approved the three recommended Phase-2 decisions in
  [OWNER_DECISIONS.md](system-design/OWNER_DECISIONS.md).
- [ ] Owner approves exact source/currentness, legal-gold, model/transport,
  resources, private review roots and evaluation contracts before their use.
- [ ] Freeze unseen custody and the exact run-validity/metric contract before the
  visible baseline.

### Technical prerequisite

- [x] Implement selected-schema manifest validation and canonical JSON digests;
  reject legacy schemas for new jobs.
- [x] Reconfirm current inputs and obtain required backup/restore evidence.
- [x] Diagnose `canonical_markdown_missing` and `lease_lost` before another index
  build; do not repeat an unchanged failed command.
- [x] Build and verify a new non-ACTIVE index candidate with pinned retrieval
  models, complete manifests and lexical/vector parity.
- [x] Pass retrieval and integration evidence on the exact technical baseline.
- [x] Implement selected typed integrity-chain verification foundations and unique
  WebSocket job/attempt/lease/terminal identity.
- [x] Implement focused-test-backed selected ConversationSnapshot, MatterFact v2,
  QueryPlan v2, RetrievalResult, EvidencePack, ClaimSet, ValidationReport,
  AnswerJob, VerifiedRelease and runtime-capability builders.
- [x] Add the schema-v31 immutable encrypted matter-fact ledger and connect exact
  selected QueryPlan budgets to the hybrid retrieval runtime.
- [x] Persist and replay-verify a complete ten-object selected chain as encrypted,
  immutable `verified_unpublished` evidence without touching the release outbox.
- [x] Make future normal-live WebSocket completion use the persisted selected
  terminal identity and actual VerifiedRelease digest, failing closed when absent.
- [x] Add a fail-closed atomic publication seam that binds a freshly replayed
  selected chain and actual answer digest to one immutable outbox/publication
  transaction without enabling the runner or live traffic.
- [ ] Integrate the full Request→Conversation/Fact→Plan→Retrieval→Evidence→Claim→
  Validation→Release objects into the durable runner, supply the selected
  publication proof, and implement the gated answer-model transport capability.
- [x] Guard automatic upload, conversation, answer-version and runtime-retention
  deletion behind exact default-deny authorization.
- [x] Implement exact 331-result whole-run reconciliation, preserving every
  terminal outcome and keeping the 32 system scenarios outside the GE denominator.
- [x] Retain, hash and worksheet all 32 system-scenario identities/order in a
  separate unscored lane, including controlled multi-turn assistant context.
- [x] Persist and replay-verify the selected visible EvaluationRun and all 331
  EvaluationCaseResult objects in an immutable encrypted, non-authorizing store.
- [x] Implement a visible-GE execution admission that cannot self-grant and
  requires all ten exact runtime/owner gates plus the pinned artifact set.
- [x] Record the owner's approved factual-first 70+ process in a non-authorizing
  readiness package with exact 331/32 identities, unseen custody, resource
  proposal, coverage predecision and a 331-item qualified-review work order.
- [x] Persist/replay the separate 32-case system run and GE cycle with immutable
  diagnoses, coverage audit, diagnostic results and explicit owner acceptance.
- [x] Implement the missing-area loop: approved coverage cells, separate cumulative
  diagnostics, complete 331 + 32 + diagnostics rerun and the two-repair stop rule.
- [x] Require verifier-issued owner authority for one exact ordered GE coverage
  topology, with all 17 current topics and six separate public-access domains;
  unassigned public domains remain open cells requiring diagnostics.
- [x] Implement deletion-free reviewed official-source intake and exact GE source
  scopes that can feed only a new non-ACTIVE successor generation.
- [x] Require exact end-to-end diagnosed-gap provenance before a researched source
  may enter a GE scope; reject generic intake markers, substitutions and drift.
- [x] Require every GE expansion to preserve one exact sealed non-ACTIVE
  predecessor and add a nonempty qualified source set; reject shrink/replacement.
- [x] Restrict held GE reads to the opaque evaluation capability and reject generic
  retrieval/benchmark/research/vector/live/direct-Lance access.
- [x] Recompute recovery evidence, enforce the two-failure stop, preserve pointers
  and verify actual held Lance row/source/hash/vector/lane parity.

### Visible GE baseline and owner review

- [ ] Evaluate all 331 accepted visible GE cases; report all failures and holds.
- [ ] Run the 32 system scenarios outside the legal-quality denominator.
- [ ] Apply the factual/legal eligibility gate before any quality result.
- [ ] Apply the practical GE quality overlay; do not require academic essay length.
- [ ] Produce readable topic-grouped answers and one final owner approval DOCX.
- [x] Verify the exact 331-case denominator and prepare the factual-first/70+
  review worksheet without opening unseen prompts.

### Improvement, training and unseen

- [x] Diagnose failures by source/currentness, retrieval, matter facts, prompt/code,
  output validation, gold or system execution. The 2 September 2026 owner review
  recorded evaluator, completeness, issue-relevance and planner-vs-answer defects
  in the diagnostic 331+60 pack; that pack remains a historical diagnostic record.
- [x] Apply authorized non-weight repairs and preserve exact before/after evidence.
  Evaluator/retrieval/answer and non-weight planner repair is evidenced by the
  2 September 2026 visible 331 diagnostic r1 rerun versus the 1 September r3
  predecessor. The r2 owner-advisory overlay records batch currentness hold,
  staging-intake authority and 008/174/312 route decisions; the owner adopted
  that overlay as a research and process decision on 2 September 2026. It is not
  gold or admission. The authorized 331 rerun remains evaluation: not gold,
  admission, qualified legal review, weight training, unseen, promotion or live.
- [x] Keep answer-weight training withheld; the returned pack is ineligible gold.
- [ ] If weight training is later approved, use only a separate rights/privacy-
  reviewed training corpus; exclude evaluation, reviewer, user and unseen data.
- [x] Re-evaluate every visible case on the exact improved candidate. The
  create-only diagnostic r1 is preserved. The continuation run is
  `LegalBot-GE-2026-09-02-visible-331-diagnostic-r2`: 38 `FACTUAL_PASS` /
  `PENDING_QUALIFIED_REVIEW`, 293 `FACTUAL_HOLD` / `NOT_ELIGIBLE`. This is
  evaluation evidence, not answer gold.
- [ ] Obtain owner approval of the improved visible result. The owner-facing
  report is
  `LegalBot-GE-2026-09-02-visible-331-diagnostic-r1-vs-r2.docx`. The unsigned
  all-PENDING draft must not be reticked. Locator HOLDs are already resolved
  (66 APPROVE, 1 REJECT). Do not emit another locator-tick pack.
- [x] Fail-closed official knowledge-gap fill (evaluation sidecar only; not gold).
- [ ] Run the authorized unseen scope once; seal findings and do not tune that
  candidate from unseen material. The previous 60 diagnostic cases are exposed
  regression material and cannot be reused as fresh unseen. The 306 private bank
  remains sealed.
- [ ] Apply the same factual-first process to PB and Essay when selected, retaining
  separate mode/topic denominators.

## Phase 3 — live, last

**Status: deferred.**

- [ ] Pass clean-room, Python, web and applicable release verification.
- [ ] Prove backup/restore, rollback, browser reconnect, cancellation, resource
  admission, monitoring and incident handling on the accepted release.
- [ ] Obtain the exact promotion, operations and live decisions.
- [ ] Keep the first implementation bound to `127.0.0.1`.
- [ ] Treat public access, accounts, sharing, cloud storage and real human handoff
  as separately approved scope.

Completing Phase 1 does not run Phase 2 or Phase 3. The current questions are not
completed legal gold and are not an approved training corpus.
