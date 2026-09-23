# LegalBot v1.11 checklist — three phases, GE first

## Model-route development and remaining acceptance — 23 September 2026

The [full maintained plan](system-design/GE_PRE_BROWSER_IMPROVEMENT_PLAN.md#23-september-development-chat-implementation-and-exact-remaining-gates) adds routes alongside Qwen. The owner later answered “both,” authorizing the scoped development implementation. These entries do not reopen completed historical checks or protected execution.

- [x] Prepare the full shared-backend/provider-route plan from the five PDFs, the Doc-AI reference, current code and public handoffs.
- [x] Define connection UX, all-stage route identity, guide/evidence separation, privacy/tool controls, durability and route-specific acceptance tests.
- [x] Implement separate scoped development-chat admission/replay and freeze route, request, candidate and authority hash without changing the exact-case Qwen lane.
- [x] Add task-local model routing through the shared generation, rewrite, repair and reviewer gateway; no database schema change was required for the scoped lane.
- [ ] Prove every configured model route's actual identity, capability and failure behavior; complete production-grade connection management.
- [ ] Integrate actual reviewed research generations, matter facts, guides and host-sent input provenance into the runner.
- [ ] Prove bounded Codex/API transports, authentication and enforced isolation with synthetic inputs.
- [ ] Produce one supported answer and one expected hold through the actual shared backend with an alternate provider and Qwen unavailable.
- [x] Connect a development-only website selector and text-question submission/read path, with owner capability and remote consent.
- [ ] Prove linked local, Codex and API answers; test follow-ups, cancellation, duplicate submit, reconnect and citations. Uploads remain excluded from this first scoped lane.
- [ ] Qualify each advertised route/workflow, including grounding, omissions, security, failure recovery, backup/restore and capacity/cost.
- [ ] Decide Qwen training from a valid diagnosed baseline and exact eligible experiment authority; `NONE` remains possible.
- [ ] Reconcile protected bank/readiness/runtime authority and execute only its existing eligible one-pass scope.
- [ ] Prepare and satisfy the exact live-last owner gate.

Development code is underway and synthetically checked. A bounded actual Qwen run ended in one review hold and one model-call timeout; a narrow Codex CLI/filesystem isolation check passed. No supported answer, infrastructure-complete, training-only, protected-run or live claim follows from them.

Updated: 5 September 2026. This is a current work tracker, not a signature or run
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

Current additional work: [automatic UK/USA knowledge-gap plan](system-design/GE_KNOWLEDGE_GAP_AUTOMATION.md).

- [x] Record authorization and the full automatic research/chunk/embedding/DB plan.
- [ ] Complete all 443 construction slots, including the preserved timed-out 12-slot author batch.
- [ ] Repair and independently review material fixture, source and currentness holds before sealing.
- [ ] Connect origin-bound official research, AI source review and structural chunking for UK/USA gaps.
- [ ] Verify real pinned-model embeddings, immutable non-live DB generations and retrieval read-back.
- [ ] Enforce shared-research/private-reference/candidate-case storage separation.
- [ ] Validate the new retrieval route on permitted visible cases before including it in a frozen unseen runtime.
- [ ] Complete the ready bank's authorized one-pass test and report/retire it without training or rescoring.

**Status: `CODEX_UNSEEN_UK_US_CREATION_RUNNING`.**
`LegalBot-GE-2026-09-05-codex-unseen-r1` remains in preseal working creation.
The owner directs UK and USA first, other countries later; see the recorded
[scope amendment](../data/evaluations/general-enquiries/LegalBot-GE-2026-09-05-codex-unseen-r1/UK-USA-SCOPE-AMENDMENT.json). Creation, review and one-pass execution
remain authorized through separate Codex author/researcher/reviewer roles.
Keep this state with a new authoring pilot started. Prior stopped drafts and failed
files remain preserved and excluded. No question or verified-source completion
is claimed; `bank_sealed=false`, `candidate_executed=false`, and no candidate
answers exist. Readiness work does not require another run approval.
No weight training, adapter activation, promotion or live use is authorized.

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
- [x] Keep answer-weight training withheld for the returned 331+60 pack; that
  historical pack remains ineligible gold and did not enter training.
- [x] Apply the owner-scoped 4 September exception only to the 13 exact accepted
  hashes. Complete rights/privacy review, exact-hash and hold exclusion checks,
  topic/source-separated 9/3/1 splits, pinned-base verification and sealed-unseen
  custody checks. Retire those 13 hashes from external scoring.
- [x] Re-evaluate every visible case on the exact improved candidate. The
  create-only diagnostic r1 is preserved. The continuation run is
  `LegalBot-GE-2026-09-02-visible-331-diagnostic-r2`: 38 `FACTUAL_PASS` /
  `PENDING_QUALIFIED_REVIEW`, 293 `FACTUAL_HOLD` / `NOT_ELIGIBLE`. This is
  evaluation evidence, not answer gold.
- [x] Obtain owner approval of the improved visible result. The owner-facing
  report is
  `LegalBot-GE-2026-09-02-visible-331-diagnostic-r1-vs-r2.docx`. That approval
  is scoped diagnostic only. The unsigned all-PENDING draft must not be
  reticked. Locator HOLDs are resolved (66 APPROVE, 1 REJECT). The 293-hold
  reason router is `LegalBot-GE-2026-09-02-control-plane-router-r1`.
- [x] Route machine-repairable holds as a targeted delta; do not rerun all 331
  on unchanged inputs. The first delta is
  `LegalBot-GE-2026-09-02-mechanical-repair-delta-r1` (191 rerun, 140 carried
  forward, 41 `FACTUAL_PASS`, 53 remaining mechanical claim-support holds).
- [x] Classify the remaining 53 at proposition level without generic retrieval,
  and prepare non-approving qualified-review packets. The receipt is
  `LegalBot-GE-2026-09-02-claim-level-and-review-prep-r1` (0 mechanically
  repaired, 53 exhausted to review, 331 packets, `qualified_legal_review`
  still `NOT_STARTED`). Gold, admission, training, unseen, promotion and live
  remain `NOT_STARTED`.
- [x] Implement Evaluation Control Plane v2 and issue-led Priority 1 sidecar
  intake (`LegalBot-GE-2026-09-02-evaluation-control-plane-v2-r1`;
  `LegalBot-GE-2026-09-02-priority1-authority-intake-r1`). Do not rebuild RAG,
  re-embed the corpus, or treat r2 as legal gold.
- [x] Run the Kajima paragraph 29/30 targeted mediation-family delta
  (`LegalBot-GE-2026-09-02-mediation-family-kajima-delta-r1`). Record the
  first remaining-runnable unit-test FAIL as an intended routing change.
  cp-d09 is not the only affected case. Remaining mediation-family runnable
  count is 0. Do not treat the delta as gold, review or training.
- [x] Run visible diagnostic 331 r3
  (`LegalBot-GE-2026-09-02-visible-331-diagnostic-r3`; 39 `FACTUAL_PASS` /
  292 `FACTUAL_HOLD`). Preserve frozen r1 and r2. Do not treat r3 as gold,
  review, training, unseen, promotion or live.
- [x] Targeted mechanical-repair delta after r3
  (`LegalBot-GE-2026-09-03-mechanical-repair-delta-r1`; 42 `FACTUAL_PASS` /
  289 `FACTUAL_HOLD`). Restore family attach rules and frozen PASSes. Do not
  generic-retrieve. Remaining changed-input runnable count is 0. Do not treat
  the delta as gold, review, training, unseen, promotion or live.
- [x] Prepare currentness-review packets for the 211 `CURRENTNESS_UNRESOLVED`
  cases (`LegalBot-GE-2026-09-03-currentness-packets-r1`). Packet preparation
  only. Do not treat packets as owner currentness approval, gold, admission,
  training, unseen, promotion or live.
- [x] Complete the continuous pre-training evaluation-packet campaign for all
  331 cases (`LegalBot-GE-2026-09-03-master-331-evaluation-review-r1`):
  bounded currentness metadata repair (210 ready / 1 incomplete-final), 56
  jurisdiction packets, 21 residual packets, case 312, 42 FACTUAL_PASS review
  packets, and one consolidated owner-review package. Packet state was
  `AWAITING_OWNER_EVALUATION_REVIEW`. Not gold, training, unseen, promotion or
  live.
- [x] Execute the standing-policy AI-assisted owner-advisory campaign
  (`LegalBot-GE-2026-09-03-ai-advisory-disposition-r2`; r1 preserved). All 331
  cases have a terminal advisory class. Human case-by-case review was not
  performed. State: `AI_ADVISORY_COMPLETE_AWAITING_QUALIFIED_LEGAL_REVIEW`.
  Not qualified legal review, gold, training, unseen, promotion or live.
- [x] Recalibrate evaluation progression without weakening gold
  (`LegalBot-GE-2026-09-03-progression-taxonomy-r1`). 289 FACTUAL_HOLD rows are
  not equivalent factual failures. Terminal dispositions classify all 331.
  State: `EVALUATION_TERMINALLY_CLASSIFIED_AWAITING_QUALIFIED_REVIEW`.
  Not qualified legal review, gold, training, unseen, promotion or live.
- [x] Prepare the 330-case qualified-review workbook and AI advisory prefill
  (`LegalBot-GE-2026-09-03-qualified-review-campaign-r1`). Three contracted
  answers that failed post-contraction claim-support were reclassified to
  working `HOLD_MATERIAL`. State: `AWAITING_QUALIFIED_REVIEWER`.
  `qualified_legal_review` remains `NOT_STARTED`. Not gold, training, unseen,
  promotion or live.
- [x] Complete the Grok independent blind AI-model review of the 330-case
  queue (`LegalBot-GE-2026-09-03-grok-independent-review-r1`).
  `reviewer_kind` is `AI_MODEL_REVIEWER`. `professional_legal_sign_off` is
  false. Dual-AI exact-hash consensus later superseded Grok r1 for sign-off.
  Not qualified legal review, gold, training, unseen, promotion or live.
- [x] Ingest ChatGPT’s independent blind review and issue Grok’s matching
  exact-hash readiness audit (`LegalBot-GE-2026-09-03-chatgpt-independent-review-r1`,
  `LegalBot-GE-2026-09-03-grok-readiness-audit-r1`). 330 `RECOMMEND_HOLD` on
  the current hashes. State:
  `ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW`.
- [x] Reconstruct the 325 diagnostic-wrapper answers and repair the five
  custom answers (`LegalBot-GE-2026-09-03-answer-reconstruction-r1`). State:
  `REVISED_ANSWERS_AWAITING_INDEPENDENT_BLIND_REVIEW`. Not qualified legal
  review, gold, training, unseen, promotion or live.
- [x] Independently review the **revised** exact answer hashes
  (`LegalBot-GE-2026-09-04-reconstructed-independent-review-r1`): 10 exact
  approvals, 11 edits, 113 holds and 196 rejects across 330 cases and 889
  claims. Re-review the 11 edited hashes once
  (`LegalBot-GE-2026-09-04-reconstructed-edit-rereview-r1`): 10 passed and
  `administrative-law:cp-d16` remained HOLD. Route only the resulting 20 exact
  hashes through the ready-only
  `LegalBot-GE-2026-09-04-qualified-review-routing-r2` pack; keep the other 310
  outside that queue. Routing r1 is internal historical evidence and is not a
  human handoff.
- [x] Supersede the 20-case human-only next route for the owner-authorized AI evaluation lane while preserving the human handoff as historical evidence.
- [x] Run `LegalBot-GE-2026-09-04-ai-auto-quality-review-r1`: review all 20 exact hashes and 38 declared material claims; accept only factual-pass answers scoring at least 70 and meeting every critical floor. Result: 13 accepted AI evaluation-gold candidates and 7 holds.
- [ ] Optional professional legal assurance: obtain signed qualified-review decisions if the owner later requires a professional-sign-off or answer-legal-gold label. AI must not fabricate that identity.
- [x] Obtain exact owner authorization for answer-weight training of the 13
  accepted hashes only, with the seven holds excluded and private unseen sealed.
- [x] Preserve the r1 Metal out-of-memory failure, apply one targeted memory repair
  and complete `LegalBot-GE-2026-09-04-answer-weight-training-r2`. Keep the base
  model unchanged and the resulting adapter inactive.
- [x] Obtain authorization and run a fresh visible successor evaluation on material
  that excludes the 13 retired training hashes. Preserve the r1 pre-model import
  failure and complete `LegalBot-GE-2026-09-04-fresh-visible-adapter-evaluation-r2`:
  base 9/23 factual and 8/23 full pass; adapter 10/23 factual and 8/23 full pass,
  with one factual regression. The all-case gate returned HOLD.
- [x] Repair only in the visible lane. Resolve unsupported additions, omitted
  controlling conditions, arithmetic/logic errors, answer truncation and the EU
  factual regression. `LegalBot-GE-2026-09-04-visible-answer-repair-r1` passed
  all 15 changed hashes and projected 23/23 with the eight unchanged passes.
- [x] Run `LegalBot-GE-2026-09-04-fresh-visible-codex-evaluation-r1` on 23 new
  questions and official locators: base 10 factual / 6 full passes; Codex route
  23/23 factual and 23/23 full 70+/floor passes, with zero recorded regressions.
  Keep the r2 adapter inactive and treat the same-provider AI review as
  non-professional evaluation evidence.
- [x] Fail-closed official knowledge-gap fill (evaluation sidecar only; not gold).
- [x] Obtain the separate unseen gate and run the protected 306-case scope once.
  `LegalBot-GE-2026-09-04-sealed-unseen-codex-evaluation-r1` returned 157 full
  passes and 149 holds. The bank is consumed and retired; its prompts and findings
  cannot be used for training, repair or rerun. The new 420+23 successor's separate
  owner authorization and Codex role separation are recorded below.
- [x] Run clean post-unseen visible evaluation without accessing the consumed bank
  or its findings. Preserve the direct 12/23 route and exposed 23/23 repair
  projection; preserve the distinct planned 20/23 route and its 22/23 bounded
  repair under the no-loop stop.
- [x] Run the final distinct source/plan-audited visible route on 23 further new
  official-source titles. `LegalBot-GE-2026-09-04-post-unseen-fresh-audited-route-r1`
  passed 23/23 factual and 23/23 70+/critical-floor gates with 108/108 declared
  claims reviewed. Same-provider AI evidence only; no qualified review or legal
  gold.
- [x] Prepare the question-free new unseen-bank design and independent custody
  proposal in `LegalBot-GE-2026-09-04-new-unseen-bank-design-r1`: 92 legal cases
  plus 23 separately scored system cases. No unseen content was created.
- [x] Record the 5 September creation-and-expansion authorization; prepare the
  420-slot/35-area coverage catalogue and 23 separate system obligations in
  `LegalBot-GE-2026-09-05-expanded-bank-creation-r1`. This historical question-free
  request and its original creation verifier remain unchanged.
- [x] Record the successor `LegalBot-GE-2026-09-05-codex-unseen-r1` authorization:
  "Create, review, then run once; no training". Separate Codex workers/reviewers
  replace external/different-provider-only roles for this pack; no Claude account
  or further execution authorization is required.
- [x] Record public `OWNER-AUTHORIZATION.json` and `CREATION-START.json` and the
  designated restricted `.private/LegalBot-GE-2026-09-05-codex-unseen-r1` root.
  The start receipt is not evidence of a complete bank. Documentation/general
  development workers must not inspect private content.
- [x] Update the maintained scope to UK and USA first: 420 legal cases across 35
  domains, 210 UK and 210 USA, plus 23 separate system cases. Preserve historical
  scope and map current `cross-border-trade-regulation` from `eu-internal-market-law`.
- [x] Record the owner's status correction: the old E&W pilot completed 12 cases;
  all are preserved/excluded before the UK/USA start, and no old worker is active.
  New authoring or bank review must not be reported as running without reports.
- [ ] Verify the new creation allocation: England 70, Wales 70, Scotland 35,
  Northern Ireland 35; USA all 50 states plus DC explicitly located, 4–5 cases
  each, with federal/state applicability per issue. Treat these as limited samples,
  not all-areas/all-states proof. Other countries are for later; explicitly route
  or defer US territories, tribal law and unsupported law.
- [ ] Complete scenario-first authoring and separate preseal factual/currentness
  and fair-oracle review of all 420+23 cases. Prohibit source-before-case questions;
  require actual synthetic fixtures with ingestion proof and fact/page provenance.
- [ ] Verify withheld future turns and oracle isolation; freeze scoring rules,
  points and critical floors before seeing candidate answers. Seal the reviewed
  bank with an encrypted copy and evidenced custody controls.
- [ ] Verify and bind exact bank/runtime hashes, including upload/OCR and retrieval
  paths, then execute once under the recorded authorization. The prior 23/23
  source-supplied visible pass does not prove this broader runtime.
- [ ] Review all material claims and omissions before 70+/critical-floor scoring;
  retain all 420 legal cases, including holds/errors, and report 23 system results
  separately. Retire the bank after the terminal run without training, repair or rerun.
- [ ] Report the scoped experimental scenario-first Codex diagnostic honestly:
  same-provider roles on the same host are not provider independence, professional
  assurance, a 100% correctness guarantee or product deployment certification.
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
