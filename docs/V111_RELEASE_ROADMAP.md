# LegalBot v1.11 delivery roadmap — three phases

Date: 1 September 2026. The owner has accepted the current system-design
amendments. The design remains editable in place; a requested design improvement
does not create another phase, archive or approval receipt.

The owner workflow is deliberately simple:

1. The owner asks for work or a change.
2. Codex investigates and prepares the improved plan or proposed result.
3. Codex asks only for decisions that require owner judgment or authority.
4. The owner approves, and Codex completes the approved work.

There are exactly three delivery phases. General Enquiries (GE) goes first in
Phase 2. Problem Based (PB) and Essay remain supported. Design acceptance alone
does not authorize sources, legal-currentness judgments, model use, evaluation,
training, unseen use, promotion or live activation.

## Phase 1 — system design

**Status: accepted and maintained as one living design.**

The current design covers:

- client, API, durable worker and WebSocket progress/replay;
- intent and response-disposition planning;
- separate legal-authority retrieval and structured matter-fact lookup;
- structural chunking, embeddings, vector storage, lexical search, hybrid fusion,
  reranking and bounded top-K evidence selection;
- conversation and message storage without treating user text as legal authority;
- evidence-bound generation, validation, deterministic citations and fallback;
- privacy, currentness, security, capacity, operations and failure handling;
- GE, PB and Essay answer modes; and
- factual-first evaluation, mode-specific quality review, improvement/training and
  protected unseen testing.

The final design-improvement audit also selects one schema version per object,
separates fact origin from certainty, binds the full request-to-release digest
chain, makes WebSocket terminal identity explicit, records complete retrieval and
per-case evaluation lineage, and requires a separate training experiment for any
future weight change.

The working design is [V111_SYSTEM_DESIGN.md](V111_SYSTEM_DESIGN.md). Supporting
contracts and schemas are in [system-design/](system-design/README.md). Future
design changes update these files directly.

The visible GE review bank retains all 331 accepted cases. The 32 synthetic system
scenarios are counted separately. The 306 private unseen drafts remain in separate
custody and do not enter visible review, calibration or training. Essay and PB
packages remain present. These question packages are drafts and review inputs,
not legal gold or training authority.

## Phase 2 — evaluation → training/improvement → unseen

**Status: active at the technical-rebuild and evaluation-preparation
prerequisites. The diagnostic 331+60 pack was returned for revision on
2 September 2026. Exact legal/model/review inputs and their applicable owner
decisions are still required before authorizing answer-model evaluation.**

The technical rebuild and verification are prerequisites inside Phase 2. They do
not create a fourth phase. The order is:

1. Verify the technical baseline, qualified sources, currentness, gold, model
   transport, resources, private review roots and exact evaluation contract.
2. Run the authorized visible GE baseline on all 331 cases. Report the 32 system
   scenarios separately and retain every failure or hold. These two accepted banks
   remain fixed throughout the GE loop.
3. Apply the hard factual/legal gate. Only factually eligible answers proceed to
   quality review.
4. Review quality using the practical plain-language GE standard. PB and Essay use
   the adapted 70+ standard when those modes are authorized.
5. Return readable answers and one final owner approval DOCX that explains the
   current model’s problems and the proposed repairs.
6. Bind every factual hold, sub-70/critical-floor result and failed system scenario
   to an evidence-backed stable diagnosis. If this exposes an unresolved in-scope
   coverage cell, add only the smallest independently reviewed visible diagnostic
   supplement. Diagnostics remain separate from the 331 and 32 denominators and
   are permanently ineligible for unseen or training.
7. Improve the responsible layer: source/currentness, retrieval, structured facts,
   prompt/code, output validation or gold. For missing knowledge, use allowlisted
   official-source quarantine/review followed by deterministic chunks and embeddings
   in a new immutable non-ACTIVE generation; never write directly to the active
   vector generation. Weight training remains a separate later gate and uses only a
   new approved corpus that excludes all evaluation, user and unseen material.
8. After targeted verification, rerun all 331 principal cases, all separate 32
   system scenarios and all accumulated diagnostics on the exact improved candidate.
   Repeat diagnosis, repair and complete rerun until the GE exit gate passes. Stop a
   path before a third attempt when the same stable fingerprint has failed twice
   despite targeted repairs.
9. Accept GE closure only when every principal answer passes the factual gate and
   the 70+ critical-floor standard, every system scenario and diagnostic passes, no
   critical/high finding, in-scope gap, unverified repair or material regression
   remains, exact run identities match and unseen custody/exposure is clean.
10. Only after owner acceptance, run the separately protected unseen scope once. Never
   tune the tested candidate using unseen prompts or findings.

The 331 questions/answers, 32 system scenarios/results, every visible diagnostic,
external gold/reviewer material, user histories/uploads and private unseen content
or findings never become training data. A change to a tested candidate or any bound
input requires a new attributable run. This is run reproducibility, not a freeze of
the system design. Technical run validity alone is not GE closure.

After the GE exit and owner acceptance, the requested GitHub update is handled by a
separate reviewed publication gate. That gate binds the exact diff, validation
evidence, retained-artifact inventory, destination and publication scope. No commit
or push is claimed or authorized merely by this roadmap update.

## Phase 3 — live, last

**Status: deferred.**

After Phase 2 acceptance, complete operational readiness, promotion, backup and
restore proof, rollback, reconnect/cancellation behaviour, monitoring, incident
handling and the final live decision. The first release remains a loopback-only,
England-and-Wales owner pilot.

The product goal is accessible lawyer-like information and triage. It must not
claim legal representation, a lawyer-client relationship, guaranteed outcomes or
complete legal coverage. Public accounts, external sharing, cloud storage, wider
languages and a real human-referral integration require explicit privacy, security
and operating decisions before implementation or activation.

## Controls retained across the three phases

| Control | Required behaviour |
| --- | --- |
| Clean room | Do not use the retired workspace or `LegalBot-New`; keep source, teaching and assessment lanes separate. |
| Evidence | No material legal claim is released without qualified, current, attributable evidence. |
| Factual gate | Unsupported or materially inaccurate answers are held before quality scoring. |
| Citations | The model does not render citations; reviewed metadata produces deterministic OSCOLA. |
| Unseen custody | Keep unseen prompts outside development, training and visible reports; disclose/run only under the approved one-pass gate. |
| Reproducibility | Bind exact sources, index, candidate, model/prompt, thresholds and evaluation data for each run. |
| Deletion | Delete only under an explicit scoped owner request; use recoverable Trash where applicable. |
| Git and release | After GE closure, prepare the exact reviewed publication package; no GitHub commit/push, promotion or live activation without its applicable exact gate. |
| Failure stop | Diagnose before rerun; stop a path after the same fingerprint fails twice despite targeted repairs. |
| Storage operations | No online blind delete or in-place `VACUUM`; require backup/restore proof and an exact approved maintenance plan. |

The [checklist](V111_REBUILD_CHECKLIST.md) records current completion and the next
authorized decision points.
