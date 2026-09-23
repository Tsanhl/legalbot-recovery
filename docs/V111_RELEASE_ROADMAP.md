# LegalBot v1.11 delivery roadmap — three phases

## Development route extension — 23 September 2026

The [shared-backend/model-route plan](system-design/GE_PRE_BROWSER_IMPROVEMENT_PLAN.md#23-september-development-chat-implementation-and-exact-remaining-gates) adds Codex, API and linked local-model routes alongside Qwen. After the owner answered “both,” a scoped owner-development admission, provider seam and website selector were implemented. The work still fits the existing three phases:

1. **System design:** provider boundaries, connection UX, schema mapping, data/tool policy and acceptance criteria.
2. **Evaluation → improvement/conditional training → unseen:** finish shared development admission, reviewed retrieval and answer/review/publication; implement adapters; prove the real website route and expected holds; qualify each advertised route; diagnose Qwen separately; preserve the exact protected one-pass gate.
3. **Live last:** complete the exact chosen route's operational, source, privacy and owner activation requirements.

The first alternate-provider milestone remains one supported answer and one expected hold through the actual API/worker/AnswerRunner and website with every shared control active. Synthetic admission/transport tests and a frontend build pass. The actual Qwen route produced a held draft and a model-call timeout, with no published answer. A narrow Codex CLI/filesystem isolation check passed; actual Codex/API inference, full isolation and provider identity remain unproved. No training run, protected dispatch or live readiness is claimed. Shared infrastructure work need not wait for Qwen training or unfinished protected-bank construction. Earlier roadmap status is historical where it conflicts with the later “both” instruction.

Updated: 5 September 2026. The owner has accepted the current system-design
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
scenarios are counted separately. The 306 private unseen drafts were later consumed
once and retired; they do not enter visible review, calibration or training. Essay and PB
packages remain present. These question packages are drafts and review inputs,
not legal gold or training authority.

## Phase 2 — evaluation → training/improvement → unseen

**Status: `CODEX_UNSEEN_UK_US_CREATION_RUNNING`.**
The current run remains `LegalBot-GE-2026-09-05-codex-unseen-r1` in preseal working
creation. The owner directs UK and USA first, other countries later; the
[scope amendment](../data/evaluations/general-enquiries/LegalBot-GE-2026-09-05-codex-unseen-r1/UK-USA-SCOPE-AMENDMENT.json) is recorded and verified.
Plan 420 legal cases across 35 domains: 210 UK (England 70, Wales 70, Scotland 35,
Northern Ireland 35) and 210 USA (all 50 states plus DC, explicit locations,
4–5 cases each, federal/state applicability per issue), plus 23 separate system
cases. These limited samples do not prove all legal areas in every state.
Explicitly route or defer US territories, tribal law and unsupported law.
Use `cross-border-trade-regulation`, retaining the historical
`eu-internal-market-law` mapping.

"Create, review, then run once; no training" remains authorized with separate Codex
author/researcher/reviewer roles and no further execution approval for this pack.
The UK/USA authoring pilot has started. Prior stopped drafts,
failed files, immutable artifacts and original verifiers remain preserved.
Question creation and verified-source/review completion are not claimed;
`bank_sealed=false`, `candidate_executed=false`, and no candidate answers exist.

Complete preseal factual/currentness and fair-oracle review, verify actual upload
ingestion, withhold future turns and freeze scoring rules before candidate answers.
Bind exact bank/runtime hashes, then run once without another authorization request.
Keep all 420 cases in the legal denominator and all 23 system results separate.
This is a scoped experimental scenario-first Codex diagnostic with same-provider
role separation, not professional assurance or product deployment certification.
The earlier 23/23 supplied-source visible pass does not prove broader runtime
capability or guarantee 100% correctness. No weight training, adapter activation,
promotion or live use is authorized. The consumed 306 bank remains excluded.
See the [governing working design](system-design/GE_EVERYDAY_UNSEEN.md).

Automatic official-source research, chunking, embedding inference and non-live DB
indexing are now authorized for actual gaps, with the [full integration plan](system-design/GE_KNOWLEDGE_GAP_AUTOMATION.md)
kept inside Phase 2. This feature is not yet connected end to end. It needs visible
validation and an exact runtime binding before an unseen run can test it. Bank
reference selections and unseen findings cannot feed shared development/training.
Indexing is non-weight improvement; the current no-training instruction persists.

The technical rebuild and verification remain inside Phase 2. The sequence below
retains the earlier visible/training/unseen history; the current 420+23 successor
above governs its own authorized work and does not reopen the frozen 331.

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
   vector generation. The owner later approved one exact-hash training exception:
   13 AI-accepted visible answers, now retired from external scoring. The local r2
   LoRA run completed with all seven holds, the other 310 rows, user material and
   the sealed private bank excluded; the adapter remains inactive.
8. Under a separate owner gate, run a fresh visible successor evaluation on the
   exact base-plus-adapter candidate, excluding the 13 training hashes. Apply the
   same factual and 70+/critical-floor gates. Internal loss improvement does not
   satisfy this step. Diagnose and repair any failure without reopening the frozen
   331 or using sealed unseen as a debugging source. The owner-authorized r2
   comparison completed with 10/23 adapter factual passes, 8/23 full passes and
   one factual regression, so it returned HOLD. The visible-only repair then
   passed all 15 changed hashes. A separate Codex-route evaluation used 23 new
   questions and new official locators and passed 23/23 factual, 23/23
   70+/critical-floor and all regression gates. It is same-provider AI evidence,
   not professional legal sign-off or independent second-model assurance.
9. Accept GE closure only when every principal answer passes the factual gate and
   the 70+ critical-floor standard, every system scenario and diagnostic passes, no
   critical/high finding, in-scope gap, unverified repair or material regression
   remains, exact run identities match and unseen custody/exposure is clean.
   The owner-authorized AI route may advance exact answers into an AI evaluation-gold candidate set. The later 13-hash training authorization is exhausted by the completed r2 experiment; neither action closes GE or creates answer legal gold.
10. The separately authorized protected unseen run completed once. It returned
   HOLD and retired the 306-case bank from fresh-unseen use. Never tune the tested
   candidate using those prompts or findings. The later 420+23 successor has its
   own creation/review/one-pass authority and Codex role separation. Clean visible
   work after that run did not access the consumed prompts or findings. Two early
   fresh routes and their bounded repairs were retained as diagnostic evidence;
   the final distinct source/plan-audited route passed 23/23 factual and 23/23
   70+/floor with 108/108 declared claims reviewed. That result permits preparation
   of a concrete new-bank design and custody proposal. Creation and execution
   authority came from the later owner decision above, not from that score.

The default training exclusion covers the 331 questions/answers, 32 system
scenarios/results, every visible diagnostic, external gold/reviewer material, user
histories/uploads and private unseen content or findings. The 4 September owner
decision supersedes that default only for the named 13 exact hashes, which are now
retired from external scoring. A change to a tested candidate or any bound input
requires a new attributable run. Technical run validity alone is not GE closure.

After the GE exit and owner acceptance, the requested GitHub update is handled by a
separate reviewed publication gate. That gate binds the exact diff, validation
evidence, retained-artifact inventory, destination and publication scope. No commit
or push is claimed or authorized merely by this roadmap update.

## Phase 3 — live, last

**Status: deferred.**

After Phase 2 acceptance, complete operational readiness, promotion, backup and
restore proof, rollback, reconnect/cancellation behaviour, monitoring, incident
handling and the final live decision. The deployment boundary remains a loopback-only
owner pilot. The current design focuses on UK and USA, with other countries later;
this scope amendment does not establish release coverage or authorize live use.

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
