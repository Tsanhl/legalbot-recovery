# LegalBot current state

**Authoritative as of:** 1 September 2026 (scope update; runtime observations below are dated 31 August)
**Product scope:** local-only, England and Wales
**Code identity:** observed HEAD `7506208cfc27237992305b4caf1d4de9b4684b05`,
tree `aa0aa137e1b7c1b40982bc7d2af5fb27e2aaf1f5`. The 31 August design/control
updates and offline question-review builder are uncommitted changes, not a new certified baseline.
Pre-loss Git history remains evidence-only. Git mutations still require exact
owner authorization.

This is the single current architecture statement. Dated reports under
`docs/reports/` are audit history and must not be treated as runtime
instructions.

## CURRENT 1 SEPTEMBER 2026 — AMENDED FULL GE REVIEW; NO DELETION

The owner requested the reviewed amendments and a complete GE pack before
returning to step-1 design review. Design revision 4 now states the fact/authority
validation, concise GE/clarification, actual same-model verification, requested-date
qualification and evaluator-only input boundaries. No runtime implementation or
policy gate was activated.

The successor [GE review pack](../data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-review-r3/README.md)
contains all 331 original case IDs, 227 amended prompts and 104 retained prompts,
case-specific proposed criteria, scenario dimensions and family links. Every case
has before/after wording and source/successor digests. A separate 32-case synthetic
system suite covers evidence gaps, scope, conversations, safety and workflow faults.
The fillable PDF has 131 pages and 726 decision/notes fields, all initially
UNREVIEWED or empty; visual QA is completed and recorded separately before delivery.

The full 306-question unseen archive remains private-r2, unchanged and separate;
its prompts were hashed without decoding. The visible-r3 work does not certify
the unseen bank's wording, semantic independence or freeze status. There are zero
approved training examples or legal gold answers in this pack. Training preparation
and a draft evaluation contract do not authorize execution.

AGENTS.md now explicitly forbids deletion without an owner request identifying
the deletion scope. It applies to all agents, datasets, predecessors, backups,
temporary files, retention jobs and cleanup tools. Exclusion from scoring never
deletes a case. The predecessor control/design files are preserved with hashes at
`docs/design-history/LegalBot-Design-2026-09-01-r3/`.

No files/questions were deleted, and no source scan/build, model, scored evaluation,
training, unseen run, Git mutation, promotion or live activation was performed.
The 31 August runtime observations below have not been re-certified by this work.

## EARLIER 1 SEPTEMBER 2026 — STEP 1 FIRST: SYSTEM DESIGN ONLY

The owner directed work to focus on system design first. The current design is
[V111_SYSTEM_DESIGN.md](V111_SYSTEM_DESIGN.md), revision 3, with a plain-language
overview, the selected components, the full architecture and explicit gaps.
Question-set review, evaluation, training, unseen testing and live work are deferred.
The previously prepared GE/PB/Essay packages and review artifacts remain unchanged.
No model, build, evaluation or live job was started for this scope update.

Predecessor design/control files are preserved with hashes under
`docs/design-history/LegalBot-Design-2026-08-31-r2/`. Earlier QA receipts describe
their exact dated revisions, not an acceptance of the current design.

## EARLIER 31 AUGUST 2026 — THREE PHASES; GE FIRST; FULL SET PREPARED

The latest owner direction is exactly three delivery phases:

1. System design.
2. Evaluation -> training/improvement -> unseen testing, with General Enquiries
   first and PB/Essay following through the same process.
3. Live, last.

The full design was expanded using the ten-page support-agent reference as
reference material, not instructions or legal authority. It now explicitly covers
knowledge-only/matter-only/hybrid intent, a proposed scoped matter-facts adapter,
hybrid ranking/reranking/top-K, structural chunking and embeddings, message and
conversation storage, WebSocket replay, four defence layers, human referral and
missing controls. The semantic relevance threshold remains unset; calibration is
an explicit prerequisite, not a fabricated passing value.

The review delivery at
`data/evaluations/general-enquiries/LegalBot-GE-2026-08-31-review-r2/`
contains all 306 current visible GE core questions and 25 stress questions with
unchanged wording, IDs and structured records, plus 331 initially UNREVIEWED owner
decision slots. The full PDF is
`output/pdf/LegalBot-GE-2026-08-31-review-r2.pdf`. The complete 306-question unseen
ZIP remains in its existing private custody location; the review package provides
a separate metadata/identity summary and link, without parsing or projecting any
unseen prompt into the visible materials. These are question-draft review artifacts,
not Development answer projections, gold, training data or scored results.

The delivered review revision is r2: all 53 PDF pages were rendered and visually
checked, and all 331 IDs and complete prompt texts were verified. Revision r1 is
preserved as a superseded layout preview; r2 fixes a wrapped table heading without
changing any question. The separate
[verification receipt](status/LegalBot-GE-2026-08-31-review-qa-r2/VERIFICATION.json)
binds the delivered files and source checks. The clean-room and review-builder
style checks pass; this is not a full runtime or promotion test result.

The earlier design/roadmap/checklist are preserved with hashes in
`docs/design-history/LegalBot-Design-2026-08-31-r1/`. The current roadmap has only
three delivery phases. Legacy gate IDs and existing certification contracts remain
compatibility controls within this organisation; no signature, model run, split,
promotion, O-04 disclosure or live permission is created by renaming phases.
The technical rebuild is a phase-2 prerequisite before model evaluation.

No source scan, catalogue repair, index execution, answer model, training, unseen
test, Git mutation or live activation ran while preparing this design/review pack.
The runtime blockers and historical observations below remain unchanged. Where
earlier text calls the technical baseline “Phase 1”, that is the legacy gate name,
not a fourth delivery phase under the owner's latest plan.

## EARLIER 31 AUGUST 2026 OBSERVATION — RECOVERED FOUNDATION

The owner chose to retain the recovered foundation and design the complete system
before rebuilding missing components and preparing evaluation. The implementation
design is `docs/V111_SYSTEM_DESIGN.md`; the work sequence is
`docs/V111_REBUILD_CHECKLIST.md`. Neither is a release decision or a claim that
the rebuilt system has passed.

Current read-only observations supersede the missing-Git/model/scan statements in
the dated sections below:

- Git metadata is present at the code identity above. No Git mutation was performed
  during this design work.
- Both Qwen3 retrieval-model stores match their pinned recursive file manifests.
- The latest completed source scan, `6c01a8c611b28cde`, accounts for 3,774/3,774
  files. This is scan accounting, not proposition-level legal qualification.
- Recovery build `current-law-ew-full-fp16-v111-20260829-recovery-a` failed with
  `canonical_markdown_missing`; recovery-b failed with `lease_lost`. A later
  canonical-recovery code repair exists, but its presence does not prove artifact
  closure or a successful build. Diagnose and verify before another attempt.
- No runnable candidate or `ACTIVE.json`/`PREVIOUS.json` is present. Historical
  candidate catalogue rows are not proof of surviving Lance bytes.
- The pinned answer runtime and archived Base directories are absent. Recovering
  the archival Base model is not a prerequisite merely to rebuild retrieval.
- The recovery-baseline input receipt, a fresh passing 24-case attestation and a
  fresh sealed 18-check Integration result remain outstanding.

All five recovered question packages match their receipt pins, all 372 listed
file checksums pass, and both current r2 ZIP hashes match. The proposed selected
visible view contains 102 Essay core questions, 102 Problem Based core plus 17
stress questions, and 306 General Enquiry core plus 25 stress questions. This is
552 visible drafts, including Administrative Law and Wills/Estates, which remain
blocked pending official-source admission and review. Current General r2
supersedes 119 earlier academic General core/stress questions for future use;
those predecessor bytes remain unchanged. No merged execution bank was created.

Private custody was checked by hashes and metadata only; no unseen question text
was parsed or projected. The three-mode plan records 102 Essay, 102 PB and 306
General private drafts; these counts do not constitute an owner freeze or a
disclosure permission. The topic banks remain distinct from Owner Certification
60 and its controlled Development-30/Sealed-Validation-30 split.

The 340 gold-answer slots and 1,678 proposition slots are pre-gold preparation,
not completed answers or a training dataset. Their earlier bank bindings must
not be silently reused for replacement General r2 questions. Evaluation and
validation material remains excluded from training exports; a future training
experiment requires its own dataset, rights/privacy review and exact owner gate.

The dated, non-authorizing inspection receipt is
`docs/status/LegalBot-Rebuild-2026-08-31/INSPECTION.json`. This work produced
design/control documentation and custody checks only: no source scan, index
execution, answer-model run, training, split, owner signature, promotion or live
activation. Existing question packages and release pointers were not changed.

Next: bounded canonical/lease diagnosis, one verified non-ACTIVE generation,
retrieval attestation and a new Integration baseline. Later Phase-2A/2B execution
still requires the applicable current owner decisions. Missing historical
artifacts remain gaps rather than being fabricated as passing evidence.

The sections below are preserved dated observations and audit narrative. Where
they conflict with this section, this 31 August section controls.

## CURRENT 29 AUGUST 2026 — RECOVERED WORKSPACE; PHASE 1 REBASELINE REQUIRED

The only writable workspace is the repository root named
`LegalBot-v111-Recovery-20260829`. The latest provable working tree was
recovered with its catalogue and 316 exact source files. It
has no `ACTIVE.json`, `PREVIOUS.json` or runnable Lance candidate. Historical
Git refs are preserved only in `recovery/2026-08-29/` and the owner will create
the new Git repository separately.

Phase 1 was historically declared complete at the r8 Integration Baseline, but
that result cannot be represented as a current recovery pass. The old Lance
trees and a surviving r7 attestation result are unavailable. The recovery must
therefore establish a new clean Git HEAD, source-root/scan identity, pinned
retrieval-model stores, one non-ACTIVE candidate, a passing frozen 24-case
attestation and a fresh 18-check Integration verification report. Exact work is
listed in `docs/status/V111_PHASE1_RECOVERY_READINESS_20260829.md`.

The seven missing seminar configs, eight later Phase-2A source representations
and 420 unavailable Phase-2A evidence roots are explicitly recovery gaps, but
they are not Phase-1 blockers. Phase 2A and every later execution remain paused
until the new Phase-1 baseline is sealed. No pre-loss Phase-2 owner packet is
current authority for executing against this rebuilt workspace.

The 28 August section below is preserved as pre-loss audit narrative. It may
reference artifacts that did not survive recovery and must not be treated as a
current executable gate.

## CURRENT 28 AUGUST 2026 — PHASE 2A PREQUALIFICATION HOLD

The owner adopted the exact final remediation packet content SHA-256
`fd8034b33ebfb0f6fdd6cedd2426b54e368bff9c20b408f3fbd86fb40b9f1b34`
on 28 August 2026. The owner-adoption receipt content SHA-256 is
`9b47af237fe4a811b51a4c21f02db1702b71505128576fa54cbd4794e1e739fa`.
It preserves one bounded Phase-2A execution chain for exact source
materialization, one complete scan, one non-ACTIVE successor build/embedding,
one retrieval re-attestation and one All-585 technical qualification. It does
not authorize an answer/model run, Phase 2B, Development 30, Validation 30,
Owner Certification 60, promotion, `ACTIVE`/`PREVIOUS`, live or export.

The exact materialization plan is ready but was not executed. Its content
SHA-256 is
`de7b8e8c0d5d4a6e1f99f0f338d623bb7e371222b8c0341b35515fe1d1567c7b`:
254 representations, comprising 250 index-eligible representations and four
raw provenance companions excluded from candidate retrieval. If later
unblocked, the proposed successor scope is the exact prior 251 sources plus
250 newly admitted representations, for 501 sources. No source file or
catalogue row has been materialized or mutated by this plan.

A mandatory read-only prequalification was run before consuming the chain.
The corrected immutable report is
`data/evaluations/phase2a-owner-review/LegalBot-Phase2A-2026-08-28-prequalification-blockers-r3/PREQUALIFICATION-BLOCKER-REPORT.json`,
content SHA-256
`5efc17b16adcae1ceb2ea1bbd7efcaba469ab0340c24b65c1e994132cb337980`.
After applying the final packet's exact eight substantive supersessions and
two safe-fallback rows, 146 rows still contain 193 structured support blockers:
116 `PARTIAL` and 77 `NONE`. These are not inferred from release-only hold
text; they are exact `support_fit` values retained by the adopted packet.
Source presence or embedding cannot truthfully upgrade them to `FULL`.

Phase 2A is therefore **blocked before materialization, scan, build and
qualification**. The execution chain remains `AVAILABLE_UNSPENT` (one
remaining, zero consumed). There is no `ACTIVE.json` or `PREVIOUS.json`, and no
Phase-2A scan, successor build, embedding, retrieval re-attestation, All-585,
answer/model or Phase-2B execution has run under this approval. A new exact
owner-approved remediation must resolve or expressly supersede the 146 rows
before the one-chain execution can safely start.

The sealed human semantic-routing advisory is
`data/evaluations/phase2a-owner-review/LegalBot-Phase2A-2026-08-28-blocker-semantic-advisory-r1/BLOCKER-SEMANTIC-ROUTING-ADVISORY-146.json`,
content SHA-256
`8b1425d10eb6f2d71dff169f52e5dbd8f1871aca14139f4316586fd6e7d9a9f5`.
It found zero strict matter-information-only fallback candidates: eight rows
are legal/policy-evidence-only, 99 combine legal evidence with missing matter
information, and 39 combine legal evidence with analytical, policy or
hypothetical inputs. A human intake response may address missing facts, but it
cannot erase a retained legal-support blocker.

The exact source-topology audit partitions the 146 rows into 59 whose sources
and locators are ready but whose propositions still require narrowing or
exclusion, eight with source-present legal-review or identity holds, 20 with
missing source identities, and 59 with authority-less `NONE` components. The
create-only successor-remediation scaffold is
`data/evaluations/phase2a-owner-review/LegalBot-Phase2A-2026-08-28-146-row-superseding-remediation-advisory-r2/EXACT-146-ROW-SUPERSEDING-REMEDIATION-ADVISORY.json`,
content SHA-256
`6078e556e8ee3eb551bd48d310b2a89728e317dc8c240f22030799b54e595e1d`.
It is not approval-ready: all 146 rows remain `RETAIN_BLOCKER`, zero additional
fallbacks are proposed, and it consumes no execution authority.

Phase-2B question-bank preparation is now complete as a non-authorizing draft
package at
`data/evaluations/phase2b-question-drafts/LegalBot-Phase2B-2026-08-28-full-question-bank-draft-r3`.
It contains 270 amended Development/remediation core questions, 30 visible
stress questions and 270 unseen-custody drafts: 15 independent topics with 18
core, two stress and 18 unseen questions per topic. All 44 audit amendments
(32 MUST and 12 SHOULD) were applied fail-closed. The unseen drafts have no
Markdown projection, are stored in private-mode JSONL files, have zero exact
prompt overlap with the 300 visible questions and remain **not owner-frozen**.
This preparation did not create gold answers, admit sources, run retrieval or a
model, train a model, build an index, start Phase 2B, authorize Phase 2C or
change any release pointer. Future execution is limited to at most two topics
per administrative wave, with independent evidence/delta/result decisions and
a separate owner freeze plus one-pass disclosure gate for unseen validation.

A separate non-executing preparation package now exists at
`data/evaluations/phase2b-question-drafts/LegalBot-Phase2B-2026-08-28-expansion-and-pre-gold-r1`.
It proposes exact official-source scopes for Administrative Law and
Wills/Estates (22 official legislation, procedure and judgment endpoints), and
adds 40 visible question drafts plus 36 unseen custody drafts. If those two
topics are later owner-approved, substantively verified and admitted, the
future combined bank would contain 17 topics, 340 visible Development/stress
questions and 306 unseen custody drafts. Combined leakage checks have zero
exact prompt overlap and maximum TF-IDF similarity `0.34985735` against an
exclusive `0.55` threshold.

The same preparation package creates 340 gold-answer work slots and 1,678
issue-bound proposition/evidence work slots across the 15 existing and two
proposed topics. These are intentionally **pre-gold**: proposition text,
official-source version identity, EvidenceSpan bindings, deterministic OSCOLA
records, legal-reviewer decisions and completed gold answers all remain empty.
No source bytes were downloaded or admitted. The separately running Phase-2A
task was not read, invoked or consumed. Completing these slots remains blocked
until a successful Phase-2A digest is delivered and separately owner-adopted,
followed by the exact Phase-2B topic/resource, source-scope and private-root
owner gates.

The original combined common-public r1 package is superseded for future use by
two physically separate r2 packages. The owner-reviewable package is
`data/evaluations/phase2b-question-drafts/LegalBot-Phase2B-2026-08-28-common-public-visible-development-r2`,
content SHA-256
`d03fe95ee1ad72444580d7ca492f7fc947db4604d23214da8a086e3dbbecb359`.
It contains 306 corrected visible core questions and 25 visible stress tests
across all 17 prepared topics. All 34 mandatory and ten recommended audit
amendments were applied, together with six additional contamination-only
rewrites. Every record now has first-class jurisdiction, date/currentness,
clarification, limitation, safety/refusal, evidence-preservation and urgent
handoff controls. The old universal clarification requirement is removed:
safe general guidance may be given with explicit assumptions while genuinely
outcome-changing jurisdiction or fact gaps remain blocking.

The separate private custody package is
`data/evaluations/phase2b-question-drafts/LegalBot-Phase2B-2026-08-28-common-public-private-unseen-r2`,
content SHA-256
`a73ef297738cf0745d1233e8d2c4748412d534bff41afadd1086e6e349f68a91`.
It contains 306 custody-draft questions in private-mode JSONL files, with no
Markdown projection, and is absent from the visible package. It is not
owner-frozen and cannot be disclosed to Development or used for scored
validation. The visible r2 bank has zero exact overlap against the prior 340
visible questions and maximum TF-IDF similarity `0.49984931`; private r2 has
zero exact overlap against all 671 visible questions and maximum similarity
`0.37406274`, both below the exclusive `0.55` threshold.

Future Phase-2B testing is organised into three independent question types:
General Enquiry, Essay and Problem Based. The corrected common-public r2 bank
supersedes the earlier general-enquiry prompts for future independent testing;
Essay and Problem-Based drafts remain sourced from the full r3 and expansion
packages. Administrative Law and Wills/Estates remain draft-only and are
ineligible for final gold answers or scored evaluation until official sources
are admitted, versioned, proposition-checked and independently reviewed. None
of these packages contains answers, gold propositions or EvidenceSpans. They
did not read or consume the separately running Phase-2A chain and did not admit
sources, scan, build or embed an index, run retrieval or a model, start Phase
2B, promote, write `ACTIVE`/`PREVIOUS` or activate live.

Live-preparation infrastructure is non-authorizing: encrypted bounded
conversation storage and replayable browser WebSockets are implemented;
model-backed standalone-query rewriting is encrypted/checkpointed but disabled;
and generated gRPC stubs plus a real UDS server/client pass deadline,
cancellation, backpressure, health and crash tests. Production gRPC/query
rewrite activation still requires the exact Phase-2B model-transport owner
gate. Storage capacity/backup-retention alerts and an offline catalogue
maintenance policy are present; neither automatically deletes or compacts
data.

The 28 August catalogue backup/restore drill passed with backup SHA-256
`7a16fc3d4b5aeedffdbf0bb36ef2ec1d12594ad84df3e863500e7f2e6cacf492`,
`integrity_check=ok`, zero foreign-key violations and matching source/backup/
restore logical-state digest
`319b69f218ce82c615c8268fc99a73a2e7bb7dafa0e1c91b9c3b79a808f9108a`.
The restore copy was temporary and the verified backup remains private mode
0600. The resulting retention run re-hashed every stored backup, kept the
current backup and r8 predecessor, and moved six older copies (37,224,525,824
bytes) to recoverable macOS Trash with sealed plan/result evidence. No
permanent deletion occurred. `data/` is now approximately 32GB, including
approximately 13GB of retained backups. The observe-only maintenance preflight
has every safety precondition except the configured Sunday 02:00–06:00 Hong
Kong window; it ran no chunk classification, delete, `VACUUM` or swap.

The sections below preserve the 17 August baseline and later audit trail. Where
a historical count or gate conflicts with this section, this 28 August section
controls.

## HISTORICAL V1

V1 treated overlay completeness as 305/305 selected issues with positive
exact spans, and treated the owner reviewer identity as sufficient to make
those spans gold. That rule is retained only as an audit path
(`v1_requires_305_positive_spans`). It is not the current evaluation
architecture.

The 16–17 August 2026 Path-B import bound 77 selected issues to catalogue
exact spans (200 spans) and left 508 issues as knowledge gaps. Of the frozen
305 selected issues that is 77 qualified / 0 limited / 228 knowledge_gap.
Those 77 mappings are preserved as mechanical exact-reuse. They are **not**
automatically V2 `VERIFIED` gold. Stale `0/585` tick files remain audit
history and cannot override `data/evaluations/live60/CURRENT.json`.

## CURRENT V2

Frozen identities remain exact: **30 selected cases** and **305 selected
issues**. Every selected issue needs a `VERIFIED` disposition of
`qualified`, `limited`, or `knowledge_gap`. Review complete means
`unreviewed_issue_count == 0` plus overlay/gap/semantic seals. Evaluation
complete means a real candidate-pinned run produced terminal jobs and
release-gate artifacts. Production ready requires a
`legalbot.production-promotion-attestation.v2`. Production active is only
written by the operator `legalbot promote` control plane.

Gold is a proof bundle that passes verification policy, not human identity
and not an AI confidence score. Knowledge gaps may not keep a positive
span. Evaluation-only authorization pins a `candidate_build_id` and must
not write ACTIVE or issue production O-04.

Mutable counts are derived from `data/evaluations/live60/CURRENT.json` and
its hashed issue-state artifact. They are not Python constants.

## Release state

LegalBot is **not live-ready and has no ACTIVE index**. Source scan
`a6200da832c587e7` is complete and reconciled (3581/3581, three roots). 75
files are quarantined (65 processing-policy rollback refused, 9 parse
failures, 1 symlink not followed). Those files are accounted and must not
be approved, indexed, or treated as gold. Diagnostic slice
`current-law-ew-core-fp16-v111-20260817` reached `built_unscored` (37 sources /
7887 chunks) bound to that scan. It is not promotable and is not
`CURRENT.candidate_build_id`. The sealed source-version owner pack
`f39ac0ab4b3efdd6ba276a868186cda7bc91f67804f08d92ae4961f8c9de8e37` was
operator-confirmed: every decision is **HOLD** (56 grouped sources, 75
selected rows). That confirmation does not approve catalogue source
versions, index them, or mint issue gold. Selected-issue V2 state remains
62 qualified / 0 limited / 150 knowledge_gap / 93 HOLD (18 substantive
semantic HOLDs and 75 owner-held source versions). Overlay completeness,
Stage A, Live60 30, production attestation and ACTIVE remain blocked.

The implemented code now contains the manifest-driven Live60 evaluation engine,
fail-closed HTTP execution adapter, generic Live30/Live60 owner views, durable
research/refinement state, encrypted upload lifecycle, build-keyed safe
retrieval cache and owner-safe event/metric/trace projections. Those are
capabilities, not evidence that the system has passed its release gates. The
accepted Go/No-Go memo remains the controlling **NO-GO** baseline.

On 16 August 2026 branch `live60-go-execution-2026-08-16` reconciled the frozen
Live60 identity and regenerated the issue-decision pack from
`expected_research_route` (33 sectioned / 27 full_enquiry; selected 15/15).
Route integrity is asserted live against the registry with zero mismatches;
the earlier coerced-route list is not kept as a frozen defect. The Desktop Law
folder was compared to `data/catalog.sqlite3`. Official legislation.gov.uk XML
was fetched for the four held provisions. Spliced s 14A(10) and IPFDA s 1
parent chunks were excluded from the body stream and replaced with contiguous
chunks; parent bytes were not deleted. The earlier owner-delegated snapshot of
263 qualified / 180 limited / 142 knowledge_gap was not issue-specific legal
gold and is retained only as audit history. The authoritative state at
`9aede84` is 0 qualified / 0 limited / 585 knowledge_gap with zero bound spans.
Path B is selected for a full 30-answer target. **V1 HISTORICAL RULE:** all 305
issues on the selected 30 cases needed owner-reviewed positive exact spans.
**CURRENT V2:** those 305 frozen issues need VERIFIED dispositions
(qualified / limited / knowledge_gap). The 280 coverage-only issues
may remain explicit knowledge gaps. The authority and supersession mapping is
recorded in `Live60-2026-08-16/artifacts/artifact-authority-map.json`.
Owner-authorised official acquisition on 16 August 2026 re-fetched truncated
legislation.gov.uk XML, ingested remaining staged Acts including full UK GDPR
and Rome I/II XML, and indexed 25 last-resort public judgment representations.
Seven historical cases still have no public HTML (Turnbull, Cooley, Banks,
Bolam, Collen, Haseldine, Lee-Parker). Official OSCOLA 5 PDFs were stored in
the assessment-guidance lane and do not overwrite the OSCOLA 5 renderer.
Twenty-two candidate assessment rules remain owner-review items; the live
bundle is still the immutable 16-rule `owner-standards-2026-08-14.1` set.
That does not seal an overlay, promote ACTIVE, pass Stage A, or issue O-04.
The two run-plan SHA values in earlier review documents are the file digest
and the object seal of the same `generation-run-plan.json`. See
`Live60-2026-08-16/go-execution/superseding-run-identity.json`.

On 17 August 2026 the owner-adopted Path-B substantive-review JSON was
imported against a sealed 585-row export. Catalogue exact-match bound 12 of
305 selected issues (14 spans). Official-source remaining-issue binds on the
same day fetched legislation.gov.uk and Find Case Law bytes and imported only
where SHA-256 matched an approved current catalogue chunk: first 47 further
issues, then 18 more after multi-section URL splits and regulation / article /
CPR rule extraction. Authoritative issue state is therefore 77 qualified / 0
limited / 508 knowledge_gap. Of the 305 selected issues, 228 remain
knowledge_gap. The imported reviewed-row SHA-256 is
`e06d7f1179d58824c16ce2e45cbf46dcdce64365d69652729255738b9ddb1d2d`.
The 280 coverage-only issues remain explicit knowledge gaps.
No selected case is fully qualified, so the v1 overlay cannot seal. D1–D15 and
contrary review remain unsigned because `CONFIRM_OWNER_AUTHORED_SEAL` is not
owner-supplied. This does not write ACTIVE, O-04, or a Stage A pass. The
incomplete Path-B overlay does not place ordinary LIVE serving on HOLD.
Ordinary queries still fail closed per proposition when evidence is not
individually runtime-eligible. Overlay seal, new overlay promotion, ACTIVE
replacement, and O-04 stay blocked until the owner promotes. V2 overlay
completeness is 305 verified dispositions (qualified, limited, or explicit
knowledge_gap), not 305 positive spans. Evaluation-only authorization may pin
a `candidate_build_id` without ACTIVE or O-04. Production remains
`NOT_ELIGIBLE` until `legalbot promote`.

The last complete source scan is `93cad83adf836e17`: all 3,419 filesystem items
were accounted for and the manifest SHA-256 is
`e484bf73a9c3ac503b173db7294d23f69fff0d1098bbe2de7cec95e2dccf09b3`.
For current source versions, 617 are approved and 2,605 are rejected. Approval
does not by itself prove present-law coverage, provision-level currentness, or
answer quality.

The configured consolidated-legislation snapshot is dated 14 August 2026.
Exactly 65 approved run-date snapshots are active and all 65 predecessor
snapshots are explicitly superseded. Fourteen provision qualifications were
inherited only where the official bytes and version metadata were identical.
Four changed provisions had structural body-span defects that are now excluded
from retrieval: Limitation Act 1980 section 14A(10) spliced parent, and
Inheritance (Provision for Family and Dependants) Act 1975 section 1 spliced
opening, editorial-ellipsis mix, and dots-only omitted marker. Contiguous
replacement chunks were inserted. Limitation Act 1980 section 2 and Trustee
Act 2000 section 1 locators were rewritten to exact sublocators. Mechanical
verification still does not treat official XML serialisation as exact-match
gold. Forty-eight instruments report one or more unapplied effects, so no
document-level approval substitutes for an issue-specific extent,
commencement and effects check.

The active provision-verification registry and its predecessor, download and
exception reports are stored as one tracked, digest-checked archive chain. A
fresh checkout therefore does not depend on ignored review-queue files to
reproduce a qualification decision.

## Authority and evidence truth

- Physical authority, teaching and assessment lanes are separate. Teaching,
  feedback and student work cannot independently support a material legal
  claim.
- Current legislation is described as a `latest_available_revised_snapshot`,
  not a guaranteed point-in-time consolidation. Material unapplied effects or
  unverified England-and-Wales extent require provision review or a limited
  answer.
- All 78 approved case source versions are present-law held. Twenty-two
  rights-reviewed official judgments remain retrievable for identity and
  historical text; 56 records without verified computational-use rights are
  metadata-only and model/runtime blocked. Source-level case approval still
  does not qualify present-law propositions. Two UNISON issue spans now have
  owner `confirmed_current` later-treatment reviews; Triple Point stayed a
  knowledge gap because `qualified_current` requires bound limiting-authority
  IDs.
- A source-level `currentness_verified=true` flag cannot establish that every
  proposition in a historical judgment remains good law. Release requires an
  expert later-treatment review tied to the exact evidence-span content hash
  and proposition hash.
- The Quistclose repair pack adds seven official OPL/OGL representations for
  *Twinsectra*, *Menelaou* and *Bailey v Angove's*. Exact reviewed paragraphs
  carry conservative `holding_ratio` or `obiter` roles; parser/raw material is
  excluded from body retrieval. The Quistclose knowledge gap remains open
  until exact proposition-level later treatment is reviewed and a new
  candidate passes regression checks.
- Find Case Law and Westlaw trustworthiness do not by themselves grant
  computational full-text rights. Rights-unverified full text remains outside
  runtime retrieval.
- The first live candidate is authority-lane only. The 163 scholarship sources
  (including 100 owner-supplied Westlaw copies) and 273 private-teaching
  sources are not selected. Any future expansion into those lanes requires a
  separate computational-use rights decision; the current privacy pass is not
  a general licence opinion.

## Assessment guidance

The active assessment bundle is an immutable set of 16 drafting and repair
rules covering 70+ targets and 60–69/50–59 anti-pattern repairs: 14 are
owner-authored policy and two are exact marker mappings approved by the owner.
Its version is `owner-standards-2026-08-14.1`, its SHA-256 is
`9d5808d9275e8a91d18c9702d76ff8e5e6fbbf1388aa57e43ac4b788e96d8252`,
and it is bound to the privacy-safe decision-manifest SHA-256
`be5916d6e3e40febb3819d1529df6f6ab4055de98baf275f8361b0fc31dda9a2`.
That bundle SHA is recorded with every build, answer checkpoint and evaluation
outcome. Rules are selected atomically: no prompt may contain a truncated rule
fragment.

The earlier feedback-derived catalogue has been re-audited. The four remaining
decisions are resolved: case synthesis and timely authority support are approved
as exact marker mappings; the criminal-element/defence and question-engagement
mappings are rejected and superseded by separately owner-authored replacements
with no marker-source attribution. There are now 6,489 rejected mappings, two
approved exact marker mappings, two approved owner replacements and no staged
rules. Partial, vague, personal, student-specific, mixed-polarity,
score-fragment and substantive-law mappings remain rejected.

Automated academic scoring is advisory. Evidence, citation, jurisdiction,
currentness and privacy remain hard gates. The UI and release text must not
claim that 70+ performance is calibrated until an independent blind legal
review validates it.

## Live evaluation contracts

### Historical Live30 record

The supplied questions are registered exactly as
`live-evaluation-30-v1` (canonical SHA-256
`65709b6bda056879c591780e5e8aec5e95e72a26dec7854369e7e4175a64b3c3`):

- 30 development-live cases and 115,000 requested words;
- 16 sectioned and 14 full-enquiry routes;
- one pass over all evidence-qualified cases;
- two additional passes over Q1, Q3, Q7, Q9, Q13, Q17, Q25, Q27 and Q30;
- 48 immutable terminal outcomes in total;
- evaluation-only, with training and training export disabled.

This package and its historical 48-outcome strategy remain readable and
unchanged. Live60 supersedes only the old run strategy; it does not rewrite the
Live30 registry, record hashes or reports. No Live30 generation run was executed.

The historical Stage A contract measures route/subject handling, Recall@5/10, MRR, graded nDCG@10,
exact-span recall, contrary-authority recall, filter correctness and per-issue
evidence coverage. Ranking scores are emitted only against sealed expert gold.
Stage B submits only evidence-qualified cases. Unsupported cases receive a
deterministic no-model held outcome plus an issue and knowledge-gap record, so
one weak subject does not abort every qualified case. Stage C reports average
and worst-run stability.

### Current Live60 contract

`live-evaluation-60-v1` is the current controlled development-live contract:

- 60 exact questions, 215,000 aggregate requested words, 39 problems and 21 essays;
- the owner is the one primary qualified England-and-Wales reviewer for **v1**
  identity-as-truth overlays (a second independent human review remains
  optional; v1 AI checks mechanical accuracy only and cannot be a reviewer).
  **v2** gold is a proof bundle: exact mechanical match plus an independent
  semantic verifier invocation. Identity and `ai_confidence` are not gold;
- exactly 30 unique selected cases, 114,000 requested words, one pass and no
  stability repeats;
- 15 sectioned and 15 full-enquiry selected routes;
- every nonselected case is explicitly `coverage_only_not_selected`;
- the Europe/London admission date is sealed independently from the registry;
- evaluation and export are ineligible for training or training export; and
- the first controlled run prohibits online research.

Three state machines stay distinct. Ordinary runtime is `NOT_SERVING` /
`LIVE` / `DEGRADED`. Evaluation candidates move `BUILDING` → `EVIDENCE_REVIEW`
→ `REVIEW_COMPLETE` → `STAGE_A_READY` → `EVALUATION_READY` → `EVALUATING` →
`EVALUATED` / `FAILED`. Production promotion is `NOT_ELIGIBLE` / `ELIGIBLE` /
`AWAITING_OPERATOR` / `PROMOTED` / `ROLLED_BACK`. Evaluation must not require
`owner_promoted_active`, ACTIVE, rollback drills, browser recovery, readiness
green, or O-04. Production still does.

Stale `owner-tick-progress.json` 0/585 snapshots are audit history. Mutable
counts come from `data/evaluations/live60/CURRENT.json` and the hashed
`issue-state.json` artifact (v1 mechanical 77 qualified / 0 limited / 508
knowledge_gap; selected 77 / 0 / 228).
`CurrentLiveStateResolver` ignores the stale 0/585 file. V1→V2 migration
reuses the 77 hash-matched issues as `mechanical_exact_reused` with
`semantic_reverify_required`. A reason string alone is not a VERIFIED
knowledge gap. Catalogue absence is not by itself a knowledge gap.

The first 30 case IDs, exact question bytes and hashes retain their Live30
lineage. Q31-Q60 are separately hash-bound. The suite manifest, registry,
lineage, run plan, candidate/currentness overlay and output manifests are
independently sealed; the existence of one cannot substitute for another.

The generic admin API selects `Live30AdminReader` or `LiveSuiteAdminReader` from
the immutable run-manifest schema. It lists safe run/case state for both formats
and decrypts only a released answer after rechecking its hard gates and artifact
digest. It never exposes encrypted questions or held/private drafts.

Execution remains blocked for **production** because there is no ACTIVE build,
no rollback/re-promotion report, no real browser recovery report, no green
readiness v6 report and no Live60 O-04 authorization. V1 overlay sealing still
requires 305/305 selected positive exact spans. V2 overlay completeness is
305 verified dispositions; 78 official candidates still HOLD pending
materialisation, so v2 review is not complete. Evaluation-only authorization
v2 may bind a candidate build without ACTIVE. The code must not fabricate
ACTIVE, O-04, or a Stage A pass. Suite `verify`/`summary` and the Python
Live60 tests may run now.

Retrieval v1.1 remains immutable and owner-frozen. Candidate evaluation now
resolves each frozen legislation authority, legal locator and span hash to the
qualified run-date source version and records the safe binding in the sealed
attestation; it does not rewrite the benchmark. A prospective 14 August audit
binds 20 of 24 rows. The other four are exactly the changed provisions already
held above, so their frozen spans cannot pass until fresh review qualifies the
current bytes.

## Research, refinements, uploads and retrieval cache

The official-law updater is a separate durable control plane. `ResearchTask`,
candidate, source-update observation, schedule and append-only event state live
in SQLite, and a separately leased `ResearchWorker` never passes work to
`AnswerRunner`. Admission enforces high/medium/low priorities of 90/60/20, five
aging points per 24 hours capped at 95, FIFO within equal effective priority, a
20-task active-capacity limit, a 20-candidate limit, two global fetches and one
fetch per origin. Capacity overflow is retained as `deferred_capacity`.

Network planning accepts only reviewed official-source adapters, fixed public
subject taxonomy, public citations or stable authority identities. It rejects
arbitrary URLs, raw user questions, subscription crawling and private-network
destinations. Find Case Law remains metadata-only. Results are encrypted or
quarantined for review and record `unchanged`, `changed`, `new`, `withdrawn` or
`unknown` against a pinned ACTIVE identity; `changed` means bytes/metadata
differ, not that legal effect has been determined. The worker cannot approve,
supersede, delete, index, promote or repair an answer automatically.

The 02:00 HKT daily known-source check and Sunday 03:00 HKT broader discovery
schedules exist but are installed disabled. Operator CLI now admits jobs onto
that SQLite queue (`legalbot research-enqueue`, `research-queue`,
`research-worker --once`). Enqueue is local and does not require the network
flag. The worker still requires `LEGALBOT_OFFICIAL_RESEARCH_ENABLED=true` and
refuses the first-live profile. `scripts/start.sh` does not start it, and no
connected task has been run. Enabling it remains conditional on a passing
local E2E run and a separate connected canary.

The former plaintext official-source gap queue has a locked one-time migration
path into safe SQLite state with sensitive notes encrypted separately; new work
does not write that JSON queue. The owner sees one append-only inbox with
`debug`, `missing` and `answer_feedback` categories. Answer feedback is
ownership-checked and any note is encrypted. Triage may link a root cause,
repair version and regression, but it cannot mutate sources, prompts, model
weights or ACTIVE.

Uploads are encrypted at rest, content-hash and MIME/resource checked,
request-scoped and non-authoritative. Their default retention is 30 days after
the associated job becomes terminal; owner-pinned source review extends the
review lifecycle without making the bytes legal authority. The source-review
endpoint creates a quarantined intake decision only.

The retrieval cache is a disposable optimization keyed by query digest, ACTIVE
build/source manifest, jurisdiction, legal date, subject/task/lanes/filters and
retrieval-model/policy versions. It stores only source-version/chunk IDs, ranks
and scores, hydrates from the exact immutable ACTIVE build, bypasses uploads and
online results and invalidates old build namespaces on promotion or rollback.
Subject-readiness views are build-keyed diagnostics over the one authority
store; counts never establish that a proposition is supported.

## Runtime and observability

The first-live topology is three loopback processes managed by
`scripts/start.sh`:

1. the pinned 4-bit MLX model sidecar on `127.0.0.1:8778`;
2. FastAPI plus the built site on `127.0.0.1:8777`;
3. a durable answer/index worker.

The connected `ResearchWorker` is deliberately a fourth, operator-started
process and is excluded from this first-live topology until its later canary.
The launcher also forces `local_only` and disables the online answer adapter.

Jobs use leases, heartbeats, encrypted section checkpoints, digest-checked
resume, idempotency keys and exactly-once release. Direct and per-section repair
checkpoints bind the question, evidence, prior draft, findings, model, prompt,
policy and assessment bundle, preventing a crash from silently reusing drifted
work or repeating a completed model repair.

Observability has privacy-safe durable state plus owner-view projections:

- event records under `logs/events/`;
- Live60 and research metric streams under `logs/metrics/`;
- Live60 and research trace streams under `logs/traces/`; and
- durable evaluation/SQLite state under `data/evaluations/` and the catalogue.

Routine INFO traces use deterministic 10% sampling; DEBUG is off; WARN, ERROR
and FATAL are retained in full. A controlled Live60 evaluation retains all safe
spans.
Traces locate queue, retrieval, rerank, DB, opaque section generation,
verification, repair, assembly and release delays without storing questions,
answers, prompts, source text, paths or filenames. SLOs are provisional,
observe-only under `local-e2e-provisional-v2` and are not an SLA or promotion
gate until at least three independent successful runs per route/word band exist
for calibration.

The owner dashboard exposes manifest-driven run/case status, released answers
only, evidence identities and locators, applied assessment rules, issues, gaps,
refinements, research tasks/candidates/update observations, subject readiness,
queue/stuck state and p50/p95/p99 stage latency. Held/private drafts remain
encrypted.

## Model state

There is one archived Qwen3.5-9B Base checkpoint and one pinned 4-bit runtime
model. The interrupted top-level duplicate Base directory is absent. No
fine-tuned adapter or feedback-trained model exists. Evaluation output is not
training data; a later weight-changing phase requires its own rights/privacy
review, curated dataset, baseline comparison and explicit owner approval.

## Required order from here

Path B is selected for a full 30-answer run. Gold remains the exact reviewed
authority span for a frozen issue. The 17 August 2026 official remaining-issue
binds imported 77 selected issues with exact catalogue spans (12 from the
earlier Path-B adoption, 47 from the first hash-matched official pass, and 18
from a later extraction pass the same day). Authoritative issue state is
77 qualified / 0 limited / 508 knowledge_gap. Of the 305 selected issues,
228 remain knowledge_gap. Coverage-only issues may stay explicit gaps. No
selected case is fully qualified. Ordinary LIVE runtime availability is
independent of that overlay seal: a serving index may remain available while
the Live60 candidate overlay stays UNSEALED.

1. Materialise the 78 unmatched official candidates into configured source
   roots as new source versions, then exact-match. Catalogue miss stays a
   candidate, not an automatic knowledge_gap. Reuse the 77 hash-matched
   issues; do not re-research them. Held statutes stay knowledge gaps with an
   explicit hold reason and a gap-verification attestation before V2 VERIFIED.
   Official legislation.gov.uk and Find Case Law bytes
   were fetched for the 293-row worksheet; the latest mechanical pass
   hash-matched 65 of those rows, of which 18 were new imports (77 selected
   qualified in total). 150 stay keep_gap pending gap attestation (case-law later treatment, held
   statutes, or no safe span). Triple Point (`live30-q26:issue-04`) stays a
   gap because `qualified_current` needs bound limiting-authority IDs. Word
   copies stay display-only. Downloaded text is not gold until the local hash
   matches. V2 gold is a proof bundle (mechanical + independent semantic
   verifier). The owner reviewer role label for v1 remains `legal_reviewer`.
2. Confirm D1–D15 and the named-source-set contrary review with
   `CONFIRM_OWNER_AUTHORED_SEAL` before any **v1** overlay seal. V2 evaluation
   derives evidence-lifecycle decisions (D-01–D-05, D-15) and keeps D-06–D-14
   as operator/product policy outside evaluation gold. Code will not set
   `owner_authored: true` without that token.
3. V2 overlay is complete when all 305 selected issues have a verified
   disposition (`qualified`, `limited`, or explicit `knowledge_gap`) and
   `unreviewed_issue_count == 0`. V1 sealing still requires 30/30 selected
   cases qualified with 305 positive exact spans. Coverage-only gaps remain
   gaps. Do not invent spans.
4. Build a rights-qualified current-date E&W **candidate** bound to that
   overlay; do not promote it. Stage A v2 scores only issues with positive
   verified gold (qualified and limited). Do not fabricate Recall@5 for
   knowledge_gap. Failures get a versioned retrieval/evidence diff, never a
   fabricated pass.
5. Issue evaluation-only authorization v2 pinned to `candidate_build_id`.
   Run the 30 selected cases against that candidate: qualified → answer;
   limited → limited answer; held → deterministic held. One held case must
   not block the other 29. Fail-closed answer gates stay. This is not
   production LIVE and must not write ACTIVE.
6. Evaluation itself never writes ACTIVE. For the Live60 production profile,
   `legalbot promote` requires a verified production-promotion attestation
   bound to a completed V2 evaluation. The owner then observes rollback and
   re-promotion, completes a real loopback browser recovery, obtains readiness
   v6 green, and alone issues O-04 for the frozen 30 IDs.
7. Review every defect as a versioned issue/refinement/regression. Only after
   the local run passes may the separate connected-crawler canary be attempted.
8. Conduct separate blind legal calibration before making any consistent-70+
   claim.
