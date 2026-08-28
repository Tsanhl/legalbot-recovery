# LegalBot v1.11 owner-gated certification roadmap

This document is the normative lifecycle policy for v1.11. Mutable observations, exact
commit identities, current defect counts and local catalogue facts belong in dated,
schema-validated evidence packages. Owner-readable Markdown and DOCX reports are
projections of canonical JSON evidence; they are never release authority by themselves.

## Current authority boundary

The applicable authority boundary is established by the latest valid record in the
append-only owner decision ledger and its dated state package. Authorization for one
phase never implies authorization for a later phase. Current artifact identities,
observed counts, blockers and authorization status must not be hard-coded into this
normative roadmap.

The governing sequence is:

`Phase-2A evidence remediation -> evidence-ready owner package -> owner/professional adoption -> deterministic final Phase-2A replay -> owner confirms the final digest and authorizes Phase-2B -> Phase-2B controls and split -> signed initial Development authorization -> initial Development 30 -> either exact-snapshot owner acceptance, or owner-authorized Phase-2D remediation followed by one signed final Development 30 -> signed promotion authorization -> operations and O-04 -> one-pass Sealed Validation 30 -> signed live authorization`

No stage automatically authorizes the next stage.

## Certification terminology

- **Historical Live60** is immutable regression history only.
- **Owner Certification 60** is the reused 60-case registry governed by the v1.11
  certification contract.
- **Development 30** is the visible iteration set after a real owner-controlled split.
- **Sealed Validation 30** is a one-pass answer-sealed complement. It is not described as
  genuinely unseen because the reused questions and historical material have existed
  before this certification cycle.
- Once Development IDs are disclosed from a known 60-case complement, Validation
  membership may be mathematically inferable. The sealed manifest remains custody-
  protected and ordinary iteration tooling cannot project or execute Validation. Fresh
  Validation retrieval, generated answers, scores, reviewer findings and results remain
  sealed until O-04. Qualification of the reused source/gold registry is permitted
  before the split.
- **Integration Baseline HEAD** is the Phase-1 checkpoint, not the production build.
- **Production Candidate HEAD** is the exact owner-accepted build later eligible for
  controlled promotion.

## Branch, manifest and decision authority

Following the 29 August 2026 recovery cleanup, the active workspace intentionally has
no Git metadata. The owner will establish its replacement Git repository and branch.
Until then, agents must not initialize Git, restore the historical bundle, add a remote,
commit or push. The recovered bundle is audit evidence only and must never be merged
wholesale. `LegalBot-New` and the damaged Integration path remain outside the workspace
and may not be used as runtime or recovery inputs.

A release manifest is a replay root and index. It cannot authorize a release merely
because its internal hashes agree. Every referenced artifact must remain independently
strict, replayable and bound to the exact commit/tree, candidate, locks, runtimes,
qualification, contract, split, results and owner decisions.

Use one append-only owner decision ledger with separately bound records for, at minimum:

1. Phase-2A row-level legal adoption;
2. confirmation of the deterministic final Phase-2A digest and authorization to prepare
   Phase-2B;
3. initial Development-run authorization;
4. any Phase-2D remediation-scope authorization;
5. any final Development-rerun authorization bound to the remediated exact snapshot;
6. final Development acceptance and Phase-3A promotion authorization;
7. O-04 one-pass Validation authorization; and
8. final Validation acceptance and owner-only live authorization.

Artifact drift automatically invalidates a decision bound to the changed artifact.
Before signing authority exists, an explicit owner instruction recorded in this task may
authorize the non-secret, non-answer-model preparation that it names. Once the Ed25519
authority is established, every answer-model run, promotion, O-04 and live gate requires
a valid bound signature. Silence, inferred consent, a stale file or an AI recommendation
is never authorization.

## AI-assisted review policy

The required review order is:

`deterministic checks -> official-source or immutable-artifact verification -> separately persisted AI advisory review -> discrepancy report -> owner/human decision`

AI review must bind the reviewed artifact, code/tree, candidate, model, prompt,
configuration, timestamp and output digest. It persists concise findings and evidence
references, never hidden chain-of-thought.

Allowed finding states are `VERIFIED`, `SUPPORTED_NOT_REPRODUCED`, `UNVERIFIED`,
`NONMATERIAL_WARNING`, `MATERIAL_DEFECT`, `OWNER_DECISION_REQUIRED` and
`RELEASE_BLOCKER`.

AI independence is described precisely:

- a different pinned model artifact, separate process/context and separate prompt with no
  shared adaptation or hidden state may be called independent;
- the same model weights in a fresh stateless context are
  `SAME_MODEL_STATELESS_REVIEW - LIMITED INDEPENDENCE`;
- a Codex review without a reproducible model-artifact digest is
  `CODEX_ADVISORY_AUDIT - NOT CERTIFICATION EVIDENCE`.

The AI review must be persisted before it is shown the deterministic verdict. Every
reviewer citation is deterministically resolved. AI acceptance cannot cure a
deterministic failure, sign a gate, promote, issue O-04, authorize live or independently
turn a proposition into legal authority. “Legal correctness” means alignment with the
frozen, adopted evidence and contract.

## Runtime and observability contract

Persisted business job states remain the existing typed durable vocabulary; v1.11 does
not add a general DAG or distributed scheduling system. One authoritative generation
worker processes one owner job at a time, with bounded internal retrieval concurrency.
SQLite leases are the intended duplicate-ownership control. Phase-2B must adversarially
prove lease acquisition, expiry/fencing, crash recovery and stale-owner rejection, and
must add a process/authority singleton proof so multiple manually launched generation
workers cannot coexist as authoritative workers.

Before Development authorization, the complete logging, trace, metric, incident and
private-review path must exist and pass synthetic tests. The three approved roots remain
separate and non-synchronised: Development review, sealed Validation custody and live
review. No lane may fall back to another lane's root.

Use unambiguous ISO dates and unique run IDs:

```text
<lane-root>/
  runs/
    YYYY-MM-DD/
      <lane>-<run-id>/
        manifest.json
        completion.json
        logs/events.jsonl
        traces/index.json
        metrics/run-metrics.json
        cases/
          <ordinal>-<opaque-case-id>/
            QUESTION.md
            ANSWER.md | HELD.json
            evidence-map.json
            metrics.json
            trace-reference.json
            reviewer/
              DETERMINISTIC-REVIEW.json
              AI-REVIEW.json
              STANDARDS-ALIGNMENT.md
              OWNER-NOTES-REFERENCE.json
            gaps.json
            incidents/
              <incident-id>.json
        incidents/
          YYYY-MM-DD/
            <incident-id>/
              incident.json
              safe-summary.md
              encrypted-debug-bundle.bin
              regression-reference.json
              disposition.json
        OWNER-SUMMARY.docx
        RENDER-RECEIPT.json
```

The immutable upstream JSON package remains authoritative. Generated folder material and
the DOCX are create-only, non-authorizing owner projections produced only after strict
upstream verification. Owner notes are a separate append-only input outside the immutable
run package and become authority only when their digest is bound into a later owner
decision. Ordinary logs exclude questions, answers, prompts, evidence content,
credentials, secrets, private paths and owner identifiers. Sensitive diagnostic prose
belongs only in encrypted, retention-bound private artifacts whose format, key custody,
permissions, retention and deletion policy were frozen in Phase-2B.

Every run binds release, commit/tree, candidate, contract, lane, run, job, case and stage
identities; UTC wall-clock timestamps plus durations measured with a monotonic clock
within one process; memory high-water mark; retries; leases;
cancellation; publication state; and failure fingerprints. Missing sidecar telemetry is
reported explicitly rather than silently omitted. Raw monotonic values are never compared
across processes or restarts.

The retry-circuit fingerprint is distinct from the aggregate observability fingerprint.
It binds the same job, case, stage, frozen snapshot and materially unchanged failure
condition. Its second occurrence stops that retry path before a third attempt; failures
in different cases do not automatically trigger this circuit. Preserve the incident,
root cause, evidence, fix commit, regression and invalidated gates. Synthetic/preflight
attempts and frozen intra-case retries have separate counters. After the first committed
Development generation request, only a same-run authenticated resume is possible; no
failure fingerprint or prior signature authorizes a second 30-answer batch.

Metrics help detect risk but do not prove hallucinations are impossible. Required quality
observations include unsupported material claims, false quotations, invented or
unresolved authorities, wrong source/version/jurisdiction/currentness, contradictions,
issue completeness, claim-to-evidence coverage, citation resolution, abstention quality,
truncation and publication integrity. Worker/job observations include queue admission,
wait, capacity, lease ownership, heartbeat, retry, cancellation, stale-worker events,
timeouts, tokens, memory, completion and partial-publication prevention.

## Knowledge-gap and improvement firewall

The knowledge-gap index is diagnostic evidence only. It is never automatically embedded
into or made searchable by the production answer path. Development/Validation questions,
generated answers, gold answers, AI findings, owner notes, incidents, logs and proposed
corrections must never enter the legal retrieval corpus.

Promotion is layer-specific:

| Finding type | Permitted destination |
| --- | --- |
| Verified official primary source | Quarantine/staging, human qualification, then a new sealed candidate followed by attestation and qualification |
| Gold correction | New versioned evaluation artifact only |
| Generic reasoning, format or safety rule | Versioned code, policy, prompt or verifier after owner approval, tests and gate invalidation |
| Case-specific observation | Diagnostic record only; never a case-ID-specific runtime rule |
| Validation or live finding | A later certification cycle; never repair of the already exposed/certified run |

Improvement states are:

`OBSERVED -> REPRODUCED -> EVIDENCE_CONFIRMED -> OWNER_APPROVED -> IMPLEMENTED -> VERIFIED -> CERTIFIED`

The certification crawler contract requires a strict allowlist, redirect revalidation
and fixed size, time and content-type limits. Before crawler output supports Phase-2A
evidence, its artifact binds exact permitted bytes where licence policy permits, final
URL, retrieval time, approved HTTP metadata, parser identity, content digest and
extracted-text digest. Any unavailable field is explicit and never inferred. It stages
evidence and never mutates the sealed candidate or supplies the answer currently being
generated. Statutory/judgment text may be authoritative;
explanatory notes, press summaries and mutable landing pages are context or locators.
“No later treatment found” always records the search protocol and its coverage limit.

## Phase 1 - Integration Baseline and Q31 retirement

Phase 1 captured read-only state, durably archived deferred work, reconciled history,
retired Q31-specific current dependencies without weakening generic safeguards, froze
the Integration Baseline, compared the complete scorer closure and completed the
Integration-Baseline scorer/retrieval successor attestation. That attestation does not
cover a future remediated candidate and does not prove present legal currentness.

Phase 1 prohibited real Stage A, All60, answer generation, promotion and live actions.
Its exit remains:

`INTEGRATION BASELINE COMPLETE - READY TO BEGIN OWNER CERTIFICATION`

## Phase 2A - Evidence remediation, adoption and final qualification

### 2A.0 Reconfirm the blocked baseline

Replay the current schema-validated Phase-2A inventory and report expected and observed
case/issue counts and diagnostic classifications from the bound evidence package. Replay
candidate bytes, ACTIVE/PREVIOUS, absence of prohibited split/signing/model outputs and
internal consistency. A blocked baseline proves only its recorded defects; it does not
prove that every registry proposition is wrong.

If row-level verification proves that a material proposition requires an official source
absent from the sealed candidate, a successor candidate is required. Exact successor
scope remains subject to relevance, effective-date and source-presence review. Incomplete
gold alone does not prove candidate insufficiency.

### 2A.1 Build one remediation row per registry issue

Each row binds case/issue identity, legal domain, `registry_proposition_as_recorded`,
`proposed_corrected_proposition`, `adopted_proposition`, existing gold, candidate
source/chunk/span, current official authority/version, effective date,
commencement/transition/amendment/repeal/later treatment, candidate coverage, gold
binding, root cause, proposed correction, candidate impact, downstream invalidation and
evidence digests.

Use one primary technical/legal root cause from this frozen taxonomy:
`MISSING_OFFICIAL_AUTHORITY_IN_CANDIDATE`, `STALE_SOURCE_VERSION`,
`MISSING_GOLD_SOURCE_BINDING`, `MISSING_GOLD_SPAN_BINDING`,
`INCORRECT_GOLD_PROPOSITION`, `INCORRECT_CASE_ISSUE_DEFINITION`,
`CANONICAL_IDENTIFIER_MISMATCH`, `CURRENTNESS_OR_COMMENCEMENT_DEFECT`,
`LATER_TREATMENT_NOT_REVIEWED` or `OTHER_CONFIRMED_DEFECT`. The last value requires a
specific explanation and evidence and can never be automatically resolved.

Adoption status is
separate and may be `NOT_REQUESTED`, `PROFESSIONAL_REVIEW_REQUIRED`,
`OWNER_ADOPTION_REQUIRED`, `PROFESSIONALLY_ADOPTED` or `OWNER_ADOPTED_INTERNAL`.
`HUMAN_OR_OWNER_ADOPTION_REQUIRED` is not used as a substitute for the actual defect.

### 2A.2 Remediate gold and candidate evidence separately

For gold/case defects, first determine whether the correct official source already exists
in the candidate. Add versioned proposition/source/span bindings without rebuilding the
candidate where its bytes are sufficient. Preserve predecessor artifacts and old-to-new
provenance.

For candidate-impact rows, prove exact source absence or staleness and proposition-level
materiality. Consolidate all confirmed official-source changes into one successor build.
Never rebuild once per authority and never patch sealed candidate bytes.

### 2A.3 Create the evidence-ready package

An evidence-ready package requires every registry-issue row to be technically complete, exact
source/version/span bindings, resolved candidate impact, a supportable proposed cutoff,
material-change rules, passing retrieval attestation for any successor candidate,
deterministic verification and no unresolved technical release blocker.

It remains non-authorizing and may contain rows awaiting adoption.

### 2A.4 Owner or professional adoption

The owner chooses one route and adopts each material row, or one immutable all-issue
manifest digest with every exception listed explicitly:

- **Option A - Professional legal certification:** an expressly qualified England-and-
  Wales legal reviewer adopts or corrects each material proposition.
- **Option B - Owner-only research-tool adoption:** the owner personally adopts the
  reviewed evidence for a private research tool. The result is labelled
  `OWNER_ADOPTED_INTERNAL`, never professional legal certification.

AI prepares and audits the material but cannot impersonate either adopter.

### 2A.5 Final Phase-2A replay

After adoption, rebuild and replay the package deterministically. It may pass only when
all registry rows are
accounted exactly once, every material row has the contract-permitted positive/adopted
status, no material candidate/gold/currentness defect remains, the common cutoff is
supportable and every AI-flagged potential blocker has been resolved through
deterministic evidence or express human adjudication. An AI label never creates the gate
result.

Because replay produces a new final digest, the owner must confirm that exact digest and
separately authorize Phase-2B preparation. Adoption of the evidence-ready predecessor is
not permission to continue automatically.

Before the Phase-2A stop, produce a sanitized manifest-bound
`YYYY-MM-DD Phase 2A Owner Review.docx` and external-review bundle. They present every
required owner decision and reference the canonical all-issue evidence without becoming
authority or authorizing transmission.

No split, Stage A or answer generation occurs in Phase 2A. The exit is:

`PHASE 2A REMEDIATION COMPLETE - OWNER REVIEW REQUIRED BEFORE PHASE 2B`

If incomplete:

`PHASE 2A SAFELY STOPPED - PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED`

## Phase 2B - Controls, contract and real 30/30 complement

Phase 2B starts only after a valid Phase-2A adoption/approval record. It must:

- bind the adopted cutoff, freshness policy and frozen certification contract;
- validate the Ed25519 public-key verifier while keeping the private key outside Git;
- establish three distinct private roots and strict file permissions;
- activate literal loopback Host/Origin/CSRF/session-secret controls;
- activate private Unix-domain-socket-only model transport with no TCP/cloud fallback;
- bind generator and reviewer models, prompts, configurations and independence status;
- enforce the 12 GiB process-tree ceiling and 3 GiB free-memory admission rule;
- prove authoritative singleton generation-worker ownership;
- implement trusted signed-decision replay;
- implement and synthetically verify the dated review/incident projection;
- freeze Development valid-run, reviewer-resume and missing-telemetry rules;
- freeze the strata variables, balancing rules, algorithm/version, registry digest and
  tie-breaking rule before generating the split secret once and freezing the
  deterministic stratified 30/30 complement;
- freeze the incident-bundle encryption format, key custody, permissions, retention and
  owner-controlled deletion policy;
- create the unsigned canonical initial Development authorization payload.

The canonical payload binds the exact commit/tree, candidate, adopted qualification,
cutoff/freshness policy, contract, split commitment, both lane-manifest digests,
generator/reviewer models and prompts, deterministic reviewer, security controls,
observability schema, retry/valid-run policy and private-root receipts. The split cannot
be redrawn after any performance result is inspected.

Runtime sanity uses deterministic fakes or non-registry synthetic fixtures. It must not
create a hidden Development answer. The pre-signature package receives deterministic and
advisory AI audits and stops at:

`PHASE 2B SPLIT FROZEN - EXTERNAL REVIEW AND OWNER SIGNATURE REQUIRED BEFORE DEVELOPMENT 30`

“External-review bundle” means exportable and sanitized; it does not authorize upload or
transmission to another person or service.

## Initial Development authorization

The owner's signature may authorize Development-only projection, Stage A, one initial
30-answer batch, deterministic review, one frozen AI-review pass and owner-package
creation. It does not authorize Validation, automatic repair, a second Development run,
promotion, ACTIVE, O-04 or live.

## Phase 2C - Initial Development 30

Verify the signature and every bound artifact, then perform a final read-only currentness
delta. Any material delta stops before generation. Project exactly the Development 30.
The Validation manifest remains custody-protected, ordinary iteration tooling cannot
project or execute it, and fresh Validation retrieval/output/review/results remain
sealed.

The tested production path is:

`Development Stage A -> generation -> evidence verification -> release-content transformation -> packaging -> private snapshot-serving replay`

The first atomically recorded Development generation dispatch starts the authorized
batch. No out-of-batch diagnostic answer calls are permitted. Predetermined per-case
section generation, verification, separately bound AI review and bounded retry calls are
part of the frozen authorized path and must be fully traced. Length diagnostics are
derived from the authorized cases. A preflight failure before that first dispatch does
not start the batch.

All 30 answers run on one immutable code/config/candidate/model/prompt/reviewer snapshot.
No partial answer is published as complete. A technical resume requires the same run ID,
authenticated checkpoint, unchanged snapshot and unexposed output. Reviewer failure
does not regenerate answers; reviewer work may resume only against the immutable answer
package under its frozen retry policy.

Every case receives deterministic claim/evidence and citation checks. Every
deterministically eligible case receives the frozen separately bound AI advisory review;
a deterministic hard stop records `NOT_INVOKED_DETERMINISTIC_HARD_STOP` instead of
fabricating or spending an AI-review result. Each package also contains standards
alignment, specific/general rule gaps, knowledge gaps, qualification/currentness artifact
references and any staged follow-up gap request, retrieval/reranker/span diagnostics,
worker/job/resource telemetry, and pending owner decision fields. No crawler network call
or newly fetched material may enter the current Development batch. The dated private
folder and rendered DOCX contain all 30 questions and verified-full answers or explicit
held records.

The exit is:

`DEVELOPMENT 30 INITIAL RUN AND AI REVIEW COMPLETE - OWNER REVIEW REQUIRED`

An invalid execution stops with:

`DEVELOPMENT 30 SAFELY STOPPED - OWNER REVIEW AND NEW AUTHORIZATION REQUIRED`

If the owner accepts the initial Development result and no release-relevant artifact
changes, that exact run may become the final Development package. It is not rerun merely
to rename it. A full final rerun is required only after a release-relevant change and a
new exact-snapshot authorization.

## Phase 2D - Owner-authorized improvement cycle

Phase 2D never starts automatically. Owner feedback and a signed/recorded remediation
scope precede root-cause analysis and any change. Changes must be generic, evidence-
bound and regression-tested; no case-ID-specific answer rule, threshold lowering, gold
rewrite-to-pass, split redraw or Validation access is allowed.

A confirmed gold defect returns to Phase-2A, creates a versioned independently reviewed
evaluation artifact, updates qualification and manifests, and requires renewed run
authorization. This is legitimate correction, not a rewrite-to-pass.

An official-source addition creates a new candidate identity/seal, retrieval attestation,
qualification, updated manifests, final Development rerun and renewed owner acceptance.
The split assignment may remain only if registry, issue identities, strata and sealed
custody are unchanged; otherwise a new split cycle is required.

After the final release-relevant change, freeze the exact build/candidate, run all
affected prerequisites and the complete release verification, then produce a new
canonical final-rerun payload. The owner must sign that exact payload before a full final
Development 30 runs on the Production Candidate commit/candidate. Remediation authority
alone never authorizes that future model run. Stop at:

`FINAL DEVELOPMENT 30 COMPLETE - OWNER ACCEPTANCE AND PROMOTION AUTHORIZATION REQUIRED`

## Phase 3A - Promotion and operational proof

Promote only the exact owner-accepted candidate. First promotion must atomically roll back
to verified no-ACTIVE and re-promote the exact bytes. Promotion authorizes controlled
operational proof only.

Operational proof covers lifecycle, singleton job ownership, duplicate submission,
idempotency, leases, stale recovery, memory/free-memory/disk/queue/heartbeat bounds,
timeouts, retries, repeated fingerprints, cancellation, no partial publication, browser
recovery, one-snapshot serving, release-content equivalence, rollback/re-promotion,
privacy, redacted audit events, loopback security and Unix-socket-only model transport.

AI may inspect sanitized reports for contradictions, missing scenarios or outliers but
cannot turn a failed deterministic test into a pass. After a final currentness delta,
produce O-04 material and stop at:

`PHASE 3 OPERATIONAL PROOF COMPLETE - EXTERNAL O-04 REVIEW AND OWNER SIGNATURE REQUIRED`

Any release-relevant operational remediation invalidates the final Development result
and acceptance. Return to the affected Phase-2 gate, rerun final Development on the new
SHA and obtain renewed promotion authorization before re-promotion.

## O-04 and Phase 3B - One-pass Sealed Validation 30

O-04 binds the exact Production Candidate commit/tree, ACTIVE candidate, models, prompts,
promotion, operations, currentness, contract, sealed Validation manifest, valid-run rules
and reviewer rules. It authorizes controlled Validation access and one answer batch only;
it does not authorize live.

The path is:

`O-04 verification -> exact ACTIVE verification -> currentness delta -> controlled unseal -> Validation Stage A -> generation once -> immutable result persistence -> deterministic scoring -> post-persistence AI review -> owner decision`

A preflight failure before the first committed evaluation request does not consume the
run. The first committed request starts it. Thereafter only frozen intra-case retries or
a same-run authenticated checkpoint resume with an unchanged snapshot, no exposed output
and the same run ID are valid. Unsafe resumption becomes invalid diagnostic evidence and
ends the cycle. Reviewer failure never regenerates answers.

No repair, tuning, prompt/threshold change, selective rerun or same-set recertification is
allowed after exposure. The owner may reject a deterministic pass but cannot convert a
deterministic failure into certification or relax the contract after seeing results.

A failure means no live and a new certification cycle with fresh, unexposed Validation
cases. The exposed Validation 30 is permanently retired from sealed status; reshuffling
the reused 60 is insufficient. A complete run stops at:

`SEALED VALIDATION 30 AND AI REVIEW COMPLETE - FINAL OWNER DECISION REQUIRED`

## Phase 3C - Owner-only live

After signed final approval, fast-forward `main` to the exact certified commit, verify its
tree, then create the signed release tag. Any different commit requires certification.
Reverify ACTIVE and all evidence/configuration drift before startup.

Live binds literally to `127.0.0.1`, uses private Unix-socket model transport and the
approved Host/Origin/CSRF/session controls, publishes only `verified_full`, and permits no
LAN/public bind, cloud deployment, telemetry export, training export or sharing.

If Phase-2A used Option B, `verified_full` means technically verified against an
`OWNER_ADOPTED_INTERNAL` contract. The UI and report display the currentness cutoff and
must not imply professional legal certification.

Local AI may provide advisory warnings and summaries but may not self-modify, reindex,
promote, alter verified answers or bypass owner review. A new post-release reviewer is
advisory until separately certified.

Final exit:

`LEGALBOT v1.11 OWNER-ONLY LIVE - EXACT VALIDATED SNAPSHOT`

## Change-to-gate invalidation matrix

Any release-relevant executable change after final Development acceptance invalidates
that acceptance and requires final Development on the new exact commit. No table row
exempts a post-acceptance executable change from this rule.

| Change | Minimum invalidation |
| --- | --- |
| Non-authoritative presentation-only documentation | Documentation, integrity and clean-tree checks |
| Normative roadmap, contract, security policy or schema | Policy review and every downstream artifact bound to the changed policy |
| Non-executable private-projection formatting/schema | Projection, rendering and integrity replay; a new projection identity; renewed owner package if its digest changes; no answer rerun |
| Runtime observability instrumentation | Backend/runtime/operational proof and final Development on the new exact commit |
| Frozen missing-telemetry or valid-run policy after split | New certification cycle |
| Frontend, browser or snapshot-serving behavior | Node/browser/snapshot-serving/operational proof and final Development on the new exact commit |
| Worker, queue, release content, packaging or serving | Backend/runtime/operational tests and final Development on the new commit |
| Prompt, generator, verifier, deterministic reviewer or AI reviewer | Development and all downstream evidence |
| Retrieval, locator, scorer closure or gold parser | Retrieval re-attestation, affected Stage A, Development and downstream evidence |
| Gold proposition/source/span binding | Qualification, affected Stage A, Development and downstream evidence; retrieval re-attestation only when retrieval/scorer closure changes |
| Candidate or material legal-currentness | Candidate reseal, qualification, retrieval attestation, Development and downstream evidence |
| Case/issue registry, strata, contract or thresholds before freeze | Rebuild the affected Phase-2A/2B artifacts before performance review |
| Case/issue registry, strata, contract, thresholds or split after freeze; Validation exposure | New certification cycle |
| Runtime/dependency lock or model artifact | Affected build/model tests, Development and downstream snapshot evidence |
| Signature verifier, security control or private-root policy | Security/replay/root tests and all downstream signed or operational evidence |
| Release-relevant post-O-04 change | O-04 invalid; return to the affected Phase-2 gate |
| Release-relevant post-Validation change | Validated evidence does not cover the new build; new certification cycle |

## Explicit exclusions

v1.11 does not add Q31 replacement states, a general DAG, distributed worker classes,
parallel implementation branches, repeated same-set “blind” validation, automatic
knowledge-gap embedding, automatic crawler-to-candidate mutation, post-freeze ordinary-
live work, self-sealed authority, unconditional out-of-closure re-attestation or
stash-only preservation.
