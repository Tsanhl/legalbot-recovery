# LegalBot v1.11 Phase-2A owner review

**Date:** 2026-08-23

**State:** non-authorizing owner review
**Verdict:** `PHASE 2A SAFELY STOPPED - PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED`

This document presents the existing Phase-2A r4 evidence and the corrected lifecycle.
It is not a legal adoption, a signing payload or permission to split, run Stage A, invoke
an answer model, run Development 30, promote, issue O-04, validate or go live.

## Executive result

The candidate's storage and index mechanics are coherent, but the Owner Certification 60
is not qualified. Phase 2 cannot advance to split or Development until the evidence/gold
work is remediated, the chosen human authority adopts the material propositions and a
deterministic final Phase-2A replay is confirmed by the owner.

The two facts must remain separate:

- **Structurally healthy:** 85 candidate sources; 149,855 chunks and 149,855 vectors;
  dimension 1,024; exact candidate binding; no observed mutation.
- **Certification blocked:** 0/60 cases and 0/585 issues positively qualified; 509 rows
  have empty/incomplete gold-source-span binding and 76 rows have confirmed material
  candidate coverage gaps.

## Exact r4 evidence binding

- Package: `v111-phase2a-20260823-r4-ee47fda9d00a`
- Artifact count: 15; all 15 file hashes match the package index
- Internal index digest: `e83681be7b737a9bd10e5886449e50da88e47e51428a53efc21836054600ac8e`
- `PHASE2A-INDEX.json` file digest:
  `7855ad3c0bf75a303c5c563a7be280c840f0c3d6faf936b40686701354da0732`
- Bound commit: `ee47fda9d00a598f148977e125461e5fab8dc156`
- Bound tree: `3b38150b2077ed9cda7acb750617de4aceffe416`
- Registry digest: `78a738afd920ff840dcedeb0fd3fd5ca81035f499a0630d351d49e7c6cd3777a`
- Candidate: `current-law-ew-full-fp16-v111-20260818-a`
- Candidate source-manifest digest:
  `d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0`

r4 is evidence for its bound commit/tree, not for the later repository HEAD. This owner
review may summarize r4 but cannot extend its authority to a different build.

## What r4 proves

- All 60 cases and 585 issue rows are present, unique and accounted exactly once.
- The 509/76 diagnostic split reproduces.
- The sealed candidate, chunks and vectors are mechanically coherent and unchanged.
- Synthetic-only split infrastructure passed without creating a real lane assignment.
- No real split or secret, signing material, Stage A, Development 30, answer-model call,
  promotion, ACTIVE/PREVIOUS change, O-04, Validation or live action occurred.
- The package is unsigned, non-authorizing and contains no question prose or private
  paths.

It does not prove that all 585 recorded propositions are wrong, that the gold is correct,
that the candidate is legally current or that a common cutoff can be frozen.

## Root defects

### Gold and case binding

The 509 `GOLD_OR_CASE_DEFECT` rows defaulted to a blocked state because the registry lacks
complete proposition/source/version/span binding. Row-level review has not yet determined
how many are gold-only defects versus additional candidate gaps. Therefore 509 is a
valid blocked count but not a completed root-cause breakdown.

### Candidate coverage and currentness

The 76 `MATERIAL_CANDIDATE_COVERAGE_GAP` rows are supported by 11 official-source
findings: six legislation sources and five binding judgments, producing 83 mappings to
76 unique issue rows. Under the current schema these findings require a successor
candidate. Exact successor scope still requires proposition-level relevance,
commencement/effective-date and source-presence review.

The broader audit found 65 legislation entries with 1,896 unapplied effects and 20
judgments for which all 20 later-treatment reviews remain required. Zero candidate
sources presently satisfy the complete “full-current-law eligible” schema.

### Cutoff

No common legal-currentness cutoff is supportable on r4. `2026-08-14` is a review target
ceiling only; it is neither a recommendation nor an adopted cutoff.

### Qualification implementation gates

The current qualification path requires 585 model-based evidence-review checkpoints and
then a trusted owner-decision signature verifier. The current authorization prohibits an
answer-model run and no signing authority exists. Verification-only model review must be
expressly classified and authorized or deferred; owner/professional legal adoption and
the later signature replay remain separate requirements.

## Structural readiness by subsystem

| Subsystem | Current position | Required before Development 30 |
| --- | --- | --- |
| Candidate chunks/vectors | Mechanically coherent at r4 | Reseal and re-attest a successor if final row-level review confirms source additions |
| Retrieval/reranker | Phase-1 infrastructure and attestation exist | Attest the final candidate; run Development Stage A only after signed authorization |
| Jobs/queue/workers | Durable jobs, leases, bounded queue, cancellation and typed stop states exist | Prove singleton authority, lease fencing/expiry, crash recovery and stale-owner rejection synthetically |
| Retry/loop control | Same fingerprint stops after the second occurrence | Keep preflight, intra-case retry and batch-resume counters separate; never infer a second batch |
| Crawler | Allowlist/staging/no-ACTIVE architecture exists | Freeze redirect, DNS, byte/type/time limits and replayable content custody; no automatic ingestion |
| Logs/traces/metrics | Redacted SQLite/JSONL observability foundation exists | Prove the dated lane-local projection and incident dossier with synthetic fixtures |
| Hallucination/quality checks | Unsupported-claim, quote, citation, contradiction, version/currentness and privacy gates exist | Bind exact contract and reviewer; metrics indicate risk but cannot prove hallucination absence |
| Local security | Controls are proposed only | After owner approval/signature: UDS model transport, session secret, strict Host/Origin/CSRF, root separation |
| Owner review projection | Synthetic projection infrastructure exists | Produce immutable case folders and rendered DOCX only for the authorized lane/run |

## Corrected lifecycle

1. Complete the unsplit 585-row remediation matrix and successor evidence work.
2. Produce an evidence-ready, non-authorizing Phase-2A package.
3. Owner chooses professional certification or owner-only internal adoption and adopts
   every material row, or the exact 585-row manifest with explicit exceptions.
4. Replay Phase-2A deterministically; owner confirms the new digest and authorizes
   Phase-2B preparation.
5. Phase-2B activates signed controls, freezes the contract/strata, generates the secret
   once and creates the deterministic 30/30 complement. No model answers run.
6. Owner signs the exact initial Development payload.
7. Run one Development Stage-A plus 30-answer batch and review the complete served path.
8. Any improvement cycle requires owner-scoped changes and a new signature for the final
   Development rerun on the exact remediated snapshot.
9. Owner accepts final Development and separately authorizes controlled promotion.
10. Run operational proof, obtain O-04, execute one-pass Sealed Validation 30, then seek
    final owner-only live approval.

No stage authorizes the next automatically.

## Dated owner-review and incident structure

Before Development authorization, synthetic tests must prove three non-synchronised
private roots and the ISO-dated layout in
`docs/observability/V111_CERTIFICATION_RUN_LAYOUT.md`. Every authorized case receives its
question, initial answer or typed held record, evidence map, deterministic review,
separately persisted AI review, standards alignment, metrics, trace reference, gaps and
incident links. A rendered owner DOCX summarizes all 30 cases without exposing Validation
artifacts.

Ordinary logs never contain question/answer prose, prompts, evidence content, credentials
or private paths. After the same deterministic failure fingerprint occurs twice, stop
before a third attempt and debug. No loop, selective rerun or silent partial publication
is allowed.

## Knowledge-gap firewall

Question/answer folders, reviewer notes, incidents, logs and proposed corrections are
diagnostic only and are never automatically indexed or embedded. Verified official
source bytes may enter quarantine and later a new sealed candidate; gold corrections
create versioned evaluation artifacts; generic rules enter versioned code/policy/prompt
only after approval and tests; case-specific observations never become case-ID-specific
runtime rules.

## Owner decisions required now

Do not sign a Development payload yet. Please decide or confirm:

1. **Adoption route:** Option A, professional England-and-Wales legal certification; or
   Option B, owner-adopted internal research-tool qualification. Option B is not
   professional legal certification.
2. **Phase-2A verification-model boundary:** permit pinned verification-only model calls
   for the 585 evidence checkpoints, with no answer generation, or defer those checkpoints
   until signing/model controls exist. Codex-only review remains advisory and not
   certification evidence.
3. **Successor remediation scope:** confirm that the existing authorization permits
   read-only official-source retrieval, quarantined source intake, one consolidated
   successor build and retrieval re-attestation after row-level proof. No source is
   admitted automatically from crawler output.
4. **Contract review:** approve or amend the conservative certification-contract proposal.
   Thresholds cannot be relaxed after results.
5. **Control review:** approve or amend the pinned Ed25519 public key, private Unix socket,
   12 GiB ceiling/3 GiB free-memory admission, three private roots and strict
   `127.0.0.1` Host/Origin/CSRF/session policy as Phase-2B controls. Approval does not yet
   create keys, secrets, roots or a split.
6. **Safe stop:** confirm Phase-2B and Development 30 remain withheld until a corrected
   Phase-2A replay passes and its exact digest is confirmed.

## Exact permitted next action

Pending the decisions above, the safe next action is non-model, unsplit Phase-2A
preparation: build the row-level remediation/authority skeleton; prepare successor-source
intake and gold-binding proposals; add synthetic verifier, crawler-admission, candidate-
builder and owner-projection tests; and preserve all work as non-authorizing evidence.

The project is not ready for Development 30.
