# Live60 evaluation contract

Live60 is registered but remains **NO-GO**. Registration proves only that the
owner questions, suite totals, lineage and single-pass selection are immutable
and internally consistent. It does not prove source coverage, legal accuracy,
candidate eligibility or permission to run live generation.

## Frozen contract

- Suite: `live-evaluation-60-v1`.
- Registry: 60 questions and 215,000 requested words.
- Evaluation status: development/live, evaluation-only, never training input.
- Gold requirement: all 60 cases, every issue, one primary qualified E&W reviewer
  (the owner). Independent second review is optional. AI cannot be a reviewer.
- Generation plan: exactly 30 unique cases once, 114,000 requested words.
- Nonselected cases: `coverage_only_not_selected`.
- Drafting routes: 15 sectioned and 15 full-enquiry.
- Legal date: Europe/London calendar date at run admission.
- First run: local-only; online research prohibited.
- Foreign-law limits are mandatory for Q43, Q55 and Q60.

The selected single-pass generation cases are:

```text
Q2 Q3 Q6 Q7 Q13 Q15 Q16 Q17 Q20 Q21 Q23 Q24 Q26 Q27 Q29
Q31 Q32 Q35 Q38 Q40 Q42 Q43 Q46 Q48 Q49 Q51 Q53 Q56 Q59 Q60
```

The remaining 30 rows stay visible as `coverage_only_not_selected`; they are
never classified as failed merely because the sealed run plan does not generate
them.

The first 30 registry rows retain their sealed Live30 IDs, questions and record
hashes. Q31-Q60 use the v2 row schema. The Live30 v1 package and historical
48-outcome strategy remain readable and unchanged.

## Commands

Verify the committed bundle and its mandatory lineage sidecars:

```bash
uv run python scripts/live_evaluation_suite.py verify
uv run python scripts/live_evaluation_suite.py summary
```

Optionally reverify the original owner attachment and accepted memo bytes:

```bash
uv run python scripts/live_evaluation_suite.py verify \
  --source <q31-60-owner-attachment> \
  --accepted-memo <accepted-go-no-go-docx>
```

`summary` also prints the exact current model, prompt, router, classifier,
policy and assessment-bundle identities. `create-run` requires all six values
explicitly and rejects any caller-supplied value that differs from the
installed runtime; an operator cannot label a new run with stale versions.
The created manifest remains unapproved and does not authorize generation.

```bash
uv run python scripts/live_evaluation_suite.py create-run \
  --run-id <run-id> \
  --index-build-id <candidate-id> \
  --model-version <summary-model-version> \
  --prompt-version <summary-prompt-version> \
  --router-version <summary-router-version> \
  --classifier-version <summary-classifier-version> \
  --policy-sha256 <summary-policy-sha256> \
  --assessment-rules-sha256 <summary-assessment-sha256>
```

Create an unapproved annotation template only after an immutable candidate ID
and legal date exist:

```bash
uv run python scripts/live_evaluation_suite.py qualification-template \
  --index-build-id <candidate-id> \
  --output <encrypted-or-owner-controlled-review-path>
```

The template is deliberately invalid as a sealed overlay. It must not be
filled by copying nearest-vector results or by inventing reviewer identities.

## Stage A behaviour

The manifest-driven store encrypts all 60 questions and snapshots the exact
suite manifest and generation plan. Coverage runs all 60 cases serially while
retrieval within one case is bounded. Without a sealed overlay it records
candidate readiness and gaps but publishes no Recall, MRR or nDCG score.

With a valid overlay, Stage A reports Recall@5, Recall@10, MRR, nDCG@10,
exact-span recall, contrary-authority recall, filter violations and context
noise. Its fixed primary gate is:

- Recall@5 = 100%.
- Recall@10 at least 95%.
- MRR at least 0.80.
- Zero filter violations.
- Every route and subject-routing check passes.

Passing Stage A does not promote ACTIVE and does not authorize generation.
Owner promotion, rollback/re-promotion, browser recovery, readiness and O-04
remain separate gates. Completing the 585 owner issue ticks is necessary but
not sufficient for a live 30-case run. If every issue remains `knowledge_gap`,
Stage A cannot publish Recall@5=100% because ranking_evaluable gold requires
`qualified` issues with exact spans.

## Generation authorization contract

The execution adapter accepts no model call until a sealed authorization binds
the exact run, suite, run plan and ACTIVE build to:

- an owner promotion reference;
- a rollback/re-promotion report;
- a real-browser recovery report;
- a readiness report with `ready=true` and zero blockers; and
- an O-04 owner authorization for the exact 30 selected IDs and one pass.

After authorization, every selected case must end exactly once as `released`,
`verified_limited`, `held` or `system_error`. A coverage-only case cannot
receive a generation outcome. Released results must reference an existing
encrypted answer artifact with a matching SHA-256 and a release-gate report.
Privacy, evidence, currentness, jurisdiction, citation, injection and OSCOLA
must all be recorded as passed. The aggregate finalizer accepts exactly 30
pass-one outcomes and no stability repeats.

The HTTP executor is implemented but is never invoked by suite registration,
coverage, readiness or export commands. Before any model call, the explicit
execution command rechecks the Europe/London run date, the O-04 seal, the exact
readiness/rollback/browser artifact digests, the database and `ACTIVE.json`
candidate identity, the current-law source-manifest date, the local-only
runtime profile, API health, model identity and worker availability:

```bash
uv run python scripts/live_evaluation_suite.py execution-preflight \
  --run-id <run-id>
```

Only after that preflight succeeds may the owner deliberately start the one
serial pass:

```bash
uv run python scripts/live_evaluation_suite.py execute \
  --run-id <run-id>
```

The command uses immutable case/run headers and deterministic idempotency keys.
An executor restart re-observes the same API job; one digest-checked checkpoint
resume is allowed, while a deadline causes cancellation and a visible terminal
system error. Coverage-only cases are never submitted. Unsupported selected
cases receive deterministic held outcomes and knowledge-gap IDs without a
model call. Full answer prose is encrypted; normal outcome, gate and review
files contain only safe IDs, hashes, states, scores and timings.

Neither command has been run for a real Live60 candidate. The repository has no
Live60 authorization, generation outcome or answer artifact merely because the
executor exists.

## Supporting control planes

Live60 does not run research work through the answer FIFO. A separately leased
`ResearchWorker` owns durable official-source update, gap-research and bounded
discovery tasks. It admits only reviewed adapters plus fixed public taxonomy,
citations or stable authority identities; raw questions and arbitrary URLs are
not network inputs. Its queue enforces the sealed priority, aging, capacity,
candidate and per-origin concurrency rules. Results enter encrypted quarantine
and human review. They never approve/supersede a source, rebuild an index,
promote ACTIVE or rewrite an already released answer.

The daily and weekly HKT schedules are installed disabled. The connected worker
is not started by the first-live launcher and remains unavailable until after a
successful local E2E run and separate connected-crawler canary. This preserves
the first Live60 run's local-only, zero-network requirement.

The unified owner inbox stores append-only `debug`, `missing` and
`answer_feedback` projections. Free-text notes are encrypted and feedback
targets are checked against the released answer. Uploads are encrypted,
request-scoped and non-authoritative; submission for source review creates only
a quarantined intake record. The safe retrieval cache contains build-bound IDs,
ranks and scores only, bypasses uploads/online results and is invalidated across
ACTIVE pointer changes.

Owner-safe projections are separated under `logs/events`, `logs/metrics` and
`logs/traces`. Every Live60 evaluation trace is retained; ordinary INFO is
deterministically sampled at 10%, while WARN/ERROR/FATAL are retained in full.
`local-e2e-provisional-v2` reports latency and reliability indicators but is
observe-only, not an SLA, legal-quality claim or promotion gate.

## Owner-view integration

`LiveSuiteAdminReader` is the read-only evaluation-layer projection for v2
Live60 runs. It exposes `list_runs()`, `run_detail(run_id)` and
`released_answer(run_id=..., case_id=..., pass_number=1)`. List and detail
views return only safe IDs, hashes, counts, states, timings and allowlisted
safe artifacts; they never decrypt questions or held answers. The released
answer method revalidates every hard-gate flag, the encrypted artifact digest,
private-path canaries and configured owner identifiers before returning prose.

The existing `Live30AdminReader` remains unchanged. The loopback admin API
dispatches to the appropriate reader from the immutable run-manifest schema,
and the SPA uses its generic run/case views. Live30 compatibility therefore does
not require a duplicate Live60-only HTTP surface.

## Readiness and Word review exports

When the Live60 bundle is present, production readiness v6 validates it and
does not fall back to Live30 if the successor manifest, lineage or run plan is
invalid. Technical readiness still requires the source/privacy gates, frozen
retrieval benchmark, current-date authority candidate, all-issue expert overlay
(at least one reviewer: the owner; second review optional), Stage A thresholds, owner ACTIVE promotion,
rollback/re-promotion, real-browser recovery and the local-only runtime profile.
O-04 is a later,
separately sealed execution authorization; `real_e2e_authorised` remains false
until it is bound to the same run, ACTIVE build and exact selected IDs.

After a completed run has a privacy-passed `review-export.json`, create the
owner review bundle with:

```bash
uv run python scripts/export_live_evaluation_review.py \
  --run-id <run-id> \
  --output-dir <owner-review-directory>
```

This creates one all-60 control DOCX, Annexes A/B/C with the exact ten selected
outcomes in each, and a sealed `output-manifest.json`. The manifest remains
`docx_created_render_pending`; saving Word files is not layout approval. Render
each DOCX with the Documents renderer into
`rendered/<control|annex-a|annex-b|annex-c>/page-N.png`, open every page at 100%
zoom, then record the immutable gate only after inspection:

```bash
uv run python scripts/record_live_evaluation_render_gate.py \
  --output-dir <owner-review-directory> \
  --inspector-ref reviewer:<sha256> \
  --confirm-visually-inspected-all-pages
```

Held, failed and privacy-failed drafts are never decrypted. Their annex section
contains a safe diagnostic only. The control document contains no answer
plaintext; released answer plaintext appears only in its assigned annex.

No final Live60 DOCX or render gate exists yet. Export is deliberately
impossible until a complete, privacy-passed real run supplies the required
manifest and released outcomes.
