# Live evaluation 30 v1

This package is the immutable, owner-supplied 30-question local-live evaluation
suite. It is evaluation input only; it is not training data and cannot be
exported for training.

The canonical registry is `cases.jsonl`. Each row contains the exact supplied
question, its SHA-256, a SHA-256 over the complete immutable record, the frozen
word target and routes, conservative must-cover issues, and structural-standard
IDs. `manifest.json` is created once from the verified registry and must never
be rewritten in place.

Runtime registration copies every complete case record into an encrypted file
under:

```text
data/evaluations/e2e/runs/<run_id>/
  manifest.json
  coverage-summary.json
  aggregate-metrics.json
  cases/<case_id>/
    case.json
    question.enc
    coverage.json
    retrieval.json
    evidence-map.json
    metrics.json
    artifacts/
      answer/<artifact_id>.enc
      human_review/<artifact_id>.enc
      issue_detail/<artifact_id>.enc
      knowledge_gap_detail/<artifact_id>.enc
```

The normal append-only logs are:

```text
logs/e2e-run-events.jsonl
logs/e2e-case-index.jsonl
data/evaluations/e2e/metrics/
data/evaluations/e2e/traces/
```

Those logs contain only allowlisted IDs, status, attempts and timings. They do
not contain questions, answers, review prose, source text, filenames or local
paths.

Registry and run-registration commands do not run the model:

```bash
python scripts/live_evaluation_30.py verify
python scripts/live_evaluation_30.py freeze-manifest
python scripts/live_evaluation_30.py create-run --run-id e2e-live30-20260814 \
  --model-version MODEL --index-build-id BUILD --prompt-version PROMPT \
  --router-version ROUTER --classifier-version CLASSIFIER \
  --policy-sha256 SHA256 --assessment-rules-sha256 SHA256
```

The coverage-first stage runs the real sealed candidate retriever but never
generates an answer:

```bash
python scripts/live_evaluation_30.py coverage \
  --run-id e2e-live30-20260814 --build-id SEALED_CANDIDATE
```

It records top IDs, locators, scores and timings for every must-cover issue.
Because the immutable question registry deliberately has empty expert-gold
fields, an unqualified coverage pass leaves Recall, MRR, nDCG and exact-span
recall as `not_evaluated_without_expert_qualification`; the runner never turns
a nearest vector into proof that a legal proposition is supported. Candidate passages
are presented for expert span review, and any empty issue creates a hash-only
knowledge-gap record.

The source/span decision is a separate, prose-free, owner-approved overlay. A
template can be created, but the command does not approve or seal it:

```bash
python scripts/live_evaluation_30.py qualification-template \
  --run-id e2e-live30-20260814 \
  --output data/review_queue/live30-expert-qualification-template.json
```

After legal expert review, every must-cover issue has an explicit immutable
status: `qualified`, `limited` or `knowledge_gap`. Qualified and limited issues
bind reviewed privacy-safe source/version/locator/span identities; a knowledge
gap binds a safe reason code and contains no fabricated gold. The derived case
status uses the same three values. The final overlay uses
`approval_status=expert_approved` and a canonical `seal_sha256`.
Coverage then accepts it explicitly:

```bash
python scripts/live_evaluation_30.py coverage \
  --run-id e2e-live30-20260814 --build-id SEALED_CANDIDATE \
  --expert-qualification OWNER_APPROVED_SEALED_OVERLAY.json
```

Execution remains disabled until all 30 cases have sealed issue dispositions
and a complete coverage pass against the subsequently owner-promoted ACTIVE
build. Ranking metrics score only complete, qualified issues that have
reviewed gold; limited and explicit knowledge-gap issues are excluded from
their denominators because their gold is knowingly incomplete or absent.
Preflight enforces Recall@5 = 1.0, Recall@10 >= 0.95 and MRR >= 0.8. Each case
with exact qualified coverage may generate. A limited case receives a
deterministic no-model held record labelled `expert_qualification_limited`; a
knowledge-gap or retrieval-failed case receives its corresponding held record.
Neither invalidates qualified cases or forces unsupported prose. The controlled run
is serial, loopback-only and forces `online_mode=local_only`:

```bash
python scripts/live_evaluation_30.py execute \
  --run-id e2e-live30-20260814 --pass-number 1

python scripts/live_evaluation_30.py execute \
  --run-id e2e-live30-20260814 --pass-number 2 --stability-sample
python scripts/live_evaluation_30.py execute \
  --run-id e2e-live30-20260814 --pass-number 3 --stability-sample
```

After the 30 first-pass and 18 repeated-sample outcomes (48 total) are all
terminal, finalise the safe master-review contract and then render the DOCX:

```bash
python scripts/live_evaluation_30.py finalize-review \
  --run-id e2e-live30-20260814
python scripts/export_live_evaluation_review.py \
  --run-id e2e-live30-20260814 \
  --output LegalBot-Live-Evaluation-Review-e2e-live30-20260814.docx
```

The executor always sends the immutable run/case headers and an idempotency
key, polls one job at a time, cancels a timed-out poll, records every terminal
state and encrypts every captured answer. Only an answer that independently
passes release, privacy and evidence checks also receives a mode-0600
`released-answer.md` (or per-pass stability variant). Held, evidence-failed
and privacy-failed artifacts are never opened by the review exporter.

The observability targets are provisional internal SLOs, not an external SLA
or a promotion gate. Metrics cover queue age/depth, progress freshness,
completion and stage p50/p95/p99, success/error budget and resource use. Safe
traces identify DB, retrieval, rerank, opaque section generation, verification,
repair and release spans without questions, answers, prompts or source text.
The 30-case evaluation keeps complete safe traces; ordinary INFO operational
logs use deterministic 10% sampling, while WARN/ERROR/FATAL are retained in
full.

The complete registry gate requires 30 ordered IDs (`live30-q01` through
`live30-q30`), a total requested output of 115,000 words, and this distribution:
five cases at each of 1,000–5,000 words and one case at each of 6,000–10,000
words. The deterministic stratified sample is Q1, Q3, Q7, Q9, Q13, Q17, Q25,
Q27 and Q30. Each registry row uses `as_of_policy=run_date`; run creation freezes
the actual date into the encrypted case input and safe run manifest.
