# LegalBot v1.11 certification run, trace and incident layout

This document freezes the private owner-review projection required before any real
Development 30 run. It defines structure and redaction only. It does not create private
roots, lane membership, a split secret, signing authority, a model run or release
authority.

## Authority and privacy

The immutable upstream JSON package remains authoritative. A dated folder and its DOCX
are create-only owner projections generated only after strict verification of the
upstream package. They cannot change a verdict, authorize a gate or become model input.

Development, sealed Validation and live use three distinct private, non-synchronised
roots. No root may fall back to another root. The real absolute paths and permissions are
introduced only through the applicable signed owner decision; committed examples use
placeholders.

Ordinary logs and low-cardinality traces must not contain question or answer text,
prompts, evidence content, source text, credentials, session secrets, owner identifiers,
private paths or hidden reasoning. Those fields belong only in the access-controlled
case projection or an encrypted, retention-bound diagnostic bundle.

## Dated lane layout

Dates use ISO 8601 (`YYYY-MM-DD`) and each execution has a unique run ID. A display label
such as “2026-08-23 first Development 30” is metadata, never the stable identity.

```text
<lane-private-root>/
  runs/
    YYYY-MM-DD/
      <lane>-<run-id>/
        manifest.json
        completion.json
        logs/
          events.jsonl
        traces/
          spans.jsonl
          index.json
        metrics/
          run-metrics.json
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
              OWNER-NOTES-TEMPLATE.md
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

Before O-04, Validation custody contains only the sealed split/custody artifacts required
to prove exclusion. A Validation run folder using this schema is created only after valid
O-04 verification and controlled unsealing. Development and live tooling may never
enumerate the custody root. Live findings use a third root and can affect only a later
certification cycle.

## Required bindings

`manifest.json` binds at least:

- schema and projection-generator versions;
- lane and split-manifest digest;
- run and release IDs;
- exact Git commit and tree;
- candidate, manifest, seal and index-tree digests;
- contract, prompt, model, reviewer and configuration identities;
- dependency locks and runtime identities;
- upstream package and projection digests;
- owner authorization record that permitted the run;
- creation time, completion state and case inventory;
- retention class and expiry for questions, answers, held drafts, debug bundles and owner
  feedback;
- destruction/reconciliation policy, permission/root-capability proof and full safe-trace
  retention status.

`manifest.json` binds the planned inventory and upstream package. `completion.json` is
written last and binds the manifest digest and ordered per-file digest inventory,
excluding `completion.json` itself. No file claims a digest closure containing its own
bytes.

Every case directory binds its opaque case/issue identity to the same snapshot. Question
and answer Markdown files are exact owner-readable projections; they are never ingested
into retrieval. `ANSWER.md` exists only for `verified_full`. Otherwise `HELD.json`
records typed safe metadata and an encrypted held-draft reference; held or partial answer
prose is never written in plaintext and no placeholder is represented as an answer.

Generated projections are immutable. `OWNER-NOTES-TEMPLATE.md` is an unfilled template,
not an editable part of the run. Owner notes and decisions are submitted as separately
bound append-only feedback/decision artifacts. A post-review DOCX is a new create-only
companion identity and never overwrites the original run package.

## Events, traces and metrics

The normal event stream records bounded identifiers, stage, timestamps, duration,
memory high-water mark, tokens when available, retry and lease state, cancellation,
failure classification, fingerprint and publication state. Missing sidecar telemetry is
recorded as `unavailable` with a reason; it is not converted to zero or omitted.

Trace references cover queue admission, claim/heartbeat, retrieval, reranking,
frozen-evidence persistence, generation, verification, release transformation,
packaging, publication and private snapshot-serving replay. For Development and
Validation, `spans.jsonl` retains the complete safe span set; sampling is insufficient.
The trace index and case references bind its content digest and immutable byte ranges.

Required run and case metrics include:

- queue depth, admission, wait, capacity and single-worker ownership;
- lease, heartbeat, retry, repeated-fingerprint, cancellation and stale recovery;
- stage latency, timeout, completion, tokens, memory and free-memory admission;
- no-partial-publication and snapshot-consistency outcomes;
- unsupported material claims, false quotations and unresolved/invented authorities;
- wrong source, version, jurisdiction, effective date or currentness;
- contradictions, issue completeness, claim-to-evidence coverage and citation resolution;
- abstention/held-result quality and answer truncation or section loss;
- deterministic and AI-review completion, discrepancy and pending owner-disposition
  counts. A later bound decision summary supplements the pending counts.

Metrics are risk indicators, not proof that hallucinations are impossible. A quality
claim passes only through the frozen deterministic contract and applicable owner gate.

## Incident dossiers and stop rules

Each material failure has a stable fingerprint and a dated incident dossier containing:

- typed symptom and affected stage/case/job;
- first and last occurrence, occurrence count and retry history;
- safe reproduction details and evidence references;
- root-cause state and invalidated gates;
- fix commit, regression reference and verification result where applicable;
- owner waiver or disposition where required.

After the same retry-circuit fingerprint occurs twice for the same job, case, stage,
snapshot and materially unchanged condition, automatic execution stops before a third
attempt. No automatic loop or unchanged-condition rerun is permitted. A later owner-
authorized remediation cycle requires changed, bound inputs and applicable invalidation.
Synthetic/preflight attempts and frozen intra-case retries use separate counters. After
the first committed real generation request, only a same-run authenticated resume is
possible; no different fingerprint or prior signature authorizes a second 30-answer
batch.

Failure to persist an authoritative database audit record on an authority-changing
transaction fails closed. Failure of a disposable JSONL/trace projection does not
reverse or corrupt durable business state, but marks the certification package incomplete
and blocks package completion until it is reconciled from authoritative records.

## Reviewer and quality separation

Deterministic review and AI advisory review are stored as separately bound artifacts.
Storage separation does not establish model independence; the manifest records the
frozen independence classification. The AI reviewer does not receive the deterministic
verdict. Deterministic hard-stop cases record
`NOT_INVOKED_DETERMINISTIC_HARD_STOP`. A later discrepancy record compares eligible
results. AI cannot cure a deterministic failure. AI output records concise findings and
evidence references, never hidden chain-of-thought.

The initial owner DOCX contains a navigable run summary, all authorized Development
questions and their verified-full answers or held records, evidence/reviewer summaries,
quality/runtime findings, proposed generic/specific improvements and decision fields
marked pending. Signed owner feedback is later stored as an append-only decision
artifact. A post-review companion DOCX may summarize it but never overwrites the initial
document. Each DOCX states its non-authorizing projection status and exact source package.

## Knowledge-gap firewall

`gaps.json` is diagnostic evidence only. Nothing in a case, reviewer, incident or owner
folder is automatically indexed, embedded or exposed to the answer path.

Permitted promotion is layer-specific:

- verified official primary-source bytes enter quarantine/staging and require human
  qualification, a new sealed candidate and all invalidated gates;
- gold corrections create a new versioned evaluation artifact only;
- generic rules enter versioned code/policy/prompt/verifier only after owner approval and
  regression testing;
- case-specific observations remain diagnostic and cannot become case-ID runtime rules;
- Validation and live findings apply only to a later certification cycle.

The controlled states are:

`OBSERVED -> REPRODUCED -> EVIDENCE_CONFIRMED -> OWNER_APPROVED -> IMPLEMENTED -> VERIFIED -> CERTIFIED`

## Readiness condition

Before Development authorization, synthetic fixtures must prove schema validation,
strict upstream replay, private-root separation, permissions, create-only projection,
redaction, complete question/answer-or-held coverage, DOCX rendering, incident linking,
missing-telemetry treatment and clean failure on drift. Synthetic proof does not
authorize or consume a real Development run.
