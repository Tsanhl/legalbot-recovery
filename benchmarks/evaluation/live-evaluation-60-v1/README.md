# LegalBot Live60 v1

This directory is the immutable, evaluation-only question and run-plan
contract for the controlled Live60 development evaluation. It does not contain
expert legal gold, an index candidate, an owner promotion, live authorization,
generated answers, or training data.

The accepted baseline remains **NO-GO**. A run is not authorised merely because
this bundle validates.

## Artifacts

- `cases.jsonl` is the exact 60-question registry. Its first 30 records are
  byte/canonical-identical to the sealed Live30 registry; Q31-Q60 use the v2
  case schema and preserve the supplied question text.
- `manifest.json` binds every question and record hash, the Live30 lineage,
  source/memo digests, evaluation-only flags, and the run-plan file.
- `generation-run-plan.json` dispositions all 60 cases. Thirty are
  `generate_once`; the remainder are `coverage_only_not_selected`.
- `source-questions-31-60.sha256` records the digest of the owner attachment.
- `accepted-no-go-memo.sha256` records the accepted memo digest.
- `schemas/` contains the machine-readable v2 case, suite, run-plan and expert
  overlay contracts. The sealed Live30 v1 schemas are not changed.

## Fixed totals

- Registry: 60 questions, 215,000 requested words, 39 problems and 21 essays.
- Generation: 30 unique single-pass answers, 114,000 requested words,
  19 problems and 11 essays.
- Routes: 15 sectioned and 15 full-enquiry.
- Annexes: A, B and C contain ten selected cases each in fixed order.
- Legal date: the Europe/London calendar date at run admission.

## Legal-gold gate

All 60 cases require an owner-sealed expert overlay. The owner is the one
primary qualified England-and-Wales reviewer. Independent second review is
optional. AI may only exact-match hashes and locators of spans the owner
actually uses; it cannot be a reviewer and cannot seal gold.
Every must-cover issue must be marked `qualified`, `limited`, or
`knowledge_gap`. Retrieval scores may be reported only for qualified issue
gold. No question text, nearest-vector result, teaching note, feedback rule or
unreviewed source is legal gold.

The application can generate a deliberately unsealable annotation template
through `scripts/live_evaluation_suite.py`. It must not be converted into a
sealed overlay without the owner binding exact evidence.

Finishing the 585 issue ticks does not authorise live 30-case generation.
Stage A, ACTIVE, rollback, browser recovery, readiness v6 and O-04 remain
separate owner gates.

## Compatibility

The loader revalidates the raw sealed Live30 registry and manifest and compares
the first 30 records exactly. Removing those legacy inputs, changing a record,
changing a run-plan disposition, or changing any seal makes this bundle fail
closed. Historical Live30 readers and outputs continue to use their unchanged
v1 contract.
