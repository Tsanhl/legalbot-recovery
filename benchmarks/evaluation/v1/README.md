# LegalBot evaluation suite v1

This directory is the evaluation source of truth, not a training-data export.

The manifest fixes the required 240-case composition and 144/48/48 split. The
suite remains in `preparation` until a legal-domain reviewer binds each answer
case to qualified source-version IDs and exact immutable gold spans. The loader
in `backend/app/evaluation/suite.py` refuses cross-split paraphrase leakage,
empty gold evidence on annotated answer cases, and incomplete promotion suites.

The 16 owner-supplied long-form questions belong only to development because
they have already been seen. They must not be copied into promotion or
adversarial holdout records.

`development-drafts.jsonl` freezes those questions without pretending that
they have expert gold evidence. They remain `needs_expert_annotation` until a
reviewer selects acceptable authorities and exact spans. Regenerate the file
deterministically with `uv run python scripts/seed_phase8_development.py`.


## Independent expert review

The suite remains `needs_independent_expert_annotation` until a legally
qualified human reviews every case. Do not fabricate gold.

- Checklist: `expert-review-checklist.md`
- Blind calibration: `blind-calibration-protocol.md`
- Reviewer quickstart: `docs/reports/expert-reviewer-quickstart-2026-08-13.md`
- Pack status: `docs/reports/expert-review-pack-status-2026-08-13.md`
- Privacy-safe queue export (IDs/hashes only; does not approve cases):

```bash
uv run python scripts/export_expert_review_queue.py
```

Artefacts land under `data/review_queue/expert-review/`.

`training_export_allowed` stays **false** and promotion stays blocked until
expert seal. The **99** approved assessment standards are drafting guidance
only — they are not evaluation gold.
