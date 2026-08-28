# LegalBot evaluation v1 — independent expert review checklist

This bundle is **evaluation-only**. System-proposed sources and spans are
**hypotheses**, not gold, until a legally qualified reviewer checks them against
the frozen approved corpus and signs the case.

**Manifest status:** `needs_independent_expert_annotation`
**Case status:** **240 / 240** are `needs_expert_annotation`. Expert-approved /
sealed: **0**. Do not fabricate approvals, sealed gold, or training exports.

**Related pack**

- Queue export: `data/review_queue/expert-review/` (run
  `uv run python scripts/export_expert_review_queue.py`)
- Quickstart: `docs/reports/expert-reviewer-quickstart-2026-08-13.md`
- Blind calibration: `benchmarks/evaluation/v1/blind-calibration-protocol.md`
- Status: `docs/reports/expert-review-pack-status-2026-08-13.md`

---

## Step-by-step workflow (every case)

### 0. Open the right materials

1. Pick the next `case_id` from `data/review_queue/expert-review/cases-needing-review.jsonl`
   (preferred order: `development` → `promotion` → `adversarial_holdout`).
2. Open the matching row in `benchmarks/evaluation/v1/draft-suite.jsonl` by
   `case_id` (do not paste long-form query text into shared chat or tickets).
3. Confirm the corpus freeze: only **current approved** primary-authority
   source versions may support gold spans.
4. Keep private notes in the evaluation vault / local encrypted store — not in
   git-tracked reviewer packs.

### 1. Frame the task

- [ ] Task type, subject, jurisdiction, as-of date match the legal question.
- [ ] Split is correct (`development` / `promotion` / `adversarial_holdout`).
- [ ] Expected behaviour is right: `answer` / `clarify_or_refuse` / `refuse`.
- [ ] Expected research and drafting routes make sense for the problem.
- [ ] `must_cover_issues` lists the issues a competent answer must address
      (for answer cases).

### 2. Accept / replace / remove every proposed source and span

Treat `acceptable_source_ids` and `exact_gold_spans` as **proposals**.

For each proposed span:

1. Locate the chunk by `chunk_id` / `source_version_id` in the approved catalogue.
2. Verify `content_hash`, `exact_locator`, and character offsets against the
   immutable chunk text.
3. Decide:
   - **accept** — span truly supports the bound issue(s) on the as-of date;
   - **replace** — record a replacement chunk/source/offsets/hash/locator;
   - **remove** — span is wrong, superseded, non-primary, or unboundable.
4. Bind each **accepted** span only to the `supported_issue_ids` it actually
   supports; drop over-claims.
5. For refuse / clarify cases, confirm that empty or absent gold spans are
   intentional and that the refusal/clarification grounds are sound.

Record span actions in a private decision-log row (see
`decision-log-template.jsonl` in the queue export).

### 3. Contrary and limiting authority

- [ ] Leading authority is present where the answer needs a governing rule.
- [ ] Add or confirm `known_contrary_authority_ids` / limiting authorities where
      conflict, hierarchy, or time-sensitivity matters (`multi_authority_*`,
      long-form, and any case where a competent answer must qualify the rule).
- [ ] Do not invent contrary IDs; only cite versions in the frozen approved set.

### 4. Lanes, prohibitions, rubric

- [ ] `forbidden_lanes` block teaching/assessment leakage as appropriate
      (typically `private_teaching`, `assessment_guidance`).
- [ ] `forbidden_source_ids` are correct for the trap (if any).
- [ ] Rubric remains human-gated: automated scores are lint only;
      `independent_human_required` stays true; pass mark 70.

### 5. Privacy (fail closed)

- [ ] Reviewer-facing notes contain **no** student names, emails, institutional
      person IDs, or absolute host paths (`/Users/…`, `C:\…`).
- [ ] Prefer `case_id`, `query_sha256`, opaque source/chunk IDs, content hashes.
- [ ] Do not copy marker-PDF / private teaching prose into case gold.
- [ ] `privacy_flags` (e.g. synthetic canaries) understood and preserved where
      they test refusal/injection behaviour.

### 6. Sealing and status (after a real human sign only)

| Split | Status after completed signed review |
|---|---|
| `development` | `expert_annotated` |
| `promotion` | `sealed` |
| `adversarial_holdout` | `sealed` |

Rules:

- Leave `needs_expert_annotation` until that case is **truly finished and signed**.
- Annotated/sealed answer cases must bind `corpus_manifest_sha256` plus accepted
  sources and exact gold spans (enforced by the suite loader).
- Promotion / holdout cases must be `sealed` (not merely `expert_annotated`)
  and must not be previewed during model tuning.
- Paraphrase families stay wholly inside one split.
- Any suite edit bumps to version `1.0.1+` with an explicit diff.
- Suite / benchmark becomes `approved` only after **every** included case is
  checked — never by bulk script approval.
- `eligible_for_training` / `training_export_allowed` remain **false** until a
  later owner phase. Promotion stays blocked until expert seal.

### 7. Blind 70+ calibration (separate gate)

After answers exist for a privacy-passed sample, a **second** marker who did not
create or tune the answers follows
`blind-calibration-protocol.md` (≥20 answers, ≥5 subjects, double-mark ≥20%).
That calibrates the lint signal; it does **not** mint evaluation gold by itself.

---

## What not to do

- Do not mark bulk cases approved or sealed.
- Do not unlock Find Case Law from this pack.
- Do not treat the **99 approved assessment standards** (drafting guidance) as
  evaluation gold.
- Do not export the suite for training.
- Do not put private student materials or absolute local paths into shared notes.

## UI note

Admin Dashboard review (`/api/v1/admin/reviews`) covers **source_version** and
**assessment_rule** queues only. Evaluation-suite expert annotation is
**file/checklist based** for now (suite JSONL + this checklist + queue export).
A later UI would need: case-ID queue, span accept/replace/remove against the
approved corpus, private signed decision log, and no query-prose leakage into
shared surfaces.
