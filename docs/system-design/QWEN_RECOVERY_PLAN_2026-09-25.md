# Qwen recovery plan (25 September 2026)

Maintained working plan. It does not by itself create training, ACTIVE,
promotion or live authority; each loop step below names the owner gate it needs.

## 1. Diagnosis: why every answer "fails"

| # | Finding | Evidence | Is it Qwen/training? |
| --- | --- | --- | --- |
| 1 | The chat's reviewed index contains **two sources**: Consumer Rights Act 2015 and one commencement order (England, 5 Sept). | `data/development-runtime/shared-chat-20260923-r29/GE-QWEN-DEVELOPMENT-RETRIEVAL.json` | No |
| 2 | All 40 campaign conversations (20 Qwen, 20 Codex) ended `healthy_retrieval_zero_hits`. **Qwen was never invoked** (`substantive_generation_attempted=false` on every row). | `docs/testing/CHAT_CAMPAIGN_2026-09-23_RESULTS.json` | No |
| 3 | Online fallback rejects whole instruments for `official_unapplied_effects_present`, point-in-time mismatch, 403/network, or "requires review". So the gap is never filled. | same file, `evidence_rejection_reasons` | No |
| 4 | A sealed, integrity-passed, `promotion_eligible` England-and-Wales index already exists (85 sources, 149,855 chunks, same embedding/reranker models) but is **not wired to the chat**. | `data/indexes/builds/current-law-ew-full-fp16-v111-20260829-recovery-b/` | No |
| 5 | When a model does draft (Codex r17–r26, on consumer law only), the two reviewer stages hold it: per-claim support, atomic-claim heuristics, exact evidence-ID copying, word budget, and repairs that grow instead of shrink. **Even GPT-5.5/6-Astra never passed.** | `docs/testing/SHARED_CHAT_CONTINUATION_2026-09-23.md` | No: the gate is stricter than any model currently meets |
| 6 | The only Qwen quality test (4 Sept, 23 cases): base 8/23 and LoRA 8/23 full passes. About 8 of 15 failures per variant **ended mid-sentence** at a 320-token eval ceiling. The rest omitted a material point or added a claim outside the supplied span. | `data/evaluations/general-enquiries/LegalBot-GE-2026-09-04-fresh-visible-adapter-evaluation-r2/CODEX-REVIEW-WITH-VARIANTS.jsonl` | Partly: omissions and out-of-span claims are real model behaviour |
| 7 | The only LoRA had 9 training rows, 30 steps, 1 test row. It is too small to change behaviour, and it is correctly inactive. | `.../answer-weight-training-r2/` | Training was not the cause; it was too small to help |

**Conclusion.** The failures come from the pipeline, not from Qwen weights.
The retriever almost always returns nothing, so no model gets to answer. When
evidence exists, the reviewers reject answers from every model, including
stronger ones. Training Qwen now would not change a single result.

Essay and PB quality: the 23 Sept final check produced 2 essays + 1 PB (Codex
diagnostics). All held for evidence. There is no Qwen Essay/PB measurement at
all. GE is the only mode with Qwen numbers (point 6).

## 2. Fix order (system first, model last)

### Loop A: retrieval coverage (blocks everything)
1. Register `recovery-b` as a **non-ACTIVE development candidate** for the chat,
   alongside the consumer candidate. It is already sealed and integrity-checked.
   *Owner gate: allow a built_unscored sealed index as a dev-chat candidate.*
2. Change the online-fallback currentness rule from "hold the whole instrument if
   any unapplied effect exists" to "hold only if an unapplied effect touches the
   retrieved provision". Keep the hold and add a visible caveat for the others.
3. Exit check: rerun the frozen 40 questions for **retrieval only** (no model).
   Target: ≥ 30/40 in-scope E&W questions return ≥ 1 relevant provision.

### Loop B: reviewer calibration (use Codex as the control)
1. Replay the retained r19–r26 drafts offline against the reviewers. Log each
   hold reason by fingerprint.
2. Fix the reviewer defects, not the model: evidence-ID copying (have reviewers
   return a short index and let the host map it to the ID); word budget measured
   on substantive text only; a repair must not increase length; atomic-claim
   heuristic false positives.
3. Exit check: Codex publishes ≥ 1 supported GE answer on the frozen consumer
   fixture, then ≥ 7/10 GE campaign cases. If Codex cannot pass, Qwen will not.
   Keep calibrating the gate.

### Loop C: Qwen on the same packets (measure before training)
1. Same qualified evidence packets as Codex; Qwen 1,600 output tokens (runtime
   value, not the old 320 eval ceiling).
2. Score 20 cases per mode: 10 GE / 5 Essay / 5 PB. Categorise every failure:
   truncation, omission, out-of-span claim, format/JSON, latency.
3. Exit check: a failure table. Only model-specific categories (omission,
   out-of-span, JSON) justify training.

### Loop D: training (only if Loop C shows model-specific errors)
1. New exposed training questions, written fresh. Never from campaign cases, the
   retired 306 bank, the Codex unseen bank or private chats: 40 GE / 10 Essay /
   10 PB. The 60 sample questions stay in the authorised 60-example envelope.
2. Targets come from Codex answers that **passed** Loop B's reviewers on the same
   evidence packets (distillation of a verified route).
3. Limits: ≤ 100 steps, ≤ 2 h, ≤ 12 GB (16 GB host). 48 train / 12 validation.
4. Exit check: rerun Loop C's 20 cases. Adapter must beat base with zero factual
   regressions. It stays inactive until the owner approves.
   *Owner gate: training dispatch; adapter activation.*

### Loop rules (as the previous Codex loop)
- Each loop iteration: run, then fingerprint failures, then make one targeted
  change, then rerun only the affected cases.
- Same fingerprint fails twice after repair: stop and report. No third retry.
- Never rerun unchanged inputs. Preserve every attempt directory.

## 3. Other design issues found

- The chat launcher pins one subject (`--subject consumer-law`), so the design
  can serve only one area at a time. Loop A needs multi-subject candidate
  support.
- Qwen evidence budget is 8,500 chars (~2 statute sections) vs 45,000 for
  Codex. After Loop A, raise it once the 8k context is measured, or move Qwen to
  a 16k context (the 9B model supports it; check memory on the 16 GB host).
- 16 GB host: Qwen 9B 4-bit (~5.6 GB) + embedder + reranker + web/API all run at
  once. Watch for swap during Loop C latency tests.

## 4. Workspace cleanup inventory (awaiting owner scope, nothing deleted)

| Item | Size | Nature |
| --- | --- | --- |
| `.mypy_cache`, `.ruff_cache`, `.pytest_cache`, `.hypothesis` | ~300 MB | Tool caches, regenerated automatically |
| `.ge-auto-index-tests-*` (3) | ~6 MB | Leftover test scratch dirs |
| `tmp/` | 49 MB | Retired dashboard, removed Cursor files, PDFs, planning |
| `output/` (qa, docx, pdf, zip, logs) | ~860 MB | Rendered review outputs |
| `Log/`, `logs/` | ~11 MB | Controller logs |
| `8-17 review/`, `Live60-2026-08-16/` | <1 MB | Old Live60 review packs (tracked in Git) |
| `recovery/2026-08-29/catalogue-backups` | 12 GB | 29 Aug catalogue backups |
| `data/backups/LegalBot-Phase2-2026-09-01-entry` | 14 GB | 1 Sept catalogue backup + restore drill |

The backups are the current recoverable backup and its predecessor. The
backup-pruning rule says to keep both until a newer restore drill exists.

## 5. Owner decisions, 25 September (later the same day)

- **Qwen only.** The hosted-API (OpenAI/Claude/Gemini), local-endpoint and Codex
  answer routes were removed from the backend, the chat authority, the launcher
  and the web UI. Session connections remain only as the session-to-Qwen
  ownership binding; API-key storage was removed. Codex-only diagnostic scripts
  were removed (Git history keeps them).
- **One unified index** at `data/indexes/unified-local-v1/` (built by
  `scripts/build_unified_local_index.py`): every non-duplicate citable
  authority, scholarship and official-secondary document, reviewed or staged,
  one row per unique chunk text, with recovery-b vectors reused by text hash.
  `review_status`/`currentness_status` travel with each row. The old consumer
  index is retired from serving; the 52 old chat run folders go to Trash only
  after the unified embedding completes.
- **Research mode now, verification pass over time.** Unreviewed sources may
  reach Qwen, but each dependent claim is labelled "unverified source" instead
  of hard-blocked; an automatic identity/currentness pass (legislation.gov.uk,
  Find Case Law) upgrades sources to verified. Not yet implemented.
- **Two reviewers:** (1) deterministic: exact-quote and citation-identity
  matching against retrieved evidence; (2) Qwen in a fresh context, per claim,
  sees only the claim and its evidence.
- **Private teaching notes** are rewritten per document by Qwen in its own words
  (about one day of local generation), then embedded in a separate teaching lane
  that is never cited as authority.
- 1,508 source versions lack real titles (filenames stripped for privacy);
  titles will be extracted from each document's first page after embedding.

## 6. Gaps found against the reference Q&A-agent design (25 September)

| Design layer | Status |
| --- | --- |
| Hybrid search (vector + keyword) | Added: the unified retriever fuses BM25 and vector results (reciprocal rank), then reranks. Needs `scripts/index_unified_local.py` after embedding. |
| ANN vector index | Added to the same script (IVF-PQ for tables with 20k+ rows). |
| Relevance floor / refuse weak context | Added: provisional reranker floor 0.10 (`LEGALBOT_RESEARCH_MIN_RELEVANCE`); rerank scores are logged for calibration in the baseline run. The frozen policy threshold was never calibrated. |
| Conversation-aware query rewriting | Still missing for the chat: rewriting is disabled and, when enabled, replaces the drafting question too. Needed: a Qwen rewrite used for retrieval only. Do it in the hardware-test step. |
| Incremental freshness (write-then-delete) | Partial: the builder adds new source versions but does not remove superseded rows. |
| Token streaming to the client | Intentionally not done: answers are released only after review; progress stages stream over SSE. |
| 2–3 s latency, high availability | Not applicable to a local 9B model on one Mac; answers take minutes. |

## 7. Progress, 25 September (afternoon)

- **Follow-up query rewriting (done, untested on real Qwen):** in research mode a
  chat follow-up is rewritten by Qwen into a standalone query used only for
  subject routing, teaching-note lookup and issue queries; drafting still sees
  the full conversation. Rejected rewrites (e.g. invented facts) fall back to
  the full question. Checkpointed so retries do not call the model again.
- **Titles (partial):** `scripts/extract_unified_titles.py` writes
  `data/indexes/unified-local-v1/TITLES.json` (catalogue unchanged). Rules give
  good titles for about 570 of 1,508 untitled sources; about 930 remain for a
  Qwen pass after embedding. It flags 51 of the owner's own drafts
  (`student_work`, currently filed as scholarship) and 195 misfiled sources
  (lecture handouts, textbook chapters and articles in the authority lane).
  These must be excluded or re-laned before the index is used for answers.

## 8. Progress, 25 September (evening)

- **Lecture notes (done, law-only):** 124 of 128 decks were rephrased, then cut
  on the owner's direction to law-only summaries (rules with their cases and
  statutes; no lecture structure, examples or explanation) in
  `data/knowledge/lecture-notes/`. Four pensions decks are skipped, and the two
  pensions notes are cut to statute and case points only, because the slides
  forbid AI use (`_SKIPPED.txt`).
- **Knowledge lane (built, not yet embedded):** `scripts/build_knowledge_lane.py`
  keeps only law and rules. It drops reflection questions, worked examples,
  exam and essay technique, debates and statistics (96 notes, 451 chunks, 33
  sections dropped). It writes `knowledge-lance/` inside the unified index. Run it
  after the main embedding finishes. The retriever feeds these notes to issue
  spotting only. Each note becomes an extra search query made of its heading and
  the authorities it names, so the citable statute or case is retrieved from the
  authority index. Note prose is never evidence or cited.
- **EU and comparative material (done):**
  - Forum-law sources are served as before.
  - EU or foreign sources are served in full when the question names that system
    (for example "Article 34 TFEU").
  - Otherwise they are comparative context: at most 3, with a relevance of 0.30
    or more, and labelled with their jurisdiction.
  - Every claim relying on them must name the system. The drafting prompt, the
    evaluator and the evidence reviewer all enforce this.
- **Research-mode release blockers (fixed; found while checking):**
  - Research spans had no relevance-threshold flags and a route the evaluator
    did not accept, so every claim would have been hard-blocked. They now carry
    the reranker score and floor.
  - The strict "fully qualified evidence" chain certificate is not issued in
    research mode.
  - All unified-retriever spans take the labelled research path.
- **Official-record verification (running):** `scripts/verify_unified_sources.py`
  checks unreviewed sources against legislation.gov.uk and Find Case Law.
  - Legislation: identity, and whether the local copy is the latest revised
    version (outstanding amendments are counted).
  - Judgments: neutral citation and name; normally byte-identical to the
    official XML. Later treatment cannot be checked automatically.
  - Results go to `VERIFICATION.json`. The retriever then renders proper OSCOLA
    citations with a note of what was not checked. No re-embedding is needed and
    the catalogue is not changed.
  - This is an automated official-record check, not legal review.
  - About 600 untitled PDFs and Word files, and the 672 scholarship sources, need
    identification (Qwen titling) or a Crossref check before they can be
    verified.

## 9. Owner decisions, 25 September (night)

- **Only four source types may be cited:**
  - legislation;
  - case law;
  - journal articles;
  - books.

  `scripts/build_unified_exclusions.py` (schema v2) classifies every indexed
  source:
  - Teaching material (seminars, lectures, tutorials, handouts, slides, module
    guides, exam and revision material) is excluded.
  - The owner's own work is excluded.
  - Other types (official guidance, reports, web pages) are excluded.
  - Unidentified sources are held.

  The retriever skips excluded and held rows at query time. Held rows are
  released after Qwen titling, when the script is re-run. Teaching knowledge
  still reaches answers only through the law-only knowledge lane, and only as
  search hints.
- **The user's own uploaded documents can be cited.** In the chat, a paperclip
  button attaches PDF, Word, text, Markdown or HTML files.
  - In research mode, the most relevant passages (up to 12 passages, 12,000
    characters) are both given to Qwen as context and offered as citable
    evidence, labelled "Uploaded document N (supplied by you) [unverified
    source]".
  - The original filename never enters the prompt or the answer.
  - An uploaded file is never treated as primary authority. Unclassified uploads
    count as secondary material, and marking guides stay context-only.
  - Outside research mode the previous context-only behaviour is unchanged.
