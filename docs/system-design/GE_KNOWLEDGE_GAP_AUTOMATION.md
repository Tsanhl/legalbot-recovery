# UK/USA GE: bank completion, automatic research and indexing

Working plan, 5 September 2026. Implementation status: **execution in progress**
under the owner's “do in full then the plan” instruction. The isolated SQLite/
LanceDB module, source parser adapter, pinned inference wrapper, document repair
modules and prefreeze gate are implemented. Actual visible execution has produced
72 document embeddings, five query embeddings, five persisted generations and
eight pinned causal reranker scores. A separately reviewed seven-proposition
successor produced 402 document and eight query embeddings, with all 402 required
context rows retrieved from persisted SQLite/Lance generations. These receipts
remain distinct from final answer review. PDF/native extraction and raster OCR passed.
The complete case consumer and remaining visible checks are still being integrated;
no complete-feature or unseen result is claimed.

The owner's latest instruction authorizes automatic searching and indexing when
a knowledge gap is found: “also when doing any knowledge gap exists u can search
auto and index (chunks - embedding in) - to db”. The request also asks for full
planning. Earlier “Create, review, then run once; no training” remains in force.
Questions about training are not new authorization to change model weights.

## Present position

The current bank is `LegalBot-GE-2026-09-05-codex-unseen-r1`: 420 legal cases
(210 UK and 210 USA) and 23 separately scored system cases. At this planning
checkpoint 431 of 443 canonical drafts are structurally validated. The bounded
author repair produced five valid two-case parts and one timed-out part; its
12-slot canonical assembly is held. All attempts and the ten partial drafts stay
preserved, with no third author attempt. The continuous successor runs unrelated
construction and targeted repair, plus 36 novelty-review jobs for the 431 complete
questions. Earlier 24-case construction-review counts are historical. These are different stages, not additive
numbers of finished cases.
Only one of the first 24 construction reviews had all flags, no issues and agreeing
researcher flags; full sealing checks remain outstanding. No bank seal, runtime
freeze, candidate answer or unseen result exists at the checkpoint.

The running coordinator continues the previously authorized construction and
one-pass route. Its terminal receipts take precedence over this snapshot. It
does not yet implement this new database integration. Preserve all drafts,
failed attempts, original source bytes, fixtures and receipts. Never reopen the
retired 306-case bank or rerun the frozen 331 diagnostic.

The immediate work is **bank completion and non-weight improvement**, followed
by one unseen test when ready. An embedding is a representation used to retrieve
source text; generating one does not train the answer model or embedding model.

## Ordered work and exit evidence

| Work | Required output and exit condition |
| --- | --- |
| Finish construction | All 443 assigned cases accounted for, including explicit holds/errors; exact IDs, location, question hashes and exposure checks reconcile. |
| Repair construction defects | Replace prose-only fixture descriptions with the actual promised synthetic documents; verify rendered pages and extraction. Repair exact source/locator/currentness gaps. Preserve originals and review changed artifacts in a fresh reviewer context. Do not simplify hard questions to fit available law. |
| Build automatic research/index integration | Durable gap jobs, official-source adapters, reviewed chunk manifests, real embeddings, an isolated non-live index and a verified retrieval consumer. Report each component's implemented/tested state separately. |
| Verify the changed retrieval route visibly | Use clean visible scenarios and synthetic fault cases, independent of private bank content. Cover UK nations, US federal/state differences, documents, freshness, citations, search failure and cross-lane denial. Check changed components and affected regressions; do not replay the frozen 331. |
| Freeze the tested runtime and ready bank | Bind exact questions, turns, fixtures, reference evidence, scoring, models, prompts, source policy, parser, chunker, embeddings, indexes and executable runtime. All bank construction checks must pass. |
| Execute unseen once | Candidate sees questions and due uploads only, uses the declared retrieval/search policy, and never receives the private reference material. A separate Codex reviewer checks substantive answers. No repairs or second answer attempts after results. |
| Report and retire | Keep 420 legal and 23 system cases in their respective denominators. Report factual/quality results, abstentions, holds, system faults, actual costs and limitations. Retire the bank after the one-pass run. No automatic training, promotion or live activation. |

The timed-out author batch now has a bounded technical repair in progress: preserve its full
attempt and original assignments, divide the 12 slots into six two-case author
jobs, then verify and combine exact slot coverage in a fresh construction artifact.
Do not repeat the unchanged oversized job, invent missing rows or silently remove
the 12 cases. The failed batch has been preserved and six two-slot jobs dispatched. Targeted
reference and document repair jobs are now implemented; completed original and
revised artifacts require independent construction review.

Construction and the new retrieval implementation may proceed in parallel with
separate data. If the database feature is to be included in this bank's test, its
visible validation and exact runtime binding must complete **before** that test's
freeze; wire that prerequisite into the coordinator as part of integration.
If the current authorized route has already frozen or run, do not insert the new
feature into it or claim that result validates the feature. Validate the successor
visibly; a later fresh unseen bank would require its own creation/run authority.
The accepted execution instruction now binds a mandatory research-validation
gate before freezing. The old dispatch loop drained without killing workers; a
separate exact resume receipt will bind the changed coordinator.

## Automatic gap handling

1. **Classify the gap.** Bind a stable ID to its origin, issue, jurisdiction,
   relevant date, source/version/locator where known, and failure fingerprint.
   Check existing exact source versions and indexed passages before fetching.
2. **Search only where research can help.** Resolve the exact authority on official
   UK or US sources. Verify a new host's official identity before allowing capture.
   Search results, titles and snippets are discovery aids, not evidence.
3. **Capture and parse.** Keep raw bytes, canonical/final URLs, redirect chain,
   fetch time, content hash and parser version. Parse HTML/XML/PDF; perform actual
   OCR where needed. Missing, blocked, oversized or unreadable material stays held.
4. **Review the source for this proposition.** A separate Codex reviewer checks
   identity, authority type, jurisdiction, date/commencement, amendments/effects,
   material later treatment, exact locators, quote support and issue relevance.
   Record uncertain points explicitly. A government domain is not a legal pass.
5. **Make structural chunks.** Follow sections, subsections, paragraphs and document
   hierarchy. Carry definitions, conditions and exceptions needed to understand a
   passage. Preserve parent/context references rather than extracting an isolated
   favourable sentence. Bind each chunk to exact source text and page/locator.
6. **Embed approved retrieval chunks.** Use the existing pinned local embedding
   model and verified files; save the model revision, dimensions and recipe with
   each generation. Never substitute fabricated, random or test vectors.
7. **Build and verify the non-live database generation.** Persist source/review/job
   metadata in SQLite and lexical/vector retrieval in the existing LanceDB design.
   Verify counts, unique identities, text and vector bindings, dimension/finiteness,
   persisted read-back and retrieval of the intended passage plus necessary context.
8. **Re-retrieve and answer.** A successful insert is not a resolved knowledge gap.
   Close a gap only after the eligible retriever returns the relevant supported
   evidence and the affected claim passes review. Otherwise preserve a terminal
   hold with a precise reason and safe conditional guidance where appropriate.

| Gap class | Action |
| --- | --- |
| Missing controlling law or case authority | Bounded official research, capture and proposition review. |
| Stale/ambiguous legal date or amendment | Point-in-time/currentness research; retain both versions and identify applicability. |
| Source present but retrieval missed it | Inspect location/date filters, chunk boundaries, lexical search, embeddings and ranking; do not repeatedly download the same source. |
| Unsupported or conflicting proposition | Check the exact claim and contrary authority; narrow or hold the claim if support cannot be established. |
| Missing user fact | Ask a focused factual question or give supported conditional branches; more law cannot establish that fact. |
| Bad upload/OCR/fixture | Repair or request the document/extraction; never invent its contents. |
| Arithmetic, omitted exception or answer-generation error | Repair the responsible calculation/planner/answer logic on permitted visible material. No automatic weight training. |

Public sources remain distinct from synthetic/user facts, AI analysis and reference
answers. Store user-document information in its matter's protected evidence store,
not in the general legal-authority vector index. Do not send private facts in web
queries when a generalized legal issue will suffice.

## Storage and unseen isolation

| Store | Permitted content and reader | Exclusion |
| --- | --- | --- |
| Shared non-live research/evaluation index | Reviewed official law found through ordinary development or authorized user research; an eligible development/evaluation retriever | No private bank prompts, expected points, reference answers, candidate answers or test findings. |
| Private bank reference store | Official evidence selected by the private curator, reference points and construction review; curator/reviewer only, under the existing restricted bank root | Never preload into the candidate or shared development index, even when the underlying law is public. Source selection can reveal test expectations. |
| Candidate case-local retrieval store | Sources independently found by that candidate during its authorized answer, under its own role-restricted directory | No curator-selected sources or post-answer reviewer feedback. No sharing newly retrieved material between unrelated test cases. |

Use distinct storage roots and checked capabilities, not just a metadata filter.
At unseen start every case receives the same frozen shared baseline. Any allowed
online research follows a policy fixed before the run, produces case-local deltas,
and records bytes and timestamps. A case's own later turn may reuse its prior
evidence; other cases cannot benefit from its dynamic cache. The score then measures
an **open-book, tool-using workflow**, not closed-book model memory.

After scoring, do not export test questions, answers, reference-source selection,
reviewer findings or case-local index deltas into shared development/training.
Do not convert unseen failures into automatic repair tickets or training examples.
Further improvement must use independently sourced clean visible/user research,
consistent with the existing retired-bank exclusion. Preserve the test artifacts
for audit; retirement does not authorize deletion.

## Implementation against the current repository

| Existing component | What is present | Required integration work |
| --- | --- | --- |
| `scripts/run_ge_codex_unseen.py`, `scripts/ge_unseen_sources.py` | Separate-role UK/US browsing and raw source capture; verified technical capture corrections | Capture results currently do not automatically become chunk/vector DB entries. Add an explicitly scoped consumer without revealing private reference material. |
| `scripts/fill_ge_knowledge_gaps.py`, `backend/app/evaluation/ge_factual_gap_fill.py` | UK official-source gap fill and structural chunks in evaluation SQLite; manifests explicitly say embeddings are not enqueued | Add UK/USA issue adapters and origin/custody handling. Do not use its “latest results” default for an unseen bank or scan retired data. |
| `backend/app/research/control_plane.py` and research jobs | SQLite research queue/control-plane components | Add idempotent origin-bound gap jobs and per-stage terminal receipts. The legacy JSON `GapQueue` remains read-only. |
| `backend/app/retrieval/qwen.py` and pinned model manifest | Qwen3 Embedding 0.6B, 1024-dimensional vectors; Qwen3 Reranker 0.6B | Verify the installed model/revision and resource readiness before inference; connect only eligible chunks. No model replacement, new provider or full-corpus re-embedding. |
| `backend/app/retrieval/lancedb.py`, index build and hybrid retrieval | Immutable index generations, lexical/vector search and existing validation | Create a scoped non-ACTIVE successor and verify actual read-back. Reuse vectors only with identical source chunk, normalization and model identity. Preserve previous generations and interrupted builds. |
| `ge_index_build_authorization.py`, `ge_evaluation_index.py` | Existing exact-source and verifier-issued capabilities for a narrower visible-GE route | Implement a separate action-scoped automatic-research policy capability for the newly authorized store. Bind owner instruction, permitted root/lane, source/review manifest, model and build hashes. Do not fabricate a signature, feed self-sealed JSON to the legacy verifier, disable its checks or reuse a visible-only capability for unseen. |

New runtime contracts must use the selected QueryPlan v2 and MatterFact v2 contracts
and bind the existing knowledge-generation and request-to-release digest chain.
An AI-reviewed evaluation-index eligibility record must not set professional legal
sign-off, answer legal gold, unrestricted current-law eligibility or production
admission. Unreviewed captures may be retained in quarantine; they are not authority
for answer generation. The new instruction authorizes the research/indexing work,
so routine per-source human ticks are not added to this route.

## Bounded execution and quality

Use the current resource envelope and a single local embedding job at a time.
Proposed initial research budget: at most four focused search queries and eight
new official source captures per issue attempt. A distinct controlling sub-issue
has its own recorded budget; do not disguise repeated searches as new issues.
Respect existing capture-size/timeout limits, site restrictions and rights metadata.
Record a budget hold rather than silently increasing limits or scraping around a
blocked service. Deduplicate by source version, locator, text, parser/chunker and
model identity. Unchanged successful work returns a no-op; unchanged failed work
is not retried. One targeted retry requires a documented change. After two failures
of the same fingerprint, stop that path before a third attempt; unrelated work
continues.

Before calling this feature complete, demonstrate actual retrieval of a freshly
captured, reviewed, chunked and embedded source from the intended database. Verify
wrong-jurisdiction and wrong-date exclusion, source/quote mismatch rejection,
superseded-law retention without accidental current use, duplicate no-op, interrupted
build preservation, no ACTIVE mutation and denial of cross-store reads. Visible
end-to-end checks must include successful and held research outcomes, a usable
upload and multi-turn fact corrections. Record model-inference/index receipts;
stubbed unit tests alone do not establish embedding execution or legal accuracy.

The current GE quality contract has these dimensions; retain it unless a future
separately defined evaluation contract changes before any answers are produced:

| Dimension | Maximum | Required minimum |
| --- | ---: | ---: |
| Legal/factual accuracy | 25 | 17.5, after the separate material factual gate passes |
| Issue coverage and reasoning | 15 | Included in total |
| Authority and currentness | 15 | 10.5 |
| Practical steps and urgency | 15 | 9 |
| Uncertainty, limits and clarification | 10 | Included in total |
| Organisation and plain language | 10 | Included in total |
| Traceability and citations | 10 | Included in total |
| Total | 100 | 70 |

Full-bank success requires 420/420 legal cases to pass the material factual gate,
total threshold and all critical floors, plus 23/23 separate system passes and no
critical/high, material-regression, custody or integrity defect. Missing, held or
failed cases stay in the denominator. Do not lower this gate to obtain a pass.

Every material factual/legal claim and material omission must be reviewed first.
Only factually eligible answers receive the frozen practical GE 70+ score and
critical-floor checks. Preserve the full denominator and distinguish useful
clarification/abstention from a substantive pass. Scores, minimums, holds and
critical failures are all reported; an average of 70 cannot conceal a factual
error. Review coverage of 100% means all identified material checks were performed;
it is not a guarantee of universal factual correctness or professional assurance.

## What happens after the single unseen run

A pass supports only the tested scope and exact runtime. It does not activate an
adapter, authorize production use or prove every UK/US legal problem is covered.
A failure/hold is an honest terminal result. Preserve it and retire the bank; do
not repeatedly improve answers and rescore that bank as unseen.

Weight training remains optional and **not authorized**. Consider a separate
training proposal only if clean visible evidence shows a persistent model-behaviour
problem that source, retrieval, prompt or code repair cannot resolve. Any later
proposal must identify exact eligible hashes and fresh evaluation exclusions.
Neither the current bank nor the retired 306 bank can supply that training data.
No new bank, repeat unseen run, release or live activation is authorized by this plan.

This remains within the three delivery phases: maintain system design; complete
evaluation/non-weight improvement and the authorized unseen run; live last under
its separate gate. No automatic evaluation → training → unseen → training loop.
