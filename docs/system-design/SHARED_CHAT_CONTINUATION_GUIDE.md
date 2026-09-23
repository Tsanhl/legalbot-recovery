# LegalBot: continuation guide

Updated 23 September 2026. The owner directed Codex-first execution. The original
fragmented-context defect is now repaired for the reviewed England/5 September
candidate; r17–r19 reached drafting and review but remained incomplete/held.
r20 ended in a review-schema error; r21 stopped on an incorrectly echoed reviewer evidence ID. r22 exposed missing ordinary-language issue queries and an invalid application-rule dependency. r23 reached both bounded repairs but held with application-rule mismatches and 623 words. r24 held after two repairs (557/553/578 words). Its per-claim review omitted user facts from context. r25 confirmed complete fact context and xhigh drafting but produced 581 claim words; it was cancelled during the first repair. r26 explicitly selected gpt-6-astra and passed its connection test, but the processes disappeared during its second repair after an interrupted turn. Its private interrupted-attempt receipt preserves the stale running row and proves no published answer. The owner now prefers Codex and API routes first; Qwen training can wait. External access is intended for invited friends only. The local launcher has no invite authentication and remains loopback-only.
In r28, Astra saved a 424-word draft and a 440-word repair before review was
cancelled; its second queued job expired. Both are terminal and preserved. The
r29 loopback UI has separately pinned Sol, Astra and Luna routes. The owner's
requested 6 Sol model failed a real isolated CLI probe because this signed-in
ChatGPT account does not support `gpt-6-sol`. The failed route is visibly marked
and cannot accept a question. No r29 legal job has run; do not rename an Astra
result as a Sol result. The single GE fixture awaits the owner's route choice.
The claim reviewer now checks independent claims with bounded parallelism and
shows a completed-claim count; conversation access has a 30-day activity
expiry. See `docs/testing/SHARED_CHAT_CONTINUATION_2026-09-23.md` for earlier
terminal outcomes.
Do not repeat the forty-case campaign before one supported Codex answer.

## Current route and audience decision

The local development UI offers the same candidate-pinned retrieval, guides,
claim review and release boundary to each selected route:

- **Codex:** the backend runs the owner's signed-in CLI inside the isolation
  wrapper. The answer call cannot browse independently; any online evidence must
  first be captured and reviewed by the backend. The actual connection probe
  passed, but no substantive answer has passed publication. This is an owner
  development connection, not a visitor's desktop Codex account.
- **Provider APIs:** OpenAI, Claude and Gemini connectors take a session-owned
  key and use the same answer pipeline. No valid key was available for a live
  legal-answer test. Do not silently substitute Codex for an API result.
- **Qwen:** the pinned base local model is selectable; its connection probe
  passed, but generation timed out in the first campaign. The owner prefers to
  defer weight training while source and runtime causes remain unresolved.

The owner wants any eventual external audience limited to invited friends. The
current launcher binds loopback and automatically creates browser sessions; it
does not authenticate friends. Before an internet endpoint is exposed, add
invite identity, per-user data and job isolation, rate/abuse controls, HTTPS,
and deployment-specific secret management. An obscure URL and a robots rule are
not access control. Find Case Law judgment content must remain within the
executed licence purpose; its local indexing is described, while remote model
transfer, internet hosting and answer-weight training are not expressly covered
by the supplied purpose. Keep those separate from non-FCL source routes. The
signed document still needs private byte binding before the runtime licence
gate activates, together with current-version/takedown, notice and crawler
controls. This is a scope review, not a blanket judgment-source admission.

## 1. The answer to “are we repeating tasks?”

Yes, repeating the entire question set now would add little information. The
40-conversation run was useful once: it demonstrated that the dominant failure
occurs **before substantive generation**, at the evidence gate. Another unchanged
40-case run cannot establish model accuracy, improve the index or fix that gate.

The next task is development and source qualification, followed by small targeted
proofs. Do not begin with more practice questions, another full campaign, another
rewritten plan, or weight training.

**Shortest useful sequence:** one supported Codex answer in the real UI → the same
supported route with base Qwen → real two-turn case → broaden reviewed source
coverage → one full 20-case comparison per model after material fixes.

## 2. Reliable starting point

Read these, in order:

1. `AGENTS.md` and `docs/CURRENT_STATE.md`, applying this latest handoff direction.
2. `docs/testing/SHARED_CHAT_2026-09-23.md` for the actual acceptance result.
3. `docs/testing/CHAT_CAMPAIGN_2026-09-23_RESULTS.json` for all 40 rows.
4. `docs/testing/CHAT_CAMPAIGN_20.json` for frozen questions, withheld follow-ups,
   expected issues and rubric. These are exposed regressions, not unseen tests.
5. The current section of `docs/system-design/GE_PRE_BROWSER_IMPROVEMENT_PLAN.md`.
   Older dated sections are history, not new execution instructions.
6. The private local `CONTINUATION-HANDOFF.json` in the r6 development state for
   the terminal/active status of the already-dispatched probe. Reconcile that
   receipt with the database/processes before dispatching anything.

Only this recovery workspace may be modified. Do not access the retired/new
sibling workspaces or protected banks. No production/ACTIVE promotion is implied.

### What is already demonstrated

| Item | Actual evidence | Do not infer |
|---|---|---|
| Model connection | Real Codex `gpt-5.5` and pinned base Qwen connection probes passed | Legal quality, full context handling or a completed answer |
| Real chat campaign | 20 conversations per selected route, 46 total submitted turns | Forty model-generated legal answers |
| Genuine clarification | Six first responses displayed before withheld follow-ups; resolved questions not repeated | Universal legal intake or contradiction resolution |
| Transcript custody | Exact frozen user text and encrypted final browser DOM receipts for every campaign conversation | Client DOM observations are legal verification authority |
| Evidence refusal | All 40 final requests held before substantive generation | Legal accuracy, material coverage, word-count or OSCOLA success |
| Vector integration | Separate in-scope probes executed real query embeddings/LanceDB/reranking | Out-of-scope metadata holds count as vector searches |
| Actual runtime limit | Base Qwen reached drafting and timed out; queued Codex timed out behind it | Qwen hallucinated or needs LoRA |
| Operational checks | Real queued cancel, refresh and invalid-key rejection; cross-session/timeout/injection engineering tests | A complete adversarial or production certification |

The installed reviewed generation is **England consumer law, as at 5 September
2026**. The main campaign asks for **23 September 2026** and multiple UK/US topics.
That mismatch is material and must not be removed by relabelling the old index.

### Execution state to preserve

- `shared-chat-20260923-r1`–`r3`: setup/early integration attempts; preserve records.
- `shared-chat-20260923-r4`: original Codex-only baseline, 20 conversations/23
  turns, all held. Its defects led to focused fixes.
- `shared-chat-20260923-r5`: complete 40-conversation/46-turn campaign, plus
  separately identified probes and system checks. All campaign final requests held.
  Correctly dated Qwen probe ended `stage_timeout`; Codex behind it ended
  `queue_wait_deadline_exceeded`. The cancelled system job is separate.
- `shared-chat-20260923-r6`: separate Codex probe with an empty queue. Read its
  handoff receipt for the final observation; do not assume interruption stopped it.

A fresh isolated state is required after changing files bound by the development
runtime authority. This preserves reproducibility; it is not permission to repeat
unchanged model attempts. Never edit old receipts to make them match new code.

## 3. Step 0 — reconcile and finish mechanical verification

**Goal:** a known terminal starting point, without another legal campaign.

- Check the r6 job and owned API/worker/model/CLI processes. If terminal, adopt its
  actual output and reason code. If still running, drain or explicitly cancel it
  through the existing job control and preserve the outcome before proceeding.
- Never run two launchers on ports 8776/8777/8778 or duplicate an in-flight probe.
- The latest combined backend run recorded **132 passed, 2 failed**. Those two
  assertions expected the removed admin UI/owner launcher; their expectations
  were corrected afterward. The final confirming output was interrupted.
- An earlier repaired durability/prompt/source/session/provider subset recorded
  **75 passed**. Counts overlap; do not add them together.
- Web build and four bundle checks passed. Lint then found a render-time ref write;
  it was removed. Confirm that small fix once; do not claim a final lint pass from
  an interrupted command.

Start with the narrow outstanding checks:

```bash
.venv/bin/pytest -q -o addopts='' backend/tests/test_local_runtime.py
npm --prefix web run lint
```

Then run formatting/lint only on changed Python files. Read failures and fix their
causes. A green component test is not a substantive legal-answer pass.

**Done when:** the active attempt is terminal and preserved, the two stale tests
and frontend lint pass, and there is no unknown background model invocation.

## 4. Step 1 — diagnose the first supported Codex route

**Do not start by rerunning GE01 as at 23 September.** First inspect the existing
r6 in-scope probe. Its question deliberately uses the generation's reviewed date
of 5 September to test integration, not current-law campaign success.

At the last pre-handoff observation it had performed three real retrieval queries,
returned 24 candidates and spent 94.664 seconds in retrieval before drafting.
The final handoff observation supersedes that running observation:

- r6 is **terminal `held_for_review`**, not still running. It completed at
  13:38:42 UTC; its held status was subsequently rendered in the real browser.
- Codex produced a structured draft recorded at **469 words** (450-word target),
  using eight supplied evidence spans. The actual draft and prompt are encrypted.
- Its preliminary automated writing score was **87.0**, but evidence did not pass:
  one `unsupported_material_fact` duration finding, one
  `non_atomic_material_claim` finding and three writing-standard failures.
- No AI evidence review was recorded and no repair stage ran. The material gate
  stopped the route before a released answer. Do not report 87 as a quality pass.
- The next diagnosis is to inspect the exact duration claim and bound text: is it
  genuinely unsupported or an extraction/matching error? Then inspect the compound
  claim and why the bounded repair route did not run. Preserve the factual gate;
  do not turn it off to improve the displayed score.

Inspect the exact sequence:

1. Browser-selected date/provider matches the saved request.
2. Session and conversation ownership are correct.
3. Candidate/generation identity and reviewed scope match the request.
4. Query vector, retrieved IDs and reranker scores exist and match supplied evidence.
5. The actual model receives the question, appropriate guide and exact evidence.
6. Its raw JSON is retained before parsing; requested versus attested model identity
   is stated accurately.
7. Parse, fact/evidence review, writing review and any repairs have separate records.
8. Released bytes/citations match the displayed answer; otherwise retain the exact
   terminal defect and label the result incomplete.

Relevant files:

- `backend/app/api/chat.py`, `backend/app/connections.py`
- `backend/app/orchestration/runner.py`, `backend/app/orchestration/worker.py`
- `backend/app/runtime_adapters.py`, `backend/app/model_routes.py`
- `backend/app/retrieval/reviewed_research_generation.py`
- `backend/app/retrieval/development_query.py`
- `backend/app/contracts/runtime_selected_chain.py`

If the probe fails, identify the **first failing stage**, not every downstream
symptom. Make one bounded repair and use an explicit changed-input/runtime receipt
for the successor. Do not loosen a material evidence check merely to release text.

**Done when:** at least one real, supported, appropriately scoped 450-word Codex
answer is displayed with source-backed citations and a complete provenance chain,
or a concrete irreducible external blocker is documented. Do not count an evidence
hold, standalone draft or health endpoint as this result.

## 5. Step 2 — repair source coverage and currentness

This is the main product blocker. It contains distinct tasks, not one “RAG works” tick.

### A. UK legislation

Current code: `backend/app/research/runtime.py`, `discovery.py`,
`case_source_review.py`, `adapters.py`.

- Exact Act identities now avoid selecting similarly named commencement orders.
- Dated CLML identity, extent, version and unapplied-effects checks still hold
  relevant requests. Inspect retained full bytes and individual effect records.
- The present implementation rejects an instrument when any unapplied effect is
  present. Determine whether a particular effect is material to the requested
  provision **and its dependencies** before proposing finer-grained handling.
- A change to a definition, scope, commencement or transitional provision can
  affect a remedy elsewhere. A different section number alone is not proof that
  an amendment is irrelevant. Ambiguous references remain a hold.
- Fetch and review the relevant amending/commencement/transitional text. Preserve
  exact provision/paragraph, digest, extent, effective dates and applicability.
- Retain enough complete context and necessary exceptions. Do not cut a long
  provision and call the remaining fragment complete.

First current-date target: GE01. Independently cover the defective-goods and
potential distance-selling routes, including exceptions, return arrangements and
different refund triggers. Chargeback/court guidance need their own sources.
Then GE02, including the actual 2026 commencement/transitional position.

### B. UK judgments and Find Case Law

Current code: `official_capture.py`, `licence_permissions.py`,
`config/official_sources.json`.

- An approved licence application is not an executed licence with verified terms.
- Keep the signed document and personal details private. Record its digest,
  effective period and the actual term supporting each purpose.
- Evaluate capture, vector indexing, external-model processing and training
  separately. Do not set all four flags because one is allowed.
- For any other official judgment source, check that source's permissions and
  exact text independently; do not use it to evade FCL restrictions.
- Implement source-currentness/later-treatment review and proposition support.
  Finding a title or index page is insufficient.

### C. US sources

Current code can capture selected official full text but **does not yet turn those
captures into reviewed answer evidence**. This is unfinished functionality.

Build adapters that preserve section/subsection or judgment pinpoints, edition,
amendments, effective dates and state/federal applicability. Provide a bounded
source-review/currentness step before creating a case evidence snapshot. Respect
403s and outages; retain a visible failure instead of silently replacing the source
with a search snippet. Shared index reuse requires a separate reviewed generation.

Start with one statutory GE case (for example the federal records request or a
state deposit question), then one US PB and one Essay. Use the already frozen
scenarios and expected issues. Do not invent new easy cases to replace failures.

### D. Research and evidence ledger

For each material proposition retain:

`claim/issue → exact source locator → captured text/digest → jurisdiction/date →
qualifications → source review → retrieval snapshot → model claim review`.

Bounded URL seeds are not deep search. Add permitted official discovery and gap
handling deliberately; avoid transmitting unnecessary personal case facts in search
queries. The claim-level review must still test what the source actually supports.

**Done when:** GE01 and one US case can obtain sufficient reviewed current-date
material through the actual backend; held sources remain explicit; a new capture
cannot silently enter the shared index or become training data.

## 6. Step 3 — separate Qwen runtime problems from model quality

Do this after a supported route exists. Keep the pinned base model and no adapter.

- Reuse the same reviewed question/evidence/guide contract as Codex; record actual
  input/output budgets. No Codex rewriting of a Qwen-labelled answer.
- Measure query/retrieval time, prefill, first token, generation, review and repair
  separately. Check memory and cancellation rather than increasing all timeouts.
- `development_query.py` currently opens embedding and reranker sessions for each
  query. Investigate safe reuse/batching of query work before spending another
  minute loading/scoring the same resources. Preserve exact model pins, isolation
  and reviewed-row restrictions; avoid unsafe parallel GPU loads on 16 GB.
- Check Qwen's complete prompt and structured-output token requirements. Existing
  Qwen budgets are smaller than hosted budgets. If complete facts/evidence cannot
  fit, return a clear capacity limitation or a reviewed section plan; do not
  silently truncate decisive facts, evidence or the target answer.
- A timeout is a runtime failure, not a measured hallucination. Missing evidence is
  a source failure. Neither alone justifies fine-tuning.
- Check queue admission/deadlines and fairness. The actual queued Codex expiration
  behind a long Qwen request must not be hidden by automatic retries. Any transport
  retry and charge implications must remain explicit and bounded.

**Done when:** one supported base-Qwen answer completes the same pipeline and can
be compared on actual facts, authority, completeness, length and latency. If the
hardware/model cannot do this within the chosen service budget, document that limit
and keep Codex as default; do not present a successful connection as smooth answering.

## 7. Step 4 — finish conversation correctness and output quality

Existing six follow-ups pass narrow intake behavior. Add focused checks for:

- Contradictory dates/amounts/jurisdictions: ask what changed or preserve explicit
  alternatives; never silently overwrite. The present fact ledger stores literal
  statements; it is not a complete semantic contradiction resolver.
- Longer histories: verify all necessary earlier facts and the assistant's questions
  reach the selected model. Overflow must be visible.
- Refresh/reconnect and rapid conversation switching: a late response from an old
  conversation must not reset the new case's date/provider or facts.
- Date input: earlier browser automation changed the DOM date without reliably
  updating React state. Native key events retained the intended date. Diagnose the
  control/event path and assert the **saved request date**, not only the visible field.
- Source outage, timeout, cancellation, invalid/revoked credentials, cross-session
  access and prompt injection: use targeted fault tests; no need for 40 legal calls.

For substantive answers enforce the shared feedback:

- GE: conclusion → immediate steps → legal reasons → qualifications/sources;
  ask only unresolved outcome-changing facts, in ordinary observable terms.
- Essay: thesis, reasoned evaluation and counterargument; distinguish holdings,
  undecided issues, types of estoppel and the scholar's own view from views discussed.
- PB: no invented evidence/bargaining facts; apply both sides of the clause arguments;
  keep deposit, outstanding price, extra demand, mitigation and claimed loss distinct.
- OSCOLA by default, source-supported pinpoints beside claims; requested bibliography
  deduplicated under Case law / Legislation / Secondary sources.
- GE 450 words; Essay/PB 700; ±10% excluding citations/requested bibliography.
  Clarification exempt. At most two targeted, reviewed repairs; never cut mid-analysis.
- Material unsupported claims, fabricated facts, wrong law/date or material omissions
  override an advisory 70+ writing score. Codex review of Codex is same-provider AI.

**Done when:** a real two-turn case ends in a supported substantive answer and the
small substantive cross-mode set passes these checks with preserved raw provenance.

## 8. Step 5 — rerun the full campaign only when informative

Use the same frozen twenty cases for both routes. There must be material changes
that plausibly address the known failures, and sufficient source coverage to make
substantive generation possible. Do not rewrite the expected issues after seeing
outputs. Preserve failures, errors and holds in each denominator.

Run interactively through the real UI/API; withhold the three follow-ups until the
actual first responses appear. Capture raw provider output, reviews/repairs, rendered
citations and exact displayed transcripts separately. Give every case its factual
support, omissions, invented facts, clarification, word count, selected/observed model,
retrieval, latency and publication result. A clarification is not a completed answer.

The existing report script is intentionally a **hold-only report**. It refuses to
score substantive outputs. Extend reporting with real claim-level evidence and
word counts when answers exist; never replace null/unassessed fields with invented
passes or a generic percentage.

## 9. Step 6 — conditional training, not the next immediate task

Only after source/prompt/runtime repairs leave measured Qwen-specific defects:

1. Prepare 60 rights-cleared, source-reviewed examples: 30 GE, 15 Essay, 15 PB.
2. Split by scenario family, 48 training / 12 validation; deduplicate families and
   exclude all twenty campaign scenarios, protected banks, private conversations
   and unverified drafts. No test-answer laundering into targets.
3. Preflight complete examples at 4096 tokens and 12 GB on the 16 GB host. Do not
   truncate away material facts/evidence/answers to make a run fit.
4. One MLX LoRA experiment: pinned base, batch1, rank2, one trainable layer,
   learning rate 1e-5, fixed seed, prompt masking and gradient checkpointing.
   Stop at 100 steps or two hours, including documented failures.
5. Select a checkpoint using validation only. Then repeat the exposed regressions
   for evaluation. Adopt only with supported-answer improvement and no new critical
   errors; otherwise keep base Qwen and preserve the negative result.

No such new training or adapter adoption has occurred in this implementation.

## 10. Step 7 — cleanup and Git delivery

The audited shared-chat, review-speed and UI changes were pushed to public
`main` through commit `2c4ab9c`. This is code delivery, not proof that a
substantive legal answer passed review. The four older review receipts below
were restored in the local checkout after separate inspection; their deletion
was not part of that commit.

For later changes:

- Audit the actual diff and runtime references. Dashboard components have been
  removed; recoverable copies and superseded working README/current-state text
  are under ignored `tmp/retired-dashboard-20260923/`.
- Preserve immutable evaluation evidence, protected material and all attempted-run
  histories. Do not run `git clean`, delete ignored data wholesale or remove evidence
  because it is old.
- Exclude credentials, private paths, raw prompts/transcripts, source/licence
  correspondence and training artifacts. Test the staged diff, not just `.gitignore`.
- Preserve these four historical review receipts and their checksum history:
  - `8-17 review/LegalBot-Live60-Path-B-Completed-Review-2026-08-17/README.md`
  - `8-17 review/LegalBot-Live60-Path-B-Completed-Review-2026-08-17/SHA256SUMS.txt`
  - `8-17 review/LegalBot-Live60-Path-B-Substantive-Review-Complete-Pending-Attestation-2026-08-17/README.md`
  - `8-17 review/LegalBot-Live60-Path-B-Substantive-Review-Complete-Pending-Attestation-2026-08-17/SHA256SUMS.txt`
- Avoid `git add -A`. Stage an explicit audited file list, inspect it and commit
  using the configured public-safe identity. Verify the remote commit after push.
- Update README/current state/maintained design around the actual final result,
  including remaining failures. Do not claim only model training remains.

## 11. Rules that stop another repetitive loop

| Trigger | Next action |
|---|---|
| Same input/runtime/source failure, no changed cause | Stop; record unchanged condition; no repeat model call |
| No qualified source before generation | Repair that source path; no writing score and no LoRA |
| Official fetch succeeds | Capture only; review text/date/applicability before use |
| Source review remains materially uncertain | Preserve an incomplete result; identify the missing dependency |
| One code defect is fixed | Run the targeted regression, not the whole legal bank |
| Shared source path is materially repaired | Run one affected case on each route |
| Several representative supported cases pass | Run the full frozen 20×2 campaign once |
| Two answer repairs exhausted | Terminal incomplete; preserve all drafts; no third disguised attempt |
| Training preflight fails | No training; no silent example truncation |
| A turn is interrupted | Inspect process/job/receipt; never assume the process stopped |

### Suggested instruction for the next implementation turn

> Continue from SHARED_CHAT_CONTINUATION_GUIDE.md. First reconcile the r6 terminal
> receipt and finish the narrow pending verification. Then diagnose the existing
> supported-date Codex probe and get one source-backed answer through the actual
> chat UI. Repair current-law source qualification before broad testing. Do not
> rerun unchanged failures, start another 40-case campaign prematurely, train Qwen,
> touch protected banks or activate production. Preserve evidence and report the
> first concrete blocker plus the changed cause for every successor attempt.
