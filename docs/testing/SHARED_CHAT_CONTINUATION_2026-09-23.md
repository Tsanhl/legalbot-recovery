# Shared chat continuation: targeted source and answer checks

Updated 23 September 2026. This is an engineering diagnostic, not legal-answer
certification. Private encrypted prompts, drafts, query vectors and browser
receipts remain under ignored `data/development-runtime` states.

## Results after the owner resumed the guide

The narrow local-runtime tests passed (9); web lint passed. A broader backend
subset initially found one legacy resume test fixture that lacked the cipher
needed by chat-only authorization. The code now returns through the legacy path
for a non-chat job while keeping chat jobs fail-closed. The 73-test subset then
passed. Ruff passed on 41 changed Python files.

| Run | Actual route | Observation | Publication |
| --- | --- | --- | --- |
| r7 | Browser → signed-in Codex → reviewed 5 September England index | Eight supplied spans omitted the controlling quality rule; source and writing checks failed | Held |
| r8 | Same route with focused issue queries | Section 9 was retrieved by a later query, but first-query-only merging kept it out of the eight supplied spans | Held |
| r9 | Same route with balanced issue merging | Sections 9/19/20/21/22 reached the model. Initial draft lost its prior unsupported-fact finding; first repair introduced another, and second repair failed validation | Held |
| r10 | Same route with all exact reviewed receipt-context rows searchable | Reviewed rows rose from 32 hit rows to 281 context rows, including section 23. The eight-span projection chose an irrelevant section 31 cross-reference and omitted section 20 | Held |
| r11–r14 | Actual local query embeddings and reranking only | Focused source queries found section 20's 14-day refund clause, collection duty and return-cost clause, and section 22's 30-day clause | No answer model invoked |
| r15 | Exact eight-span pre-draft projection of those frozen query results | Refund, collection, return costs and the 30-day rule are present; the implied quality term, nonconformity trigger and delivery condition are absent | Not ready for answer model |
| r16 | Candidate preparation only | Derived context rows initially reused child ordinals; registration stopped before a model call | No answer |
| r17 | Browser → actual vector retrieval → Codex | Complete reviewed provision context and provider-specific budgets reached drafting; draft 695 words, repair expanded rather than condensed | Cancelled during repair review; retained |
| r18 | Browser → retrieval/draft | Detected that the semantic review change targeted an inactive template; cancelled and corrected the active template | Incomplete; no adopted output |
| r19 | Browser → five vector/reranker queries → Codex and separate reviews | 583-word draft; semantic writing review resolved two lexical false positives. Repair expanded to 731 words and introduced an unsupported source-status claim | Held |
| r20 | Same exposed question with actionable omission review and explicit condensation budget | 539-word initial draft; first repair had 585 claim words. Complete review identified a missing repair-election qualification, but empty reasons on passed writing checks caused a validation error | System error; raw reviews retained |
| r21 | Same question with explicit Codex high reasoning for draft/repair, nonduplicative GE roles and corrected pass-reason validation | Retrieval 181,246 ms; draft 605 claim words. The eleventh reviewer response copied a long evidence ID incorrectly; exact identity validation refused it | System error; no publication |
| r22 | New, fully specified in-store refund case, frozen before generation in CODEX_FOCUSED_CONSUMER_FIXTURE.json; same reviewed date and Codex route | Draft 518 claim words; ordinary user wording omitted sections 9/19 from issue queries. An invalid application-rule dependency then stopped review | System error; raw draft retained |
| r23 | Same frozen in-store question after plain-language issue planning and fact-binding repair routing | Five actual vector/reranker queries supplied sections 9/19/20/22/23. Draft/repairs were 601/521/623 words; invalid application dependencies remained, so semantic review did not run | Held after two repairs |
| r24 | Same frozen question with exact missing-dependency feedback and material-issue word allocation | Draft/repairs 557/553/578 words. First repair reached claim and full-answer review; full review passed, individual claims did not. Fact excerpts omitted facts actually present in the question | Held after two repairs |
| r25 | Same frozen question; full question context bound into application review and explicit xhigh drafting/repair | Initial draft 581 claim words; all claims reviewed with full application context. Reference transport worked, but support and length findings remained | Cancelled during first repair before explicit model change; no adopted repair |
| r26 | Same frozen fixture and runtime with explicitly selected gpt-6-astra | Actual UI connection test passed; initial draft was 398 substantive words and first repair 419. The second bounded repair began, but its owned launcher/API/worker/UI processes disappeared during an interrupted turn. The database row still said running; exit code and repair output are unknown. The private interrupted-attempt receipt preserves the observed state | Incomplete; no answer published or adopted |

All browser requests above saved **England, 5 September 2026** and used the
non-ACTIVE reviewed candidate. The original 23 September campaign remains a
separate 40-conversation evidence hold. No later run changes its result.

## Repair and remaining gate

The development retriever now retains exact prepared rows appearing in frozen
retrieval receipts, rather than throwing away reviewed context. Issue queries
are focused, and reviewed consumer-law provisions can reserve search slots.
The source-only checks confirmed the individual statutory clauses are present.

The r15 fragment problem has been repaired for this scoped candidate. Exact
reviewed children of a provision are assembled in document order; component IDs,
text hashes, review/scope identities and source capture remain traceable. Actual
vector/reranker hits still use the original children before context expansion.
Registration now has 297 chunks (281 eligible original vectors plus 16 derived
context rows). The immutable underlying index is unchanged. Codex receives up to
45,000 evidence characters; Qwen keeps its smaller budget. Whole provisions that
do not fit are excluded instead of being silently truncated. Section URLs now
point to provisions; exact subsection mapping remains incomplete.

The next observed defects are answer generation and review behaviour. r19's
19-claim draft had incomplete conditions and support bindings; its repair grew
to 32 claims. The full-answer reviewer also requested a missing-authority status
without specifying an actual gap, prompting irrelevant source-status prose.
The r20 runtime requires actionable omission findings and affected
sections, preserves sealed complete-answer reviews in encrypted objects, gives an
explicit total word budget and permits condensation of repeated prose in failed
sections. Incorrect draft bindings can receive a bounded repair, but source
identity, jurisdiction, currentness, privacy and all final factual checks remain.
r21 also accepts an empty writing reason only for a passed check, gives new GE
drafts four relevant roles without a second conclusion, and binds explicit Codex
reasoning settings into the generation identity. This is a changed generation
configuration, not training or a provider substitution. A noun such as “time limit” no longer counts as a second finite predicate in the
atomic-claim heuristic. Two separately assertable rules still fail that check.

Semantic writing review may resolve only lexical writing heuristics. Every legal
claim still needs evidence review, and a high advisory score cannot offset a
material defect or requested-length failure. No reviewed answer has yet been
published in the terminal attempts above. The focused r22 case is an additional
exposed diagnostic, not a pass for the broader doctrine question or campaign GE01. Targeted engineering checks: 68 passed
(latest subset, overlapping earlier runs); Ruff passed on changed Python files.

After r26 stopped, a targeted evaluator correction made application-claim
relatedness follow its explicit legal-rule dependencies. It does not relax the
rule's own source check, the application fact-quote/dependency checks or the
independent AI support review. Offline replay of r26's retained first repair
removed three lexical `unrelated_evidence` false positives (refund application,
store-credit application and evidence-preservation step). Other observed r26
findings, including missing conditions, an atomicity error and an omitted
delivery-nonconformity explanation, remain; this replay is not a publication
pass. Targeted evidence-quality, chat-session, licence and provider tests passed;
Ruff and `git diff --check` passed on the touched files.

Current-law online source qualification is still a separate gate. The official
Consumer Rights Act capture has unapplied effects elsewhere in the instrument;
the current implementation holds the whole instrument until amendment,
commencement and dependency review. Consumer cancellation regulations and US
captures also need their own point-in-time review. A 5 September indexed probe
cannot establish the 23 September GE01 answer.

After a supported Codex answer, diagnose Qwen generation latency on the same
qualified packet, then run genuine follow-ups, Essay/PB outputs, and the frozen
20-case comparison per model. LoRA remains conditional on model-specific errors
after source and prompt repair. The owner has now supplied the executed Find Case
Law licence terms and confirmed all parties signed on 23 September 2026. Its
stated purpose covers an England-and-Wales local research assistant for the
owner's private study and invited friends, including local parsing, BM25/vector
indexing and retrieval-augmented generation with readable links. It requires
current-version and withdrawal/revision handling, a prominent approved Crown
copyright acknowledgement and partial-coverage statement, and protection
against third-party crawling and indexing of judgment contents. The executed
file itself has not been bound to the private hash-based permission gate; no
Find Case Law material was used in r26. External model processing, public
internet hosting and answer-weight training are not expressly described by the
quoted purpose. Do not turn the owner's signed confirmation into blanket
permission for those activities. The owner wants future access restricted to
invited friends; sharing an unprotected public URL does not meet that condition.
No public/ACTIVE release, training, licence activation, Git commit or push
occurred in this continuation.
