# Step 1 and visible GE question-bank review

Date: 1 September 2026. Advisory review only; no design acceptance, question
amendment, legal-currentness judgment, dataset freeze or execution authorization.

**Assessment: retain the architecture, tighten a few contracts, and amend the GE
bank before freezing it.** There is no reason from this review to discard the
foundation or rewrite all 331 questions. File completeness and question quality
are different checks.

The owner's pasted feedback was checked against the current design and the
visible GE structured records. The visible file contains 331 unique IDs and 331
distinct prompt strings: 306 core plus 25 stress. Its SHA-256 remains
`d1b6f72552dee49ca6380d3016f4908453b93a67f5cb639b19bc741c168075d5`.
Private/unseen prompt content was not inspected. No model or evaluation was run.

## Step 1: four decisions to make explicit

The [current design](../V111_SYSTEM_DESIGN.md) already covers intent routing,
hybrid retrieval, chunking/embeddings, reranking, conversation storage, WebSocket
progress, deterministic citations and fallback. These are the right component
boundaries for the local pilot. The remaining decisions are narrower than a new
architecture:

| Decision | Evidence and gap | Proposed clarification |
| --- | --- | --- |
| Validate user facts separately from law | `StructuredClaimDraft` has evidence IDs and a free-form kind, but no separate typed fact references. The material-claim evaluator expects legal EvidenceSpans. | Extend the existing versioned contract to distinguish attributed facts, legal propositions and their application. Validate message/upload provenance for facts and qualified authority for law. Never bypass fact checks by marking a material fact non-material. |
| Give GE its own answer and clarification behaviour | The design calls for concise help, but `QuestionRequest` defaults to 1,500 words; targets over 1,200 select the sectioned route. | Specify mode-aware output budgets and an explicit clarification-turn lifecycle. A safe clarification is a useful response, not automatically a held draft or failure. The next turn creates a new job bound to corrected facts. Numerical budgets remain proposals to validate. |
| Describe what verification actually establishes | Deterministic support screening explicitly does not prove entailment. The configured answer path adds a separate review pass through the same model when deterministic safety checks permit it. | Document this pass, its uncertainty/failure holds and its lack of model independence. Positive model review cannot override deterministic failures or owner decisions; “verified” must not imply guaranteed legal truth. |
| State the requested-date/reviewed-date rule | Present-law case-proposition qualification requires an exact reviewed span/proposition and matching requested answer date. | Explain the response when the requested date falls outside reviewed coverage. Never silently change the question's date, imply an old cutoff is today's verification, or relax the current policy to make a run pass. |

Implementation references: [claim/request types](../../backend/app/types.py),
[routing](../../backend/app/orchestration/routing.py),
[material-claim evaluator](../../backend/app/quality/evaluator.py),
[support screen](../../backend/app/quality/evidence.py),
[AI reviewer contract](../../backend/app/quality/ai_evidence_reviewer.py),
[answer runner](../../backend/app/orchestration/runner.py),
[case currentness](../../backend/app/currentness.py).

The missing runnable index/runtime, uncalibrated relevance threshold and outstanding
source/gold qualification are already recorded implementation prerequisites. They
are not evidence that the overall architecture must be replaced. The review also
does not imply the local pilot is ready for the broader public-service ambition.

## Corrections to the pasted review

| Pasted concern | What the actual records show | Consequence |
| --- | --- | --- |
| Add jurisdiction/date metadata | Every record already has `primary_jurisdiction`, `conditional_jurisdictions`, `jurisdiction_status`, `legal_currentness_cutoff` and `temporal_status`. Primary scope includes 180 E&W, 74 UK, 41 cross-border and other explicit scopes. | Improve owner-facing disclosure and input rules. Do not overwrite explicit Scottish, EU or cross-border scenarios with blanket E&W. Metadata may itself need review; its presence is not legal certification. |
| Currentness needs controls | All 331 records carry cutoff `2026-08-28`; verified source/version bindings and case-specific review/expiry evidence remain outstanding. | Separate the scenario's as-of date, the gold's source versions, verification date and review trigger. An expiry creates a hold/review need, not an automatic change to an immutable historical benchmark. |
| Question positions leak the answer | All 17 topics put false-premise cases at d14–d16 and urgent/evidence cases at d17–d18. | This is a real shortcut risk. The audit did not establish that a running harness actually sends these IDs or flags to the model. |
| All 17 topics are admitted | Administrative Law has 19 and Wills/Estates 21 questions still marked admission-blocked. | All 40 remain in the review inventory but are not thereby eligible for scoring. Other topics also still require their applicable gates. |
| Duplicate questions | There are no identical prompt strings; several strong semantic overlaps exist. | Differentiate, replace or deliberately group them. Do not equate different wording with independent coverage, or delete distinct scenarios merely because they share a doctrine. |
| Missing coverage | Some proposed additions overlap existing merger, distancing, medical-record correction and cross-border data questions. | Check the coverage matrix before adding more. A missing basic standalone scenario is different from an entirely absent subject. |

## Question improvements, in priority order

### 1. Separate model input from evaluator-only information

Define and verify a model-input allowlist: the user question, genuine prior user
turns/facts, publicly declared mode/jurisdiction/date context and qualified retrieved
evidence. Stable question IDs, ordinal positions, topic labels supplied only by the
test, CORE/STRESS, expected issues, refusal/urgency flags, answer keys and review
notes stay outside the model and query planner. Do not send the entire JSONL row.
If jurisdiction is intentionally unknown, do not leak the evaluator's intended
jurisdiction through request metadata.

Preserve stable review IDs and record a seeded execution order separately. Reset
conversation and mutable fact state between independent cases. Keep deliberate
multi-turn cases within their own isolated conversation. Randomisation addresses
order effects; it does not remove leading wording or make a paraphrase unseen.

Introduce a proposed `scenario_family_id` for semantic overlaps and variants.
Keep families together across training/development/unseen boundaries and report
case counts alongside family-level results. Any independent custodian overlap
check must not expose unseen prompts or case-specific feedback to developers.

### 2. Replace leading refusal and issue-spotting wording

All four refusal prompts explicitly ask what assistance must be refused:
`business-and-company-law:cp-s02` (Q058), `criminal-law:cp-s01` (Q153),
`trusts-law:cp-s01` (Q309), and `wills-and-estates:cp-s02` (Q330).
In a successor draft, make these natural requests; keep expected refusal,
preservation and lawful-redirection behaviour in the evaluator-only rubric.
Pair unsafe requests with related legitimate requests so indiscriminate refusal
does not score well. Do not add operational wrongdoing instructions as targets.

Natural GE and explicitly targeted doctrinal prompts can both be useful, but
should be labelled and reported separately. Example wording proposals, not applied:

| Original ID | Natural wording direction |
| --- | --- |
| `administrative-law:cp-d12` | “My regulator gave me its harshest penalty but did not explain why a warning would not do. Can I challenge this, and what documents should I look for?” |
| `ai-and-data-protection:cp-d14` | “I'm worried a chatbot could repeat my email address and details of a medical complaint. The company says information inside its model cannot be personal data. What can I ask it to do?” |
| `private-international-law:cp-d04` | Preserve the original dates, French proceedings and English company, then ask whether the judgment can be enforced in England. Move the named treaty/transitional checklist into the rubric. |

Add reviewed counterexamples to the predictable response patterns: false, true
and insufficient-information propositions; urgency without cue words; dated
non-urgent situations; evidence preservation without an emergency. Do not invent
an absolute legal rule simply to fill a “true” category. Language variation should
reflect the intended users; the suggested 25–35% is not an established requirement.

### 3. Make clarification and success criteria case-specific

All 331 rows currently share the same four generic clarification targets. Of
these, 114 mark blocking clarification and all 331 allow answer-then-clarify.
The combination needs precise case-level meaning, rather than being treated as
an automatic contradiction or a reason to refuse all help.

For each relevant case specify indispensable facts, helpful facts, safe guidance
available now, permissible assumptions/conditional branches, acceptable initial
question burden and expected handling after a correction. Define success in
observable terms: understanding the issue, a supported answer or honest limit,
useful lawful next steps, necessary clarification and appropriate escalation.
Do not require one exact preferred phrasing or penalise every concise answer.

Separate difficulty, urgency, safety, currentness, jurisdiction, issue structure
and language robustness. Existing `difficulty` and `scenario_class` are useful
starting points but mix these dimensions. Routine pension-information cases
Q250–251 can be retained while being reclassified more precisely.

### 4. Reduce repetition without deleting useful distinctions

| Stable IDs | Recommended review |
| --- | --- |
| `competition-law:cp-d05` / `cp-d16` (Q082/093) | Strong resale-price overlap; differentiate or retain as one robustness family. |
| `international-commercial-mediation:cp-d06` / `cp-d14` (Q179/187) | Strong compelled-mediation versus compelled-settlement overlap. |
| `international-commercial-mediation:cp-d13` / `cp-s01` (Q186/192) | Similar enforcement scenarios; require distinct assessed issues to justify both. |
| `pensions-law:cp-d04` / `cp-d17` (Q235/248) | Strong pre-transfer scam/urgency overlap; a routine member problem may add more breadth. |
| `criminal-law:cp-d08` / `cp-d14` (Q142/148) | d14 adds discouragement from advice and uncertainty about leaving; retain only with a clearly differentiated rubric. |
| `contract-law:cp-d07` / `cp-d14` (Q122/129) | Separate notice/incorporation from a concrete fairness/enforceability dispute. |

Do not remove `private-international-law:cp-d13` merely as a third mediation copy:
its later judgment and overlapping claims add a distinct problem. Likewise pension
`cp-d08` and `cp-d10` distinguish a flagged transfer from loss after a transfer.
Land/Trusts home-ownership overlaps can test routing consistency if reported as
related cases, rather than two independent demonstrations of competence.

### 5. Match everyday coverage to the product, and add a system suite

Before enlarging the bank, map each case to user problem, expected capability,
source availability and intended jurisdiction. Review housing/disrepair, wages
and dismissal, consumer purchases/refunds, debt/benefits, family issues and
immigration against the accessible-help goal. These are candidate coverage needs,
not permission to expand the legal/source scope. Do not substitute a longer
law-school syllabus for ordinary users' practical needs.

Create a separately versioned system-behaviour suite when authorized: missing or
contradictory authority, invented citations, unavailable jurisdictions, injection,
requests for protected data, mixed-topic routing, irrelevant/emotional wording,
fact corrections and multi-turn reference resolution. Technical acceptance also
needs wrong-conversation isolation, history expiry, reconnect, cancellation,
duplicate submission and slow/failing retrieval or generation. These should have
separate denominators from doctrinal accuracy; do not relabel them as more legal
topic questions or combine all results into one reassuring average.

Freeze outcome rules before runs. Report safe clarification/abstention, unsupported
claims, unsafe assistance, over-refusal, system errors and incomplete cases
separately. Eligibility exclusions must be declared before execution, not used to
remove inconvenient results afterwards. Exact thresholds and public rollout
decisions remain owner-controlled.

## Suggested next revision, not executed

1. Tighten the four design contracts and the evaluator/model-input boundary.
2. Prepare a case-level amendment proposal against visible r2, preserving original
   IDs/digests and recording proposed successor identities, reasons and family links.
3. Check source feasibility while reviewing wording and coverage; do not wait until
   after a prompt freeze to discover that required evidence cannot be admitted.
4. Review amended wording and independently supported gold; define the scoring and
   run-validity contract before freezing an execution bank.
5. Keep training separate and leave existing unseen content with its custodian.
   Exposed visible questions and their paraphrases cannot become a new unseen set.

Fillable PDF fields or a filtering workbook would make owner review easier, but
they are lower priority than input isolation, realistic prompts and gold quality.
Future packaging should distinguish content version from PDF layout version and
wording approval from source/gold/currentness/execution approval. The current PDF
already has page numbers and topic bookmarks.

The architecture, control documents, source question packages, review PDF and
unseen bank were not changed by this assessment. This file records recommendations
only; it does not mark any owner review decision as accepted.
