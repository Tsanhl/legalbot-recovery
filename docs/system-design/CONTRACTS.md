# System implementation contracts

These contracts refine `docs/V111_SYSTEM_DESIGN.md`. “Must” describes the target
implementation. A contract marked `TBD_OWNER` fails closed until the owner supplies
the named decision. Current code paths listed here are evidence of implementation,
not proof of readiness.

## 1. Deployment and trust topology

The first release remains one owner on one Mac and binds only to loopback.

| Process or store | Responsibility | Interface | Start/readiness dependency | Permission boundary |
| --- | --- | --- | --- | --- |
| Browser bundle | GE/PB/Essay input, progress and committed answer display | Same-origin HTTP and `legalbot.job-events.v1` WebSocket | Built static assets and ready API | Untrusted input; no direct DB, vault, model or index access |
| FastAPI client service | Validation, durable enqueue, status/cancel/resume, committed-answer reads | Release `127.0.0.1:8777`; development proxy to API `8776` | Key available, DB migration/readiness, deletion kill switch engaged | Never generates in request background work |
| Answer worker | One authoritative answer lease, retrieval, model calls, checks and outbox commit | SQLite jobs plus private model transport | Exact candidate, policies and model capability | Single-flight generation; fenced lease and cancellation |
| Index worker | Accounted parsing, chunking, embedding and new-generation sealing | SQLite jobs, immutable vault and candidate directory | Backup/restore receipt, exact manifest and resource admission | Cannot switch the release pointer |
| SQLite catalogue | Durable metadata, jobs, encrypted sensitive blobs and release outbox | Local file access | Key for sensitive blobs; schema compatibility | Metadata is not wholly encrypted; see data classification below |
| Raw/canonical vault | Immutable source bytes and versioned canonical objects | Local create-only files | Permitted source identity and storage availability | No model-authored writes or in-place mutation |
| Lexical/Lance generation | Candidate-bound keyword and vector search | Read-only mounted generation | Complete seal and candidate qualification | In-flight work pins one generation; no mutable ACTIVE contents |
| MLX sidecar | Pinned local generation | Private UDS/gRPC target | Exact owner transport capability and model attestation | No TCP fallback; raw tokens remain internal |

Startup order is storage/key checks, schema compatibility, deletion kill switch,
candidate/policy verification, model transport capability, API readiness, then
workers. A failed dependency keeps the affected endpoint unready. Shutdown stops
new admission, fences workers, checkpoints only frozen inputs and leaves outbox
records recoverable. Heavy indexing and answer generation do not overlap without
an approved resource schedule.

Untrusted boundaries are separate: browser input, prior messages, uploads,
retrieved prose and model output. Text crossing any boundary is data, never a
control instruction. Loopback binding limits exposure but is not authentication.

## 2. Request, API and idempotency contract

The existing route family remains canonical. Future fields extend it under an
explicit schema version; no parallel `/chat` route is created.

| Operation | Current route | Required request identity | Success result | Fail-closed outcomes |
| --- | --- | --- | --- | --- |
| Create question | `POST /api/v1/questions` | Schema version, client idempotency key, canonical request digest and optional expected conversation revision | One job ID, conversation ID, accepted request digest and event/status links | `400/422` invalid input; `409` conflicting replay/revision; `413` size; `429/503` admission unavailable |
| Get status | `GET /api/v1/jobs/{job_id}` | Job-read authority | Safe stage/progress, terminal state and committed answer identity only | `404` absent; `403/409` authority/state mismatch |
| Fetch answer | Existing committed-answer endpoint | Job/answer read authority and expected release digest | Only `verified_full`, `verified_concise` or `verified_limited` content | Held, error, partial draft or digest mismatch never returns prose |
| Cancel | `POST /api/v1/jobs/{job_id}/cancel` | Idempotency key and read/cancel authority | Durable cancellation request | A concurrently committed answer wins only if its release transaction preceded cancellation; otherwise cancellation fences publication |
| Resume | `POST /api/v1/jobs/{job_id}/resume` | Idempotency key and checkpoint/input digests | Same job or explicit successor identity | Never resumes with changed request, history, facts, evidence, candidate, model or policy |
| Conversation window | `GET /api/v1/conversation-sessions/{id}/window` | Conversation read authority and revision | Bounded messages plus omitted/truncation metadata | `410` expired eligibility; never substitutes another conversation |
| Upload | Existing upload endpoint | Idempotency key, question/conversation scope and exact bytes digest | Opaque upload ID and safe type/size metadata | Unsupported, encrypted, malformed, over-limit or unsafe archives are rejected/quarantined |

`QuestionRequest` keeps explicit mode, jurisdiction, requested as-of date,
word target, upload IDs and conversation ID. `auto` classification may fill a
missing mode but cannot override an explicit user choice. A missing as-of date
means the request date, subject to currentness qualification; it does not mean the
bank's historical cutoff. A repeated idempotency key with identical bytes returns
the original identity. The same key with a different digest returns conflict.

The current 1,500-word default is not the future GE default. Until the Phase-2
calibration freezes a mode-aware value, the client must either send an explicit
target or use a clearly provisional configuration. The reviewed per-case initial
clarification budget is 0–3; the implementation hard ceiling is three initial
questions, while each case or safety rule may require fewer or none.

Error responses use a stable code, safe user message, retryable boolean and
correlation ID. They never contain source paths, raw content, secrets, owner
identifiers or protected evaluation metadata. Retryable overload responses include
a measured `Retry-After`; validation, authorization and integrity failures do not.

## 3. Immutable query plan

`schemas/query-plan.v2.schema.json` is the selected plan. Version 1 is legacy
read-only and cannot enter a new job. The worker freezes v2 before
retrieval. It binds:

- request and original-question digests, task mode, schema selection, data intent,
  response disposition and answer route;
- request-observed time, explicit/service-default/unresolved answer date, and
  explicit or unresolved jurisdiction;
- issue IDs, outcome-changing missing facts and allowed authority lanes;
- encrypted query-variant reference and its digest, never evaluator-only metadata;
- retrieval depth, reranker candidate count, final K and context-token budgets;
- conversation revision, fact snapshot, candidate and policy/config digests; and
- rewrite result, including a reason when the original question is retained.

No evaluator ID, ordinal, topic label supplied only by the test, lane, expected
issue, urgency/refusal flag, rubric or gold enters the plan. A changed plan creates
a successor job. Model-written SQL, arbitrary paths and unconstrained tools are
never part of a plan.

## 4. Matter facts and conversation scope

The first implementation is **conversation-scoped**. It does not introduce a
generic `matter_id` or imply access to court, firm, booking or government systems.
`schemas/conversation-snapshot.v1.schema.json` binds the exact bounded message
projection. `schemas/matter-fact-snapshot.v2.schema.json` defines append-only fact
revisions. Matter-fact v1 is legacy read-only.

A `FactRef` binds one message/upload, exact content digest, optional safe locator
and source revision. A `MatterFact` separates origin (`user_statement`,
`document_extraction`, `deterministic_derivation`, `user_confirmation` or
`system_placeholder`) from status (`stated`, `extracted`, `confirmed`, `disputed`,
`unknown`, `superseded`, `rejected` or `scope_stale`). A deterministic derivation
binds its rule and input FactRefs. Model confidence never changes status to
confirmed. A correction appends a revision; it never rewrites the earlier message
or released answer.

The worker freezes a conversation revision and fact snapshot. A concurrent turn
cannot alter it. Contradictory active facts block only the affected conclusion and
produce a targeted clarification. A later correction starts a new job and marks
the earlier answer historical. Summarization is absent from the first
implementation; if added later, a summary must bind source messages and be
invalidated by corrections.

History eligibility expires without erasure. The user sees that context was
omitted or expired and is asked for outcome-changing facts again. Evaluation cases
use separate, empty conversations unless their declared multi-turn sequence says
otherwise.

## 5. Claim and evidence contracts

The claim-kind enum is `user_fact`, `legal_rule`, `application` or `limitation`.

| Kind | Mandatory binding | Invalid form |
| --- | --- | --- |
| `user_fact` | One or more fact references and attribution/status | Evidence IDs used to disguise an unconfirmed fact as law |
| `legal_rule` | Qualified evidence IDs with applicable jurisdiction/date | Search score, teaching note or model citation alone |
| `application` | Both applicable evidence IDs and the exact fact premises | Conclusion whose facts are absent, disputed or stale |
| `limitation` | Affected issue/claim plus the factual or evidence gap | Generic disclaimer used to release unsupported material |

Claims are atomic enough that one evidence decision applies to the whole claim.
An outcome-changing claim cannot evade provenance through `material=false`.
Model-rendered citations are ignored; deterministic OSCOLA uses reviewed metadata.

`schemas/claim-set.v1.schema.json` binds the atomic claims to the exact draft,
QueryPlan, fact snapshot and EvidencePack. `schemas/evidence-pack.v1.schema.json`
binds each selected span to source/version,
locator and content hashes; jurisdiction, effective/requested/review dates; extent,
commencement, legal role and currentness status; qualification receipt; retrieval
route/score system/policy; and the exact index generation. `RetrievalResult` records
rejected candidates; the pack records only qualified selections, issue coverage and
named gaps exposed to the compiler under policy.

## 6. Chunk, search and selection contract

### Chunking

The current structural limits remain `max_chars=1800` and `min_chars=160` until a
new version is measured. A chunker version freezes Unicode/line normalization,
canonical parser identity, source-version ID, locator construction, ordered block
range, long-block split rule, token estimator and chunk-ID formula. Prefer statutory
provisions/schedules and judgment paragraphs/headings; keep definitions,
exceptions, tables, footnotes, extent, commencement and later-treatment metadata.
There is no silent cross-source overlap. Adjacent context is a separately identified
span from the same qualified version. Failed OCR or incomplete representations are
held, never embedded as authoritative text.

### Embedding and vector storage

The generation manifest freezes `Qwen3-Embedding-0.6B`, exact revision and files,
1,024 dimensions, tokenizer, query/document instruction prefixes, pooling,
normalization, maximum length/truncation, numeric precision, batching, distance
metric and Lance schema/index parameters. Each row binds the exact chunk digest.
Query and document encodings cannot silently use different revisions or prefixes.

### Lexical, hybrid and reranking

The manifest also freezes lexical tokenizer/FTS settings, exact-reference parser,
field boosts, escaping, RRF formula/constant, multi-query fusion, deduplication and
stable tie-break (`score`, then source/version/locator/chunk ID). Retrieval depth,
reranker candidates and final K are separate. The current implementation default
search floor is 50; it is not a live-performance claim.

The reranker manifest freezes the `Qwen3-Reranker-0.6B` revision, yes/no prompt,
tokenization/truncation, score conversion, batch/resource limits and failure code.
Failure is fail closed. An unset semantic threshold returns
`semantic_admission_unavailable`; it never admits all results. The final selector
allocates evidence by issue, limits redundant spans, retains relevant contrary or
limiting authority and pairs exceptions with governing text. It can return fewer
than K plus a named gap. Context ordering and all discarded reasons are recorded.

## 7. Context compiler, model and verification

The compiler has separate versioned templates for classification/query rewrite,
GE, PB, Essay, evidence review and named repair. It allocates a frozen token budget
among the system/tool contract, bounded history, fact snapshot, qualified evidence
and output. When space is short it drops low-ranked redundant context before
material evidence, reports truncation and never clips a locator or quoted span
without marking it incomplete.

System instructions, user text, uploads and retrieved text have distinct delimiters.
Only allowlisted structured tool results enter the draft. The model cannot execute
SQL, fetch arbitrary paths, admit sources or render authoritative citations.

The private UDS/gRPC transport binds request, prompt, candidate and model digests;
handshake/version attestation; message and generation bounds; sequence; deadline;
cancellation; token/usage accounting; and a final structured digest. Missing,
duplicated, out-of-order, malformed or late frames fail the job. Raw tokens stay
inside the worker and never appear in browser events. Production activation remains
blocked by the exact owner transport capability.

Verification runs deterministic identity, qualification, citation, quotation,
claim/fact, date/amount, contradiction, privacy and output-shape checks. A same-model
evidence pass is advisory and cannot certify legal truth. At most one named repair
pass is proposed for the first implementation; a repeated/material failure holds.
The same failure fingerprint never triggers an unchanged retry.

`schemas/verified-release.v1.schema.json` binds the committed output digest to the
request, query plan, conversation/fact snapshots, evidence pack, model, prompt,
renderer, policies, verification report, repair lineage and outbox transaction.
Only a committed verified state reaches the client.

## 8. State machines and exactly-once release

| Object | Allowed forward states | Terminal or immutable rule |
| --- | --- | --- |
| Source version | quarantined → reviewed/held → admitted | Bytes/version never mutate; changed material is a successor |
| Index generation | building → validating → built_unscored → candidate | Failed and candidate generations are immutable; release pointer switch is separate |
| Answer job | queued → running stages → complete/held/system_error/cancelled | One fenced lease; terminal outcome cannot return to running |
| Conversation | active → closed/expired_eligible | Messages append only; expiry does not delete |
| Fact | proposed status → confirmed/disputed/superseded revision | Earlier revisions remain addressable |
| Answer version | draft → checked → committed verified/held | Draft is never public; repair creates a child version |
| Outbox | prepared in answer transaction → published → acknowledged | Publication is idempotent by outbox/release digest |

The verified answer, release manifest and outbox row commit in one database
transaction. Conversation projection occurs idempotently from that committed row.
A crash before commit exposes nothing; a crash after commit replays the same release.
Cancellation and publication races use the transaction order and fenced owner.

## 9. WebSocket and replay contract

`schemas/job-event.v1.schema.json` requires a stable event ID separate from the
monotonic sequence. Events are `progress`, `heartbeat`, `done` or `reset_required`.
Progress contains only allowlisted stage, bounded progress and a generic message.
The terminal event binds one stable job/answer/release identity and digest; replay
does not invent a new sequence.

Clients reconnect with the last accepted sequence, deduplicate by job/event ID and
use bounded jitter. The server verifies Host/Origin and read authority before accept
and on every loop. A replay gap produces `reset_required`, after which the client
fetches authoritative status; it never restarts generation. Slow consumers receive
bounded batches and then a retryable close. Heartbeat cadence, replay retention,
maximum sockets and backpressure thresholds remain `TBD_OWNER_RESOURCE`; until
frozen, admission is single-owner and conservative. Polling/SSE fallback may expose
only the same safe event projection and committed answer.

## 10. Upload contract

The current allowlist is PDF, DOC/DOCX, PPT/PPTX, ODT, HTML, XML, Markdown and UTF-8
text. This is an implementation inventory, not a public commitment. The future
contract freezes total bytes/pages/files, MIME plus magic checks, archive member
and uncompressed limits, parser/OCR time and memory, encrypted staging, macro and
password handling, and maximum extracted context. Current archive checks cap
members at 10,000 and uncompressed bytes at 256 MiB; an overall request-size policy
is still `TBD_OWNER_RESOURCE` and must fail closed.

Uploads are untrusted context, never legal authority. Injection-like text is
isolated and reported. Original filenames are encrypted; safe display aliases are
non-identifying. Expiry changes use eligibility/status only. Existing unlink/purge
paths must be disabled before any runtime under the strict no-deletion rule.

## 11. Security and data classification

| Class | Examples | Storage/logging rule |
| --- | --- | --- |
| Sensitive content | Questions, message/answer prose, upload bytes/names, fact values, model drafts | Application-level authenticated encryption; never ordinary logs or events |
| Protected evaluation | Private prompts, gold, outputs, reviewer notes | Separate owner-approved roots and lane-specific access; no development fallback |
| Legal source content | Immutable source/canonical text | Versioned vault and qualified access; citations expose only reviewed metadata |
| Privacy-safe metadata | Opaque IDs, states, times, counts, hashes, safe error codes | Plaintext SQLite permitted with strict allowlist; hashes do not make prose safe |
| Secret/capability | Encryption key, signing key, private-root/transport capability | Never stored in artifacts/logs; startup fails if required capability is absent |

SQLite is not described as wholly encrypted. Sensitive blob columns and upload
files use application encryption; IDs, timestamps, states, counts and other
allowlisted metadata remain plaintext. Backups containing sensitive blobs remain
encrypted and access controlled. Key format/source, AEAD version, rotation,
recovery and host file permissions must bind the existing owner key contract; no
key is generated or inferred by this design.

The threat model includes guessed job IDs, cross-conversation access, malicious
uploads/sources, prompt injection, local multi-user or malware access, DB/vault or
backup theft, socket spoofing, dependency/model tampering and resource exhaustion.
Controls are scoped read capabilities, file/socket permissions, exact hashes,
allowlists, encrypted content, fenced jobs, output gates and fail-closed startup.
Public use requires a new principal/authentication, authorization, abuse and privacy
design in Phase 3.

## 12. No-deletion safety contract

The current repository has automatic deletion paths for expired conversations,
uploads, unreleased answer versions, runtime records, caches and temporary files,
plus cascading database deletes. Their existence is a P0 implementation blocker.
No runtime, worker, cleanup command or broad test that can reach them may run while
the strict rule applies.

Before Phase-2 runtime work, add one startup-enforced deletion kill switch that is
off by default. A destructive method requires a typed, scoped, expiring owner
authorization naming object classes and exact identities; ordinary configuration,
TTL, retention policy, rebuild, deduplication or low disk is insufficient. Every
attempt emits a create-only report. Tests must prove API startup and workers cannot
purge under the default. Disk pressure rejects new work and alerts; it never
silently cleans up. Existing records/caches may become ineligible for use without
physical erasure.

## 13. Capacity, observability and operations

One model generation is single-flight. Queue, WebSocket, upload, DB-connection,
event and disk limits bind a versioned resource envelope. Index work and generation
are mutually excluded unless a measured owner-approved envelope permits overlap.
Queue-full, memory-admission or disk-critical conditions reject before side effects.

Measure queue age/depth; per-stage p50/p95/p99 latency; memory high-water; lexical,
vector and reranker results; relevance admissions/gaps; holds by cause; model usage;
verification/repair; outbox lag; reconnect/replay gaps; DB busy/corruption; disk;
backup/restore age; and source-currentness drift. Events use fixed taxonomies and
bounded cardinality. Redaction tests prove that no sensitive prose/path/name enters
telemetry. Existing SLO values stay provisional and observe-only until measured and
owner-frozen.

Runbooks cover the failure matrix, incident preservation, safe shutdown, restore,
candidate rollback, browser recovery and key unavailability. Recovery points and
times are `TBD_OWNER_RESOURCE`; no promise is invented. Restore tests write a new
verification target and never erase the source backup.

## 14. Generation pairing and rollout

A compatibility manifest binds API/schema, DB migration, web client, source scope,
parser/chunker, embedding, lexical scorer, reranker, relevance policy, index,
answer model, prompts, renderer and quality policies. A candidate mounts read-only.
In-flight jobs pin it. Pointer switch is atomic and separately authorized; rollback
selects an already verified compatible predecessor and never deletes the failed
candidate. Forward-only DB changes require a compatibility window and restoration
proof.

Phase 2 may build and evaluate a non-ACTIVE candidate only after its gates. Phase 3
alone may promote/live-activate it. Kill switch, backup/restore, rollback, browser
recovery and incident handling must be proved on the exact release.

## 15. Deferred owner gates and safe defaults

| Decision | Current safe design |
| --- | --- |
| Principal/authentication beyond the owner-only pilot | No public bind or accounts; Phase 3 design required |
| Exact GE default length | Explicit request/provisional config; calibrate in Phase 2 |
| Performance/concurrency/resource envelope | Conservative single-flight; reject when no approved budget |
| Overall upload byte/page limits | Reject public activation; freeze a measured local policy first |
| UDS/gRPC activation | Disabled until exact owner capability |
| Physical deletion/retention | No deletion; eligibility/status only |
| Languages/accessibility beyond current UI | Do not claim coverage; test and approve explicitly |
| Human referral channel | Provide honest information only; no automatic contact |
| Everyday-law expansion | Record housing, employment, family, immigration, benefits/debt and consumer gaps; add only through reviewed Phase-2 scope |
| GE versus retained Certification-60/30-30 controls | Do not substitute; bind the applicable contract before execution |

## 16. Living design and version selection

The active design is one editable working set. Update it in place when the owner
requests an improvement; do not create a design archive, predecessor chain, change
register, frozen pack or approval receipt unless the owner specifically asks for
one. The selected schemas are listed in `SCHEMA_REGISTRY.md`.

For each actual job or run, the selected contract/schema/policy versions and
digests are immutable inputs. Changing one requires a successor artifact or run.
This preserves reproducibility without freezing design documentation.

## 17. Data intent and response disposition

`QueryPlan v2` uses `NO_RETRIEVAL`, `KNOWLEDGE_ONLY`, `MATTER_ONLY` and `HYBRID`
for source routing. It adds exactly one response disposition: `ANSWER`, `CLARIFY`, `LIMITED`,
`REFUSE_UNSAFE`, `URGENT_NEXT_STEP`, `OUT_OF_SCOPE` or `SYSTEM_HOLD`. Safety,
scope, integrity and capability rules own the final disposition. A model may propose
classification but cannot grant authority, confirm a user fact or bypass a hold.

## 18. Retrieval-result and issue allocation

`retrieval-result.v1` binds the query plan, candidate and policy; every lexical and
vector hit; fused and reranked order; qualification/currentness decision; selected
and rejected evidence; degradation; issue allocation; gaps; timing and resource
use. The evidence pack binds its digest. Selection preserves relevant contrary,
exception and limiting authority and may return fewer than top-K. A changed result
cannot be substituted under the same evidence-pack or release identity.

## 19. Validation and release decision

`validation-report.v1` records deterministic checks separately from advisory model
review. Each check binds validator version, input digest, result, reason and affected
claim/evidence/fact IDs. Any material deterministic failure blocks the draft.
Repair creates one named child with a new digest and complete new report. The final
release manifest binds the report digest and permitted disposition.

## 20. Evaluation run and exposure custody

`evaluation-run.v1` binds authorization, case-version list/order, input projection,
full denominator, exact runtime/configuration, gold/currentness decisions, private
root capability, result states and exposure ledger. Missing, held, error, cancelled
and ineligible cases remain in the report. Unseen status requires a passing custody
and exposure check before the one authorized run.

## 21. Runtime capability and public boundary

`runtime-capability-manifest.v1` reports each required key, schema, deletion guard,
resource, candidate, model, transport, policy, root and compatibility capability as
`PASS`, `FAIL` or `NOT_APPLICABLE`. Operations declare required capabilities;
workers cannot self-grant or downgrade them. Public access remains Phase 3 and
requires principal/authentication, ownership, consent/privacy, isolation,
rate/abuse, accessibility/language, deployment, incident and human-help contracts.

## 22. Selected schema and canonical-digest contract

`SCHEMA_REGISTRY.md` is authoritative for new objects. The selected bundle includes
conversation/fact snapshots, QueryPlan, AnswerJob, job events, knowledge generation,
retrieval/evidence, ClaimSet, validation/release, capability, evaluation case/run
and optional training experiment. Legacy QueryPlan v1 and MatterFact v1 are readable
only for migration/audit.

Actual jobs/runs bind a schema-selection manifest digest. JSON validation uses Draft
2020-12 with format checks. Canonical digests use one pinned JSON canonicalization
implementation and UTF-8; dictionary insertion order, pretty printing and language-
specific float rendering are not part of the digest contract. Unknown properties,
non-finite numbers, duplicate logical IDs and schema fallback fail closed.

## 23. Complete job integrity chain

The required chain is:

`Request → ConversationSnapshot → MatterFactSnapshot → QueryPlan → RetrievalResult
→ EvidencePack → ClaimSet → ValidationReport → VerifiedRelease → terminal event`.

`AnswerJob` records each digest as the stage completes. A stage may write only under
the active attempt and lease generation. Validation checks both object ID and digest,
job/request identity, selected schema and expected predecessor. A missing or
substituted object stops the chain; the system does not reconstruct a convenient
replacement from current mutable state.

The terminal `done` event has its own event ID and strictly greater sequence. A
committed result binds release ID/digest; held/error/cancelled binds the exact
terminal kind and no release. Replay deduplicates by job, attempt, event ID and
sequence. If retained replay history cannot fill a gap, `reset_required` directs the
client to the authorized status endpoint.

## 24. Time, jurisdiction and currentness contract

Store separately:

- request-observed UTC and monotonic job durations;
- user-requested answer date and whether it is explicit, service-default or
  unresolved;
- source publication/version date;
- legal effective-from/effective-to, extent and commencement;
- reviewer qualification/currentness date; and
- answer release time.

A service-default answer date is visible in the plan and review output. Historical
questions remain historical; current questions do not inherit an evaluation-bank
cutoff. Wall-clock drift cannot change a frozen requested date or lease duration.

Jurisdiction is explicit, safely derived only for clarification, or unresolved. An
`ANSWER` plan cannot carry unresolved jurisdiction/date or `NO_RETRIEVAL`. Cross-
border issues allocate separate issue/jurisdiction evidence or limit/clarify; a
general England-and-Wales product default is never silently used to answer a
material foreign-law issue.

## 25. Context compilation and instruction isolation

The compiler creates typed sections in a fixed order: system contract, task/mode,
request scope, attributed facts, qualified legal evidence, named gaps and output
schema. Every untrusted section is delimited and labelled as data. Original source
paths, owner identifiers, private filenames, evaluator metadata and unseen-only
fields never enter the prompt.

Fact and evidence budgets are per issue plus global. The compiler records selected
IDs, rendered token counts, omissions and digest. Truncation occurs only at complete
fact/evidence boundaries; it never cuts a locator, quotation or JSON object. Prompt
injection text cannot change tools, policies, capabilities or response disposition.

## 26. Stable error and observability contract

Internal errors use a reviewed taxonomy: `validation`, `authorization`, `integrity`,
`capability`, `admission`, `retrieval`, `model`, `verification`, `publication`,
`cancelled` and `unexpected`. User responses contain only stable code, safe message,
retryability, correlation ID and measured retry time where applicable.

Logs/events permit opaque IDs, stages, counts, durations, resource values, digests
approved by allowlist and safe reason codes. They prohibit questions, answers,
facts, EvidenceSpan text, uploads, raw model frames, source paths, original filenames,
owner identifiers, secrets and protected evaluation content. Debug mode cannot
weaken this classification.

Measure acceptance/rejection, queue wait, stage latency, time to first progress,
time to verified answer, token counts, selected evidence, memory/disk high-water,
cancellation, reconnect/replay, factual holds, system errors and publication
integrity. Performance targets are accepted only after measurement on the exact
runtime; unmeasured targets do not become promises.

## 27. Evaluation and training object contract

`EvaluationCaseResult` records one case version, family, ordinal, isolated job,
terminal state, factual outcome/report, quality outcome/score where eligible, root
cause and review decision. The result manifest count must equal the run case count,
and its terminal states must reconcile with `EvaluationRun.result_counts`.

`TrainingExperiment` is required for any weight/adapter change. It binds objective,
authorization, corpus, rights/privacy/leakage reviews, excluded evaluation manifest,
base model, recipe, resource policy, internal validation, output artifact, metrics
and rollbackable terminal state. No evaluation, reviewer, user or unseen material
can be added through a looser export path.
