# Logical data model and ownership

## Aggregate boundaries

| Aggregate | Core identities | Allowed change | Preserved evidence | Primary writer |
| --- | --- | --- | --- | --- |
| Principal/session | principal ID, session ID, capability digest | Local-pilot session successor only | Prior session/capability decisions | API/auth boundary |
| Conversation | conversation ID, revision, owner scope | Append message or eligibility/state successor | Ordered message identities and digests | Conversation store |
| Message | message ID, conversation revision, ordinal | Append correction/successor | Encrypted content reference, role, digest and source time | API/conversation store |
| Conversation snapshot | snapshot ID, conversation revision | Create once for one job | Included/omitted message identities, digests and truncation reason | Answer worker |
| Upload | upload ID, bytes digest, conversation/job scope | Quarantine or append review successor | Encrypted bytes/name reference, type/size and custody state | Upload service |
| Matter fact | fact ID, revision, conflict group | Append a new status/value revision | Origin, FactRefs, value digest and affected issues | Fact adapter; user confirmation where required |
| Fact snapshot | snapshot ID, conversation revision | Create once for one job | Exact active, disputed and superseding fact revisions | Answer worker/fact adapter |
| Answer request | request ID, idempotency digest | Create once; conflicting replay rejected | Canonical request digest, mode/date/jurisdiction inputs | API |
| Answer job | job ID, attempt ID, lease generation | Forward-only stage/checkpoint under fenced owner | Frozen input digests, prior states and failure fingerprint | API then answer worker |
| Query plan | plan ID, schema/contract digest | Immutable after freeze | Data intent, response disposition, issues, budgets, gaps and capabilities | Planner plus deterministic policy |
| Retrieval result | result ID, plan/candidate/policy digests | Append within one fenced retrieval attempt, then seal | Complete route, rank, qualification, selection, timing and gap ledger | Retrieval service |
| Evidence pack | pack ID, EvidenceSpan IDs | Create once from sealed retrieval result | Source/version/locator/content/currentness/qualification chain | Evidence selector |
| Claim set | claim-set ID, draft digest | Create one set per draft/repair | Atomic user fact, legal rule, application and limitation bindings | Model boundary/context compiler |
| Validation report | report ID, draft/claim/policy digests | Create once per draft/repair | Deterministic checks, advisory findings and disposition | Validator orchestrator |
| Answer/release | answer ID, release ID, outbox ID | Create repair child; commit one verified release | Draft/report/repair/release lineage and exact digests | Worker and transactional outbox |
| Source/version | source ID, source-version ID, bytes digest | Append reviewed/admitted/held successor decision | Raw bytes, canonical object, locators and qualification | Intake and human reviewer |
| Research source intake | candidate/review/intake/content identities | Create-only materialization and staged INSERT-only catalogue version | Quarantine bytes, owner review, rights, provenance, deterministic canonical text/chunks and pending admission | Official research bridge; source reviewer separately |
| Knowledge generation | generation ID, manifest digest | Build → validate → seal; pointer change separate | Exact source/parser/chunker/model/scorer/count/file closure | Index worker; pointer owner separately |
| Runtime capability | manifest ID, process instance/config digest | Create a new short-lived readiness snapshot | Per-capability evidence and operation decisions | Startup/readiness verifier |
| Evaluation case | case ID, case version/family/digest | New reviewed version only | Question projection, gold/currentness/rubric identities and exposure | Evaluation preparation |
| Evaluation run | run ID, authorization/case-order/config digests | Planned → authorized → running → terminal | Full denominator, case results, metrics, custody and exposure | Authorized evaluation harness |
| Evaluation case result | result ID, run/case/job identities | Create one terminal result per case attempt | Factual gate, quality gate, system state and review lineage | Harness/validators/private reviewer |
| GE system run | system run/case/result identities, linked visible run | Create one immutable 32-result run | Exact system order, checks, outcomes and separate-denominator custody | System harness/validators |
| GE coverage audit | approved topology/cell/gap identities | Create a replayed visible-only audit after each complete run | Full approved topology, fixed-bank assignments, diagnostic coverage and missing cells | Evaluation controller/reviewer |
| GE diagnostic supplement | pack/case/gap/fingerprint identities | Append a create-new cumulative visible diagnostic pack | Novel missing-area bindings and permanent exclusion from fixed, unseen and training lanes | Evaluation preparation/reviewer |
| GE cycle assessment | loop/cycle/predecessor/decision-basis identities | Append one assessment per complete cycle | 331 + 32 + diagnostic results, diagnoses, coverage audit, repair lineage, exit checks and owner acceptance | GE loop controller/owner gate |
| Exposure ledger | exposure ID, content/family/lane digest | Append an exposure fact; never erase | Who/what/when/purpose and eligibility consequence | Custody verifier |
| Training experiment | experiment ID, corpus/base model/recipe digests | Planned → authorized → running → terminal | Rights/privacy/leakage decisions, metrics, artifacts and rollback | Approved training harness |
| Feedback | feedback ID, release/case reference | Append diagnostic record | Encrypted feedback and classification; no authority/training grant | Owner UI/reviewer |
| Owner decision | decision ID or current recorded instruction | Append or update the living policy view as directed | Exact execution artifacts retain the decision digest they used | Owner/control workflow |

## Identity and authorization rules

- Opaque identity is not authorization. Reads and writes require the exact owner
  scope, operation capability, expected revision and bound digest.
- Conversation, message, upload and fact objects cannot be fetched through guessed
  IDs or substituted across matters, evaluation cases or private roots.
- An idempotency key is scoped to principal, route and canonical request digest.
  Same key/same digest returns the same result; same key/different digest conflicts.
- A lease generation fences every checkpoint, retrieval result, draft, validation
  and release. A stale worker cannot publish after ownership changes.
- A terminal job cannot return to running. A committed release and cancellation
  cannot both win; the transaction/fence order selects exactly one terminal truth.

## Fact model

`MatterFactSnapshot v2` separates origin from status.

**Origin:** `user_statement`, `document_extraction`, `deterministic_derivation`,
`user_confirmation` or `system_placeholder`.

**Status:** `stated`, `extracted`, `confirmed`, `disputed`, `unknown`, `superseded`,
`rejected` or `scope_stale`.

A material application claim may use only allowed statuses under the selected
policy. A confirmed fact still is not legal authority. A disputed or unknown fact
cannot support a definite affected conclusion. Deterministic derivations bind all
input FactRefs and the derivation rule digest. Model inference cannot silently
create a confirmed fact.

Corrections append a successor with `supersedes_fact_id`. Competing active facts
share `conflict_group_id`. Facts also bind affected issue IDs, data type, encrypted
value reference, value digest, source messages/uploads and any temporal scope.

## Evidence and claim integrity chain

The release chain is:

`Request → ConversationSnapshot → MatterFactSnapshot → QueryPlan → RetrievalResult
→ EvidencePack → ClaimSet → ValidationReport → VerifiedRelease → Outbox event`.

Each arrow is enforced by both ID and SHA-256 digest. The release is invalid if any
object is absent, uses the wrong selected schema, refers to a different request/job,
or disagrees with the preceding digest.

The schema-v31 technical persistence boundary stores the ten selected answer-chain objects
(`ConversationSnapshot` through terminal event, plus `AnswerJob`) as encrypted,
content-addressed runtime objects. Immutable relational bindings record their
role, ordinal, schema and contract digest under one replay-verified chain digest.
The chain record remains `verified_unpublished` and cannot itself write
`release_outbox`, complete the job or grant evaluation/live authority. A separate
atomic database boundary may accept a freshly replayed proof, verify the actual
decrypted answer digest, recheck all immutable bindings and commit the outbox plus
an immutable `selected_answer_publications` row in one transaction. No runner or
owner authority is inferred from the existence of this seam.

Schema v31 also adds immutable encrypted custody for the separate 32-case GE system
run and for GE diagnostic/cycle records. A cycle embeds its exact replayable coverage
audit, preserves every diagnosis and diagnostic result, and cannot reach
`GE_COMPLETE_OWNER_ACCEPTED` while an approved coverage cell remains missing.
These records remain non-authorizing and cannot open unseen, train, promote, publish
or write an active index pointer.

Claim kinds are closed:

| Claim kind | Required bindings | Forbidden shortcut |
| --- | --- | --- |
| `user_fact` | One or more exact FactRefs and fact status | Treating prior assistant text or an unconfirmed inference as fact |
| `legal_rule` | Qualified EvidenceSpan IDs for jurisdiction/date | Search score, teaching note or model-generated citation |
| `application` | Applicable legal-rule evidence and exact factual premises | A conclusion based on absent, disputed or stale premises |
| `limitation` | Affected issue/claim and named fact/evidence/capability gap | A generic disclaimer used to hide unsupported analysis |

Materiality is derived and checked from claim kind, issue role and conclusion impact;
the model cannot evade support by setting `material=false`.

## Storage and data classification

| Class | Examples | Storage and projection rule |
| --- | --- | --- |
| Sensitive matter content | Questions, messages, fact values, uploads, answers, drafts | Authenticated application encryption; no ordinary logs/events |
| Protected evaluation | Private prompts, gold, results, reviewer notes | Separate owner-approved roots; prompt-only model projection; no fallback |
| Legal source content | Raw/canonical authority and EvidenceSpans | Immutable versioned vault; only reviewed metadata/citations exposed |
| Privacy-safe metadata | Opaque IDs, states, counts, times, safe codes and approved digests | Plaintext allowlist; a hash does not make sensitive prose safe |
| Secret/capability | Keys, private-root grants, signing and model transport capability | Never copied into artifacts/logs; absent capability fails closed |

Expiry changes eligibility and projection. It does not authorize physical deletion.
Caches, uploads, conversations, evidence, backups and temporary artifacts remain
subject to the strict scoped no-deletion rule.

## Evaluation and training separation

- Evaluator-only metadata, gold and unseen content never enter QueryPlan, prompts,
  ordinary conversation or the legal source store.
- Each independent evaluation case gets an isolated conversation, fact store and
  job. Deliberate multi-turn cases declare their sequence in the case contract.
- Case-family and content-digest overlap checks run across visible, training,
  internal validation and unseen lanes. Exposure invalidates the affected unseen
  claim and is recorded rather than hidden.
- Evaluation answers, reviewer notes, user histories and unseen findings cannot
  obtain training eligibility through relabelling or export.
- Training produces a successor adapter/model artifact. It never mutates the base
  model and invalidates affected model/evaluation evidence until requalified.

## Schema and migration rules

The selected versions are listed in [SCHEMA_REGISTRY.md](SCHEMA_REGISTRY.md). New
jobs accept only the selected version for each object. Legacy schemas remain
readable for migration/audit but cannot enter a new release chain. Migrations are
create-new, verify, switch and retain; no destructive rewrite is authorized.
