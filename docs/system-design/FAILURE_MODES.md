# Failure, fallback and recovery matrix

Every failure records command/gate, stage, stable error code, attempt/lease and
relevant artifact identities. Retry requires a targeted repair or an explicitly
classified transient condition. An unchanged failing command is never rerun hoping
for a different result. After the same fingerprint fails twice despite targeted
repairs, that path stops before a third retry.

| Failure | Detection | Safe user outcome | Internal recovery | Proof before use |
| --- | --- | --- | --- | --- |
| Missing material fact | QueryPlan has an unresolved outcome-changing fact | Supported general guidance plus a precise clarification; no affected conclusion | Preserve missing-fact code; new turn/job after reply | Clarification, irrelevant-question and correction tests |
| Conflicting facts | Active fact revisions share a conflict group | State conflict and ask which is correct | Preserve revisions; never auto-resolve from model confidence | Wrong-snapshot, concurrent-turn and correction tests |
| Fact origin/status confusion | Claim uses an origin as if it were confirmation | Hold affected claim | Enforce MatterFact v2 origin/status and policy | Origin/status matrix and model-inference tests |
| Conversation snapshot mismatch | Message IDs/revision/digest differ from QueryPlan/job | System hold; no model call | Create a correctly bound successor job | Concurrent append, omitted-window and cross-matter tests |
| Wrong/unclear jurisdiction | Jurisdiction/date policy cannot qualify request | Clarify or limit scope; no silent E&W assumption | Keep affected lanes/issues unresolved | Cross-border, historical and requested-date tests |
| Unsupported/stale authority | No span passes identity, role, jurisdiction, date/currentness or relevance | Verified limit or hold with named evidence gap | Preserve rejection ledger; route to reviewed source work | No-source, stale, extent/commencement and contrary-authority tests |
| Prompt injection | User/upload/retrieved prose attempts to alter system/tools or leak protected data | Continue with isolated safe content or hold | Quarantine affected context; preserve source identity | Adversarial message/upload/retrieval and delimiter tests |
| Unsafe assistance | Deterministic rule or reviewed rubric fires | Refuse only unsafe assistance and offer safe lawful alternatives | Record safety code; avoid unnecessary sensitive solicitation | Paired safe/unsafe and over-refusal tests |
| Urgent harm/deadline risk | Supplied facts activate urgency policy | Immediate supported next step without outcome/referral guarantee | Prioritize approved information; preserve uncertainty | False-reassurance, urgent-handoff and deadline-source tests |
| Invalid QueryPlan | Schema/version/digest/budget/capability mismatch | System error; no retrieval/model call | Fix planner/policy before new attempt | Selected-schema and conditional-invariant tests |
| Lexical route failure | Search error or generation identity mismatch | Limited/held/system error under frozen route policy | No silent route substitution | Exact-reference, route failure and parity tests |
| Vector route failure | Model/dimension/index/schema mismatch | Limited/held/system error | Mark candidate unusable for semantic route | Corrupt vector, dimension and model-pin tests |
| Fusion/reranker failure | Timeout, malformed score/order or model mismatch | Hold or named retrieval gap | Never pass unreranked fused order unless policy explicitly qualifies it | Timeout, malformed, deterministic tie and budget tests |
| Unset relevance policy | Threshold/calibration identity missing | Semantic admission unavailable | Separately qualified exact route only; otherwise hold | Calibration-policy gate and unseen-exclusion tests |
| Issue evidence starvation | Duplicate/high-ranked material consumes an issue budget | Limited/clarify/hold with issue-specific gap | Re-run only after allocation policy repair | Multi-issue, exception, contrary-authority and dedup tests |
| Retrieval ledger mismatch | EvidencePack differs from sealed RetrievalResult selection | Hold; no context/model use | Preserve both identities; repair compiler/selector | Rank→qualification→pack substitution tests |
| Missing/corrupt candidate | Manifest/file/count/hash/parity/attestation mismatch | Service unready/system error | Preserve candidate; build a new generation | Full closure, read-only and retrieval-attestation proof |
| Parser/OCR nondeterminism | Same input/tool identity yields different canonical/chunk digest | Candidate invalid | Diagnose tool/config/environment; no old hash reuse | Reproducibility fixture across representative sources |
| Source update conflict | New bytes/metadata differ from admitted version | Existing qualified version remains pinned or answer becomes stale/limited | Quarantine and review a new source version/generation | Update, amendment, later-treatment and rollback tests |
| Context budget overrun | Compiled tokens/issue quotas exceed frozen plan | Reduce selection deterministically or hold | Never truncate locators/claims invisibly | Tokenizer parity, boundary and oversized multi-issue tests |
| Model unavailable/timeout/malformed stream | Capability/deadline/frame/final digest fails | Held/system error; no partial model prose | Fence/cancel transport; retain safe diagnostic metadata | UDS capability, timeout, cancel and frame-identity tests |
| ClaimSet invalid | Unknown claim kind, missing FactRef/EvidenceSpan, wrong draft digest or materiality evasion | Hold draft | Reject before rendering; one named repair at most | Claim-kind, materiality and substitution tests |
| Citation/quotation/calculation mismatch | Locator/text/input/rule validation fails | Hold/limited without false detail | Deterministic renderer cannot invent/correct identity | False quote, citation, date, amount and calculation tests |
| Validator disagreement/failure | Deterministic failure, advisory uncertainty, timeout or malformed report | Hold or verified limit; raw draft never released | Deterministic material result wins; at most one repair | Same-model reviewer failure and deterministic precedence tests |
| Validation/report substitution | Draft/claim/evidence/fact/policy digest differs | No release/outbox commit | Create matching report for correct child draft | Digest-substitution and stale-report tests |
| DB busy | Bounded transaction deadline exceeded | Retryable queue/service response; no partial release | Back off without starving heartbeat | Contention, busy-timeout and lease tests |
| DB corruption/snapshot drift | Integrity/snapshot check fails | Service unavailable | Stop writers; restore only under approved create-new procedure | Integrity and restore drill |
| Encryption key absent/wrong | Startup/decrypt authentication fails | Service unready; generic error | Do not regenerate key or expose ciphertext detail | Absence, wrong-key and approved rotation recovery tests |
| Queue/resource admission failure | Frozen queue/memory/disk threshold fails | `429/503` with safe retry information | Reject before durable/model side effects | Load and no-side-effect rejection tests |
| Worker crash/stale lease | Heartbeat/fencing detects lost owner | Recoverable progress/status; no duplicate answer | Resume only exact compatible checkpoint, else successor | Crash at every stage and stale-owner publication tests |
| Outbox crash | Transaction/outbox publication state mismatch | Reconnect returns only committed truth | Replay release digest idempotently | Crash before/after commit and duplicate publication tests |
| Cancel/publication race | Fence and transaction ordering check | One stable cancelled or committed terminal state | Preserve event history; never expose both | Repeated cancel and commit-race tests |
| WebSocket disconnect/gap | Socket closes, sequence gap or slow consumer | Reconnect/status fetch; no new job | Replay by job/event/attempt/sequence; reset when history unavailable | Disconnect, gap, replay, storm and slow-client tests |
| Terminal event ambiguity | `done` lacks unique ID/sequence/release binding | Status fetch until stable terminal truth | Reject ambiguous event; use distinct committed terminal event | Duplicate/reconnect and event/release binding tests |
| Clock anomaly | Wall clock moves or monotonic ordering fails | Reject affected timing/expiry decision | Use monotonic durations plus recorded UTC; operator review | Clock rollback/forward and expiry tests |
| Disk pressure | Warning/critical policy fires | Reject new work before writes at critical state | Alert and preserve; never auto-delete | Fill-to-threshold and no-cleanup tests |
| Deletion path without capability | Default-off guard observes destructive call | Operation rejected; service safe/unready | Create-only attempted-deletion report | API/worker/startup coverage of every destructive path |
| Backup/restore failure | Hash, permission, schema or query verification fails | No repair/promotion | Preserve failed target and source backup | Current successful restore drill |
| Capability stale/absent | Required capability FAIL/expired/bound artifact changed | Operation unready; safe unrelated reads may remain | Recompute readiness; workers cannot self-grant | Per-operation grant, expiry and revocation tests |
| Evaluation denominator drift | Case/order/result counts do not reconcile | Run invalid; no score/acceptance conclusion | Preserve run; repair harness before successor | Duplicate, missing, held/error and sum reconciliation tests |
| GE cause is unproved or unstable | Failed/held/sub-70 result lacks a primary cause, evidence digest or stable fingerprint | Finding remains unresolved; no repair or closure claim | Classify gate/check, stable code, case/family and bound artifacts; obtain review evidence | Missing-cause, changed-artifact and same-fingerprint tests |
| GE diagnostic contaminates a fixed denominator | A new gap question appears in the 331 principal bank or 32 system count | Run invalid; diagnostic score excluded | Preserve the accepted banks; create a separate visible diagnostic supplement | Exact 331/32, separate-count and no-score-inflation tests |
| GE diagnostic lacks a demonstrated coverage gap | Question has no unresolved fingerprint/novel coverage target or duplicates existing coverage | Do not execute or count the diagnostic | Reject or return for independent review; preserve the proposed record | Gap-link, coverage-cell, family and duplicate tests |
| GE coverage topology is narrow, substituted or self-authorized | Required topic/public domain is omitted, renamed, aliased or reordered, or a caller supplies only a digest/self-sealed manifest | Coverage audit/cycle closure rejected | Replay the exact stored owner request and resolution; issue and replay the opaque verifier capability over all 23 breadth domains | Arbitrary-hash, omitted/duplicate/aliased domain, stale-decision, order/substitution and TOCTOU tests |
| Knowledge gap bypasses source admission | Downloaded bytes/chunks/embeddings are inserted into an active generation without quarantine/review/attestation | Candidate unready; affected retrieval held | Quarantine immutable official-source bytes; review, chunk/embed into a new non-ACTIVE generation and attest before any pointer decision | Source allowlist, currentness, immutable generation, parity and no-direct-write tests |
| GE source uses a generic or substituted provenance receipt | Scope cannot replay the diagnosed v2 result, research intent, retrieval attempt, reviews, quarantine/vault bytes, staged/current records and chunks | Source excluded; successor build blocked | Preserve the attempted receipt and repair the exact chain; never infer trust from a marker hash | Legacy-only, orphan, substitution, byte/record drift and approval-transition tests |
| GE expansion shrinks or replaces its knowledge base | Successor is not a strict superset of the exact sealed predecessor or has no qualified addition | Scope/build rejected; predecessor preserved | Rebuild the scope from the replayed ordered predecessor members plus nonempty disjoint additions | Equal/shrink/replacement/reorder/duplicate/mutation/stale-predecessor tests |
| Generic path reads a held GE generation | Retrieval, benchmark, research, vector, evidence, live or direct-Lance path observes GE selection/held markers without the opaque capability | Reject before opening Lance or invoking a model | Use only the dedicated capability-bound GE evaluation loader | Duck-type capability, arbitrary build-ID and public-entrypoint tests |
| GE recovery trusts caller evidence or exceeds retry limit | Supplied report differs from disk/DB or the same persisted failure would be attempted a third time | Recovery rejected; files and pointers unchanged | Recompute audit/reconciliation, compare expected digests and stop the repeated path | Forged-report, attempt-three, pointer preservation and row-parity tests |
| Incomplete GE successor rerun | Repair is judged from a targeted case or partial bank only | No successor acceptance or unseen decision | After targeted checks, rerun all 331, all separate 32 and all accumulated diagnostics | Partial-run rejection, exact order/count and cumulative-diagnostic tests |
| GE exit asserted from technical validity alone | Run is structurally valid but retains a factual hold, sub-70/critical-floor failure, failed system scenario, unresolved gap or regression | Keep loop open; no unseen or publication gate | Apply the complete GE exit criteria and preserve the result | Held, threshold, system, open-finding, regression and exposure tests |
| Evaluator projection leak | Gold/topic/rubric/unseen-only field reaches planner/model | Run invalid and exposure recorded | Quarantine result; repair projection | Field allowlist and prompt capture tests |
| Evaluation/training contamination | Content/family/source overlaps protected lane | Affected unseen/training eligibility fails | Append exposure; replace only through independent custody | Family-aware semantic/digest leakage audit |
| Training rights/privacy/corpus mismatch | Experiment inputs differ from approved manifest | Training blocked or invalid | Preserve attempted run; no adapter activation | Rights, privacy, corpus closure and base-model binding tests |
| Training includes evaluation, user or unseen material | Corpus overlaps any principal/system/diagnostic evaluation record, gold/review material, user history/upload or protected unseen content/finding | Experiment invalid; no output activation | Preserve exposure evidence; rebuild a separate reviewed corpus under a new authorization | Digest/family/semantic leakage, user-data exclusion and custody tests |
| Repeated GE fingerprint after two repairs | The same gate/code/case-family/artifact fingerprint fails twice despite targeted changes | Stop that repair path before a third attempt | Preserve both attempts and report the blocker/root cause; require a materially different reviewed plan | Stable-fingerprint counting and third-attempt rejection tests |
| Premature GitHub publication | Commit/push is attempted before GE closure or without the reviewed publication scope/destination | No Git mutation | Prepare exact diff/tests/evidence inventory and obtain the separate publication gate | Closed-loop status, destination, diff and authority tests |
| Public principal/ownership absent | Non-loopback/public request lacks approved identity/ownership | Refuse admission | No guessed-ID or shared-root fallback | Cross-user, tenant-isolation and account/session tests |
| Human-help channel unavailable | UI implies contact/transfer without capability | Information-only referral wording | Remove false action; require consent and real channel | Consent, failure and no-false-transfer tests |

## Fallback precedence

Deterministic precedence prevents a model or UI from selecting a more permissive
outcome:

1. integrity/capability failure → `SYSTEM_HOLD`;
2. unsafe request → `REFUSE_UNSAFE` for the unsafe portion;
3. urgent safety/deadline need → `URGENT_NEXT_STEP` with supported scope;
4. unsupported jurisdiction/service scope → `OUT_OF_SCOPE`;
5. outcome-changing fact gap → `CLARIFY`;
6. useful supported material with a material limitation → `LIMITED`; and
7. fully supported request → `ANSWER`.

Urgency can coexist with a limited legal answer, but it never bypasses integrity,
privacy or evidence checks. No fallback can change the question date/jurisdiction,
lower currentness/evidence requirements, expose another matter, publish draft
prose, turn teaching into authority or consume protected unseen content.
