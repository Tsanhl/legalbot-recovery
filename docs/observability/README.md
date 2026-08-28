# Observability contract

This folder is the committed observability contract for LegalBot v1.11. Keeping
the schemas under `docs/observability/` avoids a case-only collision with the
gitignored runtime `logs/` directory.

Runtime payloads are **not** stored here. Structured operational events are
written under gitignored `logs/` at the repository root:

- `logs/operational-events.jsonl`
- `logs/failure-ledger.jsonl`

Evaluation metrics and safe traces are stored separately under the encrypted-
artifact/evaluation tree:

- `data/evaluations/e2e/metrics/snapshot-api.json`
- `data/evaluations/e2e/metrics/snapshot-worker.json`
- `data/evaluations/e2e/metrics/slo-api.json`
- `data/evaluations/e2e/metrics/slo-worker.json`
- `data/evaluations/e2e/traces/spans.jsonl`

Normal log files never contain the question, answer, prompt, source text,
original filename or filesystem path. A validated `live-evaluation-30-v1`
run retains every safe span so a long answer can be diagnosed by stage,
opaque section and database operation. Routine INFO traces are retained by a
deterministic 10% sample; DEBUG is off; WARN, ERROR and FATAL are retained in
full.

The durable catalogue (`data/catalog.sqlite3`) holds the same records in
`operational_events` and `failure_ledger` because jobs already live there.
JSONL under `logs/` is the export/audit trail. Provenance stays on
`jobs` / `index_builds` (hashes, versions, stage timings). Full answers are
never dumped into these logs.

The dated, lane-separated certification projection and incident-dossier contract is
defined in [V111_CERTIFICATION_RUN_LAYOUT.md](V111_CERTIFICATION_RUN_LAYOUT.md). That
projection is private, create-only and non-authorizing; it never replaces the canonical
evaluation package or these low-cardinality runtime streams.

Each run records its own Git identity and dirty-tree flag. This contract must
not hard-code an old checkpoint as if it described the current runtime.

## Metrics, traces and provisional SLOs

The admin observability view combines safe process snapshots with active job
progress. It exposes:

- queue depth and oldest queued-job age;
- active/stuck jobs and age since last durable progress;
- p50, p95 and p99 for queue wait, retrieval, rerank, generation,
  verification, release and completion;
- time to first token, input/output tokens and peak model memory where the
  local sidecar reports them;
- per-job trace spans for queue admission, worker claim/heartbeat, retrieval,
  rerank, frozen-evidence storage, opaque answer sections, verification,
  repair and release;
- the longest retained span and the aggregate bottleneck stage.

`config/observability_slo.yaml` is an internal, observe-only calibration
policy. Its latency and success targets are not an SLA, a promotion gate or a
promise to the user. A route/word-band latency remains `insufficient_samples`
until both its declared per-metric observation minimum and its distinct
successful-job minimum are met. Stage calls from one long answer therefore
cannot masquerade as a multi-run baseline. After the development-live baseline
is reviewed, changing a target requires a versioned policy update.

The four golden signals are interpreted from the answer user's perspective:

- **Latency:** separate successful/limited and error completion paths, plus
  stage percentiles.
- **Traffic:** admitted, started and terminal jobs by bounded route/word band.
- **Errors:** system failures and held results; a knowledge-limited but safely
  released answer is tracked separately rather than hidden as success.
- **Saturation:** queue depth, oldest age, busy model worker and reported peak
  MLX memory.

Alerts and owner warnings should be symptom-led: stale progress, an exhausted
success error budget, high completion latency, or a growing queue. CPU or
memory alone are diagnostic context rather than proof of user harm.

## Three records

### 1. Operational events (`operational-events`)

Append-only decisions and failures. `event_type` is one of:

`operational_failure`, `data_quality_failure`, `source_policy_failure`,
`privacy_failure`, `retrieval_degradation`, `quality_gate_failure`,
`policy_decision`, `retry_scheduled`, `recovery_succeeded`,
`terminal_failure`, `dlq_transition`, `warning`.

A2/policy outcomes (`clarify`, `refuse`, `answer-safe-and-refuse-unsafe`,
`verified_limited:index_not_ready`, `verified_limited:retrieval_zero_hits`)
are `policy_decision` and **must not** inflate operational failure metrics.

Retrieval must keep distinct codes (`index_not_ready`, `retriever_unavailable`,
`zero_hits`, `filtered_out`, `wrong_jurisdiction`, `historical_above_current`,
`expected_authority_missing`, `incomplete_proposition_span`,
`reranker_unavailable`, `vector_degraded_lexical_only`). They are never
collapsed to `no_evidence`.

Fingerprint: `sha256(component + stage + failure_code + source_id)`.
The first event is stored in full; repeats increment `occurrence_count` and
refresh `last_seen`.

### 2. Failure ledger (`failure-ledger`)

One durable row per fingerprint/failure_id. States:

`open` | `retrying` | `recovered` | `terminal` | `waived`

Waive requires an owner reason. Retries link to the original `failure_id`.
Recovery closes the row. Exhaustion emits `terminal_failure` and
`dlq_transition`.

### 3. Provenance (jobs / index_builds)

Not a third JSONL dump. Build, config and code provenance rides on the
existing catalogue rows (`parser_version`, `chunker_version`,
`index_schema_version`, `embedding_model_version`, `source_manifest_hash`,
idempotency key, stage timings) and is copied as hashes into event
`provenance` objects. Git SHA/branch are recorded on every event.

## Privacy rules

Never persist:

- secrets, API keys, tokens
- system prompts or chain-of-thought
- absolute private paths (`/Users/…`, `C:\…`)
- full private source text
- unnecessary full answers

Public APIs expose only `user_or_owner_safe`. Routine internal detail is stored
only as a one-way SHA-256 correlation value; sensitive diagnostic prose belongs
in an explicitly encrypted, retention-bound artifact rather than normal logs.
Privacy-attack fields use `requested_secret="[REDACTED]"`. `/Users/` and
Windows paths in public-safe messages become `[LOCAL_PATH]`.

## Fail closed

Log-writing failure on the promote/rollback path aborts the pointer write.
A required source family omitted or truncated by a chunk cap
(`required_source_family_truncated`) cannot become `CANDIDATE`.
