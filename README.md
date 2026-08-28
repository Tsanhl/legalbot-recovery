# LegalBot v1.11

LegalBot v1.11 is the sole writable clean-room, owner-only legal
research assistant worktree for macOS. It is independent of the previous
project: only source documents are eligible for import. The application keeps
legal evidence, private teaching material and assessment guidance in separate
lanes, binds every material claim to exact source spans, and renders OSCOLA 5
citations deterministically.

Current recovery status (29 August 2026): this clean project was reconstructed
from the last provable v1.11 working tree. It is non-ACTIVE and intentionally
contains no Git metadata or runnable Lance candidate. The catalogue and 316
exact source files are present, while unrecoverable historical artifacts remain
explicit gaps. Phase 1 must be re-baselined before any later phase is resumed.
See [`docs/CURRENT_STATE.md`](docs/CURRENT_STATE.md) and
[`docs/status/V111_PHASE1_RECOVERY_READINESS_20260829.md`](docs/status/V111_PHASE1_RECOVERY_READINESS_20260829.md).

The default production endpoints are:

- Application and API (same origin): `http://127.0.0.1:8777`
- Model runtime: `http://127.0.0.1:8778`

During development only, Vite remains on `8777` and proxies `/api` to FastAPI
on `8776`. The model runtime remains on `8778` in both modes.

## Architecture

```text
Law + project-owned source vault
        │
        ▼
immutable SHA-256 vault ──► canonical provenance Markdown
        │                            │
        │                            ▼
        │                  structural chunks + catalogue
        │                            │
        │                            ▼
        └──────────────► lexical + 1024-d vectors ─► RRF ─► Qwen reranker
                                                       │
question ─► durable leased job ─► route + section plan ─► verified spans ──┘
                                                       │
                                                       ▼
                  Qwen3.5-9B 4-bit ─► evidence-bound claims
                                                       │
                                                       ▼
             identity/currentness/privacy gates ─► 70+ rubric
                                                       │
                                                       ▼
        exactly-once release outbox ─► verified_full | verified_concise | verified_limited
```

SQLite is the durable local source of truth for catalogue, leased jobs, stage
attempts, frozen evidence packs, releases, encrypted conversation sessions,
reviews, knowledge-update events, research tasks, source-update observations
and the append-only refinement inbox. Encrypted
content-addressed runtime objects under `data/runtime_objects` provide local
checkpoint/cache semantics; there is no cloud object store. Raw bytes and
canonical Markdown are content-addressed. LanceDB generations are immutable,
physically separate authority/teaching/assessment lanes, and only
`data/indexes/ACTIVE.json` selects the live build; there is no legacy fallback.

User uploads are encrypted before being written under `data/uploads`. They are
answer-scoped, untrusted context with a default terminal-job retention period;
submitting one for source review creates only a quarantined intake decision and
never grants it authority status. The disposable retrieval cache stores only
build-bound source/chunk IDs, ranks and scores. It never caches questions,
source text, evidence packs, answers, online results or upload-scoped results,
and promotion or rollback invalidates obsolete build namespaces.

Conversation history uses a bounded sliding window, not an unbounded prompt.
The durable relational record expires after 30 days of inactivity by default;
a process-local LRU cache is capped at 128 sessions and seven days, and each
session has hard message and model-context token limits. SQLite content is
encrypted and immutable per message. Redis is intentionally not required for
the owner-only local deployment; the cache interface can take a different
adapter later without changing the durable record. Conversation text is
context only and is never treated as legal evidence. Model-backed standalone
query rewriting is implemented as an encrypted, checkpointed retrieval stage;
it rejects invented fact atoms and forbidden evidence fields, and falls back to
the original question on any failure. It remains disabled until the exact
Phase-2B model-transport gate.

## Prerequisites

- macOS on Apple silicon
- Python 3.13
- `uv`
- Node 24 LTS
- the project-local OCRmyPDF/Tesseract/Ghostscript/QPDF toolchain before an OCR-complete promotion

The project deliberately refuses Python 3.14 for model downloads because the interrupted Base download failed in that toolchain’s finalisation path.

## Install

```bash
cd "${HOME}/Desktop/LegalBot-v111-Recovery-20260829"
uv sync --all-extras
uv sync --project model-runtime
cd web && npm ci && cd ..
uv run legalbot init
```

The first `init` creates a local encryption key in macOS Keychain. It is not written into the repository.

OCR setup is isolated under the ignored `tools/ocr` directory and never installs
Homebrew or modifies system Python. Review the non-mutating plan first, then run
it with the SHA-256-verified micromamba binary described in
[`docs/local-ocr-toolchain.md`](docs/local-ocr-toolchain.md):

```bash
python3 scripts/setup_ocr_toolchain.py
python3 scripts/setup_ocr_toolchain.py --execute --micromamba /path/to/verified/micromamba
```

## Recover the existing Base checkpoint

Verification is non-destructive and does not redownload 19 GB:

```bash
uv run python scripts/model/recover_base_shards.py
```

The default command now reverifies the archived checkpoint. To create the
archive from another recovered/download directory on a new installation, pass
that explicit directory together with `--execute`. The four shards are matched
against pinned official sizes and SHA-256 values, copied/APFS-cloned into
`models/archive/Qwen3.5-9B-Base`, reverified and labelled archival-only. The
interrupted download is not a runtime dependency and may be moved to macOS
Trash only after the archive and real 4-bit runtime smoke both pass.

## Download the runtime model

```bash
uv run python scripts/model/download_runtime_model.py
uv run python scripts/model/download_runtime_model.py --execute
```

The executable path enforces Python 3.13, disables Xet, uses one worker and downloads the pinned post-trained `mlx-community/Qwen3.5-9B-4bit` revision into staging before atomic promotion.

## Download the hybrid-retrieval models

```bash
uv run python scripts/model/download_retrieval_models.py
uv run python scripts/model/download_retrieval_models.py --execute
```

This downloads the official `Qwen3-Embedding-0.6B` and `Qwen3-Reranker-0.6B` checkpoints at full commit-SHA pins into `models/retrieval`. The embedding build is fixed at 1,024 dimensions. Both downloads use resumable staging, disabled Xet and one worker; mutable `main` revisions are never used by a sealed index build.

## Account for sources and build the hybrid index

```bash
uv run legalbot scan
uv run legalbot build-index
uv run legalbot promote BUILD_ID
```

Scanning never guesses success from an empty parser result. Every file receives a catalogue outcome: citable, private teaching, assessment guidance, duplicate, OCR required, encrypted, unsupported or quarantined. The generated Markdown retains document structure, comments/revisions as separate streams and source provenance. Only an evaluated candidate can become `ACTIVE`.

Production builds require the Qwen3 embedding and reranker providers pinned to immutable Hugging
Face revisions. The manifest records `repo@revision`; a project-local retrieval model is used only
after every file matches its downloader-generated SHA-256 provenance manifest. The deterministic
1,024-dimensional hash embedding is restricted to tests and diagnostics and cannot satisfy
promotion. Catalogue reads, embedding calls and LanceDB writes run in bounded batches, so an index
build does not materialise the whole corpus in memory.

The reranker is loaded only as the pinned `Qwen3ForCausalLM`. It applies the official single-token
`yes` versus `no` log-softmax scoring with left padding and a bounded batch, and fails closed if a
sequence-classification model or missing vocabulary head appears. This prevents a fallback from
silently creating an untrained `score.weight` classifier head.

Index construction requires an owner-approved v1.1 retrieval specification at
`benchmarks/retrieval/v1.1.jsonl`. Its fundamental gold is stable authority identity plus
legal locator/span hash, never an implementation-specific chunk ID. The frozen source version
preserves review provenance. The checked-in 24-row development-and-promotion pack is
owner-frozen. Candidate-time binding resolves each frozen legislation row to the one sealed
current source version only when its exact spans and provision qualifications remain valid;
the frozen benchmark bytes are never rewritten. A build seals the benchmark and policy but
remains `built_unscored`; an immutable external attestation must meet Recall@5 1.0, Recall@10
0.95 and MRR 0.8 before it becomes a candidate. Only the owner may then promote it to
`ACTIVE`. The former v1.0 pack is historical and invalid for promotion.

Jurisdiction filtering uses both a broad typed class and an exact normalized key. Non-core
jurisdictions such as the United States, Canada and Australia therefore never share a LanceDB
candidate pool merely because each is represented by the broad `comparative` enum.

## Run the production-style local application

```bash
cd web && npm run build && cd ..
./scripts/start.sh --check
./scripts/start.sh
```

FastAPI serves both the built SPA and `/api/v1` on `127.0.0.1:8777`; the MLX
model is a private sidecar on `127.0.0.1:8778`; and a separate durable answer
worker claims jobs by expiring lease. The API never runs answer work in an
in-process background task. The launcher refuses a
non-loopback host, a non-MLX runtime, missing UI assets, missing model
provenance or missing weights. Stop it with `Control-C`; both child services are
terminated together.

Official-source crawl is a **separate** SQLite queue and worker. It is not
Google, Westlaw or open-web search, it does not accept a raw user question, and
it does not feed the current answer or write `ACTIVE`. First-live
`./scripts/start.sh` keeps it off.

Knowledge freshness uses the same control plane rather than a second crawler:

```text
local webhook / detected gap / official change
        -> idempotent knowledge_update_event
        -> direct durable admission or bounded batch queue
        -> allowlisted official fetch
        -> encrypted quarantine
        -> deterministic checks + owner proposition-level admission
        -> one consolidated successor candidate (if required)
```

The webhook cannot index, embed, patch `ACTIVE`, or answer from newly fetched
bytes. `source_date` preserves the date of the official record;
`last_updated` records observation/ingestion time separately. Future candidate
rows carry both values, and retrieval removes older eligible versions of the
same authority before evidence qualification.

For this legal corpus, a generic `write-then-delete` update is intentionally
replaced by `build-new-generation -> verify -> owner-approved pointer switch`.
Old source bytes, source versions and sealed LanceDB generations remain
auditable. A changed webhook event can only open quarantine/review work; it
cannot delete the prior authority or create a searchable version in place.

```bash
uv run legalbot research-enqueue --task-type source_update_check \
  --subject contract --source-id legislation_gov_uk \
  --authority-identity-id ukpga:1980:58
uv run legalbot research-queue
LEGALBOT_OFFICIAL_RESEARCH_ENABLED=true uv run legalbot research-worker --once
```

Answers above the direct-generation budget are divided into bounded sections
(normally 500–700 words). Each section receives an immutable evidence-pack
digest and encrypted checkpoint, model generation remains single-flight, and
retrieval concurrency starts at four. Restart resumes incomplete sections and
the transactional outbox makes only one release visible.

After it starts, the model contract can be checked in another terminal:

```bash
uv run python scripts/model/smoke_runtime.py --expect-backend mlx_lm
```

For development with hot reload, run:

```bash
LEGALBOT_MODEL_MODE=mlx ./scripts/dev.sh
```

This runs Vite on `8777`, FastAPI on `8776`, and MLX on `8778`.

The first release is deliberately loopback-only. There is no account system,
friend access, cloud hosting or automatic training export.

Question requests default to `local_only`, and the first-live launcher enforces
that mode with the online adapter disabled. A distinct, separately leased
`ResearchWorker` implements the later connected-crawler control plane. It uses
registered official-source adapters, fixed public subject/citation identities,
bounded priority/candidate/concurrency rules, encrypted quarantine and human
review; it has no method that can approve a source, rebuild an index or promote
`ACTIVE`. Its daily and weekly schedules are installed disabled. The worker is
not started by `scripts/start.sh` and must not be enabled until the local E2E run
and the separate connected canary pass. Find Case Law remains metadata/link-only
without the required computational-analysis licence.

### Browser and model transports

The owner browser consumes bounded, replayable job events over
`/api/v1/jobs/{job_id}/events/ws`; reconnects resume from an explicit sequence.
Only progress metadata and the identity of a fully released answer cross that
WebSocket. Raw model tokens and unvalidated draft sentences never do.

The service-to-service replacement contract is defined in
`backend/app/model_runtime/proto/legalbot_model_runtime.proto`. It is a
server-streaming gRPC contract with TTFT, sentence evidence/standard status and
knowledge-hurdle diagnostics. Its production policy is Unix-domain-socket only
with no TCP fallback. Generated stubs, cancellable token streaming, deadlines,
single-flight backpressure, health and crash handling are implemented and
tested against a real owner-only UDS. During Phase 2A this remains
non-authorizing preparation: the existing loopback HTTP runtime stays in place,
and the production activation capability cannot be created until the exact
Phase-2B owner payload passes.

### Catalogue backup and maintenance

`scripts/create_catalogue_backup_restore_drill.py` creates a private SQLite
online backup and proves a real isolated restore with full integrity and
foreign-key checks. `scripts/plan_catalogue_maintenance.py` is observe-only: it
reports the Sunday 02:00–06:00 Hong Kong maintenance-window preconditions and
never deletes chunks or runs `VACUUM`. Large classification must use bounded
primary-key batches; compaction uses create-new `VACUUM INTO`, verification and
a separately approved atomic swap. Capacity and backup-age/count alerts are
included in the privacy-safe control-plane snapshot. No policy automatically
deletes a backup.

The owner UI also exposes a single append-only refinement inbox for `debug`,
`missing` and `answer_feedback` records. Released-answer feedback is bound to an
answer/section/claim/evidence identity and any free-text note is encrypted. It
may lead to triage and a versioned regression, but cannot change sources,
prompts, model weights or `ACTIVE` automatically. Subject readiness views are
diagnostic projections over the one authority store; source counts are never
treated as proof that a legal issue is answerable.

## Quality behaviour

Truth and academic quality are separate gates. A material evidence/privacy
defect never releases unsupported legal prose. Length, structure, application
and academic-quality weaknesses are repaired section-by-section. Every raw, structured,
repaired and released version is encrypted and persisted with an explicit
diff. A short verified answer becomes `verified_concise`; a supported answer
with legal or evidence gaps becomes `verified_limited`. Until blind human calibration, an
automated academic score below 70 is advisory and triggers repair but is not itself a
release-safety gate. If bounded repairs cannot produce any supported legal answer, the user receives a terminal
verified status response while the owner retains the encrypted held draft and
named findings. Jobs therefore finish visibly rather than hanging, without
misrepresenting an unsupported draft as a full answer.

The model-runtime checkpoint is a pinned post-trained general Qwen model. The
approved assessment rules are runtime drafting/evaluation instructions; they
do not alter model weights. Evaluation outputs are marked
`eligible_for_training: false`. Any LoRA/fine-tuning export requires a separate
source-rights, privacy, dataset and owner-approval phase.

Safe aggregate readiness and operational reports can be regenerated without
capturing raw questions or source text:

```bash
cd backend
uv run python -m app.cli readiness
uv run python -m app.cli metrics
```

Privacy-safe owner projections are written under `logs/events`, `logs/metrics`
and `logs/traces`; SQLite/evaluation storage remains the durable source of
truth. Routine INFO projections use deterministic 10% sampling, while WARN,
ERROR, FATAL and every controlled Live60 evaluation trace are retained in full.
The provisional `local-e2e-provisional-v2` SLO policy is observe-only and is not
an SLA or promotion gate.

The legacy 240-case draft suite retains the earlier 16 long-form questions as
development-only, unannotated seeds. The sealed
`live-evaluation-30-v1` package remains immutable historical audit material.
The current controlled contract is the separate `live-evaluation-60-v1`: 60
exact development-live questions, all requiring two-reviewer expert gold, with
one generation pass planned for exactly 30 selected cases. It is evaluation-only,
not a promotion set, holdout or training dataset. Registration does not
authorize a model call. Verify the bundle without running retrieval or
generation with:

```bash
uv run python scripts/live_evaluation_suite.py verify
uv run python scripts/live_evaluation_suite.py summary
```

The API and admin UI dispatch Live30 and Live60 run views from each immutable
run-manifest schema. Only released, gate-passed answers may be decrypted through
the owner view; questions and held/private drafts remain encrypted.

## Verification

```bash
uv run python scripts/check_clean_room.py
uv run pytest
uv run ruff check backend scripts
cd web && npm run lint && npm test -- --run && npm run build
```

See [architecture](docs/architecture.md), [source policy](docs/source-policy.md),
[promotion gates](docs/promotion-gates.md), [current state](docs/CURRENT_STATE.md)
and the [Live60 evaluation contract](docs/LIVE60_EVALUATION.md).

# legalbot-recovery
