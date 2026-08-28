"""Concrete immutable LanceDB build and hybrid retrieval integration.

Production builds require LanceDB plus the configured Qwen embedding and
reranker providers.  The deterministic provider is deliberately reachable
only when ``LEGALBOT_TEST_MODE`` is active; dependency or model failures never
fall back to a different retrieval stack.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import math
import os
import re
import stat
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import suppress
from dataclasses import asdict, dataclass, replace
from datetime import date
from pathlib import Path
from typing import Any

from ..config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from ..currentness import is_legislation_source
from ..db import Database, utc_iso
from ..ingestion.models import Jurisdiction, MaterialLane
from ..jurisdictions import compatible, normalise
from ..observability.live_tracing import TraceOperation, TraceStage
from ..observability.runtime import RuntimeObservability
from ..privacy import scrub_pii
from ..privacy_audit import build_candidate_privacy_report
from ..research.material_updates import MaterialUpdateGate
from ..types import CasePropositionReview, EvidenceSpan, IssueSpottingNote
from ..types import MaterialLane as CatalogLane
from .admission import ADMISSION_VERSION
from .benchmark import (
    RetrievalBenchmark,
    assert_passing_benchmark_report,
    load_retrieval_benchmark,
    score_retrieval_benchmark,
)
from .budget import (
    RetrievalBudgetExhausted,
    abort_in_flight_retrieval,
    estimate_rerank_seconds,
    raise_if_complete_rerank_plan_exceeds_remaining,
    raise_if_rerank_work_exceeds_remaining,
    raise_if_retrieval_budget_exhausted,
    remaining_retrieval_seconds,
    wait_for_rerank_slot,
)
from .cache import SafeCachedHit, SafeRetrievalCache
from .cache_keys import retrieval_cache_key
from .diagnostic_slice import allowed_index_statuses_for_pin, is_diagnostic_slice_build
from .explicit_reference import (
    EXPLICIT_REFERENCE_VERSION,
    CandidateLegislationReferenceResolver,
    ExplicitLegislationReference,
    canonical_legislation_locator,
    legislation_locator_within,
)
from .filters import chunk_matches
from .hybrid import (
    DeterministicHashEmbedding,
    HybridRetriever,
    PreparedSearch,
    explicit_authority_identity,
)
from .interfaces import Reranker
from .lancedb import ImmutableLanceRepository
from .models import (
    VECTOR_DIMENSIONS,
    IndexedChunk,
    QueryFilters,
    RetrievalPlanItem,
    SearchCandidate,
    SearchHit,
    SearchQuery,
    ensure_vector,
)
from .ranking_text import (
    RANKING_PAYLOAD_MAX_TOKENS,
    RANKING_REPRESENTATION_VERSION,
    ranking_document_text,
)
from .relevance_policy import (
    SEMANTIC_ROUTE,
    RelevanceThresholdPolicy,
    load_relevance_threshold_policy,
    qualify_retrieval_score,
)
from .source_manifest import authority_identity_id
from .telemetry import record_retrieval_workload

TEST_EMBEDDING_MODEL = "legalbot-test/hash-embedding-1024"
TEST_RERANKER_MODEL = "legalbot-test/overlap-reranker-v1"
PINNED_EMBEDDING_REPO = "Qwen/Qwen3-Embedding-0.6B"
PINNED_EMBEDDING_REVISION = "97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3"
PINNED_EMBEDDING_FILE_MANIFEST_SHA256 = (
    "1d7b1bddebe83694815066f5254c5b0c7a1d05febd4e2b9e2120f2ec3fe3c018"
)
PINNED_EMBEDDING_DTYPE = "float16"
PINNED_RERANKER_REPO = "Qwen/Qwen3-Reranker-0.6B"
PINNED_RERANKER_REVISION = "e61197ed45024b0ed8a2d74b80b4d909f1255473"
PINNED_RERANKER_FILE_MANIFEST_SHA256 = (
    "f775cce47e7cbed490693a954aadcf6141cdf5ffa31b3e33f229adc374223e29"
)
# Full-precision batch 16 drove the pinned 0.6B embedder to roughly 13.6 GB on
# the 16-GB release machine and caused sustained swap pressure.  FP16 batch 8
# is the release-one profile; dtype and batch are part of the immutable model
# identity, and measured memory/throughput remain candidate evidence.
INDEX_EMBED_BATCH_SIZE = 8
LANCE_WRITE_BATCH_SIZE = 128
RERANK_BATCH_SIZE = 4
RERANK_MAX_LENGTH = 8192
RERANK_PAD_MULTIPLE = 128
LIVE_SEARCH_DEPTH_FLOOR = 50
LIVE_RERANK_CANDIDATE_LIMIT = 32
RERANK_HARD_MAX_HITS = 120
RERANK_INFERENCE_SLOTS = 1
_RERANK_INFERENCE = threading.Semaphore(RERANK_INFERENCE_SLOTS)
RERANK_INSTRUCTION = (
    "Given a legal research query, retrieve authoritative passages that directly support the "
    "requested legal proposition"
)
RERANK_PREFIX = (
    "<|im_start|>system\nJudge whether the Document meets the requirements based on the Query "
    'and the Instruct provided. Note that the answer can only be "yes" or "no".<|im_end|>\n'
    "<|im_start|>user\n"
)
RERANK_SUFFIX = "<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"
_LEGAL_CATALOG_LANES = {
    CatalogLane.PRIMARY_AUTHORITY.value,
    CatalogLane.OFFICIAL_SECONDARY.value,
    CatalogLane.SCHOLARSHIP.value,
}
PHYSICAL_AUTHORITY_LANE = "authority"
PHYSICAL_TEACHING_LANE = "teaching"
PHYSICAL_ASSESSMENT_LANE = "assessment"
PHYSICAL_LANES = (
    PHYSICAL_AUTHORITY_LANE,
    PHYSICAL_TEACHING_LANE,
    PHYSICAL_ASSESSMENT_LANE,
)
OPTIONAL_PHYSICAL_LANES = frozenset({PHYSICAL_TEACHING_LANE, PHYSICAL_ASSESSMENT_LANE})


def _physical_lane_row_count(settings: Settings, build_id: str, physical_lane: str) -> int:
    """Read a sealed lane count without treating an empty optional lane as corruption."""

    if physical_lane not in PHYSICAL_LANES:
        raise ValueError("unknown physical retrieval lane")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", build_id):
        raise RuntimeError("ACTIVE build id is unsafe")
    path = settings.index_dir / "builds" / build_id / "lance" / "physical-lanes.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("ACTIVE build physical lane manifest is unavailable") from exc
    tables = payload.get("tables") if isinstance(payload, dict) else None
    record = tables.get(physical_lane) if isinstance(tables, dict) else None
    row_count = record.get("row_count") if isinstance(record, dict) else None
    if (
        payload.get("schema") != "legalbot.physical-lanes.v1"
        or payload.get("separated") is not True
        or isinstance(row_count, bool)
        or not isinstance(row_count, int)
        or row_count < 0
    ):
        raise RuntimeError("ACTIVE build physical lane manifest is invalid")
    return row_count


@dataclass(frozen=True, slots=True)
class _ApprovedChunkSummary:
    chunk_count: int
    document_count: int
    source_manifest_sha256: str
    jurisdictions: dict[str, int]
    lanes: dict[str, int]
    subjects: dict[str, int]
    benchmark_chunk_lanes: dict[str, str]


@dataclass(frozen=True, slots=True)
class _ApprovedSourceSnapshot:
    chunk_count: int
    document_count: int
    source_manifest_sha256: str


@dataclass(frozen=True, slots=True)
class _CompletedScanSnapshot:
    scan_id: str
    manifest_sha256: str
    expected_file_count: int
    files_accounted: int


@dataclass(slots=True)
class _StreamObservation:
    count: int = 0
    source_manifest_sha256: str = ""


class QwenEmbeddingProvider:
    """Lazy Sentence Transformers adapter for Qwen3-Embedding."""

    dimensions = VECTOR_DIMENSIONS

    def __init__(self, model_id: str, revision: str, local_path: Path) -> None:
        if model_id != PINNED_EMBEDDING_REPO or revision != PINNED_EMBEDDING_REVISION:
            raise RuntimeError(
                "production embedding model must match the pinned Qwen3-Embedding revision"
            )
        self.model_id = model_id
        self.revision = revision
        self.local_path = local_path
        self._model: Any | None = None
        self._lock = threading.RLock()

    def _load(self) -> Any:
        with self._lock:
            if self._model is not None:
                return self._model
            source = _verified_local_model(
                self.local_path,
                self.model_id,
                self.revision,
                expected_file_manifest_sha256=PINNED_EMBEDDING_FILE_MANIFEST_SHA256,
            )
            try:
                sentence_transformers = importlib.import_module("sentence_transformers")
            except ImportError as exc:
                raise RuntimeError("sentence-transformers is required for Qwen embeddings") from exc
            device = _torch_retrieval_device_name()
            load_kwargs: dict[str, Any] = {
                "truncate_dim": VECTOR_DIMENSIONS,
                "model_kwargs": {"dtype": PINNED_EMBEDDING_DTYPE},
            }
            if device:
                load_kwargs["device"] = device
            model = sentence_transformers.SentenceTransformer(
                str(source),
                local_files_only=True,
                **load_kwargs,
            )
            dimension = int(model.get_sentence_embedding_dimension() or 0)
            if dimension != VECTOR_DIMENSIONS:
                raise RuntimeError(
                    f"Qwen embedding provider returned {dimension} dimensions; {VECTOR_DIMENSIONS} required"
                )
            self._model = model
            return model

    def embed_query(self, text: str) -> tuple[float, ...]:
        instructed = (
            "Instruct: Retrieve authoritative legal passages that answer the research query.\n"
            f"Query: {text}"
        )
        return self._encode((instructed,))[0]

    def embed_documents(self, texts: Sequence[str]) -> tuple[tuple[float, ...], ...]:
        return self._encode(texts)

    def _encode(self, texts: Sequence[str]) -> tuple[tuple[float, ...], ...]:
        if not texts:
            return ()
        values = self._load().encode(
            list(texts),
            batch_size=INDEX_EMBED_BATCH_SIZE,
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        return tuple(
            ensure_vector(row.tolist() if hasattr(row, "tolist") else row) for row in values
        )


class QwenRerankerProvider:
    """Official Qwen3 causal-LM yes/no likelihood reranker.

    This intentionally avoids ``AutoModelForSequenceClassification`` and a
    generic CrossEncoder fallback: either can create an untrained ``score``
    head when the Sentence Transformers LogitScore module is unavailable.
    """

    def __init__(self, model_id: str, revision: str, local_path: Path) -> None:
        if model_id != PINNED_RERANKER_REPO or revision != PINNED_RERANKER_REVISION:
            raise RuntimeError("production reranker must match the pinned Qwen3-Reranker revision")
        self.model_id = model_id
        self.revision = revision
        self.local_path = local_path
        self._runtime: _CausalRerankerRuntime | None = None
        self._lock = threading.RLock()
        self.last_rerank_stats: dict[str, object] = {}

    def _load(self) -> _CausalRerankerRuntime:
        with self._lock:
            if self._runtime is not None:
                return self._runtime
            source = _verified_local_model(
                self.local_path,
                self.model_id,
                self.revision,
                expected_file_manifest_sha256=PINNED_RERANKER_FILE_MANIFEST_SHA256,
            )
            try:
                transformers = importlib.import_module("transformers")
                torch = importlib.import_module("torch")
            except ImportError as exc:
                raise RuntimeError(
                    "Transformers and PyTorch are required for Qwen reranking"
                ) from exc
            tokenizer = transformers.AutoTokenizer.from_pretrained(
                str(source),
                local_files_only=True,
                padding_side="left",
            )
            model = transformers.AutoModelForCausalLM.from_pretrained(
                str(source),
                local_files_only=True,
                dtype="auto",
            )
            model_class = type(model).__name__
            if (
                "ForCausalLM" not in model_class
                or "SequenceClassification" in model_class
                or getattr(model, "score", None) is not None
            ):
                raise RuntimeError(
                    f"Qwen reranker loaded unsafe model class {model_class}; causal LM required"
                )
            output_embeddings = getattr(model, "get_output_embeddings", lambda: None)()
            if output_embeddings is None:
                raise RuntimeError("Qwen reranker causal LM has no vocabulary output head")
            tokenizer.padding_side = "left"
            if tokenizer.pad_token_id is None:
                if tokenizer.eos_token_id is None:
                    raise RuntimeError("Qwen reranker tokenizer has neither pad nor EOS token")
                tokenizer.pad_token = tokenizer.eos_token
            false_token_id = tokenizer.convert_tokens_to_ids("no")
            true_token_id = tokenizer.convert_tokens_to_ids("yes")
            invalid_ids = {None, getattr(tokenizer, "unk_token_id", None)}
            if (
                false_token_id in invalid_ids
                or true_token_id in invalid_ids
                or false_token_id == true_token_id
            ):
                raise RuntimeError("Qwen reranker yes/no token ids are invalid")
            prefix_tokens = tuple(tokenizer.encode(RERANK_PREFIX, add_special_tokens=False))
            suffix_tokens = tuple(tokenizer.encode(RERANK_SUFFIX, add_special_tokens=False))
            if (
                not prefix_tokens
                or not suffix_tokens
                or len(prefix_tokens) + len(suffix_tokens) >= RERANK_MAX_LENGTH
            ):
                raise RuntimeError("Qwen reranker prompt framing is invalid")
            device = _preferred_torch_device(torch)
            model = model.to(device).eval()
            self._runtime = _CausalRerankerRuntime(
                tokenizer=tokenizer,
                model=model,
                torch=torch,
                false_token_id=int(false_token_id),
                true_token_id=int(true_token_id),
                prefix_tokens=prefix_tokens,
                suffix_tokens=suffix_tokens,
                device=device,
            )
            return self._runtime

    def rerank(self, query: str, hits: Sequence[SearchHit], *, limit: int) -> Sequence[SearchHit]:
        if not hits or limit < 1:
            return ()
        if len(hits) > RERANK_HARD_MAX_HITS:
            raise RuntimeError("expensive rerank input exceeded the hard candidate bound")
        estimated = estimate_rerank_seconds(
            hit_count=len(hits), ranking_payload_tokens=RANKING_PAYLOAD_MAX_TOKENS
        )
        remaining = remaining_retrieval_seconds()
        record_retrieval_workload(
            stage="qwen_rerank_plan",
            data={
                "hit_count": len(hits),
                "batch_count": math.ceil(len(hits) / RERANK_BATCH_SIZE),
                "ranking_payload_max_tokens": RANKING_PAYLOAD_MAX_TOKENS,
                "estimated_rerank_seconds": round(estimated, 3),
                "remaining_retrieval_seconds": None if remaining is None else round(remaining, 3),
            },
        )
        raise_if_retrieval_budget_exhausted()
        wait_for_rerank_slot(_RERANK_INFERENCE)
        runtime: _CausalRerankerRuntime | None = None
        scores: list[float] = []
        batch_ms: list[float] = []
        try:
            raise_if_retrieval_budget_exhausted()
            raise_if_rerank_work_exceeds_remaining(
                hit_count=len(hits),
                ranking_payload_tokens=RANKING_PAYLOAD_MAX_TOKENS,
            )
            runtime = self._load()
            for start in range(0, len(hits), RERANK_BATCH_SIZE):
                raise_if_retrieval_budget_exhausted()
                batch = hits[start : start + RERANK_BATCH_SIZE]
                started = time.perf_counter()
                scores.extend(self._score_batch(runtime, query, batch))
                duration_ms = round((time.perf_counter() - started) * 1000, 3)
                batch_ms.append(duration_ms)
                record_retrieval_workload(
                    stage="qwen_rerank_batch",
                    data={
                        "batch_index": start // RERANK_BATCH_SIZE,
                        "batch_size": len(batch),
                        "batch_ms": duration_ms,
                        "device": str(runtime.device),
                    },
                )
            if runtime is not None and str(runtime.device).startswith("mps"):
                runtime.torch.mps.empty_cache()
        finally:
            _RERANK_INFERENCE.release()
        if len(scores) != len(hits) or any(not math.isfinite(score) for score in scores):
            raise RuntimeError("Qwen reranker returned incomplete or invalid scores")
        rescored = [
            replace(hit, rerank_score=score) for hit, score in zip(hits, scores, strict=True)
        ]
        rescored.sort(
            key=lambda item: (-(item.rerank_score or 0.0), -item.score, item.chunk.chunk_id)
        )
        self.last_rerank_stats = {
            "hit_count": len(hits),
            "batch_count": math.ceil(len(hits) / RERANK_BATCH_SIZE),
            "ranking_payload_max_tokens": RANKING_PAYLOAD_MAX_TOKENS,
            "device": str(runtime.device) if runtime is not None else "unloaded",
            "batch_ms": batch_ms,
            "rerank_ms": round(sum(batch_ms), 3),
        }
        record_retrieval_workload(stage="qwen_rerank", data=self.last_rerank_stats)
        return tuple(rescored[:limit])

    @staticmethod
    def _score_batch(
        runtime: _CausalRerankerRuntime,
        query: str,
        hits: Sequence[SearchHit],
    ) -> list[float]:
        originals = [(hit.chunk.text, hit.chunk.content_sha256) for hit in hits]
        prompts = [
            (
                f"<Instruct>: {RERANK_INSTRUCTION}\n"
                f"<Query>: {_safe_rerank_text(query)}\n"
                f"<Document>: {_safe_rerank_text(ranking_document_text(hit.chunk, query))}"
            )
            for hit in hits
        ]
        if originals != [(hit.chunk.text, hit.chunk.content_sha256) for hit in hits]:
            raise RuntimeError("ranking representation mutated authoritative evidence")
        available_length = min(
            RANKING_PAYLOAD_MAX_TOKENS,
            RERANK_MAX_LENGTH - len(runtime.prefix_tokens) - len(runtime.suffix_tokens),
        )
        inputs = runtime.tokenizer(
            prompts,
            padding=False,
            truncation="longest_first",
            return_attention_mask=False,
            max_length=available_length,
        )
        input_ids = inputs.get("input_ids")
        if not isinstance(input_ids, list) or len(input_ids) != len(prompts):
            raise RuntimeError("Qwen reranker tokenizer returned invalid input ids")
        inputs["input_ids"] = [
            [*runtime.prefix_tokens, *token_ids, *runtime.suffix_tokens] for token_ids in input_ids
        ]
        padded = runtime.tokenizer.pad(
            inputs,
            padding=True,
            pad_to_multiple_of=RERANK_PAD_MULTIPLE,
            return_tensors="pt",
        )
        model_inputs = {key: value.to(runtime.device) for key, value in padded.items()}
        with _rerank_inference_mode(runtime.torch):
            final_logits = _forward_last_token_logits(
                torch=runtime.torch, model=runtime.model, model_inputs=model_inputs
            )
            false_logits = final_logits[:, runtime.false_token_id]
            true_logits = final_logits[:, runtime.true_token_id]
            yes_no_logits = runtime.torch.stack([false_logits, true_logits], dim=1)
            probabilities = runtime.torch.nn.functional.log_softmax(yes_no_logits, dim=1)[
                :, 1
            ].exp()
        return [float(value) for value in probabilities.detach().float().cpu().tolist()]


def _rerank_inference_mode(torch: Any) -> Any:
    inference = getattr(torch, "inference_mode", None)
    if callable(inference):
        return inference()
    return torch.no_grad()


def _forward_last_token_logits(
    *,
    torch: Any,
    model: Any,
    model_inputs: Mapping[str, Any],
) -> Any:
    """Exact last-token yes/no scoring. Never falls back to full-sequence logits."""

    del torch
    try:
        output = model(
            **model_inputs,
            use_cache=False,
            logits_to_keep=1,
        )
    except TypeError as exc:
        raise RuntimeError(
            "pinned Qwen3 reranker does not support exact last-token logits_to_keep=1"
        ) from exc
    logits = getattr(output, "logits", None)
    if logits is None:
        raise RuntimeError("pinned Qwen3 reranker returned no logits")
    return logits[:, -1, :]


@dataclass(frozen=True, slots=True)
class _CausalRerankerRuntime:
    tokenizer: Any
    model: Any
    torch: Any
    false_token_id: int
    true_token_id: int
    prefix_tokens: tuple[int, ...]
    suffix_tokens: tuple[int, ...]
    device: Any


class _TestOverlapReranker:
    def rerank(self, query: str, hits: Sequence[SearchHit], *, limit: int) -> Sequence[SearchHit]:
        query_terms = set(_tokens(query))
        output: list[SearchHit] = []
        for hit in hits:
            terms = set(_tokens(hit.chunk.text))
            overlap = len(query_terms & terms) / max(1, len(query_terms))
            output.append(replace(hit, rerank_score=overlap + hit.score))
        output.sort(
            key=lambda item: (-(item.rerank_score or 0.0), -item.score, item.chunk.chunk_id)
        )
        return tuple(output[:limit])


def build_candidate_index(settings: Settings, database: Database, build_id: str) -> dict[str, Any]:
    """Legacy fixture builder; production uses the durable staged build path."""

    if not settings.test_mode:
        raise RuntimeError(
            "legacy chunk-ID candidate builder is disabled; use durable build-index, "
            "then score the owner-frozen v1.1 benchmark"
        )

    _validate_build_id(build_id)
    if database.fetchone(
        "SELECT 1 FROM source_scans WHERE status IN ('queued', 'running') LIMIT 1"
    ):
        raise RuntimeError(
            "candidate index build refused while a source scan is queued or running; "
            "wait for the scan to finish"
        )
    settings.ensure_runtime_dirs()
    expected_path = settings.index_dir / "builds" / build_id
    relative_path = _relative_path(settings, expected_path)
    embedding_model = (
        TEST_EMBEDDING_MODEL if settings.test_mode else _production_embedding_identity(settings)
    )
    reranker_model = (
        TEST_RERANKER_MODEL if settings.test_mode else _production_reranker_identity(settings)
    )
    now = utc_iso()
    try:
        database.execute(
            """
            INSERT INTO index_builds(
              id, status, path, embedding_model, reranker_model, created_at
            ) VALUES (?, 'building', ?, ?, ?, ?)
            """,
            (build_id, relative_path, embedding_model, reranker_model, now),
        )
    except Exception as exc:
        raise ValueError(f"index build id already exists or is invalid: {build_id}") from exc

    evaluation: dict[str, Any] | None = None
    try:
        source_scan = _completed_scan_snapshot(database)
        _synchronise_source_reviews(database)
        if _approved_chunk_count(database) == 0:
            raise ValueError("candidate build has no human-approved chunks")
        benchmark = load_retrieval_benchmark(settings.retrieval_benchmark_path)
        summary = _summarise_approved_chunks(database, benchmark)
        lancedb_module = _import_lancedb()
        embedder = _embedding_provider(settings, embedding_model)
        observation = _StreamObservation()
        chunks = _stream_indexed_chunks(database, embedder, observation)
        repository = ImmutableLanceRepository(settings.index_dir)
        session_factory = _RealLanceSessionFactory(lancedb_module)
        manifest = repository.build(
            build_id=build_id,
            chunks=chunks,
            embedding_model=embedding_model,
            reranker_model=reranker_model,
            source_manifest_sha256=summary.source_manifest_sha256,
            session_factory=session_factory,
            source_scan_id=source_scan.scan_id,
            source_scan_manifest_sha256=source_scan.manifest_sha256,
        )
        build_path = repository.builds / build_id
        lance_tree_sha256 = _tree_sha256(build_path / "lance")
        lane_manifest_path = build_path / "lance" / "physical-lanes.json"
        lane_manifest = _json_object(lane_manifest_path.read_text(encoding="utf-8"))
        raw_lane_tables = lane_manifest.get("tables")
        if not isinstance(raw_lane_tables, dict):
            raise RuntimeError("physical lane manifest is incomplete")
        lane_counts: dict[str, int] = {}
        for lane in PHYSICAL_LANES:
            lane_record = raw_lane_tables.get(lane)
            if not isinstance(lane_record, dict):
                raise RuntimeError("physical lane manifest is incomplete")
            lane_counts[lane] = int(lane_record.get("row_count", -1))
        physical_lane_isolation = (
            lane_manifest.get("schema") == "legalbot.physical-lanes.v1"
            and lane_manifest.get("separated") is True
            and all((build_path / "lance" / lane).is_dir() for lane in PHYSICAL_LANES)
            and all(count >= 0 for count in lane_counts.values())
            and sum(lane_counts.values()) == manifest.chunk_count
        )
        benchmark_path = build_path / "retrieval-benchmark.json"
        _write_new_bytes(benchmark_path, benchmark.canonical_bytes)
        benchmark_report = _run_candidate_benchmark(
            lancedb_module=lancedb_module,
            build_path=build_path,
            benchmark=benchmark,
            embedder=embedder,
            reranker=_reranker_provider(settings, reranker_model),
            indexed_chunk_lanes=summary.benchmark_chunk_lanes,
        )
        benchmark_report_path = build_path / "retrieval-benchmark-report.json"
        _write_new_json(benchmark_report_path, benchmark_report)
        privacy_report = build_candidate_privacy_report(settings, database)
        privacy_report_path = build_path / "privacy-report.json"
        _write_new_json(privacy_report_path, privacy_report)
        integrity_passed = (
            manifest.chunk_count == summary.chunk_count
            and observation.count == summary.chunk_count
            and observation.source_manifest_sha256 == summary.source_manifest_sha256
            and manifest.vector_dimensions == VECTOR_DIMENSIONS
            and lance_tree_sha256 == _tree_sha256(build_path / "lance")
            and physical_lane_isolation
            and privacy_report["passed"] is True
        )
        evaluation = {
            "schema": "legalbot.index-evaluation.v2",
            "passed": integrity_passed and benchmark_report["passed"] is True,
            "integrity": {
                "approved_only": True,
                "chunk_count": observation.count,
                "vector_count": manifest.chunk_count,
                "vector_dimensions": VECTOR_DIMENSIONS,
                "source_snapshot_stable": (
                    observation.source_manifest_sha256 == summary.source_manifest_sha256
                ),
                "source_manifest_sha256": summary.source_manifest_sha256,
                "lance_tree_sha256": lance_tree_sha256,
                "physical_lane_isolation": physical_lane_isolation,
                "physical_lane_counts": lane_counts,
                "physical_lane_manifest_sha256": _file_sha256(lane_manifest_path),
                "source_scan_id": source_scan.scan_id,
                "source_scan_manifest_sha256": source_scan.manifest_sha256,
                "scan_reconciled": (source_scan.expected_file_count == source_scan.files_accounted),
            },
            "coverage": {
                "documents": summary.document_count,
                "jurisdictions": summary.jurisdictions,
                "lanes": summary.lanes,
                "subjects": summary.subjects,
            },
            "retrieval_benchmark": benchmark_report,
            "privacy": privacy_report,
            "created_at": utc_iso(),
        }
        evaluation_path = build_path / "evaluation.json"
        _write_new_json(evaluation_path, evaluation)
        if not integrity_passed:
            raise RuntimeError("candidate index integrity evaluation failed")
        assert_passing_benchmark_report(benchmark_report)
        manifest_path = build_path / "manifest.json"
        seal = {
            "schema": "legalbot.index-seal.v2",
            "build_id": build_id,
            "manifest_sha256": _file_sha256(manifest_path),
            "evaluation_sha256": _file_sha256(evaluation_path),
            "retrieval_benchmark_sha256": _file_sha256(benchmark_path),
            "retrieval_benchmark_report_sha256": _file_sha256(benchmark_report_path),
            "privacy_report_sha256": _file_sha256(privacy_report_path),
            "lance_tree_sha256": lance_tree_sha256,
            "physical_lane_manifest_sha256": _file_sha256(lane_manifest_path),
            "source_scan_manifest_sha256": source_scan.manifest_sha256,
            "sealed_at": utc_iso(),
        }
        seal_path = build_path / "seal.json"
        _write_new_json(seal_path, seal)
        seal_sha256 = _file_sha256(seal_path)
        metrics: dict[str, Any] = {
            "evaluation": evaluation,
            "base_manifest": asdict(manifest),
            "seal_sha256": seal_sha256,
        }
        database.execute(
            """
            UPDATE index_builds
            SET status='candidate', document_count=?, chunk_count=?, vector_count=?,
                manifest_sha256=?, metrics_json=?
            WHERE id=? AND status='building'
            """,
            (
                evaluation["coverage"]["documents"],
                observation.count,
                manifest.chunk_count,
                seal_sha256,
                json.dumps(metrics, ensure_ascii=False, sort_keys=True),
                build_id,
            ),
        )
        return {
            "build_id": build_id,
            "status": "candidate",
            "document_count": evaluation["coverage"]["documents"],
            "chunk_count": observation.count,
            "manifest_sha256": seal_sha256,
            "benchmark_id": benchmark.benchmark_id,
            "benchmark_version": benchmark.version,
            "retrieval_metrics": benchmark_report["metrics"],
        }
    except Exception as exc:
        failure_metrics: dict[str, Any] = {
            "failure_type": type(exc).__name__,
            "failure": _safe_failure(exc),
            "failed_at": utc_iso(),
        }
        if evaluation is not None:
            failure_metrics["evaluation"] = evaluation
        database.execute(
            """
            UPDATE index_builds SET status='failed', metrics_json=?
            WHERE id=? AND status='building'
            """,
            (
                json.dumps(failure_metrics, ensure_ascii=False, sort_keys=True),
                build_id,
            ),
        )
        raise


def promote_candidate_index(
    settings: Settings,
    database: Database,
    build_id: str,
    *,
    event_store: Any | None = None,
    live60_attestation: Any | None = None,
    live60_attestation_path: Path | None = None,
    v111_promotion_presentation: Any | None = None,
    v111_owner_authorization: Any | None = None,
) -> dict[str, str]:
    """Atomically switch ACTIVE only through the verified v1.11 transition."""

    from ..observability.events import EventStore, LogWriteError, record_index_stage_failure

    if live60_attestation is not None or live60_attestation_path is not None:
        raise ValueError("v1.11 production-promotion cannot use the legacy Live60 attestation")
    from ..evaluation.owner_quality_v111_promotion import (
        verify_v111_promotion_for_service,
    )

    if v111_promotion_presentation is None or v111_owner_authorization is None:
        raise ValueError(
            "v1.11 production-promotion requires the exact dev30 presentation "
            "and trusted owner authorization"
        )
    verify_v111_promotion_for_service(
        settings=settings,
        database=database,
        build_id=build_id,
        presentation=v111_promotion_presentation,
        owner_authorization=v111_owner_authorization,
    )

    store = event_store or EventStore.from_settings(settings, database)
    try:
        store.require_writable(component="index_promotion", stage="PROMOTION")
    except LogWriteError:
        raise
    except Exception as exc:
        raise LogWriteError("promotion aborted because observability logging failed") from exc
    _validate_build_id(build_id)
    from .diagnostic_slice import refuse_diagnostic_slice_for_production

    refuse_diagnostic_slice_for_production(build_id, purpose="production promotion")
    row = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
    if row is None:
        raise ValueError("candidate index build does not exist")
    if row["status"] == "active":
        with suppress(OSError):
            SafeRetrievalCache(settings.retrieval_cache_dir).invalidate_for_pointer_change(
                active_build_id=build_id
            )
        return {"build_id": build_id, "status": "active"}
    if row["status"] != "candidate":
        raise ValueError("only a passing candidate index may be promoted")
    expected_embedding = (
        TEST_EMBEDDING_MODEL if settings.test_mode else _production_embedding_identity(settings)
    )
    expected_reranker = (
        TEST_RERANKER_MODEL if settings.test_mode else _production_reranker_identity(settings)
    )
    repository = ImmutableLanceRepository(settings.index_dir)
    try:
        result = _promote_candidate_index_locked(
            settings, database, build_id, repository, expected_embedding, expected_reranker
        )
        with suppress(OSError):
            SafeRetrievalCache(settings.retrieval_cache_dir).invalidate_for_pointer_change(
                active_build_id=build_id
            )
        return result
    except LogWriteError:
        raise
    except Exception:
        record_index_stage_failure(
            store,
            stage="PROMOTION",
            reason_code="promotion_atomicity_failure",
            message=(
                "Promotion did not complete; verify ACTIVE/PREVIOUS pointers against the "
                "catalogue before retrying."
            ),
            build_id=build_id,
            retryable=False,
            blocking=True,
        )
        raise


def _promote_candidate_index_locked(
    settings: Settings,
    database: Database,
    build_id: str,
    repository: ImmutableLanceRepository,
    expected_embedding: str,
    expected_reranker: str,
) -> dict[str, str]:
    with database.transaction() as connection:
        locked_row = connection.execute(
            "SELECT * FROM index_builds WHERE id=?", (build_id,)
        ).fetchone()
        if locked_row is None or locked_row["status"] != "candidate":
            raise ValueError("candidate changed state before promotion; promotion refused")
        if connection.execute(
            "SELECT 1 FROM source_scans WHERE status IN ('queued', 'running') LIMIT 1"
        ).fetchone():
            raise RuntimeError(
                "candidate promotion refused while a source scan is queued or running; "
                "wait for the scan to finish"
            )
        if connection.execute(
            "SELECT 1 FROM jobs WHERE status IN ('queued', 'running') LIMIT 1"
        ).fetchone():
            raise RuntimeError(
                "candidate promotion refused while answer jobs are queued or running; "
                "their frozen evidence packs must remain bound to one index identity"
            )
        if (
            locked_row["embedding_model"] != expected_embedding
            or locked_row["reranker_model"] != expected_reranker
        ):
            raise ValueError(
                "candidate retrieval models do not match the pinned runtime identities"
            )
        expected_source_manifest = _verify_sealed_build(settings, database, dict(locked_row))
        current_scan = _completed_scan_snapshot(database)
        sealed_manifest = _json_object(
            (settings.index_dir / "builds" / build_id / "manifest.json").read_text(encoding="utf-8")
        )
        if (
            sealed_manifest.get("source_scan_id") != current_scan.scan_id
            or sealed_manifest.get("source_scan_manifest_sha256") != current_scan.manifest_sha256
        ):
            raise RuntimeError("candidate source scan manifest is stale; rebuild before promotion")
        if (settings.index_dir / "builds" / build_id / "approved-source-manifest.json").is_file():
            from .source_manifest import build_approved_source_manifest

            current_scoped = build_approved_source_manifest(
                database,
                settings,
                corpus_id=str(locked_row["corpus_id"] or locked_row["scoped_corpus_id"] or ""),
            )
            if (
                current_scoped.get("manifest_sha256") != expected_source_manifest
                or int(current_scoped.get("chunk_count") or 0) != int(locked_row["chunk_count"])
                or int(current_scoped.get("source_count") or 0) != int(locked_row["document_count"])
            ):
                raise RuntimeError(
                    "candidate scoped source manifest is stale; rebuild and reevaluate before promotion"
                )
        else:
            current_source_snapshot = _approved_source_snapshot(database)
            if (
                current_source_snapshot.source_manifest_sha256 != expected_source_manifest
                or current_source_snapshot.chunk_count != int(locked_row["chunk_count"])
                or current_source_snapshot.document_count != int(locked_row["document_count"])
            ):
                raise RuntimeError(
                    "candidate approved-source manifest is stale; rebuild and reevaluate before promotion"
                )
        # BEGIN IMMEDIATE holds the catalogue stable from the snapshot above
        # through the database update and pointer compare-and-swap.
        pointer = repository.read_active()
        database_active_row = connection.execute(
            "SELECT id FROM index_builds WHERE status='active' ORDER BY promoted_at DESC LIMIT 1"
        ).fetchone()
        database_active = (
            str(database_active_row["id"]) if database_active_row is not None else None
        )
        pointer_id = pointer.build_id if pointer else None
        if pointer_id != database_active:
            raise ValueError("ACTIVE pointer and catalogue disagree; promotion refused")
        connection.execute(
            """
            UPDATE normal_live_readiness_state SET active=0, updated_at=?
            WHERE scope='owner-only-normal-live'
            """,
            (utc_iso(),),
        )
        connection.execute(
            "UPDATE index_builds SET status='superseded' WHERE status='active' AND id<>?",
            (build_id,),
        )
        connection.execute(
            "UPDATE index_builds SET status='active', promoted_at=? WHERE id=? AND status='candidate'",
            (utc_iso(), build_id),
        )
        repository.promote(build_id, expected_previous=pointer_id)
    return {"build_id": build_id, "status": "active"}


def rollback_active_index(
    settings: Settings,
    database: Database,
    *,
    event_store: Any | None = None,
) -> dict[str, str]:
    """Restore ACTIVE from PREVIOUS. Aborts if observability logging cannot be written."""

    from ..observability.events import EventStore, LogWriteError, record_index_stage_failure

    store = event_store or EventStore.from_settings(settings, database)
    try:
        store.require_writable(component="index_rollback", stage="ROLLBACK")
    except LogWriteError:
        raise
    except Exception as exc:
        raise LogWriteError("rollback aborted because observability logging failed") from exc
    repository = ImmutableLanceRepository(settings.index_dir)
    try:
        with database.transaction() as connection:
            pointer = repository.read_active()
            previous = repository.read_previous()
            if pointer is None:
                raise FileNotFoundError("ACTIVE pointer is missing; rollback refused")
            if previous is None:
                raise FileNotFoundError("PREVIOUS pointer is missing; rollback refused")
            active_row = connection.execute(
                "SELECT id,status FROM index_builds WHERE id=?", (pointer.build_id,)
            ).fetchone()
            previous_row = connection.execute(
                "SELECT id,status FROM index_builds WHERE id=?", (previous.build_id,)
            ).fetchone()
            if active_row is None or active_row["status"] != "active":
                raise ValueError("ACTIVE pointer and catalogue disagree; rollback refused")
            if previous_row is None or previous_row["status"] not in {
                "superseded",
                "candidate",
            }:
                raise ValueError("PREVIOUS pointer is not a rollback-eligible build")
            if connection.execute(
                "SELECT 1 FROM jobs WHERE status IN ('queued','running') LIMIT 1"
            ).fetchone():
                raise RuntimeError(
                    "rollback refused while jobs are queued or running; frozen evidence "
                    "must remain bound to one index identity"
                )
            connection.execute(
                """
                UPDATE normal_live_readiness_state SET active=0, updated_at=?
                WHERE scope='owner-only-normal-live'
                """,
                (utc_iso(),),
            )
            connection.execute(
                "UPDATE index_builds SET status='superseded' WHERE id=?",
                (pointer.build_id,),
            )
            connection.execute(
                "UPDATE index_builds SET status='active', promoted_at=? WHERE id=?",
                (utc_iso(), previous.build_id),
            )
            restored = repository.rollback_build()
            if restored.build_id != previous.build_id:
                raise RuntimeError("rollback pointer did not restore the expected build")
    except Exception:
        record_index_stage_failure(
            store,
            stage="ROLLBACK",
            reason_code="rollback_atomicity_failure",
            message=(
                "Rollback did not complete; verify ACTIVE/PREVIOUS pointers against the "
                "catalogue before retrying."
            ),
            retryable=False,
            blocking=True,
        )
        raise
    with suppress(OSError):
        SafeRetrievalCache(settings.retrieval_cache_dir).invalidate_for_pointer_change(
            active_build_id=restored.build_id
        )
    return {"build_id": restored.build_id, "status": "rolled_back"}


@dataclass(frozen=True, slots=True)
class _PreparedAuthorityRetrieval:
    item: RetrievalPlanItem
    build_id: str | None = None
    table: Any = None
    retriever: HybridRetriever | None = None
    prepared: PreparedSearch | None = None
    cache_key: str | None = None
    cached_hits: tuple[SearchHit, ...] | None = None
    empty: tuple[EvidenceSpan, ...] | None = None


@dataclass(frozen=True, slots=True)
class _VerifiedBuildCapability:
    """Process-local proof that one immutable build was fully content-verified.

    The content seal remains the authority.  ``tree_metadata_sha256`` is only a
    drift sentinel that lets later retrieval boundaries detect any ordinary
    filesystem mutation without rereading the complete Lance generation.
    """

    build_id: str
    source_manifest_sha256: str
    catalogue_binding_sha256: str
    tree_metadata_sha256: str
    durable_v1_1: bool
    attestation_sha256: str | None = None
    scorer_implementation_sha256: str | None = None
    scorer_closure_aggregate_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class _VerifiedRetrievalBoundary:
    capability: _VerifiedBuildCapability
    build_row: Mapping[str, Any]

    @property
    def build_id(self) -> str:
        return self.capability.build_id


class HybridRetrievalService:
    def __init__(
        self,
        settings: Settings,
        database: Database,
        *,
        pinned_build_id: str | None = None,
        observability: RuntimeObservability | None = None,
    ) -> None:
        self.settings = settings
        self.database = database
        if pinned_build_id is not None:
            _validate_build_id(pinned_build_id)
        self._pinned_build_id = pinned_build_id
        self.observability = observability
        self._pinned_verified = False
        self._verified_build: _VerifiedBuildCapability | None = None
        self._runtime_lock = threading.RLock()
        self._runtime_build_id: str | None = None
        self.last_retrieval_code: str | None = None
        self._tables: dict[str, Any] = {}
        self._embedder: Any | None = None
        self._reranker: Reranker | None = None
        self._reference_resolver: CandidateLegislationReferenceResolver | None = None
        self._retrieval_cache = SafeRetrievalCache(settings.retrieval_cache_dir)
        self._relevance_policy: RelevanceThresholdPolicy = (
            load_relevance_threshold_policy(
                settings.relevance_threshold_policy_path,
                test_mode=settings.test_mode,
            )
        )

    def active_build_id(self) -> str | None:
        row = self._selected_build_row()
        if row is None:
            return None
        if self._pinned_build_id is not None:
            self._ensure_verified_build(row)
        return str(row["id"])

    def _selected_build_row(self) -> dict[str, Any] | None:
        if self._pinned_build_id is not None:
            row = self.database.fetchone(
                "SELECT * FROM index_builds WHERE id=?", (self._pinned_build_id,)
            )
            allowed = allowed_index_statuses_for_pin(self._pinned_build_id)
            if row is None or str(row["status"]) not in allowed:
                raise RuntimeError("pinned evaluation build is not a sealed candidate or ACTIVE")
            return dict(row)
        repository = ImmutableLanceRepository(self.settings.index_dir)
        pointer = repository.read_active()
        database_id = self.database.active_index_id()
        pointer_id = pointer.build_id if pointer else None
        if pointer_id != database_id:
            raise RuntimeError("ACTIVE pointer and index catalogue are inconsistent")
        if pointer_id is None:
            return None
        row = self.database.fetchone("SELECT * FROM index_builds WHERE id=?", (pointer_id,))
        if row is None or str(row["status"]) != "active":
            raise RuntimeError("ACTIVE build is not available in the catalogue")
        return dict(row)

    def _ensure_verified_build(self, row: Mapping[str, Any]) -> _VerifiedBuildCapability:
        build_id = str(row["id"])
        build_path = self.settings.index_dir / "builds" / build_id
        catalogue_binding = _runtime_catalogue_binding_sha256(row)
        with self._runtime_lock:
            existing = self._verified_build
            if existing is not None and existing.build_id == build_id:
                if existing.catalogue_binding_sha256 != catalogue_binding:
                    raise RuntimeError("verified candidate catalogue binding changed")
                if _tree_metadata_sha256(build_path) != existing.tree_metadata_sha256:
                    raise RuntimeError(
                        "verified candidate build changed after content verification"
                    )
                if existing.durable_v1_1:
                    # The selected proof and executable scorer closure remain
                    # independently replayed at each retrieval boundary.  The
                    # expensive candidate tree itself was already verified.
                    from .retrieval_reattest import verify_selected_retrieval_attestation

                    proof = verify_selected_retrieval_attestation(
                        self.settings,
                        self.database,
                        row,
                        tree_already_verified=True,
                    )
                    refreshed = replace(
                        existing,
                        attestation_sha256=proof.sha256,
                        scorer_implementation_sha256=proof.scorer_implementation_sha256,
                        scorer_closure_aggregate_sha256=(proof.scorer_closure_aggregate_sha256),
                    )
                    if refreshed != existing:
                        self._verified_build = refreshed
                        existing = refreshed
                return existing

            before = _tree_metadata_sha256(build_path)
            source_manifest_sha256 = _verify_pinned_build(self.settings, self.database, row)
            after = _tree_metadata_sha256(build_path)
            if before != after:
                raise RuntimeError("candidate build changed during content verification")
            durable_v1_1 = (build_path / "approved-source-manifest.json").is_file()
            from .retrieval_reattest import (
                AttestationReference,
                verify_selected_retrieval_attestation,
            )

            initial_proof: AttestationReference | None = None
            if durable_v1_1:
                initial_proof = verify_selected_retrieval_attestation(
                    self.settings,
                    self.database,
                    row,
                    tree_already_verified=True,
                )
            capability = _VerifiedBuildCapability(
                build_id=build_id,
                source_manifest_sha256=source_manifest_sha256,
                catalogue_binding_sha256=catalogue_binding,
                tree_metadata_sha256=after,
                durable_v1_1=durable_v1_1,
                attestation_sha256=(initial_proof.sha256 if initial_proof is not None else None),
                scorer_implementation_sha256=(
                    initial_proof.scorer_implementation_sha256
                    if initial_proof is not None
                    else None
                ),
                scorer_closure_aggregate_sha256=(
                    initial_proof.scorer_closure_aggregate_sha256
                    if initial_proof is not None
                    else None
                ),
            )
            self._verified_build = capability
            self._pinned_verified = self._pinned_build_id is not None
            return capability

    def _open_retrieval_boundary(self) -> _VerifiedRetrievalBoundary | None:
        row = self._selected_build_row()
        if row is None:
            return None
        return _VerifiedRetrievalBoundary(
            capability=self._ensure_verified_build(row),
            build_row=row,
        )

    def _assert_retrieval_boundary_unchanged(self, boundary: _VerifiedRetrievalBoundary) -> None:
        row = self._selected_build_row()
        if row is None or str(row["id"]) != boundary.build_id:
            raise RuntimeError("retrieval build changed during request")
        if _runtime_catalogue_binding_sha256(row) != boundary.capability.catalogue_binding_sha256:
            raise RuntimeError("retrieval catalogue binding changed during request")
        build_path = self.settings.index_dir / "builds" / boundary.build_id
        if _tree_metadata_sha256(build_path) != boundary.capability.tree_metadata_sha256:
            raise RuntimeError("verified candidate build changed during retrieval")

    async def retrieve_issue_spotting_notes(
        self,
        *,
        query: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
        limit: int = 8,
    ) -> Sequence[IssueSpottingNote]:
        if not query.strip() or limit < 1:
            return []
        raise_if_retrieval_budget_exhausted()
        timeout = remaining_retrieval_seconds()
        work = asyncio.to_thread(
            self._retrieve_issue_spotting_sync,
            query,
            jurisdiction,
            subject,
            as_of_date,
            min(limit, 12),
        )
        if timeout is None:
            return await work
        try:
            return await asyncio.wait_for(work, timeout=max(0.05, timeout))
        except RetrievalBudgetExhausted:
            raise
        except TimeoutError:
            abort_in_flight_retrieval()
            raise RuntimeError("retrieval_deadline_exceeded") from None

    def _retrieve_issue_spotting_sync(
        self,
        query: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
        limit: int,
    ) -> Sequence[IssueSpottingNote]:
        boundary = self._open_retrieval_boundary()
        if boundary is None:
            return []
        build_id = boundary.build_id
        runtime = self._runtime(
            build_id,
            boundary.build_row,
            PHYSICAL_TEACHING_LANE,
            boundary=boundary,
        )
        if runtime is None:
            # A sealed zero-row teaching lane is a valid authority-only build,
            # not a corrupt retrieval runtime. Teaching notes are optional and
            # must never prevent the authority path from answering.
            self._assert_retrieval_boundary_unchanged(boundary)
            return ()
        table, embedder, reranker = runtime
        filters = QueryFilters(
            jurisdictions=frozenset(_query_jurisdictions(jurisdiction)),
            material_lanes=frozenset({MaterialLane.LECTURE_NOTE}),
            exact_jurisdictions=frozenset(_query_exact_jurisdictions(jurisdiction)),
            subjects=_query_subjects(subject),
            review_states=frozenset({"approved"}),
        )
        retriever = HybridRetriever(
            embedder=embedder,
            lexical_backend=_LanceLexicalBackend(table, as_of_date),
            vector_backend=_LanceVectorBackend(table, as_of_date),
            reranker=reranker,
        )
        hits = retriever.search(_bounded_search_query(query, filters, limit=limit, search_floor=30))
        self._record_rerank_timing(retriever)
        notes: list[IssueSpottingNote] = []
        for hit in hits:
            metadata = hit.chunk.metadata
            if str(metadata.get("catalog_lane")) != CatalogLane.PRIVATE_TEACHING.value:
                continue
            source_jurisdiction = str(metadata.get("catalog_jurisdiction") or "")
            if not compatible(jurisdiction, source_jurisdiction):
                continue
            notes.append(
                IssueSpottingNote(
                    id=_stable_id("issue-note", build_id, hit.chunk.chunk_id),
                    source_version_id=str(metadata["source_version_id"]),
                    chunk_id=hit.chunk.chunk_id,
                    text=hit.chunk.text,
                    jurisdiction=source_jurisdiction,
                    subject=hit.chunk.subject,
                    content_sha256=hit.chunk.content_sha256,
                    index_build_id=build_id,
                )
            )
        result = tuple(notes[:limit])
        self._assert_retrieval_boundary_unchanged(boundary)
        return result

    async def retrieve(
        self,
        *,
        query: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
        limit: int = 30,
        cacheable: bool = True,
    ) -> Sequence[EvidenceSpan]:
        batches = await self.retrieve_certified_plan(
            (
                RetrievalPlanItem(
                    query=query,
                    jurisdiction=jurisdiction,
                    subject=subject,
                    as_of_date=as_of_date,
                    limit=limit,
                    cacheable=cacheable,
                ),
            )
        )
        return batches[0] if batches else []

    async def retrieve_certified_plan(
        self, requests: Sequence[RetrievalPlanItem]
    ) -> tuple[tuple[EvidenceSpan, ...], ...]:
        """Prepare every research query, then rerank only if the whole plan fits."""

        items = tuple(requests)
        if not items:
            return ()
        raise_if_retrieval_budget_exhausted()
        timeout = remaining_retrieval_seconds()
        work = asyncio.to_thread(self._retrieve_certified_plan_sync, items)
        if timeout is None:
            return await work
        try:
            return await asyncio.wait_for(work, timeout=max(0.05, timeout))
        except RetrievalBudgetExhausted:
            raise
        except TimeoutError:
            abort_in_flight_retrieval()
            raise RuntimeError("retrieval_deadline_exceeded") from None

    def _emit_retrieval(
        self, code: str, *, job_id: str | None = None, build_id: str | None = None
    ) -> None:
        from ..observability.events import EventStore

        EventStore.from_settings(self.settings, self.database).emit(
            event_type="retrieval_degradation",
            component="retrieval",
            stage="retrieve",
            failure_code=code,
            source_id=build_id or self._runtime_build_id,
            job_id=job_id,
            build_id=build_id or self._runtime_build_id,
            user_or_owner_safe=f"Retrieval ended with {code}. This is not collapsed to no_evidence.",
            retryable=code
            in {"retriever_unavailable", "reranker_unavailable", "vector_degraded_lexical_only"},
            blocking=code
            in {
                "index_not_ready",
                "retriever_unavailable",
                "relevance_threshold_policy_not_frozen",
                "no_threshold_qualified_evidence",
            },
        )
        self.last_retrieval_code = code

    def _emit_update_alert(self, *, build_id: str) -> None:
        """Record an unreviewed crawler observation without blocking evidence."""

        from ..observability.events import EventStore, EventType

        EventStore.from_settings(self.settings, self.database).emit(
            event_type=EventType.WARNING.value,
            component="retrieval",
            stage="currentness",
            failure_code="official_update_review_pending",
            source_id=build_id,
            build_id=build_id,
            user_or_owner_safe=(
                "An official-source change observation is awaiting expert materiality review; "
                "raw byte changes alone do not alter legal qualification."
            ),
            retryable=False,
            blocking=False,
            open_ledger=False,
        )

    def _retrieve_certified_plan_sync(
        self, requests: Sequence[RetrievalPlanItem]
    ) -> tuple[tuple[EvidenceSpan, ...], ...]:
        raise_if_retrieval_budget_exhausted()
        boundary: _VerifiedRetrievalBoundary | None = None
        if any(item.query.strip() and item.limit >= 1 for item in requests):
            try:
                boundary = self._open_retrieval_boundary()
            except Exception:
                self._emit_retrieval("retriever_unavailable")
                raise
        prepared_items: list[_PreparedAuthorityRetrieval | None] = []
        for item in requests:
            if not item.query.strip() or item.limit < 1:
                prepared_items.append(None)
                continue
            if boundary is None:
                self._emit_retrieval("index_not_ready")
                prepared_items.append(
                    _PreparedAuthorityRetrieval(
                        item=replace(item, limit=min(item.limit, 100)),
                        empty=(),
                    )
                )
                continue
            prepared_items.append(self._prepare_authority_sync(item, boundary=boundary))
        hit_counts = tuple(
            0
            if prepared is None
            or prepared.empty is not None
            or prepared.cached_hits is not None
            or prepared.prepared is None
            else prepared.prepared.rerank_hit_count()
            for prepared in prepared_items
        )
        raise_if_complete_rerank_plan_exceeds_remaining(
            hit_counts, ranking_payload_tokens=RANKING_PAYLOAD_MAX_TOKENS
        )
        results: list[tuple[EvidenceSpan, ...]] = []
        plan_codes: list[str] = []
        for prepared in prepared_items:
            if prepared is None:
                results.append(())
                continue
            self.last_retrieval_code = None
            results.append(self._finish_authority_sync(prepared))
            if self.last_retrieval_code is not None:
                plan_codes.append(self.last_retrieval_code)
        if results and not any(results):
            for code in (
                "relevance_threshold_policy_not_frozen",
                "no_threshold_qualified_evidence",
                "retriever_unavailable",
                "reranker_unavailable",
                "wrong_jurisdiction",
                "historical_above_current",
                "incomplete_proposition_span",
                "filtered_out",
                "zero_hits",
            ):
                if code in plan_codes:
                    self.last_retrieval_code = code
                    break
        if boundary is not None:
            self._assert_retrieval_boundary_unchanged(boundary)
        return tuple(results)

    def _prepare_authority_sync(
        self,
        item: RetrievalPlanItem,
        *,
        boundary: _VerifiedRetrievalBoundary,
    ) -> _PreparedAuthorityRetrieval:
        query = item.query
        jurisdiction = item.jurisdiction
        subject = item.subject
        as_of_date = item.as_of_date
        limit = min(item.limit, 100)
        cacheable = item.cacheable
        capped = RetrievalPlanItem(
            query=query,
            jurisdiction=jurisdiction,
            subject=subject,
            as_of_date=as_of_date,
            limit=limit,
            cacheable=cacheable,
            query_rewrite_version=item.query_rewrite_version,
        )
        self.last_retrieval_code = None
        raise_if_retrieval_budget_exhausted()
        build_id = boundary.build_id
        build_row = boundary.build_row
        try:
            source_manifest_sha256 = boundary.capability.source_manifest_sha256
            runtime = self._runtime(
                build_id,
                build_row,
                PHYSICAL_AUTHORITY_LANE,
                boundary=boundary,
            )
            if runtime is None:  # pragma: no cover - authority is not optional
                raise RuntimeError("ACTIVE build has no authority retrieval table")
            table, embedder, reranker = runtime
        except Exception:
            self._emit_retrieval("retriever_unavailable", build_id=build_id)
            raise
        filters = QueryFilters(
            jurisdictions=frozenset(_query_jurisdictions(jurisdiction)),
            material_lanes=frozenset(
                {
                    MaterialLane.PRIMARY_AUTHORITY,
                    MaterialLane.OFFICIAL_GUIDANCE,
                    MaterialLane.SECONDARY_SCHOLARSHIP,
                }
            ),
            exact_jurisdictions=frozenset(_query_exact_jurisdictions(jurisdiction)),
            subjects=_query_subjects(subject),
            review_states=frozenset({"approved"}),
        )
        search_query = _bounded_search_query(query, filters, limit=limit)
        cache_key: str | None = None
        cached_hits: tuple[SearchHit, ...] | None = None
        if cacheable:
            cache_key = retrieval_cache_key(
                query=query,
                corpus_id=str(build_row["corpus_id"] or build_id),
                tenant_visibility="owner_local_authority",
                jurisdiction=jurisdiction,
                active_build_id=build_id,
                source_manifest_sha256=source_manifest_sha256,
                as_of_date=as_of_date.isoformat(),
                task_type="legal_qa",
                subject=subject,
                material_lanes=sorted(lane.value for lane in filters.material_lanes),
                filters={
                    "jurisdictions": sorted(filters.jurisdictions),
                    "exact_jurisdictions": sorted(filters.exact_jurisdictions),
                    "subjects": sorted(filters.subjects),
                    "review_states": sorted(filters.review_states),
                },
                query_rewrite_version=item.query_rewrite_version,
                retrieval_version=(
                    f"hybrid-rrf-rerank-{ADMISSION_VERSION}-{EXPLICIT_REFERENCE_VERSION}"
                ),
                chunker_version=str(build_row["chunker_version"] or "unknown"),
                embedding_version=str(
                    build_row["embedding_model_version"] or build_row["embedding_model"]
                ),
                reranker_version=str(build_row["rerank_version"] or build_row["reranker_model"]),
                policy_version=str(build_row["policy_sha256"] or "unbound"),
                retrieval_config={
                    "limit": limit,
                    "lexical_candidate_limit": search_query.lexical_limit(),
                    "vector_candidate_limit": search_query.vector_limit(),
                    "rerank_candidate_limit": search_query.rerank_limit(),
                    "ranking_representation_version": RANKING_REPRESENTATION_VERSION,
                    "ranking_payload_max_tokens": RANKING_PAYLOAD_MAX_TOKENS,
                    "physical_lane": PHYSICAL_AUTHORITY_LANE,
                    "selected_attestation_sha256": boundary.capability.attestation_sha256,
                    "scorer_implementation_sha256": (
                        boundary.capability.scorer_implementation_sha256
                    ),
                    "scorer_closure_aggregate_sha256": (
                        boundary.capability.scorer_closure_aggregate_sha256
                    ),
                    "relevance_threshold_policy_sha256": (
                        self._relevance_policy.policy_sha256
                    ),
                },
            )
            cached = self._retrieval_cache.get(active_build_id=build_id, key=cache_key)
            if cached is not None:
                cached_hits = self._hydrate_cached_hits(table, cached)
        if cached_hits is not None:
            return _PreparedAuthorityRetrieval(
                item=capped,
                build_id=build_id,
                table=table,
                cache_key=cache_key,
                cached_hits=cached_hits,
            )
        retriever = HybridRetriever(
            embedder=embedder,
            lexical_backend=_LanceLexicalBackend(table, as_of_date),
            vector_backend=_LanceVectorBackend(table, as_of_date),
            reranker=reranker,
            reference_resolver=self._reference_resolver,
        )
        raise_if_retrieval_budget_exhausted()
        prepared = retriever.prepare(search_query)
        return _PreparedAuthorityRetrieval(
            item=capped,
            build_id=build_id,
            table=table,
            retriever=retriever,
            prepared=prepared,
            cache_key=cache_key,
        )

    def _finish_authority_sync(
        self, prepared: _PreparedAuthorityRetrieval
    ) -> tuple[EvidenceSpan, ...]:
        if prepared.empty is not None:
            return prepared.empty
        item = prepared.item
        hits: Sequence[SearchHit]
        if prepared.cached_hits is not None:
            hits = prepared.cached_hits
        else:
            if prepared.retriever is None or prepared.prepared is None:
                raise RuntimeError("authority retrieval prepare did not yield a rerank plan")
            raise_if_retrieval_budget_exhausted()
            hits = prepared.retriever.finish(prepared.prepared)
            self._record_rerank_timing(prepared.retriever)
            if getattr(prepared.retriever, "last_vector_degraded", False):
                self._emit_retrieval("vector_degraded_lexical_only", build_id=prepared.build_id)
            if getattr(prepared.retriever, "last_reranker_unavailable", False):
                self._emit_retrieval("reranker_unavailable", build_id=prepared.build_id)
            if prepared.cache_key is not None and prepared.build_id is not None:
                with suppress(OSError, TypeError, ValueError):
                    self._retrieval_cache.put(
                        active_build_id=prepared.build_id,
                        key=prepared.cache_key,
                        hits=tuple(
                            SafeCachedHit(
                                source_version_id=str(hit.chunk.metadata["source_version_id"]),
                                chunk_id=hit.chunk.chunk_id,
                                rank=rank,
                                score=(
                                    hit.rerank_score if hit.rerank_score is not None else hit.score
                                ),
                            )
                            for rank, hit in enumerate(hits, 1)
                        ),
                    )
        return self._spans_from_hits(
            query=item.query,
            jurisdiction=item.jurisdiction,
            as_of_date=item.as_of_date,
            limit=item.limit,
            hits=hits,
            build_id=prepared.build_id or "",
        )

    def _spans_from_hits(
        self,
        *,
        query: str,
        jurisdiction: str,
        as_of_date: date,
        limit: int,
        hits: Sequence[SearchHit],
        build_id: str,
    ) -> tuple[EvidenceSpan, ...]:
        output: list[EvidenceSpan] = []
        filtered = 0
        wrong_jurisdiction = 0
        historical = 0
        incomplete_span = 0
        blocked_material_update = 0
        relevance_filtered = 0
        relevance_policy_not_frozen = 0
        pending_update_alert = False
        hits, older_version_count = _latest_source_version_hits(hits)
        raw_count = len(hits)
        if older_version_count:
            self._emit_retrieval("older_source_version_filtered", build_id=build_id)
        material_update_gate = MaterialUpdateGate(self.database)
        exact_authority = explicit_authority_identity(query)
        exact_legislation = (
            self._reference_resolver.resolve(query)
            if exact_authority is None and self._reference_resolver is not None
            else None
        )
        if exact_authority is not None:
            retrieval_route = "exact_authority_identity"
        elif exact_legislation is not None:
            retrieval_route = "exact_legislation_reference"
        else:
            retrieval_route = SEMANTIC_ROUTE
        for hit in hits:
            metadata = hit.chunk.metadata
            locator = str(
                metadata.get("locator") or metadata.get("legal_locator") or ""
            ).strip()
            source_version_id = str(metadata.get("source_version_id") or "").strip()
            exact_identity_and_locator_verified = False
            if exact_authority is not None:
                exact_identity_and_locator_verified = bool(
                    hit.chunk.source_identity == exact_authority
                    and source_version_id
                    and locator
                    and metadata.get("identity_verified") is True
                )
            elif exact_legislation is not None:
                exact_identity_and_locator_verified = bool(
                    hit.chunk.source_identity == exact_legislation.source_identity
                    and source_version_id
                    and legislation_locator_within(locator, exact_legislation.locator)
                    and metadata.get("identity_verified") is True
                )
            raw_score = hit.rerank_score if hit.rerank_score is not None else hit.score
            relevance = qualify_retrieval_score(
                route=retrieval_route,
                score=raw_score,
                policy=self._relevance_policy,
                exact_identity_and_locator_verified=exact_identity_and_locator_verified,
            )
            if not relevance.qualified:
                relevance_filtered += 1
                if relevance.reason == "relevance_threshold_policy_not_frozen":
                    relevance_policy_not_frozen += 1
                continue
            source_jurisdiction = str(metadata["catalog_jurisdiction"])
            citation_data = dict(metadata.get("citation_data", {}))
            lane = str(metadata["catalog_lane"])
            if lane not in _LEGAL_CATALOG_LANES:
                filtered += 1
                continue
            if not compatible(jurisdiction, source_jurisdiction, citation_data):
                wrong_jurisdiction += 1
                continue
            row_as_of = str(metadata.get("as_of_date") or "")
            if row_as_of:
                try:
                    if date.fromisoformat(row_as_of) > as_of_date:
                        filtered += 1
                        continue
                except ValueError:
                    filtered += 1
                    continue
            status = str(metadata.get("currentness_status") or "").casefold()
            if is_legislation_source(citation_data) and status in {
                "historical",
                "historical_as_enacted",
                "as_enacted",
            }:
                historical += 1
            locator = str(metadata.get("locator") or "")
            if not locator.strip() or not str(hit.chunk.text or "").strip():
                incomplete_span += 1
                continue
            span = EvidenceSpan(
                id=_stable_id("evidence", build_id, hit.chunk.chunk_id),
                source_version_id=str(metadata["source_version_id"]),
                chunk_id=hit.chunk.chunk_id,
                text=hit.chunk.text,
                locator=str(metadata["locator"]),
                lane=CatalogLane(lane),
                jurisdiction=source_jurisdiction,
                subject=hit.chunk.subject,
                citation_data=citation_data,
                canonical_citation=_optional_text(metadata.get("canonical_citation")),
                currentness_status=str(metadata.get("currentness_status") or "unknown"),
                content_sha256=hit.chunk.content_sha256,
                index_build_id=build_id,
                canonical_url=_optional_text(metadata.get("canonical_url")),
                retrieval_relevance_score=relevance.score,
                retrieval_route=relevance.route,
                retrieval_threshold=relevance.threshold,
                retrieval_threshold_policy_sha256=relevance.policy_sha256,
                retrieval_threshold_qualified=True,
                retrieval_qualification_reason=relevance.reason,
                legal_role=str(hit.chunk.metadata.get("legal_role") or "unclassified"),
                unapplied_effect_count=(
                    int(metadata["unapplied_effect_count"])
                    if metadata.get("unapplied_effect_count") is not None
                    else None
                ),
                provision_extent_status=str(
                    metadata.get("provision_extent_status") or "unverified"
                ),
                identity_verified=bool(metadata.get("identity_verified")),
                currentness_verified=bool(metadata.get("currentness_verified")),
                case_currentness_reviews=_case_proposition_reviews(
                    metadata.get("case_currentness_reviews")
                ),
                case_currentness_manifest_seals=_case_manifest_seals(
                    metadata.get("case_currentness_manifest_seals")
                ),
            )
            assessment = material_update_gate.assess(
                span,
                enforce_promoted_resolution=self._pinned_build_id is None,
            )
            if assessment.pending_alert_ids:
                pending_update_alert = True
            if assessment.blocked_observation_ids:
                blocked_material_update += 1
                continue
            output.append(span)
        if pending_update_alert:
            self._emit_update_alert(build_id=build_id)
        if blocked_material_update:
            self._emit_retrieval("verified_material_update_unresolved", build_id=build_id)
        kept = tuple(output[:limit])
        if not kept:
            if blocked_material_update:
                pass
            elif relevance_policy_not_frozen and relevance_policy_not_frozen == raw_count:
                self._emit_retrieval(
                    "relevance_threshold_policy_not_frozen", build_id=build_id
                )
            elif relevance_filtered and relevance_filtered == raw_count:
                self._emit_retrieval(
                    "no_threshold_qualified_evidence", build_id=build_id
                )
            elif wrong_jurisdiction and not filtered:
                self._emit_retrieval("wrong_jurisdiction", build_id=build_id)
            elif historical and historical == raw_count:
                self._emit_retrieval("historical_above_current", build_id=build_id)
            elif incomplete_span and incomplete_span == raw_count:
                self._emit_retrieval("incomplete_proposition_span", build_id=build_id)
            elif raw_count:
                self._emit_retrieval("filtered_out", build_id=build_id)
            else:
                lowered = query.casefold()
                if "uksc" in lowered or "neutral citation" in lowered:
                    self._emit_retrieval("expected_authority_missing", build_id=build_id)
                else:
                    self._emit_retrieval("zero_hits", build_id=build_id)
        elif relevance_filtered:
            self._emit_retrieval("below_relevance_threshold_filtered", build_id=build_id)
        elif historical:
            self._emit_retrieval("historical_above_current", build_id=build_id)
        return kept

    @staticmethod
    def _hydrate_cached_hits(
        table: Any,
        cached: Sequence[SafeCachedHit],
    ) -> tuple[SearchHit, ...] | None:
        """Hydrate safe IDs from the exact ACTIVE table; any drift is a miss."""

        hydrated: list[SearchHit] = []
        try:
            for item in sorted(cached, key=lambda value: value.rank):
                where = (
                    f"chunk_id = '{_sql_text(item.chunk_id)}' AND "
                    f"source_version_id = '{_sql_text(item.source_version_id)}'"
                )
                rows = table.search().where(where, prefilter=True).limit(1).to_list()
                if len(rows) != 1:
                    return None
                chunk = _lance_row_to_indexed(rows[0])
                if (
                    chunk.chunk_id != item.chunk_id
                    or str(chunk.metadata.get("source_version_id")) != item.source_version_id
                ):
                    return None
                hydrated.append(
                    SearchHit(
                        chunk=chunk,
                        score=item.score,
                        rerank_score=item.score,
                        diagnostics={"cache": "safe_id_hit"},
                    )
                )
        except (KeyError, OSError, RuntimeError, TypeError, ValueError):
            return None
        return tuple(hydrated)

    def _record_rerank_timing(self, retriever: HybridRetriever) -> None:
        if self.observability is None:
            return
        context = self.observability.current_context()
        if context is None:
            return
        rerank_ms = float(getattr(retriever, "last_timings_ms", {}).get("rerank", 0.0))
        self.observability.record_duration(
            context,
            metric="rerank_seconds",
            duration_seconds=max(0.0, rerank_ms / 1_000),
            operation=TraceOperation.RERANK,
            stage=TraceStage.RERANK,
        )

    def _runtime(
        self,
        build_id: str,
        build_row: Mapping[str, Any],
        physical_lane: str,
        *,
        boundary: _VerifiedRetrievalBoundary | None = None,
    ) -> tuple[Any, Any, Reranker] | None:
        if physical_lane not in PHYSICAL_LANES:
            raise ValueError("unknown physical retrieval lane")
        if boundary is None:
            boundary = self._open_retrieval_boundary()
            if boundary is None:
                raise RuntimeError("retrieval runtime has no selected build")
        if boundary.build_id != build_id:
            raise RuntimeError("retrieval runtime build differs from verified boundary")
        if (
            _runtime_catalogue_binding_sha256(build_row)
            != boundary.capability.catalogue_binding_sha256
        ):
            raise RuntimeError("retrieval runtime catalogue binding differs")
        with self._runtime_lock:
            if self._runtime_build_id == build_id:
                if self._embedder is None or self._reranker is None:
                    raise RuntimeError("retrieval runtime cache is incomplete")
                table = self._tables.get(physical_lane)
                if table is None:
                    if (
                        physical_lane in OPTIONAL_PHYSICAL_LANES
                        and _physical_lane_row_count(self.settings, build_id, physical_lane) == 0
                    ):
                        return None
                    raise RuntimeError(f"ACTIVE build has no {physical_lane} retrieval table")
                return table, self._embedder, self._reranker
            lancedb_module = _import_lancedb()
            build_path = self.settings.index_dir / "builds" / build_id
            tables: dict[str, Any] = {}
            for lane in PHYSICAL_LANES:
                lane_path = build_path / "lance" / lane
                if not lane_path.is_dir():
                    continue
                try:
                    connection = lancedb_module.connect(str(lane_path))
                    tables[lane] = connection.open_table("chunks")
                except Exception:
                    # Empty physical lanes have a directory and a zero count in
                    # the sealed lane manifest but intentionally no table.
                    continue
            embedder = _embedding_provider(self.settings, str(build_row["embedding_model"]))
            reranker = _reranker_provider(self.settings, str(build_row["reranker_model"]))
            reference_manifest = build_path / "approved-source-manifest.json"
            reference_resolver = (
                CandidateLegislationReferenceResolver.from_path(reference_manifest)
                if reference_manifest.is_file()
                else None
            )
            self._runtime_build_id = build_id
            self._tables = tables
            self._embedder = embedder
            self._reranker = reranker
            self._reference_resolver = reference_resolver
            table = tables.get(physical_lane)
            if table is None:
                if (
                    physical_lane in OPTIONAL_PHYSICAL_LANES
                    and _physical_lane_row_count(self.settings, build_id, physical_lane) == 0
                ):
                    return None
                raise RuntimeError(f"ACTIVE build has no {physical_lane} retrieval table")
            return table, embedder, reranker


class _RealLanceSessionFactory:
    def __init__(self, lancedb_module: Any) -> None:
        self.module = lancedb_module

    def create(self, generation_path: Path) -> _RealLanceSession:
        return _RealLanceSession(self.module, generation_path)


class _RealLanceSession:
    def __init__(self, lancedb_module: Any, path: Path) -> None:
        self.module = lancedb_module
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        self.connections: dict[str, Any] = {}
        self.tables: dict[str, Any] = {}
        self.row_counts: dict[str, int] = {lane: 0 for lane in PHYSICAL_LANES}
        self.table: Any | None = None
        self.row_count = 0

    def write_chunks(
        self,
        chunks: Iterable[IndexedChunk],
        *,
        on_flush: Callable[[int], None] | None = None,
    ) -> int:
        buffers: dict[str, list[dict[str, Any]]] = {lane: [] for lane in PHYSICAL_LANES}

        def flush(lane: str) -> None:
            rows = buffers[lane]
            if not rows:
                return
            table = self.tables.get(lane)
            if table is None:
                lane_path = self.path / lane
                lane_path.mkdir(parents=True, exist_ok=True)
                connection = self.module.connect(str(lane_path))
                table = connection.create_table("chunks", data=rows, mode="create")
                self.connections[lane] = connection
                self.tables[lane] = table
                if lane == PHYSICAL_AUTHORITY_LANE or self.table is None:
                    self.table = table
            else:
                table.add(rows)
            self.row_counts[lane] += len(rows)
            self.row_count += len(rows)
            buffers[lane] = []
            if on_flush is not None:
                on_flush(self.row_count)

        for chunk in chunks:
            lane = _physical_lane_for_chunk(chunk)
            buffers[lane].append(_indexed_to_lance_row(chunk))
            if len(buffers[lane]) >= LANCE_WRITE_BATCH_SIZE:
                flush(lane)
        for lane in PHYSICAL_LANES:
            flush(lane)
            (self.path / lane).mkdir(parents=True, exist_ok=True)
        if self.row_count == 0:
            raise ValueError("LanceDB build cannot be empty")
        return self.row_count

    def open_existing(self) -> None:
        for lane in PHYSICAL_LANES:
            lane_path = self.path / lane
            if not lane_path.exists():
                continue
            connection = self.module.connect(str(lane_path))
            try:
                table = connection.open_table("chunks")
            except (OSError, ValueError, FileNotFoundError, RuntimeError):
                continue
            count = int(table.count_rows()) if hasattr(table, "count_rows") else 0
            self.connections[lane] = connection
            self.tables[lane] = table
            self.row_counts[lane] = count
            self.row_count += count
            if lane == PHYSICAL_AUTHORITY_LANE or self.table is None:
                self.table = table

    def create_indexes(self) -> None:
        if not self.tables:
            raise RuntimeError("chunks must be written before indexes are created")
        for lane, table in self.tables.items():
            table.create_fts_index("text", replace=True)
            table.create_index(
                metric="cosine",
                num_partitions=max(1, min(256, int(math.sqrt(self.row_counts[lane])) or 1)),
                vector_column_name="vector",
                index_type="IVF_FLAT",
                replace=True,
            )
        _write_new_json(
            self.path / "physical-lanes.json",
            {
                "schema": "legalbot.physical-lanes.v1",
                "separated": True,
                "tables": {
                    lane: {"directory": lane, "row_count": self.row_counts[lane]}
                    for lane in PHYSICAL_LANES
                },
            },
        )

    def close(self) -> None:
        self.table = None
        self.tables = {}
        self.connections = {}


class _LanceLexicalBackend:
    def __init__(self, table: Any, as_of_date: date) -> None:
        self.table = table
        self.as_of_date = as_of_date

    def search(self, text: str, *, filters: QueryFilters, limit: int) -> Sequence[SearchCandidate]:
        query = self.table.search(text, query_type="fts", fts_columns=["text"])
        rows = (
            query.where(_lance_filter(filters, self.as_of_date), prefilter=True)
            .limit(limit)
            .to_list()
        )
        output: list[SearchCandidate] = []
        for rank, row in enumerate(rows, 1):
            chunk = _lance_row_to_indexed(row)
            if chunk_matches(chunk, filters):
                output.append(
                    SearchCandidate(chunk, float(row.get("_score", 1.0 / rank)), rank, "lexical")
                )
        return tuple(output)

    def search_identity(
        self, source_identity: str, *, filters: QueryFilters, limit: int
    ) -> Sequence[SearchCandidate]:
        where = (
            f"{_lance_filter(filters, self.as_of_date)} AND "
            f"source_identity = '{_sql_text(source_identity)}'"
        )
        rows = self.table.search().where(where, prefilter=True).limit(limit).to_list()
        output: list[SearchCandidate] = []
        for rank, row in enumerate(rows, 1):
            chunk = _lance_row_to_indexed(row)
            if chunk.source_identity == source_identity and chunk_matches(chunk, filters):
                output.append(SearchCandidate(chunk, 1.0 / rank, rank, "identity"))
        return tuple(output)

    def search_reference(
        self,
        reference: ExplicitLegislationReference,
        *,
        filters: QueryFilters,
        limit: int,
    ) -> Sequence[SearchCandidate]:
        """Read one manifest-bound statute and retain only the requested section."""

        if limit < 1:
            raise ValueError("exact-reference limit must be positive")
        where = (
            f"{_lance_filter(filters, self.as_of_date)} AND "
            f"source_identity = '{_sql_text(reference.source_identity)}'"
        )
        rows = (
            self.table.search()
            .where(where, prefilter=True)
            .limit(reference.source_chunk_count + 1)
            .to_list()
        )
        if len(rows) > reference.source_chunk_count:
            raise RuntimeError("candidate source rows exceed the sealed manifest count")
        chunks = []
        for row in rows:
            chunk = _lance_row_to_indexed(row)
            locator = str(
                chunk.metadata.get("locator") or chunk.metadata.get("legal_locator") or ""
            ).strip()
            if (
                chunk.source_identity == reference.source_identity
                and legislation_locator_within(locator, reference.locator)
                and chunk_matches(chunk, filters)
            ):
                chunks.append(chunk)
        chunks.sort(
            key=lambda chunk: (
                canonical_legislation_locator(
                    chunk.metadata.get("locator") or chunk.metadata.get("legal_locator")
                )
                or "",
                chunk.chunk_id,
            )
        )
        return tuple(
            SearchCandidate(chunk, 1.0 / rank, rank, "explicit_reference")
            for rank, chunk in enumerate(chunks[:limit], 1)
        )


class _LanceVectorBackend:
    def __init__(self, table: Any, as_of_date: date) -> None:
        self.table = table
        self.as_of_date = as_of_date

    def search(
        self, vector: Sequence[float], *, filters: QueryFilters, limit: int
    ) -> Sequence[SearchCandidate]:
        query = self.table.search(list(ensure_vector(vector)), vector_column_name="vector")
        rows = (
            query.where(_lance_filter(filters, self.as_of_date), prefilter=True)
            .limit(limit)
            .to_list()
        )
        output: list[SearchCandidate] = []
        for rank, row in enumerate(rows, 1):
            chunk = _lance_row_to_indexed(row)
            if chunk_matches(chunk, filters):
                distance = max(0.0, float(row.get("_distance", 1.0)))
                output.append(SearchCandidate(chunk, 1.0 / (1.0 + distance), rank, "vector"))
        return tuple(output)


def _run_candidate_benchmark(
    *,
    lancedb_module: Any,
    build_path: Path,
    benchmark: RetrievalBenchmark,
    embedder: Any,
    reranker: Reranker,
    indexed_chunk_lanes: Mapping[str, str],
) -> dict[str, Any]:
    """Run the sealed hybrid stack directly against an unpromoted candidate."""

    connection = lancedb_module.connect(str(build_path / "lance" / PHYSICAL_AUTHORITY_LANE))
    table = connection.open_table("chunks")
    rankings: dict[str, tuple[str, ...]] = {}
    legal_lanes = frozenset(
        {
            MaterialLane.PRIMARY_AUTHORITY,
            MaterialLane.OFFICIAL_GUIDANCE,
            MaterialLane.SECONDARY_SCHOLARSHIP,
        }
    )
    reference_manifest = build_path / "approved-source-manifest.json"
    reference_resolver = (
        CandidateLegislationReferenceResolver.from_path(reference_manifest)
        if reference_manifest.is_file()
        else None
    )
    for benchmark_query in benchmark.queries:
        filters = QueryFilters(
            jurisdictions=frozenset(_query_jurisdictions(benchmark_query.jurisdiction)),
            material_lanes=legal_lanes,
            exact_jurisdictions=frozenset(_query_exact_jurisdictions(benchmark_query.jurisdiction)),
            subjects=_query_subjects(benchmark_query.subject),
            review_states=frozenset({"approved"}),
        )
        retriever = HybridRetriever(
            embedder=embedder,
            lexical_backend=_LanceLexicalBackend(table, benchmark_query.as_of_date),
            vector_backend=_LanceVectorBackend(table, benchmark_query.as_of_date),
            reranker=reranker,
            reference_resolver=reference_resolver,
        )
        hits = retriever.search(
            SearchQuery(
                benchmark_query.query,
                filters,
                limit=50,
                candidate_limit=100,
                lexical_candidate_limit=100,
                vector_candidate_limit=100,
                rerank_candidate_limit=max(50, LIVE_RERANK_CANDIDATE_LIMIT),
            )
        )
        rankings[benchmark_query.id] = tuple(hit.chunk.chunk_id for hit in hits)
    report = score_retrieval_benchmark(benchmark, rankings, indexed_chunk_lanes)
    report["created_at"] = utc_iso()
    return report


_APPROVED_CHUNK_SELECT = """
        SELECT
          d.id AS document_id, d.content_sha256 AS document_sha256,
          d.source_identity_id, d.representation_group_id,
          d.retrieval_canonical, d.status AS document_status, d.lane,
          d.subject_primary, d.jurisdiction,
          sv.id AS source_version_id, sv.version_sha256, sv.title,
          sv.author_or_body, sv.source_date, sv.as_of_date, sv.canonical_url,
          sv.created_at AS source_last_updated_at,
          sv.stable_identifier, sv.currentness_status, sv.licence_name,
          sv.licence_url, sv.review_status, sv.metadata_json AS source_metadata_json,
          c.id AS chunk_id, c.ordinal, c.heading_path, c.locator, c.stream,
          c.text_sha256, c.markdown_text, c.metadata_json AS chunk_metadata_json
        FROM chunks c
        JOIN source_versions sv ON sv.id=c.source_version_id
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.review_status='approved'
          AND sv.superseded_by IS NULL
          AND sv.version_sha256=d.content_sha256
          AND d.duplicate_of IS NULL
          AND d.status IN ('citable', 'private_teaching', 'assessment_guidance')
          AND json_extract(sv.metadata_json, '$.eligible_for_model_use') = 1
          AND COALESCE(json_extract(sv.metadata_json, '$.ai_use_policy'), '') <> 'prohibited'
          AND (
            (d.retrieval_canonical=1 AND c.stream='body')
            OR (d.lane='assessment_guidance' AND c.stream='comments')
          )
          AND c.id > ?
        ORDER BY c.id
        LIMIT ?
"""


def _approved_chunk_count(database: Database) -> int:
    row = database.fetchone(
        """
        SELECT COUNT(*) AS count
        FROM chunks c
        JOIN source_versions sv ON sv.id=c.source_version_id
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.review_status='approved'
          AND sv.superseded_by IS NULL
          AND sv.version_sha256=d.content_sha256
          AND d.duplicate_of IS NULL
          AND d.status IN ('citable', 'private_teaching', 'assessment_guidance')
          AND json_extract(sv.metadata_json, '$.eligible_for_model_use') = 1
          AND COALESCE(json_extract(sv.metadata_json, '$.ai_use_policy'), '') <> 'prohibited'
          AND (
            (d.retrieval_canonical=1 AND c.stream='body')
            OR (d.lane='assessment_guidance' AND c.stream='comments')
          )
        """
    )
    return int(row["count"]) if row is not None else 0


def _approved_chunk_row_batches(
    database: Database, *, batch_size: int | None = None
) -> Iterator[list[Any]]:
    if batch_size is None:
        batch_size = INDEX_EMBED_BATCH_SIZE
    if batch_size < 1:
        raise ValueError("index batch size must be positive")
    last_chunk_id = ""
    while True:
        rows = database.fetchall(_APPROVED_CHUNK_SELECT, (last_chunk_id, batch_size))
        if not rows:
            return
        yield rows
        next_chunk_id = str(rows[-1]["chunk_id"])
        if next_chunk_id <= last_chunk_id:
            raise RuntimeError("approved chunk stream did not advance")
        last_chunk_id = next_chunk_id


def _summarise_approved_chunks(
    database: Database, benchmark: RetrievalBenchmark
) -> _ApprovedChunkSummary:
    digest = hashlib.sha256()
    document_ids: set[str] = set()
    jurisdictions: dict[str, int] = {}
    lanes: dict[str, int] = {}
    subjects: dict[str, int] = {}
    expected_ids = {
        chunk_id for query in benchmark.queries for chunk_id in query.relevant_chunk_ids
    }
    benchmark_chunk_lanes: dict[str, str] = {}
    chunk_count = 0
    for rows in _approved_chunk_row_batches(database):
        for row in rows:
            _update_source_manifest_digest(digest, row)
            chunk_count += 1
            document_ids.add(str(row["document_id"]))
            _increment(jurisdictions, str(row["jurisdiction"]))
            _increment(lanes, str(row["lane"]))
            _increment(subjects, str(row["subject_primary"] or "general"))
            chunk_id = str(row["chunk_id"])
            if chunk_id in expected_ids:
                benchmark_chunk_lanes[chunk_id] = str(row["lane"])
    if chunk_count == 0:
        raise ValueError("candidate build has no human-approved chunks")
    return _ApprovedChunkSummary(
        chunk_count=chunk_count,
        document_count=len(document_ids),
        source_manifest_sha256=digest.hexdigest(),
        jurisdictions=dict(sorted(jurisdictions.items())),
        lanes=dict(sorted(lanes.items())),
        subjects=dict(sorted(subjects.items())),
        benchmark_chunk_lanes=benchmark_chunk_lanes,
    )


def _approved_source_snapshot(database: Database) -> _ApprovedSourceSnapshot:
    """Hash the current approved retrieval set under the caller's catalogue lock."""

    digest = hashlib.sha256()
    document_ids: set[str] = set()
    chunk_count = 0
    for rows in _approved_chunk_row_batches(database):
        for row in rows:
            _update_source_manifest_digest(digest, row)
            document_ids.add(str(row["document_id"]))
            chunk_count += 1
    return _ApprovedSourceSnapshot(
        chunk_count=chunk_count,
        document_count=len(document_ids),
        source_manifest_sha256=digest.hexdigest(),
    )


def _completed_scan_snapshot(database: Database) -> _CompletedScanSnapshot:
    row = database.fetchone(
        """
        SELECT id, manifest_sha256, expected_file_count, files_accounted
        FROM source_scans
        WHERE status='complete'
        ORDER BY completed_at DESC, created_at DESC
        LIMIT 1
        """
    )
    if row is None:
        raise RuntimeError("candidate build requires a completed source scan")
    manifest_sha256 = str(row["manifest_sha256"] or "")
    expected = int(row["expected_file_count"])
    accounted = int(row["files_accounted"])
    if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) or expected != accounted:
        raise RuntimeError("completed source scan is not exactly reconciled or sealed")
    actual = database.fetchone(
        "SELECT COUNT(*) AS count FROM source_scan_files WHERE scan_id=?",
        (row["id"],),
    )
    if actual is None or int(actual["count"]) != expected:
        raise RuntimeError("completed source scan file manifest does not reconcile")
    return _CompletedScanSnapshot(str(row["id"]), manifest_sha256, expected, accounted)


def _stream_indexed_chunks(
    database: Database, embedder: Any, observation: _StreamObservation
) -> Iterator[IndexedChunk]:
    digest = hashlib.sha256()
    for rows in _approved_chunk_row_batches(database):
        vectors = embedder.embed_documents([_prompt_safe_index_text(row) for row in rows])
        if len(vectors) != len(rows):
            raise RuntimeError("embedding provider did not return one vector per chunk")
        for row, vector in zip(rows, vectors, strict=True):
            _update_source_manifest_digest(digest, row)
            observation.count += 1
            yield _catalogue_row_to_indexed(row, vector)
    observation.source_manifest_sha256 = digest.hexdigest()


def _synchronise_source_reviews(database: Database) -> None:
    with database.transaction() as connection:
        connection.execute(
            """
            UPDATE source_versions
            SET review_status='approved'
            WHERE id IN (
              SELECT target_id FROM reviews
              WHERE review_type='source_version' AND status='approved'
            )
            """
        )
        connection.execute(
            """
            UPDATE source_versions
            SET review_status='rejected'
            WHERE id IN (
              SELECT target_id FROM reviews
              WHERE review_type='source_version' AND status='rejected'
            )
            """
        )


def _catalogue_row_to_indexed(
    row: Mapping[str, Any],
    vector: Sequence[float],
    *,
    provision_verifications: Mapping[tuple[str, str], Mapping[str, Any]] | None = None,
) -> IndexedChunk:
    from .provision_verification import qualification_for

    source_metadata = _json_object(row["source_metadata_json"])
    chunk_metadata = _json_object(row["chunk_metadata_json"])
    case_currentness_reviews = _case_proposition_reviews(
        chunk_metadata.get("case_currentness_reviews")
    )
    case_currentness_manifest_seals = _case_manifest_seals(
        chunk_metadata.get("case_currentness_review_manifest_seals")
    )
    citation_data = source_metadata.get("citation_data")
    if not isinstance(citation_data, dict):
        citation_data = {}
    catalog_lane = str(row["lane"])
    catalog_jurisdiction = str(row["jurisdiction"])
    canonical_text = str(row["markdown_text"])
    canonical_chunk_sha256 = _required_sha256(row["text_sha256"], label="catalogue canonical chunk")
    computed_canonical_sha256 = hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()
    if canonical_chunk_sha256 != computed_canonical_sha256:
        raise ValueError("catalogue canonical chunk SHA-256 does not match markdown text")
    prompt_safe_text = _prompt_safe_index_text(row)
    retrieval_eligible = _answer_retrieval_eligible(
        catalog_lane=catalog_lane,
        citation_data=citation_data,
        currentness_status=str(row["currentness_status"] or "unknown"),
        source_metadata=source_metadata,
    )
    stable_source_id = str(row["stable_identifier"] or row["source_identity_id"])
    legal_locator = str(row["locator"])
    try:
        source_content_sha256 = str(row["document_sha256"])
    except (KeyError, IndexError):
        source_content_sha256 = ""
    provision = qualification_for(
        provision_verifications or {},
        stable_source_id=stable_source_id,
        legal_locator=legal_locator,
        source_content_sha256=source_content_sha256,
        source_version_sha256=str(row["version_sha256"]),
    )
    official_snapshot = source_metadata.get("official_snapshot")
    if not isinstance(official_snapshot, dict):
        official_snapshot = {}
    try:
        source_last_updated = row["source_last_updated_at"]
    except (KeyError, IndexError):
        source_last_updated = source_metadata.get("last_updated")
    return IndexedChunk(
        chunk_id=str(row["chunk_id"]),
        text=prompt_safe_text,
        vector=ensure_vector(vector),
        jurisdiction=_ingestion_jurisdiction(catalog_jurisdiction),
        material_lane=_ingestion_lane(catalog_lane),
        subject=_normalise_subject(str(row["subject_primary"] or "general")),
        review_state="approved",
        source_identity=stable_source_id,
        content_sha256=hashlib.sha256(prompt_safe_text.encode("utf-8")).hexdigest(),
        title=_optional_text(row["title"]),
        canonical_url=_optional_text(row["canonical_url"]),
        citation=_optional_text(source_metadata.get("canonical_citation")),
        metadata={
            "source_version_id": str(row["source_version_id"]),
            "authority_identity_id": authority_identity_id(stable_source_id),
            "ordinal": _optional_int(row, "ordinal"),
            "source_version_sha256": str(row["version_sha256"]),
            "canonical_chunk_sha256": canonical_chunk_sha256,
            "prompt_view_schema": "legalbot.prompt-safe-index-view.v1",
            "representation_group_id": str(row["representation_group_id"]),
            "retrieval_canonical": bool(row["retrieval_canonical"]),
            "locator": legal_locator,
            "stream": str(row["stream"]),
            "catalog_lane": catalog_lane,
            "catalog_jurisdiction": catalog_jurisdiction,
            "citation_data": citation_data,
            "canonical_citation": source_metadata.get("canonical_citation"),
            "currentness_status": str(row["currentness_status"] or "unknown"),
            "identity_verified": bool(source_metadata.get("identity_verified", False)),
            "currentness_verified": bool(source_metadata.get("currentness_verified", False)),
            "unapplied_effect_count": (
                provision["section_unapplied_effect_count"]
                if provision is not None
                else official_snapshot.get("unapplied_effect_count")
            ),
            "provision_extent_status": str(
                "england_and_wales_verified"
                if provision is not None
                else source_metadata.get("provision_extent_status") or "unverified"
            ),
            "provision_unapplied_effect_materiality": (
                provision["unapplied_effect_materiality"] if provision is not None else None
            ),
            "provision_verification_url": (
                provision["official_source_url"] if provision is not None else None
            ),
            "retrieval_eligible": retrieval_eligible,
            "source_date": _optional_text(row["source_date"]),
            "as_of_date": _optional_text(row["as_of_date"]),
            "last_updated": _optional_text(source_last_updated),
            "canonical_url": _optional_text(row["canonical_url"]),
            "heading_path": _json_list(row["heading_path"]),
            "legal_role": str(chunk_metadata.get("legal_role") or "unclassified"),
            "case_currentness_reviews": [
                review.model_dump(mode="json", by_alias=True) for review in case_currentness_reviews
            ],
            "case_currentness_manifest_seals": list(case_currentness_manifest_seals),
            "chunk_metadata": chunk_metadata,
        },
    )


def _prompt_safe_index_text(row: Mapping[str, Any]) -> str:
    """Create a disposable prompt view without changing canonical source bytes."""

    return scrub_pii(str(row["markdown_text"]))


def _indexed_to_lance_row(chunk: IndexedChunk) -> dict[str, Any]:
    chunk.validate()
    metadata = chunk.metadata
    vector = ensure_vector(chunk.vector)
    content_sha256 = _required_sha256(chunk.content_sha256, label="prompt-view content")
    if content_sha256 != hashlib.sha256(chunk.text.encode("utf-8")).hexdigest():
        raise ValueError("prompt-view content SHA-256 does not match indexed text")
    canonical_value = metadata.get("canonical_chunk_sha256")
    if canonical_value is None or canonical_value == "":
        raise ValueError("new Lance rows require a canonical chunk SHA-256 binding")
    canonical_chunk_sha256 = _required_sha256(canonical_value, label="canonical chunk")
    canonical_binding = "bound"
    return {
        "chunk_id": chunk.chunk_id,
        "source_version_id": str(metadata["source_version_id"]),
        "authority_identity_id": str(
            metadata.get("authority_identity_id") or chunk.source_identity
        ),
        "representation_group_id": str(
            metadata.get("representation_group_id") or chunk.source_identity
        ),
        "stream": str(metadata.get("stream") or "body"),
        "text": chunk.text,
        "vector": list(vector),
        "jurisdiction_key": chunk.jurisdiction.value,
        "catalog_jurisdiction_key": normalise(str(metadata["catalog_jurisdiction"])),
        "lane_key": chunk.material_lane.value,
        "subject": chunk.subject,
        "review_state": chunk.review_state,
        "source_identity": chunk.source_identity,
        "content_sha256": content_sha256,
        "canonical_chunk_sha256": canonical_chunk_sha256,
        "canonical_chunk_sha256_binding": canonical_binding,
        "title": chunk.title or "",
        "canonical_url": chunk.canonical_url or "",
        "citation": chunk.citation or "",
        "locator": str(metadata["locator"]),
        "catalog_lane": str(metadata["catalog_lane"]),
        "catalog_jurisdiction": str(metadata["catalog_jurisdiction"]),
        "citation_json": json.dumps(
            metadata.get("citation_data", {}), ensure_ascii=False, sort_keys=True
        ),
        "canonical_citation": str(metadata.get("canonical_citation") or ""),
        "currentness_status": str(metadata.get("currentness_status") or "unknown"),
        "identity_verified": bool(metadata.get("identity_verified")),
        "currentness_verified": bool(metadata.get("currentness_verified")),
        "legal_role": str(metadata.get("legal_role") or "unclassified"),
        "case_currentness_reviews_json": json.dumps(
            metadata.get("case_currentness_reviews", ()),
            ensure_ascii=False,
            sort_keys=True,
        ),
        "case_currentness_manifest_seals_json": json.dumps(
            metadata.get("case_currentness_manifest_seals", ()),
            ensure_ascii=False,
            sort_keys=True,
        ),
        "retrieval_eligible": bool(metadata.get("retrieval_eligible", True)),
        "source_date": str(metadata.get("source_date") or ""),
        "as_of_date": str(metadata.get("as_of_date") or ""),
        "last_updated": str(metadata.get("last_updated") or ""),
    }


def _lance_row_to_indexed(row: Mapping[str, Any]) -> IndexedChunk:
    text = str(row["text"])
    content_sha256 = _required_sha256(row["content_sha256"], label="prompt-view content")
    if content_sha256 != hashlib.sha256(text.encode("utf-8")).hexdigest():
        raise ValueError("Lance prompt-view content SHA-256 does not match indexed text")
    canonical_value = row.get("canonical_chunk_sha256")
    if canonical_value is None or canonical_value == "":
        canonical_chunk_sha256: str | None = None
        canonical_binding = str(row.get("canonical_chunk_sha256_binding") or "legacy_missing")
        if canonical_binding != "legacy_missing":
            raise ValueError("Lance canonical chunk binding is inconsistent")
    else:
        canonical_chunk_sha256 = _required_sha256(canonical_value, label="canonical chunk")
        canonical_binding = str(row.get("canonical_chunk_sha256_binding") or "bound")
        if canonical_binding != "bound":
            raise ValueError("Lance canonical chunk binding is inconsistent")
    return IndexedChunk(
        chunk_id=str(row["chunk_id"]),
        text=text,
        vector=ensure_vector(row["vector"]),
        jurisdiction=Jurisdiction(str(row["jurisdiction_key"])),
        material_lane=MaterialLane(str(row["lane_key"])),
        subject=str(row["subject"]),
        review_state=str(row["review_state"]),
        source_identity=str(row["source_identity"]),
        content_sha256=content_sha256,
        title=_optional_text(row.get("title")),
        canonical_url=_optional_text(row.get("canonical_url")),
        citation=_optional_text(row.get("citation")),
        metadata={
            "source_version_id": str(row["source_version_id"]),
            "authority_identity_id": str(
                row.get("authority_identity_id") or row.get("source_identity") or ""
            ),
            "canonical_chunk_sha256": canonical_chunk_sha256,
            "canonical_chunk_sha256_binding": canonical_binding,
            "representation_group_id": str(row.get("representation_group_id") or ""),
            "stream": str(row.get("stream") or "body"),
            "locator": str(row["locator"]),
            "catalog_lane": str(row["catalog_lane"]),
            "catalog_jurisdiction": str(row["catalog_jurisdiction"]),
            "citation_data": _json_object(row.get("citation_json", "{}")),
            "canonical_citation": _optional_text(row.get("canonical_citation")),
            "currentness_status": str(row.get("currentness_status") or "unknown"),
            "identity_verified": bool(row.get("identity_verified")),
            "currentness_verified": bool(row.get("currentness_verified")),
            "legal_role": str(row.get("legal_role") or "unclassified"),
            "case_currentness_reviews": [
                review.model_dump(mode="json", by_alias=True)
                for review in _case_proposition_reviews(
                    row.get("case_currentness_reviews_json", "[]")
                )
            ],
            "case_currentness_manifest_seals": list(
                _case_manifest_seals(row.get("case_currentness_manifest_seals_json", "[]"))
            ),
            "retrieval_eligible": bool(row.get("retrieval_eligible", True)),
            "source_date": _optional_text(row.get("source_date")),
            "as_of_date": _optional_text(row.get("as_of_date")),
            "last_updated": _optional_text(row.get("last_updated")),
            "canonical_url": _optional_text(row.get("canonical_url")),
        },
    )


def _embedding_provider(settings: Settings, model_id: str) -> Any:
    if model_id == TEST_EMBEDDING_MODEL:
        if not settings.test_mode:
            raise RuntimeError("deterministic embeddings are forbidden outside LEGALBOT_TEST_MODE")
        return DeterministicHashEmbedding()
    if settings.test_mode:
        raise RuntimeError(
            "test runtime cannot silently substitute embeddings for a production build"
        )
    if model_id != _production_embedding_identity(settings):
        raise RuntimeError("index embedding identity does not match the pinned production model")
    return QwenEmbeddingProvider(
        PINNED_EMBEDDING_REPO,
        PINNED_EMBEDDING_REVISION,
        settings.embedding_model_path,
    )


def _reranker_provider(settings: Settings, model_id: str) -> Reranker:
    if model_id == TEST_RERANKER_MODEL:
        if not settings.test_mode:
            raise RuntimeError("deterministic reranking is forbidden outside LEGALBOT_TEST_MODE")
        return _TestOverlapReranker()
    if settings.test_mode:
        raise RuntimeError(
            "test runtime cannot silently substitute reranking for a production build"
        )
    if model_id != _production_reranker_identity(settings):
        raise RuntimeError("index reranker identity does not match the pinned production model")
    return QwenRerankerProvider(
        PINNED_RERANKER_REPO,
        PINNED_RERANKER_REVISION,
        settings.reranker_model_path,
    )


def _production_embedding_identity(settings: Settings) -> str:
    if settings.embedding_model != PINNED_EMBEDDING_REPO:
        raise RuntimeError("LEGALBOT_EMBEDDING_MODEL cannot override the pinned production repo")
    return (
        f"{PINNED_EMBEDDING_REPO}@{PINNED_EMBEDDING_REVISION}"
        f";dtype={PINNED_EMBEDDING_DTYPE};batch={INDEX_EMBED_BATCH_SIZE}"
    )


def _production_reranker_identity(settings: Settings) -> str:
    if settings.reranker_model != PINNED_RERANKER_REPO:
        raise RuntimeError("LEGALBOT_RERANKER_MODEL cannot override the pinned production repo")
    return f"{PINNED_RERANKER_REPO}@{PINNED_RERANKER_REVISION}"


def _torch_retrieval_device_name() -> str:
    """Device for torch embedder/reranker.

    First-live keeps Metal free for the MLX generation sidecar. Override with
    LEGALBOT_TORCH_DEVICE=cpu|mps|cuda.
    """

    requested = os.getenv("LEGALBOT_TORCH_DEVICE", "").strip().casefold()
    if requested in {"cpu", "mps", "cuda"}:
        return requested
    if os.getenv("LEGALBOT_LIVE_PROFILE", "") == FIRST_LIVE_LOCAL_ONLY_PROFILE:
        return "cpu"
    return ""


def _preferred_torch_device(torch: Any) -> Any:
    name = _torch_retrieval_device_name()
    if name:
        return torch.device(name)
    backends = getattr(torch, "backends", None)
    mps = getattr(backends, "mps", None)
    if mps is not None and mps.is_available():
        return torch.device("mps")
    cuda = getattr(torch, "cuda", None)
    if cuda is not None and cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


def _bounded_search_query(
    query: str,
    filters: QueryFilters,
    *,
    limit: int,
    search_floor: int = LIVE_SEARCH_DEPTH_FLOOR,
) -> SearchQuery:
    search_depth = max(search_floor, limit * 4)
    rerank_limit = max(limit, min(LIVE_RERANK_CANDIDATE_LIMIT, search_depth))
    return SearchQuery(
        query,
        filters,
        limit=limit,
        candidate_limit=search_depth,
        lexical_candidate_limit=search_depth,
        vector_candidate_limit=search_depth,
        rerank_candidate_limit=rerank_limit,
    )


def _safe_rerank_text(value: str) -> str:
    """Prevent retrieved text from closing Qwen chat-template control tokens."""

    return value.replace("<|", "< |").replace("|>", "| >")


def _verified_local_model(
    path: Path,
    repo_id: str,
    revision: str,
    *,
    expected_file_manifest_sha256: str,
) -> Path:
    if not path.is_dir():
        raise RuntimeError(f"pinned local retrieval model is missing or not a directory: {path}")
    provenance_path = path / "retrieval-model.json"
    if not provenance_path.is_file():
        raise RuntimeError(f"local retrieval model lacks verified provenance: {path}")
    provenance = _json_object(provenance_path.read_text(encoding="utf-8"))
    if (
        provenance.get("schema_version") != 1
        or provenance.get("source_repo") != repo_id
        or provenance.get("revision") != revision
    ):
        raise RuntimeError(f"local retrieval model provenance does not match its pin: {path}")
    files = provenance.get("files")
    if not isinstance(files, list) or not files:
        raise RuntimeError(f"local retrieval model provenance has no file manifest: {path}")
    for record in files:
        if not isinstance(record, dict):
            raise RuntimeError(f"local retrieval model file manifest is invalid: {path}")
        filename = record.get("path")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise RuntimeError(
                f"local retrieval model file manifest contains an unsafe path: {path}"
            )
        artifact = path / filename
        try:
            expected_size = int(record["size"])
            expected_sha256 = str(record["sha256"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(f"local retrieval model file manifest is invalid: {path}") from exc
        if (
            not artifact.is_file()
            or artifact.stat().st_size != expected_size
            or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
            or _file_sha256(artifact) != expected_sha256
        ):
            raise RuntimeError(f"local retrieval model file failed verification: {artifact}")
    if _local_model_file_manifest_sha256(path) != expected_file_manifest_sha256:
        raise RuntimeError("local retrieval model differs from the tracked file-manifest digest")
    return path


def _local_model_file_manifest_sha256(path: Path) -> str:
    """Hash every model-consumed file, including nested module configuration."""

    records: list[dict[str, Any]] = []
    for artifact in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
        relative = artifact.relative_to(path)
        if ".cache" in relative.parts or relative.as_posix() == "retrieval-model.json":
            continue
        observed = artifact.lstat()
        if stat.S_ISLNK(observed.st_mode):
            raise RuntimeError("local retrieval model contains a symbolic link")
        if stat.S_ISDIR(observed.st_mode):
            continue
        if not stat.S_ISREG(observed.st_mode):
            raise RuntimeError("local retrieval model contains an unsupported file type")
        records.append(
            {
                "path": relative.as_posix(),
                "size": int(observed.st_size),
                "sha256": _file_sha256(artifact),
            }
        )
    if not records:
        raise RuntimeError("local retrieval model file manifest is empty")
    return hashlib.sha256(
        json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _import_lancedb() -> Any:
    try:
        return importlib.import_module("lancedb")
    except ImportError as exc:
        raise RuntimeError("LanceDB is required; no alternate index backend is permitted") from exc


def _verify_pinned_build(
    settings: Settings,
    database: Database,
    row: Mapping[str, Any],
) -> str:
    """Verify a pinned candidate, or a non-promotable diagnostic slice."""

    if is_diagnostic_slice_build(str(row.get("id") or "")) and str(row.get("status") or "") == (
        "built_unscored"
    ):
        return _verify_diagnostic_slice_for_canary(settings, row)
    return _verify_sealed_build(settings, database, row)


def _verify_diagnostic_slice_for_canary(settings: Settings, row: Mapping[str, Any]) -> str:
    """Full sealed-tree verification without retrieval attestation or promotion."""

    build_id = str(row["id"])
    if not is_diagnostic_slice_build(build_id):
        raise RuntimeError("unscored pin is only permitted for the diagnostic slice")
    build_path = settings.index_dir / "builds" / build_id
    source_path = build_path / "approved-source-manifest.json"
    if not source_path.is_file():
        raise RuntimeError("diagnostic slice lacks the durable sealed-candidate contract")
    return _verify_durable_candidate_tree(settings, row)


def _verify_sealed_build(
    settings: Settings,
    database: Database,
    row: Mapping[str, Any],
) -> str:
    build_id = str(row["id"])
    build_path = settings.index_dir / "builds" / build_id
    if (build_path / "approved-source-manifest.json").is_file():
        return _verify_durable_v1_1_build(settings, database, row)
    expected_path = _relative_path(settings, build_path)
    if str(row["path"]) != expected_path:
        raise RuntimeError("catalogue build path is outside the immutable index root")
    manifest_path = build_path / "manifest.json"
    evaluation_path = build_path / "evaluation.json"
    benchmark_path = build_path / "retrieval-benchmark.json"
    benchmark_report_path = build_path / "retrieval-benchmark-report.json"
    privacy_report_path = build_path / "privacy-report.json"
    lane_manifest_path = build_path / "lance" / "physical-lanes.json"
    seal_path = build_path / "seal.json"
    required_paths = (
        manifest_path,
        evaluation_path,
        benchmark_path,
        benchmark_report_path,
        privacy_report_path,
        lane_manifest_path,
        seal_path,
    )
    if not all(path.is_file() for path in required_paths):
        raise RuntimeError(
            "candidate build is missing a manifest, evaluation, retrieval benchmark or seal"
        )
    seal = _json_object(seal_path.read_text(encoding="utf-8"))
    manifest = _json_object(manifest_path.read_text(encoding="utf-8"))
    evaluation = _json_object(evaluation_path.read_text(encoding="utf-8"))
    benchmark_report = _json_object(benchmark_report_path.read_text(encoding="utf-8"))
    privacy_report = _json_object(privacy_report_path.read_text(encoding="utf-8"))
    if seal.get("schema") != "legalbot.index-seal.v2" or seal.get("build_id") != build_id:
        raise RuntimeError("candidate build seal is invalid")
    if str(row["manifest_sha256"] or "") != _file_sha256(seal_path):
        raise RuntimeError("catalogue seal hash does not match candidate build")
    if seal.get("manifest_sha256") != _file_sha256(manifest_path):
        raise RuntimeError("candidate manifest changed after sealing")
    if (
        manifest.get("schema") != "legalbot.lance-build.v1"
        or manifest.get("build_id") != build_id
        or manifest.get("embedding_model") != row["embedding_model"]
        or manifest.get("reranker_model") != row["reranker_model"]
    ):
        raise RuntimeError("candidate manifest identities are invalid")
    if seal.get("evaluation_sha256") != _file_sha256(evaluation_path):
        raise RuntimeError("candidate evaluation changed after sealing")
    if seal.get("retrieval_benchmark_sha256") != _file_sha256(benchmark_path):
        raise RuntimeError("candidate retrieval benchmark changed after sealing")
    if seal.get("retrieval_benchmark_report_sha256") != _file_sha256(benchmark_report_path):
        raise RuntimeError("candidate retrieval benchmark report changed after sealing")
    if seal.get("privacy_report_sha256") != _file_sha256(privacy_report_path):
        raise RuntimeError("candidate privacy report changed after sealing")
    if (
        privacy_report.get("schema") != "legalbot.privacy-report.v1"
        or privacy_report.get("passed") is not True
    ):
        raise RuntimeError("candidate privacy report did not pass")
    if seal.get("physical_lane_manifest_sha256") != _file_sha256(lane_manifest_path):
        raise RuntimeError("candidate physical lane manifest changed after sealing")
    if seal.get("source_scan_manifest_sha256") != manifest.get("source_scan_manifest_sha256"):
        raise RuntimeError("candidate source scan manifest identity is inconsistent")
    if evaluation.get("schema") != "legalbot.index-evaluation.v2":
        raise RuntimeError("candidate evaluation schema is invalid")
    if evaluation.get("passed") is not True:
        raise RuntimeError("candidate evaluation did not pass")
    integrity = evaluation.get("integrity")
    if not isinstance(integrity, dict):
        raise RuntimeError("candidate integrity report is missing")
    try:
        integrity_chunk_count = int(integrity["chunk_count"])
        integrity_vector_count = int(integrity["vector_count"])
        integrity_dimensions = int(integrity["vector_dimensions"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("candidate integrity metrics are invalid") from exc
    if (
        integrity.get("approved_only") is not True
        or integrity.get("source_snapshot_stable") is not True
        or integrity_chunk_count < 1
        or integrity_chunk_count != integrity_vector_count
        or integrity_dimensions != VECTOR_DIMENSIONS
        or integrity_chunk_count != int(row["chunk_count"])
        or integrity_vector_count != int(row["vector_count"])
        or integrity.get("source_manifest_sha256") != manifest.get("source_manifest_sha256")
        or integrity.get("physical_lane_isolation") is not True
        or integrity.get("scan_reconciled") is not True
        or integrity.get("source_scan_id") != manifest.get("source_scan_id")
        or integrity.get("source_scan_manifest_sha256")
        != manifest.get("source_scan_manifest_sha256")
        or integrity.get("physical_lane_manifest_sha256") != _file_sha256(lane_manifest_path)
    ):
        raise RuntimeError("candidate index integrity promotion gates did not pass")
    if evaluation.get("retrieval_benchmark") != benchmark_report:
        raise RuntimeError("candidate evaluation and retrieval benchmark report disagree")
    if evaluation.get("privacy") != privacy_report:
        raise RuntimeError("candidate evaluation and privacy report disagree")
    benchmark_snapshot = load_retrieval_benchmark(benchmark_path)
    if (
        benchmark_snapshot.sha256 != benchmark_report.get("benchmark_sha256")
        or benchmark_snapshot.benchmark_id != benchmark_report.get("benchmark_id")
        or benchmark_snapshot.version != benchmark_report.get("benchmark_version")
    ):
        raise RuntimeError("candidate retrieval benchmark identity is inconsistent")
    assert_passing_benchmark_report(benchmark_report)
    lance_digest = _tree_sha256(build_path / "lance")
    if integrity.get("lance_tree_sha256") != lance_digest:
        raise RuntimeError("LanceDB generation changed after sealing (integrity report mismatch)")
    if seal.get("lance_tree_sha256") != lance_digest:
        raise RuntimeError("LanceDB generation changed after sealing")
    source_manifest_sha256 = str(manifest.get("source_manifest_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", source_manifest_sha256):
        raise RuntimeError("candidate approved-source manifest identity is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("source_scan_manifest_sha256") or "")):
        raise RuntimeError("candidate source scan manifest identity is invalid")
    return source_manifest_sha256


def _verify_durable_candidate_tree(settings: Settings, row: Mapping[str, Any]) -> str:
    """Verify immutable durable-candidate bytes without accepting a scorer proof."""

    from ..assessment.guidance_bundle import (
        OWNER_ASSESSMENT_BUNDLE,
        canonical_bundle_bytes,
    )
    from ..quality.policy import POLICY_SHA256

    build_id = str(row["id"])
    build_path = settings.index_dir / "builds" / build_id
    paths = {
        "manifest": build_path / "manifest.json",
        "evaluation": build_path / "evaluation.json",
        "privacy": build_path / "privacy-report.json",
        "lane": build_path / "lance/physical-lanes.json",
        "source": build_path / "approved-source-manifest.json",
        "quality_policy": build_path / "quality-policy.yaml",
        "retrieval_policy": build_path / "retrieval-policy.yaml",
        "assessment_guidance": build_path / "assessment-guidance-bundle.json",
        "benchmark": build_path / "retrieval-benchmark-v1.1.jsonl",
        "freeze": build_path / "retrieval-benchmark-v1.1.freeze.json",
        "provision_verification": build_path / "provision-verification.v1.json",
        "seal": build_path / "seal.json",
    }
    if not all(path.is_file() for path in paths.values()):
        raise RuntimeError("durable candidate is missing a sealed build artefact")
    seal = _json_object(paths["seal"].read_text(encoding="utf-8"))
    manifest = _json_object(paths["manifest"].read_text(encoding="utf-8"))
    evaluation = _json_object(paths["evaluation"].read_text(encoding="utf-8"))
    privacy = _json_object(paths["privacy"].read_text(encoding="utf-8"))
    source = _json_object(paths["source"].read_text(encoding="utf-8"))
    if seal.get("schema") != "legalbot.index-seal.v2" or seal.get("build_id") != build_id:
        raise RuntimeError("durable candidate seal is invalid")
    if str(row["manifest_sha256"] or "") != _file_sha256(paths["seal"]):
        raise RuntimeError("catalogue build seal hash mismatch")
    if str(row.get("candidate_manifest_hash") or "") not in {
        "",
        _file_sha256(paths["seal"]),
    }:
        raise RuntimeError("candidate catalogue manifest identity is invalid")
    if (
        manifest.get("schema") != "legalbot.lance-build.v1"
        or manifest.get("build_id") != build_id
        or manifest.get("embedding_model") != row["embedding_model"]
        or manifest.get("reranker_model") != row["reranker_model"]
    ):
        raise RuntimeError("durable candidate model identities are invalid")
    expected_hashes = {
        "manifest_sha256": paths["manifest"],
        "evaluation_sha256": paths["evaluation"],
        "privacy_report_sha256": paths["privacy"],
        "physical_lane_manifest_sha256": paths["lane"],
        "source_manifest_file_sha256": paths["source"],
        "quality_policy_sha256": paths["quality_policy"],
        "retrieval_policy_sha256": paths["retrieval_policy"],
        "assessment_guidance_sha256": paths["assessment_guidance"],
        "retrieval_benchmark_sha256": paths["benchmark"],
        "retrieval_freeze_sha256": paths["freeze"],
        "provision_verification_sha256": paths["provision_verification"],
    }
    for field, path in expected_hashes.items():
        if seal.get(field) != _file_sha256(path):
            raise RuntimeError(f"durable candidate sealed artefact changed: {field}")
    vector_reuse_integrity = (
        evaluation.get("integrity", {}).get("vector_reuse")
        if isinstance(evaluation.get("integrity"), dict)
        else None
    )
    reuse_fields = (
        seal.get("vector_reuse_report_sha256"),
        seal.get("parent_vector_build_id"),
        seal.get("parent_vector_seal_sha256"),
    )
    if any(value is not None for value in reuse_fields):
        if not all(isinstance(value, str) and value for value in reuse_fields):
            raise RuntimeError("candidate vector-reuse seal binding is incomplete")
        report_path = build_path / "vector-reuse-report.json"
        parent_build_id = str(seal["parent_vector_build_id"])
        if (
            not report_path.is_file()
            or _file_sha256(report_path) != seal["vector_reuse_report_sha256"]
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", parent_build_id)
        ):
            raise RuntimeError("candidate vector-reuse report changed after sealing")
        reuse_report = _json_object(report_path.read_text(encoding="utf-8"))
        reuse_seal = str(reuse_report.get("seal_sha256") or "")
        reuse_material = dict(reuse_report)
        reuse_material.pop("seal_sha256", None)
        expected_reuse_seal = hashlib.sha256(
            json.dumps(
                reuse_material,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        parent_seal_path = settings.index_dir / "builds" / parent_build_id / "seal.json"
        if (
            reuse_report.get("schema") != "legalbot.vector-reuse-report.v1"
            or reuse_seal != expected_reuse_seal
            or reuse_report.get("child_build_id") != build_id
            or reuse_report.get("parent_build_id") != parent_build_id
            or reuse_report.get("parent_seal_sha256") != seal["parent_vector_seal_sha256"]
            or not parent_seal_path.is_file()
            or _file_sha256(parent_seal_path) != seal["parent_vector_seal_sha256"]
            or not isinstance(vector_reuse_integrity, dict)
            or vector_reuse_integrity.get("report_sha256") != seal["vector_reuse_report_sha256"]
            or vector_reuse_integrity.get("parent_build_id") != parent_build_id
            or vector_reuse_integrity.get("parent_seal_sha256") != seal["parent_vector_seal_sha256"]
            or int(reuse_report.get("eligible_chunk_count") or 0)
            != int(reuse_report.get("reused_vector_count") or 0)
            + int(reuse_report.get("embedded_vector_count") or 0)
            or reuse_report.get("lexical_rebuild_required") is not True
            or reuse_report.get("active_write_allowed") is not False
        ):
            raise RuntimeError("candidate vector-reuse identities are inconsistent")
    elif vector_reuse_integrity is not None:
        raise RuntimeError("candidate integrity claims unsealed vector reuse")
    if _file_sha256(paths["quality_policy"]) != POLICY_SHA256:
        raise RuntimeError("candidate quality policy differs from current policy")
    if str(row["policy_sha256"] or "") != POLICY_SHA256:
        raise RuntimeError("candidate catalogue policy SHA is missing or stale")
    if paths["assessment_guidance"].read_bytes() != canonical_bundle_bytes(OWNER_ASSESSMENT_BUNDLE):
        raise RuntimeError("candidate assessment-guidance bundle differs from runtime")
    if str(row["assessment_bundle_sha256"] or "") != OWNER_ASSESSMENT_BUNDLE.sha256:
        raise RuntimeError("candidate catalogue assessment bundle SHA is missing or stale")
    if source.get("provision_verification_sha256") != _file_sha256(paths["provision_verification"]):
        raise RuntimeError("candidate provision-verification identity is inconsistent")
    if privacy.get("schema") != "legalbot.privacy-report.v1" or privacy.get("passed") is not True:
        raise RuntimeError("candidate privacy report did not pass")
    integrity = evaluation.get("integrity") if isinstance(evaluation, dict) else None
    if not isinstance(integrity, dict) or evaluation.get("passed") is not True:
        raise RuntimeError("candidate integrity report did not pass")
    if (
        integrity.get("approved_only") is not True
        or integrity.get("authority_lane_only") is not True
        or integrity.get("source_snapshot_stable") is not True
        or integrity.get("physical_lane_isolation") is not True
        or integrity.get("scan_reconciled") is not True
        or int(integrity.get("chunk_count") or 0) != int(row["chunk_count"])
        or int(integrity.get("vector_count") or 0) != int(row["vector_count"])
        or int(integrity.get("vector_dimensions") or 0) != VECTOR_DIMENSIONS
        or integrity.get("source_manifest_sha256") != source.get("manifest_sha256")
        or manifest.get("source_manifest_sha256") != source.get("manifest_sha256")
        or _tree_sha256(build_path / "lance") != seal.get("lance_tree_sha256")
    ):
        raise RuntimeError("durable candidate integrity gates are inconsistent")
    return str(source.get("manifest_sha256") or "")


def _verify_durable_v1_1_build(
    settings: Settings,
    database: Database,
    row: Mapping[str, Any],
) -> str:
    """Verify durable bytes plus the catalogue-selected current-scorer proof."""

    source_manifest_sha256 = _verify_durable_candidate_tree(settings, row)
    from .retrieval_reattest import verify_selected_retrieval_attestation

    verify_selected_retrieval_attestation(settings, database, row, tree_already_verified=True)
    return source_manifest_sha256


def _update_source_manifest_digest(digest: Any, row: Mapping[str, Any]) -> None:
    payload = {
        "chunk_id": str(row["chunk_id"]),
        "document_id": str(row["document_id"]),
        "document_sha256": str(row["document_sha256"]),
        "source_identity_id": str(row["source_identity_id"]),
        "representation_group_id": str(row["representation_group_id"]),
        "retrieval_canonical": int(row["retrieval_canonical"]),
        "document_status": str(row["document_status"]),
        "lane": str(row["lane"]),
        "subject_primary": str(row["subject_primary"] or ""),
        "jurisdiction": str(row["jurisdiction"]),
        "source_version_id": str(row["source_version_id"]),
        "version_sha256": str(row["version_sha256"]),
        "source_last_updated_at": str(row["source_last_updated_at"] or ""),
        "as_of_date": str(row["as_of_date"] or ""),
        "canonical_url": str(row["canonical_url"] or ""),
        "stable_identifier": str(row["stable_identifier"] or ""),
        "currentness_status": str(row["currentness_status"]),
        "source_metadata_json": str(row["source_metadata_json"]),
        "text_sha256": str(row["text_sha256"]),
        "stream": str(row["stream"]),
        "locator": str(row["locator"]),
        "chunk_metadata_json": str(row["chunk_metadata_json"]),
        "review_status": str(row["review_status"]),
    }
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)


def _latest_source_version_hits(
    hits: Sequence[SearchHit],
) -> tuple[tuple[SearchHit, ...], int]:
    """Keep only the newest eligible source version for each authority.

    Relevance ordering is preserved.  Version choice is binary and
    deterministic: legal ``as_of_date`` first, original ``source_date`` next,
    ingestion ``last_updated`` only as a tie-breaker.  The original source date
    is never overwritten by the observation/ingestion timestamp.
    """

    newest: dict[str, tuple[tuple[str, str, str], str]] = {}
    for hit in hits:
        metadata = hit.chunk.metadata
        authority_id = str(metadata.get("authority_identity_id") or "")
        source_version_id = str(metadata.get("source_version_id") or "")
        if not authority_id or not source_version_id:
            continue
        version_key = (
            str(metadata.get("as_of_date") or metadata.get("source_date") or ""),
            str(metadata.get("last_updated") or ""),
            source_version_id,
        )
        prior = newest.get(authority_id)
        if prior is None or version_key > prior[0]:
            newest[authority_id] = (version_key, source_version_id)

    output: list[SearchHit] = []
    removed = 0
    for hit in hits:
        metadata = hit.chunk.metadata
        authority_id = str(metadata.get("authority_identity_id") or "")
        source_version_id = str(metadata.get("source_version_id") or "")
        selected = newest.get(authority_id)
        if selected is not None and source_version_id != selected[1]:
            removed += 1
            continue
        output.append(hit)
    return tuple(output), removed


def _lance_filter(filters: QueryFilters, as_of_date: date) -> str:
    filters.validate()
    jurisdictions = ", ".join(
        f"'{_sql_text(item.value)}'"
        for item in sorted(filters.jurisdictions, key=lambda item: item.value)
    )
    lanes = ", ".join(
        f"'{_sql_text(item.value)}'"
        for item in sorted(filters.material_lanes, key=lambda item: item.value)
    )
    reviews = ", ".join(f"'{_sql_text(item)}'" for item in sorted(filters.review_states))
    clauses = [
        f"jurisdiction_key IN ({jurisdictions})",
        f"lane_key IN ({lanes})",
        f"review_state IN ({reviews})",
        "retrieval_eligible = TRUE",
        f"(as_of_date = '' OR as_of_date <= '{as_of_date.isoformat()}')",
    ]
    if filters.subjects:
        subjects = ", ".join(f"'{_sql_text(item)}'" for item in sorted(filters.subjects))
        clauses.append(f"subject IN ({subjects})")
    if filters.exact_jurisdictions:
        exact_jurisdictions = ", ".join(
            f"'{_sql_text(normalise(item))}'" for item in sorted(filters.exact_jurisdictions)
        )
        clauses.append(f"catalog_jurisdiction_key IN ({exact_jurisdictions})")
    return " AND ".join(clauses)


def _answer_retrieval_eligible(
    *,
    catalog_lane: str,
    citation_data: Mapping[str, Any],
    currentness_status: str,
    source_metadata: Mapping[str, Any],
) -> bool:
    """Fail closed before retrieval for rights and current-law eligibility."""

    if source_metadata.get("ai_use_policy") == "prohibited":
        return False
    if source_metadata.get("eligible_for_model_use") is not True:
        return False
    if catalog_lane not in _LEGAL_CATALOG_LANES:
        return True
    if source_metadata.get("identity_verified") is not True:
        return False
    status = currentness_status.casefold().replace("-", "_")
    if str(citation_data.get("source_type") or "").casefold() == "case":
        # Identity/historical-text queries and retrieval benchmarks must still
        # find a verified official judgment.  The indexed row carries its
        # currentness_verified=false flag; material present-law claims are
        # blocked later by the EvidenceSpan quality gate until treatment is
        # span/proposition scoped.
        return True
    if source_metadata.get("currentness_verified") is not True:
        return False
    return not (
        is_legislation_source(citation_data)
        and status in {"historical", "historical_as_enacted", "as_enacted"}
    )


def _query_jurisdictions(value: str) -> set[Jurisdiction]:
    normalized = normalise(value)
    if normalized == "england and wales":
        return {Jurisdiction.ENGLAND_WALES, Jurisdiction.UNITED_KINGDOM}
    mapping = {
        "united kingdom": Jurisdiction.UNITED_KINGDOM,
        "scotland": Jurisdiction.SCOTLAND,
        "northern ireland": Jurisdiction.NORTHERN_IRELAND,
        "european union": Jurisdiction.EUROPEAN_UNION,
    }
    return {mapping.get(normalized, Jurisdiction.COMPARATIVE)}


def _query_exact_jurisdictions(value: str) -> set[str]:
    normalized = normalise(value)
    if normalized == "england and wales":
        return {"england and wales", "united kingdom"}
    return {normalized}


def _ingestion_jurisdiction(value: str) -> Jurisdiction:
    normalized = normalise(value)
    return {
        "england and wales": Jurisdiction.ENGLAND_WALES,
        "united kingdom": Jurisdiction.UNITED_KINGDOM,
        "scotland": Jurisdiction.SCOTLAND,
        "northern ireland": Jurisdiction.NORTHERN_IRELAND,
        "european union": Jurisdiction.EUROPEAN_UNION,
    }.get(normalized, Jurisdiction.COMPARATIVE)


def _ingestion_lane(value: str) -> MaterialLane:
    return {
        CatalogLane.PRIMARY_AUTHORITY.value: MaterialLane.PRIMARY_AUTHORITY,
        CatalogLane.OFFICIAL_SECONDARY.value: MaterialLane.OFFICIAL_GUIDANCE,
        CatalogLane.SCHOLARSHIP.value: MaterialLane.SECONDARY_SCHOLARSHIP,
        CatalogLane.PRIVATE_TEACHING.value: MaterialLane.LECTURE_NOTE,
        CatalogLane.ASSESSMENT_GUIDANCE.value: MaterialLane.ASSESSMENT_FEEDBACK,
    }[value]


def _physical_lane_for_chunk(chunk: IndexedChunk) -> str:
    if chunk.material_lane in {
        MaterialLane.PRIMARY_AUTHORITY,
        MaterialLane.PROCEDURE_RULE,
        MaterialLane.REGULATOR_RULE,
        MaterialLane.OFFICIAL_GUIDANCE,
        MaterialLane.REFORM_MATERIAL,
        MaterialLane.SECONDARY_SCHOLARSHIP,
        MaterialLane.BOOK_OR_TREATISE,
        MaterialLane.OFFICIAL_METADATA,
    }:
        return PHYSICAL_AUTHORITY_LANE
    if chunk.material_lane in {
        MaterialLane.LECTURE_NOTE,
        MaterialLane.COURSE_INSTRUCTION,
        MaterialLane.GENERAL_INSTRUCTION,
        MaterialLane.PRIVATE_REFERENCE,
    }:
        return PHYSICAL_TEACHING_LANE
    if chunk.material_lane is MaterialLane.ASSESSMENT_FEEDBACK:
        return PHYSICAL_ASSESSMENT_LANE
    raise ValueError(f"material lane has no physical index mapping: {chunk.material_lane}")


def _normalise_subject(value: str | None) -> str:
    return " ".join((value or "general").casefold().replace("_", " ").split())


_SUBJECT_ALIASES: dict[str, frozenset[str]] = {
    "company": frozenset({"company", "company and insolvency"}),
    "employment": frozenset({"employment", "employment and business", "employment and equality"}),
    "employment and equality": frozenset(
        {"employment", "employment and business", "employment and equality"}
    ),
    "eu": frozenset({"eu", "eu and internal market"}),
    "human rights": frozenset(
        {
            "human rights",
            "human rights and constitutional",
            "public and constitutional",
            "constitutional",
        }
    ),
    "human rights and constitutional": frozenset(
        {
            "human rights",
            "human rights and constitutional",
            "public and constitutional",
            "constitutional",
        }
    ),
    "public and constitutional": frozenset(
        {"public and constitutional", "constitutional", "human rights and constitutional"}
    ),
    "public law": frozenset(
        {"public and constitutional", "constitutional", "human rights and constitutional"}
    ),
    "constitutional and administrative": frozenset(
        {"public and constitutional", "constitutional", "human rights and constitutional"}
    ),
    "public procurement and administrative": frozenset({"public and constitutional", "commercial"}),
    "data protection": frozenset({"data protection", "ai and data protection", "biolaw"}),
    "ai and data protection": frozenset({"data protection", "ai and data protection", "biolaw"}),
    "professional negligence": frozenset({"professional negligence", "tort"}),
    "criminal evidence": frozenset({"criminal evidence", "criminal"}),
    "equity and trusts": frozenset({"trusts"}),
    "corporate governance": frozenset({"company", "company and insolvency"}),
    "competition and digital markets": frozenset({"competition"}),
    "medical": frozenset({"medical law"}),
    "data protection and privacy": frozenset(
        {"data protection", "ai and data protection", "biolaw"}
    ),
    "insolvency and corporate transactions": frozenset(
        {"company", "company and insolvency", "commercial"}
    ),
    "construction and commercial": frozenset({"commercial", "contract", "tort"}),
    "banking fraud and restitution": frozenset(
        {"commercial", "financial services", "trusts", "company and insolvency"}
    ),
    "environmental and climate": frozenset(
        {"public and constitutional", "company", "human rights and constitutional"}
    ),
    "legal ethics and artificial intelligence": frozenset(
        {
            "professional negligence",
            "civil litigation",
            "ai and data protection",
            "employment and business",
        }
    ),
    "land trusts family property and insolvency": frozenset(
        {"land", "trusts", "family", "company and insolvency"}
    ),
    "corporate fraud regulation and litigation": frozenset(
        {
            "company",
            "company and insolvency",
            "criminal",
            "employment",
            "civil litigation",
            "financial services",
        }
    ),
    "multi-area artificial intelligence litigation": frozenset(
        {
            "contract",
            "consumer",
            "tort",
            "professional negligence",
            "public and constitutional",
            "employment",
            "ai and data protection",
            "intellectual property",
            "company",
            "company and insolvency",
            "civil litigation",
            "financial services",
        }
    ),
    "mediation and adr": frozenset({"mediation and adr", "international commercial mediation"}),
    "agency and commercial contracts": frozenset({"commercial", "contract"}),
    "defamation": frozenset({"tort", "civil litigation", "human rights and constitutional"}),
    "occupiers liability": frozenset({"tort"}),
    "criminal complicity": frozenset({"criminal"}),
    "residential tenancies and housing": frozenset({"land", "contract"}),
    "commercial insurance": frozenset({"commercial", "contract"}),
    "partnership and llp": frozenset({"company", "company and insolvency", "commercial"}),
    "sale of goods and retention of title": frozenset(
        {"commercial", "contract", "company and insolvency"}
    ),
    "product liability": frozenset({"tort", "consumer", "contract"}),
    "planning and judicial review": frozenset({"public and constitutional", "land"}),
    "immigration asylum and human rights": frozenset(
        {"public and constitutional", "human rights and constitutional"}
    ),
    "legal professional privilege": frozenset({"civil litigation", "company"}),
    "international arbitration": frozenset({"commercial", "contract", "private international law"}),
    "financial services investment mis-selling": frozenset(
        {"financial services", "contract", "tort"}
    ),
    "charity": frozenset({"trusts"}),
    "education": frozenset(
        {"public and constitutional", "contract", "data protection", "employment"}
    ),
    "consumer credit and guarantees": frozenset({"financial services", "contract", "land"}),
    "cybercrime": frozenset({"criminal", "data protection"}),
    "shipping and carriage of goods": frozenset({"commercial", "contract"}),
    "privacy media and confidential information": frozenset(
        {"tort", "data protection", "civil litigation", "human rights and constitutional"}
    ),
    "leasehold and building safety": frozenset({"land", "contract"}),
    "sports law and arbitration": frozenset(
        {"contract", "employment", "public and constitutional", "human rights and constitutional"}
    ),
    "pensions employment and corporate restructuring": frozenset(
        {"pensions", "employment", "company", "company and insolvency"}
    ),
    "cross-border civil litigation": frozenset(
        {"private international law", "civil litigation", "commercial"}
    ),
    "surveillance and national security": frozenset(
        {"public and constitutional", "human rights and constitutional", "criminal evidence"}
    ),
    "tax and professional advice": frozenset(
        {"company", "commercial", "trusts", "employment", "professional negligence"}
    ),
    "energy infrastructure and project finance": frozenset(
        {"commercial", "contract", "public and constitutional", "tort"}
    ),
    "collective redress": frozenset({"civil litigation", "competition"}),
    "crypto exchange collapse": frozenset(
        {
            "commercial",
            "contract",
            "financial services",
            "company and insolvency",
            "trusts",
            "criminal",
            "data protection",
            "civil litigation",
            "private international law",
        }
    ),
}


def _query_subjects(value: str | None) -> frozenset[str]:
    if not value:
        return frozenset()
    normalized = _normalise_subject(value)
    return _SUBJECT_ALIASES.get(normalized, frozenset({normalized}))


def _write_new_json(path: Path, payload: Mapping[str, Any]) -> None:
    data = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _write_new_bytes(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _tree_sha256(root: Path) -> str:
    if not root.is_dir():
        raise RuntimeError("LanceDB generation directory is missing")
    digest = hashlib.sha256()
    files = sorted(
        (path for path in root.rglob("*") if path.is_file()), key=lambda path: path.as_posix()
    )
    if not files:
        raise RuntimeError("LanceDB generation is empty")
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(_file_sha256(path)))
    return digest.hexdigest()


_RUNTIME_CATALOGUE_BINDING_FIELDS = (
    "id",
    "status",
    "path",
    "document_count",
    "chunk_count",
    "vector_count",
    "embedding_model",
    "reranker_model",
    "manifest_sha256",
    "corpus_id",
    "scoped_corpus_id",
    "source_manifest_hash",
    "parser_version",
    "chunker_version",
    "index_schema_version",
    "embedding_model_version",
    "rerank_version",
    "candidate_manifest_hash",
    "policy_sha256",
    "assessment_bundle_sha256",
)


def _runtime_catalogue_binding_sha256(row: Mapping[str, Any]) -> str:
    """Bind every catalogue field consumed by sealed retrieval verification."""

    payload = {field: row.get(field) for field in _RUNTIME_CATALOGUE_BINDING_FIELDS}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _tree_metadata_sha256(root: Path) -> str:
    """Cheap process-local drift sentinel for an already content-verified tree.

    This digest is deliberately not a replacement for ``_tree_sha256``.  A
    full content hash establishes the capability.  Subsequent request
    boundaries compare no-follow inode, size, mode, mtime and ctime metadata;
    ordinary writes, replacements, additions and removals therefore fail
    closed without rereading gigabytes of sealed vectors.
    """

    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise RuntimeError("verified candidate build directory is unavailable") from exc
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise RuntimeError("verified candidate build directory is unsafe")
    paths = [root, *sorted(root.rglob("*"), key=lambda path: path.as_posix())]
    digest = hashlib.sha256()
    for path in paths:
        try:
            observed = path.lstat()
        except OSError as exc:
            raise RuntimeError("verified candidate build changed during metadata scan") from exc
        if stat.S_ISLNK(observed.st_mode):
            raise RuntimeError("verified candidate build contains a symbolic link")
        relative = "." if path == root else path.relative_to(root).as_posix()
        record = (
            relative,
            int(observed.st_dev),
            int(observed.st_ino),
            int(observed.st_mode),
            int(observed.st_size),
            int(observed.st_mtime_ns),
            int(observed.st_ctime_ns),
        )
        encoded = json.dumps(record, separators=(",", ":")).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _increment(counts: dict[str, int], value: str) -> None:
    counts[value] = counts.get(value, 0) + 1


def _json_object(value: Any) -> dict[str, Any]:
    try:
        parsed = json.loads(value) if isinstance(value, str | bytes | bytearray) else value
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return dict(parsed) if isinstance(parsed, dict) else {}


def _json_list(value: Any) -> list[Any]:
    try:
        parsed = json.loads(value) if isinstance(value, str | bytes | bytearray) else value
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return list(parsed) if isinstance(parsed, list) else []


def _case_proposition_reviews(value: Any) -> tuple[CasePropositionReview, ...]:
    """Validate immutable case-review metadata without a permissive fallback."""

    if value is None or value == "":
        return ()
    try:
        parsed = json.loads(value) if isinstance(value, str | bytes | bytearray) else value
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("case proposition review metadata is malformed") from exc
    if not isinstance(parsed, list):
        raise ValueError("case proposition review metadata must be a list")
    reviews = tuple(CasePropositionReview.model_validate(item) for item in parsed)
    seals = [review.seal_sha256 for review in reviews]
    if len(seals) != len(set(seals)):
        raise ValueError("case proposition review metadata contains duplicate seals")
    return reviews


def _case_manifest_seals(value: Any) -> tuple[str, ...]:
    if value is None or value == "":
        return ()
    try:
        parsed = json.loads(value) if isinstance(value, str | bytes | bytearray) else value
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("case currentness manifest seal metadata is malformed") from exc
    if not isinstance(parsed, list) or any(
        not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item) for item in parsed
    ):
        raise ValueError("case currentness manifest seal metadata is invalid")
    if len(parsed) != len(set(parsed)):
        raise ValueError("case currentness manifest seal metadata is duplicated")
    return tuple(parsed)


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _required_sha256(value: Any, *, label: str) -> str:
    digest = str(value)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError(f"{label} SHA-256 must be 64 lowercase hexadecimal characters")
    return digest


def _optional_int(row: Mapping[str, Any], key: str) -> int | None:
    try:
        raw = row[key]
    except (KeyError, IndexError, TypeError):
        getter = getattr(row, "get", None)
        raw = getter(key) if callable(getter) else None
    if raw is None or raw == "":
        return None
    return int(raw)


def _validate_build_id(build_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", build_id):
        raise ValueError("unsafe index build id")


def _relative_path(settings: Settings, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(settings.project_root.resolve()))
    except ValueError:
        return str(path.resolve())


def _safe_failure(exc: Exception) -> str:
    message = " ".join(scrub_pii(str(exc)).split())
    return message[:300] if message else type(exc).__name__


def _sql_text(value: str) -> str:
    return value.replace("'", "''")


def _stable_id(prefix: str, *values: str) -> str:
    digest = hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:40]}"


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+(?:'[a-z0-9]+)?", text.casefold())
