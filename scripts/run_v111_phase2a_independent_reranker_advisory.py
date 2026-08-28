#!/usr/bin/env python3
"""Run independent, advisory-only relevance ranking for the remaining 448 rows.

The pinned Qwen3 reranker is a different model and adapter from the drafting
model.  It scores only deterministic candidate excerpts.  Scores never
qualify an issue, set a release threshold, adopt a proposition, admit a source,
mutate a candidate, or authorize a later phase.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import resource
import stat
import time
import warnings
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_REMAINDER_DIGEST = (
    "a7f7359c3ff12da02ee4056532198d39417459c9e20aac602f64437fb7cf5aa6"
)
EXPECTED_CASES_FILE_SHA256 = (
    "78a738afd920ff840dcedeb0fd3fd5ca81035f499a0630d351d49e7c6cd3777a"
)
PINNED_MODEL_REPO = "Qwen/Qwen3-Reranker-0.6B"
PINNED_MODEL_REVISION = "e61197ed45024b0ed8a2d74b80b4d909f1255473"
PINNED_MODEL_FILE_MANIFEST_SHA256 = (
    "f775cce47e7cbed490693a954aadcf6141cdf5ffa31b3e33f229adc374223e29"
)
EXPECTED_ROW_COUNT = 448
MAX_CANDIDATES = 6
MAX_EXCERPT_CHARS = 650
ADVISORY_BATCH_SIZE = 8
MAX_PEAK_MEMORY_GB = 12.0
OUTPUT_NAME = "INDEPENDENT-RERANKER-ADVISORY-448.json"
PARTIAL_STOP_NAME = "PARTIAL-COMPARISON-STOP.json"
REVIEWER_EXECUTION_MODE = (
    "independent_pinned_reranker_model_separate_from_drafting_adapter"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ROW_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}:issue-[0-9]{2}$")
_WORD = re.compile(r"[A-Za-z][A-Za-z'-]{3,}")
_SAFE_REASON = re.compile(r"^[a-z0-9][a-z0-9_]{0,127}$")
_ZERO_VECTOR = (0.0,) * 1024
_STOP_WORDS = frozenset(
    {
        "about",
        "after",
        "against",
        "being",
        "between",
        "could",
        "during",
        "from",
        "have",
        "into",
        "legal",
        "might",
        "must",
        "question",
        "should",
        "their",
        "there",
        "these",
        "they",
        "this",
        "under",
        "what",
        "when",
        "where",
        "which",
        "with",
        "would",
    }
)

ScoreRow = Callable[
    [str, Sequence[Mapping[str, Any]]],
    tuple[Sequence[float], Mapping[str, Any]],
]


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_independent_advisory_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_independent_advisory_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _load_cases(path: Path) -> dict[str, dict[str, Any]]:
    if _sha256_file(path) != EXPECTED_CASES_FILE_SHA256:
        raise ValueError("phase2a_independent_advisory_cases_identity_invalid")
    cases: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError("phase2a_independent_advisory_case_invalid")
        case_id = str(record.get("case_id") or "")
        if not case_id or case_id in cases or not str(record.get("question") or "").strip():
            raise ValueError("phase2a_independent_advisory_case_registry_invalid")
        cases[case_id] = record
    if len(cases) != 60:
        raise ValueError("phase2a_independent_advisory_case_count_invalid")
    return cases


def _salient_excerpt(text: str, *, issue_label: str, question: str) -> tuple[str, bool]:
    clean = " ".join(text.split())
    if len(clean) <= MAX_EXCERPT_CHARS:
        return clean, False
    needles: list[str] = []
    seen: set[str] = set()
    for token in _WORD.findall(f"{issue_label} {question}"):
        lowered = token.casefold()
        if lowered in _STOP_WORDS or lowered in seen:
            continue
        seen.add(lowered)
        needles.append(lowered)
        if len(needles) == 10:
            break
    lowered_text = clean.casefold()
    positions = [lowered_text.find(needle) for needle in needles]
    positions = sorted({position for position in positions if position >= 0})
    marker = " [EXCERPT OMITTED; FULL SPAN HASH IS BINDING] "
    windows: list[str] = []
    for position in positions[:2]:
        start = max(0, position - 90)
        end = min(len(clean), position + 210)
        window = clean[start:end].strip()
        if window and not any(window in prior or prior in window for prior in windows):
            windows.append(window)
    if not windows:
        windows = [clean[:400].rstrip(), clean[-150:].lstrip()]
    excerpt = marker.join(windows)
    if len(excerpt) > MAX_EXCERPT_CHARS:
        excerpt = excerpt[: MAX_EXCERPT_CHARS - len(marker) - 120].rstrip()
        excerpt = f"{excerpt}{marker}{clean[-120:].lstrip()}"
    return excerpt, True


def _validate_row(row: Mapping[str, Any]) -> None:
    material = dict(row)
    supplied = str(material.pop("row_packet_content_sha256", ""))
    if supplied != _sealed(material):
        raise ValueError("phase2a_independent_advisory_row_seal_invalid")
    row_id = str(row.get("row_id") or "")
    candidates = row.get("candidates")
    if not _ROW_ID.fullmatch(row_id) or not isinstance(candidates, list) or not candidates:
        raise ValueError("phase2a_independent_advisory_row_boundary_invalid")
    ranks: list[int] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("phase2a_independent_advisory_candidate_invalid")
        candidate_material = dict(candidate)
        candidate_seal = str(
            candidate_material.pop("candidate_record_content_sha256", "")
        )
        rank = candidate.get("rank")
        if (
            candidate_seal != _sealed(candidate_material)
            or isinstance(rank, bool)
            or not isinstance(rank, int)
            or rank < 1
            or not str(candidate.get("candidate_span_text") or "").strip()
            or not _SHA256.fullmatch(str(candidate.get("span_bundle_sha256") or ""))
        ):
            raise ValueError("phase2a_independent_advisory_candidate_boundary_invalid")
        ranks.append(rank)
    if len(ranks) != len(set(ranks)) or ranks != sorted(ranks):
        raise ValueError("phase2a_independent_advisory_candidate_ranks_invalid")


def _row_projection(
    row: Mapping[str, Any], case: Mapping[str, Any]
) -> tuple[str, list[dict[str, Any]], list[int]]:
    issue_label = str(row.get("issue_label") or "")
    question = str(case.get("question") or "")
    query = f"Scenario: {question}\nIssue requiring evidence: {issue_label}"
    candidates: list[dict[str, Any]] = []
    raw_candidates = row["candidates"]
    for candidate in raw_candidates[:MAX_CANDIDATES]:
        text = str(candidate.get("candidate_span_text") or "")
        excerpt, truncated = _salient_excerpt(
            text,
            issue_label=issue_label,
            question=question,
        )
        candidates.append(
            {
                "rank": candidate["rank"],
                "source_version_id": candidate.get("source_version_id"),
                "authority_identity_id": candidate.get("authority_identity_id"),
                "title": candidate.get("title"),
                "canonical_citation": candidate.get("canonical_citation"),
                "locator": candidate.get("locator"),
                "span_bundle_sha256": candidate.get("span_bundle_sha256"),
                "candidate_record_content_sha256": candidate.get(
                    "candidate_record_content_sha256"
                ),
                "identity_verified": candidate.get("identity_verified"),
                "currentness_verified": candidate.get("currentness_verified"),
                "later_treatment_review_required": candidate.get(
                    "later_treatment_review_required"
                ),
                "already_in_sealed_candidate": candidate.get(
                    "already_in_sealed_candidate"
                ),
                "lexical_tfidf_score": candidate.get("lexical_tfidf_score"),
                "full_span_text_sha256": _sha256((text + "\n").encode()),
                "full_span_character_count": len(text),
                "excerpt": excerpt,
                "excerpt_sha256": _sha256((excerpt + "\n").encode()),
                "excerpt_character_count": len(excerpt),
                "excerpt_truncated": truncated,
            }
        )
    omitted = [
        int(candidate["rank"])
        for candidate in raw_candidates[MAX_CANDIDATES:]
        if isinstance(candidate, dict) and isinstance(candidate.get("rank"), int)
    ]
    return query, candidates, omitted


def _peak_rss_gb() -> float:
    value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if platform.system() != "Darwin":
        value *= 1024.0
    return value / 1_000_000_000


def _real_scorer(model_path: Path) -> tuple[ScoreRow, dict[str, Any]]:
    import app.retrieval.service as retrieval_service
    from app.ingestion.models import Jurisdiction, MaterialLane
    from app.retrieval.models import IndexedChunk, SearchHit

    retrieval_service.RERANK_BATCH_SIZE = ADVISORY_BATCH_SIZE
    provider = retrieval_service.QwenRerankerProvider(
        retrieval_service.PINNED_RERANKER_REPO,
        retrieval_service.PINNED_RERANKER_REVISION,
        model_path,
    )
    runtime = provider._load()
    model_class = type(runtime.model).__name__
    if (
        "ForCausalLM" not in model_class
        or "SequenceClassification" in model_class
        or getattr(runtime.model, "score", None) is not None
    ):
        raise RuntimeError("phase2a_independent_advisory_unsafe_model_class")

    def score_row(
        query: str, candidates: Sequence[Mapping[str, Any]]
    ) -> tuple[Sequence[float], Mapping[str, Any]]:
        hits = []
        projection_ids: dict[str, int] = {}
        for candidate in candidates:
            rank = int(candidate["rank"])
            projection_id = f"advisory-{rank}-{str(candidate['excerpt_sha256'])[:24]}"
            projection_ids[projection_id] = rank
            hits.append(
                SearchHit(
                    chunk=IndexedChunk(
                        chunk_id=projection_id,
                        text=str(candidate["excerpt"]),
                        vector=_ZERO_VECTOR,
                        jurisdiction=Jurisdiction.ENGLAND_WALES,
                        material_lane=MaterialLane.PRIMARY_AUTHORITY,
                        subject="phase2a_advisory",
                        review_state="approved_for_advisory_projection_only",
                        source_identity=str(candidate.get("source_version_id") or ""),
                        content_sha256=str(candidate["excerpt_sha256"]),
                        title=str(candidate.get("title") or ""),
                        citation=str(candidate.get("canonical_citation") or ""),
                        metadata={"locator": candidate.get("locator")},
                    ),
                    score=float(candidate.get("lexical_tfidf_score") or 0.0),
                )
            )
        started = time.perf_counter()
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            ranked = provider.rerank(query, hits, limit=len(hits))
        warning_text = "\n".join(str(item.message) for item in captured)
        if any(
            marker in warning_text.casefold()
            for marker in ("newly initialized", "score.weight", "sequenceclassification")
        ):
            raise RuntimeError("phase2a_independent_advisory_unsafe_model_warning")
        by_rank = {
            projection_ids[hit.chunk.chunk_id]: float(hit.rerank_score)
            for hit in ranked
            if hit.rerank_score is not None
        }
        runtime = provider._load()
        mps_driver_gb: float | None = None
        if str(runtime.device).startswith("mps"):
            mps_driver_gb = float(runtime.torch.mps.driver_allocated_memory()) / 1e9
        observed_peak = max(_peak_rss_gb(), mps_driver_gb or 0.0)
        if observed_peak > MAX_PEAK_MEMORY_GB:
            raise RuntimeError("phase2a_independent_advisory_peak_memory_exceeded")
        scores = [by_rank[int(candidate["rank"])] for candidate in candidates]
        return scores, {
            **provider.last_rerank_stats,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "process_peak_rss_gb": round(_peak_rss_gb(), 6),
            "mps_driver_allocated_gb": (
                round(mps_driver_gb, 6) if mps_driver_gb is not None else None
            ),
            "observed_peak_memory_gb": round(observed_peak, 6),
            "unsafe_model_warning": False,
        }

    runtime_identity = {
        "model_repo": PINNED_MODEL_REPO,
        "model_revision": PINNED_MODEL_REVISION,
        "model_file_manifest_sha256": PINNED_MODEL_FILE_MANIFEST_SHA256,
        "adapter": "Qwen3 causal-LM yes/no likelihood reranker",
        "model_class": model_class,
        "device": str(runtime.device),
        "false_token_id": runtime.false_token_id,
        "true_token_id": runtime.true_token_id,
        "classifier_head_present": False,
        "adapter_file_sha256": _sha256_file(
            PROJECT_ROOT / "backend" / "app" / "retrieval" / "service.py"
        ),
        "ranking_representation_file_sha256": _sha256_file(
            PROJECT_ROOT / "backend" / "app" / "retrieval" / "ranking_text.py"
        ),
        "generative_model_used": False,
        "model_independent_from_drafting_adapter": True,
        "advisory_batch_size": ADVISORY_BATCH_SIZE,
        "maximum_projected_candidates_per_row": MAX_CANDIDATES,
        "maximum_excerpt_characters": MAX_EXCERPT_CHARS,
        "qualification_threshold": None,
    }
    return score_row, runtime_identity


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, RuntimeError | ValueError) and exc.args:
        value = str(exc.args[0]).casefold().replace("-", "_")
        if _SAFE_REASON.fullmatch(value):
            return value
    value = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    return value if _SAFE_REASON.fullmatch(value) else "phase2a_independent_advisory_unknown_failure"


def _checkpoint_name(ordinal: int, row_id: str) -> str:
    opaque = _sha256((row_id + "\n").encode())[:24]
    return f"{ordinal:04d}-{opaque}.json"


def _recommendation(candidate: Mapping[str, Any]) -> str:
    if candidate.get("later_treatment_review_required") is True:
        return "OWNER_INSPECT_TOP_CASE_SPANS_AFTER_LATER_TREATMENT_REVIEW"
    if (
        candidate.get("identity_verified") is not True
        or candidate.get("currentness_verified") is not True
    ):
        return "OWNER_VERIFY_TOP_CANDIDATE_VERSION_BEFORE_BINDING"
    return "OWNER_INSPECT_TOP_RERANKED_SPANS"


def _review_one(
    *,
    ordinal: int,
    row: Mapping[str, Any],
    case: Mapping[str, Any],
    scorer: ScoreRow,
    runtime_identity_sha256: str,
    checkpoints_root: Path,
    diagnostics_root: Path,
) -> dict[str, Any]:
    query, candidates, omitted = _row_projection(row, case)
    input_material = {
        "schema": "legalbot.phase2a.independent-reranker-input.v1",
        "row_id": row["row_id"],
        "source_row_packet_content_sha256": row["row_packet_content_sha256"],
        "question_sha256": case["question_sha256"],
        "query_sha256": _sha256((query + "\n").encode()),
        "candidates": candidates,
        "omitted_candidate_ranks": omitted,
        "full_span_hash_is_binding": True,
        "excerpt_truncation_is_explicit": True,
    }
    input_sha256 = _sealed(input_material)
    fingerprints: list[str] = []
    for attempt in (1, 2):
        started = time.perf_counter()
        try:
            raw_scores, metrics = scorer(query, candidates)
            scores = list(raw_scores)
            if (
                len(scores) != len(candidates)
                or any(
                    isinstance(score, bool)
                    or not isinstance(score, int | float)
                    or not math.isfinite(float(score))
                    or not 0.0 <= float(score) <= 1.0
                    for score in scores
                )
            ):
                raise ValueError("phase2a_independent_advisory_scores_invalid")
            if not isinstance(metrics, Mapping):
                raise ValueError("phase2a_independent_advisory_metrics_invalid")
        except Exception as exc:
            error = _error_code(exc)
            fingerprint = _sealed(
                {
                    "schema": "legalbot.phase2a.independent-advisory-fingerprint.v1",
                    "row_id": row["row_id"],
                    "input_content_sha256": input_sha256,
                    "runtime_identity_sha256": runtime_identity_sha256,
                    "error_code": error,
                }
            )
            fingerprints.append(fingerprint)
            diagnostic_material = {
                "schema": "legalbot.phase2a.independent-advisory-rejected-attempt.v1",
                "ordinal": ordinal,
                "row_id": row["row_id"],
                "attempt": attempt,
                "input_content_sha256": input_sha256,
                "error_code": error,
                "failure_fingerprint": fingerprint,
                "same_failure_fingerprint_as_prior_attempt": (
                    len(fingerprints) == 2 and fingerprints[0] == fingerprints[1]
                ),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "owner_decision_assigned": False,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            diagnostic = {
                **diagnostic_material,
                "diagnostic_content_sha256": _sealed(diagnostic_material),
            }
            _write_exclusive(
                diagnostics_root
                / f"{_checkpoint_name(ordinal, str(row['row_id']))[:-5]}-a{attempt}.json",
                _pretty_json(diagnostic),
            )
            if attempt == 1:
                continue
            held_material = {
                "schema": "legalbot.phase2a.independent-advisory-held-row.v1",
                "ordinal": ordinal,
                "row_id": row["row_id"],
                "source_row_packet_content_sha256": row["row_packet_content_sha256"],
                "input_content_sha256": input_sha256,
                "status": "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT",
                "attempt_count": 2,
                "failure_fingerprints": fingerprints,
                "same_failure_fingerprint_twice": fingerprints[0] == fingerprints[1],
                "debug_required_before_third_attempt": True,
                "owner_decision_required": True,
                "owner_decision_assigned": False,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            held = {**held_material, "held_content_sha256": _sealed(held_material)}
            _write_exclusive(
                checkpoints_root / _checkpoint_name(ordinal, str(row["row_id"])),
                _pretty_json(held),
            )
            return held
        ranked = sorted(
            (
                {**candidate, "reranker_score": round(float(score), 10)}
                for candidate, score in zip(candidates, scores, strict=True)
            ),
            key=lambda candidate: (-candidate["reranker_score"], candidate["rank"]),
        )
        ranked = [
            {**candidate, "model_rank": model_rank}
            for model_rank, candidate in enumerate(ranked, start=1)
        ]
        recommendation = _recommendation(ranked[0])
        checkpoint_material = {
            "schema": "legalbot.phase2a.independent-reranker-checkpoint.v1",
            "ordinal": ordinal,
            "row_id": row["row_id"],
            "source_row_packet_content_sha256": row["row_packet_content_sha256"],
            "input_content_sha256": input_sha256,
            "runtime_identity_sha256": runtime_identity_sha256,
            "attempt_count": attempt,
            "advisory_recommendation": recommendation,
            "ranked_candidates": ranked,
            "omitted_candidate_ranks": omitted,
            "model_metrics": dict(metrics),
            "score_threshold_applied": False,
            "qualification_threshold": None,
            "candidate_relevance_qualified": False,
            "model_independent_reviewer": True,
            "generative_model_used": False,
            "hidden_reasoning_persisted": False,
            "owner_decision_required": True,
            "owner_decision_assigned": False,
            "technical_qualification_assigned": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        checkpoint = {
            **checkpoint_material,
            "checkpoint_content_sha256": _sealed(checkpoint_material),
        }
        _write_exclusive(
            checkpoints_root / _checkpoint_name(ordinal, str(row["row_id"])),
            _pretty_json(checkpoint),
        )
        return checkpoint
    raise AssertionError("unreachable independent advisory attempt loop")


def _load_checkpoint(path: Path) -> dict[str, Any]:
    value = _load_object(path)
    schema = value.get("schema")
    if schema == "legalbot.phase2a.independent-reranker-checkpoint.v1":
        _verify_seal(
            value,
            "checkpoint_content_sha256",
            "phase2a_independent_advisory_checkpoint_seal_invalid",
        )
    elif schema == "legalbot.phase2a.independent-advisory-held-row.v1":
        _verify_seal(
            value,
            "held_content_sha256",
            "phase2a_independent_advisory_held_seal_invalid",
        )
    else:
        raise ValueError("phase2a_independent_advisory_checkpoint_schema_invalid")
    return value


def seal_partial_same_adapter_run(partial_root: Path, *, successor_run: str) -> dict[str, Any]:
    """Seal an interrupted same-adapter run as non-final comparison evidence."""

    target = partial_root / PARTIAL_STOP_NAME
    if target.exists():
        existing = _load_object(target)
        _verify_seal(
            existing,
            "partial_stop_content_sha256",
            "phase2a_partial_stop_seal_invalid",
        )
        return existing
    if partial_root.is_symlink() or not partial_root.is_dir():
        raise ValueError("phase2a_partial_comparison_root_invalid")
    intent = _load_object(partial_root / "INTENT.json")
    intent_digest = _verify_seal(
        intent,
        "intent_content_sha256",
        "phase2a_partial_comparison_intent_seal_invalid",
    )
    if intent.get("model_independent_reviewer") is not False:
        raise ValueError("phase2a_partial_comparison_not_same_adapter")
    entries: list[dict[str, Any]] = []
    ordinals: list[int] = []
    held_count = 0
    for path in sorted((partial_root / "checkpoints").glob("*.json")):
        value = _load_object(path)
        schema = value.get("schema")
        if schema == "legalbot.phase2a.owner-advisory-row-checkpoint.v3":
            content_digest = _verify_seal(
                value,
                "checkpoint_content_sha256",
                "phase2a_partial_comparison_checkpoint_seal_invalid",
            )
        elif schema == "legalbot.phase2a.owner-advisory-held-row.v1":
            content_digest = _verify_seal(
                value,
                "held_content_sha256",
                "phase2a_partial_comparison_held_seal_invalid",
            )
            held_count += 1
        else:
            raise ValueError("phase2a_partial_comparison_checkpoint_schema_invalid")
        ordinal = value.get("ordinal")
        if isinstance(ordinal, bool) or not isinstance(ordinal, int):
            raise ValueError("phase2a_partial_comparison_ordinal_invalid")
        ordinals.append(ordinal)
        entries.append(
            {
                "relative_path": f"checkpoints/{path.name}",
                "file_sha256": _sha256_file(path),
                "content_sha256": content_digest,
            }
        )
    diagnostics = []
    for path in sorted((partial_root / "diagnostics").glob("*.json")):
        value = _load_object(path)
        content_digest = _verify_seal(
            value,
            "diagnostic_content_sha256",
            "phase2a_partial_comparison_diagnostic_seal_invalid",
        )
        diagnostics.append(
            {
                "relative_path": f"diagnostics/{path.name}",
                "file_sha256": _sha256_file(path),
                "content_sha256": content_digest,
            }
        )
    if not entries or ordinals != list(range(1, len(ordinals) + 1)):
        raise ValueError("phase2a_partial_comparison_checkpoint_sequence_invalid")
    if (partial_root / "OWNER-ADVISORY-REVIEW-448.json").exists():
        raise ValueError("phase2a_partial_comparison_already_finalized")
    material = {
        "schema": "legalbot.phase2a.same-adapter-partial-comparison-stop.v1",
        "status": "PARTIAL_COMPARISON_SUPERSEDED_NOT_A_COMPLETE_ADVISORY_REVIEW",
        "source_intent_content_sha256": intent_digest,
        "completed_checkpoint_count": len(entries),
        "highest_completed_ordinal": max(ordinals),
        "held_checkpoint_count": held_count,
        "diagnostic_count": len(diagnostics),
        "checkpoint_custody_digest": _sealed(entries),
        "diagnostic_custody_digest": _sealed(diagnostics),
        "successor_run": successor_run,
        "reason": (
            "Replace same-drafting-adapter semantic review with the pinned independent "
            "Qwen3 reranker; preserve completed rows as comparison evidence only."
        ),
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "partial_stop_content_sha256": _sealed(material)}
    _write_exclusive(target, _pretty_json(artifact))
    return artifact


def run_review(
    *,
    remainder_path: Path,
    cases_path: Path,
    output_root: Path,
    scorer: ScoreRow,
    runtime_identity: Mapping[str, Any],
    started_at: datetime,
    resume: bool = False,
) -> dict[str, Any]:
    """Run or resume the complete 448-row independent advisory pass."""

    if started_at.tzinfo is None:
        raise ValueError("phase2a_independent_advisory_started_at_naive")
    remainder = _load_object(remainder_path)
    remainder_digest = _verify_seal(
        remainder,
        "artifact_content_sha256",
        "phase2a_independent_advisory_remainder_seal_invalid",
    )
    rows = remainder.get("rows")
    if (
        remainder_digest != EXPECTED_REMAINDER_DIGEST
        or remainder.get("row_count") != EXPECTED_ROW_COUNT
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_ROW_COUNT
        or remainder.get("technical_qualification_assigned") is not False
        or remainder.get("automatic_source_admission") is not False
        or remainder.get("candidate_mutated") is not False
        or remainder.get("phase2b_authorized") is not False
        or remainder.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_independent_advisory_remainder_boundary_invalid")
    cases = _load_cases(cases_path)
    runtime_identity_sha256 = _sealed(runtime_identity)
    intent_path = output_root / "INTENT.json"
    if output_root.exists() or output_root.is_symlink():
        if not resume or output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("phase2a_independent_advisory_output_already_exists")
        intent = _load_object(intent_path)
        _verify_seal(
            intent,
            "intent_content_sha256",
            "phase2a_independent_advisory_intent_seal_invalid",
        )
        if (
            intent.get("source_remainder_content_sha256") != remainder_digest
            or intent.get("source_cases_file_sha256") != EXPECTED_CASES_FILE_SHA256
            or intent.get("runtime_identity_sha256") != runtime_identity_sha256
        ):
            raise ValueError("phase2a_independent_advisory_resume_identity_mismatch")
    else:
        output_root.mkdir(parents=True, mode=0o700)
        if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
            raise ValueError("phase2a_independent_advisory_output_mode_invalid")
        intent_material = {
            "schema": "legalbot.phase2a.independent-reranker-intent.v1",
            "status": "ADVISORY_RELEVANCE_RANKING_ONLY_NO_OWNER_DECISIONS",
            "started_at": started_at.astimezone(UTC).isoformat(timespec="seconds"),
            "source_remainder_content_sha256": remainder_digest,
            "source_remainder_file_sha256": _sha256_file(remainder_path),
            "source_cases_file_sha256": EXPECTED_CASES_FILE_SHA256,
            "runtime_identity": dict(runtime_identity),
            "runtime_identity_sha256": runtime_identity_sha256,
            "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
            "model_independent_reviewer": True,
            "row_count": EXPECTED_ROW_COUNT,
            "maximum_attempts_per_row": 2,
            "debug_required_before_any_third_attempt": True,
            "score_threshold_applied": False,
            "qualification_threshold": None,
            "owner_decisions_applied": False,
            "technical_qualification_assigned": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        intent = {**intent_material, "intent_content_sha256": _sealed(intent_material)}
        _write_exclusive(intent_path, _pretty_json(intent))
    checkpoints_root = output_root / "checkpoints"
    diagnostics_root = output_root / "diagnostics"
    checkpoints_root.mkdir(mode=0o700, exist_ok=True)
    diagnostics_root.mkdir(mode=0o700, exist_ok=True)
    if (output_root / OUTPUT_NAME).exists():
        raise ValueError("phase2a_independent_advisory_already_finalized")

    results: list[dict[str, Any]] = []
    for ordinal, raw in enumerate(rows, start=1):
        if not isinstance(raw, dict):
            raise ValueError("phase2a_independent_advisory_row_invalid")
        _validate_row(raw)
        row_id = str(raw["row_id"])
        checkpoint_path = checkpoints_root / _checkpoint_name(ordinal, row_id)
        if checkpoint_path.exists():
            checkpoint = _load_checkpoint(checkpoint_path)
            if (
                checkpoint.get("ordinal") != ordinal
                or checkpoint.get("row_id") != row_id
                or checkpoint.get("source_row_packet_content_sha256")
                != raw.get("row_packet_content_sha256")
            ):
                raise ValueError("phase2a_independent_advisory_checkpoint_binding_invalid")
            results.append(checkpoint)
            continue
        case = cases.get(str(raw.get("case_id") or ""))
        if case is None:
            raise ValueError("phase2a_independent_advisory_case_missing")
        results.append(
            _review_one(
                ordinal=ordinal,
                row=raw,
                case=case,
                scorer=scorer,
                runtime_identity_sha256=runtime_identity_sha256,
                checkpoints_root=checkpoints_root,
                diagnostics_root=diagnostics_root,
            )
        )

    held = [
        result
        for result in results
        if result.get("schema") == "legalbot.phase2a.independent-advisory-held-row.v1"
    ]
    passed = [result for result in results if result not in held]
    recommendation_counts = Counter(
        str(result["advisory_recommendation"]) for result in passed
    )
    final_rows = []
    for result in results:
        if result in held:
            final_rows.append(
                {
                    "ordinal": result["ordinal"],
                    "row_id": result["row_id"],
                    "status": result["status"],
                    "held_content_sha256": result["held_content_sha256"],
                    "owner_decision_required": True,
                }
            )
        else:
            final_rows.append(
                {
                    "ordinal": result["ordinal"],
                    "row_id": result["row_id"],
                    "status": "INDEPENDENT_ADVISORY_RANKING_READY_OWNER_DECISION_REQUIRED",
                    "recommendation": result["advisory_recommendation"],
                    "ranked_candidates": result["ranked_candidates"],
                    "omitted_candidate_ranks": result["omitted_candidate_ranks"],
                    "model_metrics": result["model_metrics"],
                    "checkpoint_content_sha256": result[
                        "checkpoint_content_sha256"
                    ],
                    "score_threshold_applied": False,
                    "candidate_relevance_qualified": False,
                    "owner_decision_required": True,
                }
            )
    final_material = {
        "schema": "legalbot.phase2a.independent-reranker-advisory-448.v1",
        "status": (
            "INDEPENDENT_ADVISORY_COMPLETE_OWNER_DECISIONS_REQUIRED"
            if not held
            else "INDEPENDENT_ADVISORY_COMPLETE_WITH_HELD_ROWS_DEBUG_REQUIRED"
        ),
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_remainder_content_sha256": remainder_digest,
        "runtime_identity_sha256": runtime_identity_sha256,
        "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
        "model_independent_reviewer": True,
        "generative_model_used": False,
        "row_count": len(results),
        "advisory_ranking_count": len(passed),
        "held_for_debug_count": len(held),
        "recommendation_counts": dict(sorted(recommendation_counts.items())),
        "rows": final_rows,
        "score_threshold_applied": False,
        "qualification_threshold": None,
        "scores_are_advisory_not_qualification": True,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    final = {**final_material, "artifact_content_sha256": _sealed(final_material)}
    _write_exclusive(output_root / OUTPUT_NAME, _pretty_json(final))
    outcome = (
        "PHASE 2A INDEPENDENT ADVISORY RANKING COMPLETE — OWNER DECISIONS REQUIRED; NO PHASE 2B\n"
        if not held
        else "PHASE 2A INDEPENDENT ADVISORY HELD ROWS REQUIRE DEBUG — NO PHASE 2B\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    files = sorted(
        path
        for path in output_root.iterdir()
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in files).encode(),
    )
    return {
        "output_root": str(output_root),
        "artifact_content_sha256": final["artifact_content_sha256"],
        "row_count": len(results),
        "advisory_ranking_count": len(passed),
        "held_for_debug_count": len(held),
        "recommendation_counts": final["recommendation_counts"],
        "model_independent_reviewer": True,
        "owner_decisions_applied": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--remainder", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--partial-comparison-root", type=Path)
    args = parser.parse_args()
    output_root = args.output_root.resolve()
    if args.partial_comparison_root is not None:
        seal_partial_same_adapter_run(
            args.partial_comparison_root.resolve(strict=True),
            successor_run=output_root.name,
        )
    scorer, identity = _real_scorer(args.model_path.resolve(strict=True))
    result = run_review(
        remainder_path=args.remainder.resolve(strict=True),
        cases_path=args.cases.resolve(strict=True),
        output_root=output_root,
        scorer=scorer,
        runtime_identity=identity,
        started_at=datetime.now(UTC),
        resume=bool(args.resume),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
