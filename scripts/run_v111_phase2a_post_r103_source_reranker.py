#!/usr/bin/env python3
"""Independently rerank the sealed r104b official-source review packets.

The pinned Qwen3 reranker is separate from the drafting adapter.  It ranks
full-hash-bound excerpts only.  It does not decide legal support, admit a
source, change gold, qualify an issue, mutate a candidate, or authorize a
later phase.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from scripts.run_v111_phase2a_independent_reranker_advisory import (  # noqa: E402
    PINNED_MODEL_FILE_MANIFEST_SHA256,
    PINNED_MODEL_REPO,
    PINNED_MODEL_REVISION,
    _real_scorer,
    _salient_excerpt,
)

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
SOURCE_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r104b-context-aware-source-review-packets"
    / "DETERMINISTIC-SOURCE-REVIEW-PACKETS-26.json"
)
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r105-independent-source-reranker"
)
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models/retrieval/Qwen3-Reranker-0.6B"
EXPECTED_SOURCE_CONTENT_SHA256 = (
    "5fc1c6d1f8eebb1d7624abf3ca3249451f3e66873ae8826471a51fb11303318f"
)
EXPECTED_SOURCE_FILE_SHA256 = (
    "a33a918d4f2e38573ad25f08e2f66490cf87a5c68ef21b0e26dde989c938fff2"
)
EXPECTED_ROW_COUNT = 26
EXPECTED_UNIQUE_ROW_COUNT = 22
MAX_PROJECTED_CANDIDATES = 40
TOP_CANDIDATE_COUNT = 8
OUTPUT_NAME = "INDEPENDENT-SOURCE-RERANKER-26.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9_]{0,127}$")
_BOUNDARY_FIELDS = (
    "owner_decisions_applied",
    "source_admission_authorized",
    "automatic_indexing",
    "automatic_embedding",
    "candidate_mutated",
    "technical_qualification_assigned",
    "phase2b_authorized",
    "development30_authorized",
)

ScoreRow = Callable[
    [str, Sequence[Mapping[str, Any]]],
    tuple[Sequence[float], Mapping[str, Any]],
]


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
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
        raise ValueError("phase2a_r105_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r105_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _load_source(path: Path) -> dict[str, Any]:
    if _sha256_file(path) != EXPECTED_SOURCE_FILE_SHA256:
        raise ValueError("phase2a_r105_source_file_digest_invalid")
    source = _load_object(path)
    digest = _verify_seal(
        source,
        "artifact_content_sha256",
        "phase2a_r105_source_content_seal_invalid",
    )
    rows = source.get("rows")
    if (
        digest != EXPECTED_SOURCE_CONTENT_SHA256
        or source.get("schema")
        != "legalbot.v111.phase2a.source-review-packets-26.v2"
        or source.get("row_source_link_count") != EXPECTED_ROW_COUNT
        or source.get("unique_row_count") != EXPECTED_UNIQUE_ROW_COUNT
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_ROW_COUNT
        or any(source.get(field) is not False for field in _BOUNDARY_FIELDS)
    ):
        raise ValueError("phase2a_r105_source_boundary_invalid")
    link_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("phase2a_r105_source_row_invalid")
        _verify_seal(
            row,
            "record_content_sha256",
            "phase2a_r105_source_row_seal_invalid",
        )
        link_id = str(row.get("row_source_link_id") or "")
        candidates = row.get("candidate_blocks")
        if (
            not _SHA256.fullmatch(link_id)
            or link_id in link_ids
            or not isinstance(candidates, list)
            or not candidates
            or len(candidates) > MAX_PROJECTED_CANDIDATES
            or row.get("owner_outcome") is not None
            or row.get("source_admission_authorized") is not False
            or row.get("technical_qualification_assigned") is not False
        ):
            raise ValueError("phase2a_r105_source_row_boundary_invalid")
        link_ids.add(link_id)
        ranks: list[int] = []
        block_ids: set[str] = set()
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                raise ValueError("phase2a_r105_source_candidate_invalid")
            rank = candidate.get("rank")
            block_id = str(candidate.get("block_id") or "")
            text = str(candidate.get("exact_text") or "")
            if (
                isinstance(rank, bool)
                or not isinstance(rank, int)
                or rank < 1
                or block_id in block_ids
                or not block_id
                or not text
                or _sha256(text.encode("utf-8"))
                != candidate.get("exact_text_sha256")
            ):
                raise ValueError("phase2a_r105_source_candidate_boundary_invalid")
            ranks.append(rank)
            block_ids.add(block_id)
        if ranks != list(range(1, len(candidates) + 1)):
            raise ValueError("phase2a_r105_source_candidate_ranks_invalid")
    return source


def _runtime_identity(runtime_identity: Mapping[str, Any]) -> dict[str, Any]:
    identity = dict(runtime_identity)
    if (
        identity.get("model_repo") != PINNED_MODEL_REPO
        or identity.get("model_revision") != PINNED_MODEL_REVISION
        or identity.get("model_file_manifest_sha256")
        != PINNED_MODEL_FILE_MANIFEST_SHA256
        or identity.get("model_independent_from_drafting_adapter") is not True
        or identity.get("generative_model_used") is not False
        or identity.get("qualification_threshold") is not None
    ):
        raise ValueError("phase2a_r105_runtime_identity_invalid")
    identity["maximum_projected_candidates_per_row"] = MAX_PROJECTED_CANDIDATES
    identity["top_candidate_count"] = TOP_CANDIDATE_COUNT
    identity["review_purpose"] = "advisory_official_source_block_relevance_only"
    return identity


def _project_row(row: Mapping[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    issue_label = str(row.get("issue_label") or "")
    legal_domain = str(row.get("legal_domain") or "")
    question = str(row.get("case_question") or "")
    query = (
        "Rank each official-source block by its direct usefulness for checking the "
        "specific legal issue in the supplied scenario. Do not infer that the source "
        "is legally sufficient merely because it shares a topic.\n"
        f"Legal domain: {legal_domain}\n"
        f"Issue: {issue_label}\n"
        f"Scenario: {question}"
    )
    projected: list[dict[str, Any]] = []
    for candidate in row["candidate_blocks"]:
        exact_text = str(candidate["exact_text"])
        excerpt, truncated = _salient_excerpt(
            exact_text,
            issue_label=issue_label,
            question=question,
        )
        projected.append(
            {
                "rank": candidate["rank"],
                "candidate_block_id": candidate["block_id"],
                "source_version_id": (
                    f"{row['canonical_authority_identity_id']}@"
                    f"{row['source_representation_sha256']}"
                ),
                "authority_identity_id": row["authority_identity_id"],
                "title": row["source_title"],
                "canonical_citation": row["canonical_authority_identity_id"],
                "locator": candidate["locator"],
                "exact_text_sha256": candidate["exact_text_sha256"],
                "full_span_character_count": candidate["character_count"],
                "excerpt": excerpt,
                "excerpt_sha256": _sha256((excerpt + "\n").encode("utf-8")),
                "excerpt_character_count": len(excerpt),
                "excerpt_truncated": truncated,
                "lexical_tfidf_score": candidate["lexical_score"],
                "deterministic_selection_reasons": candidate[
                    "selection_reasons"
                ],
                "question_segment_match": candidate.get("question_segment_match"),
            }
        )
    return query, projected


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, RuntimeError | ValueError) and exc.args:
        candidate = str(exc.args[0]).casefold().replace("-", "_")
        if _SAFE_CODE.fullmatch(candidate):
            return candidate
    name = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    return name if _SAFE_CODE.fullmatch(name) else "phase2a_r105_unknown_failure"


def _checkpoint_name(ordinal: int, link_id: str) -> str:
    return f"{ordinal:02d}-{link_id[:24]}.json"


def _validate_scores(
    raw_scores: Sequence[float], candidates: Sequence[Mapping[str, Any]]
) -> list[float]:
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
        raise ValueError("phase2a_r105_scores_invalid")
    return [round(float(score), 10) for score in scores]


def _review_one(
    *,
    ordinal: int,
    row: Mapping[str, Any],
    scorer: ScoreRow,
    runtime_identity_sha256: str,
    checkpoints_root: Path,
    diagnostics_root: Path,
) -> dict[str, Any]:
    query, candidates = _project_row(row)
    input_material = {
        "schema": "legalbot.v111.phase2a.independent-source-reranker-input.v1",
        "row_source_link_id": row["row_source_link_id"],
        "source_row_record_content_sha256": row["record_content_sha256"],
        "query": query,
        "query_sha256": _sha256((query + "\n").encode("utf-8")),
        "candidates": candidates,
        "full_span_hash_is_binding": True,
        "excerpt_truncation_is_explicit": True,
    }
    input_sha256 = _sealed(input_material)
    fingerprints: list[str] = []
    for attempt in (1, 2):
        started = time.perf_counter()
        try:
            raw_scores, metrics = scorer(query, candidates)
            scores = _validate_scores(raw_scores, candidates)
            if not isinstance(metrics, Mapping):
                raise ValueError("phase2a_r105_metrics_invalid")
        except Exception as exc:
            error_code = _error_code(exc)
            fingerprint = _sealed(
                {
                    "schema": "legalbot.v111.phase2a.r105-failure-fingerprint.v1",
                    "row_source_link_id": row["row_source_link_id"],
                    "input_content_sha256": input_sha256,
                    "runtime_identity_sha256": runtime_identity_sha256,
                    "error_code": error_code,
                }
            )
            fingerprints.append(fingerprint)
            diagnostic_material = {
                "schema": "legalbot.v111.phase2a.r105-rejected-attempt.v1",
                "ordinal": ordinal,
                "row_id": row["row_id"],
                "row_source_link_id": row["row_source_link_id"],
                "attempt": attempt,
                "input_content_sha256": input_sha256,
                "error_code": error_code,
                "failure_fingerprint": fingerprint,
                "same_failure_fingerprint_as_prior_attempt": (
                    len(fingerprints) == 2 and fingerprints[0] == fingerprints[1]
                ),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "root_cause_status": "REQUIRES_DEBUG_BEFORE_ANY_THIRD_ATTEMPT",
                "owner_decision_assigned": False,
                "source_admission_authorized": False,
                "technical_qualification_assigned": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            diagnostic = {
                **diagnostic_material,
                "diagnostic_content_sha256": _sealed(diagnostic_material),
            }
            diagnostic_name = (
                f"{_checkpoint_name(ordinal, str(row['row_source_link_id']))[:-5]}"
                f"-a{attempt}.json"
            )
            _write_exclusive(
                diagnostics_root / diagnostic_name,
                _pretty_json(diagnostic),
            )
            if attempt == 1:
                continue
            held_material = {
                "schema": "legalbot.v111.phase2a.r105-held-source-link.v1",
                "ordinal": ordinal,
                "row_id": row["row_id"],
                "row_source_link_id": row["row_source_link_id"],
                "source_row_record_content_sha256": row["record_content_sha256"],
                "input_content_sha256": input_sha256,
                "status": "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT",
                "attempt_count": 2,
                "failure_fingerprints": fingerprints,
                "same_failure_fingerprint_twice": fingerprints[0] == fingerprints[1],
                "debug_required_before_third_attempt": True,
                "owner_decision_required": True,
                "owner_decision_assigned": False,
                "source_admission_authorized": False,
                "technical_qualification_assigned": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            held = {**held_material, "held_content_sha256": _sealed(held_material)}
            _write_exclusive(
                checkpoints_root
                / _checkpoint_name(ordinal, str(row["row_source_link_id"])),
                _pretty_json(held),
            )
            return held

        ranked = sorted(
            (
                {**candidate, "reranker_score": score}
                for candidate, score in zip(candidates, scores, strict=True)
            ),
            key=lambda candidate: (-candidate["reranker_score"], candidate["rank"]),
        )
        ranked = [
            {**candidate, "model_rank": model_rank}
            for model_rank, candidate in enumerate(ranked, start=1)
        ]
        checkpoint_material = {
            "schema": "legalbot.v111.phase2a.independent-source-reranker-checkpoint.v1",
            "ordinal": ordinal,
            "row_id": row["row_id"],
            "row_source_link_id": row["row_source_link_id"],
            "authority_identity_id": row["authority_identity_id"],
            "source_row_record_content_sha256": row["record_content_sha256"],
            "input_content_sha256": input_sha256,
            "runtime_identity_sha256": runtime_identity_sha256,
            "attempt_count": attempt,
            "query": query,
            "query_sha256": input_material["query_sha256"],
            "all_ranked_candidates": ranked,
            "top_candidates": ranked[:TOP_CANDIDATE_COUNT],
            "model_metrics": dict(metrics),
            "status": "ADVISORY_RELEVANCE_RANKING_READY_OWNER_REVIEW_REQUIRED",
            "score_threshold_applied": False,
            "qualification_threshold": None,
            "legal_sufficiency_decided": False,
            "model_independent_from_drafting_adapter": True,
            "generative_model_used": False,
            "hidden_reasoning_persisted": False,
            "owner_decision_required": True,
            "owner_decision_assigned": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "technical_qualification_assigned": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        checkpoint = {
            **checkpoint_material,
            "checkpoint_content_sha256": _sealed(checkpoint_material),
        }
        _write_exclusive(
            checkpoints_root
            / _checkpoint_name(ordinal, str(row["row_source_link_id"])),
            _pretty_json(checkpoint),
        )
        return checkpoint
    raise AssertionError("phase2a_r105_attempt_loop_unreachable")


def _load_checkpoint(path: Path) -> dict[str, Any]:
    checkpoint = _load_object(path)
    schema = checkpoint.get("schema")
    if schema == "legalbot.v111.phase2a.independent-source-reranker-checkpoint.v1":
        _verify_seal(
            checkpoint,
            "checkpoint_content_sha256",
            "phase2a_r105_checkpoint_seal_invalid",
        )
    elif schema == "legalbot.v111.phase2a.r105-held-source-link.v1":
        _verify_seal(
            checkpoint,
            "held_content_sha256",
            "phase2a_r105_held_seal_invalid",
        )
    else:
        raise ValueError("phase2a_r105_checkpoint_schema_invalid")
    return checkpoint


def _custody_entries(root: Path, pattern: str) -> list[dict[str, Any]]:
    entries = []
    for path in sorted(root.glob(pattern)):
        value = _load_object(path)
        field = (
            "diagnostic_content_sha256"
            if root.name == "diagnostics"
            else (
                "checkpoint_content_sha256"
                if "checkpoint_content_sha256" in value
                else "held_content_sha256"
            )
        )
        content_sha256 = _verify_seal(
            value,
            field,
            "phase2a_r105_custody_seal_invalid",
        )
        entries.append(
            {
                "relative_path": f"{root.name}/{path.name}",
                "file_sha256": _sha256_file(path),
                "content_sha256": content_sha256,
            }
        )
    return entries


def _write_checksums(output_root: Path) -> None:
    paths = sorted(
        path
        for path in output_root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    lines = "".join(
        f"{_sha256_file(path)}  {path.relative_to(output_root)}\n" for path in paths
    )
    _write_exclusive(output_root / "SHA256SUMS.txt", lines.encode("utf-8"))


def run_review(
    *,
    source_path: Path,
    output_root: Path,
    scorer: ScoreRow,
    runtime_identity: Mapping[str, Any],
    started_at: datetime,
    resume: bool = False,
) -> dict[str, Any]:
    if started_at.tzinfo is None:
        raise ValueError("phase2a_r105_started_at_naive")
    source = _load_source(source_path)
    identity = _runtime_identity(runtime_identity)
    identity_sha256 = _sealed(identity)
    intent_path = output_root / "INTENT.json"
    if output_root.exists() or output_root.is_symlink():
        if not resume or output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("phase2a_r105_output_already_exists")
        intent = _load_object(intent_path)
        _verify_seal(intent, "intent_content_sha256", "phase2a_r105_intent_seal_invalid")
        if (
            intent.get("source_content_sha256") != EXPECTED_SOURCE_CONTENT_SHA256
            or intent.get("runtime_identity_sha256") != identity_sha256
        ):
            raise ValueError("phase2a_r105_resume_identity_mismatch")
    else:
        output_root.mkdir(parents=True, mode=0o700)
        if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
            raise ValueError("phase2a_r105_output_mode_invalid")
        intent_material = {
            "schema": "legalbot.v111.phase2a.independent-source-reranker-intent.v1",
            "status": "ADVISORY_RANKING_ONLY_NO_LEGAL_OR_OWNER_DECISION",
            "started_at": started_at.astimezone(UTC).isoformat(timespec="seconds"),
            "source_content_sha256": source["artifact_content_sha256"],
            "source_file_sha256": _sha256_file(source_path),
            "runtime_identity": identity,
            "runtime_identity_sha256": identity_sha256,
            "row_source_link_count": EXPECTED_ROW_COUNT,
            "maximum_attempts_per_link": 2,
            "debug_required_before_any_third_attempt": True,
            "score_threshold_applied": False,
            "qualification_threshold": None,
            "owner_decisions_applied": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "technical_qualification_assigned": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        intent = {**intent_material, "intent_content_sha256": _sealed(intent_material)}
        _write_exclusive(intent_path, _pretty_json(intent))

    checkpoints_root = output_root / "checkpoints"
    diagnostics_root = output_root / "diagnostics"
    checkpoints_root.mkdir(mode=0o700, exist_ok=True)
    diagnostics_root.mkdir(mode=0o700, exist_ok=True)
    if (output_root / OUTPUT_NAME).exists() or (output_root / "SHA256SUMS.txt").exists():
        raise ValueError("phase2a_r105_already_finalized")

    results: list[dict[str, Any]] = []
    for ordinal, row in enumerate(source["rows"], start=1):
        checkpoint_path = checkpoints_root / _checkpoint_name(
            ordinal,
            str(row["row_source_link_id"]),
        )
        if checkpoint_path.exists():
            checkpoint = _load_checkpoint(checkpoint_path)
            if (
                checkpoint.get("ordinal") != ordinal
                or checkpoint.get("row_source_link_id")
                != row["row_source_link_id"]
                or checkpoint.get("source_row_record_content_sha256")
                != row["record_content_sha256"]
            ):
                raise ValueError("phase2a_r105_checkpoint_binding_invalid")
            results.append(checkpoint)
            continue
        results.append(
            _review_one(
                ordinal=ordinal,
                row=row,
                scorer=scorer,
                runtime_identity_sha256=identity_sha256,
                checkpoints_root=checkpoints_root,
                diagnostics_root=diagnostics_root,
            )
        )

    held = [result for result in results if "held_content_sha256" in result]
    ranked = [result for result in results if result not in held]
    checkpoint_custody = _custody_entries(checkpoints_root, "*.json")
    diagnostic_custody = _custody_entries(diagnostics_root, "*.json")
    final_material = {
        "schema": "legalbot.v111.phase2a.independent-source-reranker-26.v1",
        "status": (
            "INDEPENDENT_SOURCE_RERANKING_COMPLETE_OWNER_REVIEW_REQUIRED"
            if not held
            else "INDEPENDENT_SOURCE_RERANKING_HELD_DEBUG_REQUIRED"
        ),
        "source_content_sha256": source["artifact_content_sha256"],
        "source_file_sha256": _sha256_file(source_path),
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "runtime_identity_sha256": identity_sha256,
        "model_independent_from_drafting_adapter": True,
        "generative_model_used": False,
        "row_source_link_count": len(results),
        "advisory_ranking_count": len(ranked),
        "held_for_debug_count": len(held),
        "top_candidate_count_per_link": TOP_CANDIDATE_COUNT,
        "checkpoint_custody": checkpoint_custody,
        "checkpoint_custody_sha256": _sealed(checkpoint_custody),
        "diagnostic_custody": diagnostic_custody,
        "diagnostic_custody_sha256": _sealed(diagnostic_custody),
        "rows": results,
        "scores_are_advisory_not_qualification": True,
        "legal_sufficiency_decided": False,
        "score_threshold_applied": False,
        "qualification_threshold": None,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    final = {**final_material, "artifact_content_sha256": _sealed(final_material)}
    _write_exclusive(output_root / OUTPUT_NAME, _pretty_json(final))
    outcome = (
        "26 OFFICIAL-SOURCE LINKS INDEPENDENTLY RERANKED; OWNER REVIEW REQUIRED. "
        "NO SOURCE ADMISSION, INDEXING, QUALIFICATION, OR GATE CHANGE.\n"
        if not held
        else "SOURCE RERANKING HELD FOR DEBUG BEFORE ANY THIRD ATTEMPT. NO GATE CHANGE.\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode("utf-8"))
    _write_checksums(output_root)
    return final


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE_PATH)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    scorer, identity = _real_scorer(args.model_path.resolve(strict=True))
    final = run_review(
        source_path=args.source.resolve(strict=True),
        output_root=args.output_root.resolve(),
        scorer=scorer,
        runtime_identity=identity,
        started_at=datetime.now(UTC),
        resume=bool(args.resume),
    )
    print(
        json.dumps(
            {
                "artifact_content_sha256": final["artifact_content_sha256"],
                "row_source_link_count": final["row_source_link_count"],
                "advisory_ranking_count": final["advisory_ranking_count"],
                "held_for_debug_count": final["held_for_debug_count"],
                "model_independent_from_drafting_adapter": True,
                "source_admission_authorized": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
