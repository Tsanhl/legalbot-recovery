#!/usr/bin/env python3
"""Verify Phase-2A issue proposals against supplied exact catalogue chunks.

This pass is deliberately advisory.  Each supplied whole chunk is partitioned
exhaustively into exact source-text spans.  The immutable case scenario is
supplied only to disambiguate terse issue labels; answering or applying it is
forbidden.  The model may select one supplied span ID and state one atomic
proposition; deterministic code resolves that ID to the original text and
rejects invented spans, unsupported typed facts, non-atomic propositions,
unrelated evidence, truncation, and unsafe runtime identity.  The model never
reproduces the quotation text.

The output cannot assign an owner decision, qualify an issue, admit a source,
mutate a candidate, or authorize Phase 2B or Development 30.  Raw model output
and hidden reasoning are never persisted.  A malformed output receives at most
one targeted repair; diagnostics are persisted before a batch is held ahead of
any third attempt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.quality.evidence import (  # noqa: E402
    extract_material_facts,
    is_substantively_related,
    non_atomic_material_claim_reasons,
)
from app.retrieval.source_manifest import (  # noqa: E402
    approved_source_manifest_sha256,
)
from scripts import build_v111_phase2a_authority_plan_advisory as planner  # noqa: E402
from scripts import build_v111_phase2a_targeted_global_recovery as targeted_recovery  # noqa: E402
from scripts import resolve_v111_phase2a_authority_plan_locators as locator_resolver  # noqa: E402

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data" / "evaluations" / "phase2a-owner-review"
DEFAULT_LOCATORS = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r60g-targeted-global-recovery"
    / "TARGETED-GLOBAL-RECOVERY-448.json"
)
DEFAULT_PLANS = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r50-authority-plan-advisory"
    / "ADVISORY-AUTHORITY-PLANS-448.json"
)
DEFAULT_REMAINING = planner.DEFAULT_REMAINING
DEFAULT_CASES = planner.DEFAULT_CASES
DEFAULT_CANDIDATE_MANIFEST = (
    PROJECT_ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260818-a"
    / "approved-source-manifest.json"
)
DEFAULT_OUTPUT = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r67-candidate-bound-exact-semantic-span-advisory"
)
VERIFIER_CODE_PATH = Path(__file__).resolve()
EVIDENCE_VALIDATOR_CODE_PATH = (
    PROJECT_ROOT / "backend" / "app" / "quality" / "evidence.py"
)

EXPECTED_ISSUE_COUNT = 448
EXPECTED_CANDIDATE_SOURCE_COUNT = 85
EXPECTED_CANDIDATE_CHUNK_COUNT = 149_855
EXPECTED_CANDIDATE_MANIFEST_SHA256 = (
    "d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0"
)
EXPECTED_MODEL_ID = planner.EXPECTED_MODEL_ID
EXPECTED_MODEL_VERSION = planner.EXPECTED_MODEL_VERSION
MODEL_BACKEND = planner.MODEL_BACKEND
OUTPUT_SCHEMA = "p2a-exact-span-id-v2"
SPAN_OPTION_SCHEMA = "legalbot.v111.phase2a.exact-span-option.v1"
BATCH_SIZE = 1
MAX_PROMPT_CHARACTERS = 24_000
MAX_PROPOSITION_CHARACTERS = 240
MAX_QUOTE_CHARACTERS = 700
MAX_OUTPUT_TOKENS = 900
MAX_PEAK_MEMORY_GB = 12.0
MAX_REVIEW_EVIDENCE_CANDIDATES_PER_ROW = 1
MAX_REVIEW_WHOLE_CHUNKS_PER_CANDIDATE = 1
REVIEWER_EXECUTION_MODE = (
    "separate_advisory_exact_span_verifier_same_model_adapter_as_drafting_"
    "not_model_independent"
)

SYSTEM_PROMPT = """/no_think
Advisory exact-span verifier only. Use the supplied immutable scenario solely to disambiguate the scope of each terse issue label. Do not answer the scenario, apply law to its facts, state a conclusion about a party, or include scenario-specific facts in a proposition. Do not decide owner approval, legal materiality, source admission, qualification, or any gate. For each issue inspect only its supplied exact span options from the exact sealed candidate manifest. Noncandidate and unadmitted material is not supplied. Each supplied whole source chunk has been exhaustively partitioned into exact source-byte spans; no bytes within that chunk were omitted. Match the issue in its scenario context to an express rule in a supplied span. A source-stated general governing rule may be DIRECT support even though it does not complete the fact-specific analysis or remedy. DIRECT means one supplied span expressly states one atomic legal rule that governs a material component named by the contextualized issue. PARTIAL means one supplied span expressly states a relevant atomic legal rule but the text is a cross-reference, exception, limited category, or otherwise needs additional authority for the contextualized issue. GAP means no supplied span itself states a relevant legal rule for that contextualized issue. Do not require the source to resolve the whole scenario. For DIRECT or PARTIAL: state exactly one short, single-sentence atomic proposition of no more than 240 characters; paraphrase only the one rule supported by the selected span; and select exactly one supplied chunk ID and one span ID. Do not reproduce or alter quotation text—the deterministic validator resolves the selected span ID to the original exact source bytes. Do not copy an entire long provision into the proposition. Do not combine clauses, add scenario facts, or alter numbers, dates, percentages, amounts, durations, or provision identifiers. Prefer the most directly applicable span over a cross-reference or different product/category. For GAP use an empty proposition and null support. Never invent a chunk ID or span ID. Output compact JSON only with exactly: {"schema":"p2a-exact-span-id-v2","case_id":"<supplied case id>","rows":[{"row_id":"<supplied row id>","assessment":"DIRECT|PARTIAL|GAP","proposition":"<one atomic proposition of at most 240 characters or empty>","support":{"chunk_id":"<supplied chunk id>","span_id":"<supplied span id>"}|null}]}. Include each supplied row exactly once."""

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9_]{0,127}$")

Invoke = Callable[[dict[str, Any]], dict[str, Any]]


class SemanticValidationError(ValueError):
    """A stable machine-safe semantic validation failure."""

    def __init__(
        self, code: str, *, diagnostics: Mapping[str, str | int | float | bool] | None = None
    ):
        if not _SAFE_CODE.fullmatch(code):
            raise ValueError("phase2a_semantic_error_code_invalid")
        safe_diagnostics = dict(diagnostics or {})
        if any(not _SAFE_CODE.fullmatch(str(key)) for key in safe_diagnostics):
            raise ValueError("phase2a_semantic_error_diagnostics_invalid")
        self.code = code
        self.diagnostics = safe_diagnostics
        super().__init__(code)


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


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
        raise ValueError("phase2a_semantic_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_semantic_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _load_candidate_manifest(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], str, str]:
    manifest = _load_object(path)
    supplied = str(manifest.get("manifest_sha256") or "")
    sources = manifest.get("sources")
    if (
        supplied != EXPECTED_CANDIDATE_MANIFEST_SHA256
        or supplied != approved_source_manifest_sha256(manifest)
        or manifest.get("schema") != "legalbot.approved-source-manifest.v1"
        or manifest.get("authority_lane_only") is not True
        or manifest.get("exclude_find_case_law_full_text") is not True
        or manifest.get("exclude_teaching_as_authority") is not True
        or manifest.get("exclude_assessment_as_authority") is not True
        or manifest.get("source_count") != EXPECTED_CANDIDATE_SOURCE_COUNT
        or manifest.get("chunk_count") != EXPECTED_CANDIDATE_CHUNK_COUNT
        or not isinstance(sources, list)
        or len(sources) != EXPECTED_CANDIDATE_SOURCE_COUNT
        or any(not isinstance(source, dict) for source in sources)
    ):
        raise ValueError("phase2a_semantic_candidate_manifest_invalid")
    by_id: dict[str, dict[str, Any]] = {}
    for source in sources:
        source_id = str(source.get("source_version_id") or "")
        if (
            not source_id
            or source_id in by_id
            or source.get("lane") != "primary_authority"
            or source.get("document_status") != "citable"
            or source.get("identity_verified") is not True
            or not _SHA256.fullmatch(str(source.get("version_sha256") or ""))
        ):
            raise ValueError("phase2a_semantic_candidate_source_invalid")
        by_id[source_id] = dict(source)
    return by_id, supplied, _sha256_file(path)


def _load_inputs(
    *,
    locators_path: Path,
    plans_path: Path,
    remaining_path: Path,
    cases_path: Path,
    candidate_manifest_path: Path,
) -> tuple[
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    list[str],
    dict[str, dict[str, Any]],
    dict[str, str],
]:
    locator_artifact = _load_object(locators_path)
    locator_sha256 = _verify_seal(
        locator_artifact,
        "artifact_content_sha256",
        "phase2a_semantic_locator_seal_invalid",
    )
    plans_artifact = _load_object(plans_path)
    plans_sha256 = _verify_seal(
        plans_artifact,
        "artifact_content_sha256",
        "phase2a_semantic_plans_seal_invalid",
    )
    records = locator_artifact.get("records")
    held_row_ids: list[str] = []
    if (
        locator_artifact.get("schema")
        != "legalbot.v111.phase2a.targeted-global-recovery-448.v7"
        or locator_artifact.get("source_remaining_content_sha256")
        != plans_artifact.get("source_remaining_content_sha256")
        or locator_artifact.get("source_catalogue_file_sha256")
        != targeted_recovery.EXPECTED_CATALOGUE_FILE_SHA256
        or locator_artifact.get("target_ceiling_date")
        != targeted_recovery.TARGET_CEILING_DATE.isoformat()
        or locator_artifact.get("builder_code_file_sha256")
        != _sha256_file(Path(targeted_recovery.__file__).resolve())
        or locator_artifact.get("issue_count") != EXPECTED_ISSUE_COUNT
        or not isinstance(records, list)
        or len(records) != EXPECTED_ISSUE_COUNT
        or locator_artifact.get("policy", {}).get("whole_chunks_only") is not True
        or locator_artifact.get("policy", {}).get("silent_text_truncation") is not False
        or locator_artifact.get("policy", {}).get("omitted_chunk_sets_sealed") is not True
        or locator_artifact.get("semantic_proposition_support_verified") is not False
        or locator_artifact.get("owner_decisions_applied") is not False
        or locator_artifact.get("source_admission_authorized") is not False
        or locator_artifact.get("candidate_mutated") is not False
        or locator_artifact.get("phase2b_authorized") is not False
        or locator_artifact.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_semantic_locator_boundary_invalid")
    if (
        plans_artifact.get("issue_count") != EXPECTED_ISSUE_COUNT
        or plans_artifact.get("held_row_ids") != []
        or plans_artifact.get("owner_decisions_applied") is not False
        or plans_artifact.get("source_admission_authorized") is not False
        or plans_artifact.get("candidate_mutated") is not False
        or plans_artifact.get("phase2b_authorized") is not False
        or plans_artifact.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_semantic_plans_boundary_invalid")

    issue_rows, remaining_sha256 = planner._load_issue_rows(remaining_path)
    cases = planner._load_cases(cases_path)
    candidate_sources, candidate_manifest_sha256, candidate_manifest_file_sha256 = (
        _load_candidate_manifest(candidate_manifest_path)
    )
    issues_by_id = {str(row["item_id"]): row for row in issue_rows}
    records_by_id: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("phase2a_semantic_locator_record_invalid")
        record_sha256 = _verify_seal(
            record,
            "record_content_sha256",
            "phase2a_semantic_locator_record_seal_invalid",
        )
        row_id = str(record.get("row_id") or "")
        if row_id not in issues_by_id or row_id in records_by_id:
            raise ValueError("phase2a_semantic_locator_row_identity_invalid")
        selections = record.get("resolved_selections")
        if (
            record.get("schema")
            != "legalbot.v111.phase2a.targeted-global-recovery-row.v7"
            or not isinstance(selections, list)
            or not selections
        ):
            raise ValueError("phase2a_semantic_locator_selections_invalid")
        for selection in selections:
            if not isinstance(selection, dict):
                raise ValueError("phase2a_semantic_locator_selection_invalid")
            _verify_seal(
                selection,
                "selection_content_sha256",
                "phase2a_semantic_locator_selection_seal_invalid",
            )
            if (
                selection.get("whole_chunks_only") is not True
                or selection.get("silent_text_truncation") is not False
                or not _SHA256.fullmatch(
                    str(selection.get("omitted_chunk_identities_sha256") or "")
                )
            ):
                raise ValueError("phase2a_semantic_locator_projection_invalid")
        copied = dict(record)
        copied["record_content_sha256"] = record_sha256
        records_by_id[row_id] = copied
    held = [str(row_id) for row_id in held_row_ids]
    if (
        len(set(held)) != len(held)
        or any(row_id not in issues_by_id for row_id in held)
        or set(held) & set(records_by_id)
        or set(held) | set(records_by_id) != set(issues_by_id)
    ):
        raise ValueError("phase2a_semantic_locator_coverage_invalid")
    return (
        issue_rows,
        issues_by_id,
        cases,
        held,
        candidate_sources,
        {
            "locators": locator_sha256,
            "plans": plans_sha256,
            "remaining": remaining_sha256,
            "candidate_manifest": candidate_manifest_sha256,
            "candidate_manifest_file": candidate_manifest_file_sha256,
        },
    )


def _semantic_chunk_score(
    issue_label: str, chunk: Mapping[str, Any]
) -> tuple[float, float, int, int]:
    base = targeted_recovery._chunk_score(issue_label, chunk)
    text = " ".join(str(chunk.get("text") or "").casefold().split())
    linked_rule = (
        targeted_recovery._token_coverage(
            issue_label, str(chunk.get("text") or "")
        )
        >= 0.5
        and targeted_recovery._direct_rule_signal(str(chunk.get("text") or ""))
    )
    scope_or_commencement_only = any(
        marker in text
        for marker in (
            "nothing in this act shall apply",
            "does not apply in relation to",
            "does not entitle a person",
            "is amended as follows",
            "before the commencement of this act",
        )
    )
    direct_weight = 20.0 if linked_rule and not scope_or_commencement_only else 5.0 if linked_rule else 0.0
    return (direct_weight, *base)


def _exact_span_partition(chunk: Mapping[str, Any]) -> dict[str, Any]:
    """Represent a whole source chunk as exhaustive exact selectable spans."""

    chunk_id = str(chunk.get("chunk_id") or "")
    text = str(chunk.get("text") or "")
    text_sha256 = str(chunk.get("text_sha256") or "")
    if not chunk_id or not text or text_sha256 != _sha256(text.encode("utf-8")):
        raise ValueError("phase2a_semantic_span_partition_source_invalid")

    offsets: list[tuple[int, int]] = []
    start = 0
    while start < len(text):
        hard_end = min(start + MAX_QUOTE_CHARACTERS, len(text))
        if hard_end == len(text):
            end = hard_end
        else:
            window = text[start:hard_end]
            sentence_boundaries = [
                start + match.end()
                for match in re.finditer(r"(?<=[.!?])(?:[ \t]+|\r?\n+)", window)
                if match.end() >= 80
            ]
            if sentence_boundaries:
                end = sentence_boundaries[-1]
            else:
                whitespace = max(window.rfind(" "), window.rfind("\n"), window.rfind("\t"))
                end = start + whitespace + 1 if whitespace >= 80 else hard_end
        if end <= start or end - start > MAX_QUOTE_CHARACTERS:
            raise ValueError("phase2a_semantic_span_partition_boundary_invalid")
        offsets.append((start, end))
        start = end

    options: list[dict[str, Any]] = []
    for ordinal, (start, end) in enumerate(offsets, start=1):
        exact_text = text[start:end]
        identity = {
            "schema": "legalbot.v111.phase2a.exact-span-option-identity.v1",
            "chunk_id": chunk_id,
            "ordinal": ordinal,
            "start_character": start,
            "end_character_exclusive": end,
            "exact_text_sha256": _sha256(exact_text.encode("utf-8")),
        }
        span_id = f"span-{_sealed(identity)[:24]}"
        material = {
            "schema": SPAN_OPTION_SCHEMA,
            "span_id": span_id,
            "chunk_id": chunk_id,
            "ordinal": ordinal,
            "start_character": start,
            "end_character_exclusive": end,
            "exact_text": exact_text,
            "exact_text_sha256": identity["exact_text_sha256"],
        }
        options.append({**material, "span_content_sha256": _sealed(material)})

    partition_identity = [
        {
            "span_id": option["span_id"],
            "start_character": option["start_character"],
            "end_character_exclusive": option["end_character_exclusive"],
            "exact_text_sha256": option["exact_text_sha256"],
        }
        for option in options
    ]
    return {
        "chunk_id": chunk_id,
        "locator": str(chunk.get("locator") or ""),
        "heading_path": str(chunk.get("heading_path") or ""),
        "text_sha256": text_sha256,
        "text_character_count": len(text),
        "exact_span_options": options,
        "exact_span_option_count": len(options),
        "exact_span_partition_complete": True,
        "exact_span_partition_content_sha256": _sealed(partition_identity),
        "source_text_reproduced_by_partition_sha256": _sha256(
            "".join(option["exact_text"] for option in options).encode("utf-8")
        ),
        "silent_text_truncation": False,
    }


def _review_row(
    issue: Mapping[str, Any],
    locator_record: Mapping[str, Any],
    candidate_sources: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any] | None:
    candidates: list[dict[str, Any]] = []
    issue_label = str(issue["issue_label"])
    for selection in locator_record["resolved_selections"]:
        if not isinstance(selection, dict):
            raise ValueError("phase2a_semantic_resolved_selection_invalid")
        chunks = selection.get("exact_chunks")
        if not isinstance(chunks, list):
            raise ValueError("phase2a_semantic_exact_chunks_invalid")
        verified_chunks: list[dict[str, Any]] = []
        seen_chunks: set[str] = set()
        for chunk in chunks:
            if not isinstance(chunk, dict):
                raise ValueError("phase2a_semantic_exact_chunk_invalid")
            chunk_id = str(chunk.get("chunk_id") or "")
            text = str(chunk.get("text") or "")
            text_sha256 = str(chunk.get("text_sha256") or "")
            if (
                not chunk_id
                or chunk_id in seen_chunks
                or not text
                or text_sha256 != _sha256(text.encode("utf-8"))
            ):
                raise ValueError("phase2a_semantic_exact_chunk_identity_invalid")
            seen_chunks.add(chunk_id)
            verified_chunks.append(
                {
                    "chunk_id": chunk_id,
                    "locator": str(chunk.get("locator") or ""),
                    "heading_path": str(chunk.get("heading_path") or ""),
                    "text": text,
                    "text_sha256": text_sha256,
                }
            )
        if not verified_chunks:
            continue
        source = selection.get("source_identity")
        if not isinstance(source, dict):
            raise ValueError("phase2a_semantic_source_identity_invalid")
        if locator_resolver._record_is_after_target_ceiling(source):
            raise ValueError("phase2a_semantic_source_after_target_ceiling")
        metadata = selection.get("candidate_source_metadata")
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("phase2a_semantic_candidate_metadata_invalid")
        source_version_id = str(source.get("id") or "")
        admitted_candidate = candidate_sources.get(source_version_id)
        already_in_candidate = (
            metadata.get("already_in_sealed_candidate")
            if isinstance(metadata, dict)
            else None
        )
        if admitted_candidate is None:
            continue
        if (
            already_in_candidate is not True
            or metadata.get("identity_verified") is not True
            or str(selection.get("authority_identity_id") or "")
            != str(admitted_candidate.get("authority_identity_id") or "")
            or str(source.get("authority_identity_id") or "")
            != str(admitted_candidate.get("authority_identity_id") or "")
            or str(source.get("version_sha256") or "")
            != str(admitted_candidate.get("version_sha256") or "")
            or str(source.get("stable_identifier") or "")
            != str(admitted_candidate.get("stable_identifier") or "")
            or str(source.get("canonical_url") or "")
            != str(admitted_candidate.get("canonical_url") or "")
            or str(source.get("lane") or "")
            != str(admitted_candidate.get("lane") or "")
            or str(source.get("document_status") or "")
            != str(admitted_candidate.get("document_status") or "")
        ):
            raise ValueError("phase2a_semantic_candidate_identity_mismatch")
        label_linked_rule = targeted_recovery._label_linked_direct_rule(
            issue_label, verified_chunks
        )
        candidate_material = (
            {
                "authority_identity_id": str(selection.get("authority_identity_id") or ""),
                "source_version_id": str(source.get("id") or ""),
                "title": str(source.get("title") or ""),
                "canonical_url": str(source.get("canonical_url") or ""),
                "as_of_date": source.get("as_of_date"),
                "currentness_status": source.get("currentness_status"),
                "locator_hint": str(selection.get("locator_hint") or ""),
                "candidate_source_metadata": {
                    key: metadata.get(key)
                    for key in (
                        "already_in_sealed_candidate",
                        "canonical_citation",
                        "currentness_verified",
                        "later_treatment_review_required",
                        "combined_advisory_score",
                    )
                    if isinstance(metadata, dict) and key in metadata
                },
                "selection_origin": selection.get("selection_origin"),
                "projection_integrity": {
                    "whole_chunks_only": selection.get("whole_chunks_only"),
                    "silent_text_truncation": selection.get(
                        "silent_text_truncation"
                    ),
                    "complete_locator_result_used": selection.get(
                        "complete_locator_result_used"
                    ),
                    "omitted_chunk_count": selection.get("omitted_chunk_count"),
                    "omitted_chunk_identities_sha256": selection.get(
                        "omitted_chunk_identities_sha256"
                    ),
                    "selection_content_sha256": selection.get(
                        "selection_content_sha256"
                    ),
                },
                "chunks": verified_chunks,
            }
        )
        candidates.append(
            {
                **candidate_material,
                "_advisory_selection_order": (
                    1
                    if selection.get("selection_origin")
                    == "PRIOR_EXACT_SELECTION_REPROJECTED"
                    else 0,
                    1 if label_linked_rule else 0,
                    max(
                        _semantic_chunk_score(issue_label, chunk)[0]
                        + _semantic_chunk_score(issue_label, chunk)[1]
                        for chunk in verified_chunks
                    ),
                    float(
                        (metadata or {}).get("combined_advisory_score") or 0.0
                    ),
                ),
            }
        )
    if not candidates:
        return None
    candidates.sort(
        key=lambda candidate: (
            candidate["_advisory_selection_order"],
            candidate["authority_identity_id"],
            candidate["source_version_id"],
        ),
        reverse=True,
    )
    projected_candidates: list[dict[str, Any]] = []
    for candidate in candidates[:MAX_REVIEW_EVIDENCE_CANDIDATES_PER_ROW]:
        all_chunks = candidate["chunks"]
        ordered_chunks = sorted(
            all_chunks,
            key=lambda chunk: (
                _semantic_chunk_score(issue_label, chunk),
                str(chunk["chunk_id"]),
            ),
            reverse=True,
        )
        selected_source_chunks = ordered_chunks[
            :MAX_REVIEW_WHOLE_CHUNKS_PER_CANDIDATE
        ]
        selected_chunks = [
            _exact_span_partition(chunk) for chunk in selected_source_chunks
        ]
        selected_ids = {
            str(chunk["chunk_id"]) for chunk in selected_source_chunks
        }
        omitted = [
            {"chunk_id": chunk["chunk_id"], "text_sha256": chunk["text_sha256"]}
            for chunk in all_chunks
            if str(chunk["chunk_id"]) not in selected_ids
        ]
        projection = dict(candidate["projection_integrity"])
        projection.update(
            {
                "semantic_input_whole_chunk_count": len(selected_chunks),
                "semantic_input_exact_span_option_count": sum(
                    int(chunk["exact_span_option_count"])
                    for chunk in selected_chunks
                ),
                "semantic_input_source_text_fully_partitioned": True,
                "semantic_input_omitted_chunk_count": len(omitted),
                "semantic_input_omitted_chunk_identities_sha256": _sealed(omitted),
                "semantic_input_silent_text_truncation": False,
            }
        )
        projected = {
            key: value
            for key, value in candidate.items()
            if key not in {"_advisory_selection_order", "chunks", "projection_integrity"}
        }
        projected_candidates.append(
            {
                **projected,
                "projection_integrity": projection,
                "chunks": selected_chunks,
            }
        )
    return {
        "row_id": issue["item_id"],
        "issue_label": issue_label,
        "legal_domain": issue["legal_domain"],
        "evidence_candidates": projected_candidates,
    }


def _build_input(
    *,
    batch_ordinal: int,
    rows: Sequence[Mapping[str, Any]],
    case: Mapping[str, Any],
    repair_error_code: str | None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.exact-semantic-span-input.v3",
        "batch_ordinal": batch_ordinal,
        "case_id": case["case_id"],
        "subject": case["subject"],
        "scenario": case["question"],
        "scenario_content_sha256": _sha256(
            str(case["question"]).encode("utf-8")
        ),
        "scenario_text_supplied_to_exact_rule_extractor": True,
        "review_scope": (
            "GENERAL_GOVERNING_RULE_FOR_CONTEXTUALIZED_NAMED_ISSUE_ONLY_"
            "NO_FACT_APPLICATION_OR_ANSWER"
        ),
        "rows": [dict(row) for row in rows],
        "advisory_only": True,
        "exact_supplied_chunks_only": True,
        "source_chunks_exhaustively_partitioned": True,
        "model_selects_precomputed_exact_span_id": True,
        "model_reproduces_quote_text": False,
        "owner_decision_required": True,
        "qualification_forbidden": True,
        "source_admission_forbidden": True,
        "gate_authorization_forbidden": True,
        "silent_truncation_forbidden": True,
    }
    if repair_error_code is not None:
        value["repair_of_rejected_output"] = True
        value["deterministic_validation_error"] = repair_error_code
        if repair_error_code == "structured_output_proposition_missing":
            value["repair_instruction"] = (
                "For each DIRECT or PARTIAL row provide one non-empty, single-sentence "
                "atomic proposition of no more than 240 characters. Return only the "
                "exact compact schema using supplied chunk and span IDs."
            )
        elif repair_error_code == "structured_output_proposition_too_long":
            value["repair_instruction"] = (
                "Shorten every DIRECT or PARTIAL proposition to one single-sentence "
                "atomic paraphrase of no more than 240 characters. Do not paste the "
                "whole provision. Return only the exact compact schema using a supplied "
                "chunk ID and span ID."
            )
        else:
            value["repair_instruction"] = (
                "Return only the exact compact schema using supplied chunk and span IDs."
            )
    return value


def _prompt_characters(row_input: Mapping[str, Any]) -> int:
    return len(SYSTEM_PROMPT) + len(
        json.dumps(row_input, ensure_ascii=False, separators=(",", ":"))
    )


def _pack_batches(
    rows: Sequence[Mapping[str, Any]], cases: Mapping[str, Mapping[str, Any]]
) -> tuple[list[list[dict[str, Any]]], list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    case_order: list[str] = []
    for row in rows:
        case_id = str(row["row_id"]).split(":", 1)[0]
        if case_id not in cases:
            raise ValueError("phase2a_semantic_case_reference_invalid")
        if case_id not in grouped:
            case_order.append(case_id)
        grouped[case_id].append(dict(row))
    batches: list[list[dict[str, Any]]] = []
    oversized: list[dict[str, Any]] = []
    for case_id in case_order:
        case = cases[case_id]
        current: list[dict[str, Any]] = []
        for row in grouped[case_id]:
            single = _build_input(
                batch_ordinal=1,
                rows=[row],
                case=case,
                repair_error_code="repair_reserve",
            )
            if _prompt_characters(single) > MAX_PROMPT_CHARACTERS:
                oversized.append(row)
                continue
            proposed = [*current, row]
            proposed_input = _build_input(
                batch_ordinal=1,
                rows=proposed,
                case=case,
                repair_error_code="repair_reserve",
            )
            if current and (
                len(proposed) > BATCH_SIZE
                or _prompt_characters(proposed_input) > MAX_PROMPT_CHARACTERS
            ):
                batches.append(current)
                current = [row]
            else:
                current = proposed
        if current:
            batches.append(current)
    return batches, oversized


def _envelope(row_input: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    request_id = str(uuid4())
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": json.dumps(row_input, ensure_ascii=False, separators=(",", ":")),
        },
    ]
    return (
        {
            "request_id": request_id,
            "mode": "semantic_verify",
            "payload": {**dict(row_input), "messages": messages},
            "messages": messages,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "temperature": 0.0,
            "top_p": 1.0,
            "seed": 0,
            "stop": [],
        },
        request_id,
    )


def _http_invoker(
    model_url: str, timeout_seconds: float
) -> tuple[Invoke, dict[str, Any]]:
    parsed = urlparse(model_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("phase2a_semantic_model_url_must_be_literal_loopback")
    base = model_url.rstrip("/")
    with httpx.Client(
        timeout=httpx.Timeout(connect=5, read=timeout_seconds, write=30, pool=5),
        trust_env=False,
        follow_redirects=False,
    ) as client:
        response = client.get(f"{base}/api/v1/health")
        body = response.json()
    if (
        response.status_code != 200
        or not isinstance(body, dict)
        or body.get("backend") != MODEL_BACKEND
        or body.get("model_id") != EXPECTED_MODEL_ID
        or body.get("model_loaded") is not True
        or body.get("stub_mode") is not False
    ):
        raise RuntimeError("phase2a_semantic_pinned_model_unavailable")
    memory_profile = body.get("memory_profile")
    if (
        not isinstance(memory_profile, dict)
        or memory_profile.get("context_window_tokens") != 8192
        or int(memory_profile.get("max_output_tokens") or 0) < MAX_OUTPUT_TOKENS
        or memory_profile.get("single_flight_generation") is not True
    ):
        raise RuntimeError("phase2a_semantic_pinned_runtime_profile_invalid")
    runtime_material = {
        "schema": "legalbot.v111.phase2a.exact-span-runtime-identity.v1",
        "transport": "literal_loopback_http_phase2a_only",
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port or 80,
        "backend": body["backend"],
        "model_id": body["model_id"],
        "expected_model_version": EXPECTED_MODEL_VERSION,
        "memory_profile": memory_profile,
        "request_configuration": {
            "mode": "semantic_verify",
            "max_tokens": MAX_OUTPUT_TOKENS,
            "temperature": 0.0,
            "top_p": 1.0,
            "seed": 0,
            "stop": [],
        },
        "timeout_seconds": timeout_seconds,
        "stateless_advisory_review": True,
        "model_independent_reviewer": False,
    }
    runtime_identity = {
        **runtime_material,
        "runtime_identity_sha256": _sealed(runtime_material),
    }

    def invoke(envelope: dict[str, Any]) -> dict[str, Any]:
        with httpx.Client(
            timeout=httpx.Timeout(connect=5, read=timeout_seconds, write=30, pool=5),
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = client.post(f"{base}/api/v1/generate", json=envelope)
            if response.status_code != 200:
                service_code = "unknown"
                response_request_id = ""
                try:
                    error_body = response.json()
                except (json.JSONDecodeError, ValueError):
                    error_body = None
                if isinstance(error_body, dict):
                    response_request_id = str(error_body.get("request_id") or "")
                    error = error_body.get("error")
                    if isinstance(error, dict):
                        candidate_code = str(error.get("code") or "").casefold()
                        if _SAFE_CODE.fullmatch(candidate_code):
                            service_code = candidate_code
                raise SemanticValidationError(
                    f"model_http_{service_code}",
                    diagnostics={
                        "http_status": int(response.status_code),
                        "service_error_code": service_code,
                        "request_id_matches": response_request_id
                        == str(envelope.get("request_id") or ""),
                        "response_body_sha256": _sha256(response.content),
                    },
                )
            value = response.json()
        if not isinstance(value, dict):
            raise SemanticValidationError("model_response_not_object")
        return value

    return invoke, runtime_identity


def _chunk_map(row: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    chunks: dict[str, dict[str, Any]] = {}
    for source in row["evidence_candidates"]:
        for chunk in source["chunks"]:
            chunk_id = str(chunk["chunk_id"])
            if chunk_id in chunks:
                raise SemanticValidationError("supplied_chunk_identity_duplicated")
            options = chunk.get("exact_span_options")
            count = chunk.get("exact_span_option_count")
            character_count = chunk.get("text_character_count")
            if (
                not isinstance(options, list)
                or not options
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count != len(options)
                or isinstance(character_count, bool)
                or not isinstance(character_count, int)
                or character_count <= 0
                or chunk.get("exact_span_partition_complete") is not True
                or chunk.get("silent_text_truncation") is not False
            ):
                raise SemanticValidationError("supplied_span_partition_invalid")
            spans: dict[str, dict[str, Any]] = {}
            partition_identity: list[dict[str, Any]] = []
            reproduced: list[str] = []
            expected_start = 0
            for ordinal, option in enumerate(options, start=1):
                if not isinstance(option, dict):
                    raise SemanticValidationError("supplied_span_option_invalid")
                material = dict(option)
                supplied_seal = str(material.pop("span_content_sha256", ""))
                span_id = str(option.get("span_id") or "")
                exact_text = str(option.get("exact_text") or "")
                start = option.get("start_character")
                end = option.get("end_character_exclusive")
                if (
                    option.get("schema") != SPAN_OPTION_SCHEMA
                    or option.get("chunk_id") != chunk_id
                    or option.get("ordinal") != ordinal
                    or not span_id
                    or span_id in spans
                    or isinstance(start, bool)
                    or not isinstance(start, int)
                    or isinstance(end, bool)
                    or not isinstance(end, int)
                    or start != expected_start
                    or end <= start
                    or end - start != len(exact_text)
                    or len(exact_text) > MAX_QUOTE_CHARACTERS
                    or option.get("exact_text_sha256")
                    != _sha256(exact_text.encode("utf-8"))
                    or supplied_seal != _sealed(material)
                ):
                    raise SemanticValidationError("supplied_span_option_invalid")
                spans[span_id] = dict(option)
                expected_start = end
                reproduced.append(exact_text)
                partition_identity.append(
                    {
                        "span_id": span_id,
                        "start_character": start,
                        "end_character_exclusive": end,
                        "exact_text_sha256": option["exact_text_sha256"],
                    }
                )
            reproduced_sha256 = _sha256("".join(reproduced).encode("utf-8"))
            if (
                expected_start != character_count
                or reproduced_sha256 != chunk.get("text_sha256")
                or reproduced_sha256
                != chunk.get("source_text_reproduced_by_partition_sha256")
                or chunk.get("exact_span_partition_content_sha256")
                != _sealed(partition_identity)
            ):
                raise SemanticValidationError("supplied_span_partition_invalid")
            chunks[chunk_id] = {"source": source, "chunk": chunk, "spans": spans}
    return chunks


def _fact_records(text: str) -> list[dict[str, str]]:
    return [
        {
            "kind": fact.kind,
            "normalized_value": fact.normalized_value,
            "matched_text": fact.matched_text,
        }
        for fact in extract_material_facts(text)
    ]


def _validate_supported_row(
    *, row: Mapping[str, Any], assessment: str, proposition: str, support: Any
) -> dict[str, Any]:
    if not isinstance(support, dict) or set(support) != {"chunk_id", "span_id"}:
        raise SemanticValidationError("structured_output_support_invalid")
    if not proposition:
        raise SemanticValidationError(
            "structured_output_proposition_missing",
            diagnostics={"row_id": str(row["row_id"])},
        )
    if len(proposition) > MAX_PROPOSITION_CHARACTERS:
        raise SemanticValidationError(
            "structured_output_proposition_too_long",
            diagnostics={
                "row_id": str(row["row_id"]),
                "proposition_character_count": len(proposition),
                "maximum_proposition_characters": MAX_PROPOSITION_CHARACTERS,
            },
        )
    atomicity_reasons = non_atomic_material_claim_reasons(proposition)
    if atomicity_reasons:
        raise SemanticValidationError("structured_output_non_atomic_proposition")
    chunk_id = str(support.get("chunk_id") or "")
    span_id = str(support.get("span_id") or "")
    chunks = _chunk_map(row)
    if chunk_id not in chunks:
        raise SemanticValidationError("structured_output_invented_chunk")
    selected = chunks[chunk_id]
    chunk = selected["chunk"]
    source = selected["source"]
    if span_id not in selected["spans"]:
        raise SemanticValidationError("structured_output_invented_span")
    span_option = selected["spans"][span_id]
    exact_quote = str(span_option["exact_text"])
    offset = int(span_option["start_character"])
    supported_fact_ids = {
        fact.identity
        for fact in extract_material_facts(
            f"{exact_quote}\n{chunk.get('locator') or ''}"
        )
    }
    unsupported = [
        fact for fact in extract_material_facts(proposition) if fact.identity not in supported_fact_ids
    ]
    if unsupported:
        raise SemanticValidationError("structured_output_unsupported_material_fact")
    span = SimpleNamespace(text=exact_quote, locator=str(chunk.get("locator") or ""))
    if not is_substantively_related(proposition, span):
        raise SemanticValidationError("structured_output_unrelated_evidence")
    exact_span_material = {
        "schema": "legalbot.v111.phase2a.advisory-exact-span-binding.v1",
        "authority_identity_id": source["authority_identity_id"],
        "source_version_id": source["source_version_id"],
        "chunk_id": chunk_id,
        "chunk_text_sha256": chunk["text_sha256"],
        "span_id": span_id,
        "span_content_sha256": span_option["span_content_sha256"],
        "locator": chunk["locator"],
        "start_character": offset,
        "end_character_exclusive": span_option["end_character_exclusive"],
        "exact_text": exact_quote,
        "exact_text_sha256": span_option["exact_text_sha256"],
    }
    return {
        "row_id": row["row_id"],
        "assessment": f"{assessment}_EXACT_SPAN_ADVISORY",
        "atomic_proposition": proposition,
        "exact_span_binding": {
            **exact_span_material,
            "binding_content_sha256": _sealed(exact_span_material),
        },
        "source_currentness": {
            "as_of_date": source.get("as_of_date"),
            "currentness_status": source.get("currentness_status"),
            "candidate_source_metadata": source.get("candidate_source_metadata"),
            "already_in_sealed_candidate": bool(
                (source.get("candidate_source_metadata") or {}).get(
                    "already_in_sealed_candidate"
                )
            ),
            "proposition_level_source_admission_required_if_owner_approves": (
                (source.get("candidate_source_metadata") or {}).get(
                    "already_in_sealed_candidate"
                )
                is False
            ),
            "separate_currentness_or_later_treatment_review_still_required": True,
        },
        "selection_origin": source.get("selection_origin"),
        "projection_integrity": source.get("projection_integrity"),
        "deterministic_checks": {
            "exact_quote_bound": True,
            "precomputed_exact_span_id_bound": True,
            "model_reproduced_quote_text": False,
            "source_chunk_partition_complete": True,
            "atomicity_passed": True,
            "lexical_relatedness_screen_passed": True,
            "unsupported_material_fact_count": 0,
            "proposition_material_facts": _fact_records(proposition),
            "span_material_facts": _fact_records(
                f"{exact_quote}\n{chunk.get('locator') or ''}"
            ),
        },
        "owner_outcome": None,
        "owner_decision_required": True,
        "technical_qualification_assigned": False,
    }


def _validate_model_response(
    *, body: Mapping[str, Any], row_input: Mapping[str, Any], request_id: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if body.get("request_id") != request_id:
        raise SemanticValidationError("model_request_identity_mismatch")
    if body.get("model_version") != EXPECTED_MODEL_VERSION:
        raise SemanticValidationError("model_version_mismatch")
    if body.get("backend") != MODEL_BACKEND or body.get("deterministic") is not True:
        raise SemanticValidationError("model_runtime_identity_invalid")
    finish_reason = str(body.get("finish_reason") or "").casefold()
    if finish_reason in {"length", "max_tokens", "token_limit", "context_length", "truncated"}:
        raise SemanticValidationError("model_output_truncated")
    warnings = body.get("warnings")
    if not isinstance(warnings, list) or "stub_mode" in warnings:
        raise SemanticValidationError("model_warning_contract_invalid")
    peak = body.get("peak_memory_gb")
    if peak is not None and (
        isinstance(peak, bool)
        or not isinstance(peak, int | float)
        or float(peak) > MAX_PEAK_MEMORY_GB
    ):
        raise SemanticValidationError("model_peak_memory_exceeded")
    usage = body.get("usage")
    if not isinstance(usage, dict) or any(
        isinstance(usage.get(field), bool)
        or not isinstance(usage.get(field), int)
        or int(usage[field]) < 0
        for field in ("input_tokens", "output_tokens", "total_tokens")
    ):
        raise SemanticValidationError("model_usage_invalid")
    structured = body.get("structured")
    if not isinstance(structured, dict) or set(structured) != {"schema", "case_id", "rows"}:
        raise SemanticValidationError("structured_output_keys_invalid")
    if structured.get("schema") != OUTPUT_SCHEMA or structured.get("case_id") != row_input.get(
        "case_id"
    ):
        raise SemanticValidationError("structured_output_identity_invalid")
    supplied_rows = {str(row["row_id"]): row for row in row_input["rows"]}
    outputs = structured.get("rows")
    if not isinstance(outputs, list) or len(outputs) != len(supplied_rows):
        raise SemanticValidationError("structured_output_row_count_invalid")
    normalized: list[dict[str, Any]] = []
    observed: set[str] = set()
    for output in outputs:
        if not isinstance(output, dict) or set(output) != {
            "row_id",
            "assessment",
            "proposition",
            "support",
        }:
            raise SemanticValidationError("structured_output_row_keys_invalid")
        if not isinstance(output.get("row_id"), str):
            raise SemanticValidationError("structured_output_row_id_type_invalid")
        if not isinstance(output.get("assessment"), str):
            raise SemanticValidationError("structured_output_assessment_type_invalid")
        if not isinstance(output.get("proposition"), str):
            raise SemanticValidationError("structured_output_proposition_type_invalid")
        row_id = output["row_id"]
        assessment = output["assessment"]
        proposition = " ".join(output["proposition"].split())
        if row_id not in supplied_rows or row_id in observed:
            raise SemanticValidationError("structured_output_row_identity_invalid")
        observed.add(row_id)
        if assessment == "GAP":
            if proposition or output.get("support") is not None:
                raise SemanticValidationError("structured_output_gap_contract_invalid")
            normalized.append(
                {
                    "row_id": row_id,
                    "assessment": "MATERIAL_GAP_ADVISORY",
                    "atomic_proposition": None,
                    "exact_span_binding": None,
                    "gap_reason": "NO_DIRECT_SUPPORT_IN_SUPPLIED_EXACT_CHUNKS",
                    "owner_outcome": None,
                    "owner_decision_required": True,
                    "technical_qualification_assigned": False,
                }
            )
        elif assessment in {"DIRECT", "PARTIAL"}:
            normalized.append(
                _validate_supported_row(
                    row=supplied_rows[row_id],
                    assessment=assessment,
                    proposition=proposition,
                    support=output.get("support"),
                )
            )
        else:
            raise SemanticValidationError("structured_output_assessment_invalid")
    raw = str(body.get("raw_text") or "")
    return normalized, {
        "input_tokens": usage["input_tokens"],
        "output_tokens": usage["output_tokens"],
        "total_tokens": usage["total_tokens"],
        "generation_ms": body.get("generation_ms"),
        "time_to_first_token_ms": body.get("time_to_first_token_ms"),
        "peak_memory_gb": peak,
        "finish_reason": finish_reason,
        "raw_output_sha256": _sha256(raw.encode("utf-8")),
        "raw_output_character_count": len(raw),
    }


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, SemanticValidationError):
        return exc.code
    if isinstance(exc, RuntimeError | ValueError) and exc.args:
        value = str(exc.args[0]).casefold().replace("-", "_")
        if _SAFE_CODE.fullmatch(value):
            return value
    value = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    return value if _SAFE_CODE.fullmatch(value) else "phase2a_semantic_unknown_failure"


def _checkpoint_name(ordinal: int, rows: Sequence[Mapping[str, Any]]) -> str:
    row_ids = "\n".join(str(row["row_id"]) for row in rows)
    return f"{ordinal:03d}-{_sha256((row_ids + chr(10)).encode())[:24]}.json"


def _review_batch(
    *,
    ordinal: int,
    rows: Sequence[Mapping[str, Any]],
    case: Mapping[str, Any],
    invoke: Invoke,
    checkpoints_root: Path,
    diagnostics_root: Path,
    runtime_identity_sha256: str,
) -> dict[str, Any]:
    prior_error: str | None = None
    fingerprints: list[str] = []
    for attempt in (1, 2):
        row_input = _build_input(
            batch_ordinal=ordinal,
            rows=rows,
            case=case,
            repair_error_code=prior_error,
        )
        if _prompt_characters(row_input) > MAX_PROMPT_CHARACTERS:
            raise ValueError("phase2a_semantic_prompt_budget_exceeded_after_packing")
        input_sha256 = _sealed(row_input)
        envelope, request_id = _envelope(row_input)
        started = time.perf_counter()
        body: dict[str, Any] | None = None
        try:
            body = invoke(envelope)
            findings, metrics = _validate_model_response(
                body=body, row_input=row_input, request_id=request_id
            )
        except Exception as exc:
            error = _error_code(exc)
            validation_diagnostics = (
                dict(exc.diagnostics)
                if isinstance(exc, SemanticValidationError)
                else {}
            )
            fingerprint = _sealed(
                {
                    "schema": "legalbot.v111.phase2a.exact-span-failure-fingerprint.v1",
                    "batch_ordinal": ordinal,
                    "row_ids": [str(row["row_id"]) for row in rows],
                    "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode()),
                    "model_version": EXPECTED_MODEL_VERSION,
                    "runtime_identity_sha256": runtime_identity_sha256,
                    "error_code": error,
                }
            )
            fingerprints.append(fingerprint)
            diagnostic_material = {
                "schema": "legalbot.v111.phase2a.exact-span-rejected-attempt.v1",
                "batch_ordinal": ordinal,
                "row_ids": [str(row["row_id"]) for row in rows],
                "attempt": attempt,
                "input_content_sha256": input_sha256,
                "request_id": request_id,
                "error_code": error,
                "validation_diagnostics": validation_diagnostics,
                "failure_fingerprint": fingerprint,
                "runtime_identity_sha256": runtime_identity_sha256,
                "same_failure_fingerprint_as_prior_attempt": (
                    len(fingerprints) == 2 and fingerprints[0] == fingerprints[1]
                ),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "response_received": body is not None,
                "raw_output_sha256": (
                    _sha256(str(body.get("raw_text") or "").encode()) if body else None
                ),
                "raw_output_persisted": False,
                "hidden_reasoning_persisted": False,
                "owner_decision_assigned": False,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            diagnostic = {
                **diagnostic_material,
                "diagnostic_content_sha256": _sealed(diagnostic_material),
            }
            stem = _checkpoint_name(ordinal, rows)[:-5]
            _write_exclusive(
                diagnostics_root / f"{stem}-a{attempt}.json", _pretty_json(diagnostic)
            )
            prior_error = error
            if attempt == 1:
                continue
            held_material = {
                "schema": "legalbot.v111.phase2a.exact-span-held-batch.v1",
                "batch_ordinal": ordinal,
                "case_id": case["case_id"],
                "row_ids": [str(row["row_id"]) for row in rows],
                "status": "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT",
                "attempt_count": 2,
                "failure_fingerprints": fingerprints,
                "runtime_identity_sha256": runtime_identity_sha256,
                "same_failure_fingerprint_twice": fingerprints[0] == fingerprints[1],
                "debug_required_before_third_attempt": True,
                "raw_model_output_persisted": False,
                "hidden_reasoning_persisted": False,
                "owner_decision_assigned": False,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            held = {**held_material, "held_content_sha256": _sealed(held_material)}
            _write_exclusive(
                checkpoints_root / _checkpoint_name(ordinal, rows), _pretty_json(held)
            )
            return held
        checkpoint_material = {
            "schema": "legalbot.v111.phase2a.exact-span-checkpoint.v1",
            "batch_ordinal": ordinal,
            "case_id": case["case_id"],
            "row_ids": [str(row["row_id"]) for row in rows],
            "input_content_sha256": input_sha256,
            "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode()),
            "model_version": EXPECTED_MODEL_VERSION,
            "runtime_identity_sha256": runtime_identity_sha256,
            "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
            "attempt_count": attempt,
            "repaired_after_rejected_output": attempt == 2,
            "findings": findings,
            "model_metrics": metrics,
            "raw_model_output_persisted": False,
            "hidden_reasoning_persisted": False,
            "advisory_only": True,
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
            checkpoints_root / _checkpoint_name(ordinal, rows), _pretty_json(checkpoint)
        )
        return checkpoint
    raise AssertionError("unreachable exact-span attempt loop")


def _static_finding(row_id: str, *, assessment: str, reason: str) -> dict[str, Any]:
    return {
        "row_id": row_id,
        "assessment": assessment,
        "atomic_proposition": None,
        "exact_span_binding": None,
        "gap_reason": reason,
        "owner_outcome": None,
        "owner_decision_required": True,
        "technical_qualification_assigned": False,
    }


def _load_checkpoint(path: Path) -> dict[str, Any]:
    value = _load_object(path)
    if value.get("schema") == "legalbot.v111.phase2a.exact-span-checkpoint.v1":
        _verify_seal(value, "checkpoint_content_sha256", "exact_span_checkpoint_invalid")
    elif value.get("schema") == "legalbot.v111.phase2a.exact-span-held-batch.v1":
        _verify_seal(value, "held_content_sha256", "exact_span_held_invalid")
    else:
        raise ValueError("phase2a_semantic_checkpoint_schema_invalid")
    return value


def verify_exact_semantic_spans(
    *,
    locators_path: Path,
    plans_path: Path,
    remaining_path: Path,
    cases_path: Path,
    candidate_manifest_path: Path,
    output_root: Path,
    invoke: Invoke,
    runtime_identity: Mapping[str, Any],
    started_at: datetime,
    resume: bool = False,
) -> dict[str, Any]:
    """Build or resume the append-only exact-span advisory package."""

    if started_at.tzinfo is None:
        raise ValueError("phase2a_semantic_started_at_naive")
    runtime_identity_sha256 = _verify_seal(
        runtime_identity,
        "runtime_identity_sha256",
        "phase2a_semantic_runtime_identity_seal_invalid",
    )
    if (
        runtime_identity.get("schema")
        != "legalbot.v111.phase2a.exact-span-runtime-identity.v1"
        or runtime_identity.get("model_id") != EXPECTED_MODEL_ID
        or runtime_identity.get("expected_model_version") != EXPECTED_MODEL_VERSION
        or runtime_identity.get("model_independent_reviewer") is not False
    ):
        raise ValueError("phase2a_semantic_runtime_identity_invalid")
    issue_rows, issues_by_id, cases, planner_held, candidate_sources, hashes = _load_inputs(
        locators_path=locators_path,
        plans_path=plans_path,
        remaining_path=remaining_path,
        cases_path=cases_path,
        candidate_manifest_path=candidate_manifest_path,
    )
    locator_artifact = _load_object(locators_path)
    records_by_id = {
        str(record["row_id"]): record for record in locator_artifact["records"]
    }
    reviewable: list[dict[str, Any]] = []
    static_findings: dict[str, dict[str, Any]] = {
        row_id: _static_finding(
            row_id,
            assessment="HELD_UPSTREAM_PLANNER_ADVISORY",
            reason="UPSTREAM_AUTHORITY_PLANNER_HELD_FOR_DEBUG",
        )
        for row_id in planner_held
    }
    for issue in issue_rows:
        row_id = str(issue["item_id"])
        if row_id in static_findings:
            continue
        review_row = _review_row(issue, records_by_id[row_id], candidate_sources)
        if review_row is None:
            static_findings[row_id] = _static_finding(
                row_id,
                assessment="MATERIAL_GAP_ADVISORY",
                reason="NO_SEALED_CANDIDATE_EXACT_LOCATOR_CHUNK_RESOLVED",
            )
        else:
            reviewable.append(review_row)
    batches, oversized = _pack_batches(reviewable, cases)
    for row in oversized:
        static_findings[str(row["row_id"])] = _static_finding(
            str(row["row_id"]),
            assessment="HELD_CONTEXT_BUDGET_NO_TRUNCATION",
            reason="FULL_EXACT_CHUNK_INPUT_EXCEEDS_DETERMINISTIC_CONTEXT_BUDGET",
        )

    intent_path = output_root / "INTENT.json"
    if output_root.exists() or output_root.is_symlink():
        if not resume or output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("phase2a_semantic_output_already_exists")
        intent = _load_object(intent_path)
        _verify_seal(intent, "intent_content_sha256", "exact_span_intent_invalid")
        if (
            intent.get("source_locator_content_sha256") != hashes["locators"]
            or intent.get("source_plans_content_sha256") != hashes["plans"]
            or intent.get("source_remaining_content_sha256") != hashes["remaining"]
            or intent.get("source_candidate_manifest_sha256")
            != hashes["candidate_manifest"]
            or intent.get("source_candidate_manifest_file_sha256")
            != hashes["candidate_manifest_file"]
            or intent.get("prompt_sha256") != _sha256((SYSTEM_PROMPT + "\n").encode())
            or intent.get("verifier_code_file_sha256")
            != _sha256_file(VERIFIER_CODE_PATH)
            or intent.get("evidence_validator_code_file_sha256")
            != _sha256_file(EVIDENCE_VALIDATOR_CODE_PATH)
            or intent.get("runtime_identity_sha256") != runtime_identity_sha256
        ):
            raise ValueError("phase2a_semantic_resume_identity_mismatch")
    else:
        output_root.mkdir(parents=True, mode=0o700)
        if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
            raise ValueError("phase2a_semantic_output_mode_invalid")
        intent_material = {
            "schema": "legalbot.v111.phase2a.exact-span-intent.v4",
            "status": "ADVISORY_EXACT_SPAN_VERIFICATION_ONLY_NO_OWNER_DECISIONS",
            "started_at": started_at.astimezone(UTC).isoformat(timespec="seconds"),
            "source_locator_content_sha256": hashes["locators"],
            "source_locator_file_sha256": _sha256_file(locators_path),
            "source_plans_content_sha256": hashes["plans"],
            "source_remaining_content_sha256": hashes["remaining"],
            "source_candidate_manifest_sha256": hashes["candidate_manifest"],
            "source_candidate_manifest_file_sha256": hashes[
                "candidate_manifest_file"
            ],
            "sealed_candidate_source_count": len(candidate_sources),
            "sealed_candidate_sources_only": True,
            "noncandidate_and_unadmitted_sources_excluded": True,
            "source_cases_file_sha256": planner.EXPECTED_CASES_FILE_SHA256,
            "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode()),
            "verifier_code_file_sha256": _sha256_file(VERIFIER_CODE_PATH),
            "evidence_validator_code_file_sha256": _sha256_file(
                EVIDENCE_VALIDATOR_CODE_PATH
            ),
            "model_id": EXPECTED_MODEL_ID,
            "model_version": EXPECTED_MODEL_VERSION,
            "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
            "model_independent_reviewer": False,
            "runtime_identity_sha256": runtime_identity_sha256,
            "runtime_identity": dict(runtime_identity),
            "independent_reranker_completed_separately": True,
            "issue_count": EXPECTED_ISSUE_COUNT,
            "model_batch_count": len(batches),
            "maximum_rows_per_batch": BATCH_SIZE,
            "maximum_evidence_candidates_per_row": (
                MAX_REVIEW_EVIDENCE_CANDIDATES_PER_ROW
            ),
            "maximum_whole_chunks_per_evidence_candidate": (
                MAX_REVIEW_WHOLE_CHUNKS_PER_CANDIDATE
            ),
            "maximum_prompt_characters": MAX_PROMPT_CHARACTERS,
            "maximum_output_tokens": MAX_OUTPUT_TOKENS,
            "model_output_schema": OUTPUT_SCHEMA,
            "whole_source_chunks_exhaustively_partitioned": True,
            "model_selects_precomputed_exact_span_id": True,
            "model_reproduces_quote_text": False,
            "silent_context_truncation": False,
            "scenario_text_supplied_for_issue_scope_disambiguation": True,
            "scenario_answering_and_fact_application_forbidden": True,
            "scenario_identity_preserved_by_sha256": True,
            "scenario_aware_prior_selection_preferred_over_issue_label_only_recovery": True,
            "maximum_attempts_per_batch": 2,
            "debug_required_before_any_third_attempt": True,
            "raw_model_output_persisted": False,
            "hidden_reasoning_persisted": False,
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
    final_path = output_root / "ADVISORY-EXACT-SEMANTIC-SPANS-448.json"
    if final_path.exists():
        raise ValueError("phase2a_semantic_already_finalized")

    results: list[dict[str, Any]] = []
    for ordinal, batch in enumerate(batches, start=1):
        checkpoint_path = checkpoints_root / _checkpoint_name(ordinal, batch)
        if checkpoint_path.exists():
            if not resume:
                raise ValueError("phase2a_semantic_checkpoint_exists_without_resume")
            results.append(_load_checkpoint(checkpoint_path))
            continue
        case_id = str(batch[0]["row_id"]).split(":", 1)[0]
        results.append(
            _review_batch(
                ordinal=ordinal,
                rows=batch,
                case=cases[case_id],
                invoke=invoke,
                checkpoints_root=checkpoints_root,
                diagnostics_root=diagnostics_root,
                runtime_identity_sha256=runtime_identity_sha256,
            )
        )

    findings_by_id = dict(static_findings)
    held_batches: list[dict[str, Any]] = []
    for result in results:
        if result.get("schema") == "legalbot.v111.phase2a.exact-span-held-batch.v1":
            held_batches.append(result)
            for row_id in result["row_ids"]:
                findings_by_id[str(row_id)] = _static_finding(
                    str(row_id),
                    assessment="HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT",
                    reason="TWO_MODEL_OUTPUT_ATTEMPTS_REJECTED",
                )
        else:
            for finding in result["findings"]:
                row_id = str(finding["row_id"])
                if row_id in findings_by_id:
                    raise ValueError("phase2a_semantic_duplicate_finding")
                findings_by_id[row_id] = dict(finding)
    issue_order = [str(row["item_id"]) for row in issue_rows]
    if set(findings_by_id) != set(issue_order):
        raise ValueError("phase2a_semantic_final_coverage_invalid")
    findings = [findings_by_id[row_id] for row_id in issue_order]
    counts = Counter(str(finding["assessment"]) for finding in findings)
    final_material = {
        "schema": "legalbot.v111.phase2a.advisory-exact-semantic-spans-448.v4",
        "status": "ADVISORY_EXACT_SPAN_REVIEW_COMPLETE_OWNER_DECISIONS_REQUIRED",
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_locator_content_sha256": hashes["locators"],
        "source_plans_content_sha256": hashes["plans"],
        "source_remaining_content_sha256": hashes["remaining"],
        "source_candidate_manifest_sha256": hashes["candidate_manifest"],
        "source_candidate_manifest_file_sha256": hashes[
            "candidate_manifest_file"
        ],
        "sealed_candidate_sources_only": True,
        "noncandidate_and_unadmitted_sources_excluded": True,
        "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
        "model_independent_reviewer": False,
        "runtime_identity_sha256": runtime_identity_sha256,
        "independent_reranker_completed_separately": True,
        "issue_count": EXPECTED_ISSUE_COUNT,
        "assessment_counts": dict(sorted(counts.items())),
        "held_batch_count": len(held_batches),
        "held_batch_content_sha256s": [
            str(batch["held_content_sha256"]) for batch in held_batches
        ],
        "findings": findings,
        "raw_model_output_persisted": False,
        "hidden_reasoning_persisted": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    final = {**final_material, "artifact_content_sha256": _sealed(final_material)}
    _write_exclusive(final_path, _pretty_json(final))
    outcome = (
        "ADVISORY EXACT-SPAN REVIEW COMPLETE FOR 448 ISSUES. "
        "ALL SUBSTANTIVE OWNER DECISIONS REMAIN REQUIRED. "
        "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED.\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    names = ["INTENT.json", "ADVISORY-EXACT-SEMANTIC-SPANS-448.json", "OUTCOME.txt"]
    sums = "".join(f"{_sha256_file(output_root / name)}  {name}\n" for name in names)
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode())
    return final


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--locators", type=Path, default=DEFAULT_LOCATORS)
    parser.add_argument("--plans", type=Path, default=DEFAULT_PLANS)
    parser.add_argument("--remaining", type=Path, default=DEFAULT_REMAINING)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument(
        "--candidate-manifest", type=Path, default=DEFAULT_CANDIDATE_MANIFEST
    )
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model-url", default="http://127.0.0.1:8779")
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    invoke, runtime_identity = _http_invoker(args.model_url, args.timeout_seconds)
    result = verify_exact_semantic_spans(
        locators_path=args.locators,
        plans_path=args.plans,
        remaining_path=args.remaining,
        cases_path=args.cases,
        candidate_manifest_path=args.candidate_manifest,
        output_root=args.output_root,
        invoke=invoke,
        runtime_identity=runtime_identity,
        started_at=datetime.now(UTC),
        resume=args.resume,
    )
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "status": result["status"],
                "assessment_counts": result["assessment_counts"],
                "held_batch_count": result["held_batch_count"],
                "artifact_content_sha256": result["artifact_content_sha256"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
