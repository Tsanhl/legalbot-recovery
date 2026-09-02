"""Canonical retrieval v1.1 scorer: stable authority + legal locator/span.

The module name is retained for import compatibility.  The only current pack
is ``benchmarks/retrieval/v1.1.jsonl``.  Behaviour/refusal tests live in A2.
This module never writes ACTIVE.json and never calls the answer model.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from datetime import date
from pathlib import Path
from typing import Any, cast

import yaml  # type: ignore[import-untyped]  # PyYAML does not ship inline typing.

from ..config import PROJECT_ROOT, Settings
from ..currentness import LEGISLATION_SOURCE_TYPES
from ..db import Database, utc_iso
from ..ingestion.models import MaterialLane
from ..privacy import contains_absolute_private_path
from .admission import ADMISSION_VERSION
from .candidate_qualification import load_candidate_provision_qualifications
from .explicit_reference import (
    EXPLICIT_REFERENCE_VERSION,
    CandidateLegislationReferenceResolver,
    legislation_locator_within,
)
from .ge_generic_read_guard import require_generic_index_read_allowed
from .hybrid import HybridRetriever
from .models import QueryFilters, SearchHit, SearchQuery
from .service import (
    PHYSICAL_AUTHORITY_LANE,
    TEST_EMBEDDING_MODEL,
    TEST_RERANKER_MODEL,
    _embedding_provider,
    _import_lancedb,
    _LanceLexicalBackend,
    _LanceVectorBackend,
    _production_embedding_identity,
    _production_reranker_identity,
    _query_exact_jurisdictions,
    _query_jurisdictions,
    _reranker_provider,
    _sql_text,
)
from .source_manifest import MANIFEST_SCHEMA, approved_source_manifest_sha256

FROZEN_JSONL_RELATIVE = "benchmarks/retrieval/v1.1.jsonl"
FREEZE_MANIFEST_RELATIVE = "benchmarks/retrieval/v1.1.freeze.json"
FREEZE_MANIFEST_SCHEMA = "legalbot.retrieval-freeze.v1.1"
REPORT_SCHEMA = "legalbot.offline-retrieval.v1.1"
BENCHMARK_CANDIDATE_LIMIT = 20
BENCHMARK_RESULT_LIMIT = 10
BENCHMARK_RERANK_CANDIDATE_LIMIT = 40
POLICY_RELATIVE = "config/retrieval_policy.yaml"
SCORER_IMPLEMENTATION_FILES = (
    "backend/app/retrieval/retrieval_v1.py",
    "backend/app/retrieval/hybrid.py",
    "backend/app/retrieval/admission.py",
    "backend/app/retrieval/explicit_reference.py",
    "backend/app/retrieval/service.py",
)
FORBIDDEN_LANES = frozenset({"private_teaching", "assessment_guidance"})
CURRENT_SNAPSHOT_MARKER = ":latest-available@"
CANDIDATE_BINDING_SCHEMA = "legalbot.retrieval-candidate-binding.v1"


class FrozenBenchmarkMismatchError(RuntimeError):
    """The benchmark bytes no longer match the owner freeze."""


class BenchmarkNotFrozenError(RuntimeError):
    """The 24-row v1.1 pack has no valid owner freeze."""


class CandidateGoldBindingError(RuntimeError):
    """Frozen legal gold cannot be bound safely to one candidate version."""

    def __init__(self, report: Mapping[str, Any]) -> None:
        self.report = dict(report)
        issues = self.report.get("issues")
        count = len(issues) if isinstance(issues, list) else 0
        super().__init__(f"candidate cannot bind frozen retrieval gold ({count} issue(s))")


def load_retrieval_policy(project_root: Path = PROJECT_ROOT) -> tuple[dict[str, Any], str]:
    path = project_root / POLICY_RELATIVE
    raw = path.read_bytes()
    policy = yaml.safe_load(raw)
    if not isinstance(policy, dict) or policy.get("schema") != "legalbot.retrieval-policy.v1":
        raise RuntimeError("retrieval policy is invalid")
    if policy.get("positive_ranking_only") is not True:
        raise RuntimeError("retrieval benchmark must contain ranking cases only")
    return cast(dict[str, Any], policy), hashlib.sha256(raw).hexdigest()


def scorer_implementation_sha256(project_root: Path = PROJECT_ROOT) -> str:
    digest = hashlib.sha256()
    for relative in SCORER_IMPLEMENTATION_FILES:
        encoded = relative.encode("utf-8")
        payload = (project_root / relative).read_bytes()
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def parse_locators(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(part.strip() for part in str(value).split(";") if part.strip())


def verify_jsonl_sha256(path: Path, expected_sha256: str) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected_sha256:
        raise FrozenBenchmarkMismatchError(
            f"retrieval benchmark SHA-256 is {digest}, expected {expected_sha256}"
        )
    return digest


def load_retrieval_v1_jsonl(path: Path, expected_sha256: str) -> list[dict[str, Any]]:
    verify_jsonl_sha256(path, expected_sha256)
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    _validate_rows(rows)
    return rows


def _validate_rows(rows: Sequence[Mapping[str, Any]]) -> None:
    if len(rows) != 24 or len({str(row.get("id")) for row in rows}) != 24:
        raise ValueError("retrieval v1.1 must contain exactly 24 unique cases")
    if sum(row.get("split") == "development" for row in rows) != 16:
        raise ValueError("retrieval v1.1 must contain 16 development cases")
    if sum(row.get("split") == "promotion" for row in rows) != 8:
        raise ValueError("retrieval v1.1 must contain 8 promotion cases")
    allowed_modes = {"source_identity_only", "source_and_locator", "source_and_span"}
    for row in rows:
        if row.get("expected_behavior") != "retrieve_authority":
            raise ValueError("behaviour/abstention cases belong in A2, not retrieval v1.1")
        mode = row.get("match_mode")
        if mode not in allowed_modes:
            raise ValueError(f"retrieval case {row.get('id')} has invalid match_mode")
        if not row.get("expected_source_id") or not row.get("expected_source_version_id"):
            raise ValueError(f"retrieval case {row.get('id')} has no immutable source gold")
        if mode == "source_identity_only":
            if not str(row.get("query") or "").lstrip().startswith("["):
                query = str(row.get("query") or "").casefold()
                expected = str(row.get("expected_source_id") or "").casefold()
                neutral = expected.removeprefix("neutral-citation:")
                if "locate" not in query or neutral not in query:
                    raise ValueError(
                        "source_identity_only is reserved for explicit authority identifiers"
                    )
            if row.get("legal_locator") or row.get("proposition_span_sha256"):
                raise ValueError(
                    "identity-only gold must not contain a locator or proposition span"
                )
        elif not row.get("legal_locator"):
            raise ValueError(f"retrieval case {row.get('id')} has no legal locator")
        gold_spans = row.get("gold_spans")
        if not isinstance(gold_spans, list):
            raise ValueError(f"retrieval case {row.get('id')} has no exact gold-span list")
        span_hashes: list[str] = []
        for span in gold_spans:
            if not isinstance(span, Mapping):
                raise ValueError(f"retrieval case {row.get('id')} has malformed gold spans")
            digest = str(span.get("span_sha256") or "")
            if len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                raise ValueError(f"retrieval case {row.get('id')} has an invalid gold-span hash")
            if str(span.get("legal_locator") or "") not in parse_locators(row.get("legal_locator")):
                raise ValueError(
                    f"retrieval case {row.get('id')} has a gold span outside its locator"
                )
            if not str(span.get("proposition") or "").strip():
                raise ValueError(f"retrieval case {row.get('id')} has an unlabelled gold span")
            span_hashes.append(digest)
        if len(span_hashes) != len(set(span_hashes)):
            raise ValueError(f"retrieval case {row.get('id')} has duplicate gold spans")
        if mode == "source_identity_only" and span_hashes:
            raise ValueError("identity-only gold must not contain proposition spans")
        if mode != "source_identity_only" and not span_hashes:
            raise ValueError(f"retrieval case {row.get('id')} has no exact supporting spans")
        if mode == "source_and_span":
            primary = str(row.get("proposition_span_sha256") or "")
            if len(primary) != 64 or primary not in span_hashes:
                raise ValueError(
                    f"retrieval case {row.get('id')} has no exact primary span in its gold bundle"
                )
        elif row.get("proposition_span_sha256"):
            raise ValueError(
                f"retrieval case {row.get('id')} uses locator scoring but has a primary span"
            )


def verify_owner_freeze(project_root: Path, jsonl_path: Path) -> dict[str, Any]:
    freeze_path = project_root / FREEZE_MANIFEST_RELATIVE
    if not freeze_path.is_file():
        raise BenchmarkNotFrozenError(
            "retrieval v1.1 is provisional: benchmarks/retrieval/v1.1.freeze.json is absent"
        )
    try:
        freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkNotFrozenError("retrieval v1.1 freeze manifest is unreadable") from exc
    policy, policy_sha256 = load_retrieval_policy(project_root)
    if (
        freeze.get("schema") != FREEZE_MANIFEST_SCHEMA
        or freeze.get("status") != "owner_frozen"
        or freeze.get("frozen_splits") != ["development", "promotion"]
        or int(freeze.get("row_count") or 0) != 24
        or freeze.get("retrieval_policy_sha256") != policy_sha256
        or freeze.get("scorer_version") != policy.get("scorer")
    ):
        raise BenchmarkNotFrozenError("retrieval v1.1 freeze manifest is incomplete or invalid")
    expected = str(freeze.get("jsonl_sha256") or "")
    if len(expected) != 64:
        raise BenchmarkNotFrozenError("retrieval v1.1 freeze has no JSONL SHA-256")
    rows = load_retrieval_v1_jsonl(jsonl_path, expected)
    if any(
        row.get("owner_review_status") != "frozen"
        or row.get("legal_confirmation_needed") is not False
        for row in rows
    ):
        raise BenchmarkNotFrozenError("retrieval v1.1 still contains provisional legal gold")
    if freeze.get("case_ids") != [str(row["id"]) for row in rows]:
        raise BenchmarkNotFrozenError("retrieval v1.1 freeze case IDs do not match")
    for path_key, sha_key in (
        ("owner_decision_path", "owner_decision_sha256"),
        ("fact_check_path", "fact_check_sha256"),
    ):
        relative = Path(str(freeze.get(path_key) or ""))
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise BenchmarkNotFrozenError(f"retrieval v1.1 freeze has an unsafe {path_key}")
        record_path = project_root / relative
        if not record_path.is_file():
            raise BenchmarkNotFrozenError(f"retrieval v1.1 freeze is missing {path_key}")
        actual = hashlib.sha256(record_path.read_bytes()).hexdigest()
        if actual != str(freeze.get(sha_key) or ""):
            raise BenchmarkNotFrozenError(f"retrieval v1.1 freeze {path_key} digest mismatch")
    return cast(dict[str, Any], freeze)


def _candidate_binding_report(
    *,
    build_id: str,
    benchmark_sha256: str,
    manifest_sha256: str,
    provision_registry_sha256: str,
    qualification_successor_sha256: str | None,
    current_law_as_of_date: str | None,
    bindings: Sequence[Mapping[str, Any]],
    issues: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": CANDIDATE_BINDING_SCHEMA,
        "build_id": build_id,
        "benchmark_sha256": benchmark_sha256,
        "candidate_source_manifest_sha256": manifest_sha256,
        "candidate_provision_registry_sha256": provision_registry_sha256,
        "candidate_qualification_successor_sha256": qualification_successor_sha256,
        "candidate_current_law_as_of_date": current_law_as_of_date,
        "row_count": len(bindings),
        "status": "bound" if not issues else "blocked",
        "frozen_benchmark_mutated": False,
        "bindings": [dict(value) for value in bindings],
        "issues": [dict(value) for value in issues],
    }


def bind_frozen_rows_to_candidate(
    rows: Sequence[Mapping[str, Any]],
    *,
    build_id: str,
    benchmark_sha256: str,
    candidate_manifest: Mapping[str, Any],
    candidate_manifest_sha256: str,
    candidate_chunks: Sequence[Mapping[str, Any]],
    provision_registry: Mapping[str, Any],
    provision_registry_sha256: str,
    supplemental_provisions: Mapping[tuple[str, str], Mapping[str, Any]] | None = None,
    supplemental_provisions_sha256: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Resolve frozen authority/locator/span gold to one immutable candidate.

    The owner-frozen rows remain untouched.  Legislation may roll from one
    ``latest-available`` snapshot to another only when the candidate contains
    the same exact frozen spans *and* the candidate's sealed provision registry
    qualifies every relied-on locator.  Any changed or unreviewed proposition
    fails closed instead of being silently rebound.
    """

    sources_value = candidate_manifest.get("sources")
    if (
        candidate_manifest.get("schema") != MANIFEST_SCHEMA
        or candidate_manifest.get("authority_lane_only") is not True
        or candidate_manifest.get("benchmark_answers_used_for_selection") is not False
        or not isinstance(sources_value, list)
    ):
        raise CandidateGoldBindingError(
            _candidate_binding_report(
                build_id=build_id,
                benchmark_sha256=benchmark_sha256,
                manifest_sha256=candidate_manifest_sha256,
                provision_registry_sha256=provision_registry_sha256,
                qualification_successor_sha256=supplemental_provisions_sha256,
                current_law_as_of_date=None,
                bindings=(),
                issues=({"code": "candidate_source_manifest_invalid"},),
            )
        )
    sources = [value for value in sources_value if isinstance(value, Mapping)]
    by_authority: dict[str, list[Mapping[str, Any]]] = {}
    for source in sources:
        by_authority.setdefault(str(source.get("authority_identity_id") or ""), []).append(source)

    chunk_inventory: dict[tuple[str, str, str], set[str]] = {}
    chunk_count_by_version: dict[tuple[str, str], int] = {}
    for chunk in candidate_chunks:
        stable_id = str(chunk.get("source_identity") or "")
        source_version_id = str(chunk.get("source_version_id") or "")
        locator = str(chunk.get("locator") or "")
        digest = str(chunk.get("content_sha256") or "")
        if not stable_id or not source_version_id or not locator or len(digest) != 64:
            continue
        chunk_inventory.setdefault((stable_id, source_version_id, locator), set()).add(digest)
        key = (stable_id, source_version_id)
        chunk_count_by_version[key] = chunk_count_by_version.get(key, 0) + 1

    records_value = provision_registry.get("records")
    provision_records: dict[tuple[str, str], Mapping[str, Any]] = {}
    if isinstance(records_value, list):
        for record in records_value:
            if not isinstance(record, Mapping):
                continue
            key = (
                str(record.get("stable_source_id") or ""),
                str(record.get("legal_locator") or ""),
            )
            if all(key) and key not in provision_records:
                provision_records[key] = record
    for key, record in (supplemental_provisions or {}).items():
        if key in provision_records:
            if dict(provision_records[key]) != dict(record):
                raise CandidateGoldBindingError(
                    _candidate_binding_report(
                        build_id=build_id,
                        benchmark_sha256=benchmark_sha256,
                        manifest_sha256=candidate_manifest_sha256,
                        provision_registry_sha256=provision_registry_sha256,
                        qualification_successor_sha256=supplemental_provisions_sha256,
                        current_law_as_of_date=str(
                            candidate_manifest.get("current_law_as_of_date") or ""
                        )
                        or None,
                        bindings=(),
                        issues=({"code": "candidate_qualification_successor_conflict"},),
                    )
                )
            continue
        provision_records[key] = record

    current_law_as_of_date = str(candidate_manifest.get("current_law_as_of_date") or "") or None
    bindings: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    bound_rows: list[dict[str, Any]] = []
    for frozen_row in rows:
        case_id = str(frozen_row.get("id") or "")
        authority_id = str(frozen_row.get("expected_authority_id") or "")
        frozen_source_id = str(frozen_row.get("expected_source_id") or "")
        frozen_source_version_id = str(frozen_row.get("expected_source_version_id") or "")
        mode = str(frozen_row.get("match_mode") or "")
        source_type = str(frozen_row.get("source_type") or "")
        candidates = by_authority.get(authority_id, [])
        row_issues: list[dict[str, Any]] = []
        bound_source_id: str
        bound_version_ids: tuple[str, ...]
        selected_source: Mapping[str, Any]

        if not candidates:
            row_issues.append(
                {
                    "case_id": case_id,
                    "code": "expected_authority_missing",
                    "expected_authority_id": authority_id,
                }
            )
            issues.extend(row_issues)
            continue

        if source_type in LEGISLATION_SOURCE_TYPES:
            if len(candidates) != 1:
                row_issues.append(
                    {
                        "case_id": case_id,
                        "code": "candidate_authority_version_ambiguous",
                        "expected_authority_id": authority_id,
                        "candidate_count": len(candidates),
                    }
                )
            selected_source = candidates[0]
            bound_source_id = str(selected_source.get("stable_identifier") or "")
            bound_version_ids = (str(selected_source.get("source_version_id") or ""),)
            expected_suffix = (
                f"{CURRENT_SNAPSHOT_MARKER}{current_law_as_of_date}"
                if current_law_as_of_date
                else ""
            )
            if (
                not expected_suffix
                or not bound_source_id.endswith(expected_suffix)
                or _authority_stem(bound_source_id) != authority_id
            ):
                row_issues.append(
                    {
                        "case_id": case_id,
                        "code": "candidate_current_version_invalid",
                        "expected_authority_id": authority_id,
                        "candidate_source_id": bound_source_id,
                        "candidate_as_of_date": current_law_as_of_date,
                    }
                )
        else:
            exact_sources = [
                source
                for source in candidates
                if str(source.get("stable_identifier") or "") == frozen_source_id
            ]
            if not exact_sources:
                row_issues.append(
                    {
                        "case_id": case_id,
                        "code": "immutable_case_version_missing",
                        "expected_authority_id": authority_id,
                        "frozen_source_id": frozen_source_id,
                    }
                )
                selected_source = candidates[0]
                exact_sources = [selected_source]
            selected_source = exact_sources[0]
            bound_source_id = str(selected_source.get("stable_identifier") or "")
            bound_version_ids = tuple(
                sorted(str(value.get("source_version_id") or "") for value in exact_sources)
            )
            if frozen_source_version_id not in bound_version_ids:
                row_issues.append(
                    {
                        "case_id": case_id,
                        "code": "immutable_case_source_version_missing",
                        "expected_authority_id": authority_id,
                        "frozen_source_version_id": frozen_source_version_id,
                    }
                )

        bound_version_ids = tuple(value for value in bound_version_ids if value)
        if not bound_source_id or not bound_version_ids:
            row_issues.append(
                {
                    "case_id": case_id,
                    "code": "candidate_source_version_missing",
                    "expected_authority_id": authority_id,
                }
            )
        if not any(
            chunk_count_by_version.get((bound_source_id, source_version_id), 0) > 0
            for source_version_id in bound_version_ids
        ):
            row_issues.append(
                {
                    "case_id": case_id,
                    "code": "candidate_source_has_no_chunks",
                    "expected_authority_id": authority_id,
                    "candidate_source_id": bound_source_id,
                }
            )

        locators = parse_locators(cast(str | None, frozen_row.get("legal_locator")))
        if source_type in LEGISLATION_SOURCE_TYPES:
            source_content_sha256 = str(selected_source.get("content_sha256") or "")
            source_version_sha256 = str(selected_source.get("version_sha256") or "")
            for locator in locators:
                record = provision_records.get((bound_source_id, locator))
                if (
                    record is None
                    or record.get("source_content_sha256") != source_content_sha256
                    or record.get("source_version_sha256") != source_version_sha256
                    or "E+W" not in str(record.get("verified_extent") or "")
                ):
                    row_issues.append(
                        {
                            "case_id": case_id,
                            "code": "candidate_provision_not_qualified",
                            "expected_authority_id": authority_id,
                            "candidate_source_id": bound_source_id,
                            "legal_locator": locator,
                        }
                    )

        missing_spans: list[dict[str, str]] = []
        if mode != "source_identity_only":
            spans = frozen_row.get("gold_spans")
            for gold in spans if isinstance(spans, list) else []:
                if not isinstance(gold, Mapping):
                    continue
                locator = str(gold.get("legal_locator") or "")
                digest = str(gold.get("span_sha256") or "")
                present = any(
                    digest in chunk_digests
                    for (source_id, source_version_id, candidate_locator), chunk_digests in (
                        chunk_inventory.items()
                    )
                    if source_id == bound_source_id
                    and source_version_id in bound_version_ids
                    and (
                        candidate_locator == locator
                        or (
                            source_type in LEGISLATION_SOURCE_TYPES
                            and legislation_locator_within(candidate_locator, locator)
                        )
                    )
                )
                if not present:
                    missing_spans.append({"legal_locator": locator, "span_sha256": digest})
            if missing_spans:
                row_issues.append(
                    {
                        "case_id": case_id,
                        "code": "frozen_gold_span_missing_in_candidate",
                        "expected_authority_id": authority_id,
                        "candidate_source_id": bound_source_id,
                        "missing_spans": missing_spans,
                    }
                )

        binding = {
            "case_id": case_id,
            "expected_authority_id": authority_id,
            "match_mode": mode,
            "legal_locator": frozen_row.get("legal_locator"),
            "frozen_source_id": frozen_source_id,
            "frozen_source_version_id": frozen_source_version_id,
            "candidate_source_id": bound_source_id,
            "candidate_source_version_ids": list(bound_version_ids),
            "candidate_selected_source_version_id": (
                bound_version_ids[0]
                if source_type in LEGISLATION_SOURCE_TYPES
                else frozen_source_version_id
            ),
            "candidate_as_of_date": current_law_as_of_date,
            "status": "bound" if not row_issues else "blocked",
        }
        bindings.append(binding)
        if row_issues:
            issues.extend(row_issues)
            continue

        bound = dict(frozen_row)
        bound["expected_source_id"] = bound_source_id
        bound["expected_source_version_id"] = binding["candidate_selected_source_version_id"]
        bound["frozen_expected_source_id"] = frozen_source_id
        bound["frozen_expected_source_version_id"] = frozen_source_version_id
        bound["candidate_binding"] = binding
        bound_rows.append(bound)

    report = _candidate_binding_report(
        build_id=build_id,
        benchmark_sha256=benchmark_sha256,
        manifest_sha256=candidate_manifest_sha256,
        provision_registry_sha256=provision_registry_sha256,
        qualification_successor_sha256=supplemental_provisions_sha256,
        current_law_as_of_date=current_law_as_of_date,
        bindings=bindings,
        issues=issues,
    )
    if issues or len(bound_rows) != len(rows):
        raise CandidateGoldBindingError(report)
    return bound_rows, report


def _candidate_chunk_rows(
    build_path: Path,
    manifest: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    require_generic_index_read_allowed(
        build_path,
        expected_build_id=build_path.name,
    )
    authority_ids = {str(row.get("expected_authority_id") or "") for row in rows}
    raw_sources = manifest.get("sources")
    sources = raw_sources if isinstance(raw_sources, list) else []
    stable_limits: dict[str, int] = {}
    for source in sources:
        if not isinstance(source, Mapping):
            continue
        if str(source.get("authority_identity_id") or "") not in authority_ids:
            continue
        stable_id = str(source.get("stable_identifier") or "")
        stable_limits[stable_id] = stable_limits.get(stable_id, 0) + int(
            source.get("body_chunk_count") or 0
        )
    module = _import_lancedb()
    authority = build_path / "lance" / PHYSICAL_AUTHORITY_LANE
    if not authority.exists():
        authority = build_path / "lance"
    table = module.connect(str(authority)).open_table("chunks")
    output: list[dict[str, Any]] = []
    for stable_id, expected_count in sorted(stable_limits.items()):
        values = (
            table.search()
            .where(f"source_identity = '{_sql_text(stable_id)}'")
            .select(["source_identity", "source_version_id", "locator", "content_sha256"])
            .limit(max(1, expected_count + 1))
            .to_list()
        )
        output.extend(dict(value) for value in values)
    return output


def bind_retrieval_rows_to_candidate(
    build_path: Path,
    rows: Sequence[Mapping[str, Any]],
    *,
    build_id: str,
    benchmark_sha256: str,
    project_root: Path | None = None,
    qualification_path: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    require_generic_index_read_allowed(
        build_path,
        expected_build_id=build_id,
    )
    manifest_path = build_path / "approved-source-manifest.json"
    provision_path = build_path / "provision-verification.v1.json"
    seal_path = build_path / "seal.json"
    if not manifest_path.is_file() or not provision_path.is_file() or not seal_path.is_file():
        raise CandidateGoldBindingError(
            _candidate_binding_report(
                build_id=build_id,
                benchmark_sha256=benchmark_sha256,
                manifest_sha256="",
                provision_registry_sha256="",
                qualification_successor_sha256=None,
                current_law_as_of_date=None,
                bindings=(),
                issues=({"code": "candidate_binding_artifact_missing"},),
            )
        )
    manifest_raw = manifest_path.read_bytes()
    provision_raw = provision_path.read_bytes()
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_raw)
    provision_registry = json.loads(provision_raw)
    manifest_file_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    provision_sha256 = hashlib.sha256(provision_raw).hexdigest()
    if (
        not isinstance(seal, dict)
        or not isinstance(manifest, dict)
        or not isinstance(provision_registry, dict)
        or seal.get("source_manifest_file_sha256") != manifest_file_sha256
        or seal.get("provision_verification_sha256") != provision_sha256
        or manifest.get("manifest_sha256") != approved_source_manifest_sha256(manifest)
        or manifest.get("provision_verification_sha256") != provision_sha256
    ):
        raise CandidateGoldBindingError(
            _candidate_binding_report(
                build_id=build_id,
                benchmark_sha256=benchmark_sha256,
                manifest_sha256=manifest_file_sha256,
                provision_registry_sha256=provision_sha256,
                qualification_successor_sha256=None,
                current_law_as_of_date=str(manifest.get("current_law_as_of_date") or "") or None,
                bindings=(),
                issues=({"code": "candidate_binding_artifact_digest_mismatch"},),
            )
        )
    supplemental: dict[tuple[str, str], dict[str, Any]] = {}
    supplemental_sha256: str | None = None
    if project_root is not None:
        supplemental, supplemental_sha256 = load_candidate_provision_qualifications(
            project_root,
            build_path=build_path,
            build_id=build_id,
            qualification_path=qualification_path,
        )
    chunks = _candidate_chunk_rows(build_path, manifest, rows)
    return bind_frozen_rows_to_candidate(
        rows,
        build_id=build_id,
        benchmark_sha256=benchmark_sha256,
        candidate_manifest=manifest,
        candidate_manifest_sha256=manifest_file_sha256,
        candidate_chunks=chunks,
        provision_registry=provision_registry,
        provision_registry_sha256=provision_sha256,
        supplemental_provisions=supplemental,
        supplemental_provisions_sha256=supplemental_sha256,
    )


def _hit_locator(hit: SearchHit) -> str:
    return str(hit.chunk.metadata.get("locator") or "").strip()


def _hit_lane(hit: SearchHit) -> str:
    return str(hit.chunk.metadata.get("catalog_lane") or hit.chunk.material_lane.value)


def _hit_currentness(hit: SearchHit) -> str:
    return str(hit.chunk.metadata.get("currentness_status") or "").casefold()


def _hit_canonical_span_sha256(hit: SearchHit) -> str:
    """Return immutable canonical gold, not the mutable prompt-safe view hash."""

    return str(
        hit.chunk.metadata.get("canonical_chunk_sha256")
        or hit.chunk.metadata.get("canonical_span_sha256")
        or hit.chunk.content_sha256
    )


def _gold_span_hashes(row: Mapping[str, Any]) -> tuple[str, ...]:
    spans = row.get("gold_spans")
    if isinstance(spans, list):
        values = tuple(
            str(span.get("span_sha256") or "")
            for span in spans
            if isinstance(span, Mapping) and span.get("span_sha256")
        )
        if values:
            return values
    primary = str(row.get("proposition_span_sha256") or "")
    return (primary,) if primary else ()


def _authority_stem(value: str) -> str:
    if CURRENT_SNAPSHOT_MARKER in value:
        return value.split(CURRENT_SNAPSHOT_MARKER, 1)[0]
    return value.removesuffix(":enacted")


def score_query_hits(
    row: Mapping[str, Any],
    hits: Sequence[SearchHit],
    *,
    k3: int = 3,
    k5: int = 5,
    k10: int = 10,
) -> dict[str, Any]:
    gold_source = str(row.get("expected_source_id") or "")
    gold_locators = parse_locators(row.get("legal_locator"))
    gold_hash = str(row.get("proposition_span_sha256") or "")
    gold_span_hashes = _gold_span_hashes(row)
    mode = str(row.get("match_mode") or "")
    legislation = str(row.get("source_type") or "") in LEGISLATION_SOURCE_TYPES

    def locator_matches(value: str) -> bool:
        if value in gold_locators:
            return True
        return legislation and any(
            legislation_locator_within(value, expected) for expected in gold_locators
        )

    def matching_ranks(top: Sequence[SearchHit]) -> list[int]:
        output: list[int] = []
        for rank, hit in enumerate(top, 1):
            if hit.chunk.source_identity != gold_source:
                continue
            if mode == "source_identity_only":
                output.append(rank)
                continue
            if not locator_matches(_hit_locator(hit)):
                continue
            if mode == "source_and_span" and _hit_canonical_span_sha256(hit) != gold_hash:
                continue
            output.append(rank)
        return output

    top3, top5, top10 = tuple(hits[:k3]), tuple(hits[:k5]), tuple(hits[:k10])
    ranks3, ranks5, ranks10 = matching_ranks(top3), matching_ranks(top5), matching_ranks(top10)

    def exact_span_hits(top: Sequence[SearchHit]) -> set[str]:
        found: set[str] = set()
        for hit in top:
            if hit.chunk.source_identity != gold_source:
                continue
            if gold_locators and not locator_matches(_hit_locator(hit)):
                continue
            digest = _hit_canonical_span_sha256(hit)
            if digest in gold_span_hashes:
                found.add(digest)
        return found

    span_hits3 = exact_span_hits(top3)
    span_hits5 = exact_span_hits(top5)
    span_hits10 = exact_span_hits(top10)
    span_total = len(gold_span_hashes)
    gold_rank = min(ranks10) if ranks10 else None
    identity_only_ranks: list[int] = []
    wrong_version_ranks: list[int] = []
    forbidden_lane_ranks: list[int] = []
    private_path_ranks: list[int] = []
    for rank, hit in enumerate(top10, 1):
        lane = _hit_lane(hit)
        ident = hit.chunk.source_identity
        if lane in set(row.get("forbidden_lanes") or []) or lane in FORBIDDEN_LANES:
            forbidden_lane_ranks.append(rank)
        if contains_absolute_private_path(hit.chunk.text) or contains_absolute_private_path(
            _hit_locator(hit)
        ):
            private_path_ranks.append(rank)
        if ident == gold_source and mode != "source_identity_only" and rank not in ranks10:
            identity_only_ranks.append(rank)
        if _authority_stem(ident) == _authority_stem(gold_source) and ident != gold_source:
            wrong_version_ranks.append(rank)

    return {
        "id": row.get("id"),
        "split": row.get("split"),
        "match_mode": mode,
        "polarity": "positive",
        "expected_source_id": gold_source,
        "frozen_expected_source_id": row.get("frozen_expected_source_id", gold_source),
        "expected_source_version_id": row.get("expected_source_version_id"),
        "frozen_expected_source_version_id": row.get(
            "frozen_expected_source_version_id", row.get("expected_source_version_id")
        ),
        "legal_locator": row.get("legal_locator"),
        "proposition_span_sha256": row.get("proposition_span_sha256"),
        "gold_span_sha256s": list(gold_span_hashes),
        "gold_span_count": span_total,
        "exact_span_hits_at_3": sorted(span_hits3),
        "exact_span_hits_at_5": sorted(span_hits5),
        "exact_span_hits_at_10": sorted(span_hits10),
        "exact_span_recall_at_3": len(span_hits3) / span_total if span_total else None,
        "exact_span_recall_at_5": len(span_hits5) / span_total if span_total else None,
        "exact_span_recall_at_10": len(span_hits10) / span_total if span_total else None,
        "hit@3": bool(ranks3),
        "hit@5": bool(ranks5),
        "hit@10": bool(ranks10),
        "gold_rank": gold_rank,
        "reciprocal_rank": 1.0 / gold_rank if gold_rank else 0.0,
        "primary_must_hit": bool(row.get("primary_must_hit")),
        "identity_only_allowed": mode == "source_identity_only",
        "identity_only_ranks": identity_only_ranks,
        "wrong_version": bool(wrong_version_ranks),
        "wrong_version_ranks": wrong_version_ranks,
        "forbidden_lane": bool(forbidden_lane_ranks),
        "forbidden_lane_ranks": forbidden_lane_ranks,
        "teaching_assessment_hits": len(forbidden_lane_ranks),
        "private_path_hits": len(private_path_ranks),
        "current_outranks_as_enacted": not wrong_version_ranks,
        "top_chunk_ids": [hit.chunk.chunk_id for hit in top10],
        "top_source_identities": [hit.chunk.source_identity for hit in top10],
        "top_locators": [_hit_locator(hit) for hit in top10],
        "top_lanes": [_hit_lane(hit) for hit in top10],
        "top_currentness": [_hit_currentness(hit) for hit in top10],
        "top_hit_diagnostics": [
            {
                "chunk_id": hit.chunk.chunk_id,
                "fused_score": hit.score,
                "lexical_rank": hit.lexical_rank,
                "vector_rank": hit.vector_rank,
                "reranker_score": hit.rerank_score,
            }
            for hit in top10
        ],
        "hit_count": len(hits),
    }


def aggregate_split(
    results: Sequence[Mapping[str, Any]], *, project_root: Path = PROJECT_ROOT
) -> dict[str, Any]:
    positives = list(results)
    primary = [item for item in positives if item.get("primary_must_hit") is True]
    n_pos, n_primary = len(positives), len(primary)
    hit3 = sum(item.get("hit@3") is True for item in positives)
    hit5 = sum(item.get("hit@5") is True for item in positives)
    hit10 = sum(item.get("hit@10") is True for item in positives)
    primary5 = sum(item.get("hit@5") is True for item in primary)
    recall3 = hit3 / n_pos if n_pos else 0.0
    recall5 = hit5 / n_pos if n_pos else 0.0
    recall10 = hit10 / n_pos if n_pos else 0.0
    primary_recall5 = primary5 / n_primary if n_primary else 0.0
    mrr = (
        sum(float(item.get("reciprocal_rank") or 0) for item in positives) / n_pos if n_pos else 0.0
    )
    policy, policy_sha256 = load_retrieval_policy(project_root)
    thresholds = policy["gates"]
    teaching = sum(int(item.get("teaching_assessment_hits") or 0) for item in positives)
    paths = sum(int(item.get("private_path_hits") or 0) for item in positives)
    wrong = sum(item.get("wrong_version") is True for item in positives)
    span_results = [item for item in positives if int(item.get("gold_span_count") or 0) > 0]
    exact_span_recall10 = (
        sum(float(item.get("exact_span_recall_at_10") or 0) for item in span_results)
        / len(span_results)
        if span_results
        else None
    )
    timing_stages = ("query_embedding", "lexical", "vector", "fusion", "rerank", "total")
    latency_ms = {
        stage: _latency_percentiles(
            [
                float(
                    cast(
                        int | float | str,
                        (item.get("timings_ms") or {}).get(stage),
                    )
                )
                for item in positives
                if isinstance(item.get("timings_ms"), Mapping)
                and (item.get("timings_ms") or {}).get(stage) is not None
            ]
        )
        for stage in timing_stages
    }
    gates = {
        "primary_must_hit_recall_at_5": primary_recall5
        >= float(thresholds["primary_must_hit_recall_at_5"]),
        "positive_recall_at_10": recall10 >= float(thresholds["positive_recall_at_10"]),
        "mrr": mrr >= float(thresholds["mrr"]),
        "teaching_assessment_hits_zero": teaching == 0,
        "private_path_hits_zero": paths == 0,
        "wrong_version_zero": wrong == 0,
    }
    return {
        "positive_count": n_pos,
        "primary_must_hit_count": n_primary,
        "positive_hit_at_3": hit3,
        "positive_hit_at_5": hit5,
        "positive_hit_at_10": hit10,
        "positive_recall_at_3": recall3,
        "positive_recall_at_5": recall5,
        "positive_recall_at_10": recall10,
        "primary_must_hit_recall_at_5": primary_recall5,
        "mrr": mrr,
        "teaching_assessment_hits": teaching,
        "private_path_hits": paths,
        "wrong_version_count": wrong,
        "exact_span_case_count": len(span_results),
        "mean_exact_span_recall_at_10": exact_span_recall10,
        "latency_ms": latency_ms,
        "thresholds": thresholds,
        "retrieval_policy_sha256": policy_sha256,
        "gates": gates,
        "go": all(gates.values()),
        "misses": [
            {
                "id": item.get("id"),
                "match_mode": item.get("match_mode"),
                "gold_rank": item.get("gold_rank"),
                "top_source_identities": item.get("top_source_identities"),
                "top_locators": item.get("top_locators"),
            }
            for item in positives
            if item.get("hit@10") is not True
            or item.get("wrong_version")
            or item.get("forbidden_lane")
        ],
    }


def _latency_percentiles(values: Sequence[float]) -> dict[str, float | int | None]:
    ordered = sorted(values)
    if not ordered:
        return {"count": 0, "p50": None, "p95": None, "p99": None}

    def percentile(fraction: float) -> float:
        if len(ordered) == 1:
            return ordered[0]
        position = (len(ordered) - 1) * fraction
        lower = int(position)
        upper = min(lower + 1, len(ordered) - 1)
        weight = position - lower
        return ordered[lower] * (1 - weight) + ordered[upper] * weight

    return {
        "count": len(ordered),
        "p50": round(percentile(0.50), 3),
        "p95": round(percentile(0.95), 3),
        "p99": round(percentile(0.99), 3),
    }


def _candidate_bound_retrieval_date(
    candidate_binding: Mapping[str, Any], bound_rows: Sequence[Mapping[str, Any]]
) -> date:
    """Return the exact current-law snapshot date proven by candidate binding.

    Frozen legislation gold may be rolled to a later sealed candidate only by
    :func:`bind_frozen_rows_to_candidate`, which proves the exact spans and
    provision qualifications first.  Retrieval must therefore filter against
    that proven candidate snapshot rather than a hard-coded benchmark date;
    otherwise every successfully rebound statute can be excluded before
    lexical or vector candidate generation.
    """

    raw_date = candidate_binding.get("candidate_current_law_as_of_date")
    if not isinstance(raw_date, str):
        raise RuntimeError("candidate binding has no current-law snapshot date")
    try:
        snapshot_date = date.fromisoformat(raw_date)
    except ValueError as exc:
        raise RuntimeError("candidate binding current-law snapshot date is invalid") from exc

    row_bindings = candidate_binding.get("bindings")
    if not isinstance(row_bindings, list):
        raise RuntimeError("candidate binding rows are missing")
    by_case = {
        str(value.get("case_id") or ""): value
        for value in row_bindings
        if isinstance(value, Mapping)
    }
    for row in bound_rows:
        if str(row.get("source_type") or "") not in LEGISLATION_SOURCE_TYPES:
            continue
        case_id = str(row.get("id") or "")
        binding = by_case.get(case_id)
        if (
            not isinstance(binding, Mapping)
            or binding.get("status") != "bound"
            or binding.get("candidate_as_of_date") != raw_date
            or row.get("expected_source_id") != binding.get("candidate_source_id")
            or row.get("expected_source_version_id")
            != binding.get("candidate_selected_source_version_id")
        ):
            raise RuntimeError("legislation retrieval is not bound to one candidate snapshot")
    return snapshot_date


def _search_retriever(
    settings: Settings, build_path: Path, *, test_mode: bool, as_of_date: date
) -> HybridRetriever:
    require_generic_index_read_allowed(
        build_path,
        expected_build_id=build_path.name,
    )
    embedder = _embedding_provider(
        settings, TEST_EMBEDDING_MODEL if test_mode else _production_embedding_identity(settings)
    )
    reranker = _reranker_provider(
        settings, TEST_RERANKER_MODEL if test_mode else _production_reranker_identity(settings)
    )
    module = _import_lancedb()
    authority = build_path / "lance" / PHYSICAL_AUTHORITY_LANE
    if not authority.exists():
        authority = build_path / "lance"
    table = module.connect(str(authority)).open_table("chunks")
    return HybridRetriever(
        embedder=embedder,
        lexical_backend=_LanceLexicalBackend(table, as_of_date),
        vector_backend=_LanceVectorBackend(table, as_of_date),
        reranker=reranker,
        reference_resolver=CandidateLegislationReferenceResolver.from_path(
            build_path / "approved-source-manifest.json"
        ),
    )


def run_retrieval_v1(
    settings: Settings,
    *,
    build_id: str,
    splits: Sequence[str],
    jsonl_path: Path | None = None,
    test_mode: bool | None = None,
    result_observer: Callable[[Mapping[str, Any]], None] | None = None,
) -> dict[str, Any]:
    build_path = settings.index_dir / "builds" / build_id
    require_generic_index_read_allowed(build_path, expected_build_id=build_id)
    jsonl = jsonl_path or settings.project_root / FROZEN_JSONL_RELATIVE
    if not set(splits) <= {"development", "promotion"}:
        raise BenchmarkNotFrozenError("v1.1 contains only development and promotion ranking cases")
    freeze = verify_owner_freeze(settings.project_root, jsonl)
    rows = load_retrieval_v1_jsonl(jsonl, str(freeze["jsonl_sha256"]))
    selected = [row for row in rows if row.get("split") in set(splits)]
    if not (build_path / "lance").exists():
        raise FileNotFoundError(f"candidate lance tree missing: {build_path}")
    bound_rows, candidate_binding = bind_retrieval_rows_to_candidate(
        build_path,
        selected,
        build_id=build_id,
        benchmark_sha256=str(freeze["jsonl_sha256"]),
        project_root=settings.project_root,
    )
    if result_observer is not None:
        result_observer(
            {
                "stage": "binding_completed",
                "candidate_gold_binding": candidate_binding,
                "expected_query_count": len(bound_rows),
            }
        )
    retrieval_as_of_date = _candidate_bound_retrieval_date(candidate_binding, bound_rows)
    retriever = _search_retriever(
        settings,
        build_path,
        test_mode=settings.test_mode if test_mode is None else test_mode,
        as_of_date=retrieval_as_of_date,
    )
    per_query: list[dict[str, Any]] = []
    for row in bound_rows:
        filters = QueryFilters(
            jurisdictions=frozenset(_query_jurisdictions(str(row["jurisdiction"]))),
            material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
            exact_jurisdictions=frozenset(_query_exact_jurisdictions(str(row["jurisdiction"]))),
            subjects=frozenset(),
            review_states=frozenset({"approved"}),
        )
        hits = retriever.search(
            SearchQuery(
                str(row["query"]),
                filters,
                limit=BENCHMARK_RESULT_LIMIT,
                candidate_limit=BENCHMARK_CANDIDATE_LIMIT,
                lexical_candidate_limit=BENCHMARK_CANDIDATE_LIMIT,
                vector_candidate_limit=BENCHMARK_CANDIDATE_LIMIT,
                rerank_candidate_limit=BENCHMARK_RERANK_CANDIDATE_LIMIT,
            )
        )
        result = {
            **score_query_hits(row, hits),
            "timings_ms": dict(retriever.last_timings_ms),
        }
        per_query.append(result)
        if result_observer is not None:
            result_observer(
                {
                    "stage": "query_completed",
                    "completed_query_count": len(per_query),
                    "result": dict(result),
                }
            )
    policy, policy_sha256 = load_retrieval_policy(settings.project_root)
    aggregates = aggregate_split(per_query, project_root=settings.project_root)
    split_aggregates = {
        split: aggregate_split(
            [item for item in per_query if item.get("split") == split],
            project_root=settings.project_root,
        )
        for split in splits
    }
    return {
        "schema": REPORT_SCHEMA,
        "created_at": utc_iso(),
        "build_id": build_id,
        "splits": list(splits),
        "jsonl_path": FROZEN_JSONL_RELATIVE,
        "jsonl_sha256": freeze["jsonl_sha256"],
        "freeze_manifest": FREEZE_MANIFEST_RELATIVE,
        "freeze_status": freeze["status"],
        "retrieval_policy": POLICY_RELATIVE,
        "retrieval_policy_sha256": policy_sha256,
        "candidate_gold_binding": candidate_binding,
        "scorer_version": policy["scorer"],
        "scorer_implementation_files": list(SCORER_IMPLEMENTATION_FILES),
        "scorer_implementation_sha256": scorer_implementation_sha256(settings.project_root),
        "retrieval_strategy": {
            "name": "hybrid_rrf_plus_qwen_reranker",
            "candidate_limit": BENCHMARK_CANDIDATE_LIMIT,
            "rerank_candidate_limit": BENCHMARK_RERANK_CANDIDATE_LIMIT,
            "result_limit": BENCHMARK_RESULT_LIMIT,
            "exact_authority_identity_route": True,
            "exact_legislation_reference_route": True,
            "explicit_reference_version": EXPLICIT_REFERENCE_VERSION,
            "candidate_bound_as_of_date": retrieval_as_of_date.isoformat(),
            "admission_version": ADMISSION_VERSION,
            "parent_expansion": False,
        },
        "answer_model_invoked": False,
        "active_json_written": False,
        "per_query": per_query,
        "aggregates": aggregates,
        "split_aggregates": split_aggregates,
        # A combined average must not hide a failure in the sealed promotion
        # split.  Every requested split is an independent gate.
        "go": bool(split_aggregates)
        and all(bool(summary["go"]) for summary in split_aggregates.values()),
    }


def attest_retrieval_v1(
    settings: Settings,
    database: Database,
    *,
    build_id: str,
) -> dict[str, Any]:
    """Attach an immutable v1.1 result to a built_unscored generation.

    The attestation lives outside the immutable index directory.  It changes
    only the catalogue state from built_unscored to candidate when every gate
    passes.  It never promotes ACTIVE.
    """

    from ..assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
    from ..quality.policy import POLICY_SHA256
    from .index_recovery import attest_allowed
    from .retrieval_reattest import _clean_integration_sha
    from .service import _file_sha256, _json_object, _write_new_json

    row = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
    if row is None or not attest_allowed(str(row["status"])):
        raise ValueError("only a built_unscored generation may be attested")
    if str(row["policy_sha256"] or "") != POLICY_SHA256:
        raise RuntimeError("build quality-policy SHA does not match the current policy")
    if str(row["assessment_bundle_sha256"] or "") != OWNER_ASSESSMENT_BUNDLE.sha256:
        raise RuntimeError("build assessment-guidance SHA does not match the runtime bundle")
    build_path = settings.index_dir / "builds" / build_id
    evaluation = _json_object((build_path / "evaluation.json").read_text(encoding="utf-8"))
    if (
        evaluation.get("passed") is not True
        or evaluation.get("promotion_eligible") is not True
        or (evaluation.get("integrity") or {}).get("physical_lane_isolation") is not True
    ):
        raise RuntimeError("index integrity/privacy gates did not pass before retrieval scoring")
    integration_sha = _clean_integration_sha(settings.project_root)
    report = run_retrieval_v1(settings, build_id=build_id, splits=("development", "promotion"))
    if report.get("go") is not True:
        raise RuntimeError("retrieval v1.1 gates did not pass; build remains built_unscored")
    seal_path = build_path / "seal.json"
    source_manifest_path = build_path / "approved-source-manifest.json"
    payload = {
        "schema": "legalbot.retrieval-attestation.v1.1",
        "created_at": utc_iso(),
        "build_id": build_id,
        "build_seal_sha256": _file_sha256(seal_path),
        "source_manifest_sha256": _file_sha256(source_manifest_path),
        "quality_policy_sha256": POLICY_SHA256,
        "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
        "retrieval_policy_sha256": report["retrieval_policy_sha256"],
        "benchmark_sha256": report["jsonl_sha256"],
        "scorer_version": report["scorer_version"],
        "scorer_implementation_sha256": report["scorer_implementation_sha256"],
        "freeze_manifest_sha256": _file_sha256(settings.project_root / FREEZE_MANIFEST_RELATIVE),
        "embedding_model": str(row["embedding_model"]),
        "reranker_model": str(row["reranker_model"]),
        "integration_sha": integration_sha,
        "passed": True,
        "promotion_eligible": True,
        "report": report,
    }
    destination = settings.evaluation_dir / "retrieval" / build_id / "v1.1-attestation.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    _write_new_json(destination, payload)
    attestation_sha256 = _file_sha256(destination)
    summary = {
        "schema": payload["schema"],
        "passed": True,
        "promotion_eligible": True,
        "attestation_path": str(destination.relative_to(settings.project_root)),
        "attestation_sha256": attestation_sha256,
        "benchmark_sha256": report["jsonl_sha256"],
        "retrieval_policy_sha256": report["retrieval_policy_sha256"],
        "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
        "scorer_version": report["scorer_version"],
        "scorer_implementation_sha256": report["scorer_implementation_sha256"],
    }
    with database.transaction() as connection:
        changed = connection.execute(
            """UPDATE index_builds
               SET status='candidate',stage='candidate',benchmark_result_json=?
               WHERE id=? AND status='built_unscored'""",
            (json.dumps(summary, sort_keys=True), build_id),
        ).rowcount
        if changed != 1:
            raise RuntimeError("build state changed before retrieval attestation was recorded")
        connection.execute(
            """INSERT INTO retrieval_attestation_history(
                 id,build_id,attestation_path,attestation_sha256,schema_version,
                 prior_attestation_path,prior_attestation_sha256,build_seal_sha256,
                 source_manifest_sha256,embedding_model,reranker_model,
                 quality_policy_sha256,assessment_bundle_sha256,
                 retrieval_policy_sha256,benchmark_sha256,freeze_manifest_sha256,
                 scorer_version,scorer_implementation_sha256,integration_sha,created_at
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                attestation_sha256,
                build_id,
                summary["attestation_path"],
                attestation_sha256,
                payload["schema"],
                None,
                None,
                payload["build_seal_sha256"],
                payload["source_manifest_sha256"],
                payload["embedding_model"],
                payload["reranker_model"],
                payload["quality_policy_sha256"],
                payload["assessment_bundle_sha256"],
                payload["retrieval_policy_sha256"],
                payload["benchmark_sha256"],
                payload["freeze_manifest_sha256"],
                payload["scorer_version"],
                payload["scorer_implementation_sha256"],
                payload["integration_sha"],
                payload["created_at"],
            ),
        )
        connection.execute(
            """INSERT INTO retrieval_attestation_selections(
                 build_id,attestation_id,selected_at) VALUES (?,?,?)""",
            (build_id, attestation_sha256, utc_iso()),
        )
    return {**summary, "build_id": build_id, "status": "candidate"}
