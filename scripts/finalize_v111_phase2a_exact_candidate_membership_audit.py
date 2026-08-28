#!/usr/bin/env python3
"""Seal the exact-candidate membership audit that supersedes r65 booleans."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from scripts import build_v111_phase2a_authority_plan_advisory as planner  # noqa: E402
from scripts import verify_v111_phase2a_exact_semantic_spans_advisory as verifier  # noqa: E402

OUTPUT_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-25-r65-span-id-exact-semantic-span-advisory"
)
EXPECTED_OUTSIDE_EXACT_MANIFEST_COUNT = 31
KNOWN_PRIVATE_SECONDARY_SOURCE_IDS = frozenset(
    {
        "source-version-5e1963ec7ed2cb7e17094f9c447deaf9a3a21c5a",
        "source-version-fcc859af718aebf8ca01947ad6edcb06a863180b",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


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


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_exact_membership_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_exact_membership_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


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


def _old_top_selection(issue: Mapping[str, Any], record: Mapping[str, Any]) -> Mapping[str, Any]:
    issue_label = str(issue["issue_label"])
    choices: list[tuple[tuple[tuple[float, ...], str, str], Mapping[str, Any]]] = []
    for selection in record["resolved_selections"]:
        chunks = selection.get("exact_chunks") or []
        if not chunks:
            continue
        metadata = selection.get("candidate_source_metadata") or {}
        label_linked = verifier.targeted_recovery._label_linked_direct_rule(issue_label, chunks)
        semantic_score = max(
            verifier._semantic_chunk_score(issue_label, chunk)[0]
            + verifier._semantic_chunk_score(issue_label, chunk)[1]
            for chunk in chunks
        )
        order = (
            (
                float(1 if label_linked else 0),
                float(semantic_score),
                float(metadata.get("combined_advisory_score") or 0.0),
            ),
            str(selection.get("authority_identity_id") or ""),
            str(selection.get("source_identity", {}).get("id") or ""),
        )
        choices.append((order, selection))
    if not choices:
        raise ValueError("phase2a_exact_membership_old_selection_missing")
    choices.sort(key=lambda item: item[0], reverse=True)
    return choices[0][1]


def main() -> None:
    output_path = OUTPUT_ROOT / "EXACT-CANDIDATE-MEMBERSHIP-AUDIT.json"
    if output_path.exists() or output_path.is_symlink():
        raise ValueError("phase2a_exact_membership_output_already_exists")
    debug_report = _load_object(OUTPUT_ROOT / "DEBUG-STOP-REPORT.json")
    debug_report_sha256 = _verify_seal(
        debug_report,
        "report_content_sha256",
        "phase2a_exact_membership_debug_report_invalid",
    )
    locators = _load_object(verifier.DEFAULT_LOCATORS)
    locator_sha256 = _verify_seal(
        locators,
        "artifact_content_sha256",
        "phase2a_exact_membership_locator_invalid",
    )
    candidate_sources, manifest_sha256, manifest_file_sha256 = verifier._load_candidate_manifest(
        verifier.DEFAULT_CANDIDATE_MANIFEST
    )
    candidate_by_authority: dict[str, list[str]] = defaultdict(list)
    for source_id, source in candidate_sources.items():
        candidate_by_authority[str(source["authority_identity_id"])].append(source_id)

    issues, remaining_sha256 = planner._load_issue_rows(verifier.DEFAULT_REMAINING)
    records = {str(row["row_id"]): row for row in locators["records"]}
    outside: list[dict[str, Any]] = []
    for issue in issues:
        selection = _old_top_selection(issue, records[str(issue["item_id"])])
        source = selection["source_identity"]
        source_id = str(source["id"])
        if source_id in candidate_sources:
            continue
        metadata = selection.get("candidate_source_metadata") or {}
        material = {
            "schema": "legalbot.v111.phase2a.old-top-outside-exact-candidate.v1",
            "row_id": str(issue["item_id"]),
            "issue_label": str(issue["issue_label"]),
            "legal_domain": str(issue["legal_domain"]),
            "old_top_source_version_id": source_id,
            "old_top_authority_identity_id": str(selection.get("authority_identity_id") or ""),
            "old_authority_level_candidate_boolean": metadata.get("already_in_sealed_candidate"),
            "exact_source_version_in_candidate_manifest": False,
            "candidate_manifest_source_versions_for_same_authority": sorted(
                candidate_by_authority.get(str(selection.get("authority_identity_id") or ""), [])
            ),
            "known_private_secondary_content": (source_id in KNOWN_PRIVATE_SECONDARY_SOURCE_IDS),
            "selection_origin": selection.get("selection_origin"),
            "selection_content_sha256": selection.get("selection_content_sha256"),
        }
        outside.append({**material, "record_content_sha256": _sealed(material)})

    if len(outside) != EXPECTED_OUTSIDE_EXACT_MANIFEST_COUNT:
        raise ValueError("phase2a_exact_membership_scope_changed")
    if sum(bool(row["known_private_secondary_content"]) for row in outside) != 4:
        raise ValueError("phase2a_exact_membership_private_secondary_scope_changed")

    material = {
        "schema": "legalbot.v111.phase2a.exact-candidate-membership-audit-448.v1",
        "status": "OLD_TOP_SELECTIONS_REJECTED_UNLESS_EXACT_SOURCE_VERSION_IS_IN_SEALED_MANIFEST",
        "source_debug_report_content_sha256": debug_report_sha256,
        "source_locator_content_sha256": locator_sha256,
        "source_remaining_content_sha256": remaining_sha256,
        "candidate_manifest_sha256": manifest_sha256,
        "candidate_manifest_file_sha256": manifest_file_sha256,
        "candidate_source_count": len(candidate_sources),
        "issue_count": len(issues),
        "old_top_outside_exact_candidate_count": len(outside),
        "known_private_secondary_old_top_count": sum(
            bool(row["known_private_secondary_content"]) for row in outside
        ),
        "records": outside,
        "replacement_policy": {
            "exact_source_version_manifest_membership_required": True,
            "authority_level_boolean_is_not_membership_proof": True,
            "noncandidate_source_enters_owner_admission_batch_automatically": False,
            "missing_coverage_routes_to_official_quarantine": True,
        },
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    _write_exclusive(output_path, _pretty_json(artifact))
    names = ["DEBUG-STOP-REPORT.json", output_path.name]
    sums = "".join(f"{_sha256_file(OUTPUT_ROOT / name)}  {name}\n" for name in names).encode(
        "utf-8"
    )
    _write_exclusive(OUTPUT_ROOT / "EXACT-CANDIDATE-MEMBERSHIP-SHA256SUMS.txt", sums)
    print(json.dumps(artifact, sort_keys=True))


if __name__ == "__main__":
    main()
