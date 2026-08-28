#!/usr/bin/env python3
"""Seal the complete 448-row Phase-2A issue advisory after held-row debug."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

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
from scripts import verify_v111_phase2a_exact_semantic_spans_advisory as verifier  # noqa: E402

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R67_ROOT = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r67-candidate-bound-exact-semantic-span-advisory"
)
R67_ARTIFACT_PATH = R67_ROOT / "ADVISORY-EXACT-SEMANTIC-SPANS-448.json"
R67_INTENT_PATH = R67_ROOT / "INTENT.json"
R69_ROOT = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r69-deterministic-held-gap-resolution"
)
R69_ARTIFACT_PATH = R69_ROOT / "RESOLVED-HELD-FINDINGS-5.json"
OUTPUT_ROOT = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r70-complete-issue-advisory-448"
)
OUTPUT_PATH = OUTPUT_ROOT / "COMPLETE-ISSUE-ADVISORY-448.json"

EXPECTED_R67_ARTIFACT_CONTENT_SHA256 = (
    "b2f300a89895faa46a91c393a9171202b056ef4ae52942083bfb00f42f0ad732"
)
EXPECTED_R69_ARTIFACT_CONTENT_SHA256 = (
    "cf1a8d79e1c3e08738bd0087c2ba4ac2417249547ecc8c914dff19ad0679313c"
)
EXPECTED_COUNTS = {
    "DIRECT_EXACT_SPAN_ADVISORY": 36,
    "MATERIAL_GAP_ADVISORY": 364,
    "PARTIAL_EXACT_SPAN_ADVISORY": 48,
}
SUPPORTED_ASSESSMENTS = {
    "DIRECT_EXACT_SPAN_ADVISORY",
    "PARTIAL_EXACT_SPAN_ADVISORY",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


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


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_issue_advisory_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_issue_advisory_input_must_be_object")
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


def _validate_supported_finding(
    finding: Mapping[str, Any],
    *,
    issue: Mapping[str, Any],
    locator_record: Mapping[str, Any],
    candidate_sources: Mapping[str, Mapping[str, Any]],
) -> None:
    proposition = str(finding.get("atomic_proposition") or "")
    binding = finding.get("exact_span_binding")
    if (
        not proposition
        or len(proposition) > verifier.MAX_PROPOSITION_CHARACTERS
        or non_atomic_material_claim_reasons(proposition)
        or not isinstance(binding, dict)
    ):
        raise ValueError("phase2a_issue_advisory_supported_claim_invalid")
    _verify_seal(
        binding,
        "binding_content_sha256",
        "phase2a_issue_advisory_binding_seal_invalid",
    )
    exact_text = str(binding.get("exact_text") or "")
    locator = str(binding.get("locator") or "")
    source_version_id = str(binding.get("source_version_id") or "")
    source = candidate_sources.get(source_version_id)
    if (
        source is None
        or source.get("authority_identity_id") != binding.get("authority_identity_id")
        or binding.get("exact_text_sha256") != _sha256(exact_text.encode("utf-8"))
        or not _SHA256.fullmatch(str(binding.get("chunk_text_sha256") or ""))
        or not _SHA256.fullmatch(str(binding.get("span_content_sha256") or ""))
    ):
        raise ValueError("phase2a_issue_advisory_candidate_binding_invalid")

    projected = verifier._review_row(issue, locator_record, candidate_sources)
    if projected is None:
        raise ValueError("phase2a_issue_advisory_projection_missing")
    projected_chunks = verifier._chunk_map(projected)
    chunk_id = str(binding.get("chunk_id") or "")
    span_id = str(binding.get("span_id") or "")
    if chunk_id not in projected_chunks:
        raise ValueError("phase2a_issue_advisory_chunk_not_in_projection")
    selected = projected_chunks[chunk_id]
    if span_id not in selected["spans"]:
        raise ValueError("phase2a_issue_advisory_span_not_in_projection")
    span = selected["spans"][span_id]
    chunk = selected["chunk"]
    projected_source = selected["source"]
    if (
        span.get("exact_text") != exact_text
        or span.get("span_content_sha256") != binding.get("span_content_sha256")
        or chunk.get("text_sha256") != binding.get("chunk_text_sha256")
        or chunk.get("locator") != locator
        or projected_source.get("source_version_id") != source_version_id
    ):
        raise ValueError("phase2a_issue_advisory_exact_projection_binding_invalid")

    supported_fact_ids = {
        fact.identity
        for fact in extract_material_facts(f"{exact_text}\n{locator}")
    }
    unsupported = [
        fact.identity
        for fact in extract_material_facts(proposition)
        if fact.identity not in supported_fact_ids
    ]
    evidence_span = SimpleNamespace(text=exact_text, locator=locator)
    if unsupported or not is_substantively_related(proposition, evidence_span):
        raise ValueError("phase2a_issue_advisory_material_support_invalid")

    currentness = finding.get("source_currentness")
    if (
        not isinstance(currentness, dict)
        or currentness.get("already_in_sealed_candidate") is not True
        or currentness.get(
            "proposition_level_source_admission_required_if_owner_approves"
        )
        is not False
    ):
        raise ValueError("phase2a_issue_advisory_candidate_boundary_invalid")


def main() -> None:
    if OUTPUT_ROOT.exists() or OUTPUT_ROOT.is_symlink():
        raise ValueError("phase2a_issue_advisory_output_already_exists")

    r67 = _load_object(R67_ARTIFACT_PATH)
    r67_digest = _verify_seal(
        r67,
        "artifact_content_sha256",
        "phase2a_issue_advisory_r67_artifact_invalid",
    )
    r67_intent = _load_object(R67_INTENT_PATH)
    r67_intent_digest = _verify_seal(
        r67_intent,
        "intent_content_sha256",
        "phase2a_issue_advisory_r67_intent_invalid",
    )
    r69 = _load_object(R69_ARTIFACT_PATH)
    r69_digest = _verify_seal(
        r69,
        "artifact_content_sha256",
        "phase2a_issue_advisory_r69_artifact_invalid",
    )
    if (
        r67_digest != EXPECTED_R67_ARTIFACT_CONTENT_SHA256
        or r69_digest != EXPECTED_R69_ARTIFACT_CONTENT_SHA256
        or r67.get("issue_count") != verifier.EXPECTED_ISSUE_COUNT
        or r67.get("owner_decisions_applied") is not False
        or r67.get("candidate_mutated") is not False
        or r69.get("additional_model_invocations") != 0
        or r69.get("owner_decisions_applied") is not False
        or r69.get("candidate_mutated") is not False
    ):
        raise ValueError("phase2a_issue_advisory_boundary_invalid")

    old_findings = r67.get("findings")
    replacements = r69.get("findings")
    if not isinstance(old_findings, list) or not isinstance(replacements, list):
        raise ValueError("phase2a_issue_advisory_findings_invalid")
    old_by_id = {str(row.get("row_id") or ""): row for row in old_findings}
    replacement_by_id = {
        str(row.get("row_id") or ""): row for row in replacements
    }
    if (
        len(old_by_id) != verifier.EXPECTED_ISSUE_COUNT
        or len(replacement_by_id) != 5
        or set(replacement_by_id)
        != {
            row_id
            for row_id, row in old_by_id.items()
            if row.get("assessment")
            == "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT"
        }
    ):
        raise ValueError("phase2a_issue_advisory_replacement_scope_invalid")

    rows, _, _, upstream_held, candidate_sources, hashes = verifier._load_inputs(
        locators_path=verifier.DEFAULT_LOCATORS,
        plans_path=verifier.DEFAULT_PLANS,
        remaining_path=verifier.DEFAULT_REMAINING,
        cases_path=verifier.DEFAULT_CASES,
        candidate_manifest_path=verifier.DEFAULT_CANDIDATE_MANIFEST,
    )
    if upstream_held:
        raise ValueError("phase2a_issue_advisory_upstream_planner_held")
    records = {
        str(row["row_id"]): row
        for row in verifier._load_object(verifier.DEFAULT_LOCATORS)["records"]
    }
    issue_order = [str(row["item_id"]) for row in rows]
    issues = {str(row["item_id"]): row for row in rows}
    if (
        set(issue_order) != set(old_by_id)
        or r67.get("source_intent_content_sha256") != r67_intent_digest
        or r67.get("source_locator_content_sha256") != hashes["locators"]
        or r67.get("source_plans_content_sha256") != hashes["plans"]
        or r67.get("source_remaining_content_sha256") != hashes["remaining"]
        or r67.get("source_candidate_manifest_sha256")
        != hashes["candidate_manifest"]
        or r67.get("source_candidate_manifest_file_sha256")
        != hashes["candidate_manifest_file"]
    ):
        raise ValueError("phase2a_issue_advisory_source_identity_changed")

    findings = [
        replacement_by_id.get(row_id, old_by_id[row_id]) for row_id in issue_order
    ]
    counts = Counter(str(row.get("assessment") or "") for row in findings)
    if dict(sorted(counts.items())) != EXPECTED_COUNTS:
        raise ValueError("phase2a_issue_advisory_assessment_counts_invalid")

    for finding in findings:
        row_id = str(finding.get("row_id") or "")
        assessment = str(finding.get("assessment") or "")
        if (
            finding.get("owner_decision_required") is not True
            or finding.get("owner_outcome") is not None
            or finding.get("technical_qualification_assigned") is not False
        ):
            raise ValueError("phase2a_issue_advisory_owner_boundary_invalid")
        if assessment in SUPPORTED_ASSESSMENTS:
            _validate_supported_finding(
                finding,
                issue=issues[row_id],
                locator_record=records[row_id],
                candidate_sources=candidate_sources,
            )
        elif assessment == "MATERIAL_GAP_ADVISORY":
            if (
                finding.get("atomic_proposition") is not None
                or finding.get("exact_span_binding") is not None
                or not str(finding.get("gap_reason") or "")
            ):
                raise ValueError("phase2a_issue_advisory_gap_contract_invalid")
        else:
            raise ValueError("phase2a_issue_advisory_unresolved_assessment")

    material = {
        "schema": "legalbot.v111.phase2a.complete-issue-advisory-448.v1",
        "status": "COMPLETE_448_ROW_ADVISORY_OWNER_SUBSTANTIVE_DECISIONS_REQUIRED",
        "source_r67_artifact_content_sha256": r67_digest,
        "source_r67_artifact_file_sha256": _sha256_file(R67_ARTIFACT_PATH),
        "source_r67_intent_content_sha256": r67_intent_digest,
        "source_r69_artifact_content_sha256": r69_digest,
        "source_r69_artifact_file_sha256": _sha256_file(R69_ARTIFACT_PATH),
        "source_locator_content_sha256": hashes["locators"],
        "source_plans_content_sha256": hashes["plans"],
        "source_remaining_content_sha256": hashes["remaining"],
        "source_candidate_manifest_sha256": hashes["candidate_manifest"],
        "source_candidate_manifest_file_sha256": hashes[
            "candidate_manifest_file"
        ],
        "verifier_code_file_sha256": _sha256_file(
            Path(verifier.__file__).resolve()
        ),
        "evidence_validator_code_file_sha256": _sha256_file(
            verifier.EVIDENCE_VALIDATOR_CODE_PATH
        ),
        "issue_count": len(findings),
        "assessment_counts": dict(sorted(counts.items())),
        "held_row_count": 0,
        "positive_binding_count": sum(
            count for name, count in counts.items() if name in SUPPORTED_ASSESSMENTS
        ),
        "material_gap_count": counts["MATERIAL_GAP_ADVISORY"],
        "all_positive_bindings_in_exact_candidate_manifest": True,
        "all_positive_bindings_revalidated_against_exact_projection": True,
        "all_positive_material_facts_revalidated": True,
        "all_positive_atomicity_checks_revalidated": True,
        "same_model_adapter_as_drafting": True,
        "model_independent_reviewer": False,
        "additional_model_invocations_for_consolidation": 0,
        "findings": findings,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    OUTPUT_ROOT.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(OUTPUT_ROOT.stat().st_mode) != 0o700:
        raise ValueError("phase2a_issue_advisory_output_mode_invalid")
    _write_exclusive(OUTPUT_PATH, _pretty_json(artifact))
    _write_exclusive(
        OUTPUT_ROOT / "OUTCOME.txt",
        b"COMPLETE 448-ROW ISSUE ADVISORY SEALED. "
        b"OWNER SUBSTANTIVE DECISIONS REMAIN REQUIRED. "
        b"PHASE 2B AND DEVELOPMENT 30 ARE NOT AUTHORIZED.\n",
    )
    names = [OUTPUT_PATH.name, "OUTCOME.txt"]
    sums = "".join(
        f"{_sha256_file(OUTPUT_ROOT / name)}  {name}\n" for name in names
    ).encode()
    _write_exclusive(OUTPUT_ROOT / "SHA256SUMS.txt", sums)
    print(json.dumps(artifact, sort_keys=True))


if __name__ == "__main__":
    main()
