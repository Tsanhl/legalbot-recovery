#!/usr/bin/env python3
"""Seal the next exact Phase-2A substantive owner-decision batch."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r94-consolidated-substantive-owner-batch"
)
SOURCES: dict[str, tuple[Path, str]] = {
    "patents_delta": (
        REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r53-patents-s60-7-advisory/"
        "PATENTS-ACT-1977-S60-7-EXACT-DELTA-ADVISORY.json",
        "574e8bfd80955116e5c4eabda2171ba3d37eb8a8b6802a539dc9e0ea25247ae9",
    ),
    "judgments": (
        REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r59-consolidated-judgment-advisory/"
        "CONSOLIDATED-JUDGMENT-ADVISORY-20-AND-SOURCE-PROPOSALS-9.json",
        "5f851f18c26107f4fb95f85481137dc307ac057df176f7a303c1b5fbeac336c5",
    ),
    "issues": (
        REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r70-complete-issue-advisory-448/"
        "COMPLETE-ISSUE-ADVISORY-448.json",
        "a022848094a5e4ef27f97b6c245c992f1d311509163d084ecc7ed3aa021def58",
    ),
    "xml_mismatch": (
        REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r79-xml-byte-mismatch-reconciliation/"
        "XML-BYTE-MISMATCH-RECONCILIATION.json",
        "921e40c1876748c947918bb6a4f4563d502a4871fdfc8463a7316a63b755e190",
    ),
    "supplemental_material": (
        REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r83-supplemental-proposition-verification/"
        "OWNER-SOURCE-ADMISSION-BATCH.json",
        "5410b7888ac72224a0828d43d0ddbc36768a636ea54ecb1687e576958108b28d",
    ),
    "procurement_currentness": (
        REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r84-procurement-currentness-verification/"
        "OWNER-SOURCE-ADMISSION-BATCH.json",
        "1f33e04ef9ea7d39c15fba16bd2c10b1f5e7e40af008eb3180fc4d37ca03a10f",
    ),
    "as_made_currentness": (
        REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r85-as-made-currentness-verification/"
        "OWNER-SOURCE-ADMISSION-BATCH.json",
        "0ead28488b0fa6fc8c18cdfe532092b0ce397613361426b1991cbfe66ceb9fb6",
    ),
    "uksc_rehoming": (
        REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r86-issue-source-rehoming-review/"
        "OWNER-ISSUE-SOURCE-ADMISSION-BATCH.json",
        "623836f3882d6c921920adb8af32bb8bd9cf3836bfb9ed20cdd4095fc627d9b3",
    ),
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256(raw: bytes) -> str:
    import hashlib

    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_consolidated_batch_input_not_regular")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_consolidated_batch_input_not_object")
    return value


def _verify_artifact(name: str, value: Mapping[str, Any], expected: str) -> str:
    material = dict(value)
    supplied = str(material.pop("artifact_content_sha256", ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material) or supplied != expected:
        raise ValueError(f"phase2a_consolidated_batch_{name}_seal_invalid")
    return supplied


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


def _source_reference(name: str, path: Path, digest: str) -> dict[str, Any]:
    return {
        "source_name": name,
        "relative_path": str(path.relative_to(PROJECT_ROOT)),
        "artifact_content_sha256": digest,
        "file_sha256": _sha256_file(path),
    }


def _boundary_false(value: Mapping[str, Any], name: str) -> None:
    for field in (
        "source_admission_authorized",
        "candidate_mutated",
        "phase2b_authorized",
        "development30_authorized",
        "technical_qualification_assigned",
    ):
        if field in value and value.get(field) is not False:
            raise ValueError(f"phase2a_consolidated_batch_{name}_boundary_invalid")


def build(*, output_root: Path) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_consolidated_batch_output_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_consolidated_batch_output_mode_invalid")

    artifacts: dict[str, dict[str, Any]] = {}
    source_references: list[dict[str, Any]] = []
    for name, (path, expected) in SOURCES.items():
        value = _load(path)
        digest = _verify_artifact(name, value, expected)
        _boundary_false(value, name)
        artifacts[name] = value
        source_references.append(_source_reference(name, path, digest))

    issues = artifacts["issues"]
    findings = issues.get("findings")
    if (
        issues.get("issue_count") != 448
        or issues.get("positive_binding_count") != 84
        or issues.get("material_gap_count") != 364
        or not isinstance(findings, list)
        or len(findings) != 448
    ):
        raise ValueError("phase2a_consolidated_batch_issue_inventory_invalid")
    positive_findings = [
        row
        for row in findings
        if row.get("assessment") in {"DIRECT_EXACT_SPAN_ADVISORY", "PARTIAL_EXACT_SPAN_ADVISORY"}
    ]
    gap_findings = [row for row in findings if row.get("assessment") == "MATERIAL_GAP_ADVISORY"]
    if len(positive_findings) != 84 or len(gap_findings) != 364:
        raise ValueError("phase2a_consolidated_batch_issue_counts_invalid")
    issue_decisions: list[dict[str, Any]] = []
    for row in positive_findings:
        binding = row.get("exact_span_binding")
        if (
            not isinstance(binding, Mapping)
            or row.get("owner_outcome") is not None
            or not row.get("atomic_proposition")
            or not _SHA256.fullmatch(str(binding.get("binding_content_sha256") or ""))
        ):
            raise ValueError("phase2a_consolidated_batch_positive_issue_invalid")
        material = {
            "row_id": row["row_id"],
            "assessment": row["assessment"],
            "atomic_proposition": row["atomic_proposition"],
            "exact_span_binding_content_sha256": binding["binding_content_sha256"],
            "source_currentness": row.get("source_currentness"),
            "recommended_owner_outcome": (
                "APPROVE_PROPOSITION_AND_EXACT_SPAN_FOR_CONTINUED_PHASE2A_REMEDIATION"
            ),
            "technical_qualification_assigned": False,
            "owner_outcome": None,
        }
        issue_decisions.append({**material, "decision_content_sha256": _sealed(material)})

    judgments = artifacts["judgments"]
    judgment_rows = judgments.get("records")
    judgment_sources = judgments.get("source_admission_proposals")
    if (
        judgments.get("record_count") != 20
        or judgments.get("source_admission_proposal_count") != 9
        or not isinstance(judgment_rows, list)
        or len(judgment_rows) != 20
        or not isinstance(judgment_sources, list)
        or len(judgment_sources) != 9
    ):
        raise ValueError("phase2a_consolidated_batch_judgment_inventory_invalid")
    judgment_decisions = [
        {
            "neutral_citation": row["neutral_citation"],
            "source_version_id": row["source_version_id"],
            "recommended_owner_outcome": row["recommended_owner_outcome"],
            "source_record_content_sha256": row["record_content_sha256"],
            "owner_outcome": None,
        }
        for row in judgment_rows
    ]
    judgment_admissions = [
        {
            "proposal_id": row["proposal_id"],
            "neutral_citation": row["candidate_neutral_citation"],
            "source_proposal_content_sha256": row["proposal_content_sha256"],
            "recommended_owner_outcome": row["advisory_recommendation"],
            "owner_outcome": None,
        }
        for row in judgment_sources
    ]

    supplemental_decisions: list[dict[str, Any]] = []
    supplemental_admission_source_ids: set[str] = set()
    for name in (
        "supplemental_material",
        "procurement_currentness",
        "as_made_currentness",
    ):
        batch = artifacts[name]
        proposals = batch.get("proposals")
        expected_count = {
            "supplemental_material": 10,
            "procurement_currentness": 1,
            "as_made_currentness": 2,
        }[name]
        if (
            batch.get("proposal_count") != expected_count
            or not isinstance(proposals, list)
            or len(proposals) != expected_count
        ):
            raise ValueError(f"phase2a_consolidated_batch_{name}_inventory_invalid")
        for proposal in proposals:
            admission_required = proposal.get("owner_source_admission_required") is True
            if admission_required:
                supplemental_admission_source_ids.add(str(proposal["source_target_id"]))
            material = {
                "source_batch": name,
                "binding_id": proposal["binding_id"],
                "row_ids": proposal["row_ids"],
                "source_target_id": proposal["source_target_id"],
                "authority_identity": proposal["authority_identity"],
                "proposal_content_sha256": proposal["proposal_content_sha256"],
                "binding_scope": proposal["binding_scope"],
                "owner_source_admission_required": admission_required,
                "recommended_owner_outcome": proposal["advisory_recommendation"],
                "owner_outcome": None,
            }
            supplemental_decisions.append(
                {**material, "decision_content_sha256": _sealed(material)}
            )
    if len(supplemental_admission_source_ids) != 7:
        raise ValueError("phase2a_consolidated_batch_supplemental_source_count_invalid")

    uksc = artifacts["uksc_rehoming"]
    source_reviews = uksc.get("source_reviews")
    if not isinstance(source_reviews, list) or len(source_reviews) != 5:
        raise ValueError("phase2a_consolidated_batch_uksc_inventory_invalid")
    uksc_decisions: list[dict[str, Any]] = []
    uksc_admission_ids: set[str] = set()
    for source in source_reviews:
        propose = str(source["source_recommendation"]).startswith("PROPOSE_")
        if propose:
            uksc_admission_ids.add(str(source["proposal_id"]))
        material = {
            "proposal_id": source["proposal_id"],
            "neutral_citation": source["neutral_citation"],
            "source_review_content_sha256": source["source_review_content_sha256"],
            "supported_claim_binding_content_sha256s": [
                claim["binding_content_sha256"] for claim in source["supported_claims"]
            ],
            "rejected_mapping_content_sha256s": [
                row["rejection_content_sha256"] for row in source["rejected_mappings"]
            ],
            "recommended_owner_outcome": (
                "APPROVE_PROPOSITION_BINDINGS_AND_SOURCE_ADMISSION"
                if propose
                else "APPROVE_REJECTION_FOR_ALL_PLANNED_BENCHMARK_ROWS"
            ),
            "later_treatment_still_required_before_final_qualification": propose,
            "owner_outcome": None,
        }
        uksc_decisions.append({**material, "decision_content_sha256": _sealed(material)})
    if len(uksc_admission_ids) != 4:
        raise ValueError("phase2a_consolidated_batch_uksc_source_count_invalid")

    xml = artifacts["xml_mismatch"]
    if (
        xml.get("classification") != "XML_SERIALIZATION_ONLY_NONMATERIAL_BYTE_MISMATCH"
        or xml.get("canonical_xml_identical") is not True
        or xml.get("legal_xml_infoset_change_detected") is not False
    ):
        raise ValueError("phase2a_consolidated_batch_xml_disposition_invalid")
    patents = artifacts["patents_delta"]
    if not str(patents.get("advisory_recommendation") or "").startswith("DEFER_OWNER_OUTCOME"):
        raise ValueError("phase2a_consolidated_batch_patents_disposition_invalid")

    source_admission_count = (
        len(judgment_admissions) + len(supplemental_admission_source_ids) + len(uksc_admission_ids)
    )
    if source_admission_count != 20:
        raise ValueError("phase2a_consolidated_batch_total_source_admission_count_invalid")

    batch_material = {
        "schema": "legalbot.v111.phase2a.consolidated-substantive-owner-batch.v1",
        "status": "EXACT_OWNER_SUBSTANTIVE_DECISION_REQUIRED_CONTINUED_PHASE2A_ONLY",
        "owner": "Agnes",
        "decision_date": "2026-08-25",
        "qualification_route": "OWNER_ADOPTED_INTERNAL_RESEARCH_TOOL",
        "not_professional_legal_certification": True,
        "source_artifacts": source_references,
        "decision_summary": {
            "candidate_exact_binding_decision_count": len(issue_decisions),
            "judgment_later_treatment_decision_count": len(judgment_decisions),
            "judgment_source_admission_count": len(judgment_admissions),
            "supplemental_binding_decision_count": len(supplemental_decisions),
            "supplemental_unique_source_admission_count": len(supplemental_admission_source_ids),
            "uksc_source_review_decision_count": len(uksc_decisions),
            "uksc_source_admission_count": len(uksc_admission_ids),
            "total_unique_source_admission_count": source_admission_count,
            "xml_byte_mismatch_disposition_count": 1,
            "patents_delta_deferral_count": 1,
            "unresolved_material_gap_row_count": len(gap_findings),
        },
        "candidate_exact_binding_decisions": issue_decisions,
        "judgment_later_treatment_decisions": judgment_decisions,
        "judgment_source_admission_decisions": judgment_admissions,
        "supplemental_binding_and_source_decisions": supplemental_decisions,
        "uksc_source_review_decisions": uksc_decisions,
        "xml_byte_mismatch_decision": {
            "authority_identity": xml["authority_identity"],
            "artifact_content_sha256": xml["artifact_content_sha256"],
            "recommended_owner_outcome": "APPROVE_NONMATERIAL_XML_SERIALIZATION_ONLY_DISPOSITION",
            "owner_outcome": None,
        },
        "patents_delta_decision": {
            "artifact_content_sha256": patents["artifact_content_sha256"],
            "recommended_owner_outcome": patents["advisory_recommendation"],
            "owner_outcome": None,
        },
        "unresolved_material_gap_rows": [
            {
                "row_id": row["row_id"],
                "gap_reason": row["gap_reason"],
                "required_outcome": "RESEARCH_REMAINS_REQUIRED_NOT_APPROVED_OR_QUALIFIED",
            }
            for row in gap_findings
        ],
        "approval_effect": (
            "APPLY_ONLY_THE_LISTED_RECOMMENDATIONS_AND_SOURCE_ADMISSIONS_FOR_CONTINUED_PHASE2A_REMEDIATION"
        ),
        "approval_does_not": [
            "QUALIFY_ANY_OF_THE_364_UNRESOLVED_MATERIAL_GAP_ROWS",
            "AUTHORIZE_AUTOMATIC_INDEXING_OR_EMBEDDING",
            "AUTHORIZE_CANDIDATE_MUTATION_BEFORE_A_CONSOLIDATED_SUCCESSOR_SCOPE_IS_PROVEN",
            "AUTHORIZE_PHASE2B",
            "AUTHORIZE_DEVELOPMENT30",
        ],
        "owner_decision_required": True,
        "owner_approved": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    batch = {**batch_material, "artifact_content_sha256": _sealed(batch_material)}
    batch_path = output_root / "OWNER-SUBSTANTIVE-DECISION-BATCH.json"
    _write_exclusive(batch_path, _pretty_json(batch))

    digest = batch["artifact_content_sha256"]
    prompt = f"""OWNER DECISION - APPROVE EXACT PHASE-2A SUBSTANTIVE BATCH ONLY

I, Agnes, approve every recommended owner outcome and proposition-level source admission listed in the Phase-2A consolidated substantive owner batch with exact artifact digest:

{digest}

My approval covers exactly:

- 84 candidate proposition/exact-span bindings for continued Phase-2A remediation;
- 20 judgment later-treatment dispositions;
- 9 judgment later-treatment source admissions;
- 13 supplemental material/currentness bindings, including 7 unique supplemental official-source admissions;
- 5 UKSC source-review dispositions, including 4 UKSC source admissions and the listed unrelated mapping rejections;
- the Data (Use and Access) Act 2025 canonical-XML-identical byte-mismatch disposition as nonmaterial to legal text;
- deferral of the Patents Act 1977 section 60(7) owner outcome until final Patents proposition bindings are available.

I authorize Codex to apply these exact decisions and admit exactly the 20 uniquely identified official sources for continued Phase 2A only.

This approval does not qualify or approve the 364 unresolved material-gap rows. It does not authorize automatic indexing or embedding, an in-place candidate patch, Phase 2B, Development 30, Validation, promotion, ACTIVE/PREVIOUS writes, or live activation.

Any approved new source may be indexed only later through one consolidated successor-source manifest and successor candidate after the remaining Phase-2A source scope is proven.

I APPROVE THIS EXACT DIGEST-BOUND PHASE-2A BATCH.

Owner typed name: Agnes
Decision date: 2026-08-25
"""
    _write_exclusive(output_root / "OWNER-APPROVAL-PROMPT.txt", prompt.encode())

    package_material = {
        "schema": "legalbot.v111.phase2a.consolidated-substantive-owner-package.v1",
        "status": batch["status"],
        "owner_batch_content_sha256": digest,
        "owner_batch_file_sha256": _sha256_file(batch_path),
        "owner_approval_prompt_file_sha256": _sha256_file(
            output_root / "OWNER-APPROVAL-PROMPT.txt"
        ),
        "owner_approved": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    package = {**package_material, "package_content_sha256": _sealed(package_material)}
    _write_exclusive(output_root / "PACKAGE-MANIFEST.json", _pretty_json(package))
    _write_exclusive(
        output_root / "OUTCOME.txt",
        b"PHASE 2A CONSOLIDATED SUBSTANTIVE BATCH READY - EXACT OWNER APPROVAL "
        b"REQUIRED; 364 MATERIAL GAPS REMAIN; NO SOURCE ADMITTED; PHASE 2B NOT AUTHORIZED\n",
    )
    return {
        "output_root": str(output_root),
        "status": batch["status"],
        "owner_batch_content_sha256": digest,
        "package_content_sha256": package["package_content_sha256"],
        "decision_summary": batch["decision_summary"],
        "owner_approved": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists():
            return
        material = {
            "schema": "legalbot.v111.phase2a.consolidated-substantive-owner-batch-failure.v1",
            "failure_type": type(exc).__name__,
            "failure_message": str(exc),
            "failure_fingerprint": _sha256(f"{type(exc).__name__}:{exc}".encode()),
            "affected_stage": "PHASE2A_CONSOLIDATED_SUBSTANTIVE_OWNER_GATE",
            "root_cause_status": "REQUIRES_DEBUG_BEFORE_RETRY",
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path, _pretty_json({**material, "failure_content_sha256": _sealed(material)})
        )
    except Exception:
        return


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args(argv)
    output_root = args.output_root.resolve()
    try:
        result = build(output_root=output_root)
    except Exception as exc:
        _persist_failure(output_root, exc)
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
