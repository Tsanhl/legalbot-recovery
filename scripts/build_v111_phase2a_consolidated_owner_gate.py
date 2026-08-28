#!/usr/bin/env python3
"""Build the complete, non-authorizing Phase-2A owner-review gate.

The command consolidates every Phase-2A row and every still-open owner
decision into one create-only package.  It verifies all predecessor seals,
preserves the sealed candidate, and never admits, indexes, embeds, qualifies,
or authorizes a later phase.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import stat
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from scripts.build_v111_phase2a_owner_review import (  # noqa: E402
    verify_remediation_package,
)

DEFAULT_REMEDIATION_ROOT = (
    PROJECT_ROOT / "data/evaluations/phase2a-remediation/v111-phase2a-remediation-20260824-r1"
)
DEFAULT_EFFECTS_PATH = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r4"
    / "owner-reviewed-legislative-effects-1896.json"
)
DEFAULT_APPROVAL_48_PATH = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r9"
    / "OWNER-DECISIONS-APPROVED-48.json"
)
DEFAULT_APPROVAL_35_PATH = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r16"
    / "OWNER-DECISIONS-APPROVED-35.json"
)
DEFAULT_APPROVAL_54_PATH = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r28"
    / "OWNER-DECISIONS-APPROVED-54.json"
)
DEFAULT_REMAINDER_PATH = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r29"
    / "REMAINING-448-RESEARCH-PACKETS.json"
)
DEFAULT_SOURCE_CUSTODY_PATH = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r29"
    / "APPROVED-SOURCE-CUSTODY-16.json"
)
DEFAULT_RERANKER_INTENT_PATH = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r36-independent-advisory"
    / "INTENT.json"
)
DEFAULT_RERANKER_PATH = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r36-independent-advisory"
    / "INDEPENDENT-RERANKER-ADVISORY-448.json"
)
DEFAULT_DEEP_COMPARISON_PATH = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r43-deep-comparison"
    / "DEEP-RANKING-COMPARISON-176.json"
)
DEFAULT_EFFECT_RECOVERY_PATH = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r39-effects-with-recovery"
    / "LEGISLATIVE-EFFECT-RELEVANCE-WITH-RECOVERY-516.json"
)
DEFAULT_JUDGMENT_PATH = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r35-judgments"
    / "JUDGMENT-SOURCE-CUSTODY-AND-LATER-TREATMENT-READINESS-20.json"
)
DEFAULT_TARGETED_LEADS_PATH = (
    PROJECT_ROOT
    / "data/quarantine/2026-08-24/phase2a-targeted-later-treatment-r42"
    / "TARGETED-LATER-TREATMENT-LEADS-9.json"
)
DEFAULT_BYTE_MISMATCH_PATH = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r46-byte-mismatch-reconciliation"
    / "LEGISLATION-BYTE-MISMATCH-RECONCILIATION-65.json"
)
DEFAULT_FRESH_QUARANTINE_MANIFEST_PATH = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r34-quarantine"
    / "QUARANTINE-MANIFEST.json"
)
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r47-consolidated-owner-gate"
)

EXPECTED_DIGESTS = {
    "remediation_package": "e81ae7c6d213e532b4f05e18152ba19c794cdacb531011bf552d7aa0629974a0",
    "effects": "a4e315a333d30c3e02c02c0228696b37b61481c4936ca32cf7d2a205168b34a7",
    "approval_48": "fe0e43bc791de02bb637b77f8b28c563d3deb4002b00d32006edcdbda010cfde",
    "approval_35": "95e3cfc304b195de8d2599211cfeb6e8159226aa5a3333fe501f096dc46f9a71",
    "approval_54": "40d7ded06badedee0349fcb3efc3c1ed2f707e2915c2b1d1208dc1796a73cf31",
    "remainder": "a7f7359c3ff12da02ee4056532198d39417459c9e20aac602f64437fb7cf5aa6",
    "source_custody": "3a7d1d6dbcac1422cdb101fa08e72e68d1eb2a222c7486b46cb27f1956e58dd5",
    "reranker_intent": "90b4ff8e3c9ecd0aac69301196f9d65ba7afe2bddc836f4bad025e9fe52ce75e",
    "reranker": "3f7ad672f0e35068919ca1d27483d5aa1e885ba1533800402b718cfafd6d670f",
    "deep_comparison": "798645d69ad56f7329e04267c22b8af70a17395f12abc19c65be7605735936fe",
    "effect_recovery": "f6317c99b73e1928497c0ef0d9331b4fbc4dc03ce6e34c3d304683980a9abab2",
    "judgments": "5dde5c94bfe77dce4c315767d50c06bb66f43e18a3a5021e9827bef2dafab5ad",
    "targeted_leads": "ad887ac1d18b06ed459b05471188cd6f999fa6b0580589edc4bbacc46cd902a9",
    "byte_mismatch": "8f7ea6aca83aea28c3ea5624dfcd337824433c75e5b605d75773c70440a21552",
    "fresh_quarantine": "5bd11e398bcf40a42b1dda5e3261a01bc2497fe9bd8fd41c886e1b8a18f502ff",
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OWNER_OPTIONS_ISSUE = [
    "APPROVE_INTERNAL_PROPOSITION_AND_EXACT_SPAN_BINDING",
    "APPROVE_WITH_NONMATERIAL_NOTE",
    "CONFIRM_MATERIAL_GAP",
    "REQUEST_MORE_EVIDENCE",
]
_OWNER_OPTIONS_EFFECT = [
    "APPROVE_METADATA_OR_CURRENTNESS_ONLY_DISPOSITION",
    "APPROVE_AS_PROPOSITION_MATERIAL",
    "CONFIRM_OUTSIDE_585_SCOPE",
    "REQUEST_MORE_EVIDENCE",
]
_OWNER_OPTIONS_JUDGMENT = [
    "AFFIRMED",
    "LIMITED",
    "DISTINGUISHED",
    "DISPLACED",
    "NO_MATERIAL_LATER_TREATMENT_IDENTIFIED",
    "EXCLUDE_BECAUSE_NO_585_PROPOSITION_RELIANCE",
    "REQUEST_MORE_EVIDENCE",
]
_OWNER_OPTIONS_BYTE = [
    "APPROVE_NONMATERIAL_REPRESENTATION_BYTE_MISMATCH",
    "APPROVE_FRESH_VERSION_AND_SUCCESSOR_SOURCE_SCOPE",
    "CONFIRM_MATERIAL_GAP",
    "REQUEST_MORE_EVIDENCE",
]
_OWNER_OPTIONS_SOURCE = [
    "ADMIT_FOR_APPROVED_PROPOSITION_LEVEL_USE",
    "KEEP_QUARANTINED_AS_REVIEW_EVIDENCE_ONLY",
    "REJECT_SOURCE",
    "REQUEST_MORE_EVIDENCE",
]


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


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


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_consolidated_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_consolidated_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], *, field: str, expected: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != expected:
        raise ValueError(code)
    if supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _require_list(value: Any, *, count: int, code: str) -> list[dict[str, Any]]:
    if (
        not isinstance(value, list)
        or len(value) != count
        or any(not isinstance(row, dict) for row in value)
    ):
        raise ValueError(code)
    return value


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


def _sealed_record(schema: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    material = {"schema": schema, **payload}
    return {**material, "record_content_sha256": _sealed(material)}


def _sealed_artifact(
    schema: str, *, records_key: str, records: Sequence[dict[str, Any]], **metadata: Any
) -> dict[str, Any]:
    material = {
        "schema": schema,
        **metadata,
        f"{records_key[:-1] if records_key.endswith('s') else records_key}_count": len(records),
        records_key: list(records),
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    return {**material, "artifact_content_sha256": _sealed(material)}


def _approval_rows(
    value: dict[str, Any], *, collection: str, expected_count: int, source: str
) -> dict[str, dict[str, Any]]:
    rows = _require_list(
        value.get(collection), count=expected_count, code="phase2a_approval_rows_invalid"
    )
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        row_id = str(row.get("row_id") or "")
        if not row_id or row_id in result:
            raise ValueError("phase2a_approval_row_identity_invalid")
        result[row_id] = {"approval_source": source, "owner_record": row}
    return result


def _source_boundary(value: Mapping[str, Any]) -> None:
    for field in ("phase2b_authorized", "development30_authorized"):
        if field in value and value.get(field) is not False:
            raise ValueError("phase2a_consolidated_source_gate_boundary_invalid")
    if "candidate_mutated" in value and value.get("candidate_mutated") is not False:
        raise ValueError("phase2a_consolidated_candidate_boundary_invalid")


def _candidate_summary(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not value:
        return None
    return {
        key: value.get(key)
        for key in (
            "authority_identity_id",
            "source_version_id",
            "title",
            "canonical_citation",
            "locator",
            "full_span_text_sha256",
            "span_bundle_sha256",
            "candidate_record_content_sha256",
            "identity_verified",
            "currentness_verified",
            "later_treatment_review_required",
            "reranker_score",
        )
    }


def _effect_key(value: Mapping[str, Any]) -> tuple[str, int, str]:
    return (
        str(value.get("source_version_id") or ""),
        int(value.get("source_effect_ordinal") or 0),
        str(value.get("source_record_sha256") or value.get("record_sha256") or ""),
    )


def _csv_bytes(fieldnames: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


def _write_machine_files(
    output_root: Path, files: Mapping[str, bytes]
) -> tuple[str, dict[str, dict[str, Any]]]:
    for name, raw in files.items():
        _write_exclusive(output_root / name, raw)
    entries = {
        name: {"sha256": _sha256(raw), "bytes": len(raw)} for name, raw in sorted(files.items())
    }
    material = {
        "schema": "legalbot.v111.phase2a.consolidated-owner-gate-index.v1",
        "status": "OWNER_DECISIONS_REQUIRED_PHASE2A_ONLY",
        "file_count": len(entries),
        "files": entries,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    index = {**material, "machine_package_content_sha256": _sealed(material)}
    index_raw = _pretty_json(index)
    _write_exclusive(output_root / "MACHINE-PACKAGE-INDEX.json", index_raw)
    checksummed = sorted(path for path in output_root.iterdir() if path.is_file())
    sums = "".join(f"{_sha256_file(path)}  {path.name}\n" for path in checksummed)
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode())
    return index["machine_package_content_sha256"], entries


def build_consolidated_owner_gate(
    *,
    remediation_root: Path,
    effects_path: Path,
    approval_48_path: Path,
    approval_35_path: Path,
    approval_54_path: Path,
    remainder_path: Path,
    source_custody_path: Path,
    reranker_intent_path: Path,
    reranker_path: Path,
    deep_comparison_path: Path,
    effect_recovery_path: Path,
    judgment_path: Path,
    targeted_leads_path: Path,
    byte_mismatch_path: Path,
    fresh_quarantine_manifest_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Create the complete machine-readable owner-review package."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_consolidated_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_consolidated_output_mode_invalid")

    verified = verify_remediation_package(remediation_root)
    if verified["index"].get("package_digest") != EXPECTED_DIGESTS["remediation_package"]:
        raise ValueError("phase2a_consolidated_remediation_digest_invalid")
    source_artifacts = verified["artifacts"]

    effects_source = _load_object(effects_path)
    _verify_seal(
        effects_source,
        field="artifact_content_sha256",
        expected=EXPECTED_DIGESTS["effects"],
        code="phase2a_consolidated_effects_seal_invalid",
    )
    approval_48 = _load_object(approval_48_path)
    _verify_seal(
        approval_48,
        field="approved_package_content_sha256",
        expected=EXPECTED_DIGESTS["approval_48"],
        code="phase2a_consolidated_approval_48_seal_invalid",
    )
    approval_35 = _load_object(approval_35_path)
    _verify_seal(
        approval_35,
        field="approved_package_content_sha256",
        expected=EXPECTED_DIGESTS["approval_35"],
        code="phase2a_consolidated_approval_35_seal_invalid",
    )
    approval_54 = _load_object(approval_54_path)
    _verify_seal(
        approval_54,
        field="approved_package_content_sha256",
        expected=EXPECTED_DIGESTS["approval_54"],
        code="phase2a_consolidated_approval_54_seal_invalid",
    )
    remainder = _load_object(remainder_path)
    _verify_seal(
        remainder,
        field="artifact_content_sha256",
        expected=EXPECTED_DIGESTS["remainder"],
        code="phase2a_consolidated_remainder_seal_invalid",
    )
    source_custody = _load_object(source_custody_path)
    _verify_seal(
        source_custody,
        field="artifact_content_sha256",
        expected=EXPECTED_DIGESTS["source_custody"],
        code="phase2a_consolidated_source_custody_seal_invalid",
    )
    reranker_intent = _load_object(reranker_intent_path)
    _verify_seal(
        reranker_intent,
        field="intent_content_sha256",
        expected=EXPECTED_DIGESTS["reranker_intent"],
        code="phase2a_consolidated_reranker_intent_seal_invalid",
    )
    reranker = _load_object(reranker_path)
    _verify_seal(
        reranker,
        field="artifact_content_sha256",
        expected=EXPECTED_DIGESTS["reranker"],
        code="phase2a_consolidated_reranker_seal_invalid",
    )
    deep = _load_object(deep_comparison_path)
    _verify_seal(
        deep,
        field="artifact_content_sha256",
        expected=EXPECTED_DIGESTS["deep_comparison"],
        code="phase2a_consolidated_deep_seal_invalid",
    )
    effect_recovery = _load_object(effect_recovery_path)
    _verify_seal(
        effect_recovery,
        field="artifact_content_sha256",
        expected=EXPECTED_DIGESTS["effect_recovery"],
        code="phase2a_consolidated_effect_recovery_seal_invalid",
    )
    judgments = _load_object(judgment_path)
    _verify_seal(
        judgments,
        field="artifact_content_sha256",
        expected=EXPECTED_DIGESTS["judgments"],
        code="phase2a_consolidated_judgment_seal_invalid",
    )
    leads = _load_object(targeted_leads_path)
    _verify_seal(
        leads,
        field="artifact_content_sha256",
        expected=EXPECTED_DIGESTS["targeted_leads"],
        code="phase2a_consolidated_targeted_leads_seal_invalid",
    )
    byte_mismatch = _load_object(byte_mismatch_path)
    _verify_seal(
        byte_mismatch,
        field="artifact_content_sha256",
        expected=EXPECTED_DIGESTS["byte_mismatch"],
        code="phase2a_consolidated_byte_mismatch_seal_invalid",
    )
    quarantine = _load_object(fresh_quarantine_manifest_path)
    _verify_seal(
        quarantine,
        field="manifest_sha256",
        expected=EXPECTED_DIGESTS["fresh_quarantine"],
        code="phase2a_consolidated_quarantine_seal_invalid",
    )
    for source in (
        effects_source,
        approval_48,
        approval_35,
        approval_54,
        remainder,
        source_custody,
        reranker_intent,
        reranker,
        deep,
        effect_recovery,
        judgments,
        leads,
        byte_mismatch,
        quarantine,
    ):
        _source_boundary(source)

    original_rows = _require_list(
        source_artifacts["remediation-matrix-585"].get("rows"),
        count=585,
        code="phase2a_consolidated_original_rows_invalid",
    )
    original_by_id = {str(row.get("row_id") or ""): row for row in original_rows}
    if len(original_by_id) != 585 or "" in original_by_id:
        raise ValueError("phase2a_consolidated_original_row_identity_invalid")

    approvals: dict[str, dict[str, Any]] = {}
    for package in (
        _approval_rows(approval_48, collection="decisions", expected_count=48, source="r9-48"),
        _approval_rows(approval_35, collection="decisions", expected_count=35, source="r16-35"),
        _approval_rows(approval_54, collection="rows", expected_count=54, source="r28-54"),
    ):
        if set(approvals) & set(package):
            raise ValueError("phase2a_consolidated_duplicate_approval_row")
        approvals.update(package)
    if len(approvals) != 137 or not set(approvals).issubset(original_by_id):
        raise ValueError("phase2a_consolidated_approval_union_invalid")

    remainder_rows = _require_list(
        remainder.get("rows"), count=448, code="phase2a_consolidated_remainder_rows_invalid"
    )
    remainder_by_id = {str(row.get("row_id") or ""): row for row in remainder_rows}
    if len(remainder_by_id) != 448 or set(remainder_by_id) != set(original_by_id) - set(approvals):
        raise ValueError("phase2a_consolidated_remainder_partition_invalid")

    reranker_rows = _require_list(
        reranker.get("rows"), count=448, code="phase2a_consolidated_reranker_rows_invalid"
    )
    reranker_by_id = {str(row.get("row_id") or ""): row for row in reranker_rows}
    if set(reranker_by_id) != set(remainder_by_id):
        raise ValueError("phase2a_consolidated_reranker_partition_invalid")
    deep_rows = _require_list(
        deep.get("rows"), count=176, code="phase2a_consolidated_deep_rows_invalid"
    )
    deep_by_id = {str(row.get("row_id") or ""): row for row in deep_rows}
    if len(deep_by_id) != 176 or not set(deep_by_id).issubset(remainder_by_id):
        raise ValueError("phase2a_consolidated_deep_partition_invalid")

    matrix_rows: list[dict[str, Any]] = []
    pending_issue_decisions: list[dict[str, Any]] = []
    issue_csv: list[dict[str, Any]] = []
    for original in original_rows:
        row_id = str(original["row_id"])
        if row_id in approvals:
            decision = {
                "status": "RECORDED_OWNER_PHASE2A_DECISION",
                "approval": approvals[row_id],
                "owner_outcome": (
                    approvals[row_id]["owner_record"].get("owner_outcome")
                    or approvals[row_id]["owner_record"].get("owner_materiality_decision")
                ),
                "technical_qualification_status": "NOT_YET_RERUN",
            }
            research_packet = None
            advisory = None
            deep_record = None
        else:
            research_packet = remainder_by_id[row_id]
            advisory = reranker_by_id[row_id]
            deep_record = deep_by_id.get(row_id)
            ranked = advisory.get("ranked_candidates")
            if not isinstance(ranked, list) or not ranked:
                raise ValueError("phase2a_consolidated_ranked_candidates_missing")
            top = deep_record.get("deep_top") if deep_record else ranked[0]
            if not isinstance(top, dict):
                raise ValueError("phase2a_consolidated_top_candidate_invalid")
            track = (
                str(deep_record.get("advisory_review_track"))
                if deep_record
                else (
                    "INSPECT_CASE_AFTER_LATER_TREATMENT"
                    if top.get("later_treatment_review_required") is True
                    else "INSPECT_TOP_CURRENT_NONCASE"
                )
            )
            decision = {
                "status": "PENDING_EXPLICIT_OWNER_DECISION",
                "advisory_review_track": track,
                "advisory_primary_candidate": _candidate_summary(top),
                "advisory_recommendation": (
                    "OWNER_SELECT_OR_REJECT_EXACT_PROPOSITION_AND_SPAN_BINDING"
                ),
                "owner_decision_options": _OWNER_OPTIONS_ISSUE,
                "owner_outcome": None,
                "owner_comments": None,
                "technical_qualification_status": "BLOCKED_PENDING_OWNER_DECISION",
            }
            pending_issue_decisions.append(
                _sealed_record(
                    "legalbot.v111.phase2a.owner-decision-item.issue.v1",
                    {
                        "category": "issue",
                        "item_id": row_id,
                        "case_id": original.get("case_id"),
                        "issue_id": original.get("issue_id"),
                        "issue_label": original.get("issue_label"),
                        "legal_domain": original.get("legal_domain"),
                        "source_row_evidence_sha256": original.get("row_evidence_sha256"),
                        "advisory_review_track": track,
                        "advisory_primary_candidate": _candidate_summary(top),
                        "recommendation": (
                            "OWNER_SELECT_OR_REJECT_EXACT_PROPOSITION_AND_SPAN_BINDING"
                        ),
                        "decision_readiness": (
                            "EVIDENCE_PACKET_READY_OWNER_MUST_CONFIRM_PROPOSITION_AND_SPAN"
                        ),
                        "owner_decision_options": _OWNER_OPTIONS_ISSUE,
                        "owner_outcome": None,
                        "owner_comments": None,
                    },
                )
            )
            top_summary = _candidate_summary(top) or {}
            issue_csv.append(
                {
                    "ordinal": original.get("ordinal"),
                    "row_id": row_id,
                    "case_id": original.get("case_id"),
                    "issue_id": original.get("issue_id"),
                    "issue_label": original.get("issue_label"),
                    "legal_domain": original.get("legal_domain"),
                    "review_track": track,
                    "top_title": top_summary.get("title"),
                    "top_locator": top_summary.get("locator"),
                    "top_source_version_id": top_summary.get("source_version_id"),
                    "top_reranker_score": top_summary.get("reranker_score"),
                    "owner_outcome": "",
                    "owner_comments": "",
                }
            )
        matrix_rows.append(
            _sealed_record(
                "legalbot.v111.phase2a.consolidated-remediation-row.v1",
                {
                    "ordinal": original.get("ordinal"),
                    "row_id": row_id,
                    "baseline_primary_status": original.get("baseline_primary_status"),
                    "original_remediation_row": original,
                    "owner_decision": decision,
                    "remaining_research_packet": research_packet,
                    "independent_advisory_ranking": advisory,
                    "deep_recovery_comparison": deep_record,
                    "owner_adopted_qualified": False,
                    "candidate_mutated": False,
                    "phase2b_authorized": False,
                    "development30_authorized": False,
                },
            )
        )

    matrix = _sealed_artifact(
        "legalbot.v111.phase2a.consolidated-remediation-matrix.v1",
        records_key="rows",
        records=matrix_rows,
        status="137_OWNER_DECISIONS_RECORDED_448_OWNER_DECISIONS_REQUIRED",
        total_row_count=585,
        recorded_owner_decision_count=137,
        pending_owner_decision_count=448,
        technical_qualification_rerun_complete=False,
        source_remediation_package_digest=EXPECTED_DIGESTS["remediation_package"],
        source_approval_content_sha256s=[
            EXPECTED_DIGESTS["approval_48"],
            EXPECTED_DIGESTS["approval_35"],
            EXPECTED_DIGESTS["approval_54"],
        ],
        source_remainder_content_sha256=EXPECTED_DIGESTS["remainder"],
        source_independent_reranker_content_sha256=EXPECTED_DIGESTS["reranker"],
        source_deep_comparison_content_sha256=EXPECTED_DIGESTS["deep_comparison"],
    )

    matrix_by_id = {row["row_id"]: row for row in matrix_rows}

    def reconciliation(source_name: str, output_schema: str, expected_count: int) -> dict[str, Any]:
        source = source_artifacts[source_name]
        records = _require_list(
            source.get("records"),
            count=expected_count,
            code="phase2a_consolidated_reconciliation_records_invalid",
        )
        result: list[dict[str, Any]] = []
        for record in records:
            row_id = str(record.get("row_id") or "")
            consolidated = matrix_by_id.get(row_id)
            if consolidated is None:
                raise ValueError("phase2a_consolidated_reconciliation_row_missing")
            result.append(
                _sealed_record(
                    f"{output_schema}.row",
                    {
                        "ordinal": record.get("ordinal"),
                        "row_id": row_id,
                        "source_reconciliation_record": record,
                        "consolidated_remediation_row_content_sha256": consolidated[
                            "record_content_sha256"
                        ],
                        "owner_decision_status": consolidated["owner_decision"]["status"],
                        "owner_outcome": consolidated["owner_decision"].get("owner_outcome"),
                        "technical_qualification_status": consolidated["owner_decision"][
                            "technical_qualification_status"
                        ],
                    },
                )
            )
        statuses = Counter(row["owner_decision_status"] for row in result)
        return _sealed_artifact(
            output_schema,
            records_key="records",
            records=result,
            status="OWNER_REVIEW_INCOMPLETE_TECHNICAL_QUALIFICATION_NOT_RERUN",
            source_artifact_sha256=source.get("artifact_sha256"),
            owner_decision_status_counts=dict(sorted(statuses.items())),
        )

    gold = reconciliation(
        "gold-case-reconciliation-509",
        "legalbot.v111.phase2a.consolidated-gold-case-reconciliation.v1",
        509,
    )
    candidate = reconciliation(
        "candidate-impact-reconciliation-76",
        "legalbot.v111.phase2a.consolidated-candidate-impact-reconciliation.v1",
        76,
    )
    if (
        gold["owner_decision_status_counts"].get("RECORDED_OWNER_PHASE2A_DECISION") != 107
        or candidate["owner_decision_status_counts"].get("RECORDED_OWNER_PHASE2A_DECISION") != 30
    ):
        raise ValueError("phase2a_consolidated_reconciliation_approval_counts_invalid")

    effect_rows = _require_list(
        effects_source.get("effects"),
        count=1896,
        code="phase2a_consolidated_effect_rows_invalid",
    )
    effect_recovery_rows = _require_list(
        effect_recovery.get("effects"),
        count=516,
        code="phase2a_consolidated_effect_recovery_rows_invalid",
    )
    effect_recovery_by_key = {_effect_key(row): row for row in effect_recovery_rows}
    if len(effect_recovery_by_key) != 516:
        raise ValueError("phase2a_consolidated_effect_recovery_identity_invalid")
    consolidated_effects: list[dict[str, Any]] = []
    pending_effect_decisions: list[dict[str, Any]] = []
    effect_csv: list[dict[str, Any]] = []
    approved_effect_count = 0
    for effect in effect_rows:
        review = effect.get("owner_review")
        if not isinstance(review, dict):
            raise ValueError("phase2a_consolidated_effect_owner_review_invalid")
        if review.get("owner_outcome") == "APPROVE_EFFECT_DISPOSITION":
            approved_effect_count += 1
            status = "RECORDED_OWNER_EFFECT_DISPOSITION"
            recovery = None
            recommendation = None
        else:
            recovery = effect_recovery_by_key.get(_effect_key(effect))
            if recovery is None:
                raise ValueError("phase2a_consolidated_pending_effect_mapping_missing")
            status = "PENDING_EXPLICIT_OWNER_DECISION"
            recommendation = recovery.get("advisory_recommendation")
            item = _sealed_record(
                "legalbot.v111.phase2a.owner-decision-item.legislative-effect.v1",
                {
                    "category": "legislative_effect",
                    "item_id": f"effect-{int(effect.get('ordinal') or 0):04d}",
                    "effect_id": effect.get("effect_id"),
                    "source_version_id": effect.get("source_version_id"),
                    "source_effect_ordinal": effect.get("source_effect_ordinal"),
                    "source_record_sha256": effect.get("record_sha256"),
                    "source_title": effect.get("source_title"),
                    "affected_provisions": effect.get("affected_provisions"),
                    "affecting_provisions": effect.get("affecting_provisions"),
                    "recommendation": recommendation,
                    "recommendation_scope": (
                        "METADATA_OR_CURRENTNESS_ONLY_PENDING_FINAL_PROPOSITION_BINDING"
                    ),
                    "owner_decision_options": _OWNER_OPTIONS_EFFECT,
                    "owner_outcome": None,
                    "owner_comments": None,
                },
            )
            pending_effect_decisions.append(item)
            effect_csv.append(
                {
                    "ordinal": effect.get("ordinal"),
                    "item_id": item["item_id"],
                    "effect_id": effect.get("effect_id"),
                    "source_title": effect.get("source_title"),
                    "affected_provisions": effect.get("affected_provisions"),
                    "affecting_provisions": effect.get("affecting_provisions"),
                    "recommendation": recommendation,
                    "owner_outcome": "",
                    "owner_comments": "",
                }
            )
        consolidated_effects.append(
            _sealed_record(
                "legalbot.v111.phase2a.consolidated-legislative-effect-row.v1",
                {
                    "ordinal": effect.get("ordinal"),
                    "effect_record": effect,
                    "owner_decision_status": status,
                    "effect_relevance_recovery": recovery,
                    "advisory_recommendation": recommendation,
                    "technical_qualification_assigned": False,
                },
            )
        )
    if approved_effect_count != 1380 or len(pending_effect_decisions) != 516:
        raise ValueError("phase2a_consolidated_effect_partition_invalid")
    effects = _sealed_artifact(
        "legalbot.v111.phase2a.consolidated-legislative-effects.v1",
        records_key="effects",
        records=consolidated_effects,
        status="1380_RECORDED_516_OWNER_DECISIONS_REQUIRED",
        total_effect_count=1896,
        recorded_owner_decision_count=1380,
        pending_owner_decision_count=516,
        common_cutoff_supportable=False,
        source_effects_content_sha256=EXPECTED_DIGESTS["effects"],
        source_effect_recovery_content_sha256=EXPECTED_DIGESTS["effect_recovery"],
    )

    lead_rows = _require_list(
        leads.get("records"), count=9, code="phase2a_consolidated_leads_invalid"
    )
    leads_by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for lead in lead_rows:
        targets = lead.get("target_neutral_citations")
        if not isinstance(targets, list) or not targets:
            raise ValueError("phase2a_consolidated_lead_targets_invalid")
        for target in targets:
            leads_by_target[str(target)].append(lead)

    judgment_rows = _require_list(
        judgments.get("records"),
        count=20,
        code="phase2a_consolidated_judgment_rows_invalid",
    )
    consolidated_judgments: list[dict[str, Any]] = []
    pending_judgment_decisions: list[dict[str, Any]] = []
    judgment_csv: list[dict[str, Any]] = []
    for judgment in judgment_rows:
        citation = str(judgment.get("neutral_citation") or "")
        attached = sorted(leads_by_target.get(citation, []), key=lambda row: row["lead_id"])
        recommendation = (
            "REVIEW_TARGETED_LEADS_AND_RECORD_TREATMENT_RELATIONSHIP"
            if attached
            else "RESEARCH_OR_CONFIRM_NO_585_PROPOSITION_RELIANCE"
        )
        consolidated_judgments.append(
            _sealed_record(
                "legalbot.v111.phase2a.consolidated-judgment-row.v1",
                {
                    "ordinal": judgment.get("ordinal"),
                    "judgment_record": judgment,
                    "targeted_later_treatment_leads": attached,
                    "targeted_lead_count": len(attached),
                    "absence_of_targeted_lead_proves_no_later_treatment": False,
                    "owner_decision_status": "PENDING_EXPLICIT_OWNER_DECISION",
                    "advisory_recommendation": recommendation,
                    "owner_decision_options": _OWNER_OPTIONS_JUDGMENT,
                    "owner_outcome": None,
                    "owner_comments": None,
                },
            )
        )
        item = _sealed_record(
            "legalbot.v111.phase2a.owner-decision-item.judgment.v1",
            {
                "category": "judgment",
                "item_id": str(judgment.get("source_version_id") or ""),
                "title": judgment.get("title"),
                "neutral_citation": citation,
                "source_version_id": judgment.get("source_version_id"),
                "packet_content_sha256": judgment.get("packet_content_sha256"),
                "targeted_lead_ids": [lead["lead_id"] for lead in attached],
                "targeted_search_is_exhaustive": False,
                "recommendation": recommendation,
                "owner_decision_options": _OWNER_OPTIONS_JUDGMENT,
                "owner_outcome": None,
                "owner_comments": None,
            },
        )
        pending_judgment_decisions.append(item)
        judgment_csv.append(
            {
                "ordinal": judgment.get("ordinal"),
                "source_version_id": judgment.get("source_version_id"),
                "title": judgment.get("title"),
                "neutral_citation": citation,
                "targeted_lead_ids": ";".join(lead["lead_id"] for lead in attached),
                "recommendation": recommendation,
                "owner_outcome": "",
                "owner_comments": "",
            }
        )
    judgments_artifact = _sealed_artifact(
        "legalbot.v111.phase2a.consolidated-judgment-later-treatment.v1",
        records_key="records",
        records=consolidated_judgments,
        status="20_OWNER_LATER_TREATMENT_DECISIONS_REQUIRED",
        pending_owner_decision_count=20,
        targeted_lead_count=9,
        targeted_search_is_exhaustive=False,
        common_cutoff_supportable=False,
        source_judgment_readiness_content_sha256=EXPECTED_DIGESTS["judgments"],
        source_targeted_leads_content_sha256=EXPECTED_DIGESTS["targeted_leads"],
    )

    mismatch_rows = _require_list(
        byte_mismatch.get("records"),
        count=65,
        code="phase2a_consolidated_mismatch_rows_invalid",
    )
    source_row_refs: dict[str, set[str]] = defaultdict(set)
    source_exact_locator_refs: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row_id, packet in remainder_by_id.items():
        candidates = packet.get("candidates")
        if not isinstance(candidates, list):
            raise ValueError("phase2a_consolidated_remainder_candidates_invalid")
        for candidate_row in candidates:
            if not isinstance(candidate_row, dict):
                raise ValueError("phase2a_consolidated_remainder_candidate_invalid")
            source_version_id = str(candidate_row.get("source_version_id") or "")
            locator = str(candidate_row.get("locator") or "").strip().lower()
            if source_version_id:
                source_row_refs[source_version_id].add(row_id)
                if locator:
                    source_exact_locator_refs[(source_version_id, locator)].add(row_id)

    mismatch_records: list[dict[str, Any]] = []
    pending_mismatch_decisions: list[dict[str, Any]] = []
    mismatch_csv: list[dict[str, Any]] = []
    mismatch_counts: Counter[str] = Counter()
    for mismatch in mismatch_rows:
        comparison = mismatch.get("comparison")
        if not isinstance(comparison, dict):
            raise ValueError("phase2a_consolidated_mismatch_comparison_invalid")
        classification = str(comparison.get("classification") or "")
        mismatch_counts[classification] += 1
        source_version_id = str(mismatch.get("source_version_id") or "")
        changed_locators = sorted(
            {
                str(row.get("locator") or "").strip().lower()
                for field in ("changed", "removed", "added")
                for row in comparison.get(field, [])
                if isinstance(row, dict) and str(row.get("locator") or "").strip()
            }
        )
        exact_rows = sorted(
            {
                row_id
                for locator in changed_locators
                for row_id in source_exact_locator_refs.get((source_version_id, locator), set())
            }
        )
        recommendation = str(comparison.get("advisory_recommendation") or "")
        if classification != "SEMANTIC_PROVISION_TEXT_IDENTICAL_BYTE_MISMATCH_ONLY":
            recommendation = (
                "REVIEW_PATENTS_ACT_1977_SECTION_60_7_DELTA_FOR_PROPOSITION_MATERIALITY"
            )
        record = _sealed_record(
            "legalbot.v111.phase2a.consolidated-byte-mismatch-row.v1",
            {
                "ordinal": mismatch.get("ordinal"),
                "byte_mismatch_record": mismatch,
                "referencing_pending_issue_row_ids": sorted(
                    source_row_refs.get(source_version_id, set())
                ),
                "exact_changed_locator_pending_issue_row_ids": exact_rows,
                "advisory_recommendation": recommendation,
                "owner_decision_status": "PENDING_EXPLICIT_OWNER_DECISION",
                "owner_decision_options": _OWNER_OPTIONS_BYTE,
                "owner_outcome": None,
                "owner_comments": None,
            },
        )
        mismatch_records.append(record)
        item = _sealed_record(
            "legalbot.v111.phase2a.owner-decision-item.byte-mismatch.v1",
            {
                "category": "legislation_byte_mismatch",
                "item_id": source_version_id,
                "title": mismatch.get("title"),
                "authority_identity": mismatch.get("authority_identity"),
                "classification": classification,
                "changed_locators": changed_locators,
                "exact_changed_locator_pending_issue_row_ids": exact_rows,
                "recommendation": recommendation,
                "owner_decision_options": _OWNER_OPTIONS_BYTE,
                "owner_outcome": None,
                "owner_comments": None,
            },
        )
        pending_mismatch_decisions.append(item)
        mismatch_csv.append(
            {
                "ordinal": mismatch.get("ordinal"),
                "source_version_id": source_version_id,
                "title": mismatch.get("title"),
                "classification": classification,
                "changed_locators": ";".join(changed_locators),
                "exact_changed_locator_pending_issue_row_ids": ";".join(exact_rows),
                "recommendation": recommendation,
                "owner_outcome": "",
                "owner_comments": "",
            }
        )
    if mismatch_counts != {
        "SEMANTIC_PROVISION_TEXT_IDENTICAL_BYTE_MISMATCH_ONLY": 64,
        "FRESH_OFFICIAL_VERSION_HAS_CHANGED_OR_REMOVED_PROVISION_BLOCKS": 1,
    }:
        raise ValueError("phase2a_consolidated_mismatch_counts_invalid")
    mismatch_artifact = _sealed_artifact(
        "legalbot.v111.phase2a.consolidated-legislation-byte-mismatches.v1",
        records_key="records",
        records=mismatch_records,
        status="64_BYTE_ONLY_1_TEXT_DELTA_ALL_REQUIRE_OWNER_DECISION",
        pending_owner_decision_count=65,
        classification_counts=dict(sorted(mismatch_counts.items())),
        source_byte_mismatch_content_sha256=EXPECTED_DIGESTS["byte_mismatch"],
    )

    quarantine_records = quarantine.get("records")
    if not isinstance(quarantine_records, list):
        raise ValueError("phase2a_consolidated_quarantine_records_invalid")
    unavailable = [
        record
        for record in quarantine_records
        if isinstance(record, dict) and record.get("result") == "OFFICIAL_SOURCE_UNAVAILABLE"
    ]
    if len(unavailable) != 3:
        raise ValueError("phase2a_consolidated_unavailable_record_count_invalid")
    judgment_by_source = {str(row.get("source_version_id") or ""): row for row in judgment_rows}
    unavailable_records = [
        _sealed_record(
            "legalbot.v111.phase2a.consolidated-unavailable-official-record.v1",
            {
                "ordinal": index,
                "quarantine_record": record,
                "historical_local_recovery_provenance": judgment_by_source[
                    str(record.get("target_id") or "")
                ].get("historical_local_recovery_provenance"),
                "historical_snapshot_integrity_verified": True,
                "present_law_currentness_verified": False,
                "owner_decision_required": True,
            },
        )
        for index, record in enumerate(unavailable, start=1)
    ]
    unavailable_artifact = _sealed_artifact(
        "legalbot.v111.phase2a.consolidated-unavailable-official-records.v1",
        records_key="records",
        records=unavailable_records,
        status="3_FRESH_PAGES_UNAVAILABLE_HISTORICAL_BYTES_VERIFIED_CURRENTNESS_UNRESOLVED",
        source_quarantine_manifest_sha256=EXPECTED_DIGESTS["fresh_quarantine"],
    )

    pending_source_decisions: list[dict[str, Any]] = []
    pending_source_records: list[dict[str, Any]] = []
    for lead in lead_rows:
        source_record = _sealed_record(
            "legalbot.v111.phase2a.pending-later-treatment-source-admission.v1",
            {
                "lead_id": lead.get("lead_id"),
                "candidate_neutral_citation": lead.get("candidate_neutral_citation"),
                "candidate_case_name": lead.get("candidate_case_name"),
                "target_neutral_citations": lead.get("target_neutral_citations"),
                "official_case_page": lead.get("official_case_page"),
                "official_judgment_pdf": lead.get("official_judgment_pdf"),
                "source_status": "QUARANTINED_REVIEW_EVIDENCE_ONLY",
                "proposition_level_materiality_approved": False,
                "source_admitted": False,
                "indexed": False,
                "embedded": False,
                "owner_decision_required": True,
            },
        )
        pending_source_records.append(source_record)
        pending_source_decisions.append(
            _sealed_record(
                "legalbot.v111.phase2a.owner-decision-item.source-admission.v1",
                {
                    "category": "source_admission",
                    "item_id": lead.get("lead_id"),
                    "candidate_neutral_citation": lead.get("candidate_neutral_citation"),
                    "candidate_case_name": lead.get("candidate_case_name"),
                    "target_neutral_citations": lead.get("target_neutral_citations"),
                    "recommendation": (
                        "KEEP_QUARANTINED_PENDING_JUDGMENT_TREATMENT_AND_PROPOSITION_DECISION"
                    ),
                    "owner_decision_options": _OWNER_OPTIONS_SOURCE,
                    "owner_outcome": None,
                    "owner_comments": None,
                },
            )
        )
    source_register_material = {
        "schema": "legalbot.v111.phase2a.consolidated-source-custody-and-admission.v1",
        "status": "16_PREVIOUSLY_APPROVED_AUTHORITIES_VERIFIED_9_NEW_LEADS_QUARANTINED",
        "approved_source_custody_content_sha256": EXPECTED_DIGESTS["source_custody"],
        "approved_authority_count": 16,
        "approved_source_custody": source_custody,
        "pending_later_treatment_source_count": 9,
        "pending_later_treatment_sources": pending_source_records,
        "automatic_source_admission": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "successor_candidate_built": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    source_register = {
        **source_register_material,
        "artifact_content_sha256": _sealed(source_register_material),
    }

    decision_items = [
        *pending_issue_decisions,
        *pending_effect_decisions,
        *pending_judgment_decisions,
        *pending_mismatch_decisions,
        *pending_source_decisions,
    ]
    decision_counts = Counter(str(item["category"]) for item in decision_items)
    expected_decision_counts = {
        "issue": 448,
        "legislative_effect": 516,
        "judgment": 20,
        "legislation_byte_mismatch": 65,
        "source_admission": 9,
    }
    if dict(decision_counts) != expected_decision_counts or len(decision_items) != 1058:
        raise ValueError("phase2a_consolidated_decision_batch_counts_invalid")
    immediately_approvable = [
        item["record_content_sha256"]
        for item in decision_items
        if item["category"] == "legislative_effect"
        or (
            item["category"] == "legislation_byte_mismatch"
            and item.get("classification") == "SEMANTIC_PROVISION_TEXT_IDENTICAL_BYTE_MISMATCH_ONLY"
        )
    ]
    if len(immediately_approvable) != 580:
        raise ValueError("phase2a_consolidated_immediately_approvable_count_invalid")
    decision_material = {
        "schema": "legalbot.v111.phase2a.consolidated-owner-decision-batch.v1",
        "status": "OWNER_DECISIONS_REQUIRED_CONTINUED_PHASE2A_ONLY",
        "owner_route": "OWNER_ADOPTED_INTERNAL_RESEARCH_TOOL_NOT_PROFESSIONAL_CERTIFICATION",
        "item_count": len(decision_items),
        "category_counts": expected_decision_counts,
        "items": decision_items,
        "immediately_approvable_deterministic_recommendation_count": 580,
        "immediately_approvable_item_content_sha256s": immediately_approvable,
        "blanket_approval_of_all_1058_items_would_not_supply_missing_issue_propositions": True,
        "ai_review_advisory_only": True,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "successor_candidate_built": False,
        "retrieval_reattestation_rerun": False,
        "corrected_all585_qualification_rerun": False,
        "common_cutoff_supportable": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    decision_batch = {
        **decision_material,
        "owner_decision_batch_content_sha256": _sealed(decision_material),
    }
    decision_digest = decision_batch["owner_decision_batch_content_sha256"]

    overview_material = {
        "schema": "legalbot.v111.phase2a.consolidated-owner-gate-overview.v1",
        "status": "PHASE2A_OWNER_DECISIONS_REQUIRED",
        "owner_decision_batch_content_sha256": decision_digest,
        "issue_counts": {"total": 585, "recorded": 137, "pending": 448},
        "reconciliation_counts": {
            "gold_or_case": {"total": 509, "recorded": 107, "pending": 402},
            "candidate_impact": {"total": 76, "recorded": 30, "pending": 46},
        },
        "legislative_effect_counts": {"total": 1896, "recorded": 1380, "pending": 516},
        "judgment_counts": {"total": 20, "pending": 20, "targeted_leads": 9},
        "byte_mismatch_counts": {
            "total": 65,
            "semantic_text_identical": 64,
            "changed_text": 1,
        },
        "unavailable_official_record_count": 3,
        "approved_source_authority_count": 16,
        "new_quarantined_later_treatment_lead_count": 9,
        "independent_reviewer": reranker_intent["runtime_identity"],
        "reviewer_is_model_independent_from_drafting_adapter": True,
        "review_scores_are_not_release_thresholds": True,
        "sealed_candidate_immutable": True,
        "successor_candidate_built": False,
        "successor_candidate_requirement": "UNDECIDED_PENDING_OWNER_REVIEW",
        "common_cutoff_supportable": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "terminal_verdict": (
            "PHASE 2A SAFELY STOPPED AT CONSOLIDATED OWNER DECISION GATE — "
            "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED"
        ),
    }
    overview = {
        **overview_material,
        "artifact_content_sha256": _sealed(overview_material),
    }

    action_text = (
        "OWNER ACTION — SAFE DETERMINISTIC SUBSET\n\n"
        "I, Agnes, approve the exact 516 legislative-effect metadata/currentness-only "
        "recommendations and the exact 64 semantic-text-identical byte-mismatch "
        "recommendations bound to Phase-2A owner-decision batch digest:\n\n"
        f"{decision_digest}\n\n"
        "This approval is for continued Phase 2A only. It does not approve the 448 "
        "issue proposition/span selections, the 20 judgment later-treatment decisions, "
        "the Patents Act 1977 section 60(7) text delta, or the 9 new source admissions. "
        "It does not authorize Phase 2B or Development 30.\n"
    )
    outcome_text = overview["terminal_verdict"] + "\n"

    files = {
        "PHASE2A-CONSOLIDATED-OWNER-GATE.json": _pretty_json(overview),
        "COMPLETE-REMEDIATION-MATRIX-585.json": _pretty_json(matrix),
        "COMPLETE-GOLD-CASE-RECONCILIATION-509.json": _pretty_json(gold),
        "COMPLETE-CANDIDATE-IMPACT-RECONCILIATION-76.json": _pretty_json(candidate),
        "COMPLETE-LEGISLATIVE-EFFECT-REGISTER-1896.json": _pretty_json(effects),
        "COMPLETE-JUDGMENT-LATER-TREATMENT-REGISTER-20.json": _pretty_json(judgments_artifact),
        "COMPLETE-LEGISLATION-BYTE-MISMATCH-REGISTER-65.json": _pretty_json(mismatch_artifact),
        "UNAVAILABLE-OFFICIAL-RECORDS-3.json": _pretty_json(unavailable_artifact),
        "SOURCE-CUSTODY-AND-ADMISSION-REGISTER.json": _pretty_json(source_register),
        "OWNER-DECISION-BATCH-1058.json": _pretty_json(decision_batch),
        "OWNER-ACTION-SAFE-SUBSET.txt": action_text.encode(),
        "OWNER-REVIEW-ISSUES-448.csv": _csv_bytes(
            (
                "ordinal",
                "row_id",
                "case_id",
                "issue_id",
                "issue_label",
                "legal_domain",
                "review_track",
                "top_title",
                "top_locator",
                "top_source_version_id",
                "top_reranker_score",
                "owner_outcome",
                "owner_comments",
            ),
            issue_csv,
        ),
        "OWNER-REVIEW-EFFECTS-516.csv": _csv_bytes(
            (
                "ordinal",
                "item_id",
                "effect_id",
                "source_title",
                "affected_provisions",
                "affecting_provisions",
                "recommendation",
                "owner_outcome",
                "owner_comments",
            ),
            effect_csv,
        ),
        "OWNER-REVIEW-JUDGMENTS-20.csv": _csv_bytes(
            (
                "ordinal",
                "source_version_id",
                "title",
                "neutral_citation",
                "targeted_lead_ids",
                "recommendation",
                "owner_outcome",
                "owner_comments",
            ),
            judgment_csv,
        ),
        "OWNER-REVIEW-BYTE-MISMATCHES-65.csv": _csv_bytes(
            (
                "ordinal",
                "source_version_id",
                "title",
                "classification",
                "changed_locators",
                "exact_changed_locator_pending_issue_row_ids",
                "recommendation",
                "owner_outcome",
                "owner_comments",
            ),
            mismatch_csv,
        ),
        "OUTCOME.txt": outcome_text.encode(),
    }
    machine_digest, _entries = _write_machine_files(output_root, files)
    return {
        "output_root": str(output_root),
        "owner_decision_batch_content_sha256": decision_digest,
        "machine_package_content_sha256": machine_digest,
        "issue_counts": overview["issue_counts"],
        "legislative_effect_counts": overview["legislative_effect_counts"],
        "judgment_counts": overview["judgment_counts"],
        "byte_mismatch_counts": overview["byte_mismatch_counts"],
        "immediately_approvable_deterministic_recommendation_count": 580,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        failure = output_root / "FAILURE.json"
        if failure.exists():
            return
        material = {
            "schema": "legalbot.v111.phase2a.consolidated-owner-gate-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "failure_fingerprint": _sha256(f"{type(exc).__name__}:{exc}".encode()),
            "debug_required_before_any_third_attempt": True,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            failure,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except BaseException:
        pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--remediation-root", type=Path, default=DEFAULT_REMEDIATION_ROOT)
    parser.add_argument("--effects", type=Path, default=DEFAULT_EFFECTS_PATH)
    parser.add_argument("--approval-48", type=Path, default=DEFAULT_APPROVAL_48_PATH)
    parser.add_argument("--approval-35", type=Path, default=DEFAULT_APPROVAL_35_PATH)
    parser.add_argument("--approval-54", type=Path, default=DEFAULT_APPROVAL_54_PATH)
    parser.add_argument("--remainder", type=Path, default=DEFAULT_REMAINDER_PATH)
    parser.add_argument("--source-custody", type=Path, default=DEFAULT_SOURCE_CUSTODY_PATH)
    parser.add_argument("--reranker-intent", type=Path, default=DEFAULT_RERANKER_INTENT_PATH)
    parser.add_argument("--reranker", type=Path, default=DEFAULT_RERANKER_PATH)
    parser.add_argument("--deep-comparison", type=Path, default=DEFAULT_DEEP_COMPARISON_PATH)
    parser.add_argument("--effect-recovery", type=Path, default=DEFAULT_EFFECT_RECOVERY_PATH)
    parser.add_argument("--judgments", type=Path, default=DEFAULT_JUDGMENT_PATH)
    parser.add_argument("--targeted-leads", type=Path, default=DEFAULT_TARGETED_LEADS_PATH)
    parser.add_argument("--byte-mismatch", type=Path, default=DEFAULT_BYTE_MISMATCH_PATH)
    parser.add_argument(
        "--fresh-quarantine-manifest",
        type=Path,
        default=DEFAULT_FRESH_QUARANTINE_MANIFEST_PATH,
    )
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = build_consolidated_owner_gate(
            remediation_root=args.remediation_root.resolve(strict=True),
            effects_path=args.effects.resolve(strict=True),
            approval_48_path=args.approval_48.resolve(strict=True),
            approval_35_path=args.approval_35.resolve(strict=True),
            approval_54_path=args.approval_54.resolve(strict=True),
            remainder_path=args.remainder.resolve(strict=True),
            source_custody_path=args.source_custody.resolve(strict=True),
            reranker_intent_path=args.reranker_intent.resolve(strict=True),
            reranker_path=args.reranker.resolve(strict=True),
            deep_comparison_path=args.deep_comparison.resolve(strict=True),
            effect_recovery_path=args.effect_recovery.resolve(strict=True),
            judgment_path=args.judgments.resolve(strict=True),
            targeted_leads_path=args.targeted_leads.resolve(strict=True),
            byte_mismatch_path=args.byte_mismatch.resolve(strict=True),
            fresh_quarantine_manifest_path=(args.fresh_quarantine_manifest.resolve(strict=True)),
            output_root=args.output_root.resolve(),
        )
    except BaseException as exc:
        _persist_failure(args.output_root.resolve(), exc)
        raise
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
