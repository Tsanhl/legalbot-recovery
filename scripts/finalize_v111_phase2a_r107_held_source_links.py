#!/usr/bin/env python3
"""Resolve only the two r107 overlength holds under a deterministic plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
for root in (PROJECT_ROOT, BACKEND_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from app.quality.evidence import (  # noqa: E402
    extract_material_facts,
    non_atomic_material_claim_reasons,
    substantive_tokens,
)
from scripts import review_v111_phase2a_post_r105_source_links as review  # noqa: E402

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R107_ROOT = review.DEFAULT_OUTPUT_ROOT
R107_PATH = R107_ROOT / review.OUTPUT_NAME
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r108-deterministic-held-source-resolution"
)
EXPECTED_R107_CONTENT_SHA256 = (
    "6706f5b1d34e81095c5c75a6c3a918a5f8b8f8ba6d5f5ae1afd595e6bbb7f2c2"
)
EXPECTED_R107_FILE_SHA256 = (
    "5194fc42e41a33102b6f64fe51cde191bced45acc98f19b8c61de8e17d5d2729"
)
HELD_ROWS = {
    "live60-q33:issue-02": "PARTIAL",
    "live60-q33:issue-03": "UNRELATED",
}
DELIVERY_QUOTE = (
    "the persons who are to be treated as an occupier and as his visitors are "
    "the same (subject to subsection (4) of this section) as the persons who "
    "would at common law be treated as an occupier and as his invitees or licensees."
)
DELIVERY_PROPOSITION = (
    "Visitor status follows the common-law categories of invitees and licensees."
)
OUTPUT_NAME = "DETERMINISTIC-HELD-SOURCE-RESOLUTION-26.json"


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


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_r108_input_invalid")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r108_input_not_object")
    return value


def _verify(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _load_r107() -> dict[str, Any]:
    if _sha256_file(R107_PATH) != EXPECTED_R107_FILE_SHA256:
        raise ValueError("phase2a_r108_r107_file_digest_invalid")
    value = _load(R107_PATH)
    digest = _verify(
        value,
        "artifact_content_sha256",
        "phase2a_r108_r107_content_seal_invalid",
    )
    findings = value.get("findings")
    if (
        digest != EXPECTED_R107_CONTENT_SHA256
        or value.get("row_source_link_count") != 26
        or value.get("held_for_debug_count") != 2
        or value.get("assessment_counts")
        != {"HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT": 2, "UNRELATED": 24}
        or value.get("source_admission_authorized") is not False
        or value.get("candidate_mutated") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
        or not isinstance(findings, list)
        or len(findings) != 26
    ):
        raise ValueError("phase2a_r108_r107_boundary_invalid")
    held = {
        str(item.get("row_id") or ""): item
        for item in findings
        if isinstance(item, Mapping)
        and item.get("assessment") == "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT"
    }
    if set(held) != set(HELD_ROWS):
        raise ValueError("phase2a_r108_held_scope_invalid")
    for row_id, finding in held.items():
        checkpoint = next(
            path
            for path in (R107_ROOT / "checkpoints").glob("*.json")
            if _load(path).get("row_id") == row_id
        )
        checkpoint_value = _load(checkpoint)
        _verify(
            checkpoint_value,
            "checkpoint_content_sha256",
            "phase2a_r108_held_checkpoint_invalid",
        )
        diagnostics = sorted(
            (R107_ROOT / "diagnostics").glob(f"{int(finding['ordinal']):02d}-*.json")
        )
        if len(diagnostics) != 2:
            raise ValueError("phase2a_r108_held_diagnostic_count_invalid")
        fingerprints = set()
        for diagnostic_path in diagnostics:
            diagnostic = _load(diagnostic_path)
            _verify(
                diagnostic,
                "diagnostic_content_sha256",
                "phase2a_r108_held_diagnostic_invalid",
            )
            if diagnostic.get("error_code") != "atomic_proposition_too_long":
                raise ValueError("phase2a_r108_held_error_invalid")
            fingerprints.add(str(diagnostic.get("failure_fingerprint") or ""))
        if len(fingerprints) != 1:
            raise ValueError("phase2a_r108_held_fingerprint_invalid")
    return value


def _delivery_resolution(packet: Mapping[str, Any]) -> dict[str, Any]:
    block = next(
        item
        for item in packet["candidate_blocks"]
        if item.get("locator") == "section 1 2"
    )
    text = str(block["exact_text"])
    start = text.find(DELIVERY_QUOTE)
    if start < 0 or non_atomic_material_claim_reasons(DELIVERY_PROPOSITION):
        raise ValueError("phase2a_r108_delivery_binding_invalid")
    proposition_facts = {
        fact.identity for fact in extract_material_facts(DELIVERY_PROPOSITION)
    }
    span_facts = {
        fact.identity
        for fact in extract_material_facts(f"{DELIVERY_QUOTE}\nsection 1 2")
    }
    shared = set(substantive_tokens(DELIVERY_PROPOSITION)) & set(
        substantive_tokens(DELIVERY_QUOTE)
    )
    if proposition_facts - span_facts or len(shared) < 2:
        raise ValueError("phase2a_r108_delivery_validation_invalid")
    return {
        "assessment": "PARTIAL",
        "atomic_proposition": DELIVERY_PROPOSITION,
        "exact_span_binding": {
            "block_id": block["block_id"],
            "locator": block["locator"],
            "full_text_sha256": block["exact_text_sha256"],
            "quote": DELIVERY_QUOTE,
            "quote_sha256": _sha256(DELIVERY_QUOTE.encode("utf-8")),
            "quote_start": start,
            "quote_end": start + len(DELIVERY_QUOTE),
            "proposition_material_facts": [],
            "span_material_facts": [
                {
                    "kind": fact.kind,
                    "normalized_value": fact.normalized_value,
                    "matched_text": fact.matched_text,
                }
                for fact in extract_material_facts(
                    f"{DELIVERY_QUOTE}\nsection 1 2"
                )
            ],
        },
        "finding_codes": [
            "deterministic_partial_delivery_driver_visitor_status"
        ],
        "resolution_basis": (
            "The exact statutory text identifies the common-law visitor categories "
            "but does not decide the delivery driver's status on the scenario facts."
        ),
    }


def _trespasser_resolution(packet: Mapping[str, Any]) -> dict[str, Any]:
    combined = "\n".join(str(item["exact_text"]) for item in packet["candidate_blocks"])
    if "trespass" in combined.casefold():
        raise ValueError("phase2a_r108_unexpected_trespasser_text")
    return {
        "assessment": "UNRELATED",
        "atomic_proposition": None,
        "exact_span_binding": None,
        "finding_codes": ["no_direct_trespasser_duty_in_supplied_1957_act_text"],
        "resolution_basis": (
            "No supplied block in the complete official 1957 Act extraction states "
            "a trespasser-duty proposition; additional authority is required."
        ),
    }


def build_resolution(output_root: Path = DEFAULT_OUTPUT_ROOT) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_r108_output_already_exists")
    r107 = _load_r107()
    source = review._load_sources()
    replacements: dict[str, dict[str, Any]] = {}
    for row_id, assessment in HELD_ROWS.items():
        packet = next(
            item for item in source.packets["rows"] if item["row_id"] == row_id
        )
        resolution = (
            _delivery_resolution(packet)
            if row_id == "live60-q33:issue-02"
            else _trespasser_resolution(packet)
        )
        if resolution["assessment"] != assessment:
            raise ValueError("phase2a_r108_resolution_assessment_invalid")
        replacements[row_id] = {
            **resolution,
            "row_id": row_id,
            "row_source_link_id": packet["row_source_link_id"],
            "authority_identity_id": packet["authority_identity_id"],
            "canonical_authority_identity_id": packet[
                "canonical_authority_identity_id"
            ],
            "source_is_existing_candidate_alias": True,
            "prior_attempt_count": 2,
            "prior_repeated_failure": "atomic_proposition_too_long",
            "model_invoked_for_resolution": False,
            "owner_outcome": None,
            "owner_decision_required": True,
            "source_admission_authorized": False,
            "technical_qualification_assigned": False,
        }
    findings = []
    for finding in r107["findings"]:
        row_id = str(finding["row_id"])
        if row_id in replacements:
            findings.append(
                {
                    "ordinal": finding["ordinal"],
                    **replacements[row_id],
                    "superseded_r107_checkpoint_content_sha256": finding[
                        "checkpoint_content_sha256"
                    ],
                }
            )
        else:
            findings.append(
                {
                    **finding,
                    "resolution_source": "retained_r107_same_adapter_advisory",
                }
            )
    counts = Counter(str(item["assessment"]) for item in findings)
    material = {
        "schema": "legalbot.v111.phase2a.r108-held-source-resolution-26.v1",
        "status": "ALL_26_SOURCE_LINK_FINDINGS_READY_FOR_DETERMINISTIC_RECONCILIATION",
        "source_r104_content_sha256": source.packets["artifact_content_sha256"],
        "source_r105_content_sha256": source.ranking["artifact_content_sha256"],
        "source_r107_content_sha256": r107["artifact_content_sha256"],
        "source_r107_file_sha256": _sha256_file(R107_PATH),
        "row_source_link_count": len(findings),
        "held_row_resolution_count": len(replacements),
        "remaining_held_row_count": 0,
        "assessment_counts": dict(sorted(counts.items())),
        "findings": findings,
        "same_adapter_advisory_false_negatives_may_remain": True,
        "deterministic_reconciliation_required": True,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_r108_output_mode_invalid")
    files = {
        OUTPUT_NAME: _pretty_json(artifact),
        "OUTCOME.txt": (
            b"TWO R107 OVERLENGTH HOLDS RESOLVED DETERMINISTICALLY; ALL 26 "
            b"FINDINGS REQUIRE RECONCILIATION AND OWNER DECISIONS. NO GATE CHANGE.\n"
        ),
    }
    for name, raw in files.items():
        _write_exclusive(output_root / name, raw)
    sums = "".join(
        f"{_sha256_file(output_root / name)}  {name}\n" for name in sorted(files)
    )
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    result = build_resolution(args.output_root.resolve())
    print(
        json.dumps(
            {
                "artifact_content_sha256": result["artifact_content_sha256"],
                "assessment_counts": result["assessment_counts"],
                "remaining_held_row_count": result["remaining_held_row_count"],
                "source_admission_authorized": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
