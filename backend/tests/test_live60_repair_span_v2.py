from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from app.evaluation.live_suite_held_span_repair import (
    IPFDA_DOTS_PARENT,
    build_held_span_contiguous_repair,
)
from app.evaluation.live_suite_repair_span import (
    HELD_SPAN_REPAIR_SCHEMA_V1,
    HELD_SPAN_REPAIR_SCHEMA_V2,
    REPAIR_SPAN_SCHEMA_V2,
    computed_repair_span_id,
)
from app.evaluation.live_suite_span_accuracy import check_user_span_exact_match

PROJECT_ROOT = Path(__file__).resolve().parents[2]
V1_ARTIFACT = PROJECT_ROOT / "Live60-2026-08-16" / "artifacts" / "held-span-contiguous-repair.json"


def _identity_export() -> dict[str, object]:
    opening = (
        "section 1 Where after the commencement of this Act a person dies "
        "domiciled in England and Wales and is survived by any of the following "
        "persons:—that person may apply to the court for an order under section 2"
    )
    ba = (
        "section 1 any person (not being a person included in paragraph (a) or "
        "(b) above) to whom subsection (1A) ... below applies;"
    )
    dots = "section 1 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ."
    return {
        "provisions": [
            {
                "held_id": "held-provision-04",
                "authority_identity_id": "ukpga:1975:63",
                "expected_document_content_sha256": "a" * 64,
                "chunks": [
                    {
                        "chunk_id": "chunk-65e1c2ac95885e5e8e9d65e5ae138b5b6fbcde0a",
                        "source_version_id": "source-version-ipfda",
                        "document_content_sha256": "a" * 64,
                        "ordinal": 1,
                        "markdown_text": opening,
                        "structural_defect_codes": [
                            "non_contiguous_ipfda_s1_1_chapeau_spliced_with_concluding_words"
                        ],
                    },
                    {
                        "chunk_id": "chunk-3fea9d80c6f7fc0011d4db8679b75fe7185c06c7",
                        "source_version_id": "source-version-ipfda",
                        "document_content_sha256": "a" * 64,
                        "ordinal": 4,
                        "markdown_text": ba,
                        "structural_defect_codes": ["editorial_ellipsis_mixed_into_positive_text"],
                    },
                    {
                        "chunk_id": IPFDA_DOTS_PARENT,
                        "source_version_id": "source-version-ipfda",
                        "document_content_sha256": "a" * 64,
                        "ordinal": 11,
                        "markdown_text": dots,
                        "structural_defect_codes": ["repealed_or_omitted_editorial_marker"],
                    },
                ],
            }
        ]
    }


def test_v1_on_disk_artifact_is_byte_identical_and_rejected_as_new_gold() -> None:
    raw = V1_ARTIFACT.read_bytes()
    payload = json.loads(raw)
    assert payload["schema"] == HELD_SPAN_REPAIR_SCHEMA_V1
    assert V1_ARTIFACT.read_bytes() == raw
    gold = next(item for item in payload["repairs"] if item.get("gold_eligible_candidate") is True)
    report = check_user_span_exact_match(
        chunk_id=str(gold["repair_span_id"]),
        content_sha256=str(gold["text_sha256"]),
        legal_locator=str(gold["required_sublocator"]),
        repair=payload,
    )
    assert report["exact_match"] is False
    assert "repair_span_v1_rejected_as_new_gold" in report["mismatch_codes"]


def test_repair_span_v2_derives_id_from_full_identity_tuple() -> None:
    repair = build_held_span_contiguous_repair(_identity_export())
    assert repair["schema"] == HELD_SPAN_REPAIR_SCHEMA_V2
    assert repair["v1_rejected_as_new_gold"] is True
    assert repair["seals_expert_gold"] is False
    chapeau = next(
        item
        for item in repair["repairs"]
        if item["action"] == "replace_spliced_opening_with_chapeau"
    )
    assert chapeau["schema"] == REPAIR_SPAN_SCHEMA_V2
    assert chapeau["source_version_id"] == "source-version-ipfda"
    assert chapeau["legal_authority_id"] == "ukpga:1975:63"
    assert chapeau["official_snapshot_sha256"] == "a" * 64
    assert chapeau["derivation_manifest_sha256"]
    assert chapeau["stable_source_id"] == "ukpga:1975:63"
    assert chapeau["source_type"] == "legislation"
    assert chapeau["jurisdiction"] == "England and Wales"
    assert chapeau["role"] == "statutory_text"
    assert chapeau["legal_locator"] == chapeau["required_sublocator"]
    assert chapeau["repair_span_id"] == computed_repair_span_id(chapeau)
    assert chapeau["gold_eligible_candidate"] is True
    report = check_user_span_exact_match(
        chunk_id=chapeau["repair_span_id"],
        content_sha256=chapeau["text_sha256"],
        legal_locator=chapeau["required_sublocator"],
        source_version_id=chapeau["source_version_id"],
        legal_authority_id=chapeau["legal_authority_id"],
        parent_chunk_id=chapeau["parent_chunk_id"],
        legal_role=chapeau["role"],
        official_snapshot_sha256=chapeau["official_snapshot_sha256"],
        derivation_manifest_sha256=chapeau["derivation_manifest_sha256"],
        repair=repair,
    )
    assert report["exact_match"] is True


def test_repair_span_v2_tamper_of_each_identity_field_fails_closed() -> None:
    repair = build_held_span_contiguous_repair(_identity_export())
    chapeau = next(
        item
        for item in repair["repairs"]
        if item["action"] == "replace_spliced_opening_with_chapeau"
    )
    fields = {
        "source_version_id": "tampered-source-version",
        "legal_authority_id": "ukpga:9999:1",
        "parent_chunk_id": "chunk-other",
        "role": "wrong_role",
        "official_snapshot_sha256": "b" * 64,
        "derivation_manifest_sha256": "d" * 64,
        "stable_source_id": "tampered-source",
        "source_type": "case",
        "jurisdiction": "Scotland",
    }
    for field, wrong in fields.items():
        report = check_user_span_exact_match(
            chunk_id=chapeau["repair_span_id"],
            content_sha256=chapeau["text_sha256"],
            legal_locator=chapeau["required_sublocator"],
            repair=repair,
            **{field if field != "role" else "legal_role": wrong},
        )
        assert report["exact_match"] is False
        assert f"{field}_mismatch" in report["mismatch_codes"]

    tampered = copy.deepcopy(repair)
    target = next(
        item
        for item in tampered["repairs"]
        if item["action"] == "replace_spliced_opening_with_chapeau"
    )
    target["source_version_id"] = "tampered-source-version"
    report = check_user_span_exact_match(
        chunk_id=target["repair_span_id"],
        content_sha256=target["text_sha256"],
        legal_locator=target["required_sublocator"],
        repair=tampered,
    )
    assert report["exact_match"] is False
    assert "repair_span_id_mismatch" in report["mismatch_codes"]


def test_dots_only_ipfda_parent_cannot_be_new_gold() -> None:
    repair = build_held_span_contiguous_repair(_identity_export())
    dots = next(item for item in repair["repairs"] if item["parent_chunk_id"] == IPFDA_DOTS_PARENT)
    assert dots["gold_eligible_candidate"] is False
    report = check_user_span_exact_match(
        chunk_id=dots["repair_span_id"],
        content_sha256=dots["text_sha256"],
        legal_locator=dots["required_sublocator"],
        repair=repair,
        require_gold_eligible=True,
    )
    assert report["exact_match"] is False
    assert "dots_only_ipfda_parent_excluded" in report["mismatch_codes"]
    assert "repair_span_not_gold_eligible" in report["mismatch_codes"]


def test_wrong_locator_or_hash_still_fails() -> None:
    repair = build_held_span_contiguous_repair(_identity_export())
    chapeau = next(
        item
        for item in repair["repairs"]
        if item["action"] == "replace_spliced_opening_with_chapeau"
    )
    locator = check_user_span_exact_match(
        chunk_id=chapeau["repair_span_id"],
        content_sha256=chapeau["text_sha256"],
        legal_locator="s 99",
        repair=repair,
    )
    assert locator["exact_match"] is False
    assert "legal_locator_mismatch" in locator["mismatch_codes"]
    digest = check_user_span_exact_match(
        chunk_id=chapeau["repair_span_id"],
        content_sha256=hashlib.sha256(b"nope").hexdigest(),
        legal_locator=chapeau["required_sublocator"],
        repair=repair,
    )
    assert digest["exact_match"] is False
    assert "content_sha256_mismatch" in digest["mismatch_codes"]
