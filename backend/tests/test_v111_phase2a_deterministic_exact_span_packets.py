import json
from typing import Any

import pytest
from scripts import build_v111_phase2a_deterministic_exact_span_packets as packets


@pytest.fixture(scope="module")
def built_packet(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    del tmp_path_factory
    # This is an immutable historical packet. The live catalogue has evolved
    # since it was built, so replay the sealed output rather than pretending the
    # old catalogue preconditions are still current.
    return {
        name: json.loads((packets.DEFAULT_OUTPUT_ROOT / name).read_bytes())
        for name in (
            "DETERMINISTIC-EXACT-SPAN-PACKETS-364.json",
            "EXACT-SPAN-SOURCE-CORPUS.json",
            "APPROVED-142-SOURCE-CROSSWALK.json",
            "OUTSIDE-AUTHORITY-LOCAL-CROSSWALK-15.json",
            "PENDING-OUT-OF-PACKET-AUTHORITY-SCOPE.json",
        )
    }


def test_exact_partition_is_exhaustive_and_locator_matching_is_token_safe() -> None:
    text = "Section 10A applies. Section 11 supplies the separate rule."
    partition = packets._partition_exact_text(
        chunk_id="chunk-test",
        text=text,
        text_sha256=packets._sha256(text.encode("utf-8")),
    )

    assert "".join(
        span["exact_text"] for span in partition["exact_span_options"]
    ) == text
    assert partition["source_text_reproduced_by_partition_sha256"] == packets._sha256(
        text.encode("utf-8")
    )
    assert packets._locator_match("section 10A", ["section 1"]) == (
        "NO_EXACT_LOCATOR_MATCH"
    )
    assert packets._locator_match("p 37", ["[37]"]) == (
        "EXACT_CANONICAL_LOCATOR_REFERENCE"
    )


def test_packet_covers_all_rows_without_model_or_gate_authority(
    built_packet: dict[str, dict[str, Any]],
) -> None:
    rows = built_packet["DETERMINISTIC-EXACT-SPAN-PACKETS-364.json"]
    packets._verify_seal(
        rows,
        "artifact_content_sha256",
        "test_deterministic_span_rows_seal_invalid",
    )

    assert rows["row_count"] == 364
    assert rows["owner_decision_required_row_count"] == 361
    assert rows["owner_approved_ready_row_count"] == 3
    assert rows["planner_or_answer_model_invoked"] is False
    assert rows["source_scan_started"] is False
    assert rows["automatic_indexing"] is False
    assert rows["automatic_embedding"] is False
    assert rows["candidate_mutated"] is False
    assert rows["phase2b_authorized"] is False
    assert rows["development30_authorized"] is False
    assert all(row["technical_qualification_assigned"] is False for row in rows["rows"])


def test_source_corpus_records_sealed_projection_and_catalogue_distinction(
    built_packet: dict[str, dict[str, Any]],
) -> None:
    corpus = built_packet["EXACT-SPAN-SOURCE-CORPUS.json"]

    assert corpus["chunk_count"] == 1132
    assert corpus["candidate_reference_count"] == 2166
    assert corpus["projection_status_counts"] == {
        "EXACT_CATALOGUE_AND_SEALED_LANCE_TEXT_MATCH": 1126,
        "LEGACY_FALSE_PHONE_REDACTION_FIXED_FOR_SUCCESSOR_REBUILD": 6,
    }
    assert corpus["projection_reference_status_counts"][
        "LEGACY_FALSE_PHONE_REDACTION_FIXED_FOR_SUCCESSOR_REBUILD"
    ] == 11
    repaired = [
        record for record in corpus["records"] if record["successor_rebuild_required"]
    ]
    assert len(repaired) == 6
    assert all(record["exact_source_evidence_eligible"] is True for record in repaired)
    assert all(
        "[PHONE]"
        not in "".join(
            span["exact_text"] for span in record["exact_span_options"]
        )
        for record in repaired
    )


def test_exact_142_source_crosswalk_retains_holds_and_exclusions(
    built_packet: dict[str, dict[str, Any]],
) -> None:
    crosswalk = built_packet["APPROVED-142-SOURCE-CROSSWALK.json"]
    outside = built_packet["OUTSIDE-AUTHORITY-LOCAL-CROSSWALK-15.json"]
    pending = built_packet["PENDING-OUT-OF-PACKET-AUTHORITY-SCOPE.json"]

    assert crosswalk["source_count"] == 142
    assert crosswalk["classification_counts"] == {
        "APPROVED_NEW_SOURCE_LINKED_TO_REMAINING_ROW": 1,
        "APPROVED_NEW_SOURCE_NO_CURRENT_364_ROW_LINK": 141,
    }
    assert crosswalk["retained_exclusion_counts"] == {
        "ewhc_unresolved_count": 4,
        "fcl_unavailable_count": 40,
        "legislation_unmapped_or_not_exact_count": 21,
        "noncitable_representation_count": 3,
        "ocr_held_authority_count": 1,
        "unconfirmed_alias_identity_count": 38,
    }
    assert all(record["owner_source_admission_authorized"] for record in crosswalk["records"])
    assert all(record["answer_release_eligible"] is False for record in crosswalk["records"])
    assert crosswalk["source_scan_started"] is False
    assert outside["authority_count"] == 15
    assert outside["classification_counts"] == {
        "OWNER_APPROVED_DIRECT_BINDING_ALTERNATIVE_NOT_REQUIRED": 1,
        "OWNER_APPROVED_EXISTING_SOURCE_BINDING_NO_NEW_ADMISSION": 1,
        "OWNER_APPROVED_REJECTED_MAPPING_NO_ADMISSION": 11,
        "OWNER_APPROVED_SUPERSEDED_MAPPING_NO_ADMISSION": 2,
    }
    assert all(record["source_bytes_already_local"] for record in outside["records"])
    assert all(record["new_download_required"] is False for record in outside["records"])
    assert pending["authority_count"] == 0
    assert pending["status"] == "NO_OUT_OF_PACKET_AUTHORITY_SCOPE_REMAINS"
    assert pending["source_admission_authorized"] is False
    assert pending["automatic_download"] is False
