from __future__ import annotations

import json
from pathlib import Path

from scripts import repair_v111_phase2a_research_wave_hash_identity as repairer
from scripts import validate_v111_phase2a_official_research_waves as validator


def test_hash_identity_repair_preserves_both_distinct_hashes(tmp_path: Path) -> None:
    queue = json.loads(validator.DEFAULT_QUEUE.read_text(encoding="utf-8"))
    source = queue["records"][0]
    wave = {
        "schema": "unrepaired",
        "source_queue_content_sha256": validator.EXPECTED_QUEUE_CONTENT_SHA256,
        "records": [
            {
                "row_id": source["row_id"],
                "queue_record_content_sha256": source["proposition_record_content_sha256"],
                "atomic_components": [
                    {
                        "proposition": "Bound test proposition.",
                        "support_fit": "NONE",
                        "authorities": [
                            {
                                "citation": "Test source",
                                "title": "Test source",
                                "official_url": "https://www.legislation.gov.uk/ukpga/2015/15/section/49",
                                "exact_locators": ["section 49"],
                                "candidate_existing": "no",
                                "source_admission_required": True,
                            }
                        ],
                    }
                ],
                "unresolved_holds": ["Official source remains unresolved."],
            }
        ],
        "safety_flags": {
            "advisory_only": True,
            "owner_outcomes_applied": False,
            "source_admitted": False,
            "candidate_mutated": False,
            "embedding_run": False,
            "phase2b_authorized": False,
        },
    }
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(json.dumps(wave), encoding="utf-8")

    result = repairer.repair(
        queue_path=validator.DEFAULT_QUEUE,
        input_path=input_path,
        output_path=output_path,
    )

    record = result["records"][0]
    assert record["queue_record_content_sha256"] == source["record_content_sha256"]
    assert (
        record["proposition_record_content_sha256"] == source["proposition_record_content_sha256"]
    )
    assert record["atomic_components"][0]["authorities"][0]["candidate_existing"] is False
    assert result["provenance_repair"]["candidate_membership_normalization_count"] == 1
    assert result["provenance_repair"]["substantive_research_changed"] is False
