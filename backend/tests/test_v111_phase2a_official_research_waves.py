from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts import validate_v111_phase2a_official_research_waves as validator


def _wave_for_first_queue_row(tmp_path: Path) -> Path:
    queue = json.loads(validator.DEFAULT_QUEUE.read_text(encoding="utf-8"))
    row = queue["records"][0]
    wave = {
        "schema": "test-wave",
        "wave_scope": [row["row_id"]],
        "source_queue_content_sha256": validator.EXPECTED_QUEUE_CONTENT_SHA256,
        "records": [
            {
                "row_id": row["row_id"],
                "queue_record_content_sha256": row["record_content_sha256"],
                "atomic_components": [
                    {
                        "proposition": "A bounded test proposition.",
                        "support_fit": "PARTIAL",
                        "authorities": [
                            {
                                "citation": "Test authority",
                                "title": "Test authority",
                                "official_url": "https://www.legislation.gov.uk/ukpga/2015/15/section/49",
                                "exact_locators": ["section 49"],
                                "candidate_existing": False,
                                "source_admission_required": True,
                            }
                        ],
                    }
                ],
                "unresolved_holds": ["Factual application remains unresolved."],
            }
        ],
        "advisory_only": True,
        "owner_outcomes_applied": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "embedding_run": False,
        "phase2b_authorized": False,
    }
    path = tmp_path / "research-live30-q01-q05.json"
    path.write_text(json.dumps(wave), encoding="utf-8")
    return path


def test_research_wave_validator_accepts_bounded_incomplete_wave(tmp_path: Path) -> None:
    result = validator.validate_waves(
        queue_path=validator.DEFAULT_QUEUE,
        wave_paths=[_wave_for_first_queue_row(tmp_path)],
    )

    assert result["status"] == "PASS_INCOMPLETE"
    assert result["covered_row_count"] == 1
    assert result["missing_row_count"] == 315
    assert result["owner_decisions_applied"] is False
    assert result["embedding_run"] is False


def test_research_wave_validator_rejects_unbound_exact_text(tmp_path: Path) -> None:
    path = _wave_for_first_queue_row(tmp_path)
    wave = json.loads(path.read_text(encoding="utf-8"))
    wave["records"][0]["atomic_components"][0]["authorities"][0]["exact_text"] = "Unbound quote"
    path.write_text(json.dumps(wave), encoding="utf-8")

    with pytest.raises(ValueError, match="phase2a_research_wave_boundary_invalid"):
        validator.validate_waves(
            queue_path=validator.DEFAULT_QUEUE,
            wave_paths=[path],
        )


def test_research_wave_validator_accepts_nested_safety_flags(tmp_path: Path) -> None:
    path = _wave_for_first_queue_row(tmp_path)
    wave = json.loads(path.read_text(encoding="utf-8"))
    wave["safety_flags"] = {
        key: wave.pop(key)
        for key in [
            "advisory_only",
            "owner_outcomes_applied",
            "source_admitted",
            "candidate_mutated",
            "embedding_run",
            "phase2b_authorized",
        ]
    }
    path.write_text(json.dumps(wave), encoding="utf-8")

    result = validator.validate_waves(
        queue_path=validator.DEFAULT_QUEUE,
        wave_paths=[path],
    )

    assert result["covered_row_count"] == 1


def test_research_wave_validator_accepts_official_sra_guidance(
    tmp_path: Path,
) -> None:
    path = _wave_for_first_queue_row(tmp_path)
    wave = json.loads(path.read_text(encoding="utf-8"))
    authority = wave["records"][0]["atomic_components"][0]["authorities"][0]
    authority["official_url"] = "https://www.sra.org.uk/solicitors/guidance/misuse-ai/"
    path.write_text(json.dumps(wave), encoding="utf-8")

    result = validator.validate_waves(
        queue_path=validator.DEFAULT_QUEUE,
        wave_paths=[path],
    )

    assert result["covered_row_count"] == 1


def test_research_wave_validator_accepts_official_eur_lex_judgment(
    tmp_path: Path,
) -> None:
    path = _wave_for_first_queue_row(tmp_path)
    wave = json.loads(path.read_text(encoding="utf-8"))
    authority = wave["records"][0]["atomic_components"][0]["authorities"][0]
    authority["official_url"] = (
        "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:61976CJ0027"
    )
    path.write_text(json.dumps(wave), encoding="utf-8")

    result = validator.validate_waves(
        queue_path=validator.DEFAULT_QUEUE,
        wave_paths=[path],
    )

    assert result["covered_row_count"] == 1


def test_research_wave_validator_accepts_official_hudoc_judgment(
    tmp_path: Path,
) -> None:
    path = _wave_for_first_queue_row(tmp_path)
    wave = json.loads(path.read_text(encoding="utf-8"))
    authority = wave["records"][0]["atomic_components"][0]["authorities"][0]
    authority["official_url"] = "https://hudoc.echr.coe.int/eng?i=001-233206"
    path.write_text(json.dumps(wave), encoding="utf-8")

    result = validator.validate_waves(
        queue_path=validator.DEFAULT_QUEUE,
        wave_paths=[path],
    )

    assert result["covered_row_count"] == 1


def test_research_wave_validator_accepts_official_civil_procedure_rules(
    tmp_path: Path,
) -> None:
    path = _wave_for_first_queue_row(tmp_path)
    wave = json.loads(path.read_text(encoding="utf-8"))
    authority = wave["records"][0]["atomic_components"][0]["authorities"][0]
    authority["official_url"] = (
        "https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part54"
    )
    path.write_text(json.dumps(wave), encoding="utf-8")

    result = validator.validate_waves(
        queue_path=validator.DEFAULT_QUEUE,
        wave_paths=[path],
    )

    assert result["covered_row_count"] == 1


def test_research_wave_validator_accepts_official_fca_handbook(
    tmp_path: Path,
) -> None:
    path = _wave_for_first_queue_row(tmp_path)
    wave = json.loads(path.read_text(encoding="utf-8"))
    authority = wave["records"][0]["atomic_components"][0]["authorities"][0]
    authority["official_url"] = "https://www.handbook.fca.org.uk/handbook/COBS/9/2.html"
    path.write_text(json.dumps(wave), encoding="utf-8")

    result = validator.validate_waves(
        queue_path=validator.DEFAULT_QUEUE,
        wave_paths=[path],
    )

    assert result["covered_row_count"] == 1


def test_research_wave_validator_accepts_official_government_guidance(
    tmp_path: Path,
) -> None:
    path = _wave_for_first_queue_row(tmp_path)
    wave = json.loads(path.read_text(encoding="utf-8"))
    authority = wave["records"][0]["atomic_components"][0]["authorities"][0]
    authority["official_url"] = (
        "https://www.gov.uk/government/publications/"
        "speaking-out-guidance-on-campaigning-and-political-activity-by-charities-cc9"
    )
    path.write_text(json.dumps(wave), encoding="utf-8")

    result = validator.validate_waves(
        queue_path=validator.DEFAULT_QUEUE,
        wave_paths=[path],
    )

    assert result["covered_row_count"] == 1


@pytest.mark.parametrize(
    "official_url",
    [
        "https://www.wada-ama.org/sites/default/files/resources/files/2021_wada_code.pdf",
        "https://www.tas-cas.org/en/arbitration/code-procedural-rules",
        "https://www.judiciary.uk/judgments/example-official-judgment/",
    ],
)
def test_research_wave_validator_accepts_official_sports_rules(
    tmp_path: Path,
    official_url: str,
) -> None:
    path = _wave_for_first_queue_row(tmp_path)
    wave = json.loads(path.read_text(encoding="utf-8"))
    authority = wave["records"][0]["atomic_components"][0]["authorities"][0]
    authority["official_url"] = official_url
    path.write_text(json.dumps(wave), encoding="utf-8")

    result = validator.validate_waves(
        queue_path=validator.DEFAULT_QUEUE,
        wave_paths=[path],
    )

    assert result["covered_row_count"] == 1
