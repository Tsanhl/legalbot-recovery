from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest
from scripts import collect_v111_phase2a_research_wave_sources as collector
from scripts import repair_v111_phase2a_deterministic_wave_authorities as repairer
from scripts import validate_v111_phase2a_official_research_waves as validator


def _row(wave: dict[str, Any], row_id: str) -> dict[str, Any]:
    return next(record for record in wave["records"] if record["row_id"] == row_id)


def _load(output_root: Path, name: str) -> dict[str, Any]:
    return json.loads((output_root / name).read_text(encoding="utf-8"))


def test_deterministic_repair_emits_create_only_complete_r2_set(
    tmp_path: Path,
) -> None:
    result = repairer.repair_all(
        queue_path=validator.DEFAULT_QUEUE,
        manifest_path=repairer.DEFAULT_MANIFEST,
        input_root=repairer.WORKING_ROOT,
        output_root=tmp_path,
    )

    assert result["status"] == "PASS"
    assert result["output_count"] == 9
    assert result["authority_split_count"] == 14
    assert result["false_new_membership_correction_count"] == 3
    assert result["covered_row_count"] == 316
    assert result["wave_count"] == 32
    assert {output["path"] for output in result["outputs"]} == {
        binding[0] for binding in repairer.BASE_BINDINGS.values()
    }
    assert all(
        result[flag] is False
        for flag in (
            "owner_outcomes_applied",
            "source_collected",
            "source_admitted",
            "candidate_mutated",
            "embedding_run",
            "phase2b_authorized",
        )
    )

    validation = validator.validate_waves(
        queue_path=validator.DEFAULT_QUEUE,
        wave_paths=repairer.canonical_wave_paths(
            input_root=repairer.WORKING_ROOT,
            output_root=tmp_path,
        ),
    )
    assert validation["status"] == "PASS_COMPLETE"
    assert validation["covered_row_count"] == 316
    assert validation["missing_row_count"] == 0

    for output in result["outputs"]:
        path = tmp_path / output["path"]
        wave = json.loads(path.read_bytes())
        material = dict(wave)
        supplied = material.pop("artifact_content_sha256")
        assert supplied == repairer._sealed(material)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        serialized = json.dumps(wave, ensure_ascii=False)
        assert "/Users/" not in serialized
        assert "exact_text" not in serialized
        provenance = wave["deterministic_authority_repair"]
        assert provenance["source_collected"] is False
        assert provenance["source_admitted"] is False
        assert provenance["candidate_mutated"] is False
        assert provenance["embedding_run"] is False
        assert provenance["phase2b_authorized"] is False

    with pytest.raises(ValueError, match="phase2a_wave_authority_repair_output_already_exists"):
        repairer.repair_all(
            queue_path=validator.DEFAULT_QUEUE,
            manifest_path=repairer.DEFAULT_MANIFEST,
            input_root=repairer.WORKING_ROOT,
            output_root=tmp_path,
        )


def test_r2_authorities_are_split_and_manifest_membership_is_exact(
    tmp_path: Path,
) -> None:
    repairer.repair_all(
        queue_path=validator.DEFAULT_QUEUE,
        manifest_path=repairer.DEFAULT_MANIFEST,
        input_root=repairer.WORKING_ROOT,
        output_root=tmp_path,
    )

    q28 = _load(tmp_path, "research-live30-q28-r2.json")
    issue05 = _row(q28, "live30-q28:issue-05")
    e, waller = issue05["atomic_components"][3]["authorities"]
    assert e["citation"] == ("Royal Bank of Scotland plc v Etridge (No 2) [2001] UKHL 44")
    assert e["candidate_existing"] is False
    assert e["candidate_source_version_ids"] == []
    assert e["source_admission_required"] is True
    assert waller["citation"] == ("Waller-Edwards v One Savings Bank Plc [2025] UKSC 22")
    assert waller["candidate_existing"] is True
    assert waller["candidate_source_version_ids"] == [
        "source-version-adb3867a9d3850728daeb55a19c9cb4fc0c30e9b"
    ]
    assert waller["source_admission_required"] is False

    issue10 = _row(q28, "live30-q28:issue-10")
    insolvency, tolata = issue10["atomic_components"][4]["authorities"]
    assert insolvency["citation"] == "Insolvency Act 1986, s 335A"
    assert tolata["citation"] == ("Trusts of Land and Appointment of Trustees Act 1996, s 15(4)")
    assert insolvency["candidate_source_version_ids"] == [
        "source-version-c5a87b369f1425926f022fcd9d684ab2d4525839"
    ]
    assert tolata["candidate_source_version_ids"] == [
        "source-version-e4b9da65ccd473b2a7f0996ede07d4085fa1d34f"
    ]

    q31_q35 = _load(tmp_path, "research-live60-q31-q35-r2.json")
    for row_id in (
        "live60-q34:issue-03",
        "live60-q34:issue-08",
        "live60-q34:issue-05",
        "live60-q34:issue-06",
        "live60-q34:issue-07",
    ):
        authorities = _row(q31_q35, row_id)["atomic_components"][0]["authorities"]
        assert len(authorities) == 2
        assert authorities[0]["citation"].endswith("[2016] UKSC 8")
        assert authorities[1]["citation"].endswith(
            ("[2026] EWCA Crim 444", "[2018] EWCA Crim 2603")
        )
        assert all(authority["candidate_existing"] is False for authority in authorities)
        assert all(authority["source_admission_required"] is True for authority in authorities)

    q41_q43 = _load(tmp_path, "research-live60-q41-q43-r2.json")
    issue06 = _row(q41_q43, "live60-q41:issue-06")
    nationality, slavery = issue06["atomic_components"][0]["authorities"]
    assert nationality["citation"] == "Nationality and Borders Act 2022, s 60"
    assert slavery["citation"] == "Modern Slavery Act 2015, ss 49-50"
    assert slavery["official_url"] == ("https://www.legislation.gov.uk/ukpga/2015/30/2026-08-14")
    assert slavery["exact_locators"] == ["s 49(1)-(1A)", "s 50(1)-(4)"]
    assert any("section 51 remains unbound" in hold for hold in issue06["unresolved_holds"])

    membership_expectations = (
        (
            "research-live30-q24-q25-r2.json",
            "live30-q24:issue-01",
            "Supply of Goods and Services Act 1982, s 13",
            "source-version-16a9bcb428d17e0126ba147b0903bece7823d595",
        ),
        (
            "research-live30-q30-r2.json",
            "live30-q30:issue-16",
            "Trade Secrets (Enforcement, etc.) Regulations 2018",
            "source-version-f1d2fba5d67d7ecbb060841435513960b9bb861c",
        ),
        (
            "research-live60-q52-r2.json",
            "live60-q52:issue-01",
            "Arnold v Britton [2015] UKSC 36",
            "source-version-77233fd6c2c5ba582c1599a1e9df520c01b134ac",
        ),
    )
    for filename, row_id, citation, version_id in membership_expectations:
        wave = _load(tmp_path, filename)
        matches = [
            authority
            for component in _row(wave, row_id)["atomic_components"]
            for authority in component["authorities"]
            if authority["citation"] == citation
        ]
        assert len(matches) == 1
        assert matches[0]["candidate_existing"] is True
        assert matches[0]["candidate_source_version_ids"] == [version_id]
        assert matches[0]["source_admission_required"] is False
        assert "candidate manifest contains" in matches[0]["currentness_finding"]
        holds = _row(wave, row_id)["unresolved_holds"]
        assert any("candidate-bound" in hold for hold in holds)


def test_canonical_binding_artifact_is_create_only_sealed_and_downstream_compatible(
    tmp_path: Path,
) -> None:
    output = tmp_path / repairer.CANONICAL_BINDING_FILE_NAME
    result = repairer.emit_canonical_bindings(
        queue_path=validator.DEFAULT_QUEUE,
        wave_root=repairer.WORKING_ROOT,
        binding_path=output,
    )

    assert result["status"] == "PASS"
    assert result["exact_set_count"] == 32
    assert result["total_row_count"] == 316
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    artifact = json.loads(output.read_bytes())
    material = dict(artifact)
    supplied = material.pop("artifact_content_sha256")
    assert supplied == repairer._sealed(material)
    assert result["artifact_content_sha256"] == supplied
    assert result["file_sha256"] == repairer._sha256(output.read_bytes())
    assert material["schema"] == repairer.CANONICAL_BINDING_SCHEMA
    assert material["exact_set_count"] == material["wave_count"] == 32
    assert material["total_row_count"] == 316
    assert sum(item["record_count"] for item in material["waves"]) == 316
    assert [item["file_name"] for item in material["waves"]] == sorted(
        item["file_name"] for item in material["waves"]
    )
    assert not (
        {item["file_name"] for item in material["waves"]} & repairer.OBSOLETE_CANONICAL_WAVE_NAMES
    )
    assert "research-live60-q48-q50-r3.json" in {item["file_name"] for item in material["waves"]}
    for record in [material["queue_binding"], *material["waves"]]:
        record_material = dict(record)
        record_seal = record_material.pop("record_content_sha256")
        assert record_seal == repairer._sealed(record_material)
    assert all(
        material[flag] is False
        for flag in (
            "owner_decisions_applied",
            "owner_outcomes_applied",
            "source_collection_authorized",
            "source_collected",
            "source_admitted",
            "catalogue_mutated",
            "candidate_mutated",
            "automatic_indexing",
            "automatic_embedding",
            "embedding_run",
            "active_or_previous_write_authorized",
            "phase2b_authorized",
            "development30_authorized",
            "validation30_authorized",
            "live_activation_authorized",
        )
    )

    wave_bindings = []
    for path in repairer.canonical_wave_paths(
        input_root=repairer.WORKING_ROOT,
        output_root=repairer.WORKING_ROOT,
    ):
        wave = json.loads(path.read_bytes())
        wave_bindings.append(
            collector.ArtifactBinding(
                path=path,
                content_sha256=wave["artifact_content_sha256"],
                file_sha256=repairer._sha256(path.read_bytes()),
            )
        )
    loaded = collector._load_canonical_wave_set(
        collector.ArtifactBinding(
            path=output,
            content_sha256=result["artifact_content_sha256"],
            file_sha256=result["file_sha256"],
        ),
        wave_bindings,
    )
    assert loaded["exact_set_count"] == 32

    verified = repairer.verify_canonical_bindings(
        queue_path=validator.DEFAULT_QUEUE,
        wave_root=repairer.WORKING_ROOT,
        binding_path=output,
    )
    assert verified == result
    with pytest.raises(ValueError, match="phase2a_canonical_wave_binding_output_already_exists"):
        repairer.emit_canonical_bindings(
            queue_path=validator.DEFAULT_QUEUE,
            wave_root=repairer.WORKING_ROOT,
            binding_path=output,
        )
