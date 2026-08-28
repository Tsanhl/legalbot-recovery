from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from scripts import audit_v111_phase2a_admission_substantive_content as audit


def _real_quarantine() -> tuple[Path, dict[str, Any]]:
    manifest_path = audit.DEFAULT_QUARANTINE_MANIFEST_PATH
    return manifest_path.parent, json.loads(manifest_path.read_bytes())


def _real_binding(record_id: str) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    root, manifest = _real_quarantine()
    selected = next(
        item for item in manifest["selected_admission_bindings"] if item["record_id"] == record_id
    )
    record = next(item for item in manifest["records"] if item["record_id"] == record_id)
    raw = audit._read_regular_no_follow(root / record["quarantine_member"], within=root)
    return selected, record, raw


def test_direct_script_help_resolves_repository_imports() -> None:
    result = subprocess.run(
        [sys.executable, str(Path(audit.__file__)), "--help"],
        cwd=audit.PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "ModuleNotFoundError" not in result.stderr
    assert "--quarantine-manifest" in result.stdout
    assert "never admits a source" in result.stdout


def test_production_input_constants_bind_exact_files_without_running_audit() -> None:
    packet_raw = audit._read_regular_no_follow(audit.DEFAULT_PACKET_PATH, within=audit.REVIEW_ROOT)
    quarantine_raw = audit._read_regular_no_follow(
        audit.DEFAULT_QUARANTINE_MANIFEST_PATH,
        within=audit.REVIEW_ROOT,
    )
    packet = json.loads(packet_raw)
    quarantine = json.loads(quarantine_raw)
    packet_material = dict(packet)
    quarantine_material = dict(quarantine)

    assert audit._sha256(packet_raw) == audit.PACKET_FILE_SHA256
    assert packet_material.pop("artifact_content_sha256") == audit.PACKET_CONTENT_SHA256
    assert audit._sealed(packet_material) == audit.PACKET_CONTENT_SHA256
    assert audit._sha256(quarantine_raw) == audit.QUARANTINE_FILE_SHA256
    assert quarantine_material.pop("manifest_content_sha256") == audit.QUARANTINE_CONTENT_SHA256
    assert audit._sealed(quarantine_material) == audit.QUARANTINE_CONTENT_SHA256
    assert len(packet["proposed_new_source_admissions"]) == 247
    assert len(quarantine["selected_admission_bindings"]) == 247
    # The audit has since been executed and sealed. Importing this module must
    # still have no release-side effect.
    assert not (audit.PROJECT_ROOT / "data/indexes/ACTIVE.json").exists()
    assert not (audit.PROJECT_ROOT / "data/indexes/PREVIOUS.json").exists()


def test_visible_html_projection_omits_script_style_and_noscript() -> None:
    projection = audit._html_projection(
        b"""
        <html><head><title> Exact title </title><style>hidden style</style></head>
        <body><main id="main-content">Visible body</main>
        <script>hidden script</script><noscript>hidden fallback</noscript></body></html>
        """
    )

    assert projection.title == "Exact title"
    assert projection.visible_text == "Exact title Visible body"
    assert "hidden" not in projection.visible_text
    assert "tag:main" in projection.identifiers
    assert "main-content" in projection.identifiers


def test_exact_11_fca_shells_are_detected_from_content_not_record_id() -> None:
    fca_ids = {
        record_id
        for record_id, category in audit.EXPECTED_FAILURE_CATEGORY_BY_RECORD_ID.items()
        if category == audit.FCA_FAILURE
    }
    assert len(fca_ids) == 11

    for record_id in fca_ids:
        selected, record, raw = _real_binding(record_id)
        verdict, failures, warnings, evidence = audit._audit_html(
            raw,
            selected=selected,
            record=record,
        )
        assert verdict == "FAIL"
        assert failures == [audit.FCA_FAILURE]
        assert warnings == []
        assert evidence["exact_shell_fingerprint"] is True
        assert evidence["loader_markers"]
        assert evidence["present_claimed_locator_tokens"] == []


def test_exact_four_hudoc_shells_are_detected_from_content_not_record_id() -> None:
    hudoc_ids = {
        record_id
        for record_id, category in audit.EXPECTED_FAILURE_CATEGORY_BY_RECORD_ID.items()
        if category == audit.HUDOC_FAILURE
    }
    assert len(hudoc_ids) == 4

    for record_id in hudoc_ids:
        selected, record, raw = _real_binding(record_id)
        verdict, failures, warnings, evidence = audit._audit_html(
            raw,
            selected=selected,
            record=record,
        )
        assert verdict == "FAIL"
        assert failures == [audit.HUDOC_FAILURE]
        assert warnings == []
        assert evidence["exact_shell_fingerprint"] is True
        assert evidence["requested_document_id_present"] is False
        assert evidence["numbered_paragraph_marker_count"] == 0


def test_judiciary_metadata_landing_page_has_no_claimed_judgment_body() -> None:
    record_id = "quarantine-binding-caeef16146c2eea1e2b03d09"
    selected, record, raw = _real_binding(record_id)

    verdict, failures, warnings, evidence = audit._audit_html(
        raw,
        selected=selected,
        record=record,
    )

    assert verdict == "FAIL"
    assert failures == [audit.JUDICIARY_FAILURE]
    assert warnings == []
    assert evidence["neutral_citation_present"] is True
    assert evidence["judgment_body_node_present"] is False
    assert evidence["paragraph_21_52_marker_count"] == 0


def test_tas_no_results_overlay_does_not_hide_present_rule_body() -> None:
    record_id = "quarantine-binding-d31c75cc95a825afac363e91"
    selected, record, raw = _real_binding(record_id)

    verdict, failures, warnings, evidence = audit._audit_html(
        raw,
        selected=selected,
        record=record,
    )

    assert verdict == "PASS_WITH_WARNING"
    assert failures == []
    assert warnings == ["TAS_NOISY_SEARCH_OVERLAY_RULE_BODY_PRESENT"]
    assert evidence["noisy_search_overlay_present"] is True
    assert evidence["present_rule_markers"] == ["R27", "R47", "R57", "R59"]
    assert evidence["normalized_visible_text_length"] == 56058
    assert evidence["normalized_visible_text_sha256"] == (
        "2562e22669460fd93abf614b6bd26d9ff5fc5709f525750bc752db6df48869f4"
    )


def test_substantive_xml_requires_known_legal_body_and_text() -> None:
    text = "A deterministically inspectable legal proposition. " * 30
    raw = (
        '<akomaNtoso xmlns="urn:test"><judgment><judgmentBody><p>'
        + text
        + "</p></judgmentBody></judgment></akomaNtoso>"
    ).encode()

    verdict, failures, warnings, evidence = audit._audit_xml(raw)

    assert verdict == "PASS"
    assert failures == []
    assert warnings == []
    assert evidence["xml_root_local_name"] == "akomaNtoso"

    verdict, failures, _, _ = audit._audit_xml(b"<html><p>not a legal XML body</p></html>")
    assert verdict == "FAIL"
    assert failures == ["XML_LEGAL_BODY_NOT_DETERMINISTICALLY_VERIFIED"]


def test_read_regular_no_follow_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"sealed")
    link = tmp_path / "link.bin"
    link.symlink_to(target)

    with pytest.raises(
        ValueError,
        match="phase2a_admission_content_audit_symlink_rejected",
    ):
        audit._read_regular_no_follow(link, within=tmp_path)


def test_summary_requires_exact_16_failures_231_passes_and_tas_warning() -> None:
    records: list[dict[str, Any]] = []
    for record_id, reason in audit.EXPECTED_FAILURE_CATEGORY_BY_RECORD_ID.items():
        records.append(
            {
                "record_id": record_id,
                "substantive_content_verdict": "FAIL",
                "failure_reason_codes": [reason],
                "warning_reason_codes": [],
            }
        )
    warning_id, warning = next(iter(audit.EXPECTED_WARNING_CATEGORY_BY_RECORD_ID.items()))
    records.append(
        {
            "record_id": warning_id,
            "substantive_content_verdict": "PASS_WITH_WARNING",
            "failure_reason_codes": [],
            "warning_reason_codes": [warning],
        }
    )
    for ordinal in range(230):
        records.append(
            {
                "record_id": f"synthetic-pass-{ordinal:03d}",
                "substantive_content_verdict": "PASS",
                "failure_reason_codes": [],
                "warning_reason_codes": [],
            }
        )

    summary = audit._summarize(records)

    assert len(records) == 247
    assert summary["pass_count"] == 231
    assert summary["fail_count"] == 16
    assert summary["pass_with_warning_count"] == 1
    assert summary["exact_expected_result"] is True
    assert summary["failure_reason_counts"] == {
        audit.FCA_FAILURE: 11,
        audit.HUDOC_FAILURE: 4,
        audit.JUDICIARY_FAILURE: 1,
    }


def test_package_is_non_authorizing_and_checksum_bound() -> None:
    records: list[dict[str, Any]] = []
    packet_binding = audit.BoundArtifact(
        audit.DEFAULT_PACKET_PATH,
        audit.PACKET_CONTENT_SHA256,
        audit.PACKET_FILE_SHA256,
        "artifact_content_sha256",
    )
    quarantine_binding = audit.BoundArtifact(
        audit.DEFAULT_QUARANTINE_MANIFEST_PATH,
        audit.QUARANTINE_CONTENT_SHA256,
        audit.QUARANTINE_FILE_SHA256,
        "manifest_content_sha256",
    )

    artifacts, outcome = audit._package_artifacts(
        records,
        packet_binding=packet_binding,
        quarantine_binding=quarantine_binding,
    )

    assert set(artifacts) == {
        audit.AUDIT_NAME,
        audit.OUTCOME_NAME,
        audit.PACKAGE_NAME,
        audit.CHECKSUM_NAME,
    }
    assert outcome["status"] == "FAIL_CLOSED_UNEXPECTED_SUBSTANTIVE_CONTENT_RESULT"
    for field in audit._TOP_LEVEL_FALSE_FIELDS:
        assert outcome[field] is False
    expected_lines = [
        f"{audit._sha256(artifacts[name])}  {name}"
        for name in (audit.AUDIT_NAME, audit.OUTCOME_NAME, audit.PACKAGE_NAME)
    ]
    assert artifacts[audit.CHECKSUM_NAME].decode().splitlines() == expected_lines


def test_transactional_writer_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "immutable-audit"
    artifacts = {"one.json": b"{}\n", "SHA256SUMS.txt": b"sealed\n"}

    audit._write_transactional_package(output, artifacts)

    assert {path.name for path in output.iterdir()} == set(artifacts)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    with pytest.raises(ValueError, match="output_already_exists"):
        audit._write_transactional_package(output, artifacts)
    assert not any(path.name.startswith(f".{output.name}.staging-") for path in tmp_path.iterdir())


def test_no_network_or_mutation_primitives_are_imported() -> None:
    source = Path(audit.__file__).read_text()

    for forbidden in (
        "requests",
        "urllib.request",
        "httpx",
        "subprocess.run",
        'source_admission_authorized": True',
        'candidate_mutated": True',
        'active_pointer_written": True',
    ):
        assert forbidden not in source
    assert os.path.commonpath([audit.DEFAULT_OUTPUT_ROOT, audit.REVIEW_ROOT]) == str(
        audit.REVIEW_ROOT
    )
