from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts/collect_v111_phase2a_echr_held_sources.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "collect_v111_phase2a_echr_held_sources", SCRIPT_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _small_plan(module):
    return module.JudgmentPlan(
        key="fixture",
        document_id="001-999999",
        old_record_id="fixture-old",
        title="Fixture v State",
        identity_title_marker="FIXTURE v. STATE",
        application_markers=("12345/67",),
        affected_row_ids=("fixture-row",),
        exact_locators=("paras 3-4",),
        required_paragraphs=(3, 4),
        minimum_bytes=100,
        minimum_paragraph_count=8,
        minimum_text_characters=200,
    )


def _substantive_html(*, css_class: str = "document-specific-class") -> bytes:
    front = (
        "<p>GRAND CHAMBER</p><p>CASE OF FIXTURE v. STATE</p>"
        "<p>Application no. 12345/67</p><p>JUDGMENT</p><p>STRASBOURG</p>"
    )
    paragraphs = "".join(
        f"<p>{number}. This is substantive judgment paragraph {number} with adequate text.</p>"
        for number in range(1, 31)
    )
    return f'<div class="{css_class}">{front}{paragraphs}</div>'.encode()


def test_scope_is_exact_four_held_judgments_and_eight_rows() -> None:
    module = _load_module()
    assert [plan.document_id for plan in module.PLANS] == [
        "001-233206",
        "001-186828",
        "001-210077",
        "001-57974",
    ]
    assert len({plan.old_record_id for plan in module.PLANS}) == 4
    assert len({row for plan in module.PLANS for row in plan.affected_row_ids}) == 8
    assert all(module._is_exact_representation_url(plan.representation_url, plan) for plan in module.PLANS)
    assert [plan.representation_mode for plan in module.PLANS] == ["html", "pdf", "html", "html"]


def test_sealed_inputs_and_old_held_bindings_verify_read_only() -> None:
    module = _load_module()
    selected = module._verify_inputs()
    assert {plan.old_record_id for plan in module.PLANS} <= selected.keys()


def test_changed_validator_accepts_substantive_body_without_fixed_css_class() -> None:
    module = _load_module()
    validation, canonical = module._validate(_small_plan(module), _substantive_html())
    assert validation["content_fitness_status"] == (
        "OFFICIAL_FULL_JUDGMENT_BODY_AND_REQUIRED_SPANS_VERIFIED"
    )
    assert validation["required_paragraphs_verified"] == [3, 4]
    assert validation["longest_consecutive_numbered_run_first"] == 1
    assert validation["longest_consecutive_numbered_run_last"] == 30
    assert b"3. This is substantive judgment paragraph 3" in canonical


def test_validator_rejects_shell_and_missing_required_paragraph_run() -> None:
    module = _load_module()
    plan = _small_plan(module)
    shell = (
        b"<html><body><p>Fixture v State 12345/67 JUDGMENT STRASBOURG</p>"
        + b"<p>navigation filler</p>" * 20
        + b"</body></html>"
    )
    with pytest.raises(ValueError, match="consecutive_numbered_run_too_short"):
        module._validate(plan, shell)
    with pytest.raises(ValueError, match="required_paragraph_run_missing"):
        module._validate(plan, _substantive_html().replace(b"<p>4. This", b"<p>44. This"))


def test_plan_requires_every_sealed_locator_paragraph() -> None:
    module = _load_module()
    klima = next(plan for plan in module.PLANS if plan.document_id == "001-233206")
    for number in (487, 488, 497, 502, 519, 527, 545, 548, 551, 572, 574, 622, 623):
        assert number in klima.required_paragraphs
    mutu = next(plan for plan in module.PLANS if plan.document_id == "001-186828")
    assert set(range(95, 124)) <= set(mutu.required_paragraphs)
    assert set(range(138, 185)) <= set(mutu.required_paragraphs)


def test_output_boundary_is_create_only_and_non_authorizing() -> None:
    module = _load_module()
    boundaries = module._false_boundaries()
    assert boundaries
    assert not any(boundaries.values())
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    assert '"--http1.1"' in source
    assert '"--retry"' not in source
    assert "for ordinal, plan in enumerate(ATTEMPT_PLANS, start=1)" in source
    assert [plan.document_id for plan in module.ATTEMPT_PLANS] == [
        "001-233206",
        "001-186828",
        "001-210077",
    ]
    assert "ACTIVE.json" not in source


def test_final_r3_artifact_is_sealed_and_has_one_stopped_hold() -> None:
    module = _load_module()
    root = module.DEFAULT_OUTPUT_ROOT
    manifest_path = root / "ECHR-RECOVERY-QUARANTINE-MANIFEST.json"
    manifest = json.loads(manifest_path.read_bytes())
    material = dict(manifest)
    supplied = material.pop("manifest_content_sha256")
    assert supplied == "f5beba682a629d3a6e0e79be374c0d2a3d6690d45abe467fa40f67879dcb0142"
    assert supplied == module._sealed(material)
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == (
        "c2682917d3f2dbc7cc701ad63ff98552eeb0e0398a85503b4b55a12c72b78471"
    )
    assert manifest["successful_document_count"] == 3
    assert manifest["new_successful_document_count"] == 2
    assert manifest["carried_forward_document_count"] == 1
    assert {record["old_record_id"] for record in manifest["records"]} == {
        "quarantine-binding-0a370f8e41122c812c5f26d2",
        "quarantine-binding-678af407a5abea67aa817bee",
    }
    assert manifest["carried_forward_records"][0]["raw_sha256"] == (
        module.EXPECTED_GOODWIN_R2_RAW_SHA256
    )
    assert len(manifest["holds"]) == 1
    assert manifest["holds"][0]["document_id"] == "001-186828"
    assert manifest["holds"][0]["failure_fingerprint"] == (
        "cd73206a613336d1790a6b8c2db5aab2e621dda9206ed3decf20f22a9034924c"
    )
    assert "curl_exit_52" in manifest["holds"][0]["error"]
    for record in manifest["records"]:
        for member_field, digest_field in (
            ("quarantine_member", "raw_sha256"),
            ("canonical_markdown_member", "canonical_markdown_sha256"),
        ):
            member = root / record[member_field]
            assert member.parent == root
            assert hashlib.sha256(member.read_bytes()).hexdigest() == record[digest_field]
