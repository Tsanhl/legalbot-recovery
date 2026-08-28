from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts/derive_v111_phase2a_fca_canonical_markdown.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "derive_v111_phase2a_fca_canonical_markdown", SCRIPT_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def test_exact_source_delta_and_r7_inputs_are_bound_read_only() -> None:
    module = _load_module()
    inputs = module._verify_inputs()
    assert len(inputs) == 15
    assert len({record["record_id"] for record, _, _ in inputs}) == 15
    assert len({record["quarantine_member"] for record, _, _ in inputs}) == 15
    assert all(record["content_type"] == "application/json" for record, _, _ in inputs)
    assert all(decision["owner_decision_required"] is True for _, decision, _ in inputs)
    assert all(decision["owner_decision_applied"] is False for _, decision, _ in inputs)
    assert all(_sha256(raw) == record["raw_sha256"] for record, _, raw in inputs)
    assert module.EXPECTED_DELTA_CONTENT_SHA256 == (
        "01312e142dd084271aa005b3d2a5ba8b93564bf3a841e1f5a4ec68c06a604ac0"
    )


def test_single_transform_is_full_object_lossless_and_parser_compatible() -> None:
    module = _load_module()
    repair, _, raw = module._verify_inputs()[0]
    payload = module._loads_object(raw, error_code="test")
    provenance = module._make_provenance(payload, repair)
    parsed, canonical_raw, shape = module._build_parse_result(payload, repair)
    bundle = module.CanonicalMarkdownConverter().convert(parsed, provenance)
    markdown_bytes = bundle.body_markdown.encode()
    verification = module._verify_derived(
        markdown_bytes=markdown_bytes,
        source_payload=payload,
        source_canonical_json=canonical_raw,
        source_parse_result=parsed,
        provenance=provenance,
        record=repair,
        json_shape=shape,
    )

    metadata, embedded = module._extract_embedded_payload(bundle.body_markdown)
    assert embedded == canonical_raw
    assert json.loads(embedded) == payload
    assert metadata["raw_sha256"] == repair["raw_sha256"]
    assert metadata["transform_schema"] == module.TRANSFORM_SCHEMA
    assert verification["equivalence"]["full_json_object_semantic_equality"] is True
    assert verification["structural_verification"]["all_response_metadata_fields_preserved"]
    assert verification["structural_verification"]["all_provision_fields_preserved"]
    assert verification["parser_compatibility"]["parse_status"] == "ready"
    assert verification["parser_compatibility"]["passed"] is True
    assert verification["structural_verification"]["source_provision_count"] == 31

    block_text = {block.text for block in parsed.body_blocks}
    for provision in payload["Result"]["provisions"]:
        assert provision["provisionName"] in block_text
        assert provision["contentText"] in block_text
        assert module._canonical_json(provision) in block_text


def test_embedded_payload_tamper_fails_closed() -> None:
    module = _load_module()
    repair, _, raw = module._verify_inputs()[0]
    payload = module._loads_object(raw, error_code="test")
    provenance = module._make_provenance(payload, repair)
    parsed, canonical_raw, shape = module._build_parse_result(payload, repair)
    markdown = module.CanonicalMarkdownConverter().convert(parsed, provenance).body_markdown
    metadata, _ = module._extract_embedded_payload(markdown)
    payload_base64 = metadata["canonical_json_base64"]
    replacement = ("A" if payload_base64[0] != "A" else "B") + payload_base64[1:]
    tampered = markdown.replace(payload_base64, replacement, 1).encode()
    with pytest.raises(ValueError, match="phase2a_fca_markdown_equivalence_invalid"):
        module._verify_derived(
            markdown_bytes=tampered,
            source_payload=payload,
            source_canonical_json=canonical_raw,
            source_parse_result=parsed,
            provenance=provenance,
            record=repair,
            json_shape=shape,
        )


def test_full_derivation_is_create_only_sealed_and_no_replace(
    tmp_path: Path,
) -> None:
    module = _load_module()
    review_root = tmp_path / "review"
    review_root.mkdir()
    output_root = review_root / "LegalBot-Phase2A-test-fca-canonical-r1"
    result = module.derive(
        output_root=output_root,
        created_at=datetime(2026, 8, 28, 4, 0, tzinfo=UTC),
        review_root=review_root,
    )
    manifest = result["manifest"]
    assert manifest["status"] == "QUARANTINED_PRE_OWNER_NOT_ADMITTED"
    assert manifest["summary"] == {
        "raw_representation_count": 15,
        "derived_representation_count": 15,
        "total_raw_bytes": sum(record["raw_bytes"] for record in manifest["records"]),
        "total_derived_bytes": sum(record["derived_bytes"] for record in manifest["records"]),
        "total_provision_count": 312,
        "semantic_equivalence_pass_count": 15,
        "structural_verification_pass_count": 15,
        "parser_compatibility_pass_count": 15,
        "privacy_pass_count": 15,
        "unchanged_r7_unresolved_repair_hold_count": 5,
    }
    assert manifest["owner_adoption_required"] is True
    assert manifest["source_admission_required_for_derived_representations"] is True
    assert manifest["source_admitted"] is False
    assert manifest["source_scan_run"] is False
    assert manifest["index_built"] is False
    assert manifest["embedding_run"] is False
    assert manifest["candidate_mutated"] is False
    assert manifest["qualification_run"] is False
    assert manifest["phase2b_run"] is False
    assert manifest["active_pointer_written"] is False
    assert manifest["previous_pointer_written"] is False
    assert manifest["no_raw_source_bytes_copied"] is True
    assert manifest["no_source_root_materialization"] is True
    assert len(list(output_root.glob("fca-canonical-*.md"))) == 15
    assert not list(output_root.glob("repair-representation-*.json"))

    package_path = output_root / "PACKAGE-MANIFEST.json"
    package = json.loads(package_path.read_text())
    assert package["file_count"] == 17
    assert package["package_content_sha256"] == result["package_content_sha256"]
    expected_checksums = (
        "".join(f"{item['sha256']}  {item['path']}\n" for item in package["files"])
        + f"{_sha256(package_path.read_bytes())}  PACKAGE-MANIFEST.json\n"
    )
    assert (output_root / "SHA256SUMS.txt").read_text() == expected_checksums
    for record in manifest["records"]:
        member = output_root / record["derived_member"]
        assert member.stat().st_size == record["derived_bytes"]
        assert _sha256(member.read_bytes()) == record["derived_sha256"]
        assert record["equivalence"]["full_json_object_semantic_equality"] is True
        assert record["parser_compatibility"]["passed"] is True
        assert record["privacy_check_passed"] is True

    with pytest.raises(ValueError, match="phase2a_fca_markdown_output_exists"):
        module.derive(
            output_root=output_root,
            created_at=datetime(2026, 8, 28, 4, 0, tzinfo=UTC),
            review_root=review_root,
        )


def test_output_confinement_and_privacy_fail_closed(tmp_path: Path) -> None:
    module = _load_module()
    review_root = tmp_path / "review"
    review_root.mkdir()
    with pytest.raises(ValueError, match="phase2a_fca_markdown_output_outside_review_root"):
        module._validated_output_root(tmp_path / "outside", review_root=review_root)
    for forbidden in (
        "/Users/example/private/source.pdf",
        "file:///private/source.pdf",
        "C:\\private\\source.pdf",
        "owner@example.com",
        "LegalBot-New",
    ):
        with pytest.raises(ValueError, match="phase2a_fca_markdown_privacy_violation"):
            module._privacy_check_string(forbidden)


def test_invalid_or_deleted_provision_is_never_silently_derived() -> None:
    module = _load_module()
    repair, _, raw = module._verify_inputs()[0]
    payload = module._loads_object(raw, error_code="test")
    payload["Result"]["provisions"][0]["isDeleted"] = True
    with pytest.raises(ValueError, match="phase2a_fca_markdown_provision_invalid"):
        module._build_parse_result(payload, repair)


def test_false_execution_boundary_verifier_is_recursive() -> None:
    module = _load_module()
    module._verify_false_boundaries_recursively(
        {"source_admitted": False, "nested": [{"embedding_run": False}]}
    )
    with pytest.raises(ValueError, match="phase2a_fca_markdown_boundary_violation"):
        module._verify_false_boundaries_recursively({"nested": [{"embedding_run": True}]})
