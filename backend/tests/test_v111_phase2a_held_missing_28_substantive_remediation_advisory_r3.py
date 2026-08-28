from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scripts import (
    build_v111_phase2a_held_missing_28_substantive_remediation_advisory_r3 as builder,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _target(advisory: dict[str, object]) -> dict[str, object]:
    row = next(item for item in advisory["rows"] if item["row_id"] == builder.TARGET_ROW_ID)
    return next(
        item
        for item in row["blocker_recommendations"]
        if item["component_ordinal"] == builder.TARGET_COMPONENT_ORDINAL
    )


def test_r3_changes_only_the_targeted_self_defence_span_boundary() -> None:
    r2_advisory, _, _ = builder._load_r2()
    advisory, manifest, audit = builder.build_artifacts()

    assert advisory["counts"] == r2_advisory["counts"]
    assert advisory["residual_blocker_keys"] == r2_advisory["residual_blocker_keys"]
    assert advisory["residual_row_ids"] == r2_advisory["residual_row_ids"]
    assert audit["fingerprint"] == builder.TARGET_FINGERPRINT

    recommendation = _target(advisory)
    span = next(
        item
        for item in recommendation["evidence_span_proposals"]
        if item["authority_identity_id"] == builder.TARGET_SOURCE_ID
    )
    assert "section 76(2)(a)" in span["exact_locators"]
    assert "section 76(3)-(6)" in span["exact_locators"]
    excerpts = [item["text"] for item in span["supporting_excerpts"]]
    assert "the common law defence of self-defence;" in excerpts
    assert any("disproportionate in those circumstances" in item for item in excerpts)
    proposition = recommendation["after_propositions"][0]["proposition"]
    assert "section 76(1), (2)(a), (3)-(6) and (6A)-(9)" in proposition

    component = manifest["additional_q04_official_representation"]["component_binding"]
    assert (
        component["recommendation_content_sha256"]
        == recommendation["recommendation_content_sha256"]
    )
    assert component["span_proposal_content_sha256"] == span["span_proposal_content_sha256"]
    assert component["exact_locators"] == span["exact_locators"]


def test_r3_remains_recursively_non_executing() -> None:
    for artifact in builder.build_artifacts():
        assert builder.r1._recursive_no_execution_violations(artifact) == []


def test_r3_publish_is_private_create_only_and_checksummed(tmp_path: Path) -> None:
    output = tmp_path / "held-missing-r3"
    builder.publish(output)
    assert oct(output.stat().st_mode & 0o777) == "0o700"
    lines = (output / builder.CHECKSUMS_NAME).read_text(encoding="utf-8").splitlines()
    for line in lines:
        digest, name = line.split("  ", 1)
        path = output / name
        assert path.is_file() and not path.is_symlink()
        assert oct(path.stat().st_mode & 0o777) == "0o600"
        assert _sha256(path) == digest
        if path.suffix == ".json":
            json.loads(path.read_bytes())
    assert len(lines) == 4
    try:
        builder.publish(output)
    except FileExistsError:
        pass
    else:
        raise AssertionError("create-only publication unexpectedly overwrote r3")
