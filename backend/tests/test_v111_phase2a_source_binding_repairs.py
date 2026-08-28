from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts/collect_v111_phase2a_source_binding_repairs.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "collect_v111_phase2a_source_binding_repairs", SCRIPT_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _goodwin_validation_profile(module):
    return module.Replacement(
        "hudoc-001-57974-validation-only",
        "quarantine-binding-d07fad39256d15a7c6a25893",
        "https://hudoc.echr.coe.int/eng?i=001-57974",
        "https://hudoc.echr.coe.int/app/conversion/docx/html/body?"
        "library=ECHR&id=001-57974&logEvent=False",
        ".html",
        "text/html",
        ("GOODWIN", "UNITED KINGDOM"),
        ("journalist", "source"),
        ("17488/90",),
        (20, 21, 22, 39, 40, 41, 42, 43, 44, 45, 46),
        50_000,
        20_000,
        source_version_mode="OFFICIAL_FINAL_JUDGMENT_DOCUMENT",
    )


def test_exact_repair_scope_is_16_defects_and_15_representations() -> None:
    module = _load_module()
    module._validate_repair_scope()
    repaired = {item.old_record_id for item in module.REPLACEMENTS}
    held = {item["old_record_id"] for item in module.UNRESOLVED_REPAIR_HOLDS}
    assert len(module.REPLACEMENTS) == 15
    assert len(repaired) == 11
    assert len(module.DEFECTIVE_OLD_RECORD_IDS) == 16
    assert len(held) == 5
    assert repaired.isdisjoint(held)
    assert repaired | held == module.DEFECTIVE_OLD_RECORD_IDS
    assert sum(item.suffix == ".json" for item in module.REPLACEMENTS) == 15
    assert sum(item.suffix == ".html" for item in module.REPLACEMENTS) == 0
    assert "quarantine-binding-3688eea8275753b9dcabf559" in held
    assert "quarantine-binding-678af407a5abea67aa817bee" in held
    assert "quarantine-binding-0a370f8e41122c812c5f26d2" in held
    assert "quarantine-binding-d07fad39256d15a7c6a25893" in held
    assert {
        item.old_record_id
        for item in module.REPLACEMENTS
        if item.old_record_id == "quarantine-binding-c77651e23cb2156c65e9c850"
    }
    assert (
        sum(
            item.old_record_id == "quarantine-binding-c77651e23cb2156c65e9c850"
            for item in module.REPLACEMENTS
        )
        == 4
    )
    assert module.DEFAULT_OUTPUT_ROOT.name.endswith("-r7")
    r3_failure = (
        module.REVIEW_ROOT
        / "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r3"
        / "FAILURE.json"
    )
    assert hashlib.sha256(r3_failure.read_bytes()).hexdigest() == (
        "fdd9c9d2ef03cc9bda1743a2cd9c05a96027dd751bc5db1a8b407fe9e8ea25fd"
    )
    r4_failure = (
        module.REVIEW_ROOT
        / "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r4"
        / "FAILURE.json"
    )
    assert hashlib.sha256(r4_failure.read_bytes()).hexdigest() == (
        "67a070cf798e44e2253e14c67644cb51990d2e4e1f3d31eb94c1b1a02eed104e"
    )
    r5_failure = (
        module.REVIEW_ROOT
        / "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r5"
        / "FAILURE.json"
    )
    assert hashlib.sha256(r5_failure.read_bytes()).hexdigest() == (
        "4c155f6eeeab57a9fb6569e144b0e9b409fd2e1601b7eb8c48d7e9575b55ef6b"
    )
    r6_failure = (
        module.REVIEW_ROOT
        / "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r6"
        / "FAILURE.json"
    )
    assert hashlib.sha256(r6_failure.read_bytes()).hexdigest() == (
        "4c155f6eeeab57a9fb6569e144b0e9b409fd2e1601b7eb8c48d7e9575b55ef6b"
    )


def test_tas_substantive_source_is_not_in_repair_scope() -> None:
    module = _load_module()
    assert "quarantine-binding-d31c75cc95a825afac363e91" not in {
        item.old_record_id for item in module.REPLACEMENTS
    }
    tas_path = module.QUARANTINE_ROOT / "official-representation-0187-af50463d8ee72e5de91b.html"
    raw = tas_path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == (
        "af50463d8ee72e5de91bae081a66cb4b809754229f8ab81894c0df83627f9855"
    )
    visible = module._visible_html(raw)
    assert all(marker in visible for marker in ("R27", "R47", "R57", "R59"))


def test_exact_real_old_bindings_verify_read_only() -> None:
    module = _load_module()
    packet = module._load_object(module.PACKET_PATH)
    quarantine = module._load_object(module.QUARANTINE_MANIFEST_PATH)
    selected = module._verify_old_bindings(packet, quarantine)
    assert len(selected) == 247
    assert selected.keys() >= module.DEFECTIVE_OLD_RECORD_IDS


def test_replacement_validator_requires_every_locator() -> None:
    module = _load_module()
    replacement = _goodwin_validation_profile(module)
    paragraphs = [
        "<p>GOODWIN UNITED KINGDOM Application 17488/90 journalist source " + "x" * 60_000 + "</p>",
        "<p>JUDGMENT delivered by the Court.</p>",
        "<p>STRASBOURG final judgment status.</p>",
        *[
            f"<p>{number}. substantive judgment paragraph with sufficient text.</p>"
            for number in range(1, 201)
        ],
    ]
    raw = ('<div class="s800EAC49">' + "".join(paragraphs) + "</div>").encode()
    result = module._validate_replacement(replacement, raw)
    assert result["content_fitness_status"] == ("SUBSTANTIVE_BODY_AND_LOCATORS_VERIFIED")
    assert result["paragraph_markers_verified"] == [
        20,
        21,
        22,
        39,
        40,
        41,
        42,
        43,
        44,
        45,
        46,
    ]

    assert result["html_body_verified"] is True
    assert result["html_shell_mode"] == "BODY_FRAGMENT"
    assert result["html_paragraph_count"] == 203
    assert result["html_longest_consecutive_numbered_run"] == 200
    assert result["ordered_paragraph_anchor_positions"] == [
        22,
        23,
        24,
        41,
        42,
        43,
        44,
        45,
        46,
        47,
        48,
    ]
    assert result["identity_front_matter_markers_verified"] == ["17488/90"]

    with pytest.raises(
        ValueError,
        match="phase2a_binding_repair_paragraph_marker_missing_or_unordered",
    ):
        module._validate_replacement(
            replacement,
            raw.replace(b"46. substantive judgment", b"missing substantive judgment"),
        )

    with pytest.raises(ValueError, match="phase2a_binding_repair_judgment_body_missing"):
        module._validate_replacement(
            replacement,
            raw.replace(b'class="s800EAC49"', b'class="generic-shell"'),
        )

    with pytest.raises(ValueError, match="phase2a_binding_repair_judgment_body_missing"):
        module._validate_replacement(
            replacement,
            raw + b'<div class="s800EAC49"><p>second top-level wrapper</p></div>',
        )


def test_hudoc_validator_rejects_nav_filler_and_unordered_paragraphs() -> None:
    module = _load_module()
    replacement = _goodwin_validation_profile(module)
    marker_text = (
        "GOODWIN UNITED KINGDOM Application 17488/90 journalist source "
        "JUDGMENT STRASBOURG "
        + " ".join(f"{number}. navigation token" for number in replacement.paragraph_markers)
        + " x" * 60_000
    )
    harmless_body = "".join(
        f"<p>Ordinary body paragraph {number} with sufficient harmless text.</p>"
        for number in range(120)
    )
    nav_only = (
        '<html><body><div class="s800EAC49">'
        f"<nav><p>{marker_text}</p></nav>{harmless_body}</div></body></html>"
    ).encode()
    with pytest.raises(ValueError, match="phase2a_binding_repair_judgment_body_missing"):
        module._validate_replacement(replacement, nav_only)

    paragraphs = [
        "<p>GOODWIN UNITED KINGDOM Application 17488/90 journalist source " + "x" * 60_000 + "</p>",
        "<p>JUDGMENT delivered by the Court.</p>",
        "<p>STRASBOURG final judgment status.</p>",
        *[
            f"<p>{number}. substantive judgment paragraph with sufficient text.</p>"
            for number in range(1, 31)
        ],
        "<p>46. substantive judgment paragraph deliberately out of order.</p>",
        *[
            f"<p>{number}. substantive judgment paragraph with sufficient text.</p>"
            for number in range(39, 46)
        ],
        *[f"<p>Unnumbered substantive judgment paragraph {number}.</p>" for number in range(70)],
    ]
    with pytest.raises(
        ValueError,
        match="phase2a_binding_repair_paragraph_marker_missing_or_unordered",
    ):
        module._validate_replacement(
            replacement,
            (
                '<html><body><div class="s800EAC49">' + "".join(paragraphs) + "</div></body></html>"
            ).encode(),
        )


def test_hudoc_validator_excludes_toc_and_footnote_anchor_stuffing() -> None:
    module = _load_module()
    replacement = _goodwin_validation_profile(module)
    paragraphs = [
        "<p>GOODWIN UNITED KINGDOM Application 17488/90 journalist source " + "x" * 60_000 + "</p>",
        "<p>JUDGMENT delivered by the Court.</p>",
        "<p>STRASBOURG final judgment status.</p>",
        *[
            f"<p>{number}. substantive judgment paragraph with sufficient text.</p>"
            for number in range(1, 31)
        ],
        *[
            f'<p><a href="#_Toc{number}">{number}. table of contents filler.</a></p>'
            for number in range(39, 47)
        ],
        *[f"<p>Unnumbered substantive judgment paragraph {number}.</p>" for number in range(70)],
        '<div id="_ftn1"><p>39. footnote filler 40. 41. 42. 43. 44. 45. 46.</p></div>',
    ]
    raw = (
        '<html><body><div class="s800EAC49">' + "".join(paragraphs) + "</div></body></html>"
    ).encode()
    with pytest.raises(
        ValueError,
        match="phase2a_binding_repair_paragraph_marker_missing_or_unordered",
    ):
        module._validate_replacement(replacement, raw)


def test_fca_json_validator_requires_exact_chapter_section_and_provisions() -> None:
    module = _load_module()
    replacement = next(
        item
        for item in module.REPLACEMENTS
        if item.replacement_key == "fca-cobs2-2a-2026-08-14-json"
    )
    payload = {
        "Success": True,
        "Result": {
            "chapterId": "cobs2",
            "sectionId": "cobs2s6",
            "chapterName": "COBS 2 Conduct of business obligations",
            "sectionName": "COBS 2.2A Information disclosure",
            "provisions": [
                {
                    "entityId": "cobs2-cobs2s6-p1",
                    "provisionName": "COBS 2.2A.1",
                    "contentText": "<p>2.2A.1 2.2A.2 2.2A.3 " + "x" * 9_000 + "</p>",
                    "sectionId": "cobs2s6",
                    "isDeleted": False,
                }
            ],
        },
    }
    raw = json.dumps(payload).encode()
    result = module._validate_replacement(replacement, raw)
    assert result["extraction_method"] == "official-fca-json-v1"
    assert result["json_chapter_id_verified"] == "cobs2"
    assert result["json_section_id_verified"] == "cobs2s6"
    assert result["json_provision_count"] == 1
    assert result["json_all_provisions_typed_and_live"] is True
    assert result["json_point_in_time_date_verified"] == "14-08-2026"

    payload["Result"]["sectionId"] = "cobs2s2"
    with pytest.raises(ValueError, match="phase2a_binding_repair_json_section_mismatch"):
        module._validate_replacement(replacement, json.dumps(payload).encode())


def test_fca_json_rejects_markers_outside_typed_live_provisions() -> None:
    module = _load_module()
    replacement = next(
        item
        for item in module.REPLACEMENTS
        if item.replacement_key == "fca-cobs2-2a-2026-08-14-json"
    )
    payload = {
        "Success": True,
        "Result": {
            "chapterId": "cobs2",
            "sectionId": "cobs2s6",
            "provisions": [
                {
                    "entityId": "cobs2-cobs2s6-p1",
                    "provisionName": "Unrelated provision",
                    "contentText": "<p>Unrelated content " + "x" * 9_000 + "</p>",
                    "sectionId": "cobs2s6",
                    "isDeleted": False,
                }
            ],
        },
        "unrelatedEcho": "COBS 2.2A Information disclosure 2.2A.1 2.2A.2 2.2A.3",
    }
    with pytest.raises(ValueError, match="phase2a_binding_repair_title_marker_missing"):
        module._validate_replacement(replacement, json.dumps(payload).encode())

    payload["Result"]["provisions"][0]["provisionName"] = "COBS 2.2A Information disclosure"
    payload["Result"]["provisions"][0]["contentText"] = (
        "<p>2.2A.1 2.2A.2 2.2A.3 " + "x" * 9_000 + "</p>"
    )
    payload["Result"]["provisions"][0]["isDeleted"] = True
    with pytest.raises(
        ValueError,
        match="phase2a_binding_repair_json_deleted_or_unknown_provision",
    ):
        module._validate_replacement(replacement, json.dumps(payload).encode())


def test_fca_point_in_time_url_semantics_are_exact() -> None:
    module = _load_module()
    replacement = next(item for item in module.REPLACEMENTS if item.suffix == ".json")
    module._validate_fca_point_in_time_url(replacement, replacement.representation_url)

    with pytest.raises(ValueError, match="phase2a_binding_repair_fca_point_in_time_url_invalid"):
        module._validate_fca_point_in_time_url(
            replacement,
            replacement.representation_url.replace("14-08-2026", "15-08-2026"),
        )


def test_every_fetch_url_is_https_and_allowlisted() -> None:
    module = _load_module()
    from urllib.parse import urlparse

    for item in module.REPLACEMENTS:
        parsed = urlparse(item.representation_url)
        assert parsed.scheme == "https"
        assert parsed.hostname in module.ALLOWED_HOSTS


class _FakeResponse:
    def __init__(self, *, raw: bytes, media_type: str, final_url: str) -> None:
        self._raw = raw
        self.headers = {"Content-Type": media_type}
        self._final_url = final_url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        del exc_type, exc, traceback

    def read(self, limit: int) -> bytes:
        return self._raw[:limit]

    def geturl(self) -> str:
        return self._final_url


def test_fetch_requires_final_https_and_exact_media_type(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    replacement = next(item for item in module.REPLACEMENTS if item.suffix == ".json")
    payload = b"{}"

    monkeypatch.setattr(
        module,
        "urlopen",
        lambda request, timeout: _FakeResponse(
            raw=payload,
            media_type="application/jsonx",
            final_url=replacement.representation_url,
        ),
    )
    with pytest.raises(ValueError, match="phase2a_binding_repair_media_type_invalid"):
        module._fetch(replacement, 1.0)

    monkeypatch.setattr(
        module,
        "urlopen",
        lambda request, timeout: _FakeResponse(
            raw=payload,
            media_type="application/json; charset=utf-8",
            final_url=replacement.representation_url.replace("https://", "http://"),
        ),
    )
    with pytest.raises(ValueError, match="phase2a_binding_repair_redirect_not_allowlisted"):
        module._fetch(replacement, 1.0)

    monkeypatch.setattr(
        module,
        "urlopen",
        lambda request, timeout: _FakeResponse(
            raw=payload,
            media_type="application/json",
            final_url=replacement.representation_url.replace(
                "api-handbook.fca.org.uk",
                "api-handbook.fca.org.uk:444",
            ),
        ),
    )
    with pytest.raises(ValueError, match="phase2a_binding_repair_redirect_not_allowlisted"):
        module._fetch(replacement, 1.0)


def test_existing_output_is_never_mutated_by_failure_persistence(tmp_path: Path) -> None:
    module = _load_module()
    output = tmp_path / "existing-r4"
    output.mkdir(mode=0o700)
    marker = output / "SEALED.txt"
    marker.write_bytes(b"immutable\n")
    before = {path.name: path.read_bytes() for path in output.iterdir()}

    module._persist_failure(output, RuntimeError("must not mutate"), review_root=tmp_path)

    assert {path.name: path.read_bytes() for path in output.iterdir()} == before
    assert not (output / "FAILURE.json").exists()


def test_output_must_be_direct_child_of_non_symlink_review_root(tmp_path: Path) -> None:
    module = _load_module()
    valid = tmp_path / "new-r4"
    assert module._validated_output_root(valid, review_root=tmp_path) == valid

    outside = tmp_path.parent / "outside-r4"
    with pytest.raises(ValueError, match="phase2a_binding_repair_output_outside_review_root"):
        module._validated_output_root(outside, review_root=tmp_path)

    linked_parent = tmp_path / "linked"
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(ValueError, match="phase2a_binding_repair_output_parent_invalid"):
        module._validated_output_root(linked_parent / "new-r4", review_root=tmp_path)


def test_transactional_publish_is_create_only_and_fully_sealed(tmp_path: Path) -> None:
    module = _load_module()
    output = module._validated_output_root(tmp_path / "new-r4", review_root=tmp_path)

    digest = module._publish_transactionally(
        output,
        {"REPAIR-QUARANTINE-MANIFEST.json": b"{}\n", "OUTCOME.txt": b"held\n"},
        include_package=True,
    )

    assert isinstance(digest, str) and len(digest) == 64
    assert (output / "PACKAGE-MANIFEST.json").is_file()
    assert (output / "SHA256SUMS.txt").is_file()
    package = json.loads((output / "PACKAGE-MANIFEST.json").read_bytes())
    assert package["owner_delta_decision_required"] is True
    assert package["answer_eligible"] is False
    for field in module._FALSE_BOUNDARY_FIELDS:
        assert package[field] is False
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    with pytest.raises(ValueError, match="phase2a_binding_repair_output_exists"):
        module._publish_transactionally(
            output,
            {"unexpected": b"mutation"},
            include_package=True,
        )
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before
    assert not any(path.name.startswith(".new-r4.staging-") for path in tmp_path.iterdir())

    escaped_output = module._validated_output_root(
        tmp_path / "path-escape-r4",
        review_root=tmp_path,
    )
    with pytest.raises(
        ValueError,
        match="phase2a_binding_repair_output_member_path_invalid",
    ):
        module._publish_transactionally(
            escaped_output,
            {"../ESCAPE.txt": b"must not escape"},
            include_package=True,
        )
    assert not escaped_output.exists()
    assert not (tmp_path / "ESCAPE.txt").exists()
    assert not any(path.name.startswith(".path-escape-r4.staging-") for path in tmp_path.iterdir())


def test_failure_artifact_has_every_false_boundary(tmp_path: Path) -> None:
    module = _load_module()
    output = tmp_path / "failed-r4"

    module._persist_failure(output, RuntimeError("bounded failure"), review_root=tmp_path)

    failure = json.loads((output / "FAILURE.json").read_bytes())
    assert failure["owner_delta_decision_required"] is True
    assert failure["answer_eligible"] is False
    assert failure["unchanged_retry_authorized"] is False
    for field in module._FALSE_BOUNDARY_FIELDS:
        assert failure[field] is False


def test_collect_rejects_existing_output_before_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    output = tmp_path / "existing-output-r4"
    output.mkdir(mode=0o700)
    marker = output / "SEALED.txt"
    marker.write_bytes(b"unchanged\n")
    monkeypatch.setattr(
        module,
        "_fetch",
        lambda *args, **kwargs: pytest.fail("network/fetch must not be reached"),
    )
    with pytest.raises(ValueError, match="phase2a_binding_repair_output_exists"):
        module.collect(
            output_root=output,
            retrieved_at=datetime(2026, 8, 28, tzinfo=UTC),
            timeout_seconds=1.0,
            review_root=tmp_path,
        )
    assert marker.read_bytes() == b"unchanged\n"
    assert set(path.name for path in output.iterdir()) == {"SEALED.txt"}
