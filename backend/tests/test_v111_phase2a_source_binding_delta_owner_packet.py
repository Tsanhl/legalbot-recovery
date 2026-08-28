from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_source_binding_delta_owner_packet as builder


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _write_repair_package(root: Path) -> builder.RepairPackageBinding:
    root.mkdir(mode=0o700)
    original = json.loads(builder.ORIGINAL_PACKET_PATH.read_bytes())
    proposals_by_record = builder._original_proposals_by_record(original)
    audit = json.loads(builder.AUDIT_PATH.read_bytes())
    failed_ids = {
        str(record["record_id"])
        for record in audit["records"]
        if record["substantive_content_verdict"] == "FAIL"
    }
    repairable_ids = sorted(failed_ids - builder.EXPECTED_UNRESOLVED_REPAIR_IDS)
    assert len(repairable_ids) == 11

    expanded_ids = [*repairable_ids, *repairable_ids[:4]]
    records: list[dict[str, object]] = []
    payloads: dict[str, bytes] = {}
    for ordinal, old_record_id in enumerate(expanded_ids, start=1):
        original_proposal = proposals_by_record[old_record_id]
        old_binding = original_proposal["quarantine_representation_binding"][
            "selected_admission_binding"
        ]
        raw = f"substantive official body and exact locator {ordinal}".encode()
        raw_sha256 = builder._sha256(raw)
        member = f"repair-representation-{ordinal:04d}-{raw_sha256[:20]}.html"
        payloads[member] = raw
        identity_material = {
            "canonical_url": (f"https://api-handbook.fca.org.uk/Handbook/Test/{ordinal}"),
            "final_url": (f"https://api-handbook.fca.org.uk/Handbook/Test/{ordinal}/body"),
            "raw_sha256": raw_sha256,
            "retrieved_at": "2026-08-28T02:00:00+00:00",
        }
        record_material: dict[str, object] = {
            "record_id": "binding-repair-" + builder._sealed(identity_material)[:24],
            "replacement_key": f"synthetic-replacement-{ordinal}",
            "old_proposal_id": original_proposal["proposal_id"],
            "old_proposed_source_version_id": old_binding["proposed_source_version_id"],
            "old_record_id": old_record_id,
            "old_raw_sha256": old_binding["raw_sha256"],
            "old_official_urls": original_proposal["official_urls"],
            "affected_row_ids": original_proposal["affected_row_ids"],
            "citations": original_proposal["citations"],
            "titles": original_proposal["titles"],
            "canonical_url": identity_material["canonical_url"],
            "representation_url": identity_material["final_url"],
            "final_url": identity_material["final_url"],
            "retrieved_at": identity_material["retrieved_at"],
            "content_type": "text/html",
            "bytes": len(raw),
            "raw_sha256": raw_sha256,
            "quarantine_member": member,
            "proposed_source_version_id": (
                "proposed-repair-source-version-" + builder._sealed(identity_material)[:40]
            ),
            "extraction_method": "synthetic-test",
            "extracted_text_characters": len(raw),
            "extracted_text_sha256": raw_sha256,
            "normalized_text_sha256": raw_sha256,
            "page_count": None,
            "title_markers_verified": ["substantive official body"],
            "locator_markers_verified": [f"exact locator {ordinal}"],
            "paragraph_markers_verified": [],
            "content_fitness_status": "SUBSTANTIVE_BODY_AND_LOCATORS_VERIFIED",
            "source_version_mode": "OFFICIAL_TEST_REPRESENTATION",
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
            "owner_delta_decision_required": True,
            "source_admission_authorized": False,
            "source_admitted": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutated": False,
        }
        records.append(
            {
                **record_material,
                "record_content_sha256": builder._sealed(record_material),
            }
        )

    holds: list[dict[str, object]] = []
    for old_record_id, category in (
        (
            builder.EWCA_HOLD_OLD_RECORD_ID,
            "JUDICIARY_LANDING_METADATA_NO_JUDGMENT_BODY",
        ),
        (
            builder.BIG_BROTHER_WATCH_HOLD_OLD_RECORD_ID,
            "HUDOC_GENERIC_APP_SHELL_NO_CASE_DOCUMENT",
        ),
        (
            builder.MUTU_PECHSTEIN_HOLD_OLD_RECORD_ID,
            "HUDOC_GENERIC_APP_SHELL_NO_CASE_DOCUMENT",
        ),
        (
            builder.KLIMASENIORINNEN_HOLD_OLD_RECORD_ID,
            "HUDOC_GENERIC_APP_SHELL_NO_CASE_DOCUMENT",
        ),
        (
            builder.GOODWIN_HOLD_OLD_RECORD_ID,
            "HUDOC_GENERIC_APP_SHELL_NO_CASE_DOCUMENT",
        ),
    ):
        material: dict[str, object] = {
            "old_record_id": old_record_id,
            "category": category,
            "reason_code": "OFFICIAL_SUBSTANTIVE_BYTES_CURRENTLY_UNAVAILABLE",
            "checked_official_endpoints": ["https://hudoc.echr.coe.int/app/conversion/held"],
            "observed_results": ["UNAVAILABLE"],
            "source_admission_authorized": False,
            "source_admitted": False,
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
        }
        holds.append({**material, "hold_content_sha256": builder._sealed(material)})

    manifest_material: dict[str, object] = {
        "schema": "legalbot.v111.phase2a.source-binding-repair-quarantine.v1",
        "status": "EXACT_REPLACEMENTS_QUARANTINED_OWNER_DELTA_REQUIRED",
        "created_at": "2026-08-28T02:00:00+00:00",
        "source_owner_packet_content_sha256": (builder.EXPECTED_ORIGINAL_PACKET_CONTENT_SHA256),
        "source_owner_packet_file_sha256": (builder.EXPECTED_ORIGINAL_PACKET_FILE_SHA256),
        "source_quarantine_manifest_content_sha256": (
            builder.EXPECTED_ORIGINAL_QUARANTINE_CONTENT_SHA256
        ),
        "source_quarantine_manifest_file_sha256": (
            builder.EXPECTED_ORIGINAL_QUARANTINE_FILE_SHA256
        ),
        "defective_old_binding_count": 16,
        "defective_old_record_ids": sorted(failed_ids),
        "repaired_old_binding_count": 11,
        "repaired_old_record_ids": repairable_ids,
        "unresolved_repair_hold_count": 5,
        "unresolved_repair_holds": holds,
        "replacement_representation_count": 15,
        "records": records,
        "all_substantive_body_and_locator_checks_passed": True,
        "owner_delta_decision_required": True,
        **{field: False for field in builder._REPAIR_REQUIRED_FALSE_BOUNDARY_FIELDS},
    }
    manifest = {
        **manifest_material,
        "manifest_content_sha256": builder._sealed(manifest_material),
    }
    manifest_raw = builder._pretty_json(manifest)
    files = {
        **payloads,
        builder.REPAIR_MANIFEST_NAME: manifest_raw,
        "OUTCOME.txt": b"Synthetic sealed repair package for tests only.\n",
    }
    assert len(files) == 17
    for name, raw in files.items():
        (root / name).write_bytes(raw)

    entries = [
        {"path": name, "bytes": len(raw), "sha256": builder._sha256(raw)}
        for name, raw in sorted(files.items())
    ]
    package_material: dict[str, object] = {
        "schema": "legalbot.v111.phase2a.source-binding-repair-package.v1",
        "status": "QUARANTINED_NOT_OWNER_ADOPTED",
        "files": entries,
        "file_count": 17,
        **{field: False for field in builder._REPAIR_REQUIRED_FALSE_BOUNDARY_FIELDS},
    }
    package = {
        **package_material,
        "package_content_sha256": builder._sealed(package_material),
    }
    package_raw = builder._pretty_json(package)
    (root / builder.REPAIR_PACKAGE_NAME).write_bytes(package_raw)
    checksums_raw = (
        "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries)
        + f"{builder._sha256(package_raw)}  {builder.REPAIR_PACKAGE_NAME}\n"
    )
    (root / builder.CHECKSUMS_NAME).write_text(checksums_raw, encoding="utf-8")
    return builder.RepairPackageBinding(
        root=root,
        manifest_content_sha256=str(manifest["manifest_content_sha256"]),
        manifest_file_sha256=builder._sha256(manifest_raw),
        package_content_sha256=str(package["package_content_sha256"]),
        package_file_sha256=builder._sha256(package_raw),
    )


def _binding_for_root(root: Path) -> builder.RepairPackageBinding:
    manifest = _load(root / builder.REPAIR_MANIFEST_NAME)
    package = _load(root / builder.REPAIR_PACKAGE_NAME)
    return builder.RepairPackageBinding(
        root=root,
        manifest_content_sha256=str(manifest["manifest_content_sha256"]),
        manifest_file_sha256=builder._sha256_file(root / builder.REPAIR_MANIFEST_NAME),
        package_content_sha256=str(package["package_content_sha256"]),
        package_file_sha256=builder._sha256_file(root / builder.REPAIR_PACKAGE_NAME),
    )


def _install_synthetic_repair_contract(
    patcher: pytest.MonkeyPatch,
    binding: builder.RepairPackageBinding,
) -> None:
    patcher.setattr(builder, "REPAIR_INPUT_REVIEW_ROOT", binding.root.parent)
    patcher.setattr(
        builder,
        "EXPECTED_R7_MANIFEST_CONTENT_SHA256",
        binding.manifest_content_sha256,
    )
    patcher.setattr(
        builder,
        "EXPECTED_R7_MANIFEST_FILE_SHA256",
        binding.manifest_file_sha256,
    )
    patcher.setattr(
        builder,
        "EXPECTED_R7_PACKAGE_CONTENT_SHA256",
        binding.package_content_sha256,
    )
    patcher.setattr(
        builder,
        "EXPECTED_R7_PACKAGE_FILE_SHA256",
        binding.package_file_sha256,
    )
    patcher.setattr(
        builder,
        "EXPECTED_R7_CHECKSUMS_FILE_SHA256",
        builder._sha256_file(binding.root / builder.CHECKSUMS_NAME),
    )


@pytest.fixture(scope="module")
def built_delta(
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    root = tmp_path_factory.mktemp("delta-packet")
    review = root / "review"
    review.mkdir()
    repair_binding = _write_repair_package(root / builder.EXPECTED_REPAIR_ROOT_NAME)
    output = review / "delta-owner-packet-r1"
    patcher = pytest.MonkeyPatch()
    patcher.setattr(builder, "OUTPUT_REVIEW_ROOT", review)
    _install_synthetic_repair_contract(patcher, repair_binding)
    try:
        result = builder.build_delta_packet(
            repair_binding=repair_binding,
            output_root=output,
            created_at=datetime(2026, 8, 28, 3, 0, tzinfo=UTC),
        )
    finally:
        patcher.undo()
    assert result["status"] == builder.STATUS
    assert result["output_name"] == output.name
    assert "output_root" not in result
    return output


def test_delta_packet_has_exact_partition_and_keeps_execution_closed(
    built_delta: Path,
) -> None:
    packet = _load(built_delta / builder.PACKET_NAME)
    package = _load(built_delta / builder.PACKAGE_NAME)
    summary = packet["decision_summary"]
    assert isinstance(summary, dict)
    assert summary["retained_original_passing_representation_count"] == 231
    assert summary["rejected_defective_original_representation_count"] == 16
    assert summary["tas_pass_with_warning_count"] == 1
    assert summary["corrected_replacement_representation_count"] == 15
    assert summary["repaired_old_binding_count"] == 11
    assert summary["unresolved_repair_hold_count"] == 5
    assert summary["retained_original_quarantine_hold_count"] == 31
    assert summary["retained_original_identity_and_admission_hold_count"] == 86
    assert summary["source_binding_delta_owner_decision_count"] == 267

    assert len(packet["retained_original_passing_representations"]) == 231
    assert len(packet["rejected_defective_original_representations"]) == 16
    assert len(packet["proposed_corrected_source_admissions"]) == 15
    assert len(packet["unresolved_repair_holds"]) == 5
    assert packet["new_exact_owner_adoption_required"] is True
    assert packet["prior_owner_adoption_does_not_cover_changed_repair_bytes"] is True

    material_hold = packet["known_all585_material_hold"]
    assert isinstance(material_hold, dict)
    assert material_hold["row_id"] == "live60-q58:issue-14"
    assert material_hold["current_all585_can_be_successful"] is False
    assert material_hold["successful_phase2a_package_may_be_claimed"] is False

    for field, value in builder._NO_EXECUTION_FLAGS.items():
        assert value is False
        assert packet[field] is False
        assert package[field] is False
    assert builder._verify_seal(packet, "artifact_content_sha256", "invalid")
    assert builder._verify_seal(package, "artifact_content_sha256", "invalid")


def test_delta_packet_binds_failure_lineage_and_stops_repeated_fingerprint(
    built_delta: Path,
) -> None:
    packet = _load(built_delta / builder.PACKET_NAME)
    lineage = packet["failed_collection_lineage"]
    assert isinstance(lineage, list)
    assert len(lineage) == 6
    assert len({entry["failure_fingerprint"] for entry in lineage}) == 5
    assert all(entry["supplied_admissible_bytes"] is False for entry in lineage)
    assert all(entry["source_admission_eligible"] is False for entry in lineage)
    r3 = next(entry for entry in lineage if entry["revision"] == "r3")
    assert r3["failure_fingerprint"] == (
        "fb19824ad9f4094e6abe8a95bd8f15edd38aac11bab8267199753d1197720a97"
    )
    assert r3["interpretation"] == (
        "INTENTIONAL_INTERRUPTION_AFTER_VALIDATOR_AUDIT_NO_ADMISSIBLE_BYTES"
    )
    assert {entry["revision"] for entry in lineage} == {
        "r1",
        "r2",
        "r3",
        "r4",
        "r5",
        "r6",
    }
    r4 = next(entry for entry in lineage if entry["revision"] == "r4")
    r5 = next(entry for entry in lineage if entry["revision"] == "r5")
    r6 = next(entry for entry in lineage if entry["revision"] == "r6")
    assert r4["interpretation"] == "VALIDATOR_TITLE_MARKER_FAILURE_NO_ADMISSIBLE_BYTES"
    assert r5["interpretation"] == "VALIDATOR_JUDGMENT_BODY_FAILURE_NO_ADMISSIBLE_BYTES"
    assert r6["failure_fingerprint"] == r5["failure_fingerprint"]
    assert r6["file_sha256"] == r5["file_sha256"]
    assert r6["interpretation"] == (
        "SECOND_IDENTICAL_VALIDATOR_FINGERPRINT_PATH_STOPPED_BEFORE_THIRD"
    )


def test_delta_output_is_private_atomic_and_has_exact_checksums(
    built_delta: Path,
) -> None:
    assert stat.S_IMODE(built_delta.stat().st_mode) == 0o700
    assert not list(built_delta.parent.glob(f".{built_delta.name}.staging-*"))
    for path in built_delta.iterdir():
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    checksums = (built_delta / builder.CHECKSUMS_NAME).read_text(encoding="utf-8")
    expected = "".join(
        f"{builder._sha256_file(path)}  {path.name}\n"
        for path in sorted(built_delta.iterdir())
        if path.name != builder.CHECKSUMS_NAME
    )
    assert checksums == expected
    prompt = (built_delta / builder.PROMPT_NAME).read_text(encoding="utf-8")
    assert "new exact owner adoption" in prompt
    assert "current all-585 set cannot qualify successfully" in prompt


def test_repair_binding_fails_closed_when_absent_or_tampered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    absent = builder.RepairPackageBinding(
        root=tmp_path / "missing-r7",
        manifest_content_sha256="0" * 64,
        manifest_file_sha256="0" * 64,
        package_content_sha256="0" * 64,
        package_file_sha256="0" * 64,
    )
    with pytest.raises(ValueError, match="repair_root_absent_or_invalid"):
        builder._verify_repair_package(absent)

    binding = _write_repair_package(tmp_path / builder.EXPECTED_REPAIR_ROOT_NAME)
    _install_synthetic_repair_contract(monkeypatch, binding)
    with (binding.root / builder.REPAIR_MANIFEST_NAME).open("ab") as handle:
        handle.write(b"tamper")
    with pytest.raises(ValueError, match="repair_manifest_file_invalid"):
        builder._verify_repair_package(binding)


def test_external_same_basename_repair_root_is_rejected(tmp_path: Path) -> None:
    binding = _write_repair_package(tmp_path / builder.EXPECTED_REPAIR_ROOT_NAME)
    with pytest.raises(ValueError, match="repair_root_identity_invalid"):
        builder._verify_repair_package(binding)


@pytest.mark.parametrize(
    "artifact_name", [builder.REPAIR_MANIFEST_NAME, builder.REPAIR_PACKAGE_NAME]
)
@pytest.mark.parametrize(
    "field",
    ["catalogue_mutated", "answer_eligible", "technical_qualification_assigned"],
)
def test_repair_boundary_fields_must_all_remain_false(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_name: str,
    field: str,
) -> None:
    root = tmp_path / builder.EXPECTED_REPAIR_ROOT_NAME
    _write_repair_package(root)
    path = root / artifact_name
    artifact = _load(path)
    seal_field = (
        "manifest_content_sha256"
        if artifact_name == builder.REPAIR_MANIFEST_NAME
        else "package_content_sha256"
    )
    artifact[field] = True
    material = dict(artifact)
    material.pop(seal_field)
    artifact[seal_field] = builder._sealed(material)
    path.write_bytes(builder._pretty_json(artifact))
    binding = _binding_for_root(root)
    _install_synthetic_repair_contract(monkeypatch, binding)
    with pytest.raises(ValueError, match="repair_boundary_invalid"):
        builder._verify_repair_package(binding)


def test_all_52_no_execution_flags_are_rejected_true_at_every_repair_depth() -> None:
    fields = tuple(builder._NO_EXECUTION_FLAGS)
    assert len(fields) == 52
    assert fields == builder._REPAIR_REQUIRED_FALSE_BOUNDARY_FIELDS
    for field in fields:
        for value in (
            {field: True},
            {"records": [{field: True}]},
            {"unresolved_repair_holds": [{field: True}]},
        ):
            with pytest.raises(ValueError, match="repair_boundary_invalid"):
                builder._verify_repair_false_boundaries_recursively(value)


@pytest.mark.parametrize(
    ("collection", "seal_field", "field"),
    [
        ("records", "record_content_sha256", "catalogue_mutated"),
        ("unresolved_repair_holds", "hold_content_sha256", "answer_eligible"),
    ],
)
def test_nested_repair_boundary_fields_must_remain_false(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    collection: str,
    seal_field: str,
    field: str,
) -> None:
    root = tmp_path / builder.EXPECTED_REPAIR_ROOT_NAME
    _write_repair_package(root)
    path = root / builder.REPAIR_MANIFEST_NAME
    manifest = _load(path)
    nested = manifest[collection][0]
    nested[field] = True
    nested_material = dict(nested)
    nested_material.pop(seal_field)
    nested[seal_field] = builder._sealed(nested_material)
    manifest_material = dict(manifest)
    manifest_material.pop("manifest_content_sha256")
    manifest["manifest_content_sha256"] = builder._sealed(manifest_material)
    path.write_bytes(builder._pretty_json(manifest))
    binding = _binding_for_root(root)
    _install_synthetic_repair_contract(monkeypatch, binding)
    with pytest.raises(ValueError, match="repair_boundary_invalid"):
        builder._verify_repair_package(binding)


def test_repair_manifest_must_bind_exact_original_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / builder.EXPECTED_REPAIR_ROOT_NAME
    _write_repair_package(root)
    path = root / builder.REPAIR_MANIFEST_NAME
    manifest = _load(path)
    manifest["source_quarantine_manifest_content_sha256"] = "1" * 64
    material = dict(manifest)
    material.pop("manifest_content_sha256")
    manifest["manifest_content_sha256"] = builder._sealed(material)
    path.write_bytes(builder._pretty_json(manifest))
    binding = _binding_for_root(root)
    _install_synthetic_repair_contract(monkeypatch, binding)
    with pytest.raises(ValueError, match="repair_inventory_invalid"):
        builder._verify_repair_package(binding)


def test_repair_package_member_set_is_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / builder.EXPECTED_REPAIR_ROOT_NAME
    _write_repair_package(root)
    package_path = root / builder.REPAIR_PACKAGE_NAME
    package = _load(package_path)
    outcome_entry = next(item for item in package["files"] if item["path"] == "OUTCOME.txt")
    outcome_entry["path"] = "EXTRA.txt"
    (root / "EXTRA.txt").write_bytes((root / "OUTCOME.txt").read_bytes())
    material = dict(package)
    material.pop("package_content_sha256")
    package["package_content_sha256"] = builder._sealed(material)
    package_path.write_bytes(builder._pretty_json(package))
    binding = _binding_for_root(root)
    _install_synthetic_repair_contract(monkeypatch, binding)
    with pytest.raises(ValueError, match="repair_package_member_set_invalid"):
        builder._verify_repair_package(binding)


def test_output_path_must_be_inside_review_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    review = tmp_path / "review"
    review.mkdir()
    monkeypatch.setattr(builder, "OUTPUT_REVIEW_ROOT", review)
    with pytest.raises(ValueError, match="outside_review_root"):
        builder._ensure_output_path(tmp_path / "outside")


def test_delta_build_is_create_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    review = tmp_path / "review"
    review.mkdir()
    existing = review / "existing"
    existing.mkdir()
    monkeypatch.setattr(builder, "OUTPUT_REVIEW_ROOT", review)
    with pytest.raises(ValueError, match="output_already_exists"):
        builder._ensure_output_path(existing)


def test_atomic_publication_refuses_concurrently_created_empty_target(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "artifact.json").write_text("{}\n", encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(ValueError, match="output_already_exists"):
        builder._publish_directory_noreplace(staging, output)
    assert staging.is_dir()
    assert output.is_dir()
    assert not list(output.iterdir())


def test_exact_real_r7_package_and_original_crosslinks_verify() -> None:
    binding = builder.RepairPackageBinding(
        root=builder.DEFAULT_REPAIR_ROOT,
        manifest_content_sha256=builder.EXPECTED_R7_MANIFEST_CONTENT_SHA256,
        manifest_file_sha256=builder.EXPECTED_R7_MANIFEST_FILE_SHA256,
        package_content_sha256=builder.EXPECTED_R7_PACKAGE_CONTENT_SHA256,
        package_file_sha256=builder.EXPECTED_R7_PACKAGE_FILE_SHA256,
    )
    repair = builder._verify_repair_package(binding)
    original = builder._verify_exact_original_packet()
    proposals = builder._original_proposals_by_record(original)
    builder._verify_repair_crosslinks(repair, proposals)
    assert len(repair["records"]) == 15
    assert len({record["old_record_id"] for record in repair["records"]}) == 11
    assert {
        hold["old_record_id"] for hold in repair["unresolved_repair_holds"]
    } == builder.EXPECTED_UNRESOLVED_REPAIR_IDS


def test_repair_crosslink_tamper_is_rejected() -> None:
    binding = builder.RepairPackageBinding(
        root=builder.DEFAULT_REPAIR_ROOT,
        manifest_content_sha256=builder.EXPECTED_R7_MANIFEST_CONTENT_SHA256,
        manifest_file_sha256=builder.EXPECTED_R7_MANIFEST_FILE_SHA256,
        package_content_sha256=builder.EXPECTED_R7_PACKAGE_CONTENT_SHA256,
        package_file_sha256=builder.EXPECTED_R7_PACKAGE_FILE_SHA256,
    )
    repair = builder._verify_repair_package(binding)
    tampered = json.loads(json.dumps(repair))
    tampered["records"][0]["old_proposal_id"] = "wrong-proposal"
    original = builder._verify_exact_original_packet()
    proposals = builder._original_proposals_by_record(original)
    with pytest.raises(ValueError, match="repair_original_crosslink_invalid"):
        builder._verify_repair_crosslinks(tampered, proposals)


@pytest.mark.parametrize(
    "leak",
    [
        "/home/reviewer/private-notes.docx",
        "/private/var/tmp/source.pdf",
        "/tmp/legalbot/source.txt",
        "/Users/reviewer/Desktop/Exam Feedback.pdf",
        r"C:\Users\reviewer\Documents\source.docx",
        r"\\server\private-share\source.pdf",
        "reviewer@example.com",
        "Agnes",
        "LegalBot-New/private-source.pdf",
        "My Final Exam Feedback.docx",
    ],
)
def test_recursive_privacy_check_rejects_paths_identity_email_and_personal_files(
    leak: str,
) -> None:
    with pytest.raises(ValueError, match="phase2a_delta_privacy"):
        builder._privacy_check([{"nested": [{"source_derived_value": leak}]}])


def test_recursive_privacy_check_rejects_unapproved_urls_and_members() -> None:
    with pytest.raises(ValueError, match="privacy_url_not_approved"):
        builder._privacy_check([{"official_url": "https://example.com/legal.pdf"}])
    with pytest.raises(ValueError, match="privacy_artifact_name_invalid"):
        builder._privacy_check([{"quarantine_member": "personal essay.docx"}])
    with pytest.raises(ValueError, match="privacy_artifact_name_invalid"):
        builder._privacy_check([{"relative_path": "../../private/FAILURE.json"}])


def test_recursive_privacy_check_allows_controlled_members_and_public_https() -> None:
    builder._privacy_check(
        [
            {
                "file_name": builder.PACKET_NAME,
                "quarantine_member": ("repair-representation-0001-0123456789abcdef0123.json"),
                "root_name": builder.EXPECTED_REPAIR_ROOT_NAME,
                "official_url": ("https://www.legislation.gov.uk/ukpga/1977/50/section/3"),
            }
        ]
    )


@pytest.mark.parametrize(
    "host",
    [
        "gov.uk",
        "www.gov.uk",
        "jcpc.uk",
        "supremecourt.uk",
        "tas-cas.org",
        "www.tas-cas.org",
    ],
)
def test_recursive_privacy_check_allows_exact_additional_official_hosts(host: str) -> None:
    builder._privacy_check([{"official_url": f"https://{host}/official/resource"}])
