from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts import record_v111_phase2a_exact_remediation_owner_adoption as adoption


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


@pytest.fixture(scope="module")
def recorded_package(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("owner-adoption") / "approved"
    result = adoption.record_owner_adoption(
        packet_root=adoption.DEFAULT_PACKET_ROOT,
        quarantine_root=adoption.DEFAULT_QUARANTINE_ROOT,
        output_root=output,
        owner_reply=adoption.EXPECTED_OWNER_REPLY,
        owner_typed_name="Agnes",
        owner_decision_date="2026-08-28",
        recorded_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
    )
    assert result["status"] == adoption.STATUS
    return output


def test_exact_owner_adoption_is_recorded_without_executing_scope(
    recorded_package: Path,
) -> None:
    receipt = _load(recorded_package / adoption.RECEIPT_NAME)
    outcome = _load(recorded_package / adoption.OUTCOME_NAME)
    package = _load(recorded_package / adoption.PACKAGE_NAME)

    assert receipt["status"] == adoption.STATUS
    assert receipt["owner_typed_name"] == "Agnes"
    assert receipt["owner_decision_date"] == "2026-08-28"
    assert receipt["owner_approved"] is True
    assert receipt["owner_adoption_recorded"] is True
    assert receipt["owner_reply_normalized_sha256"] == (
        adoption.EXPECTED_NORMALIZED_OWNER_REPLY_SHA256
    )
    assert receipt["technical_source_binding_hold"] is True
    audit = receipt["post_approval_content_audit"]
    assert isinstance(audit, dict)
    assert audit["required"] is True
    assert audit["authorized_phase2a_execution_eligible"] is False
    assert audit["changed_raw_bytes_require_new_exact_owner_adoption"] is True

    scope = receipt["authorized_exact_scope"]
    assert isinstance(scope, dict)
    assert scope["owner_decision_count"] == 361
    assert scope["proposed_source_admission_count"] == 247
    assert scope["retained_quarantine_source_admission_hold_count"] == 31
    assert scope["retained_source_identity_and_admission_hold_count"] == 86
    assert receipt["owner_decision_application_authorized"] is True
    assert receipt["source_admission_authorized"] is True
    assert receipt["complete_source_scan_authorized"] is True
    assert receipt["successor_build_authorized"] is True
    assert receipt["embedding_authorized"] is True
    assert receipt["retrieval_reattestation_authorized"] is True
    assert receipt["all585_qualification_authorized"] is True

    for field in (
        "owner_decisions_applied",
        "owner_outcomes_applied",
        "source_admitted",
        "source_scan_run",
        "successor_build_run",
        "index_built",
        "embedding_run",
        "retrieval_reattestation_run",
        "all585_qualification_run",
        "automatic_indexing",
        "automatic_embedding",
        "candidate_mutated",
        "technical_qualification_assigned",
        *adoption._PROHIBITED_FALSE_FLAGS,
    ):
        assert receipt[field] is False

    assert outcome["status"] == adoption.STATUS
    assert outcome["successful_phase2a_package_claimed"] is False
    assert outcome["post_approval_content_audit_required"] is True
    assert package["status"] == adoption.STATUS
    assert package["technical_source_binding_hold"] is True
    assert package["post_approval_content_audit_required"] is True

    assert adoption._verify_seal(
        receipt,
        "artifact_content_sha256",
        "invalid",
    )
    assert adoption._verify_seal(
        outcome,
        "artifact_content_sha256",
        "invalid",
    )
    assert adoption._verify_seal(
        package,
        "artifact_content_sha256",
        "invalid",
    )


def test_owner_adoption_writes_verbatim_text_checksums_and_private_modes(
    recorded_package: Path,
) -> None:
    assert (recorded_package / adoption.VERBATIM_NAME).read_text(
        encoding="utf-8"
    ) == adoption.EXPECTED_OWNER_REPLY
    assert stat.S_IMODE(recorded_package.stat().st_mode) == 0o700
    for path in recorded_package.iterdir():
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    checksum_lines = (recorded_package / adoption.CHECKSUMS_NAME).read_text(encoding="utf-8")
    expected = "".join(
        f"{adoption._sha256_file(path)}  {path.name}\n"
        for path in sorted(recorded_package.iterdir())
        if path.name != adoption.CHECKSUMS_NAME
    )
    assert checksum_lines == expected


@pytest.mark.parametrize(
    ("reply", "name", "decision_date", "error"),
    [
        (
            adoption.EXPECTED_OWNER_REPLY.replace(
                "all-585 technical qualification only",
                "all-585 technical qualification and Phase 2B",
            ),
            "Agnes",
            "2026-08-28",
            "owner_reply_not_exact",
        ),
        (adoption.EXPECTED_OWNER_REPLY, "Someone Else", "2026-08-28", "name_not_exact"),
        (adoption.EXPECTED_OWNER_REPLY, "Agnes", "2026-08-29", "date_not_exact"),
    ],
)
def test_owner_adoption_rejects_nonexact_owner_identity_or_reply(
    tmp_path: Path,
    reply: str,
    name: str,
    decision_date: str,
    error: str,
) -> None:
    output = tmp_path / "rejected"
    with pytest.raises(ValueError, match=error):
        adoption.record_owner_adoption(
            packet_root=adoption.DEFAULT_PACKET_ROOT,
            quarantine_root=adoption.DEFAULT_QUARANTINE_ROOT,
            output_root=output,
            owner_reply=reply,
            owner_typed_name=name,
            owner_decision_date=decision_date,
            recorded_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    assert not output.exists()


def test_owner_adoption_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(ValueError, match="output_already_exists"):
        adoption.record_owner_adoption(
            packet_root=adoption.DEFAULT_PACKET_ROOT,
            quarantine_root=adoption.DEFAULT_QUARANTINE_ROOT,
            output_root=output,
            owner_reply=adoption.EXPECTED_OWNER_REPLY,
            owner_typed_name="Agnes",
            owner_decision_date="2026-08-28",
            recorded_at=datetime(2026, 8, 28, tzinfo=UTC),
        )


def test_item_inventory_verifier_rejects_bad_seal() -> None:
    bad = {"row_id": "row-1", "decision_content_sha256": "0" * 64}
    with pytest.raises(ValueError, match="bad_inventory"):
        adoption._verify_item_seals(
            [bad],
            count=1,
            seal_field="decision_content_sha256",
            id_field="row_id",
            code="bad_inventory",
        )
