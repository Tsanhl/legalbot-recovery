from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts import record_v111_phase2a_finite_remediation_r3_owner_adoption as adoption


@pytest.fixture(scope="module")
def recorded(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("finite-r3-adoption") / "receipt"
    receipt = adoption.record_owner_adoption(
        output_root=output,
        approval_body=(adoption.PACKET_ROOT / adoption.PROMPT_NAME).read_bytes(),
        signature_followup=adoption.EXPECTED_SIGNATURE_TEXT,
        owner_typed_name="Agnes",
        owner_decision_date="2026-08-29",
        recorded_at=datetime(2026, 8, 29, 1, tzinfo=UTC),
    )
    assert receipt["status"] == adoption.STATUS
    return output


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def test_receipt_binds_two_messages_packet_contracts_and_existing_chain(recorded: Path) -> None:
    receipt = _load(recorded / adoption.RECEIPT_NAME)
    evidence = _load(recorded / adoption.DECISION_EVIDENCE_NAME)
    link = _load(recorded / adoption.AUTHORITY_LINK_NAME)
    assert receipt["r3_packet_content_sha256"] == adoption.EXPECTED_PACKET_CONTENT_SHA256
    assert receipt["r3_contracts_content_sha256"] == adoption.EXPECTED_CONTRACTS_CONTENT_SHA256
    assert receipt["signature_evidence_mode"] == "SEPARATE_FOLLOWUP_MESSAGE"
    assert evidence["ordered_message_count"] == 2
    assert evidence["combined_verbatim_message_claimed"] is False
    assert link["authority_content_sha256"] == adoption.EXPECTED_AUTHORITY_CONTENT_SHA256
    assert link["total_count"] == 1 and link["consumed_count"] == 0 and link["remaining_count"] == 1
    assert link["new_or_additional_execution_authority_created"] is False


def test_receipt_has_exact_146_outcome_boundary_and_no_later_authority(recorded: Path) -> None:
    receipt = _load(recorded / adoption.RECEIPT_NAME)
    assert receipt["exact_row_contract_count"] == 146
    assert receipt["exact_cohort_remediation_row_count"] == 17
    assert receipt["strict_human_review_handoff_row_count"] == 129
    assert receipt["exact_source_decision_count"] == 25
    for key in adoption._PROHIBITED_FALSE_FLAGS:
        assert receipt[key] is False
    for key in adoption._NOT_RUN_FALSE_FLAGS:
        assert receipt[key] is False


def test_private_create_only_checksums(recorded: Path) -> None:
    assert stat.S_IMODE(recorded.stat().st_mode) == 0o700
    for path in recorded.iterdir():
        assert path.is_file() and not path.is_symlink()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    expected = "".join(
        f"{adoption._sha256_file(path)}  {path.name}\n"
        for path in sorted(recorded.iterdir())
        if path.name != adoption.CHECKSUMS_NAME
    )
    assert (recorded / adoption.CHECKSUMS_NAME).read_text() == expected


@pytest.mark.parametrize(
    ("body_change", "signature", "name", "decision_date", "code"),
    [
        (b"x", adoption.EXPECTED_SIGNATURE_TEXT, "Agnes", "2026-08-29", "approval_body_not_exact"),
        (
            b"",
            "Owner typed name: Agnes\nDecision date: 2026-08-28\n",
            "Agnes",
            "2026-08-29",
            "signature_followup_not_exact",
        ),
        (b"", adoption.EXPECTED_SIGNATURE_TEXT, "Other", "2026-08-29", "owner_name_not_exact"),
        (b"", adoption.EXPECTED_SIGNATURE_TEXT, "Agnes", "2026-08-28", "owner_date_not_exact"),
    ],
)
def test_nonexact_decision_evidence_rejected(
    tmp_path: Path, body_change: bytes, signature: str, name: str, decision_date: str, code: str
) -> None:
    body = (adoption.PACKET_ROOT / adoption.PROMPT_NAME).read_bytes() + body_change
    with pytest.raises(ValueError, match=code):
        adoption.record_owner_adoption(
            output_root=tmp_path / "rejected",
            approval_body=body,
            signature_followup=signature,
            owner_typed_name=name,
            owner_decision_date=decision_date,
            recorded_at=datetime(2026, 8, 29, 1, tzinfo=UTC),
        )
    assert not (tmp_path / "rejected").exists()


def test_existing_output_is_not_replaced(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(ValueError, match="output_already_exists"):
        adoption.record_owner_adoption(
            output_root=output,
            approval_body=(adoption.PACKET_ROOT / adoption.PROMPT_NAME).read_bytes(),
            signature_followup=adoption.EXPECTED_SIGNATURE_TEXT,
            owner_typed_name="Agnes",
            owner_decision_date="2026-08-29",
            recorded_at=datetime(2026, 8, 29, 1, tzinfo=UTC),
        )
