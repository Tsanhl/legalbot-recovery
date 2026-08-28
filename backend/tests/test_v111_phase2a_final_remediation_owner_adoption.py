from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts import record_v111_phase2a_final_remediation_owner_adoption as adoption


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


@pytest.fixture(scope="module")
def recorded(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("final-adoption") / "receipt"
    result = adoption.record_owner_adoption(
        packet_root=adoption.PACKET_ROOT,
        original_approval_root=adoption.ORIGINAL_APPROVAL_ROOT,
        output_root=output,
        owner_reply=adoption.EXPECTED_OWNER_REPLY,
        owner_typed_name="Agnes",
        owner_decision_date="2026-08-28",
        recorded_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
    )
    assert result["status"] == adoption.STATUS
    return output


def test_receipt_binds_exact_packet_owner_and_original_unspent_chain(recorded: Path) -> None:
    receipt = _load(recorded / adoption.RECEIPT_NAME)
    authority = _load(recorded / adoption.AUTHORITY_STATE_NAME)
    assert receipt["final_owner_packet_content_sha256"] == (adoption.EXPECTED_PACKET_CONTENT_SHA256)
    assert receipt["original_owner_receipt_content_sha256"] == (
        adoption.EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256
    )
    assert receipt["owner_typed_name"] == "Agnes"
    assert receipt["owner_decision_date"] == "2026-08-28"
    assert receipt["owner_reply_normalized_sha256"] == (
        adoption.EXPECTED_NORMALIZED_OWNER_REPLY_SHA256
    )
    assert authority["status"] == adoption.CHAIN_STATUS
    assert authority["total_execution_chain_count"] == 1
    assert authority["execution_chain_consumed_count"] == 0
    assert authority["execution_chain_remaining_count"] == 1
    assert set(authority["stages"].values()) == {"NOT_RUN"}
    assert authority["new_or_additional_authority_created"] is False


def test_receipt_keeps_execution_and_every_later_phase_unrun(recorded: Path) -> None:
    for name in (
        adoption.RECEIPT_NAME,
        adoption.OUTCOME_NAME,
        adoption.AUTHORITY_STATE_NAME,
        adoption.PACKAGE_NAME,
    ):
        value = _load(recorded / name)
        for field in (*adoption._UNSPENT_STAGE_FLAGS, *adoption._PROHIBITED_FALSE_FLAGS):
            assert value[field] is False
        material = dict(value)
        supplied = material.pop("artifact_content_sha256")
        assert supplied == adoption._sealed(material)


def test_receipt_is_private_create_only_and_checksummed(recorded: Path) -> None:
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
    ("reply", "name", "decision_date", "code"),
    [
        (
            adoption.EXPECTED_OWNER_REPLY.replace(
                "This approval does not authorize", "This approval does authorize"
            ),
            "Agnes",
            "2026-08-28",
            "owner_reply_not_exact",
        ),
        (adoption.EXPECTED_OWNER_REPLY, "Other", "2026-08-28", "owner_name_not_exact"),
        (adoption.EXPECTED_OWNER_REPLY, "Agnes", "2026-08-29", "owner_date_not_exact"),
    ],
)
def test_nonexact_owner_adoption_is_rejected_without_output(
    tmp_path: Path, reply: str, name: str, decision_date: str, code: str
) -> None:
    output = tmp_path / "rejected"
    with pytest.raises(ValueError, match=code):
        adoption.record_owner_adoption(
            packet_root=adoption.PACKET_ROOT,
            original_approval_root=adoption.ORIGINAL_APPROVAL_ROOT,
            output_root=output,
            owner_reply=reply,
            owner_typed_name=name,
            owner_decision_date=decision_date,
            recorded_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    assert not output.exists()


def test_changed_packet_bytes_are_rejected(tmp_path: Path) -> None:
    packet_root = tmp_path / "packet"
    packet_root.mkdir()
    for source in adoption.PACKET_ROOT.iterdir():
        (packet_root / source.name).write_bytes(source.read_bytes())
    (packet_root / adoption.PACKET_NAME).write_bytes(b"{}\n")
    with pytest.raises(ValueError, match="packet_file_digest_invalid"):
        adoption.record_owner_adoption(
            packet_root=packet_root,
            original_approval_root=adoption.ORIGINAL_APPROVAL_ROOT,
            output_root=tmp_path / "rejected",
            owner_reply=adoption.EXPECTED_OWNER_REPLY,
            owner_typed_name="Agnes",
            owner_decision_date="2026-08-28",
            recorded_at=datetime(2026, 8, 28, tzinfo=UTC),
        )


def test_existing_output_is_never_replaced(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(ValueError, match="output_already_exists"):
        adoption.record_owner_adoption(
            packet_root=adoption.PACKET_ROOT,
            original_approval_root=adoption.ORIGINAL_APPROVAL_ROOT,
            output_root=output,
            owner_reply=adoption.EXPECTED_OWNER_REPLY,
            owner_typed_name="Agnes",
            owner_decision_date="2026-08-28",
            recorded_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
