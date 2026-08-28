from __future__ import annotations

import io
import json
import os
import stat
import struct
import subprocess
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest
from cryptography.fernet import Fernet
from pypdf import PdfWriter

import app.evaluation.owner_quality_canary_docx as docx_module
from app.crypto import LocalCipher
from app.evaluation.owner_quality_canary_docx import (
    export_owner_quality_canary_docx,
    record_owner_quality_canary_docx_inspection,
    record_owner_quality_canary_docx_render,
)
from app.evaluation.owner_quality_canary_feedback import (
    OwnerCanaryFeedbackRecord,
    OwnerCanaryVersionDiffRecord,
    load_owner_canary_feedback_index_chain,
)
from app.evaluation.owner_quality_canary_intake import (
    create_owner_review_companion,
    ingest_owner_review_submission,
    load_owner_review_workspace,
    record_development_diff_from_owner_feedback,
)
from app.evaluation.owner_quality_canary_synthetic_fixture import (
    SyntheticOwnerCanaryReviewFixture,
    create_synthetic_owner_canary_review_fixture,
)


def _cipher() -> LocalCipher:
    return LocalCipher(Fernet(Fernet.generate_key()))


def _chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def _png() -> bytes:
    width, height = 600, 800
    rows = b"".join(b"\x00" + b"\xff\xff\xff" * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _chunk(b"IDAT", zlib.compress(rows, level=9))
        + _chunk(b"IEND", b"")
    )


def _with_rendered_docx(
    *,
    root: Path,
    run_id: str,
    monkeypatch: pytest.MonkeyPatch,
    lane: Literal["development", "blind_holdout"] = "development",
    revision: str = "baseline",
) -> SyntheticOwnerCanaryReviewFixture:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=root,
        run_id=run_id,
        lane=lane,
        answer_revision=revision,
    )
    _docx_path, _control_path, control = export_owner_quality_canary_docx(
        workspace=fixture.workspace,
        package=fixture.package,
    )
    identity = root.parent / f"{run_id}-renderer-identity.bin"
    identity.write_bytes(b"fixed synthetic renderer identity")

    def _open_identity(_path: Path, *, expected_sha256: str) -> tuple[int, bytes]:
        assert expected_sha256
        return os.open(identity, os.O_RDONLY), identity.read_bytes()

    def _write_at(directory_fd: int, name: str, data: bytes) -> None:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            os.write(descriptor, data)
        finally:
            os.close(descriptor)

    def _run(
        command: tuple[str, ...],
        *,
        pass_fds: tuple[int, ...],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        output_fd = pass_fds[-1]
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        pdf = io.BytesIO()
        writer.write(pdf)
        _write_at(output_fd, "render-input.pdf", pdf.getvalue())
        _write_at(output_fd, "page-1.png", _png())
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(docx_module, "_open_verified_regular_file", _open_identity)
    monkeypatch.setattr(docx_module.subprocess, "run", _run)
    monkeypatch.setattr(
        docx_module,
        "_verify_trusted_owner_docx_inspection_signature",
        lambda **_kwargs: None,
    )
    _receipt_path, receipt = record_owner_quality_canary_docx_render(
        workspace=fixture.workspace,
        control=control,
        rendered_at=datetime(2026, 8, 20, 12, 0, tzinfo=UTC),
    )
    record_owner_quality_canary_docx_inspection(
        workspace=fixture.workspace,
        control=control,
        receipt=receipt,
        owner_ref="owner:" + "b" * 64,
        inspected_at=datetime(2026, 8, 20, 12, 1, tzinfo=UTC),
        inspected_page_count=1,
        visual_inspection_passed=True,
        all_pages_inspected_at_full_size=True,
        no_clipped_text=True,
        no_overlapping_objects=True,
        no_broken_tables=True,
        no_missing_glyphs=True,
        signature_algorithm="synthetic-owner-signature-v1",
        signature="synthetic-owner-signature",
    )
    create_owner_review_companion(
        workspace=fixture.workspace,
        package=fixture.package,
    )
    return fixture


def _fill_submission(
    fixture: SyntheticOwnerCanaryReviewFixture,
    *,
    revise_case: str | None = None,
    confirmation: bool = True,
) -> Path:
    path = fixture.workspace.root / "review-docx" / "review-companion-form.json"
    value = json.loads(path.read_text())
    value["owner_ref"] = "owner:" + "a" * 64
    value["submitted_at"] = "2026-08-20T13:00:00Z"
    value["explicit_owner_confirmation"] = confirmation
    for row in value["decisions"]:
        row["decision"] = "revise" if row["case_id"] == revise_case else "pass"
        row["feedback_text"] = (
            "Narrow this exact released answer and run a fresh evidence review."
            if row["case_id"] == revise_case
            else "Explicit owner pass for this exact answer digest."
        )
        row["explicit_owner_confirmation"] = confirmation
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)
    return path


def test_structured_intake_never_parses_docx_marks_and_creates_exact30_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _with_rendered_docx(
        root=tmp_path / "development",
        run_id="development-intake-001",
        monkeypatch=monkeypatch,
    )
    control = json.loads(
        (fixture.workspace.root / "review-docx/review-companion-control.json").read_text()
    )
    assert control["docx_checkbox_marks_parsed"] is False
    assert control["owner_decisions_inferred"] is False
    assert control["case_count"] == 30

    cipher = _cipher()
    submission = _fill_submission(fixture)
    receipt = ingest_owner_review_submission(
        workspace=fixture.workspace,
        package=fixture.package,
        submission_path=submission,
        cipher=cipher,
    )
    assert receipt.case_count == 30
    assert receipt.all_decisions_passed
    assert receipt.acceptance_summary_created
    assert not receipt.docx_marks_inferred
    assert not receipt.holdout_feedback_used_for_tuning
    assert not receipt.tuning_input_allowed_case_ids
    assert len(receipt.feedback_record_seal_sha256s) == 30
    assert (fixture.workspace.root / "safe-metrics/owner-acceptance-summary.json").is_file()

    chain = load_owner_canary_feedback_index_chain(
        workspace=fixture.workspace,
        package=fixture.package,
    )
    assert len(chain) == 30
    encrypted = fixture.workspace.root / "owner-feedback" / f"{chain[0].feedback_id}.enc"
    record = OwnerCanaryFeedbackRecord.model_validate_json(
        cipher.decrypt_bytes(encrypted.read_bytes())
    )
    assert record.feedback_text == "Explicit owner pass for this exact answer digest."
    assert record.feedback_text not in encrypted.read_bytes().decode("latin-1")
    assert (
        record.feedback_text
        not in (
            fixture.workspace.root / "safe-metrics" / f"{chain[0].feedback_id}-index.json"
        ).read_text()
    )
    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600

    # Idempotent replay returns the create-only intake receipt and appends nothing.
    repeated = ingest_owner_review_submission(
        workspace=fixture.workspace,
        package=fixture.package,
        submission_path=submission,
        cipher=cipher,
    )
    assert repeated == receipt
    assert (
        len(
            load_owner_canary_feedback_index_chain(
                workspace=fixture.workspace,
                package=fixture.package,
            )
        )
        == 30
    )


def test_intake_requires_explicit_exact_answer_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _with_rendered_docx(
        root=tmp_path / "confirmation",
        run_id="development-intake-confirm-001",
        monkeypatch=monkeypatch,
    )
    submission = _fill_submission(fixture, confirmation=False)
    with pytest.raises(ValueError):
        ingest_owner_review_submission(
            workspace=fixture.workspace,
            package=fixture.package,
            submission_path=submission,
            cipher=_cipher(),
        )
    assert not tuple((fixture.workspace.root / "owner-feedback").glob("owner-feedback-*.enc"))

    value = json.loads(submission.read_text())
    value["explicit_owner_confirmation"] = True
    for row in value["decisions"]:
        row["explicit_owner_confirmation"] = True
    value["decisions"][0]["answer_sha256"] = "f" * 64
    submission.write_text(json.dumps(value))
    submission.chmod(0o600)
    with pytest.raises(ValueError, match="exact rendered answers"):
        ingest_owner_review_submission(
            workspace=fixture.workspace,
            package=fixture.package,
            submission_path=submission,
            cipher=_cipher(),
        )


def test_holdout_feedback_is_encrypted_but_never_tuning_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _with_rendered_docx(
        root=tmp_path / "holdout",
        run_id="blind-holdout-intake-001",
        monkeypatch=monkeypatch,
        lane="blind_holdout",
    )
    cipher = _cipher()
    receipt = ingest_owner_review_submission(
        workspace=fixture.workspace,
        package=fixture.package,
        submission_path=_fill_submission(fixture, revise_case="live30-q01"),
        cipher=cipher,
    )
    assert not receipt.all_decisions_passed
    assert not receipt.acceptance_summary_created
    assert not receipt.tuning_input_allowed_case_ids
    assert not receipt.development_version_diff_required_case_ids
    chain = load_owner_canary_feedback_index_chain(
        workspace=fixture.workspace,
        package=fixture.package,
    )
    assert not any(item.tuning_input_allowed for item in chain)


def test_development_diff_wrapper_uses_only_explicit_revise_feedback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _with_rendered_docx(
        root=tmp_path / "source",
        run_id="development-intake-source-001",
        monkeypatch=monkeypatch,
        revision="baseline",
    )
    target = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "target",
        run_id="development-intake-target-001",
        answer_revision="improved",
    )
    cipher = _cipher()
    receipt = ingest_owner_review_submission(
        workspace=source.workspace,
        package=source.package,
        submission_path=_fill_submission(source, revise_case="live30-q01"),
        cipher=cipher,
    )
    assert receipt.tuning_input_allowed_case_ids == ("live30-q01",)
    feedback = load_owner_canary_feedback_index_chain(
        workspace=source.workspace,
        package=source.package,
    )[0]
    diff = record_development_diff_from_owner_feedback(
        source_workspace=source.workspace,
        source_package=source.package,
        target_workspace=target.workspace,
        target_package=target.package,
        feedback_id=feedback.feedback_id,
        case_id="live30-q01",
        cipher=cipher,
    )
    encrypted = target.workspace.root / "version-diffs" / f"{diff.diff_id}.enc"
    decrypted = OwnerCanaryVersionDiffRecord.model_validate_json(
        cipher.decrypt_bytes(encrypted.read_bytes())
    )
    assert decrypted == diff
    assert diff.development_only and diff.tuning_input_allowed
    assert "baseline" in diff.diff_text and "improved" in diff.diff_text


def test_workspace_loader_requires_private_permissions(tmp_path: Path) -> None:
    run_id = "development-intake-loader-001"
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / run_id,
        run_id=run_id,
    )
    assert (
        load_owner_review_workspace(fixture.workspace.root).manifest == fixture.workspace.manifest
    )
    fixture.workspace.root.chmod(0o755)
    with pytest.raises(ValueError, match="0700"):
        load_owner_review_workspace(fixture.workspace.root)
