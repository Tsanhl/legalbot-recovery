from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

import app.evaluation.owner_quality_canary_feedback as feedback_module
from app.crypto import LocalCipher
from app.evaluation.owner_quality_canary_feedback import (
    OwnerCanaryFeedbackRecord,
    OwnerCanaryVersionDiffRecord,
    append_owner_canary_feedback,
    load_owner_canary_feedback_index_chain,
    record_owner_canary_development_diff,
)
from app.evaluation.owner_quality_canary_synthetic_fixture import (
    create_synthetic_owner_canary_review_fixture,
)


def _cipher() -> LocalCipher:
    return LocalCipher(Fernet(Fernet.generate_key()))


def _owner_ref() -> str:
    return "owner:" + "a" * 64


def test_feedback_is_encrypted_hash_chained_and_cannot_fork(tmp_path: Path) -> None:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "development",
        run_id="development-feedback-001",
    )
    cipher = _cipher()
    first_text = "Pass after checking every evidence-bound released claim."
    first, first_index = append_owner_canary_feedback(
        workspace=fixture.workspace,
        package=fixture.package,
        cipher=cipher,
        case_id="live30-q01",
        decision="pass",
        feedback_text=first_text,
        owner_ref=_owner_ref(),
        submitted_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
    )
    assert first.owner_pass
    assert not first.tuning_input_allowed
    assert first_index.feedback_record_seal_sha256 == first.seal_sha256

    encrypted_path = fixture.workspace.root / "owner-feedback" / f"{first.feedback_id}.enc"
    sidecar_path = fixture.workspace.root / "owner-feedback" / f"{first.feedback_id}.json"
    index_path = fixture.workspace.root / "safe-metrics" / f"{first.feedback_id}-index.json"
    decrypted = OwnerCanaryFeedbackRecord.model_validate_json(
        cipher.decrypt_bytes(encrypted_path.read_bytes())
    )
    assert decrypted == first
    assert first_text.encode() not in encrypted_path.read_bytes()
    assert first_text not in sidecar_path.read_text()
    assert first_text not in index_path.read_text()
    assert stat.S_IMODE(encrypted_path.stat().st_mode) == 0o600

    with pytest.raises(ValueError, match="exact current chain head"):
        append_owner_canary_feedback(
            workspace=fixture.workspace,
            package=fixture.package,
            cipher=cipher,
            case_id="live30-q02",
            decision="reject",
            feedback_text="This must not fork the immutable feedback chain.",
            owner_ref=_owner_ref(),
            submitted_at=datetime(2026, 8, 20, 9, 1, tzinfo=UTC),
        )

    second, _index = append_owner_canary_feedback(
        workspace=fixture.workspace,
        package=fixture.package,
        cipher=cipher,
        case_id="live30-q02",
        decision="revise",
        feedback_text="Narrow the second material proposition and re-review it.",
        owner_ref=_owner_ref(),
        submitted_at=datetime(2026, 8, 20, 9, 2, tzinfo=UTC),
        previous=first,
    )
    assert second.sequence_number == 2
    assert second.previous_feedback_seal_sha256 == first.seal_sha256
    assert second.tuning_input_allowed


def test_feedback_chain_reads_retained_directory_during_parent_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "parent-swap",
        run_id="development-feedback-parent-swap-001",
    )
    record, _index = append_owner_canary_feedback(
        workspace=fixture.workspace,
        package=fixture.package,
        cipher=_cipher(),
        case_id="live30-q01",
        decision="pass",
        feedback_text="This exact encrypted feedback must stay in its retained directory.",
        owner_ref=_owner_ref(),
        submitted_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
    )
    original_directory = fixture.workspace.root / "owner-feedback"
    retained_directory = fixture.workspace.root / "owner-feedback-retained"
    outside = tmp_path / "outside-feedback"
    outside.mkdir(mode=0o700)
    original_read = feedback_module.read_file_at
    swapped = False

    def swap_parent_then_read(
        directory_fd: int, name: str, *, required_mode: int | None = 0o600
    ) -> bytes:
        nonlocal swapped
        if not swapped:
            original_directory.rename(retained_directory)
            original_directory.symlink_to(outside, target_is_directory=True)
            swapped = True
        return original_read(directory_fd, name, required_mode=required_mode)

    monkeypatch.setattr(feedback_module, "read_file_at", swap_parent_then_read)
    chain = load_owner_canary_feedback_index_chain(
        workspace=fixture.workspace,
        package=fixture.package,
    )

    assert tuple(item.feedback_id for item in chain) == (record.feedback_id,)
    assert (retained_directory / f"{record.feedback_id}.enc").is_file()
    assert not tuple(outside.iterdir())


def test_holdout_feedback_is_recordable_but_never_tuning_input(tmp_path: Path) -> None:
    source = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "holdout-source",
        run_id="blind-holdout-source-001",
        lane="blind_holdout",
        answer_revision="holdout-source",
    )
    target = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "holdout-target",
        run_id="blind-holdout-target-001",
        lane="blind_holdout",
        answer_revision="holdout-target",
    )
    cipher = _cipher()
    feedback, index = append_owner_canary_feedback(
        workspace=source.workspace,
        package=source.package,
        cipher=cipher,
        case_id="live30-q01",
        decision="pass",
        feedback_text="Owner pass recorded for the one-shot blind answer.",
        owner_ref=_owner_ref(),
        submitted_at=datetime(2026, 8, 20, 10, 0, tzinfo=UTC),
    )
    assert feedback.owner_pass and index.owner_pass
    assert not feedback.accepted_for_change
    assert not feedback.tuning_input_allowed
    assert not index.tuning_input_allowed

    with pytest.raises(ValueError, match="accepted development feedback"):
        record_owner_canary_development_diff(
            workspace=target.workspace,
            source_package=source.package,
            target_package=target.package,
            accepted_feedback=feedback,
            cipher=cipher,
            case_id="live30-q01",
            before_answer=source.answers["live30-q01"],
            after_answer=target.answers["live30-q01"],
        )


def test_accepted_development_diff_is_encrypted_and_bound_to_both_packages(
    tmp_path: Path,
) -> None:
    source = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "development-source",
        run_id="development-source-001",
        answer_revision="baseline",
    )
    target = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "development-target",
        run_id="development-target-001",
        answer_revision="improved",
    )
    cipher = _cipher()
    feedback, _index = append_owner_canary_feedback(
        workspace=source.workspace,
        package=source.package,
        cipher=cipher,
        case_id="live30-q01",
        decision="revise",
        feedback_text="Replace the baseline wording with the accepted narrower version.",
        owner_ref=_owner_ref(),
        submitted_at=datetime(2026, 8, 20, 11, 0, tzinfo=UTC),
    )
    diff = record_owner_canary_development_diff(
        workspace=target.workspace,
        source_package=source.package,
        target_package=target.package,
        accepted_feedback=feedback,
        cipher=cipher,
        case_id="live30-q01",
        before_answer=source.answers["live30-q01"],
        after_answer=target.answers["live30-q01"],
    )
    encrypted_path = target.workspace.root / "version-diffs" / f"{diff.diff_id}.enc"
    sidecar_path = target.workspace.root / "version-diffs" / f"{diff.diff_id}.json"
    index_path = target.workspace.root / "safe-metrics" / f"{diff.diff_id}-index.json"
    decrypted = OwnerCanaryVersionDiffRecord.model_validate_json(
        cipher.decrypt_bytes(encrypted_path.read_bytes())
    )
    assert decrypted == diff
    assert diff.source_package_seal_sha256 == source.package.seal_sha256
    assert diff.target_package_seal_sha256 == target.package.seal_sha256
    assert diff.accepted_feedback_seal_sha256 == feedback.seal_sha256
    assert "baseline" in diff.diff_text and "improved" in diff.diff_text
    assert diff.diff_text not in sidecar_path.read_text()
    assert diff.diff_text not in index_path.read_text()
    assert json.loads(index_path.read_text())["diff_record_seal_sha256"] == diff.seal_sha256

    for category in ("owner-feedback", "version-diffs"):
        with pytest.raises(ValueError, match="dedicated projection contract"):
            target.workspace.write_safe_json(
                category=category,
                filename="unsafe.json",
                value={"count": 1},
            )
