from __future__ import annotations

import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app.crypto import LocalCipher
from app.evaluation.live_suite import sealed_sha256
from app.evaluation.owner_quality_canary_acceptance import (
    create_owner_canary_acceptance_summary,
    require_development_owner_acceptance_for_promotion_presentation,
    require_holdout_owner_acceptance_for_normal_live_readiness,
    verify_owner_canary_acceptance_summary,
)
from app.evaluation.owner_quality_canary_feedback import (
    OwnerCanaryFeedbackRecord,
    append_owner_canary_feedback,
)
from app.evaluation.owner_quality_canary_synthetic_fixture import (
    SyntheticOwnerCanaryReviewFixture,
    create_synthetic_owner_canary_review_fixture,
)


def _cipher() -> LocalCipher:
    return LocalCipher(Fernet(Fernet.generate_key()))


def _append_decisions(
    *,
    fixture: SyntheticOwnerCanaryReviewFixture,
    cipher: LocalCipher,
    final_decision: str = "pass",
) -> OwnerCanaryFeedbackRecord:
    previous: OwnerCanaryFeedbackRecord | None = None
    base = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
    for ordinal, case_id in enumerate(fixture.package.case_ids, start=1):
        decision = final_decision if ordinal == 30 else "pass"
        previous, _index = append_owner_canary_feedback(
            workspace=fixture.workspace,
            package=fixture.package,
            cipher=cipher,
            case_id=case_id,
            decision=decision,  # type: ignore[arg-type]
            feedback_text=f"Explicit synthetic owner decision {ordinal}: {decision}.",
            owner_ref="owner:" + "a" * 64,
            submitted_at=base + timedelta(minutes=ordinal),
            previous=previous,
        )
    assert previous is not None
    return previous


def _rewrite_index(path: Path, **changes: object) -> None:
    material = json.loads(path.read_text())
    material.update(changes)
    material["seal_sha256"] = sealed_sha256(material)
    path.write_text(json.dumps(material, sort_keys=True) + "\n")
    path.chmod(0o600)


def test_exact_30_summary_is_private_create_only_and_not_live_authority(
    tmp_path: Path,
) -> None:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "development",
        run_id="development-owner-acceptance-001",
    )
    cipher = _cipher()
    _append_decisions(fixture=fixture, cipher=cipher)
    summary = create_owner_canary_acceptance_summary(
        workspace=fixture.workspace,
        package=fixture.package,
        created_at=datetime(2026, 8, 20, 13, 0, tzinfo=UTC),
    )

    path = fixture.workspace.root / "safe-metrics" / "owner-acceptance-summary.json"
    persisted = json.loads(path.read_text())
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert summary.explicit_latest_owner_decision_count == 30
    assert summary.case_ids == fixture.package.case_ids
    assert summary.answer_sha256s == fixture.package.answer_sha256s
    assert summary.feedback_chain_entry_count == 30
    assert summary.all_latest_owner_decisions_passed
    assert summary.development_completion_gate_passed
    assert not summary.holdout_post_run_acceptance_gate_passed
    assert summary.owner_reference_authentication == "not_cryptographically_verified"
    assert not summary.owner_signature_verified
    assert not summary.o04_signature_verified
    assert not summary.technical_completion_alone_sufficient
    assert not summary.authorizes_active
    assert not summary.authorizes_promotion
    assert not summary.authorizes_o04
    assert not summary.authorizes_normal_live
    assert "question" not in persisted and "answer" not in persisted
    assert not list(fixture.workspace.root.rglob("ACTIVE.json"))
    assert not list(fixture.workspace.root.rglob("*O-04*"))
    assert (
        require_development_owner_acceptance_for_promotion_presentation(
            workspace=fixture.workspace,
            package=fixture.package,
        )
        == summary
    )
    with pytest.raises(ValueError, match="holdout owner acceptance"):
        require_holdout_owner_acceptance_for_normal_live_readiness(
            workspace=fixture.workspace,
            package=fixture.package,
        )
    with pytest.raises(FileExistsError, match="create-only"):
        create_owner_canary_acceptance_summary(
            workspace=fixture.workspace,
            package=fixture.package,
            created_at=datetime(2026, 8, 20, 13, 1, tzinfo=UTC),
        )


def test_technical_completion_without_feedback_cannot_satisfy_owner_acceptance(
    tmp_path: Path,
) -> None:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "technical-only",
        run_id="technical-only-001",
    )
    with pytest.raises(ValueError, match="summary is required"):
        require_development_owner_acceptance_for_promotion_presentation(
            workspace=fixture.workspace,
            package=fixture.package,
        )
    with pytest.raises(ValueError, match="missing one or more"):
        create_owner_canary_acceptance_summary(
            workspace=fixture.workspace,
            package=fixture.package,
            created_at=datetime(2026, 8, 20, 13, 0, tzinfo=UTC),
        )


@pytest.mark.parametrize("decision", ["revise", "reject"])
def test_latest_revise_or_reject_blocks_exact_30_acceptance(
    tmp_path: Path,
    decision: str,
) -> None:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / decision,
        run_id=f"development-{decision}-001",
    )
    _append_decisions(fixture=fixture, cipher=_cipher(), final_decision=decision)
    with pytest.raises(ValueError, match="revise or reject"):
        create_owner_canary_acceptance_summary(
            workspace=fixture.workspace,
            package=fixture.package,
            created_at=datetime(2026, 8, 20, 13, 0, tzinfo=UTC),
        )


def test_latest_decision_wins_and_a_later_revise_blocks(tmp_path: Path) -> None:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "latest",
        run_id="development-latest-001",
    )
    cipher = _cipher()
    previous = _append_decisions(fixture=fixture, cipher=cipher)
    append_owner_canary_feedback(
        workspace=fixture.workspace,
        package=fixture.package,
        cipher=cipher,
        case_id=fixture.package.case_ids[0],
        decision="revise",
        feedback_text="The newest explicit decision requires a fresh answer version.",
        owner_ref="owner:" + "a" * 64,
        submitted_at=datetime(2026, 8, 20, 14, 0, tzinfo=UTC),
        previous=previous,
    )
    with pytest.raises(ValueError, match="revise or reject"):
        create_owner_canary_acceptance_summary(
            workspace=fixture.workspace,
            package=fixture.package,
            created_at=datetime(2026, 8, 20, 14, 1, tzinfo=UTC),
        )


def test_answer_mismatched_feedback_is_rejected(tmp_path: Path) -> None:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "answer-mismatch",
        run_id="development-answer-mismatch-001",
    )
    previous = _append_decisions(fixture=fixture, cipher=_cipher())
    index_path = fixture.workspace.root / "safe-metrics" / f"{previous.feedback_id}-index.json"
    replacement = "f" * 64
    if replacement == previous.answer_sha256:
        replacement = "e" * 64
    _rewrite_index(index_path, answer_sha256=replacement)
    with pytest.raises(ValueError, match="stale or mismatched answer"):
        create_owner_canary_acceptance_summary(
            workspace=fixture.workspace,
            package=fixture.package,
            created_at=datetime(2026, 8, 20, 13, 0, tzinfo=UTC),
        )


def test_forked_feedback_chain_is_rejected(tmp_path: Path) -> None:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "forked",
        run_id="development-forked-001",
    )
    previous = _append_decisions(fixture=fixture, cipher=_cipher())
    index_path = fixture.workspace.root / "safe-metrics" / f"{previous.feedback_id}-index.json"
    _rewrite_index(index_path, previous_feedback_seal_sha256="0" * 64)
    with pytest.raises(ValueError, match="forked or incomplete"):
        create_owner_canary_acceptance_summary(
            workspace=fixture.workspace,
            package=fixture.package,
            created_at=datetime(2026, 8, 20, 13, 0, tzinfo=UTC),
        )


def test_summary_becomes_stale_if_feedback_chain_advances(tmp_path: Path) -> None:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "stale",
        run_id="development-stale-001",
    )
    cipher = _cipher()
    previous = _append_decisions(fixture=fixture, cipher=cipher)
    summary = create_owner_canary_acceptance_summary(
        workspace=fixture.workspace,
        package=fixture.package,
        created_at=datetime(2026, 8, 20, 13, 0, tzinfo=UTC),
    )
    append_owner_canary_feedback(
        workspace=fixture.workspace,
        package=fixture.package,
        cipher=cipher,
        case_id=fixture.package.case_ids[0],
        decision="pass",
        feedback_text="A later explicit pass still changes the bound feedback-chain head.",
        owner_ref="owner:" + "a" * 64,
        submitted_at=datetime(2026, 8, 20, 14, 0, tzinfo=UTC),
        previous=previous,
    )
    with pytest.raises(ValueError, match="stale or bound to different inputs"):
        verify_owner_canary_acceptance_summary(
            workspace=fixture.workspace,
            package=fixture.package,
            expected=summary,
        )


def test_holdout_requires_its_own_exact_30_acceptance_summary(tmp_path: Path) -> None:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "holdout",
        run_id="blind-holdout-owner-acceptance-001",
        lane="blind_holdout",
    )
    _append_decisions(fixture=fixture, cipher=_cipher())
    summary = create_owner_canary_acceptance_summary(
        workspace=fixture.workspace,
        package=fixture.package,
        created_at=datetime(2026, 8, 20, 13, 0, tzinfo=UTC),
    )
    assert not summary.development_completion_gate_passed
    assert summary.holdout_post_run_acceptance_gate_passed
    assert (
        require_holdout_owner_acceptance_for_normal_live_readiness(
            workspace=fixture.workspace,
            package=fixture.package,
        )
        == summary
    )
    with pytest.raises(ValueError, match="development owner acceptance"):
        require_development_owner_acceptance_for_promotion_presentation(
            workspace=fixture.workspace,
            package=fixture.package,
        )


def test_acceptance_reader_rejects_symlinked_summary(tmp_path: Path) -> None:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "symlinked-summary",
        run_id="development-owner-acceptance-symlink-001",
    )
    _append_decisions(fixture=fixture, cipher=_cipher())
    summary = create_owner_canary_acceptance_summary(
        workspace=fixture.workspace,
        package=fixture.package,
        created_at=datetime(2026, 8, 20, 13, 0, tzinfo=UTC),
    )
    path = fixture.workspace.root / "safe-metrics" / "owner-acceptance-summary.json"
    retained = path.with_name("owner-acceptance-summary-retained.json")
    path.rename(retained)
    path.symlink_to(retained)

    with pytest.raises(ValueError, match="unsafe"):
        verify_owner_canary_acceptance_summary(
            workspace=fixture.workspace,
            package=fixture.package,
            expected=summary,
        )
