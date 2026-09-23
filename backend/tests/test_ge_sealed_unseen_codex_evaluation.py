from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.evaluation.ge_sealed_unseen_codex_evaluation import (
    DEFAULT_CORRECTION_ROOT,
    DEFAULT_PUBLIC_ROOT,
    SealedUnseenVerificationError,
    verify_completed_campaign,
)


def test_completed_public_sealed_unseen_campaign_reconciles() -> None:
    result = verify_completed_campaign()
    assert result.overall_state == "SEALED_UNSEEN_ONE_PASS_COMPLETE_HOLD_NO_REPAIR"
    assert result.overall_pass_count == 157
    assert result.overall_hold_count == 149
    assert result.terminal_disposition_count == 306
    assert result.private_run_verified is False


def test_verifier_rejects_reexecution_or_training_drift(tmp_path: Path) -> None:
    public = tmp_path / "public"
    public.mkdir()
    for source in DEFAULT_PUBLIC_ROOT.iterdir():
        if source.is_file():
            (public / source.name).write_bytes(source.read_bytes())
    state_path = public / "STATE-TRANSITION-RECEIPT.json"
    state = json.loads(state_path.read_text())
    state["reexecution_permitted"] = True
    state_path.write_text(json.dumps(state))

    with pytest.raises(SealedUnseenVerificationError, match="artifact register"):
        verify_completed_campaign(public_root=public, correction_root=DEFAULT_CORRECTION_ROOT)
