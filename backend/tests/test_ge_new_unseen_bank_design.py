from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from app.evaluation.ge_new_unseen_bank_design import (
    DEFAULT_ROOT,
    NewUnseenBankDesignVerificationError,
    verify_design_package,
)


def test_question_free_design_package_reconciles() -> None:
    result = verify_design_package()
    assert result.legal_case_count == 92
    assert result.system_case_count == 23
    assert result.bank_created is False
    assert result.execution_authorized is False
    assert result.overall_state == (
        "NEW_UNSEEN_BANK_DESIGN_PREPARED_AWAITING_OWNER_CREATION_AUTHORIZATION"
    )


def test_design_verifier_rejects_created_bank_claim(tmp_path: Path) -> None:
    root = tmp_path / "design"
    shutil.copytree(DEFAULT_ROOT, root)
    state_path = root / "STATE-TRANSITION-RECEIPT.json"
    state = json.loads(state_path.read_text())
    state["new_unseen_bank"] = "CREATED"
    state_path.write_text(json.dumps(state))

    with pytest.raises(NewUnseenBankDesignVerificationError, match="artifact register"):
        verify_design_package(root)
