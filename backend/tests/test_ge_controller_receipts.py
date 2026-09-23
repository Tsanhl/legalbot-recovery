from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.evaluation.ge_controller_receipts import (
    DurableControllerReceiptStore,
    RepeatedDefectHold,
    StaleLeaseError,
    semantic_work_key,
    stable_defect_fingerprint,
)


def work(*, stage: str = "VISIBLE_CONSUMER") -> dict[str, str]:
    return {
        "stage": stage,
        "candidate_id": "candidate-visible-r1",
        "set_id": "uk-usa-development",
        "policy_sha256": "1" * 64,
        "source_set_sha256": "2" * 64,
        "evaluator_sha256": "3" * 64,
        "authority_sha256": "4" * 64,
    }


def lease(store: DurableControllerReceiptStore, controller: str = "controller-a"):
    return store.acquire_lease(
        controller_id=controller,
        owner_ref="owner-local-session",
        authority_sha256="4" * 64,
        authority_mechanism="RECORDED_OWNER_INSTRUCTION",
        authority_authenticated=True,
        scope="UK_USA_DEVELOPMENT",
    )


def test_semantic_identity_ignores_replaceable_run_ids() -> None:
    assert semantic_work_key(**work()) == semantic_work_key(**dict(work()))
    assert stable_defect_fingerprint(
        stage="VISIBLE_CONSUMER",
        defect_code="MODEL_UNAVAILABLE",
        input_sha256="5" * 64,
        repair_sha256=None,
    ) == stable_defect_fingerprint(
        stage="VISIBLE_CONSUMER",
        defect_code="MODEL_UNAVAILABLE",
        input_sha256="5" * 64,
        repair_sha256=None,
    )


def test_successor_lease_fences_every_old_commit(tmp_path: Path) -> None:
    store = DurableControllerReceiptStore(tmp_path / "controller")
    first = lease(store, "controller-a")
    second = lease(store, "controller-b")
    with pytest.raises(StaleLeaseError):
        store.commit_work(lease=first, work=work(), status="HOLD", outcome={})
    committed = store.commit_work(
        lease=second, work=work(), status="COMPLETE", outcome={"passed": True}
    )
    assert committed["duplicate"] is False
    assert committed["receipt"]["lease_generation"] == 2


def test_semantic_duplicate_is_a_noop_and_receipt_is_create_only(tmp_path: Path) -> None:
    store = DurableControllerReceiptStore(tmp_path / "controller")
    token = lease(store)
    first = store.commit_work(
        lease=token, work=work(), status="HOLD", outcome={"reason": "bounded"}
    )
    duplicate = store.commit_work(
        lease=token, work=work(), status="COMPLETE", outcome={"reason": "changed"}
    )
    assert duplicate["duplicate"] is True
    assert duplicate["receipt"]["status"] == "HOLD"
    target = tmp_path / "controller" / "completed" / f"{first['work_key_sha256']}.json"
    assert json.loads(target.read_bytes())["outcome"] == {"reason": "bounded"}


def test_same_defect_stops_after_second_observation(tmp_path: Path) -> None:
    store = DurableControllerReceiptStore(tmp_path / "controller")
    token = lease(store)
    first = store.record_failure(
        lease=token,
        work=work(),
        defect_code="MODEL_UNAVAILABLE",
        input_sha256="5" * 64,
        repair_sha256=None,
        detail={"attempt": 1},
    )
    second = store.record_failure(
        lease=token,
        work={**work(), "candidate_id": "candidate-visible-r2"},
        defect_code="MODEL_UNAVAILABLE",
        input_sha256="5" * 64,
        repair_sha256=None,
        detail={"attempt": 2},
    )
    assert first["stop_required"] is False
    assert second["stop_required"] is True
    with pytest.raises(RepeatedDefectHold):
        store.record_failure(
            lease=token,
            work={**work(), "candidate_id": "candidate-visible-r3"},
            defect_code="MODEL_UNAVAILABLE",
            input_sha256="5" * 64,
            repair_sha256=None,
            detail={"attempt": 3},
        )
