from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

import app.governance.owner_stop as owner_stop_module
from app.governance.owner_stop import (
    OWNER_DECISION_REQUIRED,
    OwnerDecisionStore,
    require_owner_resolution,
    seal_owner_decision_request,
    seal_owner_decision_resolution,
)


def _request():
    return seal_owner_decision_request(
        decision_id="decision-rights-001",
        category="source_rights",
        scope_id="source-candidate-001",
        reason_codes=("ITEM_LICENCE_AMBIGUOUS",),
        evidence=(
            {
                "evidence_id": "research-candidate-001",
                "kind": "research_candidate",
                "sha256": "a" * 64,
                "summary_code": "LICENCE_METADATA_INCOMPLETE",
            },
        ),
        options=(
            {
                "option_id": "hold-source",
                "outcome_code": "KEEP_STAGED_ONLY",
                "recommended": True,
                "consequence_codes": ("NO_INDEX_ADMISSION",),
            },
            {
                "option_id": "approve-rights",
                "outcome_code": "OWNER_APPROVES_RIGHTS",
                "recommended": False,
                "consequence_codes": ("SOURCE_INTAKE_MAY_CONTINUE",),
            },
        ),
        blocked_actions=("source_intake", "candidate_build"),
        created_at=datetime(2026, 8, 20, 6, 0, tzinfo=UTC),
    )


def test_owner_stop_is_sealed_safe_and_requires_owner_resolution() -> None:
    request = _request()
    encoded = json.dumps(request.model_dump(mode="json", by_alias=True)).casefold()
    assert request.state == OWNER_DECISION_REQUIRED
    assert request.recommended_option_id == "hold-source"
    assert "/users/" not in encoded
    assert "question" not in encoded
    with pytest.raises(PermissionError, match=OWNER_DECISION_REQUIRED):
        require_owner_resolution(request, None)

    resolution = seal_owner_decision_resolution(
        request=request,
        selected_option_id="hold-source",
        owner_ref="owner:" + "b" * 64,
        decided_at=datetime(2026, 8, 20, 6, 5, tzinfo=UTC),
    )
    assert require_owner_resolution(request, resolution) == resolution


def test_owner_stop_rejects_unsealed_or_out_of_contract_values() -> None:
    request = _request()
    changed = request.model_dump(mode="json", by_alias=True)
    changed["blocked_actions"] = ["promotion"]
    with pytest.raises(ValueError, match="seal"):
        type(request).model_validate(changed)
    with pytest.raises(ValueError, match="outside"):
        seal_owner_decision_resolution(
            request=request,
            selected_option_id="invented-option",
            owner_ref="owner:" + "b" * 64,
            decided_at=datetime.now(UTC),
        )


def test_owner_stop_store_is_private_create_only(tmp_path: Path) -> None:
    store = OwnerDecisionStore(tmp_path / "owner-decisions")
    path = store.write_request(_request())
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        store.write_request(_request())


def test_owner_stop_store_refuses_symlink_root(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        OwnerDecisionStore(alias).write_request(_request())


def test_owner_stop_create_cannot_be_redirected_by_decision_parent_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "owner-decisions"
    outside = tmp_path / "outside-decisions"
    outside.mkdir(mode=0o700)
    request = _request()
    resolution = seal_owner_decision_resolution(
        request=request,
        selected_option_id="hold-source",
        owner_ref="owner:" + "b" * 64,
        decided_at=datetime(2026, 8, 20, 6, 5, tzinfo=UTC),
    )
    original_write = owner_stop_module.write_private_file_at
    swapped = False

    def swap_parent_then_write(
        anchor: Path, relative_parts: tuple[str, ...], payload: bytes
    ) -> None:
        nonlocal swapped
        if not swapped:
            decision_directory = root / request.decision_id
            retained = root / f"{request.decision_id}-retained"
            decision_directory.rename(retained)
            decision_directory.symlink_to(outside, target_is_directory=True)
            swapped = True
        original_write(anchor, relative_parts, payload)

    monkeypatch.setattr(owner_stop_module, "write_private_file_at", swap_parent_then_write)
    with pytest.raises(ValueError, match="symlink"):
        OwnerDecisionStore(root).write_resolution(resolution)
    assert not (outside / "resolution.json").exists()
