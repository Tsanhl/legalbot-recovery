from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from app.deletion_guard import (
    DeletionAuthorization,
    DeletionBlockedError,
    DeletionGuard,
    DeletionObjectClass,
)


def _authorization(*object_ids: str) -> DeletionAuthorization:
    current = datetime.now(UTC)
    return DeletionAuthorization(
        authorization_id="synthetic-exact-delete",
        owner_decision_sha256="a" * 64,
        object_class=DeletionObjectClass.ANSWER_VERSION,
        object_ids=tuple(object_ids),
        issued_at=current - timedelta(minutes=1),
        expires_at=current + timedelta(minutes=1),
    )


def test_default_denies_and_writes_path_free_create_only_attempt(tmp_path) -> None:
    audit_dir = tmp_path / "attempts"
    guard = DeletionGuard(audit_dir=audit_dir)
    with pytest.raises(DeletionBlockedError, match="owner_authorization_missing"):
        guard.require(
            object_class=DeletionObjectClass.ANSWER_VERSION,
            object_id="answer-secret-1",
            authorization=None,
        )
    paths = list(audit_dir.glob("*.json"))
    assert len(paths) == 1
    payload = json.loads(paths[0].read_text(encoding="utf-8"))
    assert payload["allowed"] is False
    assert payload["reason"] == "owner_authorization_missing"
    assert "answer-secret-1" not in paths[0].read_text(encoding="utf-8")


def test_authorization_is_exact_by_class_identity_and_time() -> None:
    guard = DeletionGuard()
    authorization = _authorization("answer-exact-1")
    guard.require(
        object_class=DeletionObjectClass.ANSWER_VERSION,
        object_id="answer-exact-1",
        authorization=authorization,
    )
    with pytest.raises(DeletionBlockedError, match="object_identity_not_authorized"):
        guard.require(
            object_class=DeletionObjectClass.ANSWER_VERSION,
            object_id="answer-other-2",
            authorization=authorization,
        )
    with pytest.raises(DeletionBlockedError, match="object_class_not_authorized"):
        guard.require(
            object_class=DeletionObjectClass.UPLOAD_BLOB,
            object_id="answer-exact-1",
            authorization=authorization,
        )
    with pytest.raises(DeletionBlockedError, match="authorization_not_current"):
        guard.require(
            object_class=DeletionObjectClass.ANSWER_VERSION,
            object_id="answer-exact-1",
            authorization=authorization,
            now=authorization.expires_at,
        )
