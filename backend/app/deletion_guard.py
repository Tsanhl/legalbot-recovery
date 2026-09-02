"""Default-deny physical-deletion capability for owner-private data.

Expiry, ineligibility and quarantine are state changes. Physical deletion is a
separate capability and requires an exact, scoped, expiring owner authorization.
An environment variable, TTL, low-disk condition or test mode cannot grant it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,254}$")


class DeletionObjectClass(StrEnum):
    UPLOAD_BLOB = "upload_blob"
    CONVERSATION_SESSION = "conversation_session"
    ANSWER_VERSION = "answer_version"
    RUNTIME_RECORD = "runtime_record"
    RETRIEVAL_CACHE = "retrieval_cache"
    TEMPORARY_ARTIFACT = "temporary_artifact"
    CATALOGUE_ROW = "catalogue_row"


class DeletionBlockedError(PermissionError):
    """Physical deletion was attempted without exact owner authority."""


@dataclass(frozen=True, slots=True)
class DeletionAuthorization:
    authorization_id: str
    owner_decision_sha256: str
    object_class: DeletionObjectClass
    object_ids: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if _SAFE_ID.fullmatch(self.authorization_id) is None:
            raise ValueError("deletion authorization ID is invalid")
        if _SHA256.fullmatch(self.owner_decision_sha256) is None:
            raise ValueError("owner deletion decision digest is invalid")
        if not self.object_ids or len(set(self.object_ids)) != len(self.object_ids):
            raise ValueError("deletion authorization requires unique exact object IDs")
        if any(_SAFE_ID.fullmatch(value) is None for value in self.object_ids):
            raise ValueError("deletion authorization contains an invalid object ID")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("deletion authorization timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("deletion authorization has no positive lifetime")


class DeletionGuard:
    """Authorize an exact physical deletion and record every attempt create-only."""

    def __init__(self, *, audit_dir: Path | None = None) -> None:
        self.audit_dir = audit_dir

    def require(
        self,
        *,
        object_class: DeletionObjectClass,
        object_id: str,
        authorization: DeletionAuthorization | None,
        now: datetime | None = None,
    ) -> None:
        checked_at = now or datetime.now(UTC)
        reason = "authorized"
        allowed = True
        if authorization is None:
            allowed = False
            reason = "owner_authorization_missing"
        elif authorization.object_class != object_class:
            allowed = False
            reason = "object_class_not_authorized"
        elif object_id not in authorization.object_ids:
            allowed = False
            reason = "object_identity_not_authorized"
        elif checked_at < authorization.issued_at or checked_at >= authorization.expires_at:
            allowed = False
            reason = "authorization_not_current"
        self._record_attempt(
            object_class=object_class,
            object_id=object_id,
            authorization=authorization,
            checked_at=checked_at,
            allowed=allowed,
            reason=reason,
        )
        if not allowed:
            raise DeletionBlockedError(reason)

    def _record_attempt(
        self,
        *,
        object_class: DeletionObjectClass,
        object_id: str,
        authorization: DeletionAuthorization | None,
        checked_at: datetime,
        allowed: bool,
        reason: str,
    ) -> None:
        if self.audit_dir is None:
            return
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.audit_dir.chmod(0o700)
        identity_digest = hashlib.sha256(object_id.encode("utf-8")).hexdigest()
        record: dict[str, Any] = {
            "schema": "legalbot.deletion-attempt.v1",
            "attempt_id": f"deletion-attempt-{uuid4().hex}",
            "checked_at": checked_at.isoformat(),
            "object_class": object_class.value,
            "object_identity_sha256": identity_digest,
            "authorization_id": (
                authorization.authorization_id if authorization is not None else None
            ),
            "owner_decision_sha256": (
                authorization.owner_decision_sha256 if authorization is not None else None
            ),
            "allowed": allowed,
            "reason": reason,
        }
        payload = json.dumps(
            record,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        path = self.audit_dir / f"{record['attempt_id']}.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


__all__ = [
    "DeletionAuthorization",
    "DeletionBlockedError",
    "DeletionGuard",
    "DeletionObjectClass",
]
