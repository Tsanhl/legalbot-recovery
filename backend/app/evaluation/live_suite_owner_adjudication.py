"""Digest-bound owner adjudication pack for remaining semantic HOLDs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256

ADJUDICATION_PACK_SCHEMA = "legalbot.owner-adjudication-pack.v1"
CONFIRMATION_PREFIX = "CONFIRM_OWNER_ADJUDICATION:"
AdjudicationChoice = Literal["QUALIFIED", "LIMITED", "KNOWLEDGE_GAP", "KEEP_HOLD"]


def _canonical(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def pack_sha256(payload: Mapping[str, Any]) -> str:
    material = dict(payload)
    material.pop("pack_sha256", None)
    material.pop("seal_sha256", None)
    material.pop("confirmation_token", None)
    return hashlib.sha256(_canonical(material)).hexdigest()


def confirmation_token(pack_digest: str) -> str:
    if len(pack_digest) != 64:
        raise ValueError("owner adjudication pack digest is invalid")
    return f"{CONFIRMATION_PREFIX}{pack_digest}"


def build_owner_adjudication_pack(
    *,
    code_sha: str,
    scan_id: str,
    as_of_date: str,
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": ADJUDICATION_PACK_SCHEMA,
        "code_sha": code_sha,
        "scan_id": scan_id,
        "as_of_date": as_of_date,
        "row_count": len(rows),
        "rows": [dict(row) for row in rows],
        "choices": ["QUALIFIED", "LIMITED", "KNOWLEDGE_GAP", "KEEP_HOLD"],
        "ai_must_not_recommend_qualified_without_full_support": True,
        "applied": False,
        "writes_active": False,
        "writes_o04": False,
    }
    digest = pack_sha256(payload)
    payload["pack_sha256"] = digest
    payload["confirmation_token"] = confirmation_token(digest)
    payload["seal_sha256"] = sealed_sha256(
        {key: value for key, value in payload.items() if key != "rows"}
    )
    assert_safe_evaluation_payload({key: value for key, value in payload.items() if key != "rows"})
    return payload


def require_adjudication_confirmation(pack: Mapping[str, Any], token: str | None) -> None:
    digest = str(pack.get("pack_sha256") or "")
    expected = confirmation_token(digest)
    if not token or token != expected:
        raise ValueError("owner adjudication confirmation token does not match")
    if pack_sha256(pack) != digest:
        raise ValueError("owner adjudication pack digest does not match contents")
