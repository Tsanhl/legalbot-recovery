"""Digest-bound official source-version owner decision pack.

AI may recommend. The pack is not applied without the exact confirmation token.
A changed pack invalidates the previous token.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256

SOURCE_VERSION_PACK_SCHEMA = "legalbot.source-version-owner-decision-pack.v1"
CONFIRMATION_PREFIX = "CONFIRM_SOURCE_VERSION_DECISIONS:"
RecommendedDecision = Literal["APPROVE", "REJECT", "HOLD"]


def _canonical(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def pack_sha256(payload: Mapping[str, Any]) -> str:
    material = dict(payload)
    for key in (
        "pack_sha256",
        "seal_sha256",
        "confirmation_token",
        "applied_at",
        "operator_confirmed",
        "operator_decision_counts",
        "affected_row_count",
        "sources_indexed",
        "issue_gold_minted",
    ):
        material.pop(key, None)
    return hashlib.sha256(_canonical(material)).hexdigest()


def confirmation_token(pack_digest: str) -> str:
    if len(pack_digest) != 64:
        raise ValueError("source-version decision pack digest is invalid")
    return f"{CONFIRMATION_PREFIX}{pack_digest}"


def seal_source_version_decision(decision: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(decision)
    payload.setdefault("ai_review_is_not_operator_decision", True)
    payload["decision_seal"] = sealed_sha256(payload)
    assert_safe_evaluation_payload(payload)
    return payload


def build_source_version_decision_pack(
    *,
    code_sha: str,
    scan_id: str,
    catalogue_state_sha256: str,
    as_of_date: str,
    decisions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    sealed_decisions = [seal_source_version_decision(item) for item in decisions]
    payload: dict[str, Any] = {
        "schema": SOURCE_VERSION_PACK_SCHEMA,
        "code_sha": code_sha,
        "scan_id": scan_id,
        "catalogue_state_sha256": catalogue_state_sha256,
        "as_of_date": as_of_date,
        "decision_count": len(sealed_decisions),
        "decisions": sealed_decisions,
        "ai_may_recommend": True,
        "operator_decision_required": True,
        "applied": False,
        "writes_active": False,
        "writes_o04": False,
    }
    digest = pack_sha256(payload)
    payload["pack_sha256"] = digest
    payload["confirmation_token"] = confirmation_token(digest)
    payload["seal_sha256"] = sealed_sha256(
        {key: value for key, value in payload.items() if key != "decisions"}
    )
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "decisions"}
    )
    return payload


def require_source_version_pack_confirmation(
    pack: Mapping[str, Any],
    token: str | None,
) -> None:
    digest = str(pack.get("pack_sha256") or "")
    expected = confirmation_token(digest)
    if str(pack.get("schema") or "") != SOURCE_VERSION_PACK_SCHEMA:
        raise ValueError("old source-version confirmation token cannot apply a new pack")
    if not token or token != expected:
        raise ValueError("source-version decision pack confirmation token does not match")
    if pack_sha256(pack) != digest:
        raise ValueError("source-version decision pack digest does not match contents")


def apply_source_version_decision_pack(
    pack: Mapping[str, Any],
    *,
    confirmation_token_value: str | None,
    applied_at: str | None = None,
) -> dict[str, Any]:
    """Apply the exact sealed pack. HOLD/REJECT never index or mint issue gold."""

    from datetime import UTC, datetime

    require_source_version_pack_confirmation(pack, confirmation_token_value)
    counts: dict[str, int] = {"APPROVE": 0, "REJECT": 0, "HOLD": 0}
    affected: set[str] = set()
    for item in pack.get("decisions") or ():
        if not isinstance(item, Mapping):
            raise ValueError("source-version decision is not an object")
        decision = str(item.get("recommended_decision") or "")
        if decision not in {"APPROVE", "REJECT", "HOLD"}:
            raise ValueError("source-version operator decision is invalid")
        counts[decision] += 1
        affected.update(str(row_id) for row_id in (item.get("affected_row_ids") or ()))
        if decision == "APPROVE" and not str(item.get("source_version_id") or ""):
            raise ValueError("APPROVE cannot be applied without a catalogue source_version_id")
    stamp = applied_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {
        **dict(pack),
        "applied": True,
        "applied_at": stamp,
        "operator_confirmed": True,
        "operator_decision_counts": counts,
        "affected_row_count": len(affected),
        "sources_indexed": False,
        "issue_gold_minted": False,
        "writes_active": False,
        "writes_o04": False,
    }
