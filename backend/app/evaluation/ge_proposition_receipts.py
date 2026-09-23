"""Proposition-qualification receipts. Separate from knowledge-generation v1."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.contracts.schema_registry import content_sha256

from .ge_authority_roles import authority_dependency

SCHEMA = "legalbot.proposition-qualification-receipt.v1"


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def build_proposition_receipt(
    *,
    source_version_id: str,
    official_bytes_sha256: str,
    canonical_sha256: str,
    locator: str,
    proposition_id: str,
    proposition_text: str,
    evidence_span_ids: list[str],
    evidence_span_sha256s: list[str],
    legal_role: str = "STATUTORY_RULE",
    material_date: str = "2026-08-28",
    jurisdiction: str = "England and Wales",
    title: str = "",
    ai_research_recommendation: str = "NOT_MADE",
    owner_adoption: str = "NOT_MADE",
    decision: str = "PENDING",
    locator_evaluation_approved: bool = False,
) -> dict[str, Any]:
    digest = hashlib.sha256(proposition_text.encode("utf-8")).hexdigest()
    role = authority_dependency(title)
    body: dict[str, Any] = {
        "schema": SCHEMA,
        "source_version_id": source_version_id,
        "official_bytes_sha256": official_bytes_sha256,
        "canonical_sha256": canonical_sha256,
        "locator": locator,
        "material_date": material_date,
        "jurisdiction": jurisdiction,
        "extent_verified": False,
        "commencement_verified": False,
        "transitional_position": "not_separately_recorded",
        "material_effects_reviewed": False,
        "proposition_id": proposition_id,
        "proposition_text_sha256": digest,
        "evidence_span_ids": evidence_span_ids,
        "evidence_span_sha256s": evidence_span_sha256s,
        "legal_role": legal_role,
        "later_treatment_checked_through": None,
        "contrary_authority_checked": False,
        "limiting_authority": None,
        "authority_dependency_role": role["authority_dependency_role"],
        "decision": decision,
        "ai_research_recommendation": ai_research_recommendation,
        "owner_adoption": owner_adoption,
        "qualified_legal_review": False,
        "answer_legal_gold": False,
        "training_gold": False,
        "runtime_promoted": False,
        "source_identity_verified": True,
        "source_staged": True,
        "source_runtime_admitted": False,
        "locator_evaluation_approved": locator_evaluation_approved,
        "locator_currentness_verified": False,
        "locator_extent_verified": False,
        "proposition_qualified": False,
        "decision_maker_note": (
            "AI research recommendation and owner adoption are not qualified legal review."
        ),
    }
    body["receipt_sha256"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    body["content_sha256"] = content_sha256(body)
    return body
