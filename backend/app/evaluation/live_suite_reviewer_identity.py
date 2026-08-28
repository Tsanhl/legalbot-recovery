"""Live60 reviewer identity: the owner is the one primary legal reviewer.

AI may verify mechanical accuracy of hashes and locators. It cannot occupy
the legal_reviewer role, cannot be a second legal reviewer, and cannot seal
gold. The live suite remains England-and-Wales law; the role label does not
name a jurisdiction or an expert title.
"""

from __future__ import annotations

import hashlib
import re
from datetime import date
from typing import Any

from ..types import CASE_PROPOSITION_REVIEWER_ROLES, FORBIDDEN_MACHINE_REVIEWER_ROLES

OWNER_REVIEWER_IDENTITY_SCHEMA = "legalbot.live60-owner-reviewer-identity.v1"
OWNER_REVIEWER_ROLE = "legal_reviewer"
OWNER_REVIEWER_MINT_PREFIX = "legalbot.live60-owner-reviewer"
_ROLE_TOKENS = re.compile(r"[_\s-]+")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def reviewer_role_is_forbidden_machine(role: str | None) -> bool:
    """True only for machine identities, not for roles that merely contain 'ai'."""

    if role is None:
        return False
    normalized = role.strip().casefold()
    if normalized in FORBIDDEN_MACHINE_REVIEWER_ROLES:
        return True
    return bool(set(_ROLE_TOKENS.split(normalized)) & FORBIDDEN_MACHINE_REVIEWER_ROLES)


def mint_owner_reviewer_ref(*, role: str, as_of_date: date) -> str:
    if role not in CASE_PROPOSITION_REVIEWER_ROLES:
        raise ValueError("owner reviewer role is not an allowed legal_reviewer role")
    if reviewer_role_is_forbidden_machine(role):
        raise ValueError("AI cannot be a Live60 reviewer")
    material = f"{OWNER_REVIEWER_MINT_PREFIX}|{role}|{as_of_date.isoformat()}|live-evaluation-60-v1"
    return f"reviewer:{_sha256_text(material)}"


def build_owner_reviewer_identity(*, as_of_date: date) -> dict[str, Any]:
    role = OWNER_REVIEWER_ROLE
    return {
        "schema": OWNER_REVIEWER_IDENTITY_SCHEMA,
        "suite_id": "live-evaluation-60-v1",
        "as_of_date": as_of_date.isoformat(),
        "owner_is_primary_reviewer": True,
        "approval_reviewer_role": role,
        "approval_reviewer_ref": mint_owner_reviewer_ref(role=role, as_of_date=as_of_date),
        "independent_second_review_status": "not_required",
        "independent_second_reviewer_role": None,
        "independent_second_reviewer_ref": None,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "ai_cannot_seal_gold": True,
        "ai_role_in_reviewer_enum": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "seals_expert_gold": False,
        "o04_authorised": False,
    }
