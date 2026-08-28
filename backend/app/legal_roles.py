"""One legal-role taxonomy shared by ingestion, gold and release checks."""

from __future__ import annotations

from enum import StrEnum


class LegalRole(StrEnum):
    STATUTORY_TEXT = "statutory_text"
    HOLDING_RATIO = "holding_ratio"
    BINDING_LEGAL_RULE = "binding_legal_rule"
    OBITER = "obiter"
    FACTS = "facts"
    SUBMISSION = "submission"
    PROCEDURAL = "procedural"
    DISSENT = "dissent"
    SECONDARY_COMMENTARY = "secondary_commentary"
    UNCLASSIFIED = "unclassified"


MATERIAL_CASE_ROLES = frozenset({LegalRole.HOLDING_RATIO.value, LegalRole.BINDING_LEGAL_RULE.value})
REVIEWED_GOLD_LEGAL_ROLES = frozenset(
    role.value for role in LegalRole if role is not LegalRole.UNCLASSIFIED
)
REPORT_LEGAL_ROLES = frozenset(role.value for role in LegalRole)
