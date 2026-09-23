"""Question facts are premises, never substitutes for legal authority."""
from ..types import StructuredDraft, StructuredClaimDraft


def verified_application_quotes(
    claim: StructuredClaimDraft, draft: StructuredDraft, question: str | None,
) -> tuple[str, ...]:
    if claim.kind != "application":
        return ()
    if not question or any(quote not in question for quote in claim.fact_quotes):
        raise ValueError("application_fact_not_in_question")
    by_id = {c.id: c for section in draft.sections for c in section.claims}
    rules = [by_id.get(identifier) for identifier in claim.rule_claim_ids]
    if not rules or any(rule is None or rule.kind != "legal_proposition" or not rule.material or not rule.evidence_ids for rule in rules):
        raise ValueError("application_legal_rule_dependency_invalid")
    evidence = {identifier for rule in rules for identifier in rule.evidence_ids}
    if not claim.evidence_ids or not set(claim.evidence_ids) <= evidence:
        raise ValueError("application_evidence_outside_legal_rules")
    return tuple(claim.fact_quotes)
