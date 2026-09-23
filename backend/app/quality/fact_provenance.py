"""Question facts are premises, never substitutes for legal authority."""
from ..types import StructuredClaimDraft, StructuredDraft


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


def application_binding_repair_hint(
    claim: StructuredClaimDraft, draft: StructuredDraft, question: str | None,
) -> str:
    """Describe the exact broken references without changing or approving them."""
    rules = {
        item.id: item for section in draft.sections for item in section.claims
        if item.kind == "legal_proposition" and item.material and item.evidence_ids
    }
    invalid = [identifier for identifier in claim.rule_claim_ids if identifier not in rules]
    covered = {
        evidence_id for identifier in claim.rule_claim_ids if identifier in rules
        for evidence_id in rules[identifier].evidence_ids
    }
    uncovered = sorted(set(claim.evidence_ids) - covered)
    candidates = {
        evidence_id: [identifier for identifier, rule in rules.items()
                      if evidence_id in rule.evidence_ids]
        for evidence_id in uncovered
    }
    import json

    details = {
        "invalid_rule_claim_ids": invalid,
        "uncovered_evidence_ids": uncovered,
        "existing_rule_candidates_by_evidence": candidates,
        "fact_quotes_absent_from_question": [
            quote for quote in claim.fact_quotes if not question or quote not in question
        ],
    }
    return (
        "Repair only the invalid references or unsupported premise shown here. "
        "Candidate rules share a source; this does not establish that their meaning "
        "supports the application. Select the actually relevant rule, add a concise "
        "supported rule if missing, or narrow the application and its evidence. "
        "Recheck dependency IDs after renumbering. Do not expand unrelated prose. "
        + json.dumps(details, ensure_ascii=False, sort_keys=True)
    )
