"""Deterministic structural contract for bounded, targeted answer repairs."""

from __future__ import annotations

from collections.abc import Sequence

from ..types import QualityFinding, StructuredDraft


def failed_section_scope(
    *, prior: StructuredDraft, findings: Sequence[QualityFinding]
) -> tuple[str, ...]:
    """Derive the only sections a repair may change from exact findings."""

    claim_sections = {
        claim.id: section.id for section in prior.sections for claim in section.claims
    }
    return tuple(
        sorted(
            {
                section_id
                for finding in findings
                if (
                    section_id := (finding.section_id or claim_sections.get(finding.claim_id or ""))
                )
            }
        )
    )


def verify_targeted_structured_repair(
    *,
    prior: StructuredDraft,
    repaired: StructuredDraft,
    failed_sections: Sequence[str],
    findings: Sequence[QualityFinding],
) -> None:
    """Require exact preservation outside a non-empty, finding-bound scope."""

    scope = tuple(failed_sections)
    expected_scope = failed_section_scope(prior=prior, findings=findings)
    if not scope or len(scope) != len(set(scope)) or tuple(sorted(scope)) != expected_scope:
        raise ValueError("targeted repair scope differs from prior quality findings")
    prior_sections = {section.id: section for section in prior.sections}
    repaired_sections = {section.id: section for section in repaired.sections}
    if (
        len(prior_sections) != len(prior.sections)
        or len(repaired_sections) != len(repaired.sections)
        or tuple(section.id for section in repaired.sections)
        != tuple(section.id for section in prior.sections)
        or set(prior_sections) != set(repaired_sections)
        or prior.title != repaired.title
        or prior.task_type != repaired.task_type
        or prior.jurisdiction != repaired.jurisdiction
        or prior.as_of_date != repaired.as_of_date
        or prior.limitations != repaired.limitations
    ):
        raise ValueError("targeted repair changed the whole-draft structure or context")
    changed = False
    for section_id, prior_section in prior_sections.items():
        repaired_section = repaired_sections[section_id]
        if section_id not in scope and repaired_section != prior_section:
            raise ValueError("targeted repair changed an unaffected section")
        if section_id in scope and repaired_section != prior_section:
            changed = True
    if not changed:
        raise ValueError("targeted repair did not change its authorized section scope")
