"""Closed, provenance-bearing ClaimSet construction for Phase 2."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from .schema_registry import ContractSchemaRegistry, canonical_json_bytes, seal_contract

ClaimKind = Literal["user_fact", "legal_rule", "application", "limitation"]
MaterialityBasis = Literal[
    "issue_element",
    "outcome_premise",
    "remedy_or_deadline",
    "scope_or_limitation",
    "non_material_explanation",
]


@dataclass(frozen=True, slots=True)
class ClaimContractInput:
    claim_id: str
    kind: ClaimKind
    encrypted_text_ref: str
    text_sha256: str
    materiality_basis: MaterialityBasis
    issue_ids: tuple[str, ...] = ()
    fact_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    depends_on_claim_ids: tuple[str, ...] = ()
    gap_codes: tuple[str, ...] = ()

    def as_contract(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "kind": self.kind,
            "encrypted_text_ref": self.encrypted_text_ref,
            "text_sha256": self.text_sha256,
            # Materiality is derived from the selected basis. Callers cannot
            # mark an outcome premise or legal rule non-material to bypass
            # evidence and factual validation.
            "material": self.materiality_basis != "non_material_explanation",
            "materiality_basis": self.materiality_basis,
            "issue_ids": list(self.issue_ids),
            "fact_ids": list(self.fact_ids),
            "evidence_ids": list(self.evidence_ids),
            "depends_on_claim_ids": list(self.depends_on_claim_ids),
            "gap_codes": list(self.gap_codes),
        }


def _require_dependency_dag(claims: tuple[ClaimContractInput, ...]) -> None:
    by_id = {claim.claim_id: claim for claim in claims}
    if len(by_id) != len(claims):
        raise ValueError("claim IDs must be unique")
    for claim in claims:
        dependencies = claim.depends_on_claim_ids
        if len(dependencies) != len(set(dependencies)):
            raise ValueError("claim dependencies must be unique")
        if claim.claim_id in dependencies:
            raise ValueError("claim cannot depend on itself")
        if any(identifier not in by_id for identifier in dependencies):
            raise ValueError("claim dependency is outside the claim set")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            raise ValueError("claim dependency graph contains a cycle")
        if identifier in visited:
            return
        visiting.add(identifier)
        for dependency in by_id[identifier].depends_on_claim_ids:
            visit(dependency)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in by_id:
        visit(identifier)


def validate_claim_support_graph(
    claim_set: Mapping[str, Any],
    *,
    issue_ids: Sequence[str] | None = None,
    evidence_ids: Sequence[str] | None = None,
    facts: Sequence[Mapping[str, Any]] | None = None,
) -> None:
    """Validate material rule/fact/application dependencies and their scope.

    The selected schema validates fields and the builder validates cycles.  This
    function closes the substantive reference relations for builders and release
    consumers, including objects loaded from persistence rather than constructed
    in the current process.
    """

    claims = list(claim_set["claims"])
    by_id = {str(claim["claim_id"]): claim for claim in claims}
    if len(by_id) != len(claims):
        raise ValueError("claim IDs must be unique")
    for claim in claims:
        dependencies = list(claim["depends_on_claim_ids"])
        if len(dependencies) != len(set(dependencies)):
            raise ValueError("claim dependencies must be unique")
        if claim["claim_id"] in dependencies:
            raise ValueError("claim cannot depend on itself")
        if any(identifier not in by_id for identifier in dependencies):
            raise ValueError("claim dependency is outside the claim set")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            raise ValueError("claim dependency graph contains a cycle")
        if identifier in visited:
            return
        visiting.add(identifier)
        for dependency in by_id[identifier]["depends_on_claim_ids"]:
            visit(dependency)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in by_id:
        visit(identifier)

    allowed_issues = set(issue_ids) if issue_ids is not None else None
    allowed_evidence = set(evidence_ids) if evidence_ids is not None else None
    fact_by_id = (
        {str(fact["fact_id"]): fact for fact in facts}
        if facts is not None
        else None
    )
    if fact_by_id is not None and len(fact_by_id) != len(facts):
        raise ValueError("fact snapshot contains duplicate fact IDs")

    for claim in claims:
        claim_issues = set(claim["issue_ids"])
        claim_evidence = set(claim["evidence_ids"])
        claim_facts = set(claim["fact_ids"])
        if claim["material"] and not claim_issues:
            raise ValueError("material claim requires at least one issue binding")
        if allowed_issues is not None and not claim_issues <= allowed_issues:
            raise ValueError("claim issue is outside the frozen query plan")
        if allowed_evidence is not None and not claim_evidence <= allowed_evidence:
            raise ValueError("claim evidence is outside the selected evidence pack")
        if fact_by_id is not None:
            if not claim_facts <= set(fact_by_id):
                raise ValueError("claim fact is outside the frozen fact snapshot")
            for fact_id in claim_facts:
                fact = fact_by_id[fact_id]
                if fact["status"] not in {"stated", "extracted", "confirmed"}:
                    raise ValueError("claim relies on an unresolved or stale fact")
                affected = set(fact["affected_issue_ids"])
                if affected and not claim_issues <= affected:
                    raise ValueError("claim fact does not support every bound issue")

        if not claim["material"]:
            continue
        dependencies = [by_id[identifier] for identifier in claim["depends_on_claim_ids"]]
        if claim["kind"] == "legal_rule" and not claim_evidence:
            raise ValueError("material legal-rule claim requires evidence")
        if claim["kind"] == "user_fact" and not claim_facts:
            raise ValueError("material user-fact claim requires fact provenance")
        if claim["kind"] == "application":
            rules = [item for item in dependencies if item["kind"] == "legal_rule"]
            user_facts = [item for item in dependencies if item["kind"] == "user_fact"]
            if not rules or not user_facts:
                raise ValueError(
                    "material application claim requires direct legal-rule and user-fact dependencies"
                )
            for issue_id in claim_issues:
                if not any(issue_id in item["issue_ids"] for item in rules):
                    raise ValueError("application issue lacks a legal-rule dependency")
                if not any(issue_id in item["issue_ids"] for item in user_facts):
                    raise ValueError("application issue lacks a user-fact dependency")
            dependency_evidence = {
                evidence_id for item in rules for evidence_id in item["evidence_ids"]
            }
            dependency_facts = {fact_id for item in user_facts for fact_id in item["fact_ids"]}
            if not claim_evidence <= dependency_evidence:
                raise ValueError("application evidence is not supplied by its legal-rule dependencies")
            if not claim_facts <= dependency_facts:
                raise ValueError("application facts are not supplied by its user-fact dependencies")
        elif claim["kind"] == "limitation" and not claim_evidence and not dependencies:
            raise ValueError("material limitation requires evidence or a supported dependency")


def build_claim_set(
    *,
    job_id: str,
    draft_id: str,
    draft_sha256: str,
    query_plan_sha256: str,
    fact_snapshot_sha256: str | None,
    evidence_pack_sha256: str,
    claims: tuple[ClaimContractInput, ...],
    created_at: datetime,
    registry: ContractSchemaRegistry,
) -> dict[str, Any]:
    """Build, seal and validate one selected ClaimSet v1."""

    if not claims:
        raise ValueError("claim set cannot be empty")
    _require_dependency_dag(claims)
    stamp = created_at
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    stamp = stamp.astimezone(UTC)
    identity_material = {
        "schema": "legalbot.claim-set-identity.v1",
        "job_id": job_id,
        "draft_id": draft_id,
        "draft_sha256": draft_sha256,
        "query_plan_sha256": query_plan_sha256,
        "fact_snapshot_sha256": fact_snapshot_sha256,
        "evidence_pack_sha256": evidence_pack_sha256,
        "claims": [claim.as_contract() for claim in claims],
        "created_at": stamp.isoformat(),
    }
    identity = hashlib.sha256(canonical_json_bytes(identity_material)).hexdigest()
    value = seal_contract(
        {
            "schema": "legalbot.claim-set.v1",
            "claim_set_id": f"claim-set-{identity[:40]}",
            "job_id": job_id,
            "draft_id": draft_id,
            "draft_sha256": draft_sha256,
            "query_plan_sha256": query_plan_sha256,
            "fact_snapshot_sha256": fact_snapshot_sha256,
            "evidence_pack_sha256": evidence_pack_sha256,
            "claims": [claim.as_contract() for claim in claims],
            "created_at": stamp.isoformat(),
        }
    )
    registry.validate_new(value)
    validate_claim_support_graph(value)
    return value


__all__ = [
    "ClaimContractInput",
    "ClaimKind",
    "MaterialityBasis",
    "build_claim_set",
    "validate_claim_support_graph",
]
