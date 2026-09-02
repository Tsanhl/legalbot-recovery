"""Closed, provenance-bearing ClaimSet construction for Phase 2."""

from __future__ import annotations

import hashlib
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
    return value


__all__ = [
    "ClaimContractInput",
    "ClaimKind",
    "MaterialityBasis",
    "build_claim_set",
]
