from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema.exceptions import ValidationError

from app.contracts import (
    ClaimContractInput,
    ClaimKind,
    ContractSchemaRegistry,
    MaterialityBasis,
    build_claim_set,
)


def _registry() -> ContractSchemaRegistry:
    return ContractSchemaRegistry.from_project_root(Path.cwd())


def _claim(
    claim_id: str,
    *,
    kind: ClaimKind = "legal_rule",
    basis: MaterialityBasis = "issue_element",
    facts: tuple[str, ...] = (),
    evidence: tuple[str, ...] = ("evidence-1",),
    depends: tuple[str, ...] = (),
    gaps: tuple[str, ...] = (),
) -> ClaimContractInput:
    return ClaimContractInput(
        claim_id=claim_id,
        kind=kind,
        encrypted_text_ref=f"claim-text-{claim_id}",
        text_sha256="1" * 64,
        materiality_basis=basis,
        issue_ids=("issue-1",),
        fact_ids=facts,
        evidence_ids=evidence,
        depends_on_claim_ids=depends,
        gap_codes=gaps,
    )


def _build(claims: tuple[ClaimContractInput, ...]) -> dict[str, object]:
    return build_claim_set(
        job_id="job-contract-1",
        draft_id="draft-contract-1",
        draft_sha256="2" * 64,
        query_plan_sha256="3" * 64,
        fact_snapshot_sha256="4" * 64,
        evidence_pack_sha256="5" * 64,
        claims=claims,
        created_at=datetime(2026, 9, 1, tzinfo=UTC),
        registry=_registry(),
    )


def test_materiality_is_derived_and_closed_claims_validate() -> None:
    value = _build(
        (
            _claim("claim-rule"),
            _claim(
                "claim-application",
                kind="application",
                basis="outcome_premise",
                facts=("fact-1",),
                depends=("claim-rule",),
            ),
            _claim(
                "claim-limitation",
                kind="limitation",
                basis="non_material_explanation",
                evidence=(),
                depends=("claim-application",),
                gaps=("missing.currentness",),
            ),
        )
    )

    claims = value["claims"]
    assert isinstance(claims, list)
    assert [claim["material"] for claim in claims] == [True, True, False]
    _registry().validate_new(value)


def test_application_cannot_omit_fact_provenance() -> None:
    with pytest.raises(ValidationError, match="fact_ids"):
        _build((_claim("claim-application", kind="application"),))


def test_dependencies_must_be_internal_and_acyclic() -> None:
    with pytest.raises(ValueError, match="outside"):
        _build((_claim("claim-one", depends=("claim-missing",)),))
    with pytest.raises(ValueError, match="cycle"):
        _build(
            (
                _claim("claim-one", depends=("claim-two",)),
                _claim("claim-two", depends=("claim-one",)),
            )
        )
