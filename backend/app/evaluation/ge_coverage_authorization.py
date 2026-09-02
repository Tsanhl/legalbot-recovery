"""Verifier-issued authority for one exact General Enquiry coverage topology.

Coverage breadth is an owner policy boundary.  A digest-shaped string or a
self-sealed topology is evidence, not authority.  This module binds the fixed
breadth floor, exact ordered cells, and stored owner request/resolution to an
opaque proof.  The trusted verifier seam deliberately fails closed until the
real owner-signature capability exists.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from ..config import Settings
from ..contracts import canonical_json_bytes, content_sha256, seal_contract
from ..governance.owner_stop import (
    OwnerDecisionRequest,
    OwnerDecisionResolution,
    require_owner_resolution,
    seal_owner_decision_request,
)
from ..governance.v111_decision_generation import read_private_owner_decision_member

GE_EXISTING_TOPIC_IDS: tuple[str, ...] = (
    "administrative-law",
    "ai-and-data-protection",
    "business-and-company-law",
    "commercial-law",
    "competition-law",
    "contemporary-biolaw-and-regulation",
    "contract-law",
    "criminal-law",
    "eu-internal-market-law",
    "international-commercial-mediation",
    "land-law",
    "law-and-medicine",
    "pensions-law",
    "private-international-law",
    "tort-law",
    "trusts-law",
    "wills-and-estates",
)
GE_PUBLIC_ACCESS_DOMAIN_IDS: tuple[str, ...] = (
    "housing",
    "employment",
    "family",
    "immigration",
    "benefits-debt",
    "consumer",
)
GE_REQUIRED_COVERAGE_DOMAIN_IDS: tuple[str, ...] = tuple(
    f"topic:{topic_id}" for topic_id in GE_EXISTING_TOPIC_IDS
) + tuple(f"public:{domain_id}" for domain_id in GE_PUBLIC_ACCESS_DOMAIN_IDS)
GE_COVERAGE_BREADTH_POLICY_ID = "ge-coverage-breadth-2026-09-01-v1"
GE_COVERAGE_APPROVE_OPTION = "approve-exact-ge-coverage-topology"
GE_COVERAGE_DECISION_PURPOSE = "exact_ge_coverage_topology"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,254}$")
_VERIFIED_GE_COVERAGE_AUTHORIZATION_TOKEN = object()


def _taxonomy_token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().casefold()).strip("-")


def _sha256(value: Any) -> str:
    return hashlib.sha256(
        (
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
    ).hexdigest()


def _require_sha256(value: Any, *, code: str) -> str:
    digest = str(value or "")
    if _SHA256_RE.fullmatch(digest) is None:
        raise ValueError(code)
    return digest


def _require_aware_timestamp(value: Any, *, code: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(str(value or ""))
    except ValueError as exc:
        raise ValueError(code) from exc
    if timestamp.tzinfo is None:
        raise ValueError(code)
    return timestamp


def ge_required_domain_set_sha256() -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "legalbot.ge-required-coverage-domain-set.v1",
                "required_domain_ids": list(GE_REQUIRED_COVERAGE_DOMAIN_IDS),
            }
        )
    ).hexdigest()


def ge_coverage_breadth_policy() -> dict[str, Any]:
    """Return the living-design breadth floor as a deterministic policy."""

    return seal_contract(
        {
            "schema": "legalbot.ge-coverage-breadth-policy.v1",
            "policy_id": GE_COVERAGE_BREADTH_POLICY_ID,
            "existing_topic_ids": list(GE_EXISTING_TOPIC_IDS),
            "separate_public_access_domain_ids": list(GE_PUBLIC_ACCESS_DOMAIN_IDS),
            "required_domain_ids": list(GE_REQUIRED_COVERAGE_DOMAIN_IDS),
            "required_domain_set_sha256": ge_required_domain_set_sha256(),
            "exactly_one_breadth_anchor_per_required_domain": True,
            "public_domains_are_not_topic_aliases": True,
            "empty_assignments_create_missing_cells": True,
            "diagnostics_join_fixed_visible_denominator": False,
            "diagnostics_unseen_eligible": False,
            "diagnostics_training_eligible": False,
        }
    )


@dataclass(frozen=True, slots=True)
class GECoverageDecisionBinding:
    manifest_id: str
    predecision_sha256: str
    proposed_at: str
    breadth_policy_id: str
    breadth_policy_sha256: str
    required_domain_set_sha256: str
    cell_manifest_sha256: str
    cell_order_sha256: str
    topology_sha256: str
    cell_count: int


class VerifiedGECoverageAuthorization:
    """Opaque proof issued only after exact stored owner-decision replay."""

    __slots__ = (
        "binding",
        "decided_at",
        "decision_id",
        "request_content_sha256",
        "resolution_content_sha256",
    )

    def __init__(
        self,
        *,
        binding: GECoverageDecisionBinding,
        decision_id: str,
        request_content_sha256: str,
        resolution_content_sha256: str,
        decided_at: datetime,
        _token: object,
    ) -> None:
        if _token is not _VERIFIED_GE_COVERAGE_AUTHORIZATION_TOKEN:
            raise TypeError("GE coverage authorization is verifier-issued only")
        self.binding = binding
        self.decision_id = decision_id
        self.request_content_sha256 = request_content_sha256
        self.resolution_content_sha256 = resolution_content_sha256
        self.decided_at = decided_at

    def __repr__(self) -> str:
        return "<VerifiedGECoverageAuthorization>"


def ge_coverage_decision_binding(
    predecision: Mapping[str, Any],
) -> GECoverageDecisionBinding:
    supplied_sha256 = _require_sha256(
        predecision.get("content_sha256"), code="ge_coverage_predecision_sha256_invalid"
    )
    if content_sha256(predecision) != supplied_sha256:
        raise ValueError("ge_coverage_predecision_seal_invalid")
    policy = ge_coverage_breadth_policy()
    required_domains = predecision.get("required_domain_ids")
    cells = predecision.get("cells")
    if (
        predecision.get("schema")
        != "legalbot.ge-coverage-topology-predecision.v1"
        or predecision.get("authorization_state") != "AWAITING_OWNER_ACCEPTANCE"
        or predecision.get("owner_decision_id") is not None
        or predecision.get("owner_request_sha256") is not None
        or predecision.get("owner_resolution_sha256") is not None
        or predecision.get("breadth_floor_satisfied") is not True
        or predecision.get("breadth_policy_id") != GE_COVERAGE_BREADTH_POLICY_ID
        or predecision.get("breadth_policy_sha256") != policy["content_sha256"]
        or required_domains != list(GE_REQUIRED_COVERAGE_DOMAIN_IDS)
        or predecision.get("required_domain_set_sha256")
        != ge_required_domain_set_sha256()
        or not isinstance(cells, list)
        or len(cells) != predecision.get("cell_count")
        or predecision.get("unseen_inspected") is not False
        or predecision.get("training_export_authorized") is not False
    ):
        raise ValueError("ge_coverage_predecision_policy_or_custody_invalid")
    manifest_id = str(predecision.get("manifest_id") or "")
    cell_count = predecision.get("cell_count")
    if (
        _SAFE_ID_RE.fullmatch(manifest_id) is None
        or not isinstance(cell_count, int)
        or isinstance(cell_count, bool)
        or cell_count < len(GE_REQUIRED_COVERAGE_DOMAIN_IDS)
    ):
        raise ValueError("ge_coverage_predecision_identity_invalid")
    seen_cell_ids: set[str] = set()
    assigned_ids: set[str] = set()
    breadth_anchors: dict[str, int] = {
        domain_id: 0 for domain_id in GE_REQUIRED_COVERAGE_DOMAIN_IDS
    }
    cell_manifest: list[dict[str, Any]] = []
    cell_order: list[dict[str, Any]] = []
    for ordinal, raw_cell in enumerate(cells, start=1):
        if not isinstance(raw_cell, Mapping):
            raise ValueError("ge_coverage_predecision_cell_invalid")
        supplied_cell_sha256 = _require_sha256(
            raw_cell.get("content_sha256"), code="ge_coverage_cell_sha256_invalid"
        )
        if (
            content_sha256(raw_cell) != supplied_cell_sha256
            or raw_cell.get("schema") != "legalbot.ge-coverage-cell.v1"
            or raw_cell.get("ordinal") != ordinal
        ):
            raise ValueError("ge_coverage_predecision_cell_seal_or_order_invalid")
        cell_id = str(raw_cell.get("coverage_cell_id") or "")
        domain_id = str(raw_cell.get("coverage_domain_id") or "")
        breadth_anchor = raw_cell.get("breadth_anchor")
        assignments = raw_cell.get("assigned_case_ids")
        if (
            _SAFE_ID_RE.fullmatch(cell_id) is None
            or cell_id in seen_cell_ids
            or domain_id not in breadth_anchors
            or type(breadth_anchor) is not bool
            or _taxonomy_token(raw_cell.get("topic")) != domain_id.split(":", 1)[1]
            or not isinstance(assignments, list)
            or any(_SAFE_ID_RE.fullmatch(str(value)) is None for value in assignments)
            or len(assignments) != len(set(str(value) for value in assignments))
        ):
            raise ValueError("ge_coverage_predecision_cell_policy_invalid")
        assignment_set = {str(value) for value in assignments}
        if assigned_ids.intersection(assignment_set):
            raise ValueError("ge_coverage_predecision_assignment_collision")
        assigned_ids.update(assignment_set)
        seen_cell_ids.add(cell_id)
        if breadth_anchor:
            breadth_anchors[domain_id] += 1
        cell_manifest.append(
            {
                "ordinal": ordinal,
                "coverage_cell_id": cell_id,
                "coverage_domain_id": domain_id,
                "breadth_anchor": breadth_anchor,
                "content_sha256": supplied_cell_sha256,
            }
        )
        cell_order.append(
            {
                "ordinal": ordinal,
                "coverage_cell_id": cell_id,
                "coverage_domain_id": domain_id,
            }
        )
    if any(count != 1 for count in breadth_anchors.values()):
        raise ValueError("ge_coverage_predecision_breadth_anchor_set_invalid")
    expected_manifest_sha256 = hashlib.sha256(
        canonical_json_bytes(cell_manifest)
    ).hexdigest()
    expected_order_sha256 = hashlib.sha256(canonical_json_bytes(cell_order)).hexdigest()
    expected_topology_sha256 = hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "legalbot.ge-coverage-topology.v1",
                "breadth_policy_sha256": policy["content_sha256"],
                "required_domain_set_sha256": ge_required_domain_set_sha256(),
                "cells": cells,
            }
        )
    ).hexdigest()
    if (
        predecision.get("cell_manifest_sha256") != expected_manifest_sha256
        or predecision.get("cell_order_sha256") != expected_order_sha256
        or predecision.get("topology_sha256") != expected_topology_sha256
    ):
        raise ValueError("ge_coverage_predecision_topology_digest_invalid")
    return GECoverageDecisionBinding(
        manifest_id=manifest_id,
        predecision_sha256=supplied_sha256,
        proposed_at=_require_aware_timestamp(
            predecision.get("proposed_at"), code="ge_coverage_predecision_time_invalid"
        ).isoformat(),
        breadth_policy_id=GE_COVERAGE_BREADTH_POLICY_ID,
        breadth_policy_sha256=_require_sha256(
            predecision.get("breadth_policy_sha256"),
            code="ge_coverage_breadth_policy_sha256_invalid",
        ),
        required_domain_set_sha256=_require_sha256(
            predecision.get("required_domain_set_sha256"),
            code="ge_coverage_domain_set_sha256_invalid",
        ),
        cell_manifest_sha256=_require_sha256(
            predecision.get("cell_manifest_sha256"),
            code="ge_coverage_cell_manifest_sha256_invalid",
        ),
        cell_order_sha256=_require_sha256(
            predecision.get("cell_order_sha256"),
            code="ge_coverage_cell_order_sha256_invalid",
        ),
        topology_sha256=_require_sha256(
            predecision.get("topology_sha256"),
            code="ge_coverage_topology_sha256_invalid",
        ),
        cell_count=cell_count,
    )


def ge_coverage_decision_id(binding: GECoverageDecisionBinding) -> str:
    identity = _sha256(
        {
            "schema": "legalbot.ge-coverage-owner-decision-identity.v1",
            "purpose": GE_COVERAGE_DECISION_PURPOSE,
            **asdict(binding),
        }
    )
    return f"ge-coverage-{identity[:24]}"


def build_ge_coverage_decision_request(
    *, binding: GECoverageDecisionBinding, created_at: datetime
) -> OwnerDecisionRequest:
    if created_at.tzinfo is None or created_at < _require_aware_timestamp(
        binding.proposed_at, code="ge_coverage_predecision_time_invalid"
    ):
        raise ValueError("ge_coverage_owner_request_predates_predecision")
    decision_id = ge_coverage_decision_id(binding)
    evidence = (
        ("coverage-predecision", "coverage_predecision", binding.predecision_sha256),
        ("coverage-policy", "coverage_policy", binding.breadth_policy_sha256),
        ("coverage-domains", "coverage_domains", binding.required_domain_set_sha256),
        ("coverage-cell-manifest", "coverage_cells", binding.cell_manifest_sha256),
        ("coverage-cell-order", "coverage_order", binding.cell_order_sha256),
        ("coverage-topology", "coverage_topology", binding.topology_sha256),
    )
    return seal_owner_decision_request(
        decision_id=decision_id,
        category="policy",
        scope_id=f"ge-coverage:{decision_id.rsplit('-', 1)[-1]}",
        reason_codes=(
            "EXACT_GE_COVERAGE_TOPOLOGY_APPROVAL_REQUIRED",
            "SIX_PUBLIC_ACCESS_DOMAINS_MUST_REMAIN_SEPARATE",
        ),
        evidence=tuple(
            {
                "evidence_id": evidence_id,
                "kind": kind,
                "sha256": digest,
                "summary_code": f"EXACT_{evidence_id.replace('-', '_').upper()}",
            }
            for evidence_id, kind, digest in evidence
        ),
        options=(
            {
                "option_id": "keep-ge-coverage-unapproved",
                "outcome_code": "KEEP_GE_COVERAGE_UNAPPROVED",
                "recommended": True,
                "consequence_codes": (
                    "NO_GE_COVERAGE_CLOSURE",
                    "NO_GE_CYCLE_CLOSURE",
                ),
            },
            {
                "option_id": GE_COVERAGE_APPROVE_OPTION,
                "outcome_code": "APPROVE_EXACT_GE_COVERAGE_TOPOLOGY",
                "recommended": False,
                "consequence_codes": (
                    "EXACT_ORDERED_TOPOLOGY_ONLY",
                    "MISSING_PUBLIC_DOMAINS_REMAIN_OPEN",
                    "NO_UNSEEN_OR_TRAINING_USE",
                ),
            },
        ),
        blocked_actions=("ge-coverage-close", "ge-cycle-close"),
        created_at=created_at,
    )


def _verify_trusted_ge_coverage_authorization_signature(
    _request: OwnerDecisionRequest,
    _resolution: OwnerDecisionResolution,
) -> None:
    raise PermissionError(
        "OWNER_DECISION_REQUIRED:trusted_ge_coverage_authorization_verifier_missing"
    )


def load_verified_ge_coverage_authorization(
    settings: Settings,
    *,
    predecision: Mapping[str, Any],
    decision_id: str,
    decision_content_sha256: str,
) -> VerifiedGECoverageAuthorization:
    supplied_resolution_sha256 = _require_sha256(
        decision_content_sha256, code="ge_coverage_decision_content_sha256_invalid"
    )
    binding = ge_coverage_decision_binding(predecision)
    if decision_id != ge_coverage_decision_id(binding):
        raise PermissionError("OWNER_DECISION_REQUIRED:ge_coverage_decision_id_mismatch")

    def read_pair() -> tuple[OwnerDecisionRequest, OwnerDecisionResolution]:
        try:
            request = OwnerDecisionRequest.model_validate_json(
                read_private_owner_decision_member(
                    settings.owner_decision_root, decision_id, "request.json"
                )
            )
            resolution = OwnerDecisionResolution.model_validate_json(
                read_private_owner_decision_member(
                    settings.owner_decision_root, decision_id, "resolution.json"
                )
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise PermissionError(
                "OWNER_DECISION_REQUIRED:ge_coverage_decision_unavailable"
            ) from exc
        return request, resolution

    request, resolution = read_pair()
    expected_request = build_ge_coverage_decision_request(
        binding=binding, created_at=request.created_at
    )
    if request != expected_request:
        raise PermissionError("OWNER_DECISION_REQUIRED:ge_coverage_request_binding_invalid")
    try:
        verified_resolution = require_owner_resolution(request, resolution)
    except PermissionError as exc:
        raise PermissionError(
            "OWNER_DECISION_REQUIRED:ge_coverage_resolution_binding_invalid"
        ) from exc
    if (
        verified_resolution.selected_option_id != GE_COVERAGE_APPROVE_OPTION
        or verified_resolution.seal_sha256 != supplied_resolution_sha256
        or verified_resolution.decided_at < request.created_at
    ):
        raise PermissionError("OWNER_DECISION_REQUIRED:ge_coverage_not_authorized")
    _verify_trusted_ge_coverage_authorization_signature(request, verified_resolution)
    final_request, final_resolution = read_pair()
    if final_request != request or final_resolution != verified_resolution:
        raise RuntimeError("GE coverage owner decision changed during verification")
    return VerifiedGECoverageAuthorization(
        binding=binding,
        decision_id=decision_id,
        request_content_sha256=request.seal_sha256,
        resolution_content_sha256=verified_resolution.seal_sha256,
        decided_at=verified_resolution.decided_at,
        _token=_VERIFIED_GE_COVERAGE_AUTHORIZATION_TOKEN,
    )


def require_verified_ge_coverage_authorization(
    authorization: VerifiedGECoverageAuthorization | None,
    *,
    predecision_sha256: str,
) -> VerifiedGECoverageAuthorization:
    if (
        not isinstance(authorization, VerifiedGECoverageAuthorization)
        or authorization.binding.predecision_sha256 != predecision_sha256
    ):
        raise PermissionError(
            "OWNER_DECISION_REQUIRED:verifier_issued_ge_coverage_proof_required"
        )
    return authorization


__all__ = [
    "GE_COVERAGE_APPROVE_OPTION",
    "GE_COVERAGE_BREADTH_POLICY_ID",
    "GE_EXISTING_TOPIC_IDS",
    "GE_PUBLIC_ACCESS_DOMAIN_IDS",
    "GE_REQUIRED_COVERAGE_DOMAIN_IDS",
    "GECoverageDecisionBinding",
    "VerifiedGECoverageAuthorization",
    "build_ge_coverage_decision_request",
    "ge_coverage_breadth_policy",
    "ge_coverage_decision_binding",
    "ge_coverage_decision_id",
    "ge_required_domain_set_sha256",
    "load_verified_ge_coverage_authorization",
    "require_verified_ge_coverage_authorization",
]
