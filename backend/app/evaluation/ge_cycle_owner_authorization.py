"""Verifier-issued owner authority for one exact closed GE decision basis.

Self-sealed JSON and hash-looking strings are evidence identities, not owner
authority.  This module replays a create-only private owner request/resolution,
requires an action-specific trusted signature seam, and returns an opaque proof
bound to the exact GE decision basis.  The bootstrap seam deliberately fails
closed until the trusted verifier is implemented.
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
from ..contracts import content_sha256, seal_contract
from ..governance.owner_stop import (
    OwnerDecisionRequest,
    OwnerDecisionResolution,
    require_owner_resolution,
    seal_owner_decision_request,
)
from ..governance.v111_decision_generation import read_private_owner_decision_member

GE_CYCLE_ACCEPT_OPTION = "accept-exact-closed-ge-visible-successor"
GE_CYCLE_DECISION_PURPOSE = "exact_closed_ge_visible_successor"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,254}$")
_VERIFIED_GE_CYCLE_OWNER_AUTHORIZATION_TOKEN = object()


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


@dataclass(frozen=True, slots=True)
class GECycleOwnerDecisionBinding:
    """Exact path-free GE identities covered by the owner's decision."""

    loop_id: str
    cycle_id: str
    cycle_number: int
    predecision_assessed_at: str
    decision_basis_sha256: str
    predecision_assessment_sha256: str
    candidate_sha256: str
    visible_run_sha256: str
    system_run_sha256: str
    coverage_audit_sha256: str
    diagnostic_result_manifest_sha256: str
    repair_manifest_sha256: str


class VerifiedGECycleOwnerAuthorization:
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
        binding: GECycleOwnerDecisionBinding,
        decision_id: str,
        request_content_sha256: str,
        resolution_content_sha256: str,
        decided_at: datetime,
        _token: object,
    ) -> None:
        if _token is not _VERIFIED_GE_CYCLE_OWNER_AUTHORIZATION_TOKEN:
            raise TypeError("GE cycle owner authorization is verifier-issued only")
        self.binding = binding
        self.decision_id = decision_id
        self.request_content_sha256 = request_content_sha256
        self.resolution_content_sha256 = resolution_content_sha256
        self.decided_at = decided_at

    def __repr__(self) -> str:
        return "<VerifiedGECycleOwnerAuthorization>"


def ge_cycle_owner_decision_binding(
    predecision: Mapping[str, Any],
) -> GECycleOwnerDecisionBinding:
    """Derive the exact owner gate from an otherwise closed visible assessment."""

    supplied_sha256 = _require_sha256(
        predecision.get("content_sha256"), code="ge_cycle_predecision_sha256_invalid"
    )
    if content_sha256(predecision) != supplied_sha256:
        raise ValueError("ge_cycle_predecision_seal_invalid")
    exit_checks = predecision.get("exit_checks")
    if not isinstance(exit_checks, Mapping):
        raise ValueError("ge_cycle_predecision_exit_checks_invalid")
    required_exit_checks = {
        "exact_fixed_visible_pack",
        "all_331_factual_pass",
        "all_331_meet_70_and_critical_floors",
        "all_32_system_pass",
        "all_diagnostics_pass",
        "no_open_material_diagnoses_or_gaps",
        "no_missing_coverage_areas",
        "full_changed_binding_rerun_complete",
        "unseen_unopened",
        "explicit_owner_acceptance",
    }
    if (
        predecision.get("schema") != "legalbot.ge-cycle-assessment.v2"
        or predecision.get("status") != "AWAITING_OWNER_ACCEPTANCE"
        or predecision.get("candidate_state") != "NON_ACTIVE"
        or predecision.get("promotion_authorized") is not False
        or predecision.get("owner_acceptance_sha256") is not None
        or predecision.get("unseen_opened") is not False
        or predecision.get("blockers") != []
        or set(exit_checks) != required_exit_checks
        or exit_checks.get("explicit_owner_acceptance") is not False
        or any(
            value is not True
            for key, value in exit_checks.items()
            if key != "explicit_owner_acceptance"
        )
    ):
        raise ValueError("ge_cycle_predecision_not_ready_for_owner_acceptance")
    loop_id = str(predecision.get("loop_id") or "")
    cycle_id = str(predecision.get("cycle_id") or "")
    cycle_number = predecision.get("cycle_number")
    if (
        _SAFE_ID_RE.fullmatch(loop_id) is None
        or _SAFE_ID_RE.fullmatch(cycle_id) is None
        or not isinstance(cycle_number, int)
        or isinstance(cycle_number, bool)
        or cycle_number < 1
    ):
        raise ValueError("ge_cycle_predecision_identity_invalid")
    return GECycleOwnerDecisionBinding(
        loop_id=loop_id,
        cycle_id=cycle_id,
        cycle_number=cycle_number,
        predecision_assessed_at=_require_aware_timestamp(
            predecision.get("assessed_at"), code="ge_cycle_predecision_time_invalid"
        ).isoformat(),
        decision_basis_sha256=_require_sha256(
            predecision.get("decision_basis_sha256"),
            code="ge_cycle_decision_basis_sha256_invalid",
        ),
        predecision_assessment_sha256=supplied_sha256,
        candidate_sha256=_require_sha256(
            predecision.get("candidate_sha256"), code="ge_cycle_candidate_sha256_invalid"
        ),
        visible_run_sha256=_require_sha256(
            predecision.get("visible_run_sha256"), code="ge_cycle_visible_run_sha256_invalid"
        ),
        system_run_sha256=_require_sha256(
            predecision.get("system_run_sha256"), code="ge_cycle_system_run_sha256_invalid"
        ),
        coverage_audit_sha256=_require_sha256(
            predecision.get("coverage_audit_sha256"),
            code="ge_cycle_coverage_audit_sha256_invalid",
        ),
        diagnostic_result_manifest_sha256=_require_sha256(
            predecision.get("diagnostic_result_manifest_sha256"),
            code="ge_cycle_diagnostic_manifest_sha256_invalid",
        ),
        repair_manifest_sha256=_require_sha256(
            predecision.get("repair_manifest_sha256"),
            code="ge_cycle_repair_manifest_sha256_invalid",
        ),
    )


def ge_cycle_owner_decision_id(binding: GECycleOwnerDecisionBinding) -> str:
    identity = _sha256(
        {
            "schema": "legalbot.ge-cycle-owner-decision-identity.v1",
            "purpose": GE_CYCLE_DECISION_PURPOSE,
            **asdict(binding),
        }
    )
    return f"ge-cycle-close-{identity[:24]}"


def build_ge_cycle_owner_decision_request(
    *, binding: GECycleOwnerDecisionBinding, created_at: datetime
) -> OwnerDecisionRequest:
    """Build the exact create-only request; this never grants authority."""

    if created_at.tzinfo is None or created_at < _require_aware_timestamp(
        binding.predecision_assessed_at, code="ge_cycle_predecision_time_invalid"
    ):
        raise ValueError("ge_cycle_owner_request_predates_predecision")
    decision_id = ge_cycle_owner_decision_id(binding)
    evidence_values = (
        ("ge-predecision", "ge_predecision", binding.predecision_assessment_sha256),
        ("ge-decision-basis", "ge_decision_basis", binding.decision_basis_sha256),
        ("ge-candidate", "candidate", binding.candidate_sha256),
        ("ge-visible-run", "visible_run", binding.visible_run_sha256),
        ("ge-system-run", "system_run", binding.system_run_sha256),
        ("ge-coverage-audit", "coverage_audit", binding.coverage_audit_sha256),
        (
            "ge-diagnostic-results",
            "diagnostic_results",
            binding.diagnostic_result_manifest_sha256,
        ),
        ("ge-repair-manifest", "repair_manifest", binding.repair_manifest_sha256),
    )
    return seal_owner_decision_request(
        decision_id=decision_id,
        category="policy",
        scope_id=f"ge-cycle:{decision_id.rsplit('-', 1)[-1]}",
        reason_codes=(
            "EXACT_GE_VISIBLE_SUCCESSOR_ACCEPTANCE_REQUIRED",
            "UNSEEN_MUST_REMAIN_CLOSED",
        ),
        evidence=tuple(
            {
                "evidence_id": evidence_id,
                "kind": kind,
                "sha256": digest,
                "summary_code": f"EXACT_{evidence_id.replace('-', '_').upper()}",
            }
            for evidence_id, kind, digest in evidence_values
        ),
        options=(
            {
                "option_id": "keep-ge-cycle-open",
                "outcome_code": "KEEP_GE_CYCLE_OPEN",
                "recommended": True,
                "consequence_codes": (
                    "NO_GE_CLOSURE",
                    "NO_UNSEEN_AUTHORIZATION",
                    "NO_PUBLICATION",
                ),
            },
            {
                "option_id": GE_CYCLE_ACCEPT_OPTION,
                "outcome_code": "ACCEPT_EXACT_CLOSED_GE_VISIBLE_SUCCESSOR",
                "recommended": False,
                "consequence_codes": (
                    "EXACT_DECISION_BASIS_ONLY",
                    "UNSEEN_REMAINS_CLOSED",
                    "NO_PROMOTION_OR_PUBLICATION",
                ),
            },
        ),
        blocked_actions=(
            "ge-cycle-close",
            "ge-unseen-authorization",
            "ge-publication",
        ),
        created_at=created_at,
    )


def _verify_trusted_ge_cycle_owner_authorization_signature(
    _request: OwnerDecisionRequest,
    _resolution: OwnerDecisionResolution,
) -> None:
    """Bootstrap seam: self-sealed request/resolution JSON is insufficient."""

    raise PermissionError(
        "OWNER_DECISION_REQUIRED:trusted_ge_cycle_owner_authorization_verifier_missing"
    )


def load_verified_ge_cycle_owner_authorization(
    settings: Settings,
    *,
    predecision: Mapping[str, Any],
    decision_id: str,
    decision_content_sha256: str,
) -> VerifiedGECycleOwnerAuthorization:
    """Replay one exact stored owner request/resolution and issue an opaque proof."""

    supplied_resolution_sha256 = _require_sha256(
        decision_content_sha256, code="ge_cycle_decision_content_sha256_invalid"
    )
    binding = ge_cycle_owner_decision_binding(predecision)
    if decision_id != ge_cycle_owner_decision_id(binding):
        raise PermissionError("OWNER_DECISION_REQUIRED:ge_cycle_decision_id_mismatch")

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
                "OWNER_DECISION_REQUIRED:ge_cycle_decision_unavailable"
            ) from exc
        return request, resolution

    request, resolution = read_pair()
    expected_request = build_ge_cycle_owner_decision_request(
        binding=binding, created_at=request.created_at
    )
    if request != expected_request:
        raise PermissionError("OWNER_DECISION_REQUIRED:ge_cycle_request_binding_invalid")
    try:
        verified_resolution = require_owner_resolution(request, resolution)
    except PermissionError as exc:
        raise PermissionError(
            "OWNER_DECISION_REQUIRED:ge_cycle_resolution_binding_invalid"
        ) from exc
    if (
        verified_resolution.selected_option_id != GE_CYCLE_ACCEPT_OPTION
        or verified_resolution.seal_sha256 != supplied_resolution_sha256
        or verified_resolution.decided_at < request.created_at
    ):
        raise PermissionError("OWNER_DECISION_REQUIRED:ge_cycle_not_authorized")
    _verify_trusted_ge_cycle_owner_authorization_signature(request, verified_resolution)
    final_request, final_resolution = read_pair()
    if final_request != request or final_resolution != verified_resolution:
        raise RuntimeError("GE cycle owner decision changed during verification")
    return VerifiedGECycleOwnerAuthorization(
        binding=binding,
        decision_id=decision_id,
        request_content_sha256=request.seal_sha256,
        resolution_content_sha256=verified_resolution.seal_sha256,
        decided_at=verified_resolution.decided_at,
        _token=_VERIFIED_GE_CYCLE_OWNER_AUTHORIZATION_TOKEN,
    )


def build_verified_cycle_owner_acceptance(
    authorization: VerifiedGECycleOwnerAuthorization,
) -> dict[str, Any]:
    """Project one verifier-issued proof into the persisted acceptance contract."""

    if not isinstance(authorization, VerifiedGECycleOwnerAuthorization):
        raise PermissionError("OWNER_DECISION_REQUIRED:verifier_issued_ge_cycle_proof_required")
    return seal_contract(
        {
            "schema": "legalbot.ge-cycle-owner-acceptance.v1",
            "owner_decision_id": authorization.decision_id,
            "decision": "ACCEPT",
            "decision_basis_sha256": authorization.binding.decision_basis_sha256,
            "predecision_assessment_sha256": (
                authorization.binding.predecision_assessment_sha256
            ),
            "owner_request_sha256": authorization.request_content_sha256,
            "authorization_sha256": authorization.resolution_content_sha256,
            "unseen_opened": False,
            "decided_at": authorization.decided_at.isoformat(),
        }
    )


def require_verified_cycle_owner_authorization(
    authorization: VerifiedGECycleOwnerAuthorization | None,
    *,
    decision_basis_sha256: str,
) -> VerifiedGECycleOwnerAuthorization:
    if (
        not isinstance(authorization, VerifiedGECycleOwnerAuthorization)
        or authorization.binding.decision_basis_sha256 != decision_basis_sha256
    ):
        raise PermissionError("OWNER_DECISION_REQUIRED:verifier_issued_ge_cycle_proof_required")
    return authorization


__all__ = [
    "GE_CYCLE_ACCEPT_OPTION",
    "GE_CYCLE_DECISION_PURPOSE",
    "GECycleOwnerDecisionBinding",
    "VerifiedGECycleOwnerAuthorization",
    "build_ge_cycle_owner_decision_request",
    "build_verified_cycle_owner_acceptance",
    "ge_cycle_owner_decision_binding",
    "ge_cycle_owner_decision_id",
    "load_verified_ge_cycle_owner_authorization",
    "require_verified_cycle_owner_authorization",
]
