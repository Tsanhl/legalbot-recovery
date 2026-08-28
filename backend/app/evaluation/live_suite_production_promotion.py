"""Live60 production-promotion attestation. Index benchmark pass is not ACTIVE."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from .live_suite import sealed_sha256

PRODUCTION_PROMOTION_ATTESTATION_SCHEMA = "legalbot.production-promotion-attestation.v2"


class ProductionPromotionAttestationV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.production-promotion-attestation.v2"] = Field(
        default="legalbot.production-promotion-attestation.v2", alias="schema"
    )
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    evaluation_aggregate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    answer_quality_passed: Literal[True]
    privacy_security_passed: Literal[True]
    required_readiness_passed: Literal[True]
    rollback_canary_required: bool
    operator_deployment_authorization: str = Field(pattern=r"^operator:[0-9a-f]{64}$")
    policy_version: str
    writes_active: Literal[True] = True
    legal_evidence_review_is_not_deployment: Literal[True] = True
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def attestation_is_sealed(self) -> Self:
        dumped = self.model_dump(mode="json", by_alias=True)
        if self.seal_sha256 != sealed_sha256(dumped):
            raise ValueError("production-promotion attestation seal does not match")
        return self


def live60_production_promotion_required(settings: Settings) -> bool:
    """Live60 first-live production profile requires a v2 promotion attestation."""

    return settings.live_profile == FIRST_LIVE_LOCAL_ONLY_PROFILE


def load_production_promotion_attestation(
    path: Path,
) -> ProductionPromotionAttestationV2:
    return ProductionPromotionAttestationV2.model_validate_json(path.read_bytes())


def require_live60_production_attestation(
    *,
    settings: Settings,
    build_id: str,
    attestation: ProductionPromotionAttestationV2 | Mapping[str, Any] | None,
) -> ProductionPromotionAttestationV2 | None:
    if not live60_production_promotion_required(settings):
        return None
    if attestation is None:
        raise ValueError(
            "Live60 production promotion requires a verified production-promotion attestation"
        )
    record = (
        attestation
        if isinstance(attestation, ProductionPromotionAttestationV2)
        else ProductionPromotionAttestationV2.model_validate(attestation)
    )
    if record.candidate_build_id != build_id:
        raise ValueError("promotion attestation is bound to a different candidate")
    from ..retrieval.diagnostic_slice import refuse_diagnostic_slice_for_production

    refuse_diagnostic_slice_for_production(
        record.candidate_build_id, purpose="production-promotion attestation"
    )
    return record
