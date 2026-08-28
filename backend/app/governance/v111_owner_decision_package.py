"""Non-authorizing v1.11 owner-decision package and signature primitives.

The package is an append-only record with three deliberately narrow tranches:

* the policy tranche records the owner's Phase-2 preparation policy;
* the configuration tranche binds the exact path-free evidence identities
  required before those policy choices can be replayed; and
* the split tranche may be appended only after configuration and qualification
  and binds the deterministic 30/30 split by digest.

This module never generates a key, chooses a secret, signs a payload, writes a
decision, or turns a valid signature into runtime authority.  It only defines
canonical bytes for an external Ed25519 signer and verifies a supplied detached
signature against a caller-pinned public key.  A separate, action-specific
owner gate is still required before Development 30, promotion, O-04,
validation, or live use.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime
from itertools import pairwise
from typing import Annotated, Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .immutable_capability import ImmutableOpaqueCapability

PACKAGE_SCHEMA = "legalbot.v111-owner-decision-package.v1"
POLICY_TRANCHE_SCHEMA = "legalbot.v111-owner-policy-tranche.v1"
CONFIGURATION_EVIDENCE_BINDING_SCHEMA = "legalbot.v111-owner-configuration-evidence-binding.v1"
CONFIGURATION_TRANCHE_SCHEMA = "legalbot.v111-owner-configuration-tranche.v1"
SPLIT_TRANCHE_SCHEMA = "legalbot.v111-owner-split-tranche.v1"
SIGNATURE_SCHEMA = "legalbot.v111-owner-decision-detached-signature.v1"
SIGNATURE_STATEMENT_SCHEMA = "legalbot.v111-owner-decision-signature-statement.v1"
SIGNATURE_VERIFICATION_SCHEMA = "legalbot.v111-owner-decision-signature-verification.v1"

_SIGNATURE_DOMAIN = b"LEGALBOT-V111-OWNER-DECISION-ED25519-V1\x00"
_VERIFIED_OWNER_DECISION_EVIDENCE_REPLAY_TOKEN = object()


def _valid_utc_timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValueError("owner decision timestamp is not a real UTC instant") from exc
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("owner decision timestamp must be UTC")
    return value


def _utc_datetime(value: str) -> datetime:
    _valid_utc_timestamp(value)
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Return the only JSON encoding eligible for package hashing/signing."""

    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sealed_sha256(value: Mapping[str, Any], *, seal_field: str) -> str:
    material = dict(value)
    material.pop(seal_field, None)
    return hashlib.sha256(canonical_json(material)).hexdigest()


def review_root_set_identity_sha256(
    *,
    development_review_root_identity_sha256: str,
    sealed_validation_review_root_identity_sha256: str,
    live_review_root_identity_sha256: str,
) -> str:
    """Return the canonical path-free identity for the ordered three-lane set."""

    identities = (
        development_review_root_identity_sha256,
        sealed_validation_review_root_identity_sha256,
        live_review_root_identity_sha256,
    )
    if len(set(identities)) != 3 or any(
        re.fullmatch(r"[0-9a-f]{64}", value) is None for value in identities
    ):
        raise ValueError("configuration review-root identities are not distinct")
    return hashlib.sha256(
        canonical_json(
            {
                "schema": "legalbot.v111-phase2-review-root-set.v1",
                "identities": [
                    {"lane": lane, "sha256": identity}
                    for lane, identity in zip(
                        ("development", "sealed_validation", "live"),
                        identities,
                        strict=True,
                    )
                ],
                "owner_nonsynced_attestation_required": True,
                "authorizing": False,
            }
        )
    ).hexdigest()


class ReleaseBinding(BaseModel):
    """Exact implementation and sealed candidate identity for both tranches."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    git_commit_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    git_tree_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    candidate_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_index_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_source_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def exact_binding_is_self_sealed(self) -> ReleaseBinding:
        if len(self.git_commit_sha) != len(self.git_tree_sha):
            raise ValueError("Git commit and tree object formats differ")
        dumped = self.model_dump(mode="json")
        if self.binding_sha256 != _sealed_sha256(dumped, seal_field="binding_sha256"):
            raise ValueError("release binding seal does not match its contents")
        return self


def seal_release_binding(
    *,
    git_commit_sha: str,
    git_tree_sha: str,
    candidate_id: str,
    candidate_manifest_sha256: str,
    candidate_seal_sha256: str,
    candidate_index_tree_sha256: str,
    candidate_source_manifest_sha256: str,
) -> ReleaseBinding:
    material = {
        "git_commit_sha": git_commit_sha,
        "git_tree_sha": git_tree_sha,
        "candidate_id": candidate_id,
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "candidate_seal_sha256": candidate_seal_sha256,
        "candidate_index_tree_sha256": candidate_index_tree_sha256,
        "candidate_source_manifest_sha256": candidate_source_manifest_sha256,
    }
    material["binding_sha256"] = _sealed_sha256(material, seal_field="binding_sha256")
    return ReleaseBinding.model_validate(material)


class Phase2PolicyChoices(BaseModel):
    """Bounded vocabulary for the owner's stated Phase-2 preparation choices.

    No path, key, session secret, split seed, legal cutoff, case ID, or model
    credential belongs in this record.  Exact later artifacts are referenced by
    the split tranche or by their own signed, action-specific decisions.
    Instantiating this model does not record approval or owner authority.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    signature_mechanism: Literal["local_ed25519_pinned_public_key"]
    private_key_custody: Literal["external_to_project_never_recorded"]
    model_transport: Literal["private_unix_domain_socket"]
    maximum_memory_bytes: Literal[12_884_901_888]
    minimum_free_memory_bytes: Literal[3_221_225_472]
    legal_currentness_process: Literal["official_source_review_before_owner_cutoff_decision"]
    legal_currentness_cutoff_included: Literal[False]
    service_bind: Literal["127.0.0.1"]
    host_policy: Literal["strict_allowlist"]
    origin_policy: Literal["strict_validation"]
    csrf_policy: Literal["required"]
    session_secret_policy: Literal["local_secret_never_recorded"]
    review_root_lanes: tuple[
        Literal["development"],
        Literal["sealed_validation"],
        Literal["live"],
    ]
    review_root_policy: Literal["three_distinct_private_nonsynchronised_roots_bound_before_use"]
    certification_contract_profile: Literal["conservative_frozen_before_results"]
    split_method: Literal["deterministic_stratified_complement"]
    split_secret_policy: Literal["generated_locally_after_qualification_never_recorded"]

    @model_validator(mode="after")
    def choices_remain_non_secret_and_bounded(self) -> Phase2PolicyChoices:
        if self.review_root_lanes != (
            "development",
            "sealed_validation",
            "live",
        ):
            raise ValueError("the three review lanes must be distinct and ordered")
        if self.maximum_memory_bytes <= self.minimum_free_memory_bytes:
            raise ValueError("memory envelope is invalid")
        return self


class NonAuthorizingBoundary(BaseModel):
    """Explicitly prevents a package/signature verifier becoming a release gate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    preparation_record_only: Literal[True] = True
    development_30_authorized: Literal[False] = False
    promotion_authorized: Literal[False] = False
    o04_authorized: Literal[False] = False
    sealed_validation_authorized: Literal[False] = False
    owner_only_live_authorized: Literal[False] = False
    separate_action_specific_owner_authorization_required: Literal[True] = True


class OwnerPolicyTranche(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-owner-policy-tranche.v1"] = Field(
        default="legalbot.v111-owner-policy-tranche.v1", alias="schema"
    )
    tranche_kind: Literal["policy"] = "policy"
    package_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    sequence: Literal[1] = 1
    prior_tranche_sha256: None = None
    release_binding: ReleaseBinding
    choices: Phase2PolicyChoices
    boundary: NonAuthorizingBoundary = Field(default_factory=NonAuthorizingBoundary)
    recorded_at_utc: str = Field(
        pattern=(
            r"^(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
            r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?Z$"
        )
    )
    tranche_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    _recorded_at_is_real = field_validator("recorded_at_utc")(_valid_utc_timestamp)

    @model_validator(mode="after")
    def tranche_is_self_sealed(self) -> OwnerPolicyTranche:
        dumped = self.model_dump(mode="json", by_alias=True)
        if self.tranche_sha256 != _sealed_sha256(dumped, seal_field="tranche_sha256"):
            raise ValueError("policy tranche seal does not match its contents")
        return self


class ConfigurationEvidenceBinding(BaseModel):
    """Path-free identities of the exact Phase-2 configuration evidence.

    The UDS value is an endpoint-intent digest (for example, a canonical
    configured endpoint identity), never a transient socket inode observation.
    This record contains no path, key bytes, session secret, or capability.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-owner-configuration-evidence-binding.v1"] = Field(
        default="legalbot.v111-owner-configuration-evidence-binding.v1",
        alias="schema",
    )
    certification_contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    review_root_set_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    development_review_root_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sealed_validation_review_root_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    live_review_root_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_public_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_public_key_observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    local_owner_request_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    local_session_secret_observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    private_model_uds_endpoint_intent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def exact_configuration_is_self_sealed(self) -> ConfigurationEvidenceBinding:
        review_root_identities = {
            self.development_review_root_identity_sha256,
            self.sealed_validation_review_root_identity_sha256,
            self.live_review_root_identity_sha256,
        }
        if len(review_root_identities) != 3:
            raise ValueError("configuration review-root identities are not distinct")
        expected_root_set = review_root_set_identity_sha256(
            development_review_root_identity_sha256=(self.development_review_root_identity_sha256),
            sealed_validation_review_root_identity_sha256=(
                self.sealed_validation_review_root_identity_sha256
            ),
            live_review_root_identity_sha256=self.live_review_root_identity_sha256,
        )
        if self.review_root_set_identity_sha256 != expected_root_set:
            raise ValueError("configuration review-root set identity is inconsistent")
        dumped = self.model_dump(mode="json", by_alias=True)
        if self.binding_sha256 != _sealed_sha256(dumped, seal_field="binding_sha256"):
            raise ValueError("configuration evidence binding seal does not match its contents")
        return self


def seal_configuration_evidence_binding(
    *,
    certification_contract_sha256: str,
    development_review_root_identity_sha256: str,
    sealed_validation_review_root_identity_sha256: str,
    live_review_root_identity_sha256: str,
    owner_public_key_sha256: str,
    owner_public_key_observation_sha256: str,
    local_owner_request_policy_sha256: str,
    local_session_secret_observation_sha256: str,
    private_model_uds_endpoint_intent_sha256: str,
) -> ConfigurationEvidenceBinding:
    """Seal supplied path-free observations without creating any resource."""

    root_set_identity_sha256 = review_root_set_identity_sha256(
        development_review_root_identity_sha256=(development_review_root_identity_sha256),
        sealed_validation_review_root_identity_sha256=(
            sealed_validation_review_root_identity_sha256
        ),
        live_review_root_identity_sha256=live_review_root_identity_sha256,
    )
    material = {
        "schema": CONFIGURATION_EVIDENCE_BINDING_SCHEMA,
        "certification_contract_sha256": certification_contract_sha256,
        "review_root_set_identity_sha256": root_set_identity_sha256,
        "development_review_root_identity_sha256": (development_review_root_identity_sha256),
        "sealed_validation_review_root_identity_sha256": (
            sealed_validation_review_root_identity_sha256
        ),
        "live_review_root_identity_sha256": live_review_root_identity_sha256,
        "owner_public_key_sha256": owner_public_key_sha256,
        "owner_public_key_observation_sha256": owner_public_key_observation_sha256,
        "local_owner_request_policy_sha256": local_owner_request_policy_sha256,
        "local_session_secret_observation_sha256": (local_session_secret_observation_sha256),
        "private_model_uds_endpoint_intent_sha256": (private_model_uds_endpoint_intent_sha256),
    }
    material["binding_sha256"] = _sealed_sha256(material, seal_field="binding_sha256")
    return ConfigurationEvidenceBinding.model_validate(material)


class OwnerConfigurationTranche(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-owner-configuration-tranche.v1"] = Field(
        default="legalbot.v111-owner-configuration-tranche.v1", alias="schema"
    )
    tranche_kind: Literal["configuration"] = "configuration"
    package_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    sequence: Literal[2] = 2
    prior_tranche_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_binding: ReleaseBinding
    evidence: ConfigurationEvidenceBinding
    boundary: NonAuthorizingBoundary = Field(default_factory=NonAuthorizingBoundary)
    recorded_at_utc: str = Field(
        pattern=(
            r"^(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
            r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?Z$"
        )
    )
    tranche_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    _recorded_at_is_real = field_validator("recorded_at_utc")(_valid_utc_timestamp)

    @model_validator(mode="after")
    def tranche_is_self_sealed(self) -> OwnerConfigurationTranche:
        dumped = self.model_dump(mode="json", by_alias=True)
        if self.tranche_sha256 != _sealed_sha256(dumped, seal_field="tranche_sha256"):
            raise ValueError("configuration tranche seal does not match its contents")
        return self


class SplitEvidenceBinding(BaseModel):
    """Digest-only result of qualification and owner-controlled split freezing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    qualification_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    certification_contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_registry_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    split_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    split_algorithm_version: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    split_seed_commitment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    development_case_count: Literal[30] = 30
    sealed_validation_case_count: Literal[30] = 30
    owner_certification_case_count: Literal[60] = 60
    split_secret_included: Literal[False] = False
    validation_case_material_included: Literal[False] = False


class OwnerSplitTranche(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-owner-split-tranche.v1"] = Field(
        default="legalbot.v111-owner-split-tranche.v1", alias="schema"
    )
    tranche_kind: Literal["split"] = "split"
    package_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    sequence: Literal[3] = 3
    prior_tranche_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_binding: ReleaseBinding
    evidence: SplitEvidenceBinding
    boundary: NonAuthorizingBoundary = Field(default_factory=NonAuthorizingBoundary)
    recorded_at_utc: str = Field(
        pattern=(
            r"^(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
            r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?Z$"
        )
    )
    tranche_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    _recorded_at_is_real = field_validator("recorded_at_utc")(_valid_utc_timestamp)

    @model_validator(mode="after")
    def tranche_is_self_sealed(self) -> OwnerSplitTranche:
        dumped = self.model_dump(mode="json", by_alias=True)
        if self.tranche_sha256 != _sealed_sha256(dumped, seal_field="tranche_sha256"):
            raise ValueError("split tranche seal does not match its contents")
        return self


OwnerDecisionTranche = Annotated[
    OwnerPolicyTranche | OwnerConfigurationTranche | OwnerSplitTranche,
    Field(discriminator="tranche_kind"),
]


class OwnerDecisionPackage(BaseModel):
    """Schema-validated replay root; never a self-authorizing artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-owner-decision-package.v1"] = Field(
        default="legalbot.v111-owner-decision-package.v1", alias="schema"
    )
    package_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    tranches: tuple[OwnerDecisionTranche, ...]
    package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def package_is_an_append_only_chain(self) -> OwnerDecisionPackage:
        if len(self.tranches) not in {1, 2, 3}:
            raise ValueError(
                "owner decision package requires policy and optional configuration/split tranches"
            )
        policy = self.tranches[0]
        if not isinstance(policy, OwnerPolicyTranche):
            raise ValueError("policy tranche must be first")
        expected_id = owner_decision_package_id(policy.release_binding)
        if self.package_id != expected_id or policy.package_id != expected_id:
            raise ValueError("owner decision package ID does not match release binding")
        configuration: OwnerConfigurationTranche | None = None
        if len(self.tranches) >= 2:
            possible_configuration = self.tranches[1]
            if not isinstance(possible_configuration, OwnerConfigurationTranche):
                raise ValueError("configuration tranche must be second")
            configuration = possible_configuration
            if (
                configuration.package_id != self.package_id
                or configuration.prior_tranche_sha256 != policy.tranche_sha256
                or configuration.release_binding != policy.release_binding
            ):
                raise ValueError(
                    "configuration tranche does not append to the exact policy binding"
                )
            if _utc_datetime(configuration.recorded_at_utc) <= _utc_datetime(
                policy.recorded_at_utc
            ):
                raise ValueError("configuration tranche must be recorded after the policy tranche")
        if len(self.tranches) == 3:
            split = self.tranches[2]
            if not isinstance(split, OwnerSplitTranche) or configuration is None:
                raise ValueError("split tranche must be third and follow configuration")
            if (
                split.package_id != self.package_id
                or split.prior_tranche_sha256 != configuration.tranche_sha256
                or split.release_binding != configuration.release_binding
                or split.evidence.certification_contract_sha256
                != configuration.evidence.certification_contract_sha256
            ):
                raise ValueError("split tranche does not append to the exact configuration binding")
            if _utc_datetime(split.recorded_at_utc) <= _utc_datetime(configuration.recorded_at_utc):
                raise ValueError("split tranche must be recorded after configuration")
        dumped = self.model_dump(mode="json", by_alias=True)
        if self.package_sha256 != _sealed_sha256(dumped, seal_field="package_sha256"):
            raise ValueError("owner decision package seal does not match its contents")
        return self

    @property
    def policy_tranche(self) -> OwnerPolicyTranche:
        return self.tranches[0]  # type: ignore[return-value]

    @property
    def configuration_tranche(self) -> OwnerConfigurationTranche | None:
        if len(self.tranches) == 1:
            return None
        return self.tranches[1]  # type: ignore[return-value]

    @property
    def split_tranche(self) -> OwnerSplitTranche | None:
        if len(self.tranches) < 3:
            return None
        return self.tranches[2]  # type: ignore[return-value]


def _strict_replay_owner_decision_package(
    value: OwnerDecisionPackage,
) -> OwnerDecisionPackage:
    """Revalidate canonical bytes so ``model_copy`` cannot bypass self-seals."""

    if type(value) is not OwnerDecisionPackage:
        raise TypeError("owner decision package must be an exact validated object")
    raw = canonical_json(value.model_dump(mode="json", by_alias=True))
    replayed = OwnerDecisionPackage.model_validate_json(raw)
    if canonical_json(replayed.model_dump(mode="json", by_alias=True)) != raw:
        raise ValueError("owner decision package canonical replay differs")
    return replayed


def _strict_replay_release_binding(value: ReleaseBinding) -> ReleaseBinding:
    if type(value) is not ReleaseBinding:
        raise TypeError("release binding must be an exact validated object")
    raw = canonical_json(value.model_dump(mode="json"))
    replayed = ReleaseBinding.model_validate_json(raw)
    if canonical_json(replayed.model_dump(mode="json")) != raw:
        raise ValueError("release binding canonical replay differs")
    return replayed


def owner_decision_package_id(binding: ReleaseBinding) -> str:
    return (
        f"v111-owner-decisions-{binding.git_commit_sha[:12]}-"
        f"{binding.candidate_manifest_sha256[:12]}"
    )


def require_exact_release_binding(
    package: OwnerDecisionPackage,
    *,
    expected_release_binding: ReleaseBinding,
) -> ReleaseBinding:
    """Require an independently reconstructed exact code/tree/candidate binding."""

    package = _strict_replay_owner_decision_package(package)
    expected_release_binding = _strict_replay_release_binding(expected_release_binding)
    actual = package.policy_tranche.release_binding
    if actual != expected_release_binding:
        raise PermissionError("owner decision package release binding is stale or mismatched")
    if (
        package.configuration_tranche is not None
        and package.configuration_tranche.release_binding != actual
    ):
        raise PermissionError("owner decision configuration binding differs from policy binding")
    if package.split_tranche is not None and package.split_tranche.release_binding != actual:
        raise PermissionError("owner decision split binding differs from policy binding")
    return actual


def build_policy_package(
    *,
    release_binding: ReleaseBinding,
    choices: Phase2PolicyChoices,
    recorded_at_utc: str,
) -> OwnerDecisionPackage:
    package_id = owner_decision_package_id(release_binding)
    tranche_material: dict[str, Any] = {
        "schema": POLICY_TRANCHE_SCHEMA,
        "tranche_kind": "policy",
        "package_id": package_id,
        "sequence": 1,
        "prior_tranche_sha256": None,
        "release_binding": release_binding.model_dump(mode="json"),
        "choices": choices.model_dump(mode="json"),
        "boundary": NonAuthorizingBoundary().model_dump(mode="json"),
        "recorded_at_utc": recorded_at_utc,
    }
    tranche_material["tranche_sha256"] = _sealed_sha256(
        tranche_material, seal_field="tranche_sha256"
    )
    policy = OwnerPolicyTranche.model_validate(tranche_material)
    package_material: dict[str, Any] = {
        "schema": PACKAGE_SCHEMA,
        "package_id": package_id,
        "tranches": [policy.model_dump(mode="json", by_alias=True)],
    }
    package_material["package_sha256"] = _sealed_sha256(
        package_material, seal_field="package_sha256"
    )
    return OwnerDecisionPackage.model_validate(package_material)


def append_configuration_tranche(
    package: OwnerDecisionPackage,
    *,
    evidence: ConfigurationEvidenceBinding,
    recorded_at_utc: str,
) -> OwnerDecisionPackage:
    """Append sequence 2 without rewriting or re-sealing sequence 1."""

    package = _strict_replay_owner_decision_package(package)
    if package.configuration_tranche is not None:
        raise ValueError("configuration tranche has already been appended")
    if package.split_tranche is not None:
        raise ValueError("configuration tranche cannot follow a split tranche")
    policy = package.policy_tranche
    configuration_material: dict[str, Any] = {
        "schema": CONFIGURATION_TRANCHE_SCHEMA,
        "tranche_kind": "configuration",
        "package_id": package.package_id,
        "sequence": 2,
        "prior_tranche_sha256": policy.tranche_sha256,
        "release_binding": policy.release_binding.model_dump(mode="json"),
        "evidence": evidence.model_dump(mode="json", by_alias=True),
        "boundary": NonAuthorizingBoundary().model_dump(mode="json"),
        "recorded_at_utc": recorded_at_utc,
    }
    configuration_material["tranche_sha256"] = _sealed_sha256(
        configuration_material,
        seal_field="tranche_sha256",
    )
    configuration = OwnerConfigurationTranche.model_validate(configuration_material)
    package_material: dict[str, Any] = {
        "schema": PACKAGE_SCHEMA,
        "package_id": package.package_id,
        "tranches": [
            policy.model_dump(mode="json", by_alias=True),
            configuration.model_dump(mode="json", by_alias=True),
        ],
    }
    package_material["package_sha256"] = _sealed_sha256(
        package_material,
        seal_field="package_sha256",
    )
    appended = OwnerDecisionPackage.model_validate(package_material)
    if canonical_json(
        appended.policy_tranche.model_dump(mode="json", by_alias=True)
    ) != canonical_json(policy.model_dump(mode="json", by_alias=True)):
        raise RuntimeError("policy tranche changed during configuration append")
    return appended


def append_split_tranche(
    package: OwnerDecisionPackage,
    *,
    evidence: SplitEvidenceBinding,
    recorded_at_utc: str,
) -> OwnerDecisionPackage:
    """Append sequence 3 without rewriting or re-sealing sequences 1 and 2."""

    package = _strict_replay_owner_decision_package(package)
    if package.split_tranche is not None:
        raise ValueError("split tranche has already been appended")
    configuration = package.configuration_tranche
    if configuration is None:
        raise ValueError("configuration tranche is required before split append")
    policy = package.policy_tranche
    split_material: dict[str, Any] = {
        "schema": SPLIT_TRANCHE_SCHEMA,
        "tranche_kind": "split",
        "package_id": package.package_id,
        "sequence": 3,
        "prior_tranche_sha256": configuration.tranche_sha256,
        "release_binding": configuration.release_binding.model_dump(mode="json"),
        "evidence": evidence.model_dump(mode="json"),
        "boundary": NonAuthorizingBoundary().model_dump(mode="json"),
        "recorded_at_utc": recorded_at_utc,
    }
    split_material["tranche_sha256"] = _sealed_sha256(split_material, seal_field="tranche_sha256")
    split = OwnerSplitTranche.model_validate(split_material)
    package_material: dict[str, Any] = {
        "schema": PACKAGE_SCHEMA,
        "package_id": package.package_id,
        "tranches": [
            policy.model_dump(mode="json", by_alias=True),
            configuration.model_dump(mode="json", by_alias=True),
            split.model_dump(mode="json", by_alias=True),
        ],
    }
    package_material["package_sha256"] = _sealed_sha256(
        package_material, seal_field="package_sha256"
    )
    appended = OwnerDecisionPackage.model_validate(package_material)
    if canonical_json(
        appended.policy_tranche.model_dump(mode="json", by_alias=True)
    ) != canonical_json(policy.model_dump(mode="json", by_alias=True)):
        raise RuntimeError("policy tranche changed during append")
    appended_configuration = appended.configuration_tranche
    if appended_configuration is None or canonical_json(
        appended_configuration.model_dump(mode="json", by_alias=True)
    ) != canonical_json(configuration.model_dump(mode="json", by_alias=True)):
        raise RuntimeError("configuration tranche changed during append")
    return appended


class OwnerDecisionSignatureStatement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-owner-decision-signature-statement.v1"] = Field(
        default="legalbot.v111-owner-decision-signature-statement.v1", alias="schema"
    )
    package_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    tranche_sequence: Literal[1, 2, 3]
    tranche_kind: Literal["policy", "configuration", "split"]
    tranche_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    algorithm: Literal["ed25519"] = "ed25519"
    public_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signed_at_utc: str = Field(
        pattern=(
            r"^(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
            r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?Z$"
        )
    )

    _signed_at_is_real = field_validator("signed_at_utc")(_valid_utc_timestamp)


class VerifiedOwnerDecisionEvidenceReplay(ImmutableOpaqueCapability):
    """Opaque future proof that non-policy tranche evidence was strictly replayed."""

    __slots__ = ("_token", "package_sha256", "verified_tranche_sequences")

    def __init__(
        self,
        *,
        package_sha256: str,
        verified_tranche_sequences: tuple[Literal[1, 2, 3], ...],
        _token: object,
    ) -> None:
        if _token is not _VERIFIED_OWNER_DECISION_EVIDENCE_REPLAY_TOKEN:
            raise TypeError("trusted owner-decision evidence replay required")
        if re.fullmatch(
            r"[0-9a-f]{64}", package_sha256
        ) is None or verified_tranche_sequences not in {(1, 2), (1, 2, 3)}:
            raise ValueError("owner-decision evidence replay binding is invalid")
        self.package_sha256 = package_sha256
        self.verified_tranche_sequences = verified_tranche_sequences
        self._token = _token

    def __repr__(self) -> str:
        return "<VerifiedOwnerDecisionEvidenceReplay>"


def _require_owner_decision_evidence_replay(
    *,
    package: OwnerDecisionPackage,
    tranche_sequence: Literal[1, 2, 3],
    evidence_replay: object | None,
) -> None:
    if tranche_sequence == 1:
        return
    expected_sequences = tuple(tranche.sequence for tranche in package.tranches)
    if (
        type(evidence_replay) is not VerifiedOwnerDecisionEvidenceReplay
        or evidence_replay._token is not _VERIFIED_OWNER_DECISION_EVIDENCE_REPLAY_TOKEN
        or evidence_replay.package_sha256 != package.package_sha256
        or evidence_replay.verified_tranche_sequences != expected_sequences
        or tranche_sequence not in evidence_replay.verified_tranche_sequences
    ):
        raise PermissionError("trusted owner-decision evidence replay required")


class DetachedOwnerDecisionSignature(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-owner-decision-detached-signature.v1"] = Field(
        default="legalbot.v111-owner-decision-detached-signature.v1", alias="schema"
    )
    statement: OwnerDecisionSignatureStatement
    signature_base64: str

    @model_validator(mode="after")
    def signature_is_canonical_ed25519_bytes(self) -> DetachedOwnerDecisionSignature:
        try:
            decoded = base64.b64decode(self.signature_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("detached signature is not canonical base64") from exc
        if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != self.signature_base64:
            raise ValueError("detached signature is not a 64-byte Ed25519 signature")
        return self


def _tranche_for_sequence(
    package: OwnerDecisionPackage, sequence: int
) -> OwnerPolicyTranche | OwnerConfigurationTranche | OwnerSplitTranche:
    for tranche in package.tranches:
        if tranche.sequence == sequence:
            return tranche
    raise ValueError("requested owner decision tranche is absent")


def canonical_signature_payload(statement: OwnerDecisionSignatureStatement) -> bytes:
    """Domain-separated canonical payload for an external Ed25519 signer."""

    return _SIGNATURE_DOMAIN + canonical_json(statement.model_dump(mode="json", by_alias=True))


def raw_ed25519_public_key(public_key_bytes: bytes) -> tuple[Ed25519PublicKey, bytes]:
    """Parse raw or PEM public bytes and return the canonical 32-byte key."""

    if len(public_key_bytes) == 32:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    else:
        try:
            loaded = serialization.load_pem_public_key(public_key_bytes)
        except (TypeError, ValueError) as exc:
            raise ValueError("pinned public key is not valid Ed25519 raw/PEM data") from exc
        if not isinstance(loaded, Ed25519PublicKey):
            raise ValueError("pinned public key is not Ed25519")
        public_key = loaded
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return public_key, raw


def public_key_sha256(public_key_bytes: bytes) -> str:
    _, raw = raw_ed25519_public_key(public_key_bytes)
    return hashlib.sha256(raw).hexdigest()


def _require_configured_owner_public_key(
    package: OwnerDecisionPackage,
    *,
    key_digest_sha256: str,
) -> None:
    configuration = package.configuration_tranche
    if (
        configuration is not None
        and configuration.evidence.owner_public_key_sha256 != key_digest_sha256
    ):
        raise ValueError("pinned public key differs from configuration evidence")


def build_signature_statement(
    package: OwnerDecisionPackage,
    *,
    tranche_sequence: Literal[1, 2, 3],
    public_key_bytes: bytes,
    signed_at_utc: str,
    evidence_replay: object | None = None,
) -> OwnerDecisionSignatureStatement:
    package = _strict_replay_owner_decision_package(package)
    _require_owner_decision_evidence_replay(
        package=package,
        tranche_sequence=tranche_sequence,
        evidence_replay=evidence_replay,
    )
    tranche = _tranche_for_sequence(package, tranche_sequence)
    key_digest = public_key_sha256(public_key_bytes)
    _require_configured_owner_public_key(
        package,
        key_digest_sha256=key_digest,
    )
    return OwnerDecisionSignatureStatement(
        package_id=package.package_id,
        tranche_sequence=tranche_sequence,
        tranche_kind=tranche.tranche_kind,
        tranche_sha256=tranche.tranche_sha256,
        public_key_sha256=key_digest,
        signed_at_utc=signed_at_utc,
    )


def bind_external_signature(
    *,
    statement: OwnerDecisionSignatureStatement,
    signature: bytes,
) -> DetachedOwnerDecisionSignature:
    """Bind externally produced bytes; this function never holds a private key."""

    return DetachedOwnerDecisionSignature(
        statement=statement,
        signature_base64=base64.b64encode(signature).decode("ascii"),
    )


class OwnerDecisionSignatureVerification(BaseModel):
    """Cryptographic fact only; intentionally grants no runtime capability."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-owner-decision-signature-verification.v1"] = Field(
        default="legalbot.v111-owner-decision-signature-verification.v1",
        alias="schema",
    )
    package_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    release_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tranche_sequence: Literal[1, 2, 3]
    tranche_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature_payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    cryptographic_signature_valid: Literal[True] = True
    complete_package_coverage: Literal[False] = False
    authorizing: Literal[False] = False
    owner_authorization_inferred: Literal[False] = False
    action_specific_authorization_required: Literal[True] = True


class OwnerDecisionSignatureSetVerification(BaseModel):
    """Proof that every currently appended tranche has one valid signature."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-owner-decision-signature-set-verification.v1"] = Field(
        default="legalbot.v111-owner-decision-signature-set-verification.v1",
        alias="schema",
    )
    package_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified_tranche_sequences: tuple[Literal[1, 2, 3], ...]
    verifications: tuple[OwnerDecisionSignatureVerification, ...]
    every_appended_tranche_cryptographically_verified: Literal[True] = True
    authorizing: Literal[False] = False
    owner_authorization_inferred: Literal[False] = False
    action_specific_authorization_required: Literal[True] = True


def verify_detached_signature(
    *,
    package: OwnerDecisionPackage,
    detached_signature: DetachedOwnerDecisionSignature,
    pinned_public_key_bytes: bytes,
    expected_release_binding: ReleaseBinding,
    evidence_replay: object | None = None,
) -> OwnerDecisionSignatureVerification:
    """Verify one exact tranche without authorizing any downstream action."""

    package = _strict_replay_owner_decision_package(package)
    detached_signature = DetachedOwnerDecisionSignature.model_validate_json(
        canonical_json(detached_signature.model_dump(mode="json", by_alias=True))
    )
    release_binding = require_exact_release_binding(
        package,
        expected_release_binding=expected_release_binding,
    )
    statement = detached_signature.statement
    _require_owner_decision_evidence_replay(
        package=package,
        tranche_sequence=statement.tranche_sequence,
        evidence_replay=evidence_replay,
    )
    tranche = _tranche_for_sequence(package, statement.tranche_sequence)
    public_key, raw = raw_ed25519_public_key(pinned_public_key_bytes)
    key_digest = hashlib.sha256(raw).hexdigest()
    _require_configured_owner_public_key(
        package,
        key_digest_sha256=key_digest,
    )
    if (
        statement.package_id != package.package_id
        or statement.tranche_kind != tranche.tranche_kind
        or statement.tranche_sha256 != tranche.tranche_sha256
        or statement.public_key_sha256 != key_digest
    ):
        raise ValueError("detached signature statement does not match package and pinned key")
    if _utc_datetime(statement.signed_at_utc) < _utc_datetime(tranche.recorded_at_utc):
        raise ValueError("owner decision signature predates its tranche")
    payload = canonical_signature_payload(statement)
    signature = base64.b64decode(detached_signature.signature_base64, validate=True)
    try:
        public_key.verify(signature, payload)
    except InvalidSignature as exc:
        raise ValueError("owner decision Ed25519 signature is invalid") from exc
    return OwnerDecisionSignatureVerification(
        package_id=package.package_id,
        release_binding_sha256=release_binding.binding_sha256,
        tranche_sequence=statement.tranche_sequence,
        tranche_sha256=statement.tranche_sha256,
        public_key_sha256=key_digest,
        signature_payload_sha256=hashlib.sha256(payload).hexdigest(),
    )


def verify_complete_signature_set(
    *,
    package: OwnerDecisionPackage,
    detached_signatures: tuple[DetachedOwnerDecisionSignature, ...],
    pinned_public_key_bytes: bytes,
    expected_release_binding: ReleaseBinding,
    evidence_replay: object | None = None,
) -> OwnerDecisionSignatureSetVerification:
    """Require exactly one signature for each tranche present in the package."""

    package = _strict_replay_owner_decision_package(package)
    detached_signatures = tuple(
        DetachedOwnerDecisionSignature.model_validate_json(
            canonical_json(signature.model_dump(mode="json", by_alias=True))
        )
        for signature in detached_signatures
    )
    expected_sequences = tuple(tranche.sequence for tranche in package.tranches)
    if len(expected_sequences) > 1:
        _require_owner_decision_evidence_replay(
            package=package,
            tranche_sequence=expected_sequences[-1],
            evidence_replay=evidence_replay,
        )
    supplied_sequences = tuple(
        signature.statement.tranche_sequence for signature in detached_signatures
    )
    if supplied_sequences != expected_sequences or len(set(supplied_sequences)) != len(
        supplied_sequences
    ):
        raise ValueError("detached signature set does not exactly cover appended tranches")
    signed_times = tuple(
        _utc_datetime(signature.statement.signed_at_utc) for signature in detached_signatures
    )
    if any(later <= earlier for earlier, later in pairwise(signed_times)):
        raise ValueError("owner decision signature chronology is invalid")
    verifications = tuple(
        verify_detached_signature(
            package=package,
            detached_signature=signature,
            pinned_public_key_bytes=pinned_public_key_bytes,
            expected_release_binding=expected_release_binding,
            evidence_replay=evidence_replay,
        )
        for signature in detached_signatures
    )
    release_binding = require_exact_release_binding(
        package,
        expected_release_binding=expected_release_binding,
    )
    return OwnerDecisionSignatureSetVerification(
        package_id=package.package_id,
        package_sha256=package.package_sha256,
        release_binding_sha256=release_binding.binding_sha256,
        verified_tranche_sequences=supplied_sequences,
        verifications=verifications,
    )


__all__ = [
    "ConfigurationEvidenceBinding",
    "DetachedOwnerDecisionSignature",
    "NonAuthorizingBoundary",
    "OwnerConfigurationTranche",
    "OwnerDecisionPackage",
    "OwnerDecisionSignatureSetVerification",
    "OwnerDecisionSignatureStatement",
    "OwnerDecisionSignatureVerification",
    "OwnerPolicyTranche",
    "OwnerSplitTranche",
    "Phase2PolicyChoices",
    "ReleaseBinding",
    "SplitEvidenceBinding",
    "VerifiedOwnerDecisionEvidenceReplay",
    "append_configuration_tranche",
    "append_split_tranche",
    "bind_external_signature",
    "build_policy_package",
    "build_signature_statement",
    "canonical_json",
    "canonical_signature_payload",
    "owner_decision_package_id",
    "public_key_sha256",
    "raw_ed25519_public_key",
    "require_exact_release_binding",
    "review_root_set_identity_sha256",
    "seal_configuration_evidence_binding",
    "seal_release_binding",
    "verify_complete_signature_set",
    "verify_detached_signature",
]
