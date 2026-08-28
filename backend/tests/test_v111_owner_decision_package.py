from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from scripts import v111_owner_decision_package as package_cli

from app.governance import v111_owner_decision_package as decision_module
from app.governance.v111_owner_decision_package import (
    ConfigurationEvidenceBinding,
    OwnerDecisionPackage,
    Phase2PolicyChoices,
    ReleaseBinding,
    SplitEvidenceBinding,
    VerifiedOwnerDecisionEvidenceReplay,
    append_configuration_tranche,
    append_split_tranche,
    bind_external_signature,
    build_policy_package,
    build_signature_statement,
    canonical_json,
    canonical_signature_payload,
    seal_configuration_evidence_binding,
    seal_release_binding,
    verify_complete_signature_set,
    verify_detached_signature,
)


def _binding() -> ReleaseBinding:
    return seal_release_binding(
        git_commit_sha="1" * 40,
        git_tree_sha="2" * 40,
        candidate_id="current-law-ew-full-v111-test",
        candidate_manifest_sha256="3" * 64,
        candidate_seal_sha256="4" * 64,
        candidate_index_tree_sha256="5" * 64,
        candidate_source_manifest_sha256="6" * 64,
    )


def _choices() -> Phase2PolicyChoices:
    return Phase2PolicyChoices(
        signature_mechanism="local_ed25519_pinned_public_key",
        private_key_custody="external_to_project_never_recorded",
        model_transport="private_unix_domain_socket",
        maximum_memory_bytes=12_884_901_888,
        minimum_free_memory_bytes=3_221_225_472,
        legal_currentness_process=("official_source_review_before_owner_cutoff_decision"),
        legal_currentness_cutoff_included=False,
        service_bind="127.0.0.1",
        host_policy="strict_allowlist",
        origin_policy="strict_validation",
        csrf_policy="required",
        session_secret_policy="local_secret_never_recorded",
        review_root_lanes=("development", "sealed_validation", "live"),
        review_root_policy=("three_distinct_private_nonsynchronised_roots_bound_before_use"),
        certification_contract_profile="conservative_frozen_before_results",
        split_method="deterministic_stratified_complement",
        split_secret_policy=("generated_locally_after_qualification_never_recorded"),
    )


def _policy_package() -> OwnerDecisionPackage:
    return build_policy_package(
        release_binding=_binding(),
        choices=_choices(),
        recorded_at_utc="2026-08-22T12:00:00Z",
    )


def _configuration_evidence(
    *,
    owner_public_key_sha256: str = "0" * 64,
    owner_public_key_observation_sha256: str = "1" * 64,
) -> ConfigurationEvidenceBinding:
    return seal_configuration_evidence_binding(
        certification_contract_sha256="8" * 64,
        development_review_root_identity_sha256="d" * 64,
        sealed_validation_review_root_identity_sha256="e" * 64,
        live_review_root_identity_sha256="f" * 64,
        owner_public_key_sha256=owner_public_key_sha256,
        owner_public_key_observation_sha256=owner_public_key_observation_sha256,
        local_owner_request_policy_sha256="2" * 64,
        local_session_secret_observation_sha256="3" * 64,
        private_model_uds_endpoint_intent_sha256="4" * 64,
    )


def _configured_package(
    *,
    evidence: ConfigurationEvidenceBinding | None = None,
    recorded_at_utc: str = "2026-08-22T13:00:00Z",
) -> OwnerDecisionPackage:
    return append_configuration_tranche(
        _policy_package(),
        evidence=_configuration_evidence() if evidence is None else evidence,
        recorded_at_utc=recorded_at_utc,
    )


def _split_evidence() -> SplitEvidenceBinding:
    return SplitEvidenceBinding(
        qualification_manifest_sha256="7" * 64,
        certification_contract_sha256="8" * 64,
        case_registry_sha256="9" * 64,
        split_manifest_sha256="a" * 64,
        split_algorithm_version="legalbot.deterministic-stratified-complement.v1",
        split_seed_commitment_sha256="b" * 64,
    )


def _evidence_replay(package: OwnerDecisionPackage) -> VerifiedOwnerDecisionEvidenceReplay:
    return VerifiedOwnerDecisionEvidenceReplay(
        package_sha256=package.package_sha256,
        verified_tranche_sequences=tuple(tranche.sequence for tranche in package.tranches),  # type: ignore[arg-type]
        _token=decision_module._VERIFIED_OWNER_DECISION_EVIDENCE_REPLAY_TOKEN,
    )


def test_owner_evidence_replay_capability_is_immutable() -> None:
    replay = _evidence_replay(_configured_package())
    with pytest.raises(AttributeError, match="immutable"):
        replay.package_sha256 = "0" * 64
    with pytest.raises(AttributeError, match="immutable"):
        replay.verified_tranche_sequences = (1, 2, 3)


def _reseal_package_material(material: dict[str, object]) -> None:
    seal_material = dict(material)
    seal_material.pop("package_sha256", None)
    material["package_sha256"] = hashlib.sha256(canonical_json(seal_material)).hexdigest()


def _raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_policy_package_is_exact_bound_schema_valid_and_non_authorizing() -> None:
    package = _policy_package()
    dumped = package.model_dump(mode="json", by_alias=True)

    assert dumped["schema"] == "legalbot.v111-owner-decision-package.v1"
    assert len(package.tranches) == 1
    assert package.policy_tranche.release_binding.git_commit_sha == "1" * 40
    assert package.policy_tranche.release_binding.git_tree_sha == "2" * 40
    assert package.policy_tranche.release_binding.candidate_id.endswith("v111-test")
    assert package.policy_tranche.boundary.preparation_record_only
    assert not package.policy_tranche.boundary.development_30_authorized
    assert not package.policy_tranche.boundary.promotion_authorized
    assert not package.policy_tranche.boundary.o04_authorized
    assert not package.policy_tranche.boundary.sealed_validation_authorized
    assert not package.policy_tranche.boundary.owner_only_live_authorized

    encoded = canonical_json(dumped).decode("utf-8").casefold()
    assert "/users/" not in encoded
    assert "private_key" not in encoded.replace("private_key_custody", "")
    assert 'split_seed"' not in encoded
    assert 'session_secret"' not in encoded


def test_package_rejects_content_drift_and_unknown_secret_material() -> None:
    dumped = _policy_package().model_dump(mode="json", by_alias=True)
    dumped["tranches"][0]["release_binding"]["candidate_id"] = "different-candidate"
    with pytest.raises(ValidationError, match="seal"):
        OwnerDecisionPackage.model_validate(dumped)

    choices = _choices().model_dump(mode="json")
    choices["split_seed"] = "must-never-enter-package"
    with pytest.raises(ValidationError, match="Extra inputs"):
        Phase2PolicyChoices.model_validate(choices)

    with pytest.raises(ValidationError, match="real UTC instant"):
        build_policy_package(
            release_binding=_binding(),
            choices=_choices(),
            recorded_at_utc="2026-02-31T12:00:00Z",
        )


def test_configuration_binding_rejects_drift_paths_and_non_distinct_roots() -> None:
    dumped = _configuration_evidence().model_dump(mode="json", by_alias=True)
    dumped["certification_contract_sha256"] = "7" * 64
    with pytest.raises(ValidationError, match="binding seal"):
        ConfigurationEvidenceBinding.model_validate(dumped)

    with_path = _configuration_evidence().model_dump(mode="json", by_alias=True)
    with_path["model_socket_path"] = "/private/owner/model.sock"
    with pytest.raises(ValidationError, match="Extra inputs"):
        ConfigurationEvidenceBinding.model_validate(with_path)

    with pytest.raises(ValueError, match="not distinct"):
        seal_configuration_evidence_binding(
            certification_contract_sha256="8" * 64,
            development_review_root_identity_sha256="d" * 64,
            sealed_validation_review_root_identity_sha256="d" * 64,
            live_review_root_identity_sha256="f" * 64,
            owner_public_key_sha256="0" * 64,
            owner_public_key_observation_sha256="1" * 64,
            local_owner_request_policy_sha256="2" * 64,
            local_session_secret_observation_sha256="3" * 64,
            private_model_uds_endpoint_intent_sha256="4" * 64,
        )

    inconsistent_set = _configuration_evidence().model_dump(mode="json", by_alias=True)
    inconsistent_set["review_root_set_identity_sha256"] = "c" * 64
    unsealed = dict(inconsistent_set)
    unsealed.pop("binding_sha256")
    inconsistent_set["binding_sha256"] = hashlib.sha256(canonical_json(unsealed)).hexdigest()
    with pytest.raises(ValidationError, match="root set identity is inconsistent"):
        ConfigurationEvidenceBinding.model_validate(inconsistent_set)


def test_configuration_tranche_is_path_free_self_sealed_and_append_only() -> None:
    policy_only = _policy_package()
    original_policy = canonical_json(
        policy_only.policy_tranche.model_dump(mode="json", by_alias=True)
    )
    with pytest.raises(ValueError, match="configuration tranche is required"):
        append_split_tranche(
            policy_only,
            evidence=_split_evidence(),
            recorded_at_utc="2026-08-22T14:00:00Z",
        )

    configured = append_configuration_tranche(
        policy_only,
        evidence=_configuration_evidence(),
        recorded_at_utc="2026-08-22T13:00:00Z",
    )

    assert configured.configuration_tranche is not None
    assert configured.split_tranche is None
    assert configured.configuration_tranche.sequence == 2
    assert (
        configured.configuration_tranche.prior_tranche_sha256
        == policy_only.policy_tranche.tranche_sha256
    )
    assert (
        configured.configuration_tranche.release_binding
        == policy_only.policy_tranche.release_binding
    )
    configuration_dump = configured.configuration_tranche.evidence.model_dump(
        mode="json", by_alias=True
    )
    assert configuration_dump["schema"] == "legalbot.v111-owner-configuration-evidence-binding.v1"
    assert len(configured.configuration_tranche.evidence.binding_sha256) == 64
    assert "socket_observation" not in canonical_json(configuration_dump).decode()
    assert "/users/" not in canonical_json(configuration_dump).decode().casefold()
    assert (
        canonical_json(configured.policy_tranche.model_dump(mode="json", by_alias=True))
        == original_policy
    )
    with pytest.raises(ValueError, match="configuration tranche has already been appended"):
        append_configuration_tranche(
            configured,
            evidence=_configuration_evidence(),
            recorded_at_utc="2026-08-22T14:00:00Z",
        )


def test_split_tranche_is_sequence_three_and_preserves_both_prior_tranches() -> None:
    configured = _configured_package()
    configuration = configured.configuration_tranche
    assert configuration is not None
    original_policy = canonical_json(
        configured.policy_tranche.model_dump(mode="json", by_alias=True)
    )
    original_configuration = canonical_json(configuration.model_dump(mode="json", by_alias=True))
    appended = append_split_tranche(
        configured,
        evidence=_split_evidence(),
        recorded_at_utc="2026-08-22T14:00:00Z",
    )
    assert appended.split_tranche is not None
    assert appended.split_tranche.sequence == 3
    assert appended.split_tranche.prior_tranche_sha256 == configuration.tranche_sha256
    assert appended.split_tranche.release_binding == configuration.release_binding
    assert (
        appended.split_tranche.evidence.certification_contract_sha256
        == configuration.evidence.certification_contract_sha256
    )
    assert not appended.split_tranche.evidence.split_secret_included
    assert not appended.split_tranche.evidence.validation_case_material_included
    assert (
        canonical_json(appended.policy_tranche.model_dump(mode="json", by_alias=True))
        == original_policy
    )
    appended_configuration = appended.configuration_tranche
    assert appended_configuration is not None
    assert (
        canonical_json(appended_configuration.model_dump(mode="json", by_alias=True))
        == original_configuration
    )
    with pytest.raises(ValueError, match="split tranche has already been appended"):
        append_split_tranche(
            appended,
            evidence=_split_evidence(),
            recorded_at_utc="2026-08-22T15:00:00Z",
        )


def test_package_rejects_configuration_forks_missing_tranches_and_contract_drift() -> None:
    policy = _policy_package()
    configuration_a = append_configuration_tranche(
        policy,
        evidence=_configuration_evidence(owner_public_key_observation_sha256="1" * 64),
        recorded_at_utc="2026-08-22T13:00:00Z",
    )
    configuration_b = append_configuration_tranche(
        policy,
        evidence=_configuration_evidence(owner_public_key_observation_sha256="5" * 64),
        recorded_at_utc="2026-08-22T13:00:00Z",
    )
    full_b = append_split_tranche(
        configuration_b,
        evidence=_split_evidence(),
        recorded_at_utc="2026-08-22T14:00:00Z",
    )

    fork_material = json.loads(
        canonical_json(configuration_a.model_dump(mode="json", by_alias=True))
    )
    full_b_material = full_b.model_dump(mode="json", by_alias=True)
    fork_material["tranches"].append(full_b_material["tranches"][2])
    _reseal_package_material(fork_material)
    with pytest.raises(ValidationError, match="exact configuration binding"):
        OwnerDecisionPackage.model_validate(fork_material)

    missing_configuration = json.loads(canonical_json(full_b_material))
    missing_configuration["tranches"] = [
        missing_configuration["tranches"][0],
        missing_configuration["tranches"][2],
    ]
    _reseal_package_material(missing_configuration)
    with pytest.raises(ValidationError, match="configuration tranche must be second"):
        OwnerDecisionPackage.model_validate(missing_configuration)

    mismatched_contract = _split_evidence().model_copy(
        update={"certification_contract_sha256": "7" * 64}
    )
    with pytest.raises(ValidationError, match="exact configuration binding"):
        append_split_tranche(
            configuration_a,
            evidence=mismatched_contract,
            recorded_at_utc="2026-08-22T14:00:00Z",
        )


def test_canonical_ed25519_verification_is_exact_and_grants_no_authority() -> None:
    package = _policy_package()
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))
    public_key = _raw_public_key(private_key)
    statement = build_signature_statement(
        package,
        tranche_sequence=1,
        public_key_bytes=public_key,
        signed_at_utc="2026-08-22T12:15:00Z",
    )
    payload = canonical_signature_payload(statement)
    detached = bind_external_signature(
        statement=statement,
        signature=private_key.sign(payload),
    )

    verified = verify_detached_signature(
        package=package,
        detached_signature=detached,
        pinned_public_key_bytes=public_key,
        expected_release_binding=package.policy_tranche.release_binding,
    )
    assert verified.cryptographic_signature_valid
    assert not verified.complete_package_coverage
    assert not verified.authorizing
    assert not verified.owner_authorization_inferred
    assert verified.action_specific_authorization_required

    other_public_key = _raw_public_key(
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex("22" * 32))
    )
    with pytest.raises(ValueError, match="pinned key"):
        verify_detached_signature(
            package=package,
            detached_signature=detached,
            pinned_public_key_bytes=other_public_key,
            expected_release_binding=package.policy_tranche.release_binding,
        )


def test_configuration_must_bind_the_actual_signature_verification_key() -> None:
    policy = _policy_package()
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("23" * 32))
    public_key = _raw_public_key(private_key)
    statement = build_signature_statement(
        policy,
        tranche_sequence=1,
        public_key_bytes=public_key,
        signed_at_utc="2026-08-22T12:15:00Z",
    )
    detached = bind_external_signature(
        statement=statement,
        signature=private_key.sign(canonical_signature_payload(statement)),
    )
    configured = append_configuration_tranche(
        policy,
        evidence=_configuration_evidence(owner_public_key_sha256="0" * 64),
        recorded_at_utc="2026-08-22T13:00:00Z",
    )
    evidence_replay = _evidence_replay(configured)

    with pytest.raises(ValueError, match="differs from configuration evidence"):
        verify_detached_signature(
            package=configured,
            detached_signature=detached,
            pinned_public_key_bytes=public_key,
            expected_release_binding=configured.policy_tranche.release_binding,
        )
    with pytest.raises(ValueError, match="differs from configuration evidence"):
        build_signature_statement(
            configured,
            tranche_sequence=2,
            public_key_bytes=public_key,
            signed_at_utc="2026-08-22T13:15:00Z",
            evidence_replay=evidence_replay,
        )


def test_signature_boundary_revalidates_model_copy_and_all_self_seals() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("24" * 32))
    public_key = _raw_public_key(private_key)
    configured = _configured_package(
        evidence=_configuration_evidence(
            owner_public_key_sha256=hashlib.sha256(public_key).hexdigest()
        )
    )
    configuration = configured.configuration_tranche
    assert configuration is not None
    replay = _evidence_replay(configured)
    forged_evidence = configuration.evidence.model_copy(
        update={"local_owner_request_policy_sha256": "f" * 64}
    )
    forged_configuration = configuration.model_copy(update={"evidence": forged_evidence})
    forged_package = configured.model_copy(
        update={"tranches": (configured.policy_tranche, forged_configuration)}
    )

    with pytest.raises(ValidationError, match="seal"):
        build_signature_statement(
            forged_package,
            tranche_sequence=2,
            public_key_bytes=public_key,
            signed_at_utc="2026-08-22T13:15:00Z",
            evidence_replay=replay,
        )


def test_signature_cannot_be_replayed_to_appended_or_changed_tranche() -> None:
    policy_only = _policy_package()
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("33" * 32))
    public_key = _raw_public_key(private_key)
    statement = build_signature_statement(
        policy_only,
        tranche_sequence=1,
        public_key_bytes=public_key,
        signed_at_utc="2026-08-22T12:15:00Z",
    )
    detached = bind_external_signature(
        statement=statement,
        signature=private_key.sign(canonical_signature_payload(statement)),
    )
    configured = append_configuration_tranche(
        policy_only,
        evidence=_configuration_evidence(
            owner_public_key_sha256=hashlib.sha256(public_key).hexdigest()
        ),
        recorded_at_utc="2026-08-22T13:00:00Z",
    )
    appended = append_split_tranche(
        configured,
        evidence=_split_evidence(),
        recorded_at_utc="2026-08-22T14:00:00Z",
    )
    evidence_replay = _evidence_replay(appended)

    # The independent policy signature remains valid after a byte-identical append.
    assert verify_detached_signature(
        package=appended,
        detached_signature=detached,
        pinned_public_key_bytes=public_key,
        expected_release_binding=appended.policy_tranche.release_binding,
    ).cryptographic_signature_valid
    with pytest.raises(ValueError, match="exactly cover"):
        verify_complete_signature_set(
            package=appended,
            detached_signatures=(detached,),
            pinned_public_key_bytes=public_key,
            expected_release_binding=appended.policy_tranche.release_binding,
            evidence_replay=evidence_replay,
        )

    with pytest.raises(PermissionError, match="trusted owner-decision evidence replay"):
        build_signature_statement(
            appended,
            tranche_sequence=2,
            public_key_bytes=public_key,
            signed_at_utc="2026-08-22T13:15:00Z",
        )
    configuration_statement = build_signature_statement(
        appended,
        tranche_sequence=2,
        public_key_bytes=public_key,
        signed_at_utc="2026-08-22T13:15:00Z",
        evidence_replay=evidence_replay,
    )
    configuration_signature = bind_external_signature(
        statement=configuration_statement,
        signature=private_key.sign(canonical_signature_payload(configuration_statement)),
    )
    split_statement = build_signature_statement(
        appended,
        tranche_sequence=3,
        public_key_bytes=public_key,
        signed_at_utc="2026-08-22T14:15:00Z",
        evidence_replay=evidence_replay,
    )
    split_signature = bind_external_signature(
        statement=split_statement,
        signature=private_key.sign(canonical_signature_payload(split_statement)),
    )
    signature_set = verify_complete_signature_set(
        package=appended,
        detached_signatures=(detached, configuration_signature, split_signature),
        pinned_public_key_bytes=public_key,
        expected_release_binding=appended.policy_tranche.release_binding,
        evidence_replay=evidence_replay,
    )
    assert signature_set.verified_tranche_sequences == (1, 2, 3)
    assert signature_set.every_appended_tranche_cryptographically_verified
    assert signature_set.authorizing is False
    assert not signature_set.owner_authorization_inferred

    replay = bind_external_signature(
        statement=split_statement,
        signature=private_key.sign(canonical_signature_payload(statement)),
    )
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_detached_signature(
            package=appended,
            detached_signature=replay,
            pinned_public_key_bytes=public_key,
            expected_release_binding=appended.policy_tranche.release_binding,
            evidence_replay=evidence_replay,
        )


def test_verifier_requires_independently_reconstructed_exact_release_binding() -> None:
    package = _policy_package()
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("44" * 32))
    public_key = _raw_public_key(private_key)
    statement = build_signature_statement(
        package,
        tranche_sequence=1,
        public_key_bytes=public_key,
        signed_at_utc="2026-08-22T12:15:00Z",
    )
    detached = bind_external_signature(
        statement=statement,
        signature=private_key.sign(canonical_signature_payload(statement)),
    )
    stale_binding = seal_release_binding(
        git_commit_sha="f" * 40,
        git_tree_sha="2" * 40,
        candidate_id="current-law-ew-full-v111-test",
        candidate_manifest_sha256="3" * 64,
        candidate_seal_sha256="4" * 64,
        candidate_index_tree_sha256="5" * 64,
        candidate_source_manifest_sha256="6" * 64,
    )

    with pytest.raises(PermissionError, match="stale or mismatched"):
        verify_detached_signature(
            package=package,
            detached_signature=detached,
            pinned_public_key_bytes=public_key,
            expected_release_binding=stale_binding,
        )


def test_tranche_and_signature_chronology_is_strict() -> None:
    package = _policy_package()
    with pytest.raises(ValueError, match="configuration tranche must be recorded after"):
        append_configuration_tranche(
            package,
            evidence=_configuration_evidence(),
            recorded_at_utc="2026-08-22T11:59:59Z",
        )

    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("66" * 32))
    public_key = _raw_public_key(private_key)
    configured = _configured_package(
        evidence=_configuration_evidence(
            owner_public_key_sha256=hashlib.sha256(public_key).hexdigest()
        )
    )
    with pytest.raises(ValueError, match="split tranche must be recorded after"):
        append_split_tranche(
            configured,
            evidence=_split_evidence(),
            recorded_at_utc="2026-08-22T13:00:00Z",
        )

    statement = build_signature_statement(
        package,
        tranche_sequence=1,
        public_key_bytes=public_key,
        signed_at_utc="2026-08-22T11:59:59Z",
    )
    detached = bind_external_signature(
        statement=statement,
        signature=private_key.sign(canonical_signature_payload(statement)),
    )
    with pytest.raises(ValueError, match="predates"):
        verify_detached_signature(
            package=package,
            detached_signature=detached,
            pinned_public_key_bytes=public_key,
            expected_release_binding=package.policy_tranche.release_binding,
        )

    fully_appended = append_split_tranche(
        configured,
        evidence=_split_evidence(),
        recorded_at_utc="2026-08-22T14:00:00Z",
    )
    evidence_replay = _evidence_replay(fully_appended)
    nonchronological_signatures = []
    for sequence, signed_at in (
        (1, "2026-08-22T15:00:00Z"),
        (2, "2026-08-22T14:00:00Z"),
        (3, "2026-08-22T15:30:00Z"),
    ):
        signed_statement = build_signature_statement(
            fully_appended,
            tranche_sequence=sequence,  # type: ignore[arg-type]
            public_key_bytes=public_key,
            signed_at_utc=signed_at,
            evidence_replay=evidence_replay,
        )
        nonchronological_signatures.append(
            bind_external_signature(
                statement=signed_statement,
                signature=private_key.sign(canonical_signature_payload(signed_statement)),
            )
        )
    with pytest.raises(ValueError, match="signature chronology"):
        verify_complete_signature_set(
            package=fully_appended,
            detached_signatures=tuple(nonchronological_signatures),
            pinned_public_key_bytes=public_key,
            expected_release_binding=fully_appended.policy_tranche.release_binding,
            evidence_replay=evidence_replay,
        )


def test_cli_is_read_only_and_signing_payload_requires_later_owner_invocation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    package_cli.main(["status"])
    status = json.loads(capsys.readouterr().out)
    assert status["state"] == "OWNER_INVOCATION_REQUIRED"
    assert not status["key_generation_supported"]
    assert not status["signature_creation_supported"]
    assert not status["development_30_authorized"]

    package_path = tmp_path / "package.json"
    package_path.write_bytes(
        canonical_json(_policy_package().model_dump(mode="json", by_alias=True))
    )
    with pytest.raises(SystemExit, match="OWNER_INVOCATION_REQUIRED"):
        package_cli.main(
            [
                "signing-payload",
                "--package",
                str(package_path),
                "--tranche-sequence",
                "1",
                "--signed-at-utc",
                "2026-08-22T12:15:00Z",
                "--owner-invocation",
                "NOT-AUTHORIZED",
            ]
        )
    configured_path = tmp_path / "configured-package.json"
    configured_path.write_bytes(
        canonical_json(_configured_package().model_dump(mode="json", by_alias=True))
    )
    with pytest.raises(
        SystemExit,
        match="TRUSTED_CONFIGURATION_OR_SPLIT_EVIDENCE_REPLAY_REQUIRED",
    ):
        package_cli.main(
            [
                "signing-payload",
                "--package",
                str(configured_path),
                "--tranche-sequence",
                "2",
                "--signed-at-utc",
                "2026-08-22T13:15:00Z",
                "--owner-invocation",
                package_cli.OWNER_INVOCATION_PHRASE,
            ]
        )
    with pytest.raises(
        SystemExit,
        match="TRUSTED_CONFIGURATION_OR_SPLIT_EVIDENCE_REPLAY_REQUIRED",
    ):
        package_cli.main(
            [
                "verify-signature-set",
                "--package",
                str(configured_path),
                "--signature",
                str(package_path),
            ]
        )
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "configured-package.json",
        "package.json",
    ]


def test_cli_signature_verification_reconstructs_release_binding_and_uses_pinned_key(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = _policy_package()
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("55" * 32))
    public_key = _raw_public_key(private_key)
    statement = build_signature_statement(
        package,
        tranche_sequence=1,
        public_key_bytes=public_key,
        signed_at_utc="2026-08-22T12:15:00Z",
    )
    signature = bind_external_signature(
        statement=statement,
        signature=private_key.sign(canonical_signature_payload(statement)),
    )
    package_path = tmp_path / "package.json"
    signature_path = tmp_path / "signature.json"
    public_key_path = tmp_path / "owner.pub"
    package_path.write_bytes(canonical_json(package.model_dump(mode="json", by_alias=True)))
    signature_path.write_bytes(canonical_json(signature.model_dump(mode="json", by_alias=True)))
    public_key_path.write_bytes(public_key)
    public_key_path.chmod(0o600)
    tmp_path.chmod(0o700)
    monkeypatch.setenv("LEGALBOT_OWNER_PUBLIC_KEY_PATH", str(public_key_path))
    monkeypatch.setattr(package_cli, "_reconstruct_release_binding", lambda _package: _binding())

    package_cli.main(
        [
            "verify-signature-set",
            "--package",
            str(package_path),
            "--signature",
            str(signature_path),
        ]
    )
    verified = json.loads(capsys.readouterr().out)
    assert verified["every_appended_tranche_cryptographically_verified"]
    assert not verified["owner_authorization_inferred"]

    stale = seal_release_binding(
        git_commit_sha="f" * 40,
        git_tree_sha="2" * 40,
        candidate_id="current-law-ew-full-v111-test",
        candidate_manifest_sha256="3" * 64,
        candidate_seal_sha256="4" * 64,
        candidate_index_tree_sha256="5" * 64,
        candidate_source_manifest_sha256="6" * 64,
    )
    monkeypatch.setattr(package_cli, "_reconstruct_release_binding", lambda _package: stale)
    with pytest.raises(PermissionError, match="stale or mismatched"):
        package_cli.main(
            [
                "verify-signature-set",
                "--package",
                str(package_path),
                "--signature",
                str(signature_path),
            ]
        )
