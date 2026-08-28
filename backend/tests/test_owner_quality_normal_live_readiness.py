from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.db import Database
from app.evaluation.live_suite import sealed_sha256
from app.evaluation.live_suite_stage_a_v2_runner import STAGE_A_SCORER_IDENTITY_SHA256
from app.evaluation.owner_quality_normal_live_readiness import (
    OWNER_QUALITY_NORMAL_LIVE_POINTER,
    OwnerQualityNormalLiveReadinessContract,
    OwnerQualityReadinessArtifactRef,
    _load_referenced_model,
    _load_verified_canary_manifest_reference,
    _read_reference,
    owner_quality_normal_live_readiness_status,
)
from app.evaluation.v111_technical_attestation import FIXED_CHECK_MATRIX_SHA256
from app.readiness import build_readiness_report


def _normal_live_contract_material() -> dict[str, object]:
    artifact_names = (
        "all60_qualification",
        "canary_manifest",
        "development_authorization",
        "development_final_package",
        "development_owner_acceptance",
        "promotion_presentation",
        "technical_attestation_admission",
        "promoted_active_proof",
        "operational_proof",
        "owner_o04",
        "blind_holdout_authorization",
        "blind_holdout_final_package",
        "blind_holdout_owner_acceptance",
    )
    evidence_names = (
        "owner_only_smoke_evidence",
        "rollback_repromotion_evidence",
        "browser_recovery_evidence",
        "technical_readiness_evidence",
        "disk_heartbeat_lease_evidence",
        "model_identity_evidence",
    )
    material: dict[str, object] = {
        "schema": "legalbot.owner-quality-normal-live-readiness-contract.v1",
        "profile": "legalbot-v1.11-owner-only-normal-live",
        "candidate_build_id": "candidate-v111",
        "candidate_manifest_sha256": "1" * 64,
        "canary_manifest_id": "owner-quality-canary-" + "2" * 20,
        "canary_manifest_seal_sha256": "3" * 64,
        "development_run_id": "development-run-v111",
        "blind_holdout_run_id": "holdout-run-v111",
        "integration_sha": "4" * 40,
        "technical_run_id": "technical-run-v111",
        "technical_admission_id": "v111-technical-admission:" + "5" * 64,
        "technical_admission_seal_sha256": "6" * 64,
        "technical_final_attestation_seal_sha256": "7" * 64,
        "technical_matrix_sha256": FIXED_CHECK_MATRIX_SHA256,
        "technical_artifact_set_sha256": "9" * 64,
        "technical_artifact_member_count": 32,
        "technical_stage_a_result_seal_sha256": "c" * 64,
        "technical_stage_a_attestation_seal_sha256": "d" * 64,
        "technical_rollback_plan_seal_sha256": "a" * 64,
        "technical_rollback_policy_binding_seal_sha256": "b" * 64,
        "scorer_identity_sha256": STAGE_A_SCORER_IDENTITY_SHA256,
        "legacy_technical_summaries_accepted": False,
        "exact_development_case_count": 30,
        "exact_blind_holdout_case_count": 30,
        "one_blind_serial_pass": True,
        "owner_acceptance_required_for_every_answer": True,
        "trusted_owner_signature_required": True,
        "owner_signature_self_claim_sufficient": False,
        "legacy_readiness_sufficient": False,
        "local_only": True,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "writes_active": False,
        "writes_previous": False,
        "writes_o04": False,
        "authorizes_normal_live": False,
    }
    for index, name in enumerate(artifact_names, start=1):
        seal = "6" * 64 if name == "technical_attestation_admission" else f"{index:x}"[-1] * 64
        material[name] = {
            "relative_path": f"data/evaluations/readiness/{index:02d}-{name}.json",
            "file_sha256": hashlib.sha256(f"file-{name}".encode()).hexdigest(),
            "artifact_seal_sha256": seal,
        }
    for index, name in enumerate(evidence_names, start=20):
        material[name] = {
            "relative_path": f"data/evaluations/readiness/{index:02d}-{name}.json",
            "file_sha256": hashlib.sha256(f"file-{name}".encode()).hexdigest(),
        }
    material["seal_sha256"] = sealed_sha256(material)
    return material


def test_missing_pointer_is_an_explicit_v111_normal_live_blocker(tmp_path: Path) -> None:
    status = owner_quality_normal_live_readiness_status(tmp_path)

    assert status["pointer_present"] is False
    assert status["contract_present"] is False
    assert status["exact_artifacts_verified"] is False
    assert status["trusted_owner_o04_signature_verified"] is False
    assert status["normal_live_ready"] is False
    assert status["legacy_readiness_sufficient"] is False
    assert status["blocking_reason_codes"] == ["owner_quality_normal_live_pointer_missing"]
    assert status["writes_active"] is False
    assert status["writes_previous"] is False
    assert status["writes_o04"] is False


def test_readiness_contract_requires_exact_persisted_technical_admission() -> None:
    material = _normal_live_contract_material()
    contract = OwnerQualityNormalLiveReadinessContract.model_validate(material)
    assert contract.technical_admission_id == "v111-technical-admission:" + "5" * 64

    legacy = dict(material)
    for key in tuple(legacy):
        if key.startswith("technical_") or key == "promotion_presentation":
            legacy.pop(key)
    legacy["seal_sha256"] = sealed_sha256(legacy)
    with pytest.raises(ValidationError):
        OwnerQualityNormalLiveReadinessContract.model_validate(legacy)

    mutated = json.loads(json.dumps(material))
    mutated["technical_attestation_admission"]["artifact_seal_sha256"] = "f" * 64
    mutated["seal_sha256"] = sealed_sha256(mutated)
    with pytest.raises(ValidationError, match="reference and contract seal differ"):
        OwnerQualityNormalLiveReadinessContract.model_validate(mutated)


def test_unsafe_or_self_sealed_pointer_cannot_bypass_artifact_verification(
    tmp_path: Path,
) -> None:
    pointer_path = tmp_path / OWNER_QUALITY_NORMAL_LIVE_POINTER
    pointer_path.parent.mkdir(parents=True)
    pointer_path.parent.chmod(0o700)
    material = {
        "schema": "legalbot.owner-quality-normal-live-readiness-pointer.v1",
        "profile": "legalbot-v1.11-owner-only-normal-live",
        "current_contract": {
            "relative_path": "data/evaluations/../../private/owner.json",
            "file_sha256": "a" * 64,
            "artifact_seal_sha256": "b" * 64,
        },
        "owner_configured": True,
        "create_only_contract": True,
        "writes_active": False,
        "writes_previous": False,
        "writes_o04": False,
    }
    material["seal_sha256"] = sealed_sha256(material)
    pointer_path.write_text(json.dumps(material))
    pointer_path.chmod(0o600)

    status = owner_quality_normal_live_readiness_status(tmp_path)

    assert status["pointer_present"] is False
    assert status["normal_live_ready"] is False
    assert status["blocking_reason_codes"] == [
        "owner_quality_normal_live_artifact_verification_failed"
    ]
    assert status["error_code"] == "ValidationError"


def test_legacy_green_flag_cannot_claim_v111_normal_live(tmp_path: Path, monkeypatch) -> None:
    settings = Settings(project_root=tmp_path)
    database = Database(settings.database_path)
    database.initialize()
    monkeypatch.setattr(
        "app.readiness._build_readiness_report_v5",
        lambda _settings, _database: {
            "schema": "legalbot.production-readiness.v6",
            "status": "ready",
            "ready": True,
            "blocking_gates": [],
            "real_e2e_authorised": True,
        },
    )
    try:
        report = build_readiness_report(settings, database)
    finally:
        database.close()

    assert report["status"] == "ready"
    assert report["legacy_technical_ready"] is True
    assert report["ready_scope"] == "legacy_pre_holdout_technical_and_operational_only"
    assert report["legacy_ready_is_not_v111_normal_live"] is True
    assert report["normal_live_ready"] is False
    assert report["normal_live_authorised"] is False
    assert report["normal_live_blocking_gates"] == ["owner_quality_normal_live_pointer_missing"]
    assert report["normal_live_readiness_v111"]["legacy_readiness_sufficient"] is False


def test_exact_artifacts_still_stop_without_trusted_o04_signature_verifier(
    tmp_path: Path, monkeypatch
) -> None:
    import app.evaluation.owner_quality_normal_live_readiness as readiness

    pointer = SimpleNamespace(current_contract=object())
    contract = object()
    monkeypatch.setattr(readiness, "_load_pointer", lambda _root: pointer)
    monkeypatch.setattr(
        readiness,
        "_load_referenced_model",
        lambda _root, _reference, _model_type: (tmp_path / "contract.json", contract),
    )
    monkeypatch.setattr(
        readiness,
        "_verify_exact_artifacts",
        lambda **_kwargs: object(),
    )

    status = owner_quality_normal_live_readiness_status(tmp_path)

    assert status["pointer_present"] is True
    assert status["contract_present"] is True
    assert status["exact_artifacts_verified"] is True
    assert status["owner_acceptance_development_30_passed"] is True
    assert status["owner_acceptance_blind_holdout_30_passed"] is True
    assert status["trusted_owner_o04_signature_verified"] is False
    assert status["normal_live_ready"] is False
    assert status["blocking_reason_codes"] == ["trusted_owner_o04_signature_verifier_missing"]


def test_readiness_parses_the_same_fd_bytes_even_if_path_is_swapped(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "data/evaluations/private"
    parent.mkdir(parents=True)
    parent.chmod(0o700)
    artifact = parent / "artifact.json"
    original = b'{"identity":"original"}\n'
    replacement = b'{"identity":"replacement"}\n'
    artifact.write_bytes(original)
    artifact.chmod(0o600)
    reference = OwnerQualityReadinessArtifactRef(
        relative_path="data/evaluations/private/artifact.json",
        file_sha256=hashlib.sha256(original).hexdigest(),
        artifact_seal_sha256="a" * 64,
    )

    class SwappingModel:
        @classmethod
        def model_validate_json(cls, raw: bytes) -> SimpleNamespace:
            artifact.unlink()
            artifact.write_bytes(replacement)
            artifact.chmod(0o600)
            return SimpleNamespace(seal_sha256="a" * 64, parsed_bytes=raw)

    _path, parsed = _load_referenced_model(
        tmp_path,
        reference,
        SwappingModel,  # type: ignore[arg-type]
    )
    assert parsed.parsed_bytes == original
    assert artifact.read_bytes() == replacement


def test_readiness_rejects_symlinked_parent_and_favorable_redraw(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = tmp_path / "data/evaluations/real"
    real.mkdir(parents=True)
    real.chmod(0o700)
    payload = b'{"favorable":"redraw"}\n'
    (real / "manifest.json").write_bytes(payload)
    (real / "manifest.json").chmod(0o600)
    (tmp_path / "data/evaluations/linked").symlink_to(real, target_is_directory=True)
    linked = OwnerQualityReadinessArtifactRef(
        relative_path="data/evaluations/linked/manifest.json",
        file_sha256=hashlib.sha256(payload).hexdigest(),
        artifact_seal_sha256="b" * 64,
    )
    with pytest.raises(ValueError, match="symlink"):
        _read_reference(tmp_path, linked)

    direct = OwnerQualityReadinessArtifactRef(
        relative_path="data/evaluations/real/manifest.json",
        file_sha256=hashlib.sha256(payload).hexdigest(),
        artifact_seal_sha256="b" * 64,
    )
    qualification_payload = b'{"qualification":true}\n'
    qualification_path = real / "all60-qualification.json"
    qualification_path.write_bytes(qualification_payload)
    qualification_path.chmod(0o600)
    qualification = OwnerQualityReadinessArtifactRef(
        relative_path="data/evaluations/real/all60-qualification.json",
        file_sha256=hashlib.sha256(qualification_payload).hexdigest(),
        artifact_seal_sha256="c" * 64,
    )
    monkeypatch.setattr(
        "app.evaluation.owner_quality_normal_live_readiness."
        "load_verified_owner_quality_canary_manifest",
        lambda *_args, **_kwargs: SimpleNamespace(seal_sha256="b" * 64),
    )
    monkeypatch.setattr(
        "app.evaluation.owner_quality_normal_live_readiness.owner_quality_manifest_bytes",
        lambda _manifest: b'{"canonical":true}\n',
    )
    with pytest.raises(ValueError, match="favorable redraw"):
        _load_verified_canary_manifest_reference(
            tmp_path,
            direct,
            bundle=SimpleNamespace(),  # type: ignore[arg-type]
            candidate=SimpleNamespace(),  # type: ignore[arg-type]
            qualification_reference=qualification,
        )


def test_verified_manifest_loader_receives_retained_inodes_during_path_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "data/evaluations/private"
    parent.mkdir(parents=True)
    parent.chmod(0o700)
    manifest_path = parent / "manifest.json"
    qualification_path = parent / "all60-qualification.json"
    manifest_bytes = b'{"manifest":"original"}\n'
    qualification_bytes = b'{"qualification":"original"}\n'
    manifest_path.write_bytes(manifest_bytes)
    qualification_path.write_bytes(qualification_bytes)
    manifest_path.chmod(0o600)
    qualification_path.chmod(0o600)
    manifest_reference = OwnerQualityReadinessArtifactRef(
        relative_path="data/evaluations/private/manifest.json",
        file_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        artifact_seal_sha256="d" * 64,
    )
    qualification_reference = OwnerQualityReadinessArtifactRef(
        relative_path="data/evaluations/private/all60-qualification.json",
        file_sha256=hashlib.sha256(qualification_bytes).hexdigest(),
        artifact_seal_sha256="e" * 64,
    )
    retained_bytes_seen: list[tuple[bytes, bytes]] = []

    def swap_and_load(
        retained_manifest: Path, *, qualification_path: Path, **_kwargs
    ) -> SimpleNamespace:
        manifest_path.unlink()
        manifest_path.write_bytes(b'{"manifest":"replacement"}\n')
        manifest_path.chmod(0o600)
        qualification_path_on_disk = parent / "all60-qualification.json"
        qualification_path_on_disk.unlink()
        qualification_path_on_disk.write_bytes(b'{"qualification":"replacement"}\n')
        qualification_path_on_disk.chmod(0o600)
        retained_bytes_seen.append(
            (retained_manifest.read_bytes(), qualification_path.read_bytes())
        )
        return SimpleNamespace(seal_sha256="d" * 64)

    monkeypatch.setattr(
        "app.evaluation.owner_quality_normal_live_readiness."
        "load_verified_owner_quality_canary_manifest",
        swap_and_load,
    )
    monkeypatch.setattr(
        "app.evaluation.owner_quality_normal_live_readiness.owner_quality_manifest_bytes",
        lambda _manifest: manifest_bytes,
    )

    with pytest.raises(ValueError, match="identity changed while it was open"):
        _load_verified_canary_manifest_reference(
            tmp_path,
            manifest_reference,
            bundle=SimpleNamespace(),  # type: ignore[arg-type]
            candidate=SimpleNamespace(),  # type: ignore[arg-type]
            qualification_reference=qualification_reference,
        )
    assert retained_bytes_seen == [(manifest_bytes, qualification_bytes)]
