from __future__ import annotations

import json
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from app.evaluation import v111_certification_split as split_module
from app.evaluation.all60_qualification import (
    ExactAll60CaseBinding,
    ExactAll60Qualification,
)
from app.evaluation.live_suite import load_live_evaluation_bundle
from app.evaluation.owner_quality_canary import All60CaseQualification
from app.evaluation.sealed_candidate import SealedCandidateIdentity
from app.evaluation.v111_certification_split import (
    V111_CERTIFICATION_SPLIT_POLICY_SHA256,
    VerifiedDevelopmentReviewCustody,
    VerifiedSealedValidationCustody,
    VerifiedV111SplitFreezeAuthorization,
    assert_preparation_does_not_contain_split_secret,
    freeze_v111_certification_split,
    load_v111_certification_split,
    scan_development_package_for_validation_leaks,
    split_secret_commitment,
    v111_certification_split_bytes,
    verify_v111_certification_split,
    write_v111_certification_split,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


def _candidate() -> SealedCandidateIdentity:
    return SealedCandidateIdentity(
        build_id="candidate-v111",
        status="candidate",
        candidate_manifest_sha256="a" * 64,
        candidate_seal_sha256="b" * 64,
        source_manifest_sha256="c" * 64,
        embedding_model="embedding-model-v1",
        reranker_model="reranker-model-v1",
        document_count=85,
        chunk_count=149_855,
        vector_count=149_855,
    )


def _qualification() -> ExactAll60Qualification:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    case_bindings = tuple(
        ExactAll60CaseBinding.model_construct(
            ordinal=case.ordinal,
            case_id=case.case_id,
            issue_count=len(case.must_cover_issues),
        )
        for case in bundle.registry.cases
    )
    return ExactAll60Qualification.model_construct(
        suite_id=bundle.manifest.suite_id,
        suite_manifest_seal_sha256=bundle.manifest.seal_sha256,
        suite_registry_canonical_sha256=bundle.registry.canonical_sha256,
        candidate_build_id="candidate-v111",
        candidate_manifest_sha256="a" * 64,
        candidate_seal_sha256="b" * 64,
        candidate_source_manifest_sha256="c" * 64,
        case_count=60,
        case_ids=tuple(case.case_id for case in bundle.registry.cases),
        case_bindings=case_bindings,
        issue_count=585,
        issue_identity_set_sha256="d" * 64,
        as_of_date=date(2026, 8, 22),
        seal_sha256="e" * 64,
    )


def _manifest(secret: bytes = b"s" * 32):
    return freeze_v111_certification_split(authorization=_authorization(secret))


def _authorization(
    secret: bytes = b"s" * 32,
    *,
    candidate: SealedCandidateIdentity | None = None,
    qualification: object | None = None,
) -> VerifiedV111SplitFreezeAuthorization:
    return VerifiedV111SplitFreezeAuthorization(
        bundle=load_live_evaluation_bundle(BUNDLE_ROOT),
        candidate=_candidate() if candidate is None else candidate,
        qualification=_qualification() if qualification is None else qualification,  # type: ignore[arg-type]
        certification_contract_sha256="f" * 64,
        owner_configuration_tranche_sha256="1" * 64,
        secret=secret,
        authorization_sha256="2" * 64,
        _token=split_module._VERIFIED_V111_SPLIT_FREEZE_TOKEN,
    )


def _custody(root: Path) -> VerifiedSealedValidationCustody:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    from app.governance.v111_decision_generation import private_root_identity

    return VerifiedSealedValidationCustody(
        project_root=PROJECT_ROOT,
        root=root,
        root_identity_sha256=private_root_identity(root, project_root=PROJECT_ROOT),
        release_binding_sha256="3" * 64,
        owner_policy_tranche_sha256="4" * 64,
        configuration_tranche_sha256="1" * 64,
        package_sha256="5" * 64,
        _token=split_module._VERIFIED_SEALED_VALIDATION_CUSTODY_TOKEN,
    )


def _development_custody(root: Path) -> VerifiedDevelopmentReviewCustody:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    from app.governance.v111_decision_generation import private_root_identity

    return VerifiedDevelopmentReviewCustody(
        project_root=PROJECT_ROOT,
        root=root,
        root_identity_sha256=private_root_identity(root, project_root=PROJECT_ROOT),
        release_binding_sha256="3" * 64,
        owner_policy_tranche_sha256="4" * 64,
        configuration_tranche_sha256="1" * 64,
        package_sha256="5" * 64,
        _token=split_module._VERIFIED_DEVELOPMENT_REVIEW_CUSTODY_TOKEN,
    )


def test_keyed_split_is_deterministic_exact_balanced_and_prose_free() -> None:
    first = _manifest()
    second = _manifest()

    assert v111_certification_split_bytes(first) == v111_certification_split_bytes(second)
    assert first.algorithm_sha256 == V111_CERTIFICATION_SPLIT_POLICY_SHA256
    assert first.secret_commitment_sha256 == split_secret_commitment(b"s" * 32)
    assert len(first.development_case_ids) == 30
    assert len(first.sealed_validation_case_ids) == 30
    assert set(first.development_case_ids).isdisjoint(first.sealed_validation_case_ids)
    for key, development_count in first.development_distribution.items():
        validation_count = first.sealed_validation_distribution[key]
        assert abs(development_count - validation_count) <= 1

    encoded = v111_certification_split_bytes(first)
    assert b"s" * 32 not in encoded
    assert b'"question"' not in encoded
    assert b'"subject"' not in encoded
    assert b"blind" not in encoded
    assert b"/Users/" not in encoded


def test_secret_changes_allocation_and_replay_requires_exact_secret() -> None:
    first = _manifest(b"a" * 32)
    second = _manifest(b"b" * 32)
    assert first.secret_commitment_sha256 != second.secret_commitment_sha256
    assert first.split_digest_sha256 != second.split_digest_sha256

    assert (
        verify_v111_certification_split(
            first,
            authorization=_authorization(b"a" * 32),
        )
        == first
    )
    with pytest.raises(ValueError, match="redraw or replay mismatch"):
        verify_v111_certification_split(
            first,
            authorization=_authorization(b"b" * 32),
        )


def test_split_refuses_missing_secret_or_shallow_qualification() -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    authorization = _authorization()
    with pytest.raises(AttributeError, match="immutable"):
        authorization._secret = b"z" * 32
    with pytest.raises(AttributeError, match="immutable"):
        del authorization.authorization_sha256
    with pytest.raises(ValueError, match="32-byte"):
        freeze_v111_certification_split(authorization=_authorization(b"short"))

    shallow = All60CaseQualification.model_construct(
        suite_id=bundle.manifest.suite_id,
        suite_manifest_seal_sha256=bundle.manifest.seal_sha256,
        suite_registry_canonical_sha256=bundle.registry.canonical_sha256,
        candidate_build_id="candidate-v111",
        case_count=60,
        case_ids=tuple(case.case_id for case in bundle.registry.cases),
        seal_sha256="e" * 64,
    )
    with pytest.raises(ValueError, match="exact all-60 qualification"):
        freeze_v111_certification_split(authorization=_authorization(qualification=shallow))

    with pytest.raises(ValueError, match="differ from exact qualification or candidate"):
        freeze_v111_certification_split(
            authorization=_authorization(candidate=replace(_candidate(), status="active"))
        )

    with pytest.raises(PermissionError, match="trusted split-freeze"):
        freeze_v111_certification_split(authorization=_qualification())
    with pytest.raises(TypeError, match="trusted split-freeze"):
        VerifiedV111SplitFreezeAuthorization(
            bundle=bundle,
            candidate=_candidate(),
            qualification=_qualification(),
            certification_contract_sha256="f" * 64,
            owner_configuration_tranche_sha256="1" * 64,
            secret=b"s" * 32,
            authorization_sha256="2" * 64,
            _token=object(),
        )


def test_split_private_create_only_canonical_io(tmp_path: Path) -> None:
    manifest = _manifest()
    authorization = _authorization()
    custody = _custody(tmp_path / "custody")
    with pytest.raises(AttributeError, match="immutable"):
        custody._root = tmp_path / "replacement"
    with pytest.raises(AttributeError, match="immutable"):
        custody.root_identity_sha256 = "0" * 64
    with pytest.raises(ValueError, match="redraw or replay mismatch"):
        write_v111_certification_split(
            custody=custody,
            manifest=_manifest(b"a" * 32),
            authorization=_authorization(b"b" * 32),
        )
    assert not (tmp_path / "custody" / "v111-certification-split.json").exists()

    path = write_v111_certification_split(
        custody=custody,
        manifest=manifest,
        authorization=authorization,
    )
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert path.name == "v111-certification-split.json"
    assert load_v111_certification_split(custody=custody, authorization=authorization) == manifest

    with pytest.raises(FileExistsError):
        write_v111_certification_split(
            custody=custody,
            manifest=manifest,
            authorization=authorization,
        )

    path.write_text("{}", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_v111_certification_split(
            custody=custody,
            manifest=manifest,
            authorization=authorization,
        )
    with pytest.raises(ValueError, match="contract is invalid"):
        load_v111_certification_split(custody=custody, authorization=authorization)

    with pytest.raises(PermissionError, match="trusted sealed-Validation"):
        write_v111_certification_split(
            custody=object(),
            manifest=manifest,
            authorization=authorization,
        )
    with pytest.raises(TypeError, match="trusted sealed-Validation"):
        VerifiedSealedValidationCustody(
            project_root=PROJECT_ROOT,
            root=tmp_path / "arbitrary",
            root_identity_sha256="1" * 64,
            release_binding_sha256="2" * 64,
            owner_policy_tranche_sha256="3" * 64,
            configuration_tranche_sha256="4" * 64,
            package_sha256="5" * 64,
            _token=object(),
        )
    assert not (tmp_path / "arbitrary").exists()


def test_split_write_stays_on_signed_custody_descriptor_during_swap_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization = _authorization()
    manifest = _manifest()
    custody = _custody(tmp_path / "custody")
    original_root = custody._root
    replacement_root = tmp_path / "replacement-custody"
    replacement_root.mkdir(mode=0o700)
    replacement_root.chmod(0o700)
    saved_root = tmp_path / "saved-custody"
    original_open = split_module.open_exact_private_root_descriptor
    original_require = split_module.require_exact_private_root_descriptor_current
    swapped = False

    def swap_after_open(*args: object, **kwargs: object) -> tuple[int, str]:
        nonlocal swapped
        descriptor, identity = original_open(*args, **kwargs)  # type: ignore[arg-type]
        if args[0] == original_root:
            original_root.rename(saved_root)
            replacement_root.rename(original_root)
            swapped = True
        return descriptor, identity

    def restore_before_replay(*args: object, **kwargs: object) -> None:
        nonlocal swapped
        if swapped and kwargs.get("root") == original_root:
            original_root.rename(replacement_root)
            saved_root.rename(original_root)
            swapped = False
        original_require(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(split_module, "open_exact_private_root_descriptor", swap_after_open)
    monkeypatch.setattr(
        split_module,
        "require_exact_private_root_descriptor_current",
        restore_before_replay,
    )
    try:
        path = write_v111_certification_split(
            custody=custody,
            manifest=manifest,
            authorization=authorization,
        )
    finally:
        if swapped:
            original_root.rename(replacement_root)
            saved_root.rename(original_root)

    assert path.read_bytes() == v111_certification_split_bytes(manifest)
    assert not (replacement_root / path.name).exists()


def test_preparation_guard_stops_before_secret_or_lane_materialisation() -> None:
    assert_preparation_does_not_contain_split_secret(
        {
            "schema": "legalbot.v111-certification-contract-draft.v1",
            "split_status": "pending_post_qualification_owner_secret",
        }
    )
    with pytest.raises(ValueError, match="must not contain"):
        assert_preparation_does_not_contain_split_secret({"split_secret": "do-not-store"})
    with pytest.raises(ValueError, match="must not contain"):
        assert_preparation_does_not_contain_split_secret(
            {"nested": [{"split_secret": "do-not-store"}]}
        )
    with pytest.raises(ValueError, match="must not contain"):
        assert_preparation_does_not_contain_split_secret(
            {"nested": {"development_case_ids": ["do-not-materialise"]}}
        )
    with pytest.raises(ValueError, match="stop before"):
        assert_preparation_does_not_contain_split_secret({"secret_commitment_sha256": "a" * 64})


def test_development_leak_check_is_path_free_and_rejects_validation_material(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    custody = _custody(tmp_path / "custody")
    development_custody = _development_custody(tmp_path / "development")
    development_root = development_custody._root
    safe_path = development_root / "safe.json"
    safe_path.write_text('{"lane":"development","result":"pending"}', encoding="utf-8")
    safe_path.chmod(0o600)

    passed = scan_development_package_for_validation_leaks(
        custody=custody,
        development_custody=development_custody,
        authorization=_authorization(),
        manifest=manifest,
        bundle=bundle,
    )
    assert passed.passed
    assert passed.leak_count == 0
    assert not passed.leak_file_sha256s

    validation_id = manifest.sealed_validation_case_ids[0]
    validation_case = next(case for case in bundle.registry.cases if case.case_id == validation_id)
    leak_path = development_root / "leak.json"
    leak_path.write_text(
        json.dumps(
            {
                "case_id": validation_id,
                "question_sha256": validation_case.question_sha256,
                "validation_result": "not-allowed",
            }
        ),
        encoding="utf-8",
    )
    leak_path.chmod(0o600)
    failed = scan_development_package_for_validation_leaks(
        custody=custody,
        development_custody=development_custody,
        authorization=_authorization(),
        manifest=manifest,
        bundle=bundle,
    )
    assert not failed.passed
    assert set(failed.reason_codes) == {
        "validation_case_identity",
        "validation_lane_material",
        "validation_question_identity",
    }
    encoded = failed.model_dump_json()
    assert str(development_root) not in encoded
    assert validation_id not in encoded

    leak_path.unlink()
    name_leak_path = development_root / f"{validation_id}.json"
    name_leak_path.write_text('{"lane":"development"}', encoding="utf-8")
    name_leak_path.chmod(0o600)
    name_failed = scan_development_package_for_validation_leaks(
        custody=custody,
        development_custody=development_custody,
        authorization=_authorization(),
        manifest=manifest,
        bundle=bundle,
    )
    assert not name_failed.passed
    assert "validation_case_identity" in name_failed.reason_codes
    assert validation_id not in name_failed.model_dump_json()

    with pytest.raises(PermissionError, match="trusted Development review custody"):
        scan_development_package_for_validation_leaks(
            custody=custody,
            development_custody=object(),
            authorization=_authorization(),
            manifest=manifest,
            bundle=bundle,
        )
    with pytest.raises(TypeError, match="trusted Development review custody"):
        VerifiedDevelopmentReviewCustody(
            project_root=PROJECT_ROOT,
            root=tmp_path / "arbitrary-development",
            root_identity_sha256="1" * 64,
            release_binding_sha256="2" * 64,
            owner_policy_tranche_sha256="3" * 64,
            configuration_tranche_sha256="4" * 64,
            package_sha256="5" * 64,
            _token=object(),
        )


def test_development_leak_scan_stays_on_signed_root_during_swap_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    custody = _custody(tmp_path / "custody")
    development_custody = _development_custody(tmp_path / "development")
    development_root = development_custody._root
    replacement_root = tmp_path / "replacement-development"
    replacement_root.mkdir(mode=0o700)
    replacement_root.chmod(0o700)
    saved_root = tmp_path / "saved-development"
    validation_id = manifest.sealed_validation_case_ids[0]
    leak = development_root / f"{validation_id}.json"
    leak.write_text('{"lane":"development"}', encoding="utf-8")
    leak.chmod(0o600)
    original_open = split_module.open_exact_private_root_descriptor
    original_require = split_module.require_exact_private_root_descriptor_current
    swapped = False

    def swap_after_open(*args: object, **kwargs: object) -> tuple[int, str]:
        nonlocal swapped
        descriptor, identity = original_open(*args, **kwargs)  # type: ignore[arg-type]
        if args[0] == development_root:
            development_root.rename(saved_root)
            replacement_root.rename(development_root)
            swapped = True
        return descriptor, identity

    def restore_before_replay(*args: object, **kwargs: object) -> None:
        nonlocal swapped
        if swapped and kwargs.get("root") == development_root:
            development_root.rename(replacement_root)
            saved_root.rename(development_root)
            swapped = False
        original_require(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(split_module, "open_exact_private_root_descriptor", swap_after_open)
    monkeypatch.setattr(
        split_module,
        "require_exact_private_root_descriptor_current",
        restore_before_replay,
    )
    try:
        report = scan_development_package_for_validation_leaks(
            custody=custody,
            development_custody=development_custody,
            authorization=_authorization(),
            manifest=manifest,
            bundle=bundle,
        )
    finally:
        if swapped:
            development_root.rename(replacement_root)
            saved_root.rename(development_root)

    assert not report.passed
    assert "validation_case_identity" in report.reason_codes
    assert validation_id not in report.model_dump_json()
