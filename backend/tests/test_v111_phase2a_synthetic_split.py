from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import date
from pathlib import Path

import pytest

from app.evaluation import v111_certification_split as split_module
from app.evaluation.all60_qualification import (
    ExactAll60CaseBinding,
    ExactAll60Qualification,
)
from app.evaluation.live_suite import (
    LiveEvaluationBundle,
    LiveQuestionCase,
    LiveQuestionRegistry,
    LiveSuiteManifest,
)
from app.evaluation.sealed_candidate import SealedCandidateIdentity
from app.evaluation.v111_certification_split import (
    VerifiedDevelopmentReviewCustody,
    VerifiedSealedValidationCustody,
    VerifiedV111SplitFreezeAuthorization,
    freeze_v111_certification_split,
    load_v111_certification_split,
    scan_development_package_for_validation_leaks,
    verify_v111_certification_split,
    write_v111_certification_split,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _synthetic_groups() -> dict[tuple[str, str, str], tuple[str, ...]]:
    sizes = (9, 11, 9, 11, 9, 11)
    groups: dict[tuple[str, str, str], tuple[str, ...]] = {}
    ordinal = 0
    for index, size in enumerate(sizes):
        route = "route-a" if index < 3 else "route-b"
        task = "essay" if index % 2 == 0 else "problem"
        word_band = ("short", "medium", "long")[index % 3]
        members = []
        for _ in range(size):
            ordinal += 1
            members.append(f"synthetic-case-{ordinal:02d}")
        groups[(route, task, word_band)] = tuple(members)
    assert ordinal == 60
    return groups


def _synthetic_partition(secret: bytes) -> tuple[tuple[str, ...], tuple[str, ...]]:
    groups = _synthetic_groups()
    allocation = split_module._allocation_for_strata(
        groups=groups,
        secret=secret,
        binding="phase2a-synthetic-registry-v1",
    )
    development: list[str] = []
    validation: list[str] = []
    for stratum, members in sorted(groups.items()):
        ranked = sorted(
            members,
            key=lambda case_id: split_module._keyed_sha256(
                secret,
                "legalbot.v111-phase2a-synthetic-ranking.v1",
                "|".join(stratum),
                case_id,
            ),
        )
        cut = allocation[stratum]
        development.extend(ranked[:cut])
        validation.extend(ranked[cut:])
    return tuple(sorted(development)), tuple(sorted(validation))


def test_synthetic_split_is_deterministic_secret_keyed_and_exact() -> None:
    first = _synthetic_partition(b"a" * 32)
    replay = _synthetic_partition(b"a" * 32)
    alternative = _synthetic_partition(b"b" * 32)

    assert first == replay
    assert first != alternative
    development, validation = first
    assert len(development) == len(validation) == 30
    assert not set(development) & set(validation)
    assert set(development) | set(validation) == {
        f"synthetic-case-{ordinal:02d}" for ordinal in range(1, 61)
    }


def test_synthetic_split_preserves_frozen_primary_strata_constraints() -> None:
    groups = _synthetic_groups()
    development = set(_synthetic_partition(b"c" * 32)[0])
    selected_by_stratum: defaultdict[tuple[str, str, str], int] = defaultdict(int)
    for stratum, members in groups.items():
        selected_by_stratum[stratum] = len(set(members) & development)

    for stratum, members in groups.items():
        assert selected_by_stratum[stratum] in {len(members) // 2, (len(members) + 1) // 2}
    assert split_module.V111_CERTIFICATION_SPLIT_POLICY["performance_results_used"] is False
    assert split_module.V111_CERTIFICATION_SPLIT_POLICY["stage_a_used"] is False
    assert split_module.V111_CERTIFICATION_SPLIT_POLICY["redraw_allowed"] is False
    assert all("live30" not in case_id for members in groups.values() for case_id in members)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _synthetic_bundle(*, reverse_historical_labels: bool = False) -> LiveEvaluationBundle:
    """Build synthetic prose/metadata behind production-shaped non-secret IDs."""

    cases: list[LiveQuestionCase] = []
    for ordinal in range(1, 61):
        prefix = "live30" if ordinal <= 30 else "live60"
        historical_label = "historical-second-half" if ordinal <= 30 else "historical-first-half"
        if reverse_historical_labels:
            historical_label = (
                "historical-first-half" if ordinal <= 30 else "historical-second-half"
            )
        question = f"Synthetic certification infrastructure question {ordinal:02d}."
        # ``split`` is deliberately synthetic historical metadata. The v1.11
        # allocator must not read it or grant it selection authority.
        cases.append(
            LiveQuestionCase.model_construct(
                schema_name=(
                    "legalbot.live-evaluation-case.v1"
                    if ordinal <= 30
                    else "legalbot.live-evaluation-case.v2"
                ),
                suite_id=("live-evaluation-30-v1" if ordinal <= 30 else "live-evaluation-60-v1"),
                suite_version="1.0.0",
                split=historical_label,
                purpose="evaluation_only",
                eligible_for_training=False,
                training_export_allowed=False,
                immutable=True,
                case_id=f"{prefix}-q{ordinal:02d}",
                ordinal=ordinal,
                question=question,
                question_sha256=_digest(f"question:{ordinal}"),
                record_sha256=_digest(f"record:{ordinal}"),
                task_type="essay" if ordinal % 2 else "problem",
                subject=f"synthetic-subject-{ordinal % 7}",
                jurisdiction="Synthetic test jurisdiction",
                as_of_policy="test-only",
                word_target=(1_000, 3_000, 6_000)[ordinal % 3],
                expected_research_route="sectioned" if ordinal % 3 else "full_enquiry",
                expected_drafting_route="sectioned",
                expected_behaviour="answer",
                structural_standard_ids=(),
                must_cover_issues=("synthetic issue one", "synthetic issue two"),
                acceptable_source_ids=(),
                exact_gold_spans=(),
                known_contrary_authority_ids=(),
                forbidden_lanes=(),
                coverage_status="unqualified",
            )
        )
    registry = LiveQuestionRegistry(
        cases=tuple(cases),
        file_sha256=_digest("synthetic-registry-file"),
        canonical_sha256=_digest("synthetic-registry-canonical"),
    )
    manifest = LiveSuiteManifest.model_construct(
        suite_id="live-evaluation-60-v1",
        seal_sha256=_digest("synthetic-suite-seal"),
        registry_canonical_sha256=registry.canonical_sha256,
    )
    return LiveEvaluationBundle(
        root=Path("synthetic-test-bundle"),
        registry=registry,
        manifest=manifest,
        run_plan=None,
    )


def _synthetic_candidate() -> SealedCandidateIdentity:
    return SealedCandidateIdentity(
        build_id="synthetic-candidate-v111",
        status="candidate",
        candidate_manifest_sha256=_digest("synthetic-candidate-manifest"),
        candidate_seal_sha256=_digest("synthetic-candidate-seal"),
        source_manifest_sha256=_digest("synthetic-source-manifest"),
        embedding_model="synthetic-embedding-model",
        reranker_model="synthetic-reranker-model",
        document_count=60,
        chunk_count=600,
        vector_count=600,
    )


def _synthetic_qualification(bundle: LiveEvaluationBundle) -> ExactAll60Qualification:
    bindings = tuple(
        ExactAll60CaseBinding.model_construct(
            ordinal=case.ordinal,
            case_id=case.case_id,
            issue_count=10 if case.ordinal <= 45 else 9,
        )
        for case in bundle.registry.cases
    )
    assert sum(row.issue_count for row in bindings) == 585
    candidate = _synthetic_candidate()
    return ExactAll60Qualification.model_construct(
        suite_id=bundle.manifest.suite_id,
        suite_manifest_seal_sha256=bundle.manifest.seal_sha256,
        suite_registry_canonical_sha256=bundle.registry.canonical_sha256,
        candidate_build_id=candidate.build_id,
        candidate_manifest_sha256=candidate.candidate_manifest_sha256,
        candidate_seal_sha256=candidate.candidate_seal_sha256,
        candidate_source_manifest_sha256=candidate.source_manifest_sha256,
        case_count=60,
        case_ids=tuple(case.case_id for case in bundle.registry.cases),
        case_bindings=bindings,
        issue_count=585,
        issue_identity_set_sha256=_digest("synthetic-issue-identities"),
        as_of_date=date(2026, 8, 22),
        seal_sha256=_digest("synthetic-qualification-seal"),
    )


def _synthetic_authorization(
    *,
    bundle: LiveEvaluationBundle,
    secret: bytes,
) -> VerifiedV111SplitFreezeAuthorization:
    return VerifiedV111SplitFreezeAuthorization(
        bundle=bundle,
        candidate=_synthetic_candidate(),
        qualification=_synthetic_qualification(bundle),
        certification_contract_sha256=_digest("synthetic-contract"),
        owner_configuration_tranche_sha256=_digest("synthetic-configuration"),
        secret=secret,
        authorization_sha256=_digest("synthetic-freeze-authorization"),
        _token=split_module._VERIFIED_V111_SPLIT_FREEZE_TOKEN,
    )


def _validation_custody(root: Path) -> VerifiedSealedValidationCustody:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    from app.governance.v111_decision_generation import private_root_identity

    return VerifiedSealedValidationCustody(
        project_root=PROJECT_ROOT,
        root=root,
        root_identity_sha256=private_root_identity(root, project_root=PROJECT_ROOT),
        release_binding_sha256=_digest("synthetic-release"),
        owner_policy_tranche_sha256=_digest("synthetic-owner-policy"),
        configuration_tranche_sha256=_digest("synthetic-configuration"),
        package_sha256=_digest("synthetic-package"),
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
        release_binding_sha256=_digest("synthetic-release"),
        owner_policy_tranche_sha256=_digest("synthetic-owner-policy"),
        configuration_tranche_sha256=_digest("synthetic-configuration"),
        package_sha256=_digest("synthetic-package"),
        _token=split_module._VERIFIED_DEVELOPMENT_REVIEW_CUSTODY_TOKEN,
    )


def test_synthetic_public_freeze_replay_refuses_redraw_and_ignores_history() -> None:
    first_bundle = _synthetic_bundle()
    relabelled_bundle = _synthetic_bundle(reverse_historical_labels=True)
    first_authorization = _synthetic_authorization(bundle=first_bundle, secret=b"a" * 32)
    relabelled_authorization = _synthetic_authorization(
        bundle=relabelled_bundle,
        secret=b"a" * 32,
    )
    redraw_authorization = _synthetic_authorization(bundle=first_bundle, secret=b"b" * 32)

    frozen = freeze_v111_certification_split(authorization=first_authorization)
    relabelled = freeze_v111_certification_split(authorization=relabelled_authorization)
    assert frozen.development_case_ids == relabelled.development_case_ids
    assert frozen.sealed_validation_case_ids == relabelled.sealed_validation_case_ids
    assert verify_v111_certification_split(frozen, authorization=first_authorization) == frozen
    with pytest.raises(ValueError, match="redraw or replay mismatch"):
        verify_v111_certification_split(frozen, authorization=redraw_authorization)


def test_synthetic_public_custody_and_development_projection_are_fail_closed(
    tmp_path: Path,
) -> None:
    bundle = _synthetic_bundle()
    authorization = _synthetic_authorization(bundle=bundle, secret=b"c" * 32)
    frozen = freeze_v111_certification_split(authorization=authorization)
    validation = _validation_custody(tmp_path / "sealed-validation")
    development = _development_custody(tmp_path / "development")

    written = write_v111_certification_split(
        custody=validation,
        manifest=frozen,
        authorization=authorization,
    )
    assert written.stat().st_mode & 0o777 == 0o600
    assert (
        load_v111_certification_split(
            custody=validation,
            authorization=authorization,
        )
        == frozen
    )

    safe_member = development._root / "synthetic-development-record.json"
    safe_member.write_text(
        json.dumps({"case_id": frozen.development_case_ids[0]}),
        encoding="utf-8",
    )
    safe_member.chmod(0o600)
    clean = scan_development_package_for_validation_leaks(
        custody=validation,
        development_custody=development,
        authorization=authorization,
        manifest=frozen,
        bundle=bundle,
    )
    assert clean.passed is True

    safe_member.write_text(
        json.dumps({"case_id": frozen.sealed_validation_case_ids[0]}),
        encoding="utf-8",
    )
    safe_member.chmod(0o600)
    leaked = scan_development_package_for_validation_leaks(
        custody=validation,
        development_custody=development,
        authorization=authorization,
        manifest=frozen,
        bundle=bundle,
    )
    assert leaked.passed is False
    assert leaked.reason_codes == ("validation_case_identity",)
