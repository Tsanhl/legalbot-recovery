from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.evaluation.live_suite import (
    LiveEvaluationBundle,
    canonical_json,
    load_live_evaluation_bundle,
)
from app.evaluation.v111_phase2a_package import (
    ALLOWED_ISSUE_STATUSES,
    ARTIFACT_IDS,
    IssueDispositionInput,
    Phase2AActionAbsenceAudit,
    Phase2AArtifact,
    Phase2ACandidateBinding,
    Phase2ACodeBinding,
    Phase2APackage,
    Phase2APackageIndex,
    Phase2AReviewInputs,
    build_phase2a_package,
    phase2a_package_json_payloads,
    verify_phase2a_package,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
CANDIDATE_SOURCE_MANIFEST = (
    PROJECT_ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260818-a"
    / "approved-source-manifest.json"
)


def _sha(character: str) -> str:
    return character * 64


def _review() -> Phase2AReviewInputs:
    return Phase2AReviewInputs(
        generated_at=datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
        code=Phase2ACodeBinding(
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            worktree_clean=True,
        ),
        candidate=Phase2ACandidateBinding(
            build_id="current-law-ew-full-fp16-v111-20260818-a",
            candidate_manifest_sha256=(
                "e28a4138e87cfeb2502e746073208ab25a647de8082a3c7fe96a44ed7d5cc74a"
            ),
            candidate_seal_file_sha256=(
                "d8009de258306cb13ae2b5d0c0d03dbf725d8c0e563bccde74cedaa9acdba04a"
            ),
            approved_source_manifest_sha256=(
                "d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0"
            ),
            approved_source_manifest_file_sha256=(
                "02a13a3641d0e406d974a1c8f1a4912ae6e761d059774bd68ff97a4cc7732e0e"
            ),
            embedding_store_sha256=(
                "1d7b1bddebe83694815066f5254c5b0c7a1d05febd4e2b9e2120f2ec3fe3c018"
            ),
            reranker_store_sha256=(
                "f775cce47e7cbed490693a954aadcf6141cdf5ffa31b3e33f229adc374223e29"
            ),
            document_count=85,
            chunk_count=149855,
            vector_count=149855,
            dimensions=1024,
        ),
        action_absence_audit=Phase2AActionAbsenceAudit(
            audit_sha256=_sha("0"),
            active_pointer_absent=True,
            previous_pointer_absent=True,
            real_split_absent=True,
            real_split_secret_absent=True,
            signing_key_absent=True,
            session_secret_absent=True,
            real_review_roots_absent=True,
            stage_a_results_absent=True,
            answer_model_results_absent=True,
            development_projection_absent=True,
        ),
        entry_state_sha256=_sha("1"),
        official_source_review_method_sha256=_sha("2"),
        recommended_cutoff_date=None,
        review_target_cutoff_date=date(2026, 8, 14),
        cutoff_support_status="UNSUPPORTABLE_ON_CURRENT_CANDIDATE",
        cutoff_basis_sha256=_sha("3"),
        freshness_policy_sha256=_sha("4"),
        security_controls_proposal_sha256=_sha("5"),
        certification_contract_proposal_sha256=_sha("6"),
        synthetic_split_verification_sha256=_sha("7"),
        synthetic_split_verification_passed=True,
        terminal_verdict="BLOCKED_MATERIAL_GAPS",
    )


def _inputs() -> tuple[LiveEvaluationBundle, dict[str, object]]:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    manifest = json.loads(CANDIDATE_SOURCE_MANIFEST.read_text(encoding="utf-8"))
    return bundle, manifest


def _pending_default() -> IssueDispositionInput:
    return IssueDispositionInput(
        primary_status="OWNER_LEGAL_JUDGMENT_REQUIRED",
        official_review_record_sha256=_sha("8"),
        reason_code="owner-legal-review-pending",
        supporting_evidence_sha256s=(_sha("9"),),
        affected_proposition_state="OWNER_JUDGMENT_PENDING",
        prevents_common_cutoff=True,
        remediation_code="obtain-owner-legal-review",
        candidate_bytes_change_required=None,
        owner_approval_required=True,
    )


def _pending_dispositions(bundle: LiveEvaluationBundle) -> dict[str, IssueDispositionInput]:
    output: dict[str, IssueDispositionInput] = {}
    for case in bundle.registry.cases:
        for issue_number, _label in enumerate(case.must_cover_issues, start=1):
            row_id = f"{case.case_id}:issue-{issue_number:02d}"
            output[row_id] = _pending_default().model_copy(
                update={
                    "official_review_record_sha256": hashlib.sha256(
                        f"review:{row_id}".encode()
                    ).hexdigest(),
                    "supporting_evidence_sha256s": (
                        hashlib.sha256(f"support:{row_id}".encode()).hexdigest(),
                    ),
                }
            )
    assert len(output) == 585
    return output


def _package():
    bundle, manifest = _inputs()
    return build_phase2a_package(
        bundle=bundle,  # type: ignore[arg-type]
        candidate_source_manifest=manifest,
        review=_review(),
        dispositions=_pending_dispositions(bundle),
    )


def test_package_accounts_for_exact_60_cases_and_585_issues_without_authority() -> None:
    package = _package()

    assert tuple(artifact.artifact_id for artifact in package.artifacts) == ARTIFACT_IDS
    assert package.index.artifact_count == 15
    assert package.index.artifact_order == ARTIFACT_IDS
    assert package.index.authorizing is False
    assert package.index.owner_signature_present is False
    assert package.index.signing_payload_created is False

    issues = package.artifact("issue-currentness-register").payload["issues"]
    cases = package.artifact("case-qualification-register").payload["cases"]
    aggregate = package.artifact("qualification-aggregate").payload
    assert len(issues) == 585
    assert len({row["row_id"] for row in issues}) == 585
    assert [row["ordinal"] for row in issues] == list(range(1, 586))
    assert len(cases) == 60
    assert sum(case["issue_count"] for case in cases) == 585
    assert aggregate["status_counts"] == {
        status: (585 if status == "OWNER_LEGAL_JUDGMENT_REQUIRED" else 0)
        for status in ALLOWED_ISSUE_STATUSES
    }
    assert aggregate["split_allowed_by_this_artifact"] is False

    for artifact in package.artifacts:
        assert artifact.authorizing is False
        assert artifact.owner_signature_present is False
        assert artifact.signing_authority_created is False
        assert artifact.split_created is False
        assert artifact.split_secret_generated is False
        assert artifact.stage_a_invoked is False
        assert artifact.answer_model_invoked is False
        assert artifact.development_30_invoked is False
        assert artifact.active_changed is False
        assert artifact.previous_changed is False
        assert artifact.promotion_performed is False
        assert artifact.o04_issued is False
        assert artifact.live_activated is False
        assert artifact.contains_question_prose is False
        assert artifact.contains_private_paths is False


def test_package_is_deterministic_and_returns_canonical_bytes_without_writes() -> None:
    first = _package()
    second = _package()

    assert first == second
    payloads = phase2a_package_json_payloads(first)
    assert len(payloads) == 16
    assert tuple(payloads) == tuple(
        [f"{artifact_id}.json" for artifact_id in ARTIFACT_IDS] + ["PHASE2A-INDEX.json"]
    )
    assert json.loads(payloads["PHASE2A-INDEX.json"])["index_sha256"] == (first.index.index_sha256)

    first.artifact("owner-readable-summary").payload["body"] = "mutated after construction"
    with pytest.raises(ValidationError, match="payload (?:digest|keys differ)"):
        phase2a_package_json_payloads(first)


def test_serialized_package_replays_with_json_array_normalization() -> None:
    package = _package()
    payloads = phase2a_package_json_payloads(package)
    reparsed = Phase2APackage(
        artifacts=tuple(
            Phase2AArtifact.model_validate_json(payloads[f"{artifact_id}.json"])
            for artifact_id in ARTIFACT_IDS
        ),
        index=Phase2APackageIndex.model_validate_json(payloads["PHASE2A-INDEX.json"]),
    )
    bundle, manifest = _inputs()

    verify_phase2a_package(
        reparsed,
        bundle=bundle,  # type: ignore[arg-type]
        candidate_source_manifest=manifest,
        candidate_replay_binding=_review().candidate,
        expected_artifact_payload_extensions={},
    )


def test_positive_qualification_requires_per_issue_source_and_span_bindings() -> None:
    with pytest.raises(ValidationError, match="explicit row-specific source, candidate"):
        IssueDispositionInput(
            primary_status="QUALIFIED",
            official_review_record_sha256=_sha("8"),
        )

    bundle, manifest = _inputs()
    positive = IssueDispositionInput(
        primary_status="QUALIFIED",
        official_review_record_sha256=_sha("8"),
        official_source_version_ids=(manifest["sources"][0]["source_version_id"],),
        evidence_span_binding_sha256s=(_sha("9"),),
        registry_gold_binding_sha256=_sha("a"),
        candidate_source_binding_sha256=_sha("b"),
        source_gold_consistency_binding_sha256=_sha("c"),
        currentness_binding_sha256=_sha("d"),
        effective_date_binding_sha256=_sha("e"),
        candidate_bytes_change_required=False,
    )
    with pytest.raises(ValueError, match="blanket default"):
        build_phase2a_package(
            bundle=bundle,  # type: ignore[arg-type]
            candidate_source_manifest=manifest,
            review=_review(),
            dispositions={},
            default_disposition=positive,
        )


def test_fabricated_positive_qualification_cannot_enable_phase2b() -> None:
    bundle, manifest = _inputs()
    fabricated = IssueDispositionInput(
        primary_status="QUALIFIED",
        official_review_record_sha256=_sha("8"),
        official_source_version_ids=(manifest["sources"][0]["source_version_id"],),
        evidence_span_binding_sha256s=(_sha("9"),),
        registry_gold_binding_sha256=_sha("a"),
        candidate_source_binding_sha256=_sha("b"),
        source_gold_consistency_binding_sha256=_sha("c"),
        currentness_binding_sha256=_sha("d"),
        effective_date_binding_sha256=_sha("e"),
        candidate_bytes_change_required=False,
    )

    dispositions = _pending_dispositions(bundle)
    dispositions["live30-q01:issue-01"] = fabricated
    with pytest.raises(ValueError, match="nonempty row-bound registry gold"):
        build_phase2a_package(
            bundle=bundle,  # type: ignore[arg-type]
            candidate_source_manifest=manifest,
            review=_review(),
            dispositions=dispositions,
        )

    package = _package()
    assert package.artifact("final-invariants").payload["phase2b_allowed"] is False


def test_disposition_map_rejects_missing_unknown_and_out_of_candidate_sources() -> None:
    bundle, manifest = _inputs()
    with pytest.raises(ValueError, match="does not cover all 585"):
        build_phase2a_package(
            bundle=bundle,  # type: ignore[arg-type]
            candidate_source_manifest=manifest,
            review=_review(),
            dispositions={},
        )
    with pytest.raises(ValueError, match="unknown issue rows"):
        build_phase2a_package(
            bundle=bundle,  # type: ignore[arg-type]
            candidate_source_manifest=manifest,
            review=_review(),
            dispositions={"live60-q60:issue-99": _pending_default()},
            default_disposition=_pending_default(),
        )

    invalid_source = IssueDispositionInput(
        primary_status="MATERIAL_CANDIDATE_COVERAGE_GAP",
        official_review_record_sha256=_sha("8"),
        official_source_version_ids=("source-version-not-in-candidate",),
        reason_code="official-source-missing-from-candidate",
        supporting_evidence_sha256s=(_sha("9"),),
        affected_proposition_state="MAPPED_MATERIAL_GAP",
        prevents_common_cutoff=True,
        remediation_code="rebuild-candidate-with-official-source",
        candidate_bytes_change_required=True,
        owner_approval_required=True,
    )
    with pytest.raises(ValueError, match="outside the candidate"):
        build_phase2a_package(
            bundle=bundle,  # type: ignore[arg-type]
            candidate_source_manifest=manifest,
            review=_review(),
            dispositions={"live30-q01:issue-01": invalid_source},
            default_disposition=_pending_default(),
        )


def test_candidate_source_manifest_tampering_is_rejected() -> None:
    bundle, manifest = _inputs()
    manifest["current_law_as_of_date"] = "2026-08-15"
    with pytest.raises(ValueError, match="manifest identity"):
        build_phase2a_package(
            bundle=bundle,  # type: ignore[arg-type]
            candidate_source_manifest=manifest,
            review=_review(),
            dispositions={},
            default_disposition=_pending_default(),
        )


def test_private_path_or_question_prose_is_rejected_even_with_recomputed_seals() -> None:
    package = _package()
    original = package.artifact("owner-readable-summary")
    raw = original.model_dump(mode="json", by_alias=True)
    raw["payload"]["review_details"] = {"review_root": "/Users/owner/private-review"}
    raw["payload_sha256"] = hashlib.sha256(canonical_json(raw["payload"])).hexdigest()
    raw.pop("seal_sha256")
    raw["seal_sha256"] = hashlib.sha256(canonical_json(raw)).hexdigest()
    with pytest.raises(ValidationError, match="private path"):
        Phase2AArtifact.model_validate(raw)

    raw = original.model_dump(mode="json", by_alias=True)
    raw["payload"]["review_details"] = {"question": "owner question prose"}
    raw["payload_sha256"] = hashlib.sha256(canonical_json(raw["payload"])).hexdigest()
    raw.pop("seal_sha256")
    raw["seal_sha256"] = hashlib.sha256(canonical_json(raw)).hexdigest()
    with pytest.raises(
        ValidationError,
        match="review detail boolean|forbidden control field",
    ):
        Phase2AArtifact.model_validate(raw)


@pytest.mark.parametrize(
    "fabricated_control",
    (
        {"split_secret_created": True},
        {"owner_signature_created": True},
    ),
)
def test_resealed_review_details_cannot_claim_control_creation(
    fabricated_control: dict[str, bool],
) -> None:
    original = _package().artifact("candidate-impact-report")
    raw = original.model_dump(mode="json", by_alias=True)
    raw["payload"]["review_details"] = fabricated_control
    raw["payload_sha256"] = hashlib.sha256(canonical_json(raw["payload"])).hexdigest()
    raw.pop("seal_sha256")
    raw["seal_sha256"] = hashlib.sha256(canonical_json(raw)).hexdigest()

    with pytest.raises(
        ValidationError,
        match="review detail boolean|forbidden control field",
    ):
        Phase2AArtifact.model_validate(raw)


@pytest.mark.parametrize(
    "fabricated_claim",
    (
        {"gate_open": True},
        {"owner_approval_complete": True},
        {"all_issues_positive_qualified": True},
        {"qualification_state": "QUALIFIED"},
    ),
)
def test_review_details_reject_unregistered_gate_or_qualification_aliases(
    fabricated_claim: dict[str, object],
) -> None:
    bundle, manifest = _inputs()
    with pytest.raises(ValueError, match="review detail|semantic alias"):
        build_phase2a_package(
            bundle=bundle,  # type: ignore[arg-type]
            candidate_source_manifest=manifest,
            review=_review(),
            dispositions=_pending_dispositions(bundle),
            artifact_payload_extensions={
                "owner-readable-summary": fabricated_claim,
            },
        )


@pytest.mark.parametrize(
    ("artifact_id", "fabricated_fields"),
    (
        ("owner-readable-summary", {"phase2b_allowed": True}),
        (
            "owner-readable-summary",
            {"all_issues_positive_qualified": True, "qualification_state": "QUALIFIED"},
        ),
    ),
)
def test_resealed_semantic_aliases_cannot_escape_exact_artifact_contract(
    artifact_id: str,
    fabricated_fields: dict[str, object],
) -> None:
    original = _package().artifact(artifact_id)
    raw = original.model_dump(mode="json", by_alias=True)
    raw["payload"].update(fabricated_fields)
    raw["payload_sha256"] = hashlib.sha256(canonical_json(raw["payload"])).hexdigest()
    raw.pop("seal_sha256")
    raw["seal_sha256"] = hashlib.sha256(canonical_json(raw)).hexdigest()

    with pytest.raises(ValidationError, match="payload keys differ from its exact contract"):
        Phase2AArtifact.model_validate(raw)


@pytest.mark.parametrize(
    ("artifact_id", "field", "unsafe_value"),
    (
        ("security-owner-controls-proposal", "controls_created", True),
        ("cutoff-recommendation", "recommendation_is_authority", True),
        ("final-invariants", "owner_approval_required", False),
    ),
)
def test_resealed_core_authority_constants_are_exact(
    artifact_id: str,
    field: str,
    unsafe_value: bool,
) -> None:
    original = _package().artifact(artifact_id)
    raw = original.model_dump(mode="json", by_alias=True)
    raw["payload"][field] = unsafe_value
    raw["payload_sha256"] = hashlib.sha256(canonical_json(raw["payload"])).hexdigest()
    raw.pop("seal_sha256")
    raw["seal_sha256"] = hashlib.sha256(canonical_json(raw)).hexdigest()

    with pytest.raises(ValidationError, match="payload constant differs from its contract"):
        Phase2AArtifact.model_validate(raw)


def test_verifier_rejects_any_artifact_or_index_mismatch() -> None:
    package = _package()
    bundle, manifest = _inputs()
    with pytest.raises(ValueError, match="exact 15 artifacts"):
        verify_phase2a_package(
            replace(package, artifacts=package.artifacts[:-1]),
            bundle=bundle,  # type: ignore[arg-type]
            candidate_source_manifest=manifest,
            candidate_replay_binding=_review().candidate,
            expected_artifact_payload_extensions={},
        )


def test_verifier_requires_the_independently_replayed_candidate_binding() -> None:
    package = _package()
    bundle, manifest = _inputs()
    changed = Phase2ACandidateBinding.model_construct(
        **{
            **_review().candidate.model_dump(),
            "embedding_store_sha256": _sha("f"),
        }
    )
    with pytest.raises(ValueError, match="exact candidate binding"):
        verify_phase2a_package(
            package,
            bundle=bundle,  # type: ignore[arg-type]
            candidate_source_manifest=manifest,
            candidate_replay_binding=changed,
            expected_artifact_payload_extensions={},
        )


def test_verifier_binds_nested_review_details_to_independent_replay_input() -> None:
    bundle, manifest = _inputs()
    expected = {
        "owner-readable-summary": {
            "result": "BLOCKED_BEFORE_PHASE2B",
            "owner_decision_count": 2,
        }
    }
    package = build_phase2a_package(
        bundle=bundle,  # type: ignore[arg-type]
        candidate_source_manifest=manifest,
        review=_review(),
        dispositions=_pending_dispositions(bundle),
        artifact_payload_extensions=expected,
    )
    with pytest.raises(ValueError, match="review details differ from replay inputs"):
        verify_phase2a_package(
            package,
            bundle=bundle,  # type: ignore[arg-type]
            candidate_source_manifest=manifest,
            candidate_replay_binding=_review().candidate,
            expected_artifact_payload_extensions={
                "owner-readable-summary": {
                    "result": "READY_FOR_PHASE2B",
                    "owner_decision_count": 0,
                }
            },
        )


def test_unsupported_cutoff_is_not_misrepresented_as_a_recommendation() -> None:
    review = _review().model_copy(
        update={
            "recommended_cutoff_date": None,
            "review_target_cutoff_date": date(2026, 8, 14),
            "cutoff_support_status": "UNSUPPORTABLE_ON_CURRENT_CANDIDATE",
        }
    )
    bundle, manifest = _inputs()
    package = build_phase2a_package(
        bundle=bundle,  # type: ignore[arg-type]
        candidate_source_manifest=manifest,
        review=review,
        dispositions=_pending_dispositions(bundle),
    )

    cutoff = package.artifact("cutoff-recommendation").payload
    assert cutoff["recommended_cutoff_date"] is None
    assert cutoff["review_target_cutoff_date"] == "2026-08-14"
    assert cutoff["cutoff_support_status"] == "UNSUPPORTABLE_ON_CURRENT_CANDIDATE"
    assert cutoff["common_cutoff_freezable"] is False


def test_review_detail_extensions_are_sealed_and_safety_checked() -> None:
    bundle, manifest = _inputs()
    package = build_phase2a_package(
        bundle=bundle,  # type: ignore[arg-type]
        candidate_source_manifest=manifest,
        review=_review(),
        dispositions=_pending_dispositions(bundle),
        artifact_payload_extensions={
            "candidate-impact-report": {
                "verdict": "SUCCESSOR_CANDIDATE_REQUIRED",
                "finding_ids": ["official-gap-001"],
            }
        },
    )
    assert package.artifact("candidate-impact-report").payload["review_details"] == {
        "verdict": "SUCCESSOR_CANDIDATE_REQUIRED",
        "finding_ids": ["official-gap-001"],
    }

    with pytest.raises(ValueError, match="private path"):
        build_phase2a_package(
            bundle=bundle,  # type: ignore[arg-type]
            candidate_source_manifest=manifest,
            review=_review(),
            dispositions=_pending_dispositions(bundle),
            artifact_payload_extensions={
                "security-owner-controls-proposal": {"proposed_root": "/private/root"}
            },
        )
