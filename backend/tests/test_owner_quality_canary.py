from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.evaluation.all60_qualification import ExactAll60Qualification
from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256
from app.evaluation.owner_quality_canary import (
    ALL60_QUALIFICATION_SCHEMA,
    All60CaseQualification,
    OwnerQualityCanaryManifest,
    freeze_owner_quality_canary_manifest,
    load_verified_owner_quality_canary_manifest,
    owner_quality_manifest_bytes,
    verify_owner_quality_canary_manifest,
    write_owner_quality_canary_manifest,
)
from app.evaluation.sealed_candidate import SealedCandidateIdentity

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


def _qualification(candidate_build_id: str = "candidate-v111") -> tuple[object, object]:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    case_ids = [case.case_id for case in bundle.registry.cases]
    value = {
        "schema": ALL60_QUALIFICATION_SCHEMA,
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "candidate_build_id": candidate_build_id,
        "case_count": 60,
        "case_ids": case_ids,
        "qualified_case_ids": case_ids,
        "limited_case_ids": [],
        "review_complete": True,
        "unreviewed_issue_count": 0,
    }
    value["seal_sha256"] = sealed_sha256(value)
    return bundle, All60CaseQualification.model_validate(value)


def _manifest() -> OwnerQualityCanaryManifest:
    bundle, qualification = _qualification()
    return freeze_owner_quality_canary_manifest(
        bundle=bundle,
        candidate_build_id="candidate-v111",
        candidate_manifest_sha256="a" * 64,
        qualification=qualification,
    )


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


def _exact_qualification() -> ExactAll60Qualification:
    _bundle, shallow = _qualification()
    values = shallow.model_dump(mode="python", by_alias=False)
    return ExactAll60Qualification.model_construct(
        **values,
        candidate_manifest_sha256="a" * 64,
        candidate_seal_sha256="b" * 64,
        candidate_source_manifest_sha256="c" * 64,
    )


def test_owner_quality_split_is_deterministic_exact_and_prose_free() -> None:
    first = _manifest()
    second = _manifest()

    assert owner_quality_manifest_bytes(first) == owner_quality_manifest_bytes(second)
    assert len(first.development_case_ids) == 30
    assert len(first.blind_holdout_case_ids) == 30
    assert set(first.development_case_ids).isdisjoint(first.blind_holdout_case_ids)
    assert {case.case_id for case in first.cases} == set(first.development_case_ids) | set(
        first.blind_holdout_case_ids
    )
    for key, count in first.development_distribution.items():
        assert abs(count - first.blind_holdout_distribution[key]) <= 1

    encoded = owner_quality_manifest_bytes(first).decode()
    assert '"question"' not in encoded
    assert '"subject"' not in encoded
    assert "/Users/" not in encoded
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    assert all(case.question not in encoded for case in bundle.registry.cases)


def test_candidate_identity_changes_seed_without_redrawing_same_contract() -> None:
    bundle, qualification = _qualification()
    first = freeze_owner_quality_canary_manifest(
        bundle=bundle,
        candidate_build_id="candidate-v111",
        candidate_manifest_sha256="a" * 64,
        qualification=qualification,
    )
    second = freeze_owner_quality_canary_manifest(
        bundle=bundle,
        candidate_build_id="candidate-v111",
        candidate_manifest_sha256="b" * 64,
        qualification=qualification,
    )

    assert first.seed_sha256 != second.seed_sha256
    assert first.manifest_id != second.manifest_id
    assert first.seal_sha256 != second.seal_sha256


def test_all60_qualification_is_required_and_exactly_bound() -> None:
    bundle, qualification = _qualification("candidate-other")
    with pytest.raises(ValueError, match="not bound"):
        freeze_owner_quality_canary_manifest(
            bundle=bundle,
            candidate_build_id="candidate-v111",
            candidate_manifest_sha256="a" * 64,
            qualification=qualification,
        )

    value = qualification.model_dump(mode="json", by_alias=True)
    value["review_complete"] = False
    value["seal_sha256"] = sealed_sha256(value)
    with pytest.raises(ValidationError):
        All60CaseQualification.model_validate(value)


def test_manifest_write_is_private_idempotent_and_create_only(tmp_path: Path) -> None:
    manifest = _manifest()
    destination = tmp_path / "private" / "owner-canary.json"

    assert write_owner_quality_canary_manifest(destination, manifest) == destination
    assert write_owner_quality_canary_manifest(destination, manifest) == destination
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700
    OwnerQualityCanaryManifest.model_validate_json(destination.read_bytes())

    tampered = json.loads(destination.read_text())
    tampered["candidate_manifest_sha256"] = "b" * 64
    destination.write_text(json.dumps(tampered))
    with pytest.raises(FileExistsError, match="immutable"):
        write_owner_quality_canary_manifest(destination, manifest)


def test_verified_loader_recomputes_every_rank_and_rejects_resealed_redraw(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    candidate = _candidate()
    exact = _exact_qualification()
    manifest = _manifest()
    assert (
        verify_owner_quality_canary_manifest(
            manifest,
            bundle=bundle,
            candidate=candidate,
            qualification=exact,
        )
        == manifest
    )

    changed = manifest.model_dump(mode="json", by_alias=True)
    changed["cases"][0]["selection_rank_sha256"] = "f" * 64
    changed["seal_sha256"] = sealed_sha256(changed)
    redraw = OwnerQualityCanaryManifest.model_validate(changed)
    with pytest.raises(ValueError, match="redraw or derivation mismatch"):
        verify_owner_quality_canary_manifest(
            redraw,
            bundle=bundle,
            candidate=candidate,
            qualification=exact,
        )

    destination = tmp_path / "owner-canary.json"
    destination.write_bytes(owner_quality_manifest_bytes(manifest))
    destination.chmod(0o600)
    qualification_path = tmp_path / "all60-qualification.json"
    qualification_path.write_text("not consulted after verified loader stub", encoding="utf-8")
    monkeypatch.setattr(
        "app.evaluation.owner_quality_canary.load_all60_qualification",
        lambda _path: exact,
    )
    assert (
        load_verified_owner_quality_canary_manifest(
            destination,
            bundle=bundle,
            candidate=candidate,
            qualification_path=qualification_path,
        )
        == manifest
    )

    destination.write_text(
        json.dumps(manifest.model_dump(mode="json", by_alias=True)), encoding="utf-8"
    )
    destination.chmod(0o600)
    with pytest.raises(ValueError, match="bytes are not canonical"):
        load_verified_owner_quality_canary_manifest(
            destination,
            bundle=bundle,
            candidate=candidate,
            qualification_path=qualification_path,
        )
