from __future__ import annotations

import hashlib
import inspect
import json
import stat
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.config import Settings
from app.db import utc_iso
from app.evaluation import sealed_candidate as sealed_candidate_module
from app.evaluation.candidate_runtime_preflight import (
    PREFLIGHT_SELECTION_ALGORITHM_VERSION,
    RUNTIME_PREFLIGHT_POLICY,
    build_preflight_case_selection,
    run_candidate_runtime_preflight,
)
from app.evaluation.live_suite import load_live_evaluation_bundle
from app.evaluation.sealed_candidate import (
    SealedCandidateIdentity,
    load_sealed_candidate_identity,
)
from app.observability.live_metrics import load_slo_policy
from app.retrieval.budget import RetrievalBudgetExhausted

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


def _candidate() -> SealedCandidateIdentity:
    return SealedCandidateIdentity(
        build_id="candidate-v111",
        status="candidate",
        candidate_manifest_sha256="a" * 64,
        candidate_seal_sha256="b" * 64,
        source_manifest_sha256="c" * 64,
        embedding_model="Qwen/Qwen3-Embedding-0.6B",
        reranker_model="Qwen/Qwen3-Reranker-0.6B",
        document_count=85,
        chunk_count=149_855,
        vector_count=149_855,
    )


def _safe_span() -> dict[str, Any]:
    return {
        "chunk_id": "chunk-safe-1",
        "index_build_id": "candidate-v111",
        "lane": "primary_authority",
        "jurisdiction": "England and Wales",
        "citation_data": {"source_type": "legislation"},
        "identity_verified": True,
        "currentness_verified": True,
        "locator": "section-1",
        "text": "runtime-only-test-span",
    }


def _synthetic_selection_bundle(
    rows: tuple[tuple[str, str, int, str], ...],
) -> SimpleNamespace:
    cases = tuple(
        SimpleNamespace(
            case_id=case_id,
            question_sha256=question_sha256,
            record_sha256=hashlib.sha256(f"record:{question_sha256}".encode()).hexdigest(),
            expected_research_route=route,
            word_target=word_target,
        )
        for case_id, route, word_target, question_sha256 in rows
    )
    canonical = hashlib.sha256("\0".join(case_id for case_id, *_rest in rows).encode()).hexdigest()
    return SimpleNamespace(
        registry=SimpleNamespace(cases=cases, canonical_sha256=canonical),
        manifest=SimpleNamespace(seal_sha256=hashlib.sha256(b"synthetic-suite").hexdigest()),
    )


def test_generic_selector_records_complete_case_agnostic_identity() -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    policy = load_slo_policy(PROJECT_ROOT / "config/observability_slo.yaml")

    selection = build_preflight_case_selection(
        bundle=bundle,
        slo_policy=policy,
        additional_case_ids=None,
    )
    payload = selection.safe_dict()
    eligible_band_ids = {
        policy.band_for(
            route=case.expected_research_route,
            word_target=case.word_target,
        ).id
        for case in bundle.registry.cases
    }

    assert selection.algorithm_version == PREFLIGHT_SELECTION_ALGORITHM_VERSION
    assert len(selection.selected_case_ids) == len(eligible_band_ids)
    assert "live60-q31" not in selection.selected_case_ids
    assert payload["eligible_case_set_sha256"]
    assert payload["selection_seed_sha256"]
    assert payload["selection_order_rule"]
    assert payload["selected_set_sha256"]
    assert payload["coverage_constraints"][1] == {
        "kind": "case-specific-preference-forbidden",
        "case_specific_authority": False,
    }
    assert RUNTIME_PREFLIGHT_POLICY["case_specific_authority"] is False
    assert "live60-q31" not in inspect.getsource(build_preflight_case_selection)


def test_generic_selector_preserves_safety_across_composition_and_case_id_changes() -> None:
    policy = load_slo_policy(PROJECT_ROOT / "config/observability_slo.yaml")
    digests = tuple(hashlib.sha256(f"question-{index}".encode()).hexdigest() for index in range(8))
    first_rows = (
        ("case-a", "sectioned", 1_500, digests[0]),
        ("case-b", "sectioned", 1_700, digests[1]),
        ("case-c", "sectioned", 3_000, digests[2]),
        ("case-d", "sectioned", 4_000, digests[3]),
        ("case-e", "full_enquiry", 4_000, digests[4]),
        ("case-f", "full_enquiry", 4_500, digests[5]),
        ("case-g", "full_enquiry", 6_000, digests[6]),
        ("case-h", "full_enquiry", 8_000, digests[7]),
    )
    renamed_rows = tuple(
        (f"renamed-{index}", route, word_target, question_sha256)
        for index, (_case_id, route, word_target, question_sha256) in enumerate(first_rows)
    )

    for rows in (first_rows, first_rows[::2], renamed_rows):
        selection = build_preflight_case_selection(
            bundle=_synthetic_selection_bundle(rows),
            slo_policy=policy,
            additional_case_ids=None,
        )
        selected_cases = {
            case.case_id: case for case in _synthetic_selection_bundle(rows).registry.cases
        }
        observed_bands = {
            policy.band_for(
                route=selected_cases[case_id].expected_research_route,
                word_target=selected_cases[case_id].word_target,
            ).id
            for case_id in selection.selected_case_ids
        }
        eligible_bands = {
            policy.band_for(route=route, word_target=word_target).id
            for _case_id, route, word_target, _question_sha256 in rows
        }
        assert observed_bands == eligible_bands
        assert len(selection.selected_case_ids) == len(eligible_bands)


def test_q31_history_remains_byte_exact_and_readable_without_current_authority() -> None:
    path = PROJECT_ROOT / "docs/status/live60-v2-latest.json"
    raw = path.read_bytes()
    payload = json.loads(raw)

    assert hashlib.sha256(raw).hexdigest() == (
        "35b2355b9e66f43768ec150921985b78d650ef22ad2cda888fa47ec3abca92a3"
    )
    assert payload["early_canary_case_id"] == "live60-q31"
    selector_source = inspect.getsource(build_preflight_case_selection).casefold()
    assert all(
        forbidden not in selector_source
        for forbidden in ("active", "promotion", "stage_a", "certification")
    )


def test_candidate_verifier_accepts_sealed_candidate_without_active_pointer(
    tmp_path: Path, database: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path, test_mode=True)
    build_root = settings.index_dir / "builds/candidate-v111"
    build_root.mkdir(parents=True)
    (build_root / "manifest.json").write_text("{}\n")
    (build_root / "seal.json").write_text('{"sealed":true}\n')
    seal_sha = hashlib.sha256((build_root / "seal.json").read_bytes()).hexdigest()
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,document_count,chunk_count,vector_count,
          embedding_model,reranker_model,manifest_sha256,created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (
            "candidate-v111",
            "candidate",
            "data/indexes/builds/candidate-v111",
            85,
            149_855,
            149_855,
            "Qwen/Qwen3-Embedding-0.6B",
            "Qwen/Qwen3-Reranker-0.6B",
            seal_sha,
            utc_iso(),
        ),
    )
    monkeypatch.setattr(
        sealed_candidate_module, "_verify_sealed_build", lambda *_args, **_kwargs: "c" * 64
    )

    identity = load_sealed_candidate_identity(
        settings=settings, database=database, candidate_build_id="candidate-v111"
    )

    assert identity.status == "candidate"
    assert identity.chunk_count == identity.vector_count == 149_855


@pytest.mark.asyncio
async def test_preflight_runs_generic_cold_warm_set_without_persisting_prose(
    tmp_path: Path,
) -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    policy_path = PROJECT_ROOT / "config/observability_slo.yaml"
    policy = load_slo_policy(policy_path)
    selection = build_preflight_case_selection(
        bundle=bundle,
        slo_policy=policy,
        additional_case_ids=None,
    )

    class Retriever:
        calls = 0

        def active_build_id(self) -> str:
            return "candidate-v111"

        async def retrieve_certified_plan(self, requests: Any) -> tuple[Any, ...]:
            self.calls += 1
            return tuple((_safe_span(),) for _item in requests)

    retriever = Retriever()
    result = await run_candidate_runtime_preflight(
        run_id="preflight-test-1",
        output_root=tmp_path / "private",
        bundle=bundle,
        candidate=_candidate(),
        retriever=retriever,
        slo_policy=policy,
        slo_policy_sha256=hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        as_of_date=date(2026, 8, 20),
        code_revision="d" * 40,
        code_dirty=False,
        additional_case_ids=None,
    )

    assert result["preflight_passed"] is True
    assert result["sample_count"] == len(selection.selected_case_ids) * 2
    assert retriever.calls == len(selection.selected_case_ids) * 2
    assert result["case_selection"] == selection.safe_dict()
    run_root = tmp_path / "private" / "preflight-test-1"
    assert stat.S_IMODE(run_root.stat().st_mode) == 0o700
    for path in run_root.rglob("*.json"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    encoded = "\n".join(path.read_text() for path in run_root.rglob("*.json"))
    for case_id in selection.selected_case_ids:
        case = bundle.registry.case(case_id)
        assert case.question not in encoded
        assert all(issue not in encoded for issue in case.must_cover_issues)
    assert '"answer"' not in encoded
    assert "/Users/" not in encoded


@pytest.mark.asyncio
async def test_preflight_deterministic_budget_failure_stops_without_retry(
    tmp_path: Path,
) -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    policy_path = PROJECT_ROOT / "config/observability_slo.yaml"

    class Retriever:
        calls = 0

        def active_build_id(self) -> str:
            return "candidate-v111"

        async def retrieve_certified_plan(self, _requests: Any) -> tuple[Any, ...]:
            self.calls += 1
            raise RetrievalBudgetExhausted("retrieval_budget_exceeded")

    retriever = Retriever()
    result = await run_candidate_runtime_preflight(
        run_id="preflight-stop-1",
        output_root=tmp_path / "private",
        bundle=bundle,
        candidate=_candidate(),
        retriever=retriever,
        slo_policy=load_slo_policy(policy_path),
        slo_policy_sha256=hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        as_of_date=date(2026, 8, 20),
        code_revision="d" * 40,
        code_dirty=False,
        additional_case_ids=None,
    )

    assert result["status"] == "stopped"
    assert result["stop_reason"] == "deterministic_safety_failure"
    assert retriever.calls == 1
    stopped = json.loads((tmp_path / "private/preflight-stop-1/STOPPED.json").read_text())
    assert stopped["failure_reason_code"] == "retrieval_budget_exceeded"


@pytest.mark.asyncio
async def test_preflight_empty_retrieval_batch_is_a_hard_viability_failure(
    tmp_path: Path,
) -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    policy_path = PROJECT_ROOT / "config/observability_slo.yaml"

    class Retriever:
        calls = 0

        def active_build_id(self) -> str:
            return "candidate-v111"

        async def retrieve_certified_plan(self, requests: Any) -> tuple[Any, ...]:
            self.calls += 1
            return tuple(() for _item in requests)

    retriever = Retriever()
    result = await run_candidate_runtime_preflight(
        run_id="preflight-empty-1",
        output_root=tmp_path / "private",
        bundle=bundle,
        candidate=_candidate(),
        retriever=retriever,
        slo_policy=load_slo_policy(policy_path),
        slo_policy_sha256=hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        as_of_date=date(2026, 8, 20),
        code_revision="d" * 40,
        code_dirty=False,
        additional_case_ids=None,
    )

    assert result["status"] == "stopped"
    assert result["failure_reason_code"] == "retrieval_empty_batch"
    assert result["stop_reason"] == "deterministic_safety_failure"
    assert retriever.calls == 1


@pytest.mark.asyncio
async def test_preflight_repeated_transient_fingerprint_stops_on_second_attempt(
    tmp_path: Path,
) -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    policy_path = PROJECT_ROOT / "config/observability_slo.yaml"

    class Retriever:
        calls = 0

        def active_build_id(self) -> str:
            return "candidate-v111"

        async def retrieve_certified_plan(self, _requests: Any) -> tuple[Any, ...]:
            self.calls += 1
            raise RuntimeError("transient_worker_failure")

    retriever = Retriever()
    result = await run_candidate_runtime_preflight(
        run_id="preflight-repeat-1",
        output_root=tmp_path / "private",
        bundle=bundle,
        candidate=_candidate(),
        retriever=retriever,
        slo_policy=load_slo_policy(policy_path),
        slo_policy_sha256=hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        as_of_date=date(2026, 8, 20),
        code_revision="d" * 40,
        code_dirty=False,
        additional_case_ids=None,
    )

    assert result["stop_reason"] == "repeated_failure_fingerprint"
    assert retriever.calls == 2
