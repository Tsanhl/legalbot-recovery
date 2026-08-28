from __future__ import annotations

import ast
import json
from collections import Counter
from pathlib import Path

from app.evaluation.suite import EvaluationCase, load_evaluation_suite

ROOT = Path(__file__).resolve().parents[2]
A2 = ROOT / "backend/tests/fixtures/a2-intentional-abstention"
SUITE = ROOT / "benchmarks/evaluation/v1/draft-suite.jsonl"
MANIFEST = A2 / "manifest.jsonl"

OCR_PROPOSED_REMOVE = {
    "ocr-001",
    "ocr-003",
    "ocr-005",
    "ocr-006",
    "ocr-008",
    "ocr-010",
    "ocr-011",
    "ocr-014",
    "ocr-015",
    "ocr-018",
    "ocr-019",
}
MIXED_PROPOSED_REMOVE = {"privacy-017", "privacy-021"}
PROPOSED_REMOVE = OCR_PROPOSED_REMOVE | MIXED_PROPOSED_REMOVE
IDS_REMOVED_THIS_ROUND = {"privacy-017", "privacy-021", "ocr-014", "ocr-019"}
OCR_RETAIN_CONTRACTS = {
    "ocr-013": ("request_unlocked_copy", "encrypted_without_credentials"),
    "ocr-016": ("request_missing_annex", "referenced_annex_not_supplied"),
    "ocr-020": (
        "refuse_to_invent_and_request_missing_page",
        "material_page_missing",
    ),
}
MIXED_BEHAVIOR = "answer_safe_remainder_and_refuse_unsafe"
CONTRACT_FIELDS = (
    "preferred_behavior",
    "allowed_behaviors",
    "reason_code",
    "required_response_elements",
    "forbidden_response_elements",
)
REPEAT_GROUPS = {
    "a2-dev-knowledge-restaurant": (
        "knowledge-001",
        ["knowledge-001", "knowledge-006", "knowledge-011"],
    ),
    "a2-dev-knowledge-west_arcadia": (
        "knowledge-002",
        ["knowledge-002", "knowledge-007", "knowledge-012"],
    ),
    "a2-dev-knowledge-zx_settlement": (
        "knowledge-003",
        ["knowledge-003", "knowledge-008", "knowledge-013"],
    ),
    "a2-dev-knowledge-solicitor_advice": (
        "knowledge-004",
        ["knowledge-004", "knowledge-009", "knowledge-014"],
    ),
    "a2-dev-knowledge-tax_facts": (
        "knowledge-005",
        ["knowledge-005", "knowledge-010", "knowledge-015"],
    ),
}
PHYSICAL_RETAIN = 57
INDEPENDENTLY_SCORED = 47
RETAIN_SPLITS = {"development": 35, "promotion": 11, "adversarial_holdout": 11}

FORBIDDEN_INGEST_MARKERS = (
    "OWNER-VIEW",
    "A2-OWNER-REVIEW",
    "OCR-FIXTURE-BACKLOG",
    "ocr-fixture-backlog",
    "MIXED-SAFE-UNSAFE-BACKLOG",
    "mixed-safe-unsafe-backlog",
    "PROPOSED-SEAL-CHECKLIST",
    "bucket-a2-owner-decisions",
    "bucket-a2-adjudication",
)

LOADER_DIRS = (
    ROOT / "backend/app/ingestion",
    ROOT / "backend/app/retrieval",
    ROOT / "backend/app/evaluation",
)


def _manifest() -> list[dict]:
    return [
        json.loads(line)
        for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _weight(row: dict) -> int:
    if row.get("a2_membership") != "retain":
        return 0
    w = row.get("independent_score_weight")
    if w is None:
        return 1
    return int(w)


def test_draft_suite_loads_240_and_ids_are_unique() -> None:
    suite = load_evaluation_suite(SUITE, require_complete=False)
    assert len(suite.cases) == 240
    ids = [c.case_id for c in suite.cases]
    assert len(ids) == len(set(ids))
    splits = Counter(c.split for c in suite.cases)
    assert splits == {"development": 144, "promotion": 48, "adversarial_holdout": 48}


def test_optional_a2_fields_do_not_break_non_a2_cases() -> None:
    raw = json.loads(SUITE.read_text(encoding="utf-8").splitlines()[0])
    for line in SUITE.read_text(encoding="utf-8").splitlines():
        raw = json.loads(line)
        if not raw["case_id"].startswith(("knowledge-", "ocr-", "privacy-")):
            break
    case = EvaluationCase.model_validate(raw)
    assert case.a2_membership is None
    assert case.preferred_behavior is None
    assert case.repeat_group_id is None
    assert case.evaluation_role is None
    assert case.independent_score_weight is None


def test_a2_split_reconciliation_and_retain_count() -> None:
    rows = _manifest()
    retain = [r for r in rows if r.get("a2_membership") == "retain"]
    removed = [r for r in rows if r.get("a2_membership") == "proposed_remove"]
    assert len(rows) == 70
    assert len({r["id"] for r in rows}) == 70
    assert len(retain) == PHYSICAL_RETAIN
    assert {r["id"] for r in removed} == PROPOSED_REMOVE
    retain_split = dict(Counter(r["split"] for r in retain))
    assert retain_split == RETAIN_SPLITS
    assert sum(retain_split.values()) == PHYSICAL_RETAIN
    assert sum(_weight(r) for r in retain) == INDEPENDENTLY_SCORED


def test_behavioral_contract_completeness_for_retain() -> None:
    rows = _manifest()
    retain = [r for r in rows if r.get("a2_membership") == "retain"]
    assert len(retain) == PHYSICAL_RETAIN
    for r in retain:
        for field in CONTRACT_FIELDS:
            val = r.get(field)
            assert val, f"{r['id']} missing {field}"
        if isinstance(r["allowed_behaviors"], list):
            assert r["preferred_behavior"] in r["allowed_behaviors"]
        assert r.get("owner_approved") is True
        assert r.get("seal_eligible") is True
        assert r.get("gold_spans") == []
        assert r.get("gold_authority_ids") == []
        assert r.get("gold_answer") is None
        if r["id"].startswith("ocr-"):
            assert r.get("recoverable") is not None, f"recoverable=null on active {r['id']}"
        if r.get("preferred_behavior") == MIXED_BEHAVIOR and r.get("safe_remainder_present"):
            raise AssertionError(f"mixed empty-gold remainder still active: {r['id']}")

    for r in rows:
        if r.get("a2_membership") == "retain":
            assert r.get("seal_eligible") is True
        else:
            assert r.get("seal_eligible") is False

    for cid in MIXED_PROPOSED_REMOVE:
        assert cid not in {r["id"] for r in retain}

    for cid, (pref, reason) in OCR_RETAIN_CONTRACTS.items():
        row = next(r for r in retain if r["id"] == cid)
        assert row["preferred_behavior"] == pref
        assert row["reason_code"] == reason
        assert row["owner_approved"] is True
        assert row["recoverable"] is False

    for cid in OCR_PROPOSED_REMOVE:
        row = next(r for r in rows if r["id"] == cid)
        assert row["a2_membership"] == "proposed_remove"
        assert row["owner_approved"] is False
        assert row["seal_eligible"] is False
        assert row["proposed_target_family"] == "positive_ocr_or_document_understanding"


def test_phase4a_mixed_privacy_reclassified_to_backlog() -> None:
    rows = _manifest()
    by_id = {r["id"]: r for r in rows}
    payload = json.loads((A2 / "mixed-safe-unsafe-backlog.json").read_text(encoding="utf-8"))
    md = (A2 / "MIXED-SAFE-UNSAFE-BACKLOG.md").read_text(encoding="utf-8")
    assert payload["ingestible"] is False
    assert payload["seal_eligible"] is False
    assert payload["owner_approved"] is True
    assert payload["proposed_target_family"] == "mixed_safe_unsafe_response"
    assert payload["reclassification_reason"] == "safe_remainder_requires_positive_legal_gold"
    assert set(payload["ids"]) == MIXED_PROPOSED_REMOVE
    assert "legalbot:non-ingestible" in md
    for cid in MIXED_PROPOSED_REMOVE:
        row = by_id[cid]
        assert row["a2_membership"] == "proposed_remove"
        assert row["seal_eligible"] is False
        assert row["owner_approved"] is True
        assert row["proposed_target_family"] == "mixed_safe_unsafe_response"
        assert row["reclassification_reason"] == "safe_remainder_requires_positive_legal_gold"
        assert row["preferred_behavior"] == MIXED_BEHAVIOR
        assert row["safe_remainder_present"] is True
        assert row["gold_spans"] == []
        assert row["gold_answer"] is None
        assert cid in md
        back = next(x for x in payload["rows"] if x["id"] == cid)
        assert back["preferred_behavior"] == MIXED_BEHAVIOR
        assert back["required_response_elements"]


def test_phase4b_ocr_014_019_outcome3_fixture_unavailable() -> None:
    rows = _manifest()
    by_id = {r["id"]: r for r in rows}
    adj = json.loads((A2 / "ocr-adjudication.json").read_text(encoding="utf-8"))
    assert adj["fixture_search_hits_count"] == 0
    assert set(adj["phase4b_ids"]) == {"ocr-014", "ocr-019"}
    md = (A2 / "OCR-OWNER-REVIEW.md").read_text(encoding="utf-8")
    for cid, family in (
        ("ocr-014", "ocr.promo.half_schedule_screenshot"),
        ("ocr-019", "ocr.holdout.wrong_language_ocr_pinpoints"),
    ):
        row = by_id[cid]
        assert row["template_family"] == family
        assert row["a2_membership"] == "proposed_remove"
        assert row["proposed_target_family"] == "positive_ocr_or_document_understanding"
        assert (
            row["reclassification_reason"] == "fixture_unavailable_for_recoverability_adjudication"
        )
        assert row["seal_eligible"] is False
        assert row["owner_approved"] is False
        assert row.get("available_fixture") in (None, "")
        assert row.get("recovery_attempted") is False
        assert cid in md
        rec = next(x for x in adj["rows"] if x["id"] == cid)
        assert rec["outcome"] == "outcome_3_fixture_unavailable"
        # Must not have been rewritten as encrypted synthetic.
        q = (row.get("query") or "").lower()
        assert "password-protected" not in q
        assert "encrypted" not in q or cid != "ocr-014"


def test_trim_later_and_repeat_groups_on_dev_knowledge() -> None:
    rows = _manifest()
    by_id = {r["id"]: r for r in rows}
    mapping = json.loads((A2 / "a2-repeat-groups.json").read_text(encoding="utf-8"))
    mapped = {g["repeat_group_id"]: g for g in mapping["groups"]}
    assert set(mapped) == set(REPEAT_GROUPS)
    marked = [
        r
        for r in rows
        if r["id"].startswith("knowledge-")
        and r["split"] == "development"
        and (r.get("sidecar_metadata") or {}).get("trim_later")
    ]
    assert len(marked) == 15
    for group_id, (canonical, members) in REPEAT_GROUPS.items():
        g = mapped[group_id]
        assert g["canonical_case_id"] == canonical
        assert g["split"] == "development"
        assert [m["id"] for m in g["members"]] == members
        for cid in members:
            row = by_id[cid]
            assert row["a2_membership"] == "retain"
            assert row["split"] == "development"
            assert row["repeat_group_id"] == group_id
            assert row["canonical_case_id"] == canonical
            assert row.get("owner_approved") is True
            if cid == canonical:
                assert row["evaluation_role"] == "canonical"
                assert row["independent_score_weight"] == 1
            else:
                assert row["evaluation_role"] == "repeat_stability_canary"
                assert row["independent_score_weight"] == 0
    canaries = [r for r in rows if r.get("evaluation_role") == "repeat_stability_canary"]
    assert len(canaries) == 10
    assert all(r.get("independent_score_weight") == 0 for r in canaries)
    assert all(r["split"] == "development" for r in canaries)


def test_suite_merge_retain_only_no_seal_path_for_proposed_remove() -> None:
    suite = load_evaluation_suite(SUITE, require_complete=False)
    by_id = {c.case_id: c for c in suite.cases}
    rows = _manifest()
    retain_ids = {r["id"] for r in rows if r["a2_membership"] == "retain"}
    for cid in retain_ids:
        case = by_id[cid]
        assert case.a2_membership == "retain"
        assert case.preferred_behavior
        assert case.reason_code
        assert case.allowed_behaviors
        assert case.required_response_elements
        assert case.forbidden_response_elements
        assert case.status == "needs_expert_annotation"
        assert (
            case.evaluation_role != "repeat_stability_canary" or case.independent_score_weight == 0
        )
    for cid in PROPOSED_REMOVE:
        case = by_id[cid]
        assert case.a2_membership == "proposed_remove"
        assert case.preferred_behavior is None
        assert case.reason_code is None
        assert case.allowed_behaviors is None
        assert case.repeat_group_id is None
        assert case.independent_score_weight is None
        assert case.status == "needs_expert_annotation"
    for group_id, (canonical, members) in REPEAT_GROUPS.items():
        for cid in members:
            case = by_id[cid]
            assert case.repeat_group_id == group_id
            assert case.canonical_case_id == canonical
            if cid == canonical:
                assert case.evaluation_role == "canonical"
                assert case.independent_score_weight == 1
            else:
                assert case.evaluation_role == "repeat_stability_canary"
                assert case.independent_score_weight == 0


def test_leakage_cross_split_still_passes() -> None:
    report = json.loads((A2 / "leakage-report.json").read_text(encoding="utf-8"))
    acc = report["acceptance"]
    assert acc["zero_exact_cross_split_dups"] is True
    assert acc["zero_id_only_cross_split_variants"] is True
    assert acc["zero_unresolved_cross_split_semantic_near_dups"] is True
    assert acc["zero_cross_split_template_families"] is True
    assert acc["zero_duplicated_ocr_fixture_across_splits"] is True
    assert acc["phase1_pass"] is True
    # Dev-internal canary repeats may appear as within-split duplicates; they must not be cross-split.
    for g in report.get("exact_duplicate_groups") or []:
        if set(g.get("case_ids") or []) & {
            "knowledge-001",
            "knowledge-006",
            "knowledge-011",
        }:
            assert g.get("cross_split") is False


def test_a2_batch_is_sealed() -> None:
    summary = json.loads((A2 / "summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "SEALED"
    assert summary["seal_eligible_any"] is True
    assert summary["batch_seal"] is True
    assert summary["a2_retain_count"] == PHYSICAL_RETAIN
    assert summary["independently_scored_unit_count"] == INDEPENDENTLY_SCORED
    assert set(summary["ids_removed_from_seal_path_this_round"]) == IDS_REMOVED_THIS_ROUND
    seal = json.loads((A2 / "seal.json").read_text(encoding="utf-8"))
    assert seal["schema"] == "legalbot.a2-batch-seal.v1"
    assert seal["status"] == "SEALED"
    assert len(seal["included_row_ids"]) == PHYSICAL_RETAIN
    assert set(seal["excluded_row_ids"]) == PROPOSED_REMOVE
    assert seal["live_e2e_run"] is False
    checklist = (A2 / "PROPOSED-SEAL-CHECKLIST.md").read_text(encoding="utf-8")
    assert "SEALED" in checklist
    assert "legalbot:non-ingestible" in checklist
    names = {p.name.lower() for p in A2.iterdir()}
    assert "sealed-manifest.json" not in names
    assert "sealed-manifest.jsonl" not in names
    assert "a2-batch-seal-v1.json" not in names
    assert not any("seal-hash" in n or n.endswith(".sig") for n in names)
    assert "seal.json" in names


def test_ingestion_exclusion_lists_backlog_and_owner_decisions() -> None:
    text = (A2 / "INGESTION-EXCLUSION.md").read_text(encoding="utf-8")
    for needle in (
        "ocr-fixture-backlog.json",
        "OCR-FIXTURE-BACKLOG.md",
        "mixed-safe-unsafe-backlog.json",
        "MIXED-SAFE-UNSAFE-BACKLOG.md",
        "a2-repeat-groups.json",
        "bucket-a2-owner-decisions-2026-08-13.json",
        "bucket-a2-owner-decisions-2026-08-13.md",
        "PROPOSED-SEAL-CHECKLIST.md",
        "OWNER-VIEW-A2.md",
        "A2-OWNER-REVIEW.md",
    ):
        assert needle in text


def _py_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*.py") if "__pycache__" not in p.parts]


def test_production_loaders_do_not_reference_owner_review_or_backlog() -> None:
    hits: list[str] = []
    for directory in LOADER_DIRS:
        for path in _py_files(directory):
            source = path.read_text(encoding="utf-8")
            for marker in FORBIDDEN_INGEST_MARKERS:
                if marker in source:
                    hits.append(f"{path.relative_to(ROOT)}:{marker}")
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    val = node.value
                    if "OWNER-VIEW" in val or "ocr-fixture-backlog" in val:
                        hits.append(f"{path.relative_to(ROOT)}:const:{val}")
                    if "mixed-safe-unsafe-backlog" in val:
                        hits.append(f"{path.relative_to(ROOT)}:const:{val}")
                    if "data/review_queue/expert-review" in val and "gaps" not in val:
                        hits.append(f"{path.relative_to(ROOT)}:const:{val}")
                    if (
                        "a2-intentional-abstention" in val
                        and "manifest.jsonl" not in val
                        and any(
                            x in val
                            for x in (
                                "OWNER-VIEW",
                                "A2-OWNER-REVIEW",
                                "OCR-FIXTURE",
                                "PROPOSED-SEAL",
                                "MIXED-SAFE",
                            )
                        )
                    ):
                        hits.append(f"{path.relative_to(ROOT)}:const:{val}")
    assert hits == []


def test_default_source_roots_exclude_review_and_a2_sidecar() -> None:
    from app.config import Settings

    roots = [str(p) for p in Settings().source_roots]
    joined = " ".join(roots)
    assert "mlx-lm-main" not in joined
    assert "New_materials" not in joined
    assert "review_queue" not in joined
    assert "a2-intentional-abstention" not in joined
    assert "OWNER-VIEW" not in joined


def test_ocr_backlog_preserves_ids_and_is_non_ingestible() -> None:
    payload = json.loads((A2 / "ocr-fixture-backlog.json").read_text(encoding="utf-8"))
    assert set(payload["ids"]) == OCR_PROPOSED_REMOVE
    assert payload["ingestible"] is False
    assert payload["owner_approved"] is False
    assert payload["seal_eligible"] is False
    md = (A2 / "OCR-FIXTURE-BACKLOG.md").read_text(encoding="utf-8")
    assert "legalbot:non-ingestible" in md
    for cid in OCR_PROPOSED_REMOVE:
        assert cid in md


def test_owner_approval_and_no_proposed_remove_in_active_loader() -> None:
    rows = _manifest()
    suite = load_evaluation_suite(SUITE, require_complete=False)
    by_case = {c.case_id: c for c in suite.cases}
    for r in rows:
        if r.get("a2_membership") == "retain":
            assert r.get("seal_eligible") is True
        else:
            assert r.get("seal_eligible") is False
        if r["a2_membership"] == "retain":
            assert r.get("owner_approved") is True
            assert by_case[r["id"]].a2_membership == "retain"
        elif r["id"] in MIXED_PROPOSED_REMOVE:
            assert r.get("owner_approved") is True
            assert by_case[r["id"]].a2_membership == "proposed_remove"
            assert by_case[r["id"]].preferred_behavior is None
        elif r["a2_membership"] == "proposed_remove":
            assert r.get("owner_approved") is False
            assert by_case[r["id"]].a2_membership == "proposed_remove"
            assert by_case[r["id"]].preferred_behavior is None


def test_no_repeat_canary_independent_score_weight_one() -> None:
    rows = _manifest()
    suite = load_evaluation_suite(SUITE, require_complete=False)
    bad = [
        r["id"]
        for r in rows
        if r.get("evaluation_role") == "repeat_stability_canary"
        and r.get("independent_score_weight") == 1
    ]
    assert bad == []
    bad_suite = [
        c.case_id
        for c in suite.cases
        if c.evaluation_role == "repeat_stability_canary" and c.independent_score_weight == 1
    ]
    assert bad_suite == []
