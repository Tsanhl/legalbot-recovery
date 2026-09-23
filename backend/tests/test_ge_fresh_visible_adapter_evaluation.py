from __future__ import annotations

import json
from pathlib import Path

import app.evaluation.ge_fresh_visible_adapter_evaluation as fresh


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def test_static_fresh_visible_topology_is_complete_and_source_distinct() -> None:
    fresh._validate_static_contract()
    assert len(fresh.CASES) == 23
    assert len({case.topic for case in fresh.CASES}) == 23
    assert sum(case.coverage_kind == "LEGAL_TOPIC" for case in fresh.CASES) == 17
    assert sum(case.coverage_kind == "PUBLIC_ACCESS_DOMAIN" for case in fresh.CASES) == 6
    training_titles = {
        "Companies Act 2006",
        "Consumer Rights Act 2015",
        "Insolvency Act 1986",
        "Misrepresentation Act 1967",
        "Sale of Goods Act 1979",
        "Unfair Contract Terms Act 1977",
        "Administration of Estates Act 1925",
        "Wills Act 1837",
        "Wills Act 1837 (as at 2024-01-15)",
        "The Wills Act 1837 (Electronic Communications) (Amendment) (Coronavirus) Order 2020",
        "The Wills Act 1837 (Electronic Communications) (Amendment) Order 2022",
        "Equality Act 2010",
        "The Public Sector Bodies (Websites and Mobile Applications) (No. 2) "
        "Accessibility Regulations 2018",
    }
    assert not training_titles & {source.title for source in fresh.SOURCES}


def test_official_source_parser_requires_revised_point_in_time_text() -> None:
    spec = fresh.SOURCES[0]
    texts = "".join(
        f"<Text xmlns='{fresh.LEG_NS}'>proposition {index}</Text>" for index in range(1, 15)
    )
    xml = f"""<?xml version='1.0'?>
    <Legislation xmlns='{fresh.LEG_NS}'
      xmlns:dc='{fresh.DC_NS}' xmlns:dct='{fresh.DCT_NS}' xmlns:meta='{fresh.META_NS}'>
      <Metadata><dc:title>{spec.title}</dc:title><dc:modified>2026-09-03</dc:modified>
      <dct:valid>2026-09-03</dct:valid><meta:DocumentStatus Value='revised'/></Metadata>
      <Body><P1group><P1><P1para>{texts}</P1para></P1></P1group></Body>
    </Legislation>""".encode()
    row = fresh._parse_source(
        spec,
        xml,
        {"Last-Modified": "Thu, 03 Sep 2026 16:52:26 GMT"},
        spec.url,
    )
    assert row["title"] == spec.title
    assert row["document_status"] == "revised"
    assert row["evidence_excerpt"].startswith("proposition 1")
    assert row["runtime_admitted"] is False


def _make_finalization_fixture(root: Path, *, adapter_hold: bool) -> None:
    root.mkdir()
    (root / "official-source-snapshots").mkdir()
    for index in range(24):
        (root / "official-source-snapshots" / f"{index:064x}.xml").write_text("<source/>")
    case_rows = []
    control_rows = []
    base_rows = []
    adapter_rows = []
    evidence_hash = "a" * 64
    for ordinal, case in enumerate(fresh.CASES, 1):
        case_rows.append(
            {
                "ordinal": ordinal,
                "case_id": case.case_id,
                "topic": case.topic,
                "coverage_kind": case.coverage_kind,
                "question": case.question,
                "question_hash": f"{ordinal:064x}",
                "evidence_references": [{"evidence_span_sha256": evidence_hash}],
            }
        )
        control_rows.append(
            {
                "case_id": case.case_id,
                "required_points": list(case.required_points),
                "material_limits": list(case.material_limits),
                "prohibited_overclaims": list(case.prohibited_overclaims),
            }
        )
        base_rows.append(
            {
                "case_id": case.case_id,
                "candidate_variant": "BASE",
                "candidate_answer": f"base answer {ordinal}",
                "candidate_answer_hash": f"b{ordinal:063x}",
            }
        )
        adapter_rows.append(
            {
                "case_id": case.case_id,
                "candidate_variant": "R2_ADAPTER",
                "candidate_answer": f"adapter answer {ordinal}",
                "candidate_answer_hash": f"c{ordinal:063x}",
            }
        )
    _write_jsonl(root / "FRESH-VISIBLE-CASES.jsonl", case_rows)
    _write_jsonl(root / "EXPECTED-CONTROLS.jsonl", control_rows)
    _write_jsonl(root / "BASE-OUTPUTS.jsonl", base_rows)
    _write_jsonl(root / "R2-ADAPTER-OUTPUTS.jsonl", adapter_rows)
    (root / "PREPARATION-MANIFEST.json").write_text("{}\n")
    fresh.build_blind_workbook(root)
    mapping = {
        (row["case_id"], row["blind_label"]): row["candidate_variant"]
        for row in fresh.load_jsonl(root / "BLIND-MAP.jsonl")
    }
    reviews = []
    for row in fresh.load_jsonl(root / "BLIND-REVIEW-WORKBOOK.jsonl"):
        is_held_adapter = (
            adapter_hold
            and mapping[(row["case_id"], row["blind_label"])] == "R2_ADAPTER"
            and row["case_id"] == fresh.CASES[0].case_id
        )
        checks = {name: "PASS" for name in fresh.FACTUAL_CHECKS}
        claims = [
            {
                "claim": "supported proposition",
                "support_status": "SUPPORTED",
                "evidence_span_sha256": [evidence_hash],
            }
        ]
        if is_held_adapter:
            checks["claim_evidence_support"] = "FAIL"
            claims[0]["support_status"] = "UNSUPPORTED"
            claims[0]["evidence_span_sha256"] = []
        scores = (
            {}
            if is_held_adapter
            else {
                "legal_and_factual_accuracy": 20,
                "issue_coverage_and_reasoning": 11,
                "authority_and_currentness": 12,
                "practical_steps_and_urgency": 10,
                "uncertainty_limits_and_clarification": 8,
                "organisation_and_plain_language": 8,
                "traceability_and_citations": 8,
            }
        )
        reviews.append(
            {
                "case_id": row["case_id"],
                "blind_label": row["blind_label"],
                "candidate_answer_hash": row["candidate_answer_hash"],
                "reviewer_kind": "AI_MODEL_REVIEWER",
                "professional_legal_sign_off": False,
                "material_proposition_coverage_complete": True,
                "material_claims": claims,
                "factual_checks": checks,
                "factual_outcome": "FACTUAL_HOLD" if is_held_adapter else "FACTUAL_PASS",
                "quality_dimensions": scores,
                "quality_score": None if is_held_adapter else 77.0,
                "quality_outcome": (
                    "NOT_SCORED_FACTUAL_HOLD" if is_held_adapter else "MEETS_70_STANDARD"
                ),
            }
        )
    _write_jsonl(root / "CODEX-BLIND-REVIEW.jsonl", reviews)


def test_finalize_passes_only_when_every_adapter_case_passes(tmp_path: Path) -> None:
    passing = tmp_path / "passing"
    _make_finalization_fixture(passing, adapter_hold=False)
    result = fresh.finalize_campaign(passing)
    assert result["adapter_pass"] is True
    assert result["overall_state"].endswith("AWAITING_UNSEEN_AUTHORIZATION")

    held = tmp_path / "held"
    _make_finalization_fixture(held, adapter_hold=True)
    result = fresh.finalize_campaign(held)
    assert result["adapter_pass"] is False
    assert result["overall_state"].endswith("VISIBLE_REPAIR_REQUIRED")
