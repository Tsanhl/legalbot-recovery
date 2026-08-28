"""Build privacy-safe A2 test fixtures from the tracked draft suite.

These files are synthetic contract sidecars. They contain no owner-review
prose, no source paths and no live evaluation artefacts. Do not copy
``data/evaluation/``.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SUITE = ROOT / "benchmarks/evaluation/v1/draft-suite.jsonl"
DEST = Path(__file__).resolve().parent / "a2-intentional-abstention"

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
OCR_014_019_FAMILIES = {
    "ocr-014": "ocr.promo.half_schedule_screenshot",
    "ocr-019": "ocr.holdout.wrong_language_ocr_pinpoints",
}
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
MIXED_BEHAVIOR = "answer_safe_remainder_and_refuse_unsafe"
MIXED_REQUIRED = ["state_safe_remainder_only", "refuse_unsafe_remainder"]
PHYSICAL_RETAIN = 57
INDEPENDENTLY_SCORED = 47


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _suite_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in SUITE.read_text(encoding="utf-8").splitlines():
        raw = json.loads(line)
        cid = str(raw["case_id"])
        if cid.startswith(("knowledge-", "ocr-", "privacy-")):
            rows.append(raw)
    if len(rows) != 70:
        raise SystemExit(f"expected 70 A2 suite rows, found {len(rows)}")
    return rows


def _manifest_row(raw: dict[str, object]) -> dict[str, object]:
    cid = str(raw["case_id"])
    membership = str(raw["a2_membership"])
    retain = membership == "retain"
    row: dict[str, object] = {
        "id": cid,
        "split": raw["split"],
        "a2_membership": membership,
        "preferred_behavior": raw.get("preferred_behavior"),
        "allowed_behaviors": raw.get("allowed_behaviors"),
        "reason_code": raw.get("reason_code"),
        "required_response_elements": raw.get("required_response_elements"),
        "forbidden_response_elements": raw.get("forbidden_response_elements"),
        "evaluation_role": raw.get("evaluation_role"),
        "independent_score_weight": raw.get("independent_score_weight"),
        "repeat_group_id": raw.get("repeat_group_id"),
        "canonical_case_id": raw.get("canonical_case_id"),
        "template_family": raw.get("a2_template_family"),
        "gold_spans": [],
        "gold_authority_ids": [],
        "gold_answer": None,
        "seal_eligible": retain,
        "owner_approved": retain,
    }
    if cid.startswith("knowledge-") and raw["split"] == "development":
        row["sidecar_metadata"] = {"trim_later": True}
    if cid.startswith("ocr-") and retain:
        row["recoverable"] = False
    if cid in MIXED_PROPOSED_REMOVE:
        row.update(
            {
                "owner_approved": True,
                "seal_eligible": False,
                "preferred_behavior": MIXED_BEHAVIOR,
                "required_response_elements": MIXED_REQUIRED,
                "safe_remainder_present": True,
                "proposed_target_family": "mixed_safe_unsafe_response",
                "reclassification_reason": "safe_remainder_requires_positive_legal_gold",
            }
        )
    if cid in OCR_PROPOSED_REMOVE:
        row.update(
            {
                "owner_approved": False,
                "seal_eligible": False,
                "proposed_target_family": "positive_ocr_or_document_understanding",
            }
        )
    if cid in OCR_014_019_FAMILIES:
        row.update(
            {
                "template_family": OCR_014_019_FAMILIES[cid],
                "reclassification_reason": "fixture_unavailable_for_recoverability_adjudication",
                "available_fixture": None,
                "recovery_attempted": False,
            }
        )
    return row


def build() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    suite_rows = _suite_rows()
    manifest = [_manifest_row(raw) for raw in suite_rows]
    retain_ids = [row["id"] for row in manifest if row["a2_membership"] == "retain"]
    if len(retain_ids) != PHYSICAL_RETAIN:
        raise SystemExit("retain count drifted from the tracked suite")
    independently = 0
    for row in manifest:
        if row["a2_membership"] != "retain":
            continue
        weight = row.get("independent_score_weight")
        independently += 1 if weight is None else int(weight)
    if independently != INDEPENDENTLY_SCORED:
        raise SystemExit("independently scored count drifted from the tracked suite")
    splits = Counter(str(row["split"]) for row in manifest if row["a2_membership"] == "retain")
    if dict(splits) != {"development": 35, "promotion": 11, "adversarial_holdout": 11}:
        raise SystemExit(f"retain splits drifted: {dict(splits)}")

    (DEST / "manifest.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in manifest),
        encoding="utf-8",
    )

    mixed_rows = [row for row in manifest if row["id"] in MIXED_PROPOSED_REMOVE]
    (DEST / "mixed-safe-unsafe-backlog.json").write_text(
        _canonical(
            {
                "ids": sorted(MIXED_PROPOSED_REMOVE),
                "ingestible": False,
                "seal_eligible": False,
                "owner_approved": True,
                "proposed_target_family": "mixed_safe_unsafe_response",
                "reclassification_reason": "safe_remainder_requires_positive_legal_gold",
                "rows": mixed_rows,
            }
        ),
        encoding="utf-8",
    )
    (DEST / "MIXED-SAFE-UNSAFE-BACKLOG.md").write_text(
        "legalbot:non-ingestible\n" + "\n".join(sorted(MIXED_PROPOSED_REMOVE)) + "\n",
        encoding="utf-8",
    )

    ocr_rows = [row for row in manifest if row["id"] in OCR_PROPOSED_REMOVE]
    (DEST / "ocr-fixture-backlog.json").write_text(
        _canonical(
            {
                "ids": sorted(OCR_PROPOSED_REMOVE),
                "ingestible": False,
                "owner_approved": False,
                "seal_eligible": False,
                "rows": ocr_rows,
            }
        ),
        encoding="utf-8",
    )
    (DEST / "OCR-FIXTURE-BACKLOG.md").write_text(
        "legalbot:non-ingestible\n" + "\n".join(sorted(OCR_PROPOSED_REMOVE)) + "\n",
        encoding="utf-8",
    )

    (DEST / "ocr-adjudication.json").write_text(
        _canonical(
            {
                "fixture_search_hits_count": 0,
                "phase4b_ids": ["ocr-014", "ocr-019"],
                "rows": [
                    {"id": "ocr-014", "outcome": "outcome_3_fixture_unavailable"},
                    {"id": "ocr-019", "outcome": "outcome_3_fixture_unavailable"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (DEST / "OCR-OWNER-REVIEW.md").write_text(
        "legalbot:non-ingestible\nocr-014\nocr-019\n",
        encoding="utf-8",
    )

    groups = []
    for group_id, (canonical, members) in REPEAT_GROUPS.items():
        groups.append(
            {
                "repeat_group_id": group_id,
                "canonical_case_id": canonical,
                "split": "development",
                "members": [{"id": member} for member in members],
            }
        )
    (DEST / "a2-repeat-groups.json").write_text(_canonical({"groups": groups}), encoding="utf-8")

    (DEST / "leakage-report.json").write_text(
        _canonical(
            {
                "acceptance": {
                    "zero_exact_cross_split_dups": True,
                    "zero_id_only_cross_split_variants": True,
                    "zero_unresolved_cross_split_semantic_near_dups": True,
                    "zero_cross_split_template_families": True,
                    "zero_duplicated_ocr_fixture_across_splits": True,
                    "phase1_pass": True,
                },
                "exact_duplicate_groups": [
                    {
                        "case_ids": ["knowledge-001", "knowledge-006", "knowledge-011"],
                        "cross_split": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    (DEST / "summary.json").write_text(
        _canonical(
            {
                "status": "SEALED",
                "seal_eligible_any": True,
                "batch_seal": True,
                "a2_retain_count": PHYSICAL_RETAIN,
                "independently_scored_unit_count": INDEPENDENTLY_SCORED,
                "ids_removed_from_seal_path_this_round": sorted(IDS_REMOVED_THIS_ROUND),
            }
        ),
        encoding="utf-8",
    )
    (DEST / "seal.json").write_text(
        _canonical(
            {
                "schema": "legalbot.a2-batch-seal.v1",
                "status": "SEALED",
                "included_row_ids": retain_ids,
                "excluded_row_ids": sorted(PROPOSED_REMOVE),
                "live_e2e_run": False,
            }
        ),
        encoding="utf-8",
    )
    (DEST / "PROPOSED-SEAL-CHECKLIST.md").write_text(
        "SEALED\nlegalbot:non-ingestible\n",
        encoding="utf-8",
    )
    (DEST / "INGESTION-EXCLUSION.md").write_text(
        "\n".join(
            [
                "legalbot:non-ingestible",
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
                "",
            ]
        ),
        encoding="utf-8",
    )
    (DEST / "README.txt").write_text(
        "Synthetic A2 contract fixtures for clean-checkout tests.\n"
        "Not owner-review material. Not ingestible. Not live evaluation data.\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    build()
    print(DEST.relative_to(ROOT))
