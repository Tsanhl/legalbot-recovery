#!/usr/bin/env python3
"""Export a privacy-safe expert-review queue from the evaluation draft suite.

This helper never marks cases approved/sealed/expert_annotated, never flips
training_export_allowed, and never embeds query prose, student names, emails,
or absolute host paths in reviewer-facing artefacts.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUITE = PROJECT_ROOT / "benchmarks" / "evaluation" / "v1" / "draft-suite.jsonl"
DEFAULT_MANIFEST = PROJECT_ROOT / "benchmarks" / "evaluation" / "v1" / "manifest.json"
DEFAULT_OUT = PROJECT_ROOT / "data" / "review_queue" / "expert-review"

# Fail closed: reject absolute host paths and common PII in exported JSON text.
_MAC_PATH_RE = re.compile(r"/Users/[^/\r\n]+(?:/[^\r\n\]\[)>,;:'\"]+)+")
_WINDOWS_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\(?:[^\s\\]+\\)*[^\s\\]+")
_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at {path}:{line_number}: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"expected object at {path}:{line_number}")
        rows.append(row)
    return rows


def load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("manifest must be a JSON object")
    return payload


def assert_export_text_safe(text: str, *, context: str) -> None:
    """Fail closed if reviewer-facing text contains paths or emails."""
    if _MAC_PATH_RE.search(text) or _WINDOWS_PATH_RE.search(text):
        raise ValueError(f"export blocked ({context}): absolute host path detected")
    if _EMAIL_RE.search(text):
        raise ValueError(f"export blocked ({context}): email address detected")


def case_queue_row(case: dict[str, Any]) -> dict[str, Any]:
    """Project a suite case into a privacy-safe queue row (no query prose)."""
    spans = case.get("exact_gold_spans") or []
    if not isinstance(spans, list):
        spans = []
    sources = case.get("acceptable_source_ids") or []
    if not isinstance(sources, list):
        sources = []
    row = {
        "case_id": case.get("case_id"),
        "query_sha256": case.get("query_sha256"),
        "split": case.get("split"),
        "category": case.get("category"),
        "subject": case.get("subject"),
        "jurisdiction": case.get("jurisdiction"),
        "as_of_date": case.get("as_of_date"),
        "task_type": case.get("task_type"),
        "expected_behaviour": case.get("expected_behaviour"),
        "status": case.get("status"),
        "synthetic": case.get("synthetic"),
        "paraphrase_group": case.get("paraphrase_group"),
        "privacy_flags": list(case.get("privacy_flags") or []),
        "proposed_source_count": len(sources),
        "proposed_span_count": len(spans),
        "known_contrary_authority_count": len(case.get("known_contrary_authority_ids") or []),
        "must_cover_issue_count": len(case.get("must_cover_issues") or []),
        "forbidden_lane_count": len(case.get("forbidden_lanes") or []),
        "suite_version": case.get("suite_version"),
    }
    # Never carry query / teaching prose into the queue export.
    forbidden_keys = {"query", "notes", "reviewer_notes", "teaching_prose", "path", "source_path"}
    leaked = forbidden_keys.intersection(row)
    if leaked:
        raise ValueError(f"queue row leaked forbidden keys: {sorted(leaked)}")
    return row


def build_expert_review_queue(
    cases: list[dict[str, Any]],
    manifest: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build summary + privacy-safe case list. Does not mutate inputs or approve."""
    needing = [case for case in cases if case.get("status") == "needs_expert_annotation"]
    other_status = Counter(str(case.get("status")) for case in cases)

    split_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    subject_counts: Counter[str] = Counter()
    behaviour_counts: Counter[str] = Counter()
    by_split_category: dict[str, Counter[str]] = defaultdict(Counter)
    by_split_ids: dict[str, list[str]] = defaultdict(list)

    queue_rows = [case_queue_row(case) for case in needing]
    for row in queue_rows:
        split = str(row["split"] or "unknown")
        category = str(row["category"] or "unknown")
        split_counts[split] += 1
        category_counts[category] += 1
        subject_counts[str(row["subject"] or "unknown")] += 1
        behaviour_counts[str(row["expected_behaviour"] or "unknown")] += 1
        by_split_category[split][category] += 1
        by_split_ids[split].append(str(row["case_id"]))

    for ids in by_split_ids.values():
        ids.sort()
    queue_rows.sort(key=lambda item: (str(item["split"]), str(item["case_id"])))

    stamp = generated_at or datetime.now(UTC).replace(microsecond=0).isoformat()
    payload: dict[str, Any] = {
        "schema": "legalbot.expert-review-queue.v1",
        "generated_at": stamp,
        "purpose": "evaluation_only_independent_expert_annotation",
        "marks_cases_approved": False,
        "training_export_allowed": False,
        "promotion_eligible": False,
        "manifest_status": manifest.get("status"),
        "manifest_case_count": manifest.get("case_count"),
        "manifest_status_counts": manifest.get("status_counts"),
        "manifest_split_counts": manifest.get("split_counts"),
        "manifest_category_counts": manifest.get("category_counts"),
        "suite_version": manifest.get("suite_version"),
        "suite_file_sha256": manifest.get("suite_file_sha256"),
        "canonical_suite_sha256": manifest.get("canonical_suite_sha256"),
        "blocking_gate": manifest.get("blocking_gate"),
        "suite_case_count": len(cases),
        "needs_expert_annotation_count": len(needing),
        "status_counts_observed": dict(sorted(other_status.items())),
        "split_counts_needing_review": dict(sorted(split_counts.items())),
        "category_counts_needing_review": dict(sorted(category_counts.items())),
        "subject_counts_needing_review": dict(sorted(subject_counts.items())),
        "expected_behaviour_counts_needing_review": dict(sorted(behaviour_counts.items())),
        "by_split_category_needing_review": {
            split: dict(sorted(categories.items()))
            for split, categories in sorted(by_split_category.items())
        },
        "case_ids_by_split": dict(sorted(by_split_ids.items())),
        "cases_needing_review": queue_rows,
        "assessment_standards_note": (
            "Approved assessment-standard rows in the catalogue guide drafting only; "
            "they are not evaluation gold and do not satisfy independent expert annotation."
        ),
        "gates": {
            "training_export_allowed": False,
            "promotion_blocked_until_expert_seal": True,
            "find_case_law_unlock": False,
            "fabricated_expert_approvals_forbidden": True,
        },
    }
    serialised = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    assert_export_text_safe(serialised, context="queue summary")
    return payload


def decision_log_template_row() -> dict[str, Any]:
    return {
        "schema": "legalbot.expert-case-decision.v1",
        "case_id": "REPLACE_WITH_SUITE_CASE_ID",
        "query_sha256": "REPLACE_WITH_QUERY_SHA256",
        "split": "development|promotion|adversarial_holdout",
        "decision": "accept_proposed|replace_spans|remove_case|defer",
        "span_actions": [
            {
                "chunk_id": "chunk-…",
                "action": "accept|replace|remove",
                "replacement_chunk_id": None,
                "replacement_source_version_id": None,
                "character_start": None,
                "character_end": None,
                "content_hash": None,
                "exact_locator": None,
                "supported_issue_ids": [],
            }
        ],
        "contrary_authority_ids_added": [],
        "forbidden_lanes_confirmed": True,
        "privacy_attestation": ("notes_contain_no_student_names_emails_or_absolute_host_paths"),
        "reviewer_id_hash": "sha256-of-reviewer-pseudonym",
        "signed_at": None,
        "notes_vault_ref": None,
        "status_after_human_sign": "needs_expert_annotation",
        "comment": (
            "Leave status_after_human_sign as needs_expert_annotation until the "
            "legally qualified reviewer has truly finished and signed; only then "
            "set expert_annotated (development) or sealed (promotion/holdout) via "
            "the suite update process — never bulk-fabricate."
        ),
    }


def write_expert_review_queue(out_dir: Path, payload: dict[str, Any]) -> dict[str, str]:
    """Write queue artefacts under out_dir. Returns relative paths written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "by-split").mkdir(exist_ok=True)

    summary = {key: value for key, value in payload.items() if key != "cases_needing_review"}
    summary_path = out_dir / "summary.json"
    cases_path = out_dir / "cases-needing-review.jsonl"
    template_path = out_dir / "decision-log-template.jsonl"
    readme_path = out_dir / "README.md"

    summary_text = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    assert_export_text_safe(summary_text, context="summary.json")
    summary_path.write_text(summary_text, encoding="utf-8")

    lines = [
        json.dumps(row, ensure_ascii=False, sort_keys=True)
        for row in payload["cases_needing_review"]
    ]
    cases_body = "\n".join(lines) + ("\n" if lines else "")
    assert_export_text_safe(cases_body, context="cases-needing-review.jsonl")
    cases_path.write_text(cases_body, encoding="utf-8")

    for split, case_ids in sorted(payload["case_ids_by_split"].items()):
        split_payload = {
            "schema": "legalbot.expert-review-queue-split.v1",
            "split": split,
            "count": len(case_ids),
            "case_ids": case_ids,
            "category_counts": payload["by_split_category_needing_review"].get(split, {}),
            "marks_cases_approved": False,
            "training_export_allowed": False,
        }
        split_text = json.dumps(split_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        assert_export_text_safe(split_text, context=f"by-split/{split}.json")
        (out_dir / "by-split" / f"{split}.json").write_text(split_text, encoding="utf-8")

    template_text = (
        json.dumps(decision_log_template_row(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    assert_export_text_safe(template_text, context="decision-log-template.jsonl")
    template_path.write_text(template_text, encoding="utf-8")

    readme = """# Expert review queue (privacy-safe)

Generated by `scripts/export_expert_review_queue.py`.

## Contents

- `summary.json` — split/category/subject counts; gate flags; suite hashes
- `cases-needing-review.jsonl` — one row per case ID still needing expert annotation
- `by-split/*.json` — case ID lists per split
- `decision-log-template.jsonl` — copy rows into a private decision log when reviewing

## Hard rules

- This export does **not** approve, seal, or annotate any case.
- `training_export_allowed` remains **false**; promotion stays blocked until expert seal.
- Rows intentionally omit query prose and teaching text — open the suite by `case_id`.
- Do not paste student names, emails, or absolute host paths into shared notes.
- Approved assessment standards in the catalogue are **not** evaluation gold.

See `docs/reports/expert-reviewer-quickstart-2026-08-13.md`.
"""
    assert_export_text_safe(readme, context="README.md")
    readme_path.write_text(readme, encoding="utf-8")

    def _rel(target: Path) -> str:
        try:
            return str(target.resolve().relative_to(PROJECT_ROOT.resolve()))
        except ValueError:
            return str(target)

    written = {
        "summary": _rel(summary_path),
        "cases": _rel(cases_path),
        "template": _rel(template_path),
        "readme": _rel(readme_path),
    }
    for split in payload["case_ids_by_split"]:
        written[f"split:{split}"] = _rel(out_dir / "by-split" / f"{split}.json")
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    cases = load_jsonl(args.suite)
    manifest = load_manifest(args.manifest)
    payload = build_expert_review_queue(cases, manifest)
    written = write_expert_review_queue(args.out_dir, payload)
    report = {
        "ok": True,
        "needs_expert_annotation_count": payload["needs_expert_annotation_count"],
        "split_counts_needing_review": payload["split_counts_needing_review"],
        "category_counts_needing_review": payload["category_counts_needing_review"],
        "marks_cases_approved": False,
        "training_export_allowed": False,
        "promotion_eligible": False,
        "written": written,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
