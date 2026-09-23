#!/usr/bin/env python3
"""Build the ready-only human qualified-review routing pack."""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ID = "LegalBot-GE-2026-09-04-reconstructed-edit-rereview-r1"
CAMPAIGN_ID = "LegalBot-GE-2026-09-04-qualified-review-routing-r2"
SOURCE = PROJECT_ROOT / "data/evaluations/general-enquiries" / SOURCE_ID
OUTPUT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
DESKTOP_ZIP = (Path.home() / "Desktop") / f"{CAMPAIGN_ID}.zip"
COPY_FILES = (
    "QUALIFIED-REVIEW-READY-BLIND.jsonl",
    "QUALIFIED-REVIEW-DECISION-TEMPLATE.jsonl",
    "QUALIFIED-REVIEW-HANDOFF.md",
    "STATE-TRANSITION-RECEIPT.json",
    "TEST-RECEIPT.json",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    if path.exists():
        raise RuntimeError(f"refusing to replace existing artifact: {path}")
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def main() -> int:
    if OUTPUT.exists() or DESKTOP_ZIP.exists():
        raise RuntimeError("routing r2 already exists")
    OUTPUT.mkdir(parents=True, exist_ok=False)
    for name in COPY_FILES:
        source = SOURCE / name
        if not source.is_file():
            raise RuntimeError(f"missing routing source: {name}")
        shutil.copyfile(source, OUTPUT / name)
    ready = [
        json.loads(line)
        for line in (OUTPUT / "QUALIFIED-REVIEW-READY-BLIND.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    decisions = [
        json.loads(line)
        for line in (OUTPUT / "QUALIFIED-REVIEW-DECISION-TEMPLATE.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    tests = {
        "exactly_20_ready_rows": len(ready) == 20,
        "unique_ready_case_ids": len({row["case_id"] for row in ready}) == 20,
        "exactly_20_blank_decision_rows": len(decisions) == 20
        and all(not row["qualified_review_decision"] for row in decisions),
        "decision_case_ids_match": {row["case_id"] for row in ready}
        == {row["case_id"] for row in decisions},
        "no_ai_recommendation_fields": all(
            "ai_recommended_decision" not in row and "ai_advisory_recommendation" not in row
            for row in ready
        ),
        "nonready_records_not_included": not (OUTPUT / "NONREADY-ROUTING.jsonl").exists(),
        "professional_identity_blank": all(
            not row["reviewer_name"]
            and not row["reviewer_qualification"]
            and not row["reviewer_signature"]
            and row["professional_legal_sign_off"] is None
            for row in decisions
        ),
    }
    if not all(tests.values()):
        raise RuntimeError(f"routing r2 tests failed: {tests}")
    write_json(
        OUTPUT / "ROUTING-R2-TEST-RECEIPT.json",
        {"schema": "legalbot.ge-qualified-review-routing-r2-test.v1", "tests": tests, "pass": True},
    )
    source_hashes = {name: sha256(SOURCE / name) for name in COPY_FILES}
    write_json(
        OUTPUT / "ROUTING-MANIFEST.json",
        {
            "schema": "legalbot.ge-qualified-review-routing.v2",
            "campaign_id": CAMPAIGN_ID,
            "source_campaign_id": SOURCE_ID,
            "ready_rows": len(ready),
            "decision_rows": len(decisions),
            "nonready_rows_included": 0,
            "ai_recommendations_included": False,
            "professional_legal_sign_off": False,
            "qualified_legal_review": "NOT_STARTED",
            "answer_legal_gold": "NOT_STARTED",
            "source_artifact_hashes": source_hashes,
            "historical_r1_not_for_human_delivery": True,
        },
    )
    artifacts = {path.name: sha256(path) for path in sorted(OUTPUT.iterdir()) if path.is_file()}
    write_json(
        OUTPUT / "ARTIFACT-SHA256-REGISTER.json",
        {
            "schema": "legalbot.ge-qualified-review-routing-r2-hashes.v1",
            "campaign_id": CAMPAIGN_ID,
            "artifacts": artifacts,
        },
    )
    with zipfile.ZipFile(DESKTOP_ZIP, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(OUTPUT.iterdir()):
            if path.is_file():
                archive.write(path, arcname=str(Path(CAMPAIGN_ID) / path.name))
    print(
        json.dumps(
            {
                "campaign_id": CAMPAIGN_ID,
                "output": str(OUTPUT),
                "ready_rows": len(ready),
                "desktop_zip": str(DESKTOP_ZIP),
                "desktop_zip_sha256": sha256(DESKTOP_ZIP),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
