#!/usr/bin/env python3
"""Build a deterministic official-source queue from the sealed 361-row ledger.

The queue replaces any temptation to restart the planner.  It carries forward
the human-readable proposition work, rejected lexical matches and exact local
evidence identities, then assigns a purely mechanical research route.  It does
not select a new authority or make a legal/owner decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER = PROJECT_ROOT / (
    "data/evaluations/phase2a-owner-review/"
    "LegalBot-Phase2A-2026-08-27-remediation-working-r1/"
    "PROPOSITION-RECONCILIATION-WORKING-LEDGER-361.json"
)
EXPECTED_LEDGER_CONTENT_SHA256 = (
    "62d56c8b34d1fc964dca1a5920ee49b87499471c187dbe82aa58ebee191737ce"
)
EXPECTED_LEDGER_FILE_SHA256 = (
    "bdc091b1a3b8de2febcbc14d86d8c88113ed112ca2bc28908eeb3e6d95ccc297"
)
EXPECTED_QUEUE_COUNT = 316

FALSE_GATES = {
    "official_research_performed": False,
    "new_source_selected": False,
    "automatic_source_admission": False,
    "automatic_indexing": False,
    "automatic_embedding": False,
    "candidate_mutated": False,
    "owner_decisions_applied": False,
    "technical_qualification_assigned": False,
    "phase2b_authorized": False,
}


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _content_sha256(value: dict[str, Any], field: str) -> str:
    payload = dict(value)
    payload.pop(field, None)
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _load_ledger(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("sealed 361-row proposition ledger unavailable")
    if path == DEFAULT_LEDGER and _sha256_file(path) != EXPECTED_LEDGER_FILE_SHA256:
        raise ValueError("sealed proposition-ledger file identity changed")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("proposition ledger must be a JSON object")
    if (
        value.get("schema")
        != "legalbot.v111.phase2a.proposition-reconciliation-working-ledger.v1"
        or value.get("status") != "COMPLETE_NON_AUTHORIZING_WORKING_LEDGER"
        or value.get("covered_row_count") != 361
        or value.get("missing_row_count") != 0
        or value.get("artifact_content_sha256")
        != EXPECTED_LEDGER_CONTENT_SHA256
        or _content_sha256(value, "artifact_content_sha256")
        != EXPECTED_LEDGER_CONTENT_SHA256
    ):
        raise ValueError("sealed proposition-ledger content identity changed")
    return value


def _route(record: dict[str, Any]) -> str | None:
    status = record["proposition_status"]
    fit = record["local_evidence_fit"]
    if status == "READY_FOR_EVIDENCE_REVIEW" and fit == "FULL":
        return None
    if status == "NEEDS_PROPOSITION_SPLIT":
        return "PROPOSITION_SPLIT_AND_EXACT_OFFICIAL_SOURCES_REQUIRED"
    if status == "NEEDS_LEGAL_RESEARCH":
        return "LEGAL_RESEARCH_AND_EXACT_OFFICIAL_SOURCES_REQUIRED"
    if status == "READY_FOR_EVIDENCE_REVIEW":
        return "EXACT_OFFICIAL_SOURCE_OR_SPAN_REQUIRED"
    raise ValueError(f"unsupported proposition status: {status}")


def build_queue(ledger_path: Path = DEFAULT_LEDGER) -> dict[str, Any]:
    ledger = _load_ledger(ledger_path)
    records: list[dict[str, Any]] = []
    route_counts: Counter[str] = Counter()
    fit_counts: Counter[str] = Counter()
    by_case: defaultdict[str, int] = defaultdict(int)
    for source in ledger["records"]:
        route = _route(source)
        if route is None:
            continue
        row = {
            "schema": "legalbot.v111.phase2a.official-source-research-queue-row.v1",
            "ordinal": source.get("ordinal"),
            "row_id": source["row_id"],
            "case_id": source["case_id"],
            "issue_id": source["issue_id"],
            "issue_label": source["issue_label"],
            "qualification_status": source["qualification_status"],
            "proposition_record_content_sha256": source["record_content_sha256"],
            "proposition_status": source["proposition_status"],
            "canonical_atomic_proposition": source.get(
                "canonical_atomic_proposition"
            ),
            "local_evidence_fit": source["local_evidence_fit"],
            "selected_local_evidence": source["selected_local_evidence"],
            "rejected_candidate_reasons": source["rejected_candidate_reasons"],
            "proposition_version_conflicts": source["proposition_version_conflicts"],
            "required_research": source["required_research"],
            "research_route": route,
            "official_primary_sources_only": True,
            "source_ceiling_date": "2026-08-14",
            "owner_outcome": None,
        }
        row["record_content_sha256"] = _content_sha256(
            row, "record_content_sha256"
        )
        records.append(row)
        route_counts[route] += 1
        fit_counts[source["local_evidence_fit"]] += 1
        by_case[source["case_id"]] += 1
    if len(records) != EXPECTED_QUEUE_COUNT:
        raise ValueError(f"official-source research queue count changed: {len(records)}")
    if len({record["row_id"] for record in records}) != len(records):
        raise ValueError("official-source research queue has duplicate rows")
    artifact: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.official-source-research-queue.v1",
        "status": "COMPLETE_NON_AUTHORIZING_OFFICIAL_SOURCE_RESEARCH_QUEUE",
        "source_proposition_ledger_content_sha256": ledger[
            "artifact_content_sha256"
        ],
        "source_proposition_ledger_file_sha256": _sha256_file(ledger_path),
        "row_count": len(records),
        "ready_full_rows_not_queued": 45,
        "research_route_counts": dict(sorted(route_counts.items())),
        "local_evidence_fit_counts": dict(sorted(fit_counts.items())),
        "case_row_counts": dict(sorted(by_case.items())),
        "records": records,
        **FALSE_GATES,
    }
    artifact["artifact_content_sha256"] = _content_sha256(
        artifact, "artifact_content_sha256"
    )
    return artifact


def write_new(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(_canonical_json(value))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    artifact = build_queue(args.ledger)
    if args.output is not None:
        write_new(args.output, artifact)
    print(
        json.dumps(
            {
                "artifact_content_sha256": artifact["artifact_content_sha256"],
                "ready_full_rows_not_queued": artifact[
                    "ready_full_rows_not_queued"
                ],
                "research_route_counts": artifact["research_route_counts"],
                "row_count": artifact["row_count"],
                "status": artifact["status"],
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
