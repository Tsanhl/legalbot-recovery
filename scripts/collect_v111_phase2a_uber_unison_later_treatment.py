#!/usr/bin/env python3
"""Collect bounded official later-treatment evidence for Uber and UNISON rows."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import (  # noqa: E402
    collect_v111_phase2a_direct_hold_later_treatment as base,
)

DEFAULT_PLAN = PROJECT_ROOT / "config/phase2a_uber_unison_later_treatment.2026-08-27.v1.json"
DEFAULT_QUARANTINE = (
    PROJECT_ROOT / "data/quarantine/2026-08-27/phase2a-uber-unison-later-treatment-r2"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2A-2026-08-27-remediation-working-r1"
    / "UBER-UNISON-LATER-TREATMENT-ADVISORY-4-ROWS-r2.json"
)
EXPECTED_PLAN_FILE_SHA256 = "9c220c0482db6826dc95dd165381364c2020416ea35f3dbb757738a5610160bf"


def _load_plan(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_uber_unison_plan_must_be_regular_file")
    if base._sha256_file(path) != EXPECTED_PLAN_FILE_SHA256:
        raise ValueError("phase2a_uber_unison_plan_identity_invalid")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_uber_unison_plan_must_be_object")
    return value


def _validate_plan(plan: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    targets = plan.get("targets")
    if (
        plan.get("schema") != "legalbot.v111.phase2a.uber-unison-later-treatment-plan.v1"
        or plan.get("purpose")
        != "TARGETED_NON_BULK_EXACT_CITATION_LATER_TREATMENT_FOR_UBER_AND_UNISON_DIRECT_ROWS"
        or plan.get("source_ceiling_date") != "2026-08-14"
        or plan.get("as_of_date") != "2026-08-14"
        or plan.get("bulk_search") is not False
        or plan.get("automatic_source_admission") is not False
        or plan.get("automatic_indexing") is not False
        or plan.get("automatic_embedding") is not False
        or plan.get("owner_outcomes_applied") is not False
        or plan.get("candidate_mutated") is not False
        or plan.get("technical_qualification_assigned") is not False
        or plan.get("phase2b_authorized") is not False
        or not isinstance(targets, list)
        or len(targets) != 2
    ):
        raise ValueError("phase2a_uber_unison_plan_boundary_invalid")
    expected_rows = {
        "live60-q31:issue-01",
        "live60-q31:issue-02",
        "live30-q27:issue-02",
        "live30-q27:issue-08",
    }
    clean: list[dict[str, Any]] = []
    rows: set[str] = set()
    citations: set[str] = set()
    urls: set[str] = set()
    candidate_count = 0
    for raw_target in targets:
        if not isinstance(raw_target, Mapping):
            raise ValueError("phase2a_uber_unison_target_invalid")
        target = dict(raw_target)
        citation = str(target.get("target_neutral_citation") or "")
        row_ids = target.get("row_ids")
        candidates = target.get("candidates")
        if (
            not citation.startswith("[")
            or citation in citations
            or not isinstance(row_ids, list)
            or not row_ids
            or any(not isinstance(row, str) or row in rows for row in row_ids)
            or not isinstance(candidates, list)
            or not candidates
            or not str(target.get("recommended_owner_outcome") or "").strip()
        ):
            raise ValueError("phase2a_uber_unison_target_invalid")
        clean_candidates: list[dict[str, Any]] = []
        for raw_candidate in candidates:
            if not isinstance(raw_candidate, Mapping):
                raise ValueError("phase2a_uber_unison_candidate_invalid")
            candidate = dict(raw_candidate)
            url = base._safe_url(str(candidate.get("official_url") or ""))
            paragraph_ids = candidate.get("exact_paragraph_ids")
            if (
                url in urls
                or candidate.get("candidate_existing") not in {True, False}
                or not str(candidate.get("neutral_citation") or "").startswith("[")
                or not str(candidate.get("title") or "").strip()
                or not str(candidate.get("advisory_relationship") or "").strip()
                or not isinstance(paragraph_ids, list)
                or not paragraph_ids
                or any(
                    not isinstance(value, str) or base._PARAGRAPH_ID.fullmatch(value) is None
                    for value in paragraph_ids
                )
            ):
                raise ValueError("phase2a_uber_unison_candidate_invalid")
            candidate["official_url"] = url
            clean_candidates.append(candidate)
            urls.add(url)
            candidate_count += 1
        target["candidates"] = clean_candidates
        clean.append(target)
        citations.add(citation)
        rows.update(row_ids)
    if rows != expected_rows or candidate_count != 4:
        raise ValueError("phase2a_uber_unison_scope_invalid")
    return tuple(clean)


def _paragraph_spans(
    root: Any, paragraph_ids: list[str], *, source_sha256: str
) -> list[dict[str, Any]]:
    """Bind paragraphs from either eId-bearing or legacy number-only AKN XML."""

    namespace = {"akn": base.AKN_NS}
    spans: list[dict[str, Any]] = []
    for paragraph_id in paragraph_ids:
        matches = root.xpath(f'.//akn:paragraph[@eId="{paragraph_id}"]', namespaces=namespace)
        locator_method = "AKN_EID"
        if not matches:
            number = paragraph_id.removeprefix("para_")
            matches = []
            for paragraph in root.xpath(".//akn:paragraph[akn:num]", namespaces=namespace):
                values = paragraph.xpath("./akn:num//text()", namespaces=namespace)
                normalized = "".join(values).strip().strip("[]. ")
                if normalized == number:
                    matches.append(paragraph)
            locator_method = "AKN_CHILD_NUM"
        if len(matches) != 1:
            raise ValueError("phase2a_uber_unison_exact_paragraph_missing")
        exact_text = " ".join("".join(matches[0].itertext()).split())
        if not 20 <= len(exact_text) <= 20_000:
            raise ValueError("phase2a_uber_unison_exact_paragraph_invalid")
        material = {
            "schema": "legalbot.v111.phase2a.uber-unison-exact-span.v1",
            "source_sha256": source_sha256,
            "paragraph_id": paragraph_id,
            "locator_method": locator_method,
            "exact_text": exact_text,
            "exact_text_sha256": base._sha256(exact_text.encode("utf-8")),
            "exact_text_is_contiguous_in_official_xml": True,
        }
        spans.append({**material, "span_content_sha256": base._sealed(material)})
    return spans


def collect(*, plan_path: Path, quarantine_root: Path, output_path: Path) -> dict[str, Any]:
    if quarantine_root.exists() or quarantine_root.is_symlink():
        raise ValueError("phase2a_uber_unison_quarantine_already_exists")
    if output_path.exists() or output_path.is_symlink():
        raise ValueError("phase2a_uber_unison_output_already_exists")
    targets = _validate_plan(_load_plan(plan_path))
    quarantine_root.mkdir(parents=True, mode=0o700)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    client = httpx.Client(
        timeout=httpx.Timeout(45.0),
        follow_redirects=False,
        headers={"User-Agent": base.USER_AGENT},
    )
    try:
        for target in targets:
            citation = str(target["target_neutral_citation"])
            search_url = base._search_url(citation)
            search_raw = base._fetch(client, search_url, atom=True)
            search_sha256 = base._sha256(search_raw)
            search_name = f"search-{search_sha256[:20]}.atom.xml"
            base._write_exclusive(quarantine_root / search_name, search_raw)
            search = base._search_evidence(search_raw, target)
            candidates: list[dict[str, Any]] = []
            for candidate in target["candidates"]:
                raw = base._fetch(client, str(candidate["official_url"]))
                source_sha256 = base._sha256(raw)
                found_citation, judgment_date, root = base._judgment_metadata(raw)
                if found_citation != candidate["neutral_citation"]:
                    raise ValueError("phase2a_uber_unison_candidate_citation_mismatch")
                member_name = f"judgment-{source_sha256[:20]}.xml"
                base._write_exclusive(quarantine_root / member_name, raw)
                material = {
                    "schema": "legalbot.v111.phase2a.uber-unison-candidate-review.v1",
                    "neutral_citation": found_citation,
                    "title": candidate["title"],
                    "judgment_date": judgment_date.isoformat(),
                    "official_url": candidate["official_url"],
                    "official_source_sha256": source_sha256,
                    "official_source_bytes": len(raw),
                    "quarantine_relative_path": str(
                        (quarantine_root / member_name).relative_to(PROJECT_ROOT)
                    ),
                    "candidate_existing": candidate["candidate_existing"],
                    "source_admission_required_for_treatment_only": False,
                    "advisory_relationship": candidate["advisory_relationship"],
                    "exact_treatment_spans": _paragraph_spans(
                        root,
                        list(candidate["exact_paragraph_ids"]),
                        source_sha256=source_sha256,
                    ),
                    "owner_outcome": None,
                }
                candidates.append({**material, "record_content_sha256": base._sealed(material)})
            material = {
                "schema": "legalbot.v111.phase2a.uber-unison-target-review.v1",
                "target_neutral_citation": citation,
                "row_ids": target["row_ids"],
                "search_url": search_url,
                "search_sha256": search_sha256,
                "search_bytes": len(search_raw),
                "search_quarantine_relative_path": str(
                    (quarantine_root / search_name).relative_to(PROJECT_ROOT)
                ),
                "search_evidence": search,
                "candidate_reviews": candidates,
                "recommended_owner_outcome": target["recommended_owner_outcome"],
                "owner_outcome": None,
            }
            records.append({**material, "record_content_sha256": base._sealed(material)})
    finally:
        client.close()
    material = {
        "schema": "legalbot.v111.phase2a.uber-unison-later-treatment-advisory.v1",
        "status": "ADVISORY_ONLY_NOT_OWNER_ADOPTED",
        "created_at": datetime.now(UTC).isoformat(),
        "source_ceiling_date": "2026-08-14",
        "plan_file_sha256": EXPECTED_PLAN_FILE_SHA256,
        "record_count": len(records),
        "candidate_review_count": sum(len(record["candidate_reviews"]) for record in records),
        "records": records,
        "targeted_search_is_exhaustive": False,
        "absence_of_other_hits_proves_no_later_treatment": False,
        "owner_outcomes_applied": False,
        "automatic_source_admission": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "technical_qualification_assigned": False,
        "active_pointer_write_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
    }
    result = {**material, "artifact_content_sha256": base._sealed(material)}
    base._write_exclusive(output_path, base._pretty_json(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--quarantine-root", type=Path, default=DEFAULT_QUARANTINE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = collect(
        plan_path=args.plan,
        quarantine_root=args.quarantine_root,
        output_path=args.output,
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "record_count": result["record_count"],
                "candidate_review_count": result["candidate_review_count"],
                "artifact_content_sha256": result["artifact_content_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
