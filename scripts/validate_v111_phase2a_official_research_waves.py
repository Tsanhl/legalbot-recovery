#!/usr/bin/env python3
"""Validate bounded human-readable official-source research wave records.

Wave files contain locator-level research leads only.  This validator prevents
them from being mistaken for owner decisions or exact byte-bound spans and
cross-checks every row against the sealed 316-row research queue.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKING_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2A-2026-08-27-remediation-working-r1"
)
DEFAULT_QUEUE = WORKING_ROOT / "OFFICIAL-SOURCE-RESEARCH-QUEUE-316.json"
DEFAULT_WAVE_ROOT = WORKING_ROOT
EXPECTED_QUEUE_CONTENT_SHA256 = "155af28ca81bb6848a875fab8173e0f646339282d695d2ae61edece143bda7a5"
ALLOWED_HOSTS = {
    "caselaw.nationalarchives.gov.uk",
    "www.legislation.gov.uk",
    "legislation.gov.uk",
    "www.supremecourt.uk",
    "supremecourt.uk",
    "www.jcpc.uk",
    "jcpc.uk",
    "publications.parliament.uk",
    "eur-lex.europa.eu",
    "hudoc.echr.coe.int",
    "www.justice.gov.uk",
    "justice.gov.uk",
    "www.judiciary.uk",
    "judiciary.uk",
    "www.handbook.fca.org.uk",
    "handbook.fca.org.uk",
    "www.gov.uk",
    "gov.uk",
    "www.wada-ama.org",
    "wada-ama.org",
    "www.tas-cas.org",
    "tas-cas.org",
    "www.sra.org.uk",
    "sra.org.uk",
}
SUPPORT_FITS = {"FULL", "PARTIAL", "NONE"}
REQUIRED_FALSE_FLAGS = {
    "owner_outcomes_applied",
    "source_admitted",
    "candidate_mutated",
    "embedding_run",
    "phase2b_authorized",
}


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sealed(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _load_queue(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_research_wave_queue_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_research_wave_queue_must_be_object")
    supplied = str(value.get("artifact_content_sha256") or "")
    material = dict(value)
    material.pop("artifact_content_sha256", None)
    if supplied != EXPECTED_QUEUE_CONTENT_SHA256 or supplied != _sealed(material):
        raise ValueError("phase2a_research_wave_queue_seal_invalid")
    return value


def _contains_exact_text(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if str(key) in {"exact_text", "exact_span_text", "quoted_text"}:
                return True
            if _contains_exact_text(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_exact_text(item) for item in value)
    return False


def _validate_authority(authority: Mapping[str, Any]) -> None:
    url = authority.get("official_url")
    locators = authority.get("exact_locators")
    if url is None:
        if authority.get("source_admission_required") not in {"unknown", None}:
            raise ValueError("phase2a_research_wave_missing_official_url_invalid")
        return
    parsed = urlsplit(str(url))
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").casefold() not in ALLOWED_HOSTS
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.port not in (None, 443)
    ):
        raise ValueError("phase2a_research_wave_official_url_invalid")
    if not isinstance(locators, list) or any(
        not isinstance(locator, str) or not locator.strip() for locator in locators
    ):
        raise ValueError("phase2a_research_wave_locator_invalid")
    if authority.get("candidate_existing") not in {True, False, "unknown"}:
        raise ValueError("phase2a_research_wave_candidate_membership_invalid")
    if authority.get("source_admission_required") not in {True, False, "unknown"}:
        raise ValueError("phase2a_research_wave_source_admission_flag_invalid")


def _safety_flag(wave: Mapping[str, Any], name: str) -> Any:
    nested = wave.get("safety_flags")
    nested_value = nested.get(name) if isinstance(nested, Mapping) else None
    direct_present = name in wave
    if direct_present and nested_value is not None and wave.get(name) != nested_value:
        raise ValueError("phase2a_research_wave_safety_flag_conflict")
    return wave.get(name) if direct_present else nested_value


def validate_waves(*, queue_path: Path, wave_paths: list[Path]) -> dict[str, Any]:
    queue = _load_queue(queue_path)
    queue_records = {
        str(record["row_id"]): record
        for record in queue.get("records", [])
        if isinstance(record, Mapping)
    }
    if len(queue_records) != 316:
        raise ValueError("phase2a_research_wave_queue_scope_invalid")
    seen: dict[str, str] = {}
    wave_summaries: list[dict[str, Any]] = []
    for path in sorted(wave_paths):
        if path.is_symlink() or not path.is_file():
            raise ValueError("phase2a_research_wave_must_be_regular_file")
        wave = json.loads(path.read_bytes())
        if not isinstance(wave, dict):
            raise ValueError("phase2a_research_wave_must_be_object")
        if (
            wave.get("source_queue_content_sha256") != EXPECTED_QUEUE_CONTENT_SHA256
            or _safety_flag(wave, "advisory_only") is not True
            or any(_safety_flag(wave, flag) is not False for flag in REQUIRED_FALSE_FLAGS)
            or _contains_exact_text(wave)
        ):
            raise ValueError("phase2a_research_wave_boundary_invalid")
        records = wave.get("records")
        if not isinstance(records, list) or not records:
            raise ValueError("phase2a_research_wave_records_invalid")
        wave_rows: list[str] = []
        for record in records:
            if not isinstance(record, Mapping):
                raise ValueError("phase2a_research_wave_record_invalid")
            row_id = str(record.get("row_id") or "")
            expected = queue_records.get(row_id)
            if expected is None:
                raise ValueError("phase2a_research_wave_row_outside_queue")
            if row_id in seen:
                raise ValueError("phase2a_research_wave_duplicate_row")
            if record.get("queue_record_content_sha256") != expected.get("record_content_sha256"):
                raise ValueError("phase2a_research_wave_row_identity_invalid")
            components = record.get("atomic_components")
            unresolved = record.get("unresolved_holds")
            if (
                not isinstance(components, list)
                or not components
                or not isinstance(unresolved, list)
                or any(not isinstance(item, str) or not item.strip() for item in unresolved)
            ):
                raise ValueError("phase2a_research_wave_components_invalid")
            for component in components:
                if not isinstance(component, Mapping):
                    raise ValueError("phase2a_research_wave_component_invalid")
                authorities = component.get("authorities")
                if (
                    not str(component.get("proposition") or "").strip()
                    or component.get("support_fit") not in SUPPORT_FITS
                    or not isinstance(authorities, list)
                ):
                    raise ValueError("phase2a_research_wave_component_invalid")
                for authority in authorities:
                    if not isinstance(authority, Mapping):
                        raise ValueError("phase2a_research_wave_authority_invalid")
                    _validate_authority(authority)
            seen[row_id] = path.name
            wave_rows.append(row_id)
        wave_summaries.append(
            {"path": str(path), "record_count": len(wave_rows), "row_ids": wave_rows}
        )
    missing = sorted(set(queue_records) - set(seen))
    return {
        "schema": "legalbot.v111.phase2a.official-research-wave-validation.v1",
        "status": "PASS_INCOMPLETE" if missing else "PASS_COMPLETE",
        "wave_count": len(wave_summaries),
        "covered_row_count": len(seen),
        "missing_row_count": len(missing),
        "missing_row_ids": missing,
        "waves": wave_summaries,
        "owner_decisions_applied": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "embedding_run": False,
        "phase2b_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--wave-root", type=Path, default=DEFAULT_WAVE_ROOT)
    parser.add_argument("--wave", type=Path, action="append")
    args = parser.parse_args()
    paths = sorted(args.wave) if args.wave else sorted(args.wave_root.glob("research-live*.json"))
    result = validate_waves(queue_path=args.queue, wave_paths=paths)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
