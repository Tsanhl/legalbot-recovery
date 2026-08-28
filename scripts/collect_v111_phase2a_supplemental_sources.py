#!/usr/bin/env python3
"""Collect a sealed, non-admitting supplemental Phase-2A source batch."""

from __future__ import annotations

import argparse
import io
import json
import re
import stat
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

if __package__:
    from scripts import collect_v111_phase2a_official_sources as official
else:
    import collect_v111_phase2a_official_sources as official

PLAN_SCHEMA = "legalbot.v111.phase2a.supplemental-official-source-plan.v1"
MANIFEST_SCHEMA = "legalbot.v111.phase2a.supplemental-source-quarantine.v1"
TARGET_CEILING = "2026-08-14T23:59:59+01:00 Europe/London"
_TARGET_DATE_PATH = re.compile(r"/2026-08-14/data\.xml$")
_AS_MADE_PATH = re.compile(r"/made/data\.xml$")


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_supplemental_plan_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_supplemental_plan_must_be_object")
    return value


def _sealed(value: Any) -> str:
    return official._sha256(official._canonical_json(value))


def _canonical_xml_sha256(raw: bytes) -> str:
    """Hash XML canonical form so representation-only changes are distinguishable."""

    try:
        canonical = ET.canonicalize(
            from_file=io.BytesIO(raw),
            with_comments=False,
        )
    except (ET.ParseError, UnicodeError, ValueError) as exc:
        raise ValueError("phase2a_supplemental_source_xml_invalid") from exc
    return official._sha256(canonical.encode("utf-8"))


def _validate_plan(plan: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    if (
        plan.get("schema") != PLAN_SCHEMA
        or plan.get("target_ceiling") != TARGET_CEILING
        or plan.get("automatic_source_admission") is not False
        or plan.get("automatic_gold_change") is not False
        or plan.get("automatic_indexing") is not False
        or plan.get("automatic_embedding") is not False
        or plan.get("candidate_mutation_authorized") is not False
        or plan.get("phase2b_authorized") is not False
        or plan.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_supplemental_plan_boundary_invalid")
    raw_targets = plan.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ValueError("phase2a_supplemental_plan_targets_invalid")
    targets: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in raw_targets:
        if not isinstance(value, dict):
            raise ValueError("phase2a_supplemental_target_invalid")
        target = dict(value)
        target_id = str(target.get("target_id") or "")
        url = official._safe_url(str(target.get("official_url") or ""))
        target_type = str(target.get("target_type") or "")
        representation_path_valid = (
            target_type == "point_in_time_legislation_xml"
            and _TARGET_DATE_PATH.search(url) is not None
        ) or (target_type == "as_made_legislation_xml" and _AS_MADE_PATH.search(url) is not None)
        if (
            not target_id
            or target_id in seen
            or not representation_path_valid
            or not str(target.get("authority_identity") or "").startswith(("ukpga:", "uksi:"))
            or not target.get("required_locators")
            or not target.get("affected_rows")
        ):
            raise ValueError("phase2a_supplemental_target_boundary_invalid")
        seen.add(target_id)
        target["official_url"] = url
        target["page"] = None
        targets.append(target)
    return tuple(targets)


def collect(*, plan_path: Path, quarantine_root: Path, run_id: str) -> dict[str, Any]:
    """Download official XML into a create-only quarantine and seal provenance."""

    if quarantine_root.exists() or quarantine_root.is_symlink():
        raise ValueError("phase2a_supplemental_quarantine_already_exists")
    quarantine_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(quarantine_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_supplemental_quarantine_mode_invalid")
    plan = _load_object(plan_path)
    targets = _validate_plan(plan)
    records: list[dict[str, Any]] = []
    with httpx.Client(
        follow_redirects=False,
        timeout=httpx.Timeout(30.0, connect=10.0),
        headers={"User-Agent": official.USER_AGENT, "Accept": "application/xml"},
        trust_env=False,
    ) as client:
        for ordinal, target in enumerate(targets, start=1):
            requested_url = str(target["official_url"])
            retrieved_at = datetime.now(UTC).isoformat(timespec="seconds")
            final_url, status, content_type, raw = official._fetch(client, requested_url)
            if status == 200:
                member = official._member_name(target, raw)
                official._write_exclusive(quarantine_root / member, raw)
                result = "DOWNLOADED_QUARANTINED_NOT_ADMITTED"
                error_code = None
                digest = official._sha256(raw)
                canonical_xml_digest = _canonical_xml_sha256(raw)
            else:
                member = None
                result = "OFFICIAL_SOURCE_UNAVAILABLE"
                error_code = f"http_{status}"
                digest = None
                canonical_xml_digest = None
            material = {
                "ordinal": ordinal,
                "target_id": target["target_id"],
                "target_type": target["target_type"],
                "authority_identity": target["authority_identity"],
                "source_title": target["source_title"],
                "requested_url": requested_url,
                "final_url": final_url,
                "required_locators": target["required_locators"],
                "affected_rows": target["affected_rows"],
                "research_reason": target["research_reason"],
                "http_status": status,
                "content_type": content_type,
                "retrieved_at": retrieved_at,
                "result": result,
                "error_code": error_code,
                "quarantine_member": member,
                "sha256": digest,
                "canonical_xml_sha256": canonical_xml_digest,
                "bytes": len(raw),
                "owner_source_admission_required": True,
                "automatically_admitted": False,
                "automatically_indexed": False,
                "automatically_embedded": False,
            }
            records.append({**material, "record_content_sha256": _sealed(material)})

    manifest_material = {
        "schema": MANIFEST_SCHEMA,
        "status": "SUPPLEMENTAL_OFFICIAL_BYTES_QUARANTINED_OWNER_REVIEW_REQUIRED",
        "run_id": run_id,
        "phase": "2A",
        "target_ceiling": TARGET_CEILING,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "source_plan_file_sha256": official._sha256(plan_path.read_bytes()),
        "source_plan_content_sha256": _sealed(plan),
        "quarantine_root_name": quarantine_root.name,
        "record_count": len(records),
        "result_counts": {
            state: sum(record["result"] == state for record in records)
            for state in sorted({str(record["result"]) for record in records})
        },
        "records": records,
        "owner_source_admission_required": True,
        "automatic_source_admission": False,
        "automatic_gold_change": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    manifest = {
        **manifest_material,
        "manifest_content_sha256": _sealed(manifest_material),
    }
    official._write_exclusive(
        quarantine_root / "QUARANTINE-MANIFEST.json",
        official._canonical_json(manifest),
    )
    return manifest


def _persist_failure(quarantine_root: Path, exc: BaseException) -> None:
    try:
        quarantine_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        failure_path = quarantine_root / "FAILURE.json"
        if failure_path.exists():
            return
        material = {
            "schema": "legalbot.v111.phase2a.supplemental-source-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        official._write_exclusive(
            failure_path,
            official._canonical_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except Exception:
        return


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--quarantine-root", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.quarantine_root.resolve()
    try:
        manifest = collect(
            plan_path=args.plan.resolve(strict=True),
            quarantine_root=root,
            run_id=str(args.run_id),
        )
    except Exception as exc:
        _persist_failure(root, exc)
        raise
    print(
        json.dumps(
            {
                "status": manifest["status"],
                "record_count": manifest["record_count"],
                "result_counts": manifest["result_counts"],
                "manifest_content_sha256": manifest["manifest_content_sha256"],
                "automatically_admitted": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
