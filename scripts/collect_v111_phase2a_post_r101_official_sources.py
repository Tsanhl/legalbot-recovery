#!/usr/bin/env python3
"""Quarantine the exact official sources routed by the sealed r102 ledger.

This create-only collector derives its sixteen targets from r102, verifies
their identities against official XML, and emits paragraph/provision
extractions for proposition review.  It does not admit a source, change gold,
index, embed, mutate a candidate, qualify Phase 2A, or authorize another gate.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import httpx

if __package__:
    from scripts import collect_v111_phase2a_official_sources as official
else:
    import collect_v111_phase2a_official_sources as official

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R102_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r102-post-r101-research-routing"
    / "POST-R101-RESEARCH-ROUTING-364.json"
)
R71_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r71-gap-triage"
    / "ISSUE-GAP-TRIAGE-448.json"
)
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT
    / "data/quarantine/2026-08-26/phase2a-post-r101-official-source-research-r103"
)
TARGET_DATE = "2026-08-14"
TARGET_CEILING = "2026-08-14T23:59:59+01:00 Europe/London"
EXPECTED_IDENTITIES = {
    R102_PATH: (
        "artifact_content_sha256",
        "eef0de2cfb5e1be2ab9279c4acbe064f288cdfa24418d1d444b1d6830d18af0b",
        "a636daf079e44ab6e51ff98fae3c8ae375949f8054764b71c9697c85583f6062",
    ),
    R71_PATH: (
        "artifact_content_sha256",
        "d813a1fdc1b9b6f2d6c67b0ac2c113af696343cc8c619355c74ee8654beca475",
        "1e453c34e939a1d733bdcbae2243bf0bee4050b98ecb2220cd71628c46623f50",
    ),
}
EXPECTED_AUTHORITY_COUNT = 16
EXPECTED_ROW_LINK_COUNT = 26
ALLOWED_HOSTS = frozenset(
    {"caselaw.nationalarchives.gov.uk", "www.legislation.gov.uk"}
)
USER_AGENT = "LegalBot-v1.11-Phase2A-post-r101-official-source-research/1.0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EWCA = re.compile(
    r"^neutral-citation:\[(?P<year>\d{4})\] EWCA "
    r"(?P<division>Civ|Crim) (?P<number>\d+)$"
)
_EWHC = re.compile(
    r"^neutral-citation:\[(?P<year>\d{4})\] EWHC "
    r"(?P<number>\d+) \((?P<division>Comm|Ch)\)$"
)
_UKPGA = re.compile(r"^ukpga:(?P<year>\d{4}):(?P<number>\d+)$")
_PARAGRAPH_EID = re.compile(r"^para_(?P<number>\d+)$")
_BOUNDARY_FIELDS = (
    "technical_qualification_assigned",
    "source_admission_authorized",
    "automatic_indexing",
    "automatic_embedding",
    "candidate_mutated",
    "phase2b_authorized",
    "development30_authorized",
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load_verified(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_r103_input_must_be_regular_file")
    field, expected_content, expected_file = EXPECTED_IDENTITIES[path]
    if _sha256_file(path) != expected_file:
        raise ValueError("phase2a_r103_input_file_digest_invalid")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r103_input_must_be_object")
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if (
        not _SHA256.fullmatch(supplied)
        or supplied != expected_content
        or supplied != _sealed(material)
    ):
        raise ValueError("phase2a_r103_input_content_seal_invalid")
    return value


def _safe_url(value: str) -> str:
    safe = official._safe_url(value)
    parsed = httpx.URL(safe)
    if parsed.host not in ALLOWED_HOSTS:
        raise ValueError("phase2a_r103_url_outside_narrow_allowlist")
    return safe


def _authority_url(authority: str) -> str:
    ewca = _EWCA.fullmatch(authority)
    if ewca is not None:
        return _safe_url(
            "https://caselaw.nationalarchives.gov.uk/ewca/"
            f"{ewca.group('division').casefold()}/{ewca.group('year')}/"
            f"{int(ewca.group('number'))}/data.xml"
        )
    ewhc = _EWHC.fullmatch(authority)
    if ewhc is not None:
        return _safe_url(
            "https://caselaw.nationalarchives.gov.uk/ewhc/"
            f"{ewhc.group('division').casefold()}/{ewhc.group('year')}/"
            f"{int(ewhc.group('number'))}/data.xml"
        )
    ukpga = _UKPGA.fullmatch(authority)
    if ukpga is not None:
        return _safe_url(
            "https://www.legislation.gov.uk/ukpga/"
            f"{ukpga.group('year')}/{int(ukpga.group('number'))}/"
            f"{TARGET_DATE}/data.xml"
        )
    raise ValueError("phase2a_r103_authority_identity_unsupported")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _normal_text(element: ET.Element) -> str:
    return " ".join("".join(element.itertext()).replace("\u00a0", " ").split())


def _canonical_xml_sha256(raw: bytes) -> str:
    try:
        canonical = ET.canonicalize(from_file=io.BytesIO(raw), with_comments=False)
    except (ET.ParseError, UnicodeError, ValueError) as exc:
        raise ValueError("phase2a_r103_official_xml_invalid") from exc
    return _sha256(canonical.encode("utf-8"))


def _judgment_extraction(authority: str, raw: bytes) -> dict[str, Any]:
    root = official._xml_root(raw)
    if _local_name(root.tag) != "akomaNtoso":
        raise ValueError("phase2a_r103_judgment_xml_root_invalid")
    citation = authority.removeprefix("neutral-citation:")
    citations = {
        _normal_text(element)
        for element in root.iter()
        if _local_name(element.tag) in {"neutralCitation", "cite"}
    }
    if citation not in citations:
        raise ValueError("phase2a_r103_judgment_identity_mismatch")
    titles = [
        str(element.get("value"))
        for element in root.iter()
        if _local_name(element.tag) == "FRBRname" and element.get("value")
    ]
    dates = [
        str(element.get("date"))
        for element in root.iter()
        if _local_name(element.tag) == "FRBRdate"
        and element.get("name") == "judgment"
        and element.get("date")
    ]
    if not titles or not dates or dates[0] > TARGET_DATE:
        raise ValueError("phase2a_r103_judgment_metadata_invalid")
    blocks: list[dict[str, Any]] = []
    seen: set[str] = set()
    for element in root.iter():
        if _local_name(element.tag) != "paragraph":
            continue
        element_id = str(element.get("eId") or "")
        match = _PARAGRAPH_EID.fullmatch(element_id)
        if match is None or element_id in seen:
            continue
        text = _normal_text(element)
        if not text:
            continue
        seen.add(element_id)
        blocks.append(
            {
                "locator": f"paragraph {int(match.group('number'))}",
                "element_id": element_id,
                "text": text,
                "text_sha256": _sha256(text.encode("utf-8")),
            }
        )
    if not blocks:
        raise ValueError("phase2a_r103_judgment_paragraphs_missing")
    return {
        "source_class": "OFFICIAL_BINDING_OR_PERSUASIVE_JUDGMENT",
        "authority_identity_id": authority,
        "source_title": titles[0],
        "source_date": dates[0],
        "block_count": len(blocks),
        "blocks": blocks,
    }


def _legislation_extraction(authority: str, raw: bytes) -> dict[str, Any]:
    root = official._xml_root(raw)
    if _local_name(root.tag) != "Legislation":
        raise ValueError("phase2a_r103_legislation_xml_root_invalid")
    match = _UKPGA.fullmatch(authority)
    if match is None:
        raise ValueError("phase2a_r103_legislation_identity_invalid")
    years = {
        str(element.get("Value"))
        for element in root.iter()
        if _local_name(element.tag) == "Year" and element.get("Value")
    }
    numbers = {
        str(element.get("Value"))
        for element in root.iter()
        if _local_name(element.tag) == "Number" and element.get("Value")
    }
    document_uri = str(root.get("DocumentURI") or "")
    if (
        match.group("year") not in years
        or match.group("number") not in numbers
        or not document_uri.endswith(f"/{TARGET_DATE}")
    ):
        raise ValueError("phase2a_r103_legislation_identity_mismatch")
    titles = [
        _normal_text(element)
        for element in root.iter()
        if _local_name(element.tag) == "title" and _normal_text(element)
    ]
    if not titles:
        titles = [
            _normal_text(element)
            for element in root.iter()
            if _local_name(element.tag) == "Title" and _normal_text(element)
        ]
    blocks: list[dict[str, Any]] = []
    seen: set[str] = set()
    for element in root.iter():
        element_id = str(element.get("id") or "")
        if (
            _local_name(element.tag) not in {"P1", "P2", "P3", "P4", "P5"}
            or not element_id
            or element_id in seen
        ):
            continue
        text = _normal_text(element)
        if not text:
            continue
        seen.add(element_id)
        blocks.append(
            {
                "locator": element_id.replace("-", " "),
                "element_id": element_id,
                "text": text,
                "text_sha256": _sha256(text.encode("utf-8")),
            }
        )
    if not titles or not blocks:
        raise ValueError("phase2a_r103_legislation_content_missing")
    return {
        "source_class": "OFFICIAL_POINT_IN_TIME_LEGISLATION",
        "authority_identity_id": authority,
        "canonical_authority_identity_id": (
            f"ukpga:Eliz2:5-6:{match.group('number')}"
            if authority == "ukpga:1957:31"
            else authority
        ),
        "source_title": titles[0],
        "source_date": TARGET_DATE,
        "block_count": len(blocks),
        "blocks": blocks,
    }


def _targets(
    r102: Mapping[str, Any], r71: Mapping[str, Any]
) -> tuple[dict[str, Any], ...]:
    if (
        r102.get("row_count") != 364
        or r102.get("outside_source_research_authority_count")
        != EXPECTED_AUTHORITY_COUNT
        or r102.get("outside_source_research_row_link_count")
        != EXPECTED_ROW_LINK_COUNT
        or any(r102.get(field) is not False for field in _BOUNDARY_FIELDS)
        or r71.get("row_count") != 448
        or any(
            r71.get(field) is not False
            for field in (
                "technical_qualification_assigned",
                "candidate_mutated",
                "phase2b_authorized",
                "development30_authorized",
            )
        )
    ):
        raise ValueError("phase2a_r103_input_boundary_invalid")
    scope = r102.get("outside_source_research_authorities")
    triage_rows = r71.get("rows")
    route_rows = r102.get("rows")
    if (
        not isinstance(scope, list)
        or len(scope) != EXPECTED_AUTHORITY_COUNT
        or not isinstance(triage_rows, list)
        or len(triage_rows) != 448
        or not isinstance(route_rows, list)
        or len(route_rows) != 364
    ):
        raise ValueError("phase2a_r103_input_records_invalid")
    by_triage = {
        str(row["row_id"]): row for row in triage_rows if isinstance(row, dict)
    }
    by_route = {
        str(row["row_id"]): row for row in route_rows if isinstance(row, dict)
    }
    if len(by_triage) != 448 or len(by_route) != 364:
        raise ValueError("phase2a_r103_input_row_identity_collision")

    targets: list[dict[str, Any]] = []
    row_link_count = 0
    for ordinal, raw_scope in enumerate(scope, start=1):
        if not isinstance(raw_scope, Mapping):
            raise ValueError("phase2a_r103_scope_record_invalid")
        authority = str(raw_scope.get("authority_identity_id") or "")
        affected = raw_scope.get("affected_row_ids")
        if (
            not isinstance(affected, list)
            or not affected
            or raw_scope.get("affected_row_count") != len(affected)
            or raw_scope.get("retrieval_status")
            != "OFFICIAL_PRIMARY_SOURCE_QUARANTINE_REQUIRED"
            or raw_scope.get("source_admission_authorized") is not False
        ):
            raise ValueError("phase2a_r103_scope_boundary_invalid")
        row_ids = [str(row_id) for row_id in affected]
        row_link_count += len(row_ids)
        locator_hints: dict[str, list[str]] = defaultdict(list)
        issue_contexts: list[dict[str, str]] = []
        for row_id in row_ids:
            triage = by_triage.get(row_id)
            route = by_route.get(row_id)
            if (
                triage is None
                or route is None
                or authority
                not in route.get("effective_outside_candidate_authority_ids", [])
            ):
                raise ValueError("phase2a_r103_scope_row_binding_invalid")
            planned = triage.get("planned_authorities")
            if not isinstance(planned, list):
                raise ValueError("phase2a_r103_triage_authority_plan_invalid")
            matches = [
                item
                for item in planned
                if isinstance(item, Mapping)
                and item.get("authority_identity_id") == authority
            ]
            if len(matches) != 1:
                raise ValueError("phase2a_r103_locator_binding_missing")
            locator = str(matches[0].get("locator_hint") or "").strip()
            if not locator:
                raise ValueError("phase2a_r103_locator_hint_missing")
            locator_hints[row_id].append(locator)
            issue_contexts.append(
                {
                    "row_id": row_id,
                    "issue_label": str(triage.get("issue_label") or ""),
                    "legal_domain": str(triage.get("legal_domain") or ""),
                    "research_route": str(route.get("route") or ""),
                }
            )
        targets.append(
            {
                "ordinal": ordinal,
                "authority_identity_id": authority,
                "official_url": _authority_url(authority),
                "affected_row_ids": row_ids,
                "locator_hints_by_row": dict(sorted(locator_hints.items())),
                "issue_contexts": issue_contexts,
            }
        )
    if (
        row_link_count != EXPECTED_ROW_LINK_COUNT
        or len({target["authority_identity_id"] for target in targets})
        != EXPECTED_AUTHORITY_COUNT
    ):
        raise ValueError("phase2a_r103_target_inventory_invalid")
    return tuple(targets)


def _member_stem(ordinal: int, authority: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", authority.casefold()).strip("-")
    return f"{ordinal:02d}-{slug[:80]}-{_sha256(authority.encode())[:12]}"


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def collect(
    *,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    transport: httpx.BaseTransport | None = None,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_r103_output_already_exists")
    r102 = _load_verified(R102_PATH)
    r71 = _load_verified(R71_PATH)
    targets = _targets(r102, r71)
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_r103_output_mode_invalid")
    now = clock or (lambda: datetime.now(UTC))
    intent_material = {
        "schema": "legalbot.v111.phase2a.post-r101-official-source-research-intent.v1",
        "status": "OFFICIAL_PRIMARY_SOURCE_QUARANTINE_ONLY",
        "source_r102_content_sha256": r102["artifact_content_sha256"],
        "source_r71_content_sha256": r71["artifact_content_sha256"],
        "target_ceiling": TARGET_CEILING,
        "authority_count": len(targets),
        "row_link_count": sum(len(target["affected_row_ids"]) for target in targets),
        "targets": list(targets),
        "bulk_search_performed": False,
        "owner_source_admission_required": True,
        "automatic_source_admission": False,
        "automatic_gold_change": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    intent = {**intent_material, "intent_content_sha256": _sealed(intent_material)}
    _write_exclusive(output_root / "INTENT.json", _pretty_json(intent))

    records: list[dict[str, Any]] = []
    client_kwargs: dict[str, Any] = {
        "follow_redirects": False,
        "timeout": httpx.Timeout(30.0, connect=10.0),
        "headers": {"User-Agent": USER_AGENT, "Accept": "application/xml"},
        "trust_env": False,
    }
    if transport is not None:
        client_kwargs["transport"] = transport
    with httpx.Client(**client_kwargs) as client:
        for target in targets:
            retrieved_at = now().astimezone(UTC).isoformat(timespec="seconds")
            requested_url = str(target["official_url"])
            final_url, status, content_type, raw = official._fetch(client, requested_url)
            if status != 200:
                raise ValueError(f"phase2a_r103_official_source_unavailable_http_{status}")
            if _safe_url(final_url) != final_url:
                raise ValueError("phase2a_r103_final_url_invalid")
            authority = str(target["authority_identity_id"])
            extraction = (
                _judgment_extraction(authority, raw)
                if authority.startswith("neutral-citation:")
                else _legislation_extraction(authority, raw)
            )
            extraction_material = {
                "schema": "legalbot.v111.phase2a.official-source-extraction.v1",
                **extraction,
                "source_representation_sha256": _sha256(raw),
                "source_canonical_xml_sha256": _canonical_xml_sha256(raw),
                "requested_url": requested_url,
                "final_url": final_url,
                "affected_row_ids": target["affected_row_ids"],
                "locator_hints_by_row": target["locator_hints_by_row"],
                "issue_contexts": target["issue_contexts"],
                "owner_source_admission_required": True,
                "automatically_admitted": False,
                "automatically_indexed": False,
                "automatically_embedded": False,
            }
            extraction_artifact = {
                **extraction_material,
                "artifact_content_sha256": _sealed(extraction_material),
            }
            stem = _member_stem(int(target["ordinal"]), authority)
            raw_member = f"{stem}.xml"
            extraction_member = f"{stem}.extraction.json"
            _write_exclusive(output_root / raw_member, raw)
            _write_exclusive(
                output_root / extraction_member, _pretty_json(extraction_artifact)
            )
            record_material = {
                "ordinal": target["ordinal"],
                "authority_identity_id": authority,
                "canonical_authority_identity_id": extraction_artifact.get(
                    "canonical_authority_identity_id", authority
                ),
                "source_class": extraction_artifact["source_class"],
                "source_title": extraction_artifact["source_title"],
                "source_date": extraction_artifact["source_date"],
                "requested_url": requested_url,
                "final_url": final_url,
                "http_status": status,
                "content_type": content_type,
                "retrieved_at": retrieved_at,
                "affected_row_ids": target["affected_row_ids"],
                "locator_hints_by_row": target["locator_hints_by_row"],
                "raw_quarantine_member": raw_member,
                "raw_bytes": len(raw),
                "raw_sha256": _sha256(raw),
                "canonical_xml_sha256": extraction_artifact[
                    "source_canonical_xml_sha256"
                ],
                "extraction_member": extraction_member,
                "extraction_file_sha256": _sha256_file(
                    output_root / extraction_member
                ),
                "extraction_content_sha256": extraction_artifact[
                    "artifact_content_sha256"
                ],
                "extracted_block_count": extraction_artifact["block_count"],
                "result": "OFFICIAL_SOURCE_QUARANTINED_NOT_ADMITTED",
                "owner_source_admission_required": True,
                "automatically_admitted": False,
                "automatically_indexed": False,
                "automatically_embedded": False,
            }
            records.append(
                {**record_material, "record_content_sha256": _sealed(record_material)}
            )

    manifest_material = {
        "schema": "legalbot.v111.phase2a.post-r101-official-source-quarantine.v1",
        "status": "OFFICIAL_SOURCES_QUARANTINED_PROPOSITION_REVIEW_REQUIRED",
        "created_at": now().astimezone(UTC).isoformat(timespec="seconds"),
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_r102_content_sha256": r102["artifact_content_sha256"],
        "source_r71_content_sha256": r71["artifact_content_sha256"],
        "target_ceiling": TARGET_CEILING,
        "allowlisted_hosts": sorted(ALLOWED_HOSTS),
        "record_count": len(records),
        "row_link_count": sum(len(record["affected_row_ids"]) for record in records),
        "result_counts": {
            "OFFICIAL_SOURCE_QUARANTINED_NOT_ADMITTED": len(records)
        },
        "records": records,
        "bulk_search_performed": False,
        "owner_source_admission_required": True,
        "automatic_source_admission": False,
        "automatic_gold_change": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    if (
        len(records) != EXPECTED_AUTHORITY_COUNT
        or manifest_material["row_link_count"] != EXPECTED_ROW_LINK_COUNT
    ):
        raise ValueError("phase2a_r103_collection_inventory_invalid")
    manifest = {
        **manifest_material,
        "manifest_content_sha256": _sealed(manifest_material),
    }
    _write_exclusive(
        output_root / "QUARANTINE-MANIFEST.json", _pretty_json(manifest)
    )
    _write_exclusive(
        output_root / "OUTCOME.txt",
        b"16 OFFICIAL SOURCES QUARANTINED. OWNER PROPOSITION-LEVEL REVIEW "
        b"REQUIRED; NOTHING ADMITTED, INDEXED, OR EMBEDDED.\n",
    )
    names = sorted(
        path.name
        for path in output_root.iterdir()
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    sums = "".join(
        f"{_sha256_file(output_root / name)}  {name}\n" for name in names
    )
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return manifest


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists() or path.is_symlink():
            return
        material = {
            "schema": "legalbot.v111.phase2a.post-r101-official-source-failure.v1",
            "failure_fingerprint": _sealed(
                {"exception_type": type(exc).__name__, "error": str(exc)}
            ),
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "affected_stage": "PHASE2A_OFFICIAL_SOURCE_QUARANTINE",
            "source_admission_authorized": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except Exception:
        return


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args(argv)
    output_root = args.output_root.resolve()
    try:
        manifest = collect(output_root=output_root)
    except Exception as exc:
        _persist_failure(output_root, exc)
        raise
    print(
        json.dumps(
            {
                "manifest_content_sha256": manifest["manifest_content_sha256"],
                "record_count": manifest["record_count"],
                "row_link_count": manifest["row_link_count"],
                "automatic_source_admission": False,
                "automatic_indexing": False,
                "automatic_embedding": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
