#!/usr/bin/env python3
"""Execute owner-authorized next work without a 331 rerun.

Creates a new immutable pack with:
- owner authorization receipt for this workstream
- mechanical PIT/extent/commencement/effects review of captured official XML
- proposition and case-route mapping for 008/174/312 and missing bundles

Does not admit, gold-mark, qualify, train, open unseen, or rerun 331.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
STAGING = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-official-staging-intake-r1"
)
ADOPTION = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-owner-adoption-r1"
    / "OWNER-ADOPTION.json"
)
OVERLAY = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-owner-advisory-decision-overlay-r2"
    / "LegalBot-GE-owner-advisory-decision-overlay-r2.json"
)
PACK = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-authorized-next-work-r1"
)
DATE_RE = re.compile(rb"2026-08-(?:14|28)")
EXTENT_RE = re.compile(rb'\bRestrictExtent="([^"]+)"')
START_RE = re.compile(rb'\bRestrictStartDate="([^"]+)"')
VALID_RE = re.compile(rb"<dct:valid>([^<]+)</dct:valid>")
MODIFIED_RE = re.compile(rb"<dc:modified>([^<]+)</dc:modified>")
BODY_RE = re.compile(rb"<Body\b[\s\S]*?</Body>")
SCHEDULES_RE = re.compile(rb"<Schedules\b[\s\S]*?</Schedules>")
EXPECTED_OVERLAY_FILE = "51aecae99cf7820ebec181102ec4c0be0d3ee594ead1c6bd4f9f463a8779e816"
EXPECTED_ADOPTION = "f9f71c875b709c89a4af6d43f2ad9750269e1f9a46b93d29e64602e47c686543"

MAPPED_PROVISIONS: tuple[dict[str, str], ...] = (
    {
        "case_id": "administrative-law:cp-d08",
        "role": "confirm",
        "source_id": "ukpga-2010-15",
        "element_id": "section-20",
        "label": "Equality Act 2010 section 20",
    },
    {
        "case_id": "administrative-law:cp-d08",
        "role": "confirm",
        "source_id": "ukpga-2010-15",
        "element_id": "section-21",
        "label": "Equality Act 2010 section 21",
    },
    {
        "case_id": "administrative-law:cp-d08",
        "role": "confirm",
        "source_id": "ukpga-2010-15",
        "element_id": "section-29",
        "label": "Equality Act 2010 section 29",
    },
    {
        "case_id": "administrative-law:cp-d08",
        "role": "confirm",
        "source_id": "ukpga-2010-15",
        "element_id": "schedule-2",
        "label": "Equality Act 2010 Schedule 2",
    },
    {
        "case_id": "administrative-law:cp-d08",
        "role": "reject",
        "source_id": "ukpga-2010-15",
        "element_id": "section-174",
        "label": "Equality Act 2010 section 174",
    },
    {
        "case_id": "administrative-law:cp-d08",
        "role": "add_where_in_scope",
        "source_id": "uksi-2018-952",
        "element_id": "regulation-12",
        "label": "PSB Accessibility Regulations 2018 regulation 12",
    },
    {
        "case_id": "wills-and-estates:cp-d02",
        "role": "point_in_time_bundle",
        "source_id": "ukpga-Will4and1Vict-7-26",
        "element_id": "section-9",
        "label": "Wills Act 1837 section 9 (latest stored official XML, not a 2024-01-15 snapshot)",
    },
    {
        "case_id": "wills-and-estates:cp-d02",
        "role": "point_in_time_bundle",
        "source_id": "uksi-2020-952",
        "element_id": "article-2",
        "label": "SI 2020/952 article 2",
    },
    {
        "case_id": "wills-and-estates:cp-d02",
        "role": "point_in_time_bundle",
        "source_id": "uksi-2022-18",
        "element_id": "article-2",
        "label": "SI 2022/18 article 2",
    },
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: dict[str, Any]) -> dict[str, Any]:
    body = {key: item for key, item in value.items() if key != "content_sha256"}
    result = dict(value)
    result["content_sha256"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    return result


def _write_text(path: Path, text: str) -> None:
    data = text.encode("utf-8")
    if not data.endswith(b"\n"):
        data += b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _write_json(path: Path, value: Any) -> None:
    _write_text(path, json.dumps(value, ensure_ascii=False, indent=2))


def _local(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _text_of(element: ET.Element) -> str:
    parts: list[str] = []
    if element.text:
        parts.append(element.text)
    for child in list(element):
        parts.append(_text_of(child))
        if child.tail:
            parts.append(child.tail)
    return re.sub(r"\s+", " ", "".join(parts)).strip()


def _xml_stats(raw: bytes) -> dict[str, Any]:
    extent_match = EXTENT_RE.search(raw[:8000]) or EXTENT_RE.search(raw)
    start_match = START_RE.search(raw[:8000]) or START_RE.search(raw)
    valid_match = VALID_RE.search(raw[:20000])
    modified_match = MODIFIED_RE.search(raw[:20000])
    effect_count = raw.count(b"<ukm:UnappliedEffect") + raw.count(b"<UnappliedEffect")
    requires_applied = raw.count(b'RequiresApplied="true"')
    prospective = raw.count(b'Prospective="true"')
    body = b"".join(BODY_RE.findall(raw) + SCHEDULES_RE.findall(raw))
    if not body:
        body = raw
    normalized = DATE_RE.sub(b"DATE", raw)
    body_norm = DATE_RE.sub(b"DATE", body)
    return {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "normalized_sha256": hashlib.sha256(normalized).hexdigest(),
        "body_normalized_sha256": hashlib.sha256(body_norm).hexdigest(),
        "restrict_extent": extent_match.group(1).decode("ascii", "replace") if extent_match else None,
        "restrict_start_date": start_match.group(1).decode("ascii", "replace") if start_match else None,
        "dct_valid": valid_match.group(1).decode("ascii", "replace") if valid_match else None,
        "dc_modified": modified_match.group(1).decode("ascii", "replace") if modified_match else None,
        "unapplied_effect_markup_count": effect_count,
        "requires_applied_true_count": requires_applied,
        "prospective_true_count": prospective,
        "england_and_wales_in_extent": bool(
            extent_match
            and (
                b"E+W" in extent_match.group(1)
                or b"England" in extent_match.group(1)
            )
        ),
    }


def _review_row(ident: str) -> dict[str, Any]:
    left_path = STAGING / "raw" / ident / "2026-08-14" / "data.xml"
    right_path = STAGING / "raw" / ident / "2026-08-28" / "data.xml"
    if not left_path.is_file() or not right_path.is_file():
        return {
            "id": ident,
            "pair_complete": False,
            "owner_status": "HOLD_FOR_2026-08-28",
            "full_current_law_eligible_2026_08_28": False,
            "qualified_legal_review": False,
        }
    left = left_path.read_bytes()
    right = right_path.read_bytes()
    left_stats = _xml_stats(left)
    right_stats = _xml_stats(right)
    body_equal = left_stats["body_normalized_sha256"] == right_stats["body_normalized_sha256"]
    xml_equal = left_stats["normalized_sha256"] == right_stats["normalized_sha256"]
    effects_changed = (
        left_stats["unapplied_effect_markup_count"] != right_stats["unapplied_effect_markup_count"]
        or left_stats["requires_applied_true_count"] != right_stats["requires_applied_true_count"]
    )
    if not xml_equal:
        mechanical = "OFFICIAL_XML_DIFFERS_AFTER_REQUEST_DATE_NORMALIZATION"
    elif effects_changed:
        mechanical = "NORMALIZED_XML_IDENTICAL_BUT_EFFECT_COUNTS_DIFFER"
    else:
        mechanical = "OFFICIAL_XML_IDENTICAL_AFTER_REQUEST_DATE_NORMALIZATION"
    return {
        "id": ident,
        "pair_complete": True,
        "as_of_14": left_stats,
        "as_of_28": right_stats,
        "raw_bytes_equal": left == right,
        "normalized_xml_equal": xml_equal,
        "normalized_body_equal": body_equal,
        "effects_markup_changed": effects_changed,
        "mechanical_signal": mechanical,
        "owner_status": "HOLD_FOR_2026-08-28",
        "full_current_law_eligible_2026_08_28": False,
        "qualified_legal_review": False,
        "legal_gold": False,
        "admitted": False,
        "transition_blocked_because": [
            "no qualified or adopted per-locator review receipt",
            "extent recorded from RestrictExtent is not an applicability decision",
            "unapplied-effect materiality is not proposition-mapped",
        ],
    }


def _extract_provision(source_id: str, element_id: str) -> dict[str, Any]:
    path = STAGING / "raw" / source_id / "2026-08-28" / "data.xml"
    if not path.is_file():
        return {"ok": False, "error": "xml_missing", "source_id": source_id, "element_id": element_id}
    try:
        root = ET.fromstring(path.read_bytes())
    except ET.ParseError as exc:
        return {"ok": False, "error": f"parse:{exc}", "source_id": source_id, "element_id": element_id}
    found: ET.Element | None = None
    for element in root.iter():
        if element.attrib.get("id") == element_id:
            found = element
            break
    if found is None:
        return {"ok": False, "error": "element_id_not_found", "source_id": source_id, "element_id": element_id}
    text = _text_of(found)
    return {
        "ok": True,
        "source_id": source_id,
        "element_id": element_id,
        "restrict_extent": found.attrib.get("RestrictExtent"),
        "restrict_start_date": found.attrib.get("RestrictStartDate"),
        "text": text,
        "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "candidate_only": True,
        "legal_gold": False,
        "admitted": False,
        "qualified_legal_review": False,
    }


def main() -> int:
    if PACK.exists() or PACK.is_symlink():
        raise FileExistsError(f"create-only pack exists: {PACK}")
    overlay_sha = _sha256_file(OVERLAY)
    if overlay_sha != EXPECTED_OVERLAY_FILE:
        raise RuntimeError("overlay mutated")
    adoption = json.loads(ADOPTION.read_text(encoding="utf-8"))
    if adoption["content_sha256"] != EXPECTED_ADOPTION:
        raise RuntimeError("adoption receipt mutated")
    PACK.mkdir(parents=True, mode=0o700)
    os.chmod(PACK, stat.S_IRWXU)

    authorization = _digest(
        {
            "schema": "legalbot.ge-authorized-next-work.v1",
            "recorded_at_utc": datetime.now(UTC).isoformat(),
            "disposition": "OWNER_AUTHORIZATION_TO_EXECUTE_ADOPTED_NEXT_WORK",
            "owner_adoption_content_sha256": EXPECTED_ADOPTION,
            "overlay_file_sha256": EXPECTED_OVERLAY_FILE,
            "qualified_legal_review": False,
            "legal_gold": False,
            "admitted": False,
            "full_current_law_eligible": False,
            "answer_weight_training": False,
            "rerun_331": False,
            "sealed_unseen": False,
            "promotion": False,
            "live": False,
            "authorized": {
                "official_create_only_staging_intake": True,
                "point_in_time_extent_commencement_and_effects_review": True,
                "proposition_and_case_route_mapping": True,
                "evaluator_retrieval_and_non_weight_planner_repair": True,
            },
            "not_authorized": {
                "rerun_331": False,
                "qualified_legal_review": False,
                "legal_gold": False,
                "admitted": False,
                "full_current_law_eligible": False,
                "answer_weight_training": False,
                "sealed_unseen": False,
                "promotion": False,
                "live": False,
            },
        }
    )
    _write_json(PACK / "AUTHORIZATION.json", authorization)

    raw_root = STAGING / "raw"
    rows = [
        _review_row(path.name)
        for path in sorted(raw_root.iterdir())
        if path.is_dir() and (path / "2026-08-14" / "data.xml").is_file()
    ]
    review = _digest(
        {
            "schema": "legalbot.ge-mechanical-currentness-review.v1",
            "qualified_legal_review": False,
            "full_current_law_eligible": False,
            "legal_gold": False,
            "admitted": False,
            "source_count": len(rows),
            "pair_complete_count": sum(1 for row in rows if row.get("pair_complete")),
            "normalized_xml_equal_count": sum(1 for row in rows if row.get("normalized_xml_equal")),
            "normalized_body_equal_count": sum(1 for row in rows if row.get("normalized_body_equal")),
            "effects_markup_changed_count": sum(1 for row in rows if row.get("effects_markup_changed")),
            "note": (
                "Mechanical signals only. Identical normalized official XML does not "
                "approve extent, commencement, effects, propositions, chunks or answers."
            ),
            "rows": rows,
        }
    )
    _write_json(PACK / "MECHANICAL-CURRENTNESS-REVIEW.json", review)

    mapped: list[dict[str, Any]] = []
    for item in MAPPED_PROVISIONS:
        extracted = _extract_provision(item["source_id"], item["element_id"])
        mapped.append({**item, "extraction": extracted, "gold": False})
    mapping = _digest(
        {
            "schema": "legalbot.ge-proposition-and-case-route-map.v1",
            "qualified_legal_review": False,
            "legal_gold": False,
            "admitted": False,
            "runtime_admission": False,
            "cases": {
                "case_008": {
                    "case_id": "administrative-law:cp-d08",
                    "route": "EqA 2010 ss 20, 21, 29 and Schedule 2; 2018 accessibility regulations where in scope",
                    "reject": ["section 174", "section 208", "section 210"],
                    "gold": False,
                    "runtime": "fail_closed_pending_exact_spans_scope_extent_currentness",
                },
                "case_174": {
                    "case_id": "international-commercial-mediation:cp-d01",
                    "reject": "Arbitration Act 1996 section 9",
                    "route": [
                        "exact contractual clause",
                        "incorporated ICC Mediation Rules, especially article 5",
                        "Cable & Wireless [2002] EWHC 2059 (Comm) — official FCL capture failed HTTP 404",
                        "Ohpen [2019] EWHC 2246 (TCC) — staged FCL XML captured, not admitted",
                        "Kajima [2023] EWCA Civ 292 — staged FCL XML captured, not admitted",
                        "Churchill [2023] EWCA Civ 1416 — staged FCL XML captured, not admitted",
                        "current CPR stay/case-management locators after exact verification",
                    ],
                    "singapore_convention": "NOT_CONTROLLING",
                    "gold": False,
                    "runtime": "fail_closed_pending_intake_and_review",
                },
                "case_312": {
                    "case_id": "wills-and-estates:cp-d02",
                    "legal_date": "2024-01-15",
                    "temporal_method": "POINT_IN_TIME",
                    "video_will_window": "IN_SCOPE",
                    "latest_2026_text_only": "PROHIBITED",
                    "bundle": ["Wills Act 1837 s 9 as at 2024-01-15", "SI 2020/952", "SI 2022/18"],
                    "validity": "HOLD",
                    "gold": False,
                },
            },
            "missing_authority_bundles": {
                "ai_and_data_protection": ["ukpga/2018/12", "eur/2016/679", "ukpga/2025/18", "uksi/2026/82"],
                "competition_law_new": ["ukpga/1998/41", "ukpga/2002/40"],
                "competition_law_reverify_not_duplicate": ["ukpga/2024/13"],
                "mental_capacity_and_fertility": ["ukpga/2005/9", "ukpga/1990/37", "ukpga/2008/22"],
                "pensions_law": [
                    "ukpga/1993/48",
                    "ukpga/1995/26",
                    "ukpga/2004/35",
                    "ukpga/2008/30",
                    "ukpga/2021/1",
                    "ukpga/2026/22",
                    "uksi/2021/1237",
                    "uksi/2022/1220",
                    "uksi/2026/669",
                ],
                "eu_and_withdrawal": [
                    "ukpga/2018/16",
                    "ukpga/2020/1",
                    "ukpga/2023/28",
                    "eut/teec",
                    "eut/withdrawal-agreement",
                ],
            },
            "extracted_candidate_spans": mapped,
            "cable_and_wireless_status": {
                "citation": "[2002] EWHC 2059 (Comm)",
                "official_fcl_data_xml": "http_404",
                "admitted": False,
                "runtime": "fail_closed",
            },
        }
    )
    _write_json(PACK / "PROPOSITION-AND-CASE-ROUTE-MAP.json", mapping)
    _write_text(
        PACK / "README.md",
        """# Authorized next work r1

Owner authorization to execute the adopted next workstream. Not a 331 rerun.

- Mechanical currentness review of captured official XML
- Proposition/case-route mapping for 008, 174 and 312
- Cable & Wireless remains fail-closed after official FCL 404

All of `qualified_legal_review`, `legal_gold`, `admitted` and
`full_current_law_eligible` remain false.
""",
    )
    artifacts = []
    for path in sorted(PACK.rglob("*")):
        if path.is_file():
            artifacts.append(f"{_sha256_file(path)}  {path.relative_to(PACK).as_posix()}")
    _write_text(PACK / "SHA256SUMS.txt", "\n".join(artifacts) + "\n")
    print(
        json.dumps(
            {
                "pack": str(PACK),
                "authorization": authorization["content_sha256"],
                "review_sources": len(rows),
                "normalized_xml_equal": review["normalized_xml_equal_count"],
                "normalized_body_equal": review["normalized_body_equal_count"],
                "mapped": len(mapped),
                "mapped_ok": sum(1 for item in mapped if item["extraction"].get("ok")),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
