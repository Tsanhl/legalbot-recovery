#!/usr/bin/env python3
"""Create-only official staging capture for the r2 owner-advisory overlay.

Fetches official legislation.gov.uk and Find Case Law bytes into a quarantine
folder. Does not admit, qualify, gold-mark, index, train, open unseen, or rerun
331. Does not mutate the approved-source manifest or source matrix.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import stat
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
PACK = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-official-staging-intake-r1"
)
MANIFEST = (
    ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260829-recovery-b"
    / "approved-source-manifest.json"
)
OVERLAY = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-owner-advisory-decision-overlay-r2"
    / "LegalBot-GE-owner-advisory-decision-overlay-r2.json"
)
DATES = ("2026-08-14", "2026-08-28")
USER_AGENT = "LegalBot-v111-official-staging-intake/1.0 (owner-advisory; no admission)"
TIMEOUT_S = 180
SLEEP_S = 0.35
ALLOWED_HOSTS = frozenset(
    {
        "www.legislation.gov.uk",
        "legislation.gov.uk",
        "caselaw.nationalarchives.gov.uk",
        "iccwbo.org",
        "treaties.un.org",
    }
)
DO_NOT_ADMIT = frozenset({"mediation-act-2025"})

NEW_STAGING: tuple[dict[str, Any], ...] = (
    {
        "id": "ukpga-2018-12",
        "title": "Data Protection Act 2018",
        "identifier": "ukpga/2018/12",
        "bundle": "ai_and_data_protection",
    },
    {
        "id": "eur-2016-679",
        "title": "UK GDPR / Regulation (EU) 2016/679 as retained",
        "identifier": "eur/2016/679",
        "bundle": "ai_and_data_protection",
    },
    {
        "id": "ukpga-2025-18",
        "title": "Data (Use and Access) Act 2025",
        "identifier": "ukpga/2025/18",
        "bundle": "ai_and_data_protection",
    },
    {
        "id": "uksi-2026-82",
        "title": "The Data (Use and Access) Act 2025 (Commencement No. 1) Regulations 2026",
        "identifier": "uksi/2026/82",
        "bundle": "ai_and_data_protection",
    },
    {
        "id": "ukpga-1998-41",
        "title": "Competition Act 1998",
        "identifier": "ukpga/1998/41",
        "bundle": "competition_law",
    },
    {
        "id": "ukpga-2002-40",
        "title": "Enterprise Act 2002",
        "identifier": "ukpga/2002/40",
        "bundle": "competition_law",
    },
    {
        "id": "ukpga-2005-9",
        "title": "Mental Capacity Act 2005",
        "identifier": "ukpga/2005/9",
        "bundle": "mental_capacity_and_fertility",
    },
    {
        "id": "ukpga-1990-37",
        "title": "Human Fertilisation and Embryology Act 1990",
        "identifier": "ukpga/1990/37",
        "bundle": "mental_capacity_and_fertility",
    },
    {
        "id": "ukpga-2008-22",
        "title": "Human Fertilisation and Embryology Act 2008",
        "identifier": "ukpga/2008/22",
        "bundle": "mental_capacity_and_fertility",
    },
    {
        "id": "ukpga-1993-48",
        "title": "Pension Schemes Act 1993",
        "identifier": "ukpga/1993/48",
        "bundle": "pensions_law",
    },
    {
        "id": "ukpga-1995-26",
        "title": "Pensions Act 1995",
        "identifier": "ukpga/1995/26",
        "bundle": "pensions_law",
    },
    {
        "id": "ukpga-2004-35",
        "title": "Pensions Act 2004",
        "identifier": "ukpga/2004/35",
        "bundle": "pensions_law",
    },
    {
        "id": "ukpga-2008-30",
        "title": "Pensions Act 2008",
        "identifier": "ukpga/2008/30",
        "bundle": "pensions_law",
    },
    {
        "id": "ukpga-2021-1",
        "title": "Pension Schemes Act 2021",
        "identifier": "ukpga/2021/1",
        "bundle": "pensions_law",
    },
    {
        "id": "ukpga-2026-22",
        "title": "Pension Schemes Act 2026",
        "identifier": "ukpga/2026/22",
        "bundle": "pensions_law",
    },
    {
        "id": "uksi-2021-1237",
        "title": "Occupational and Personal Pension Schemes (Conditions for Transfers) Regulations 2021",
        "identifier": "uksi/2021/1237",
        "bundle": "pensions_law",
    },
    {
        "id": "uksi-2022-1220",
        "title": "Pensions Dashboards Regulations 2022",
        "identifier": "uksi/2022/1220",
        "bundle": "pensions_law",
    },
    {
        "id": "uksi-2026-669",
        "title": "The Pension Schemes Act 2026 (Commencement No. 1) Regulations 2026",
        "identifier": "uksi/2026/669",
        "bundle": "pensions_law",
    },
    {
        "id": "ukpga-2018-16",
        "title": "European Union (Withdrawal) Act 2018",
        "identifier": "ukpga/2018/16",
        "bundle": "eu_and_withdrawal",
    },
    {
        "id": "ukpga-2020-1",
        "title": "European Union (Withdrawal Agreement) Act 2020",
        "identifier": "ukpga/2020/1",
        "bundle": "eu_and_withdrawal",
    },
    {
        "id": "ukpga-2023-28",
        "title": "Retained EU Law (Revocation and Reform) Act 2023",
        "identifier": "ukpga/2023/28",
        "bundle": "eu_and_withdrawal",
    },
    {
        "id": "eut-teec",
        "title": "Treaty on the Functioning of the European Union",
        "identifier": "eut/teec",
        "bundle": "eu_and_withdrawal",
    },
    {
        "id": "eut-withdrawal-agreement",
        "title": "Agreement on the withdrawal of the United Kingdom from the EU",
        "identifier": "eut/withdrawal-agreement",
        "bundle": "eu_and_withdrawal",
    },
    {
        "id": "uksi-2018-952",
        "title": "Public Sector Bodies (Websites and Mobile Applications) (No. 2) Accessibility Regulations 2018",
        "identifier": "uksi/2018/952",
        "bundle": "case_008",
    },
    {
        "id": "uksi-2020-952",
        "title": "The Wills Act 1837 (Electronic Communications) (Amendment) (Coronavirus) Order 2020",
        "identifier": "uksi/2020/952",
        "bundle": "case_312",
    },
    {
        "id": "uksi-2022-18",
        "title": "The Wills Act 1837 (Electronic Communications) (Amendment) Order 2022",
        "identifier": "uksi/2022/18",
        "bundle": "case_312",
    },
)

JUDGMENTS: tuple[dict[str, Any], ...] = (
    {
        "id": "ewhc-tcc-2019-2246",
        "title": "Ohpen Operations UK Ltd v Invesco Fund Managers Ltd",
        "url": "https://caselaw.nationalarchives.gov.uk/ewhc/tcc/2019/2246/data.xml",
        "bundle": "case_174",
    },
    {
        "id": "ewca-civ-2023-292",
        "title": "Kajima Construction Europe (UK) Ltd v Children's Ark Partnership Ltd",
        "url": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2023/292/data.xml",
        "bundle": "case_174",
    },
    {
        "id": "ewca-civ-2023-1416",
        "title": "Churchill v Merthyr Tydfil County Borough Council",
        "url": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2023/1416/data.xml",
        "bundle": "case_174",
    },
    {
        "id": "ewhc-comm-2002-2059",
        "title": "Cable & Wireless plc v IBM United Kingdom Ltd",
        "url": "https://caselaw.nationalarchives.gov.uk/ewhc/comm/2002/2059/data.xml",
        "bundle": "case_174",
        "optional": True,
    },
)

SECONDARY: tuple[dict[str, Any], ...] = (
    {
        "id": "icc-mediation-rules-html",
        "title": "ICC Mediation Rules (publisher HTML, edition not yet bound)",
        "url": "https://iccwbo.org/dispute-resolution/dispute-resolution-services/adr/mediation/mediation-rules/",
        "bundle": "case_174",
        "lane": "official_secondary_candidate",
    },
)

_REVISED_RE = re.compile(
    r'Revised[^>]*Date="(\d{4}-\d{2}-\d{2})"|RestrictStartDate[^>]*Value="(\d{4}-\d{2}-\d{2})"|'
    r"Revised to (\d{2}/\d{2}/\d{4})"
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _write_text(path: Path, text: str) -> None:
    data = text.encode("utf-8")
    if not data.endswith(b"\n"):
        data += b"\n"
    _write_bytes(path, data)


def _write_json(path: Path, value: Any) -> None:
    _write_text(path, json.dumps(value, ensure_ascii=False, indent=2))


def _authority_path(authority_identity_id: str) -> str | None:
    text = str(authority_identity_id or "")
    if text.startswith("neutral-citation:"):
        return None
    parts = text.split(":")
    if len(parts) < 3:
        return None
    kind = parts[0]
    if kind not in {"ukpga", "uksi", "eur", "eut"}:
        return None
    remainder = [part for part in parts[1:] if part != "made"]
    return f"{kind}/{'/'.join(remainder)}"


def _legislation_urls(identifier: str, as_of: str) -> tuple[str, ...]:
    return (
        f"https://www.legislation.gov.uk/{identifier}/{as_of}/data.xml",
        f"https://www.legislation.gov.uk/{identifier}/data.xml",
        f"https://www.legislation.gov.uk/{identifier}/made/data.xml",
    )


def _host_ok(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host in ALLOWED_HOSTS


def _fetch(url: str) -> dict[str, Any]:
    if not _host_ok(url):
        return {"ok": False, "url": url, "error": "host_not_allowlisted"}
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/xml,text/xml,text/html,*/*"},
        method="GET",
    )
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S, context=context) as response:
            body = response.read()
            return {
                "ok": True,
                "url": url,
                "final_url": str(response.geturl()),
                "status": int(response.status),
                "content_type": response.headers.get("Content-Type"),
                "bytes": len(body),
                "sha256": _sha256_bytes(body),
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        return {"ok": False, "url": url, "status": int(exc.code), "error": f"http_{exc.code}"}
    except Exception as exc:  # noqa: BLE001 - record fetch failure, do not retry blindly
        return {"ok": False, "url": url, "error": type(exc).__name__}


def _revised_hint(body: bytes) -> str | None:
    text = body[:20000].decode("utf-8", errors="ignore")
    match = _REVISED_RE.search(text)
    if match is None:
        return None
    return next((group for group in match.groups() if group), None)


def _save_capture(relative: Path, result: dict[str, Any]) -> dict[str, Any]:
    record = {key: value for key, value in result.items() if key != "body"}
    if result.get("ok"):
        dest = PACK / relative
        _write_bytes(dest, result["body"])
        record["relative_path"] = relative.as_posix()
        record["revised_hint"] = _revised_hint(result["body"])
    return record


def main() -> int:
    if PACK.exists() or PACK.is_symlink():
        raise FileExistsError(f"create-only pack exists: {PACK}")
    if not OVERLAY.is_file():
        raise FileNotFoundError("owner-advisory overlay r2 must be recorded first")
    overlay = json.loads(OVERLAY.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    PACK.mkdir(parents=True, mode=0o700)
    os.chmod(PACK, stat.S_IRWXU)
    (PACK / "raw").mkdir(mode=0o700)

    existing_legislation: list[dict[str, Any]] = []
    for row in manifest["sources"]:
        path = _authority_path(str(row.get("authority_identity_id") or ""))
        if path is None:
            continue
        existing_legislation.append(
            {
                "id": path.replace("/", "-"),
                "title": row.get("title"),
                "identifier": path,
                "source_version_id": row.get("source_version_id"),
                "authority_identity_id": row.get("authority_identity_id"),
                "already_in_85": True,
                "reverify_not_duplicate": path == "ukpga/2024/13",
            }
        )

    captures: list[dict[str, Any]] = []
    comparisons: list[dict[str, Any]] = []

    def capture_legislation(item: dict[str, Any], *, staging: bool) -> None:
        date_hashes: dict[str, str | None] = {}
        for as_of in DATES:
            record: dict[str, Any] | None = None
            for url in _legislation_urls(str(item["identifier"]), as_of):
                time.sleep(SLEEP_S)
                result = _fetch(url)
                if result.get("ok"):
                    relative = Path("raw") / item["id"] / as_of / "data.xml"
                    record = _save_capture(relative, result)
                    record.update(
                        {
                            "id": item["id"],
                            "title": item.get("title"),
                            "identifier": item["identifier"],
                            "as_of_requested": as_of,
                            "already_in_85": bool(item.get("already_in_85")),
                            "staging_new": staging,
                            "admitted": False,
                            "full_current_law_eligible": False,
                            "qualified_legal_review": False,
                            "legal_gold": False,
                            "bundle": item.get("bundle"),
                        }
                    )
                    break
                record = {
                    "ok": False,
                    "id": item["id"],
                    "title": item.get("title"),
                    "identifier": item["identifier"],
                    "as_of_requested": as_of,
                    "url": url,
                    "error": result.get("error") or result.get("status"),
                    "already_in_85": bool(item.get("already_in_85")),
                    "staging_new": staging,
                    "admitted": False,
                }
            assert record is not None
            captures.append(record)
            date_hashes[as_of] = record.get("sha256") if record.get("ok") else None
        left = date_hashes[DATES[0]]
        right = date_hashes[DATES[1]]
        comparisons.append(
            {
                "id": item["id"],
                "title": item.get("title"),
                "identifier": item["identifier"],
                "already_in_85": bool(item.get("already_in_85")),
                "official_xml_sha256_2026_08_14": left,
                "official_xml_sha256_2026_08_28": right,
                "official_xml_unchanged_14_to_28": bool(left and right and left == right),
                "full_current_law_eligible_2026_08_28": False,
                "qualified_legal_review": False,
                "transition": (
                    "IDENTICAL_OFFICIAL_XML_STILL_REQUIRES_EXTENT_COMMENCEMENT_EFFECTS_PROPOSITION_AND_QUALIFIED_RECEIPT"
                    if left and right and left == right
                    else "HOLD_OR_QUALIFIED_REVIEW_IF_RELIED_ON"
                ),
            }
        )

    for item in existing_legislation:
        capture_legislation(item, staging=False)
    for item in NEW_STAGING:
        capture_legislation(item, staging=True)

    for item in JUDGMENTS:
        time.sleep(SLEEP_S)
        result = _fetch(str(item["url"]))
        record = {
            "id": item["id"],
            "title": item["title"],
            "bundle": item["bundle"],
            "already_in_85": False,
            "staging_new": True,
            "admitted": False,
            "full_current_law_eligible": False,
            "qualified_legal_review": False,
            "legal_gold": False,
            "lane": "primary_authority_candidate",
        }
        if result.get("ok"):
            record.update(_save_capture(Path("raw") / item["id"] / "data.xml", result))
        else:
            record.update({key: value for key, value in result.items() if key != "body"})
        captures.append(record)

    for item in SECONDARY:
        time.sleep(SLEEP_S)
        result = _fetch(str(item["url"]))
        record = {
            "id": item["id"],
            "title": item["title"],
            "bundle": item["bundle"],
            "lane": item["lane"],
            "already_in_85": False,
            "staging_new": True,
            "admitted": False,
            "full_current_law_eligible": False,
            "qualified_legal_review": False,
            "legal_gold": False,
        }
        if result.get("ok"):
            suffix = "page.html" if "html" in str(result.get("content_type") or "") else "page.bin"
            record.update(_save_capture(Path("raw") / item["id"] / suffix, result))
        else:
            record.update({key: value for key, value in result.items() if key != "body"})
        captures.append(record)

    unchanged = sum(1 for row in comparisons if row["official_xml_unchanged_14_to_28"])
    failed = [row for row in captures if not row.get("ok")]
    package = {
        "schema": "legalbot.ge-official-staging-intake.v1",
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "owner_advisory_overlay_content_sha256": overlay["content_sha256"],
        "source_manifest_sha256": manifest["manifest_sha256"],
        "admitted": False,
        "full_current_law_eligible": False,
        "qualified_legal_review": False,
        "legal_gold": False,
        "catalogue_ingest_performed": False,
        "writes_active": False,
        "writes_index": False,
        "rerun_331": False,
        "answer_weight_training": False,
        "do_not_admit": sorted(DO_NOT_ADMIT),
        "existing_legislation_compared": len(comparisons),
        "official_xml_unchanged_14_to_28_count": unchanged,
        "capture_count": len(captures),
        "failed_count": len(failed),
        "note": (
            "Identical official XML between 14 and 28 August is a mechanical "
            "exception signal only. It does not approve extent, commencement, "
            "effects, propositions, chunks or answers."
        ),
    }
    _write_json(PACK / "STAGING-MANIFEST.json", package)
    _write_json(PACK / "CAPTURES.json", {"schema": "legalbot.ge-official-staging-captures.v1", "rows": captures})
    _write_json(
        PACK / "PIT-14-VS-28-COMPARISON.json",
        {
            "schema": "legalbot.ge-official-pit-14-vs-28.v1",
            "full_current_law_eligible": False,
            "rows": comparisons,
        },
    )
    _write_text(
        PACK / "README.md",
        """# Official staging intake r1

Create-only official capture for the 2 September 2026 owner-advisory overlay.

- `admitted=false`
- `full_current_law_eligible=false`
- `qualified_legal_review=false`
- `legal_gold=false`
- no catalogue ingest, no ACTIVE write, no 331 rerun, no weight training

Mediation Act 2025 is recorded as `DO_NOT_ADMIT_UNIDENTIFIED_TITLE` and was
not fetched.
""",
    )
    artifacts = []
    for path in sorted(PACK.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            artifacts.append(f"{_sha256_bytes(path.read_bytes())}  {path.relative_to(PACK).as_posix()}")
    _write_text(PACK / "SHA256SUMS.txt", "\n".join(artifacts) + "\n")
    print(
        json.dumps(
            {
                "pack": str(PACK),
                "captures": len(captures),
                "failed": len(failed),
                "unchanged_14_to_28": unchanged,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
