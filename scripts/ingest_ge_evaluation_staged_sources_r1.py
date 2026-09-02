#!/usr/bin/env python3
"""Create-only evaluation chunk store from official staging bytes.

Ingests 174/312/008 missing primaries and the remaining declared gap titles.
Writes a sidecar evaluation SQLite. Does not mutate data/catalog.sqlite3, the
recovery-b 85-source identity, or ACTIVE indexes. admitted and legal_gold stay
false. Cable & Wireless remains fail-closed on Find Case Law 404.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import ssl
import stat
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.ingestion.chunking import StructuralChunker
from app.ingestion.parsers import ParserRegistry
from app.ingestion.privacy import PIIAliaser
from app.ingestion.sanitation import sanitize_parse_result

ROOT = Path(__file__).resolve().parents[1]
STAGING_R1 = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-official-staging-intake-r1"
    / "raw"
)
PACK = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-evaluation-staged-chunks-r1"
)
ALLOWED_HOSTS = frozenset(
    {
        "www.legislation.gov.uk",
        "legislation.gov.uk",
        "caselaw.nationalarchives.gov.uk",
        "iccwbo.org",
    }
)
USER_AGENT = "LegalBot-v111-evaluation-staged-ingest/1.0 (owner-eval; no admission)"
TIMEOUT_S = 180
DO_NOT_ADMIT = frozenset({"mediation-act-2025"})
AS_OF = "2026-08-28"
PIT_WILLS_URL = (
    "https://www.legislation.gov.uk/ukpga/Will4and1Vict/7/26/2024-01-15/data.xml"
)
CABLE_URL = "https://caselaw.nationalarchives.gov.uk/ewhc/comm/2002/2059/data.xml"

PRIORITY: tuple[dict[str, Any], ...] = (
    {
        "id": "ewhc-tcc-2019-2246",
        "title": "Ohpen Operations UK Ltd v Invesco Fund Managers Ltd",
        "path": STAGING_R1 / "ewhc-tcc-2019-2246/data.xml",
        "bundle": "case_174",
        "lane": "primary_authority",
        "jurisdiction": "England and Wales",
    },
    {
        "id": "ewca-civ-2023-292",
        "title": "Kajima Construction Europe (UK) Ltd v Children's Ark Partnership Ltd",
        "path": STAGING_R1 / "ewca-civ-2023-292/data.xml",
        "bundle": "case_174",
        "lane": "primary_authority",
        "jurisdiction": "England and Wales",
    },
    {
        "id": "ewca-civ-2023-1416",
        "title": "Churchill v Merthyr Tydfil County Borough Council",
        "path": STAGING_R1 / "ewca-civ-2023-1416/data.xml",
        "bundle": "case_174",
        "lane": "primary_authority",
        "jurisdiction": "England and Wales",
    },
    {
        "id": "icc-mediation-rules-html",
        "title": "ICC Mediation Rules (contractually incorporated edition)",
        "path": STAGING_R1 / "icc-mediation-rules-html/page.html",
        "bundle": "case_174",
        "lane": "official_secondary",
        "jurisdiction": "England and Wales",
    },
    {
        "id": "uksi-2018-952",
        "title": "The Public Sector Bodies (Websites and Mobile Applications) (No. 2) Accessibility Regulations 2018",
        "path": STAGING_R1 / "uksi-2018-952" / AS_OF / "data.xml",
        "bundle": "case_008",
        "lane": "primary_authority",
        "jurisdiction": "United Kingdom",
    },
    {
        "id": "uksi-2020-952",
        "title": "The Wills Act 1837 (Electronic Communications) (Amendment) (Coronavirus) Order 2020",
        "path": STAGING_R1 / "uksi-2020-952" / AS_OF / "data.xml",
        "bundle": "case_312",
        "lane": "primary_authority",
        "jurisdiction": "England and Wales",
        "point_in_time_as_at": "2024-01-15",
    },
    {
        "id": "uksi-2022-18",
        "title": "The Wills Act 1837 (Electronic Communications) (Amendment) Order 2022",
        "path": STAGING_R1 / "uksi-2022-18" / AS_OF / "data.xml",
        "bundle": "case_312",
        "lane": "primary_authority",
        "jurisdiction": "England and Wales",
        "point_in_time_as_at": "2024-01-15",
    },
    {
        "id": "ukpga-Will4and1Vict-7-26-2024-01-15",
        "title": "Wills Act 1837 (as at 2024-01-15)",
        "fetch_url": PIT_WILLS_URL,
        "filename": "data.xml",
        "bundle": "case_312",
        "lane": "primary_authority",
        "jurisdiction": "England and Wales",
        "point_in_time_as_at": "2024-01-15",
    },
)

GAP_LANE: tuple[dict[str, Any], ...] = (
    {"id": "ukpga-2018-12", "title": "Data Protection Act 2018"},
    {"id": "eur-2016-679", "title": "UK GDPR"},
    {"id": "ukpga-2025-18", "title": "Data (Use and Access) Act 2025"},
    {
        "id": "uksi-2026-82",
        "title": "The Data (Use and Access) Act 2025 (Commencement No. 1) Regulations 2026",
    },
    {"id": "ukpga-1998-41", "title": "Competition Act 1998"},
    {"id": "ukpga-2002-40", "title": "Enterprise Act 2002"},
    {"id": "ukpga-2005-9", "title": "Mental Capacity Act 2005"},
    {"id": "ukpga-1990-37", "title": "Human Fertilisation and Embryology Act 1990"},
    {"id": "ukpga-2008-22", "title": "Human Fertilisation and Embryology Act 2008"},
    {"id": "ukpga-1968-60", "title": "Theft Act 1968", "identifier": "ukpga/1968/60"},
    {"id": "ukpga-2006-35", "title": "Fraud Act 2006", "identifier": "ukpga/2006/35"},
    {"id": "ukpga-1990-18", "title": "Computer Misuse Act 1990", "identifier": "ukpga/1990/18"},
    {"id": "eut-teec", "title": "Treaty on the Functioning of the European Union"},
    {"id": "eut-withdrawal-agreement", "title": "Withdrawal Agreement"},
    {"id": "ukpga-2018-16", "title": "European Union (Withdrawal) Act 2018"},
    {"id": "ukpga-2020-1", "title": "European Union (Withdrawal Agreement) Act 2020"},
    {"id": "ukpga-2023-28", "title": "Retained EU Law (Revocation and Reform) Act 2023"},
    {"id": "ukpga-1967-7", "title": "Abortion Act 1967"},
    {"id": "ukpga-1982-27", "title": "Civil Jurisdiction and Judgments Act 1982", "identifier": "ukpga/1982/27"},
    {
        "id": "ukpga-2020-24",
        "title": "Private International Law (Implementation of Agreements) Act 2020",
        "identifier": "ukpga/2020/24",
    },
    {"id": "ukpga-1993-48", "title": "Pension Schemes Act 1993"},
    {"id": "ukpga-1995-26", "title": "Pensions Act 1995"},
    {"id": "ukpga-2004-35", "title": "Pensions Act 2004"},
    {"id": "ukpga-2008-30", "title": "Pensions Act 2008"},
    {"id": "ukpga-2021-1", "title": "Pension Schemes Act 2021"},
    {"id": "ukpga-2025-4", "title": "Pension Schemes Act 2026"},
    {
        "id": "uksi-2021-1237",
        "title": "Occupational and Personal Pension Schemes (Conditions for Transfers) Regulations 2021",
    },
    {"id": "uksi-2022-1220", "title": "Pensions Dashboards Regulations 2022"},
    {
        "id": "uksi-2002-618",
        "title": "Medical Devices Regulations 2002",
        "identifier": "uksi/2002/618",
    },
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
                "status": int(response.status),
                "bytes": len(body),
                "sha256": _sha256_bytes(body),
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        return {"ok": False, "url": url, "status": int(exc.code), "error": f"http_{exc.code}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "url": url, "error": type(exc).__name__}


def _staging_xml(item: dict[str, Any]) -> Path | None:
    staged = STAGING_R1 / item["id"] / AS_OF / "data.xml"
    if staged.is_file():
        return staged
    flat = STAGING_R1 / item["id"] / "data.xml"
    if flat.is_file():
        return flat
    return None


def _open_db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript(
        """
        CREATE TABLE chunk_meta(
          chunk_id TEXT PRIMARY KEY,
          source_version_id TEXT NOT NULL,
          title TEXT NOT NULL,
          locator TEXT NOT NULL,
          body TEXT NOT NULL,
          ordinal INTEGER NOT NULL
        );
        CREATE TABLE ingest_log(
          source_version_id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          bytes INTEGER NOT NULL,
          chunk_count INTEGER NOT NULL,
          bundle TEXT NOT NULL
        );
        """
    )
    return connection


def _ingest_file(
    *,
    connection: sqlite3.Connection,
    item: dict[str, Any],
    path: Path,
    registry: ParserRegistry,
    chunker: StructuralChunker,
    aliaser: PIIAliaser,
) -> dict[str, Any]:
    raw = path.read_bytes()
    digest = _sha256_bytes(raw)
    source_id = "staged-" + digest[:40]
    parsed = sanitize_parse_result(
        registry.parse(raw, filename=path.name, aliaser=aliaser)
    )
    if not parsed.is_ready:
        return {
            "ok": False,
            "id": item["id"],
            "title": item["title"],
            "error": f"parse_not_ready:{parsed.status.value}",
        }
    chunks = chunker.chunk_body(parsed, document_sha256=digest)
    inserted = 0
    for chunk in chunks:
        body = str(chunk.text or "").strip()
        if not body:
            continue
        locator = str((chunk.metadata or {}).get("legal_locator") or "")
        if not locator and chunk.heading_path:
            locator = str(chunk.heading_path[-1])
        connection.execute(
            "INSERT INTO chunk_meta VALUES (?,?,?,?,?,?)",
            (
                chunk.chunk_id,
                source_id,
                str(item["title"]),
                locator,
                body,
                int(chunk.ordinal),
            ),
        )
        inserted += 1
    connection.execute(
        "INSERT INTO ingest_log VALUES (?,?,?,?,?)",
        (source_id, str(item["title"]), len(raw), inserted, str(item.get("bundle") or "gap")),
    )
    return {
        "ok": True,
        "id": item["id"],
        "title": item["title"],
        "source_version_id": source_id,
        "content_sha256": digest,
        "chunk_count": inserted,
        "path": str(path),
        "bundle": item.get("bundle") or "gap",
        "lane": item.get("lane") or "primary_authority",
        "jurisdiction": item.get("jurisdiction") or "United Kingdom",
        "point_in_time_as_at": item.get("point_in_time_as_at"),
        "admitted": False,
        "legal_gold": False,
        "full_current_law_eligible": False,
        "currentness_verified": False,
        "identity_verified": True,
        "provision_extent_status": "unverified",
        "review_status": "staged",
    }


def main() -> int:
    if PACK.exists() or PACK.is_symlink():
        raise FileExistsError(f"create-only pack exists: {PACK}")
    PACK.mkdir(parents=True, mode=0o700)
    os.chmod(PACK, stat.S_IRWXU)
    (PACK / "raw").mkdir(mode=0o700)
    registry = ParserRegistry.default()
    chunker = StructuralChunker()
    aliaser = PIIAliaser(b"legalbot-eval-staged-alias-secret")
    db_path = PACK / "chunks.sqlite3"
    connection = _open_db(db_path)
    captures: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    cable = _fetch(CABLE_URL)
    cable_record = {key: value for key, value in cable.items() if key != "body"}
    cable_record.update(
        {
            "id": "ewhc-comm-2002-2059",
            "title": "Cable & Wireless plc v IBM United Kingdom Ltd",
            "fail_closed": not cable.get("ok"),
            "admitted": False,
            "legal_gold": False,
        }
    )
    if cable.get("ok"):
        dest = PACK / "raw/ewhc-comm-2002-2059/data.xml"
        _write_bytes(dest, cable["body"])
        cable_record["relative_path"] = dest.relative_to(PACK).as_posix()
    captures.append(cable_record)

    work: list[dict[str, Any]] = []
    for item in PRIORITY:
        row = dict(item)
        if row.get("fetch_url"):
            time.sleep(0.35)
            result = _fetch(str(row["fetch_url"]))
            capture = {key: value for key, value in result.items() if key != "body"}
            capture.update({"id": row["id"], "title": row["title"]})
            if result.get("ok"):
                dest = PACK / "raw" / row["id"] / str(row.get("filename") or "data.xml")
                _write_bytes(dest, result["body"])
                row["path"] = dest
                capture["relative_path"] = dest.relative_to(PACK).as_posix()
            else:
                failures.append(capture)
                captures.append(capture)
                continue
            captures.append(capture)
        work.append(row)
    for item in GAP_LANE:
        if str(item["id"]).casefold() in DO_NOT_ADMIT:
            continue
        path = _staging_xml(item)
        if path is None and item.get("identifier"):
            time.sleep(0.35)
            url = f"https://www.legislation.gov.uk/{item['identifier']}/{AS_OF}/data.xml"
            result = _fetch(url)
            capture = {key: value for key, value in result.items() if key != "body"}
            capture.update({"id": item["id"], "title": item["title"]})
            if result.get("ok"):
                dest = PACK / "raw" / item["id"] / AS_OF / "data.xml"
                _write_bytes(dest, result["body"])
                path = dest
                capture["relative_path"] = dest.relative_to(PACK).as_posix()
            captures.append(capture)
            if path is None:
                failures.append({"id": item["id"], "title": item["title"], "error": capture.get("error")})
                continue
        elif path is None:
            failures.append({"id": item["id"], "title": item["title"], "error": "staging_bytes_missing"})
            continue
        work.append(
            {
                **item,
                "path": path,
                "bundle": "gap",
                "lane": "primary_authority",
                "jurisdiction": "United Kingdom",
            }
        )

    for item in work:
        path = Path(item["path"])
        if not path.is_file():
            failures.append({"id": item["id"], "title": item["title"], "error": "file_missing"})
            continue
        try:
            ingested = _ingest_file(
                connection=connection,
                item=item,
                path=path,
                registry=registry,
                chunker=chunker,
                aliaser=aliaser,
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(
                {"id": item["id"], "title": item["title"], "error": type(exc).__name__, "detail": str(exc)[:300]}
            )
            continue
        if ingested.get("ok"):
            sources.append(ingested)
        else:
            failures.append(ingested)
        connection.commit()

    connection.commit()
    connection.close()
    appendix = []
    db = sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    try:
        for source in sources:
            row = db.execute(
                """
                SELECT locator, substr(body,1,240) AS quote
                FROM chunk_meta
                WHERE source_version_id = ? AND length(locator) > 0
                ORDER BY ordinal
                LIMIT 1
                """,
                (source["source_version_id"],),
            ).fetchone()
            appendix.append(
                {
                    "source_version_id": source["source_version_id"],
                    "title": source["title"],
                    "locator": None if row is None else row["locator"],
                    "quote": None if row is None else row["quote"],
                    "owner_decision": "PENDING",
                    "owner_signed": False,
                    "legal_gold": False,
                    "admitted": False,
                    "full_current_law_eligible": False,
                    "recommended_owner_action": "HOLD",
                    "notes": "Staged evaluation chunk only. Not gold until a signed locator receipt.",
                }
            )
    finally:
        db.close()

    manifest = {
        "schema": "legalbot.ge-evaluation-staged-chunks.v1",
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "live_catalogue_insert": False,
        "live_catalogue_reason": (
            "Evaluation sidecar only. data/catalog.sqlite3 and the 85-source recovery-b "
            "identity were not mutated. Embeddings/ACTIVE LanceDB remain unauthorized."
        ),
        "embeddings_enqueued": False,
        "writes_index": False,
        "writes_active": False,
        "admitted": False,
        "legal_gold": False,
        "full_current_law_eligible": False,
        "qualified_legal_review": False,
        "source_count": len(sources),
        "failed_count": len(failures),
        "cable_and_wireless_fail_closed": bool(cable_record.get("fail_closed")),
        "do_not_admit": sorted(DO_NOT_ADMIT),
        "sources": [
            {
                "source_version_id": row["source_version_id"],
                "title": row["title"],
                "identity_verified": True,
                "currentness_verified": False,
                "full_current_law_verification_eligible": False,
                "provision_extent_status": "unverified",
                "jurisdiction": row.get("jurisdiction") or "United Kingdom",
                "lane": row.get("lane") or "primary_authority",
                "review_status": "staged",
                "admitted": False,
                "legal_gold": False,
                "point_in_time_as_at": row.get("point_in_time_as_at"),
                "canonical_url": None,
                "stable_identifier": row["id"],
                "authority_identity_id": row["id"],
                "unapplied_effect_count": None,
            }
            for row in sources
        ],
    }
    _write_json(PACK / "STAGED-SOURCE-MANIFEST.json", manifest)
    _write_json(PACK / "INGEST-LOG.json", {"captures": captures, "ingested": sources, "failures": failures})
    appendix_pack = (
        ROOT
        / "data/evaluations/general-enquiries"
        / "LegalBot-GE-2026-09-02-per-locator-gold-draft-r1-appendix"
    )
    if appendix_pack.exists() or appendix_pack.is_symlink():
        raise FileExistsError(f"create-only appendix exists: {appendix_pack}")
    appendix_pack.mkdir(parents=True, mode=0o700)
    os.chmod(appendix_pack, stat.S_IRWXU)
    appendix_payload = {
        "schema": "legalbot.ge-per-locator-gold-draft-appendix.v1",
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "owner_pack_signed": False,
        "evaluation_as_of_date": "2026-08-28",
        "legal_gold": False,
        "admitted": False,
        "full_current_law_eligible": False,
        "qualified_legal_review": False,
        "locators": appendix,
    }
    _write_json(appendix_pack / "LOCATOR-GOLD-DRAFT-APPENDIX.json", appendix_payload)
    _write_text(
        appendix_pack / "README.md",
        "Unsigned appendix of staged missing-primary locators. Not gold.\n",
    )
    _write_text(
        PACK / "README.md",
        """# Evaluation staged chunks r1

Create-only evaluation sidecar. Staged, not admitted, not gold.
Cable & Wireless remains fail-closed unless official bytes were captured.
Live catalog.sqlite3 was not written.
""",
    )
    print(
        json.dumps(
            {
                "pack": str(PACK),
                "source_count": len(sources),
                "failed_count": len(failures),
                "cable_fail_closed": cable_record.get("fail_closed"),
                "appendix": str(appendix_pack),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
