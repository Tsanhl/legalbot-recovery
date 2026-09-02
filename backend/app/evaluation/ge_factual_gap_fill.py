"""Fail-closed official-source fill for GE knowledge gaps and wrong routes.

100% factual here means: allowlisted official hosts only, exact SHA-256 bytes,
deterministic locator-bound chunks, quotation matching stored text, and no gold
or admission flags on fetch. Unidentified titles, blogs and commentary never
enter the index. Wrong-route quotations are recorded, not treated as authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..ingestion.chunking import StructuralChunker
from ..ingestion.parsers import ParserRegistry
from ..ingestion.privacy import PIIAliaser
from ..ingestion.sanitation import sanitize_parse_result
from .ge_diagnostic_evaluator import (
    alphanumeric_token_count,
    passage_completeness,
    quotation_fidelity,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
ALLOWED_HOSTS = frozenset(
    {
        "www.legislation.gov.uk",
        "legislation.gov.uk",
        "caselaw.nationalarchives.gov.uk",
    }
)
DO_NOT_ADMIT_TITLES = frozenset(
    {
        "mediation act 2025",
        "the mediation act 2025",
        "unidentified mediation act 2025",
    }
)
PERMANENT_FAIL_CLOSED = frozenset(
    {
        "cable & wireless plc v ibm united kingdom ltd",
    }
)
TITLE_ALIASES = {
    "wills act 1837 section 9 as it had effect on 2024-01-15": (
        "wills act 1837 (as at 2024-01-15)"
    ),
}
USER_AGENT = "LegalBot-v111-factual-gap-fill/1.0 (evaluation; no admission; no gold)"
AS_OF = "2026-08-28"
TIMEOUT_S = 180

FetchFn = Callable[[str], dict[str, Any]]

# Title -> official identifier. No guessed statutes. PDF is fallback after XML.
OFFICIAL_REGISTRY: dict[str, dict[str, str]] = {
    "data protection act 2018": {"kind": "legislation", "identifier": "ukpga/2018/12"},
    "uk gdpr": {"kind": "legislation", "identifier": "eur/2016/679"},
    "data (use and access) act 2025": {"kind": "legislation", "identifier": "ukpga/2025/18"},
    "the data (use and access) act 2025 (commencement no. 1) regulations 2026": {
        "kind": "legislation",
        "identifier": "uksi/2026/82",
    },
    "competition act 1998": {"kind": "legislation", "identifier": "ukpga/1998/41"},
    "enterprise act 2002": {"kind": "legislation", "identifier": "ukpga/2002/40"},
    "mental capacity act 2005": {"kind": "legislation", "identifier": "ukpga/2005/9"},
    "human fertilisation and embryology act 1990": {"kind": "legislation", "identifier": "ukpga/1990/37"},
    "human fertilisation and embryology act 2008": {"kind": "legislation", "identifier": "ukpga/2008/22"},
    "theft act 1968": {"kind": "legislation", "identifier": "ukpga/1968/60"},
    "fraud act 2006": {"kind": "legislation", "identifier": "ukpga/2006/35"},
    "computer misuse act 1990": {"kind": "legislation", "identifier": "ukpga/1990/18"},
    "treaty on the functioning of the european union": {"kind": "legislation", "identifier": "eut/teec"},
    "withdrawal agreement": {"kind": "legislation", "identifier": "eut/withdrawal-agreement"},
    "european union (withdrawal) act 2018": {"kind": "legislation", "identifier": "ukpga/2018/16"},
    "european union (withdrawal agreement) act 2020": {"kind": "legislation", "identifier": "ukpga/2020/1"},
    "retained eu law (revocation and reform) act 2023": {"kind": "legislation", "identifier": "ukpga/2023/28"},
    "abortion act 1967": {"kind": "legislation", "identifier": "ukpga/1967/7"},
    "civil jurisdiction and judgments act 1982": {"kind": "legislation", "identifier": "ukpga/1982/27"},
    "private international law (implementation of agreements) act 2020": {
        "kind": "legislation",
        "identifier": "ukpga/2020/24",
    },
    "rome i regulation": {"kind": "legislation", "identifier": "eur/2008/593"},
    "rome i": {"kind": "legislation", "identifier": "eur/2008/593"},
    "rome ii regulation": {"kind": "legislation", "identifier": "eur/2007/864"},
    "rome ii": {"kind": "legislation", "identifier": "eur/2007/864"},
    "pension schemes act 1993": {"kind": "legislation", "identifier": "ukpga/1993/48"},
    "pensions act 1995": {"kind": "legislation", "identifier": "ukpga/1995/26"},
    "pensions act 2004": {"kind": "legislation", "identifier": "ukpga/2004/35"},
    "pensions act 2008": {"kind": "legislation", "identifier": "ukpga/2008/30"},
    "pension schemes act 2021": {"kind": "legislation", "identifier": "ukpga/2021/1"},
    "pension schemes act 2026": {"kind": "legislation", "identifier": "ukpga/2025/4"},
    "occupational and personal pension schemes (conditions for transfers) regulations 2021": {
        "kind": "legislation",
        "identifier": "uksi/2021/1237",
    },
    "pensions dashboards regulations 2022": {"kind": "legislation", "identifier": "uksi/2022/1220"},
    "medical devices regulations 2002": {"kind": "legislation", "identifier": "uksi/2002/618"},
    "the public sector bodies (websites and mobile applications) (no. 2) accessibility regulations 2018": {
        "kind": "legislation",
        "identifier": "uksi/2018/952",
    },
    "the wills act 1837 (electronic communications) (amendment) (coronavirus) order 2020": {
        "kind": "legislation",
        "identifier": "uksi/2020/952",
    },
    "the wills act 1837 (electronic communications) (amendment) order 2022": {
        "kind": "legislation",
        "identifier": "uksi/2022/18",
    },
    "wills act 1837 section 9 as it had effect on 2024-01-15": {
        "kind": "legislation",
        "identifier": "ukpga/Will4and1Vict/7/26",
        "as_of": "2024-01-15",
        "title": "Wills Act 1837 (as at 2024-01-15)",
    },
    "ohpen operations uk ltd v invesco fund managers ltd": {
        "kind": "judgment",
        "url": "https://caselaw.nationalarchives.gov.uk/ewhc/tcc/2019/2246/data.xml",
    },
    "kajima construction europe (uk) ltd v children's ark partnership ltd": {
        "kind": "judgment",
        "url": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2023/292/data.xml",
    },
    "churchill v merthyr tydfil county borough council": {
        "kind": "judgment",
        "url": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2023/1416/data.xml",
    },
    "cable & wireless plc v ibm united kingdom ltd": {
        "kind": "judgment",
        "url": "https://caselaw.nationalarchives.gov.uk/ewhc/comm/2002/2059/data.xml",
    },
}

_TITLE_NOISE = re.compile(r"\s+")
_R_PACK = re.compile(r"^LegalBot-GE-\d{4}-\d{2}-\d{2}-(?:evaluation-staged-chunks|factual-gap-fill)-r\d+$")
_ATOM_NS = "http://www.w3.org/2005/Atom"
_LEGISLATION_TYPES = frozenset(
    {
        "ukpga",
        "ukla",
        "uksi",
        "ukcm",
        "ukppa",
        "asp",
        "nia",
        "anaw",
        "asc",
        "wsi",
        "ssi",
        "nisi",
        "eur",
        "eudn",
        "eudr",
        "eut",
    }
)
_CASE_NAME = re.compile(r"\bv\b", re.IGNORECASE)
_SEARCHABLE_INSTRUMENT = re.compile(
    r"\b(act|regulations?|order|directive|treaty|convention|statute)\b",
    re.IGNORECASE,
)
_FCL_PATH = re.compile(
    r"^/(?:uksc|ukpc|ewca/(?:civ|crim)|ewhc/[a-z0-9-]+)/\d{4}/\d+(?:/data\.xml)?$"
)


def normalize_title(title: str) -> str:
    return _TITLE_NOISE.sub(" ", str(title or "").casefold().replace("’", "'")).strip()


def canonical_title_key(title: str) -> str:
    key = normalize_title(title)
    return TITLE_ALIASES.get(key, key)


def official_urls(spec: Mapping[str, str]) -> tuple[str, ...]:
    if spec.get("kind") == "judgment":
        return (str(spec["url"]),)
    identifier = str(spec["identifier"])
    as_of = str(spec.get("as_of") or AS_OF)
    xml = (
        f"https://www.legislation.gov.uk/{identifier}/{as_of}/data.xml",
        f"https://www.legislation.gov.uk/{identifier}/data.xml",
    )
    pdf = (
        f"https://www.legislation.gov.uk/{identifier}/{as_of}/data.pdf",
        f"https://www.legislation.gov.uk/{identifier}/data.pdf",
    )
    return xml + pdf


def host_allowed(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host in ALLOWED_HOSTS


def default_fetch(url: str) -> dict[str, Any]:
    if not host_allowed(url):
        return {"ok": False, "url": url, "error": "host_not_allowlisted"}
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/atom+xml,application/xml,text/xml,application/pdf,*/*"},
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
                "content_type": str(response.headers.get("Content-Type") or ""),
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        return {"ok": False, "url": url, "status": int(exc.code), "error": f"http_{exc.code}"}
    except Exception as exc:
        return {"ok": False, "url": url, "error": type(exc).__name__}


def scan_results(path: Path) -> dict[str, Any]:
    missing: dict[str, list[str]] = {}
    wrong: list[dict[str, Any]] = []
    if not path.is_file():
        return {"missing": [], "wrong_routes": [], "error": "results_missing"}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            case_id = str(row.get("case_id") or "")
            for name in row.get("known_missing_primary_authorities") or []:
                missing.setdefault(str(name), []).append(case_id)
            checks = (row.get("factual_result") or {}).get("diagnostic_checks") or {}
            evidence = row.get("evidence") or []
            if (
                evidence
                and str((checks.get("issue_relevance") or {}).get("outcome") or "") == "FAIL"
            ):
                for item in evidence:
                    wrong.append(
                        {
                            "case_id": case_id,
                            "title": item.get("title"),
                            "locator": item.get("locator"),
                            "reason": "negative_wrong_route",
                        }
                    )
    return {
        "missing": [
            {"title": title, "case_ids": ids, "kind": "knowledge_gap"}
            for title, ids in sorted(missing.items())
        ],
        "wrong_routes": wrong,
    }


def lookup_official(title: str) -> dict[str, str] | None:
    key = normalize_title(title)
    if key in DO_NOT_ADMIT_TITLES or "mediation act 2025" in key:
        return None
    return OFFICIAL_REGISTRY.get(key)


def looks_officially_searchable(title: str) -> bool:
    key = normalize_title(title)
    if not key or key in DO_NOT_ADMIT_TITLES or "mediation act 2025" in key:
        return False
    if lookup_official(title) is not None:
        return True
    if _CASE_NAME.search(key):
        return True
    return _SEARCHABLE_INSTRUMENT.search(key) is not None


def _atom_entries(body: bytes) -> list[tuple[str, str]]:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    rows: list[tuple[str, str]] = []
    for entry in root.findall(f"{{{_ATOM_NS}}}entry"):
        title_node = entry.find(f"{{{_ATOM_NS}}}title")
        id_node = entry.find(f"{{{_ATOM_NS}}}id")
        title = normalize_title(title_node.text or "") if title_node is not None else ""
        official_id = (id_node.text or "").strip() if id_node is not None else ""
        if title and official_id:
            rows.append((title, official_id))
    return rows


def _identifier_from_legislation_path(path: str) -> str | None:
    path = path.strip("/")
    if path.endswith("/data.xml"):
        path = path[: -len("/data.xml")]
    if path.endswith("/contents"):
        path = path[: -len("/contents")]
    parts = [part for part in path.split("/") if part]
    if parts and re.fullmatch(r"20\d{2}-\d{2}-\d{2}", parts[-1]):
        parts = parts[:-1]
    if not parts or parts[0] not in _LEGISLATION_TYPES:
        return None
    return "/".join(parts)


def _legislation_search_url(title: str) -> str:
    encoded = urllib.parse.quote(title, safe="")
    return f"https://www.legislation.gov.uk/title/{encoded}/data.feed"


def _judgment_search_url(title: str) -> str:
    query = urllib.parse.urlencode({"query": title, "per_page": "20", "page": "1"})
    return f"https://caselaw.nationalarchives.gov.uk/atom.xml?{query}"


def resolve_official_search(title: str, fetch: FetchFn) -> dict[str, str] | None:
    """Resolve a missing title on official hosts only. Unique exact title match required."""

    key = normalize_title(title)
    if key in DO_NOT_ADMIT_TITLES or "mediation act 2025" in key:
        return None
    if _CASE_NAME.search(key):
        url = _judgment_search_url(title)
        if not host_allowed(url):
            return None
        result = fetch(url)
        if not result.get("ok"):
            return None
        exact: list[str] = []
        for atom_title, official_id in _atom_entries(result["body"]):
            parsed = urlparse(official_id)
            if (parsed.hostname or "") not in ALLOWED_HOSTS:
                continue
            if canonical_title_key(atom_title) != key:
                continue
            if not _FCL_PATH.match(parsed.path or ""):
                continue
            path = parsed.path.rstrip("/")
            if not path.endswith("/data.xml"):
                path = path + "/data.xml"
            exact.append(f"https://caselaw.nationalarchives.gov.uk{path}")
        unique = sorted(set(exact))
        if len(unique) != 1:
            return None
        return {"kind": "judgment", "url": unique[0], "resolved_by": "official_atom_exact_title"}

    url = _legislation_search_url(title)
    if not host_allowed(url):
        return None
    result = fetch(url)
    if not result.get("ok"):
        return None
    exact: list[str] = []
    for atom_title, official_id in _atom_entries(result["body"]):
        parsed = urlparse(official_id)
        if parsed.hostname not in {"www.legislation.gov.uk", "legislation.gov.uk"}:
            continue
        if canonical_title_key(atom_title) != key:
            continue
        identifier = _identifier_from_legislation_path(parsed.path or "")
        if identifier:
            exact.append(identifier)
    unique = sorted(set(exact))
    if len(unique) != 1:
        return None
    return {
        "kind": "legislation",
        "identifier": unique[0],
        "resolved_by": "official_atom_exact_title",
    }


def resolve_official(title: str, fetch: FetchFn | None = None) -> dict[str, str] | None:
    spec = lookup_official(title)
    if spec is not None:
        return spec
    if fetch is None or not looks_officially_searchable(title):
        return None
    return resolve_official_search(title, fetch)


def title_already_present(title: str, already: set[str]) -> bool:
    keys = {canonical_title_key(title), normalize_title(title)}
    spec = lookup_official(title)
    if spec and spec.get("title"):
        keys.add(canonical_title_key(str(spec["title"])))
    return bool(keys & already)


def chunk_is_factual(title: str, locator: str, body: str) -> bool:
    if alphanumeric_token_count(body) < 8 or not str(locator or "").strip():
        return False
    fidelity = quotation_fidelity(displayed=body[:800], stored=body)
    completeness = passage_completeness(
        title=title,
        locator=locator,
        stored_text=body,
        displayed_quote_text=body[:800],
    )
    return fidelity.outcome == "PASS" and completeness.outcome == "PASS"


def _filename_for(url: str, content_type: str) -> str:
    lowered = content_type.casefold()
    if url.endswith(".pdf") or "pdf" in lowered:
        return "data.pdf"
    if url.endswith(".html") or "html" in lowered:
        return "page.html"
    return "data.xml"


def ingest_official_bytes(
    *,
    title: str,
    body: bytes,
    filename: str,
    connection: sqlite3.Connection,
    registry: ParserRegistry,
    chunker: StructuralChunker,
    aliaser: PIIAliaser,
) -> dict[str, Any]:
    digest = hashlib.sha256(body).hexdigest()
    source_id = "staged-" + digest[:40]
    parsed = sanitize_parse_result(registry.parse(body, filename=filename, aliaser=aliaser))
    if not parsed.is_ready:
        return {"ok": False, "title": title, "error": f"parse_not_ready:{parsed.status.value}"}
    chunks = chunker.chunk_body(parsed, document_sha256=digest)
    kept = 0
    rejected = 0
    for chunk in chunks:
        text = str(chunk.text or "").strip()
        locator = str((chunk.metadata or {}).get("legal_locator") or "")
        if not chunk_is_factual(title, locator, text):
            rejected += 1
            continue
        connection.execute(
            "INSERT INTO chunk_meta VALUES (?,?,?,?,?,?)",
            (chunk.chunk_id, source_id, title, locator, text, int(chunk.ordinal)),
        )
        kept += 1
    if kept == 0:
        return {
            "ok": False,
            "title": title,
            "error": "no_factual_locator_bound_chunk",
            "rejected_chunks": rejected,
        }
    return {
        "ok": True,
        "title": title,
        "source_version_id": source_id,
        "content_sha256": digest,
        "factual_chunk_count": kept,
        "rejected_nonfactual_chunks": rejected,
        "admitted": False,
        "legal_gold": False,
        "full_current_law_eligible": False,
        "qualified_legal_review": False,
        "identity_verified": True,
        "currentness_verified": False,
        "provision_extent_status": "unverified",
        "review_status": "staged",
        "jurisdiction": "United Kingdom",
        "lane": "primary_authority",
    }


def ge_eval_root(project_root: Path = PROJECT_ROOT) -> Path:
    return project_root / "data/evaluations/general-enquiries"


def sidecar_packs(project_root: Path = PROJECT_ROOT) -> list[Path]:
    packs: list[Path] = []
    seen: set[Path] = set()
    root = ge_eval_root(project_root)
    index = root / "evaluation-staged-index"
    candidates: list[Path] = []
    if index.is_dir():
        for pointer in sorted(index.glob("*.json")):
            try:
                data = json.loads(pointer.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            relative = str(data.get("pack_relative") or "")
            if relative:
                candidates.append(project_root / relative)
    if root.is_dir():
        for child in sorted(root.iterdir()):
            if child.is_dir() and _R_PACK.match(child.name):
                candidates.append(child)
    for pack in candidates:
        resolved = pack.resolve() if pack.exists() else pack
        if resolved in seen:
            continue
        if (pack / "STAGED-SOURCE-MANIFEST.json").is_file():
            packs.append(pack)
            seen.add(resolved)
    return packs


def existing_titles(
    paths: Sequence[Path] | None = None, *, project_root: Path = PROJECT_ROOT
) -> set[str]:
    titles: set[str] = set()
    manifests = list(paths or ())
    if not manifests:
        for pack in sidecar_packs(project_root):
            manifests.append(pack / "STAGED-SOURCE-MANIFEST.json")
        recovery = (
            project_root
            / "data/indexes/builds/current-law-ew-full-fp16-v111-20260829-recovery-b"
            / "approved-source-manifest.json"
        )
        if recovery.is_file():
            manifests.append(recovery)
    for path in manifests:
        if not path.is_file():
            continue
        raw = json.loads(path.read_text(encoding="utf-8"))
        rows = raw.get("sources") if isinstance(raw, dict) else None
        if not isinstance(rows, list):
            continue
        for row in rows:
            if isinstance(row, dict) and row.get("title"):
                titles.add(canonical_title_key(str(row["title"])))
    return titles


def latest_visible_results(project_root: Path = PROJECT_ROOT) -> Path | None:
    preferred = (
        ge_eval_root(project_root)
        / "LegalBot-GE-2026-09-02-visible-331-diagnostic-r1"
        / "visible"
        / "RESULTS.jsonl"
    )
    if preferred.is_file():
        return preferred
    root = ge_eval_root(project_root)
    if not root.is_dir():
        return None
    candidates = sorted(
        root.glob("LegalBot-GE-*/visible/RESULTS.jsonl"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def next_output_pack(project_root: Path = PROJECT_ROOT, day: str | None = None) -> Path:
    stamp = day or datetime.now(UTC).strftime("%Y-%m-%d")
    n = 1
    while True:
        candidate = ge_eval_root(project_root) / f"LegalBot-GE-{stamp}-factual-gap-fill-r{n}"
        if not candidate.exists() and not candidate.is_symlink():
            return candidate
        n += 1


def write_index_pointer(pack: Path, *, project_root: Path = PROJECT_ROOT) -> Path:
    folder = ge_eval_root(project_root) / "evaluation-staged-index"
    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, stat.S_IRWXU)
    relative = pack.relative_to(project_root).as_posix()
    path = folder / f"{pack.name}.json"
    _write_json(
        path,
        {
            "schema": "legalbot.ge-evaluation-staged-index-pointer.v1",
            "pack_name": pack.name,
            "pack_relative": relative,
            "manifest": "STAGED-SOURCE-MANIFEST.json",
            "chunks_sqlite": "chunks.sqlite3",
            "live_catalogue_insert": False,
            "admitted": False,
            "legal_gold": False,
            "full_current_law_eligible": False,
            "qualified_legal_review": False,
        },
    )
    return path


def remaining_fetchable_titles(
    *,
    results_path: Path,
    already: set[str],
    failed_closed: set[str] | None = None,
) -> list[str]:
    scanned = scan_results(results_path)
    blocked = set(PERMANENT_FAIL_CLOSED)
    blocked.update(canonical_title_key(name) for name in (failed_closed or set()))
    remaining: list[str] = []
    for item in scanned.get("missing") or []:
        title = str(item["title"])
        key = canonical_title_key(title)
        if key in blocked or key in DO_NOT_ADMIT_TITLES or "mediation act 2025" in key:
            continue
        if title_already_present(title, already):
            continue
        if lookup_official(title) is None and not looks_officially_searchable(title):
            continue
        remaining.append(title)
    return remaining


def fill_gaps(
    *,
    results_path: Path,
    output: Path,
    already_titled: set[str],
    fetch: FetchFn = default_fetch,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"create-only pack exists: {output}")
    scanned = scan_results(results_path)
    output.mkdir(parents=True, mode=0o700)
    os.chmod(output, stat.S_IRWXU)
    (output / "raw").mkdir(mode=0o700)
    db_path = output / "chunks.sqlite3"
    connection = sqlite3.connect(db_path)
    connection.executescript(
        """
        PRAGMA journal_mode=DELETE;
        PRAGMA synchronous=FULL;
        CREATE TABLE chunk_meta(
          chunk_id TEXT PRIMARY KEY,
          source_version_id TEXT NOT NULL,
          title TEXT NOT NULL,
          locator TEXT NOT NULL,
          body TEXT NOT NULL,
          ordinal INTEGER NOT NULL
        );
        """
    )
    registry = ParserRegistry.default()
    chunker = StructuralChunker()
    aliaser = PIIAliaser(b"legalbot-factual-gap-fill-alias")
    ingested: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for item in scanned.get("missing") or []:
        title = str(item["title"])
        key = normalize_title(title)
        if key in DO_NOT_ADMIT_TITLES or "mediation act 2025" in key:
            failed.append(
                {"title": title, "error": "do_not_admit_unidentified_title", "factual": False}
            )
            continue
        if title_already_present(title, already_titled):
            skipped.append({"title": title, "reason": "already_staged_evaluation_chunks"})
            continue
        spec = resolve_official(title, fetch)
        if spec is None:
            failed.append(
                {
                    "title": title,
                    "error": "no_official_identifier",
                    "factual": False,
                    "detail": "no registry hit and no unique official exact-title match",
                }
            )
            continue
        display_title = str(spec.get("title") or title)
        fetched: dict[str, Any] | None = None
        last_error: dict[str, Any] | None = None
        for url in official_urls(spec):
            if not host_allowed(url):
                last_error = {
                    "title": title,
                    "url": url,
                    "error": "host_not_allowlisted",
                    "factual": False,
                }
                continue
            candidate = fetch(url)
            if candidate.get("ok"):
                fetched = candidate
                break
            last_error = {
                "title": title,
                "error": candidate.get("error") or "fetch_failed",
                "url": candidate.get("url"),
                "fail_closed": True,
                "factual": False,
            }
        if fetched is None:
            failed.append(last_error or {"title": title, "error": "fetch_failed", "factual": False})
            continue
        filename = _filename_for(str(fetched.get("url") or ""), str(fetched.get("content_type") or ""))
        dest = output / "raw" / re.sub(r"[^a-zA-Z0-9._-]+", "-", key)[:80] / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        _write_bytes(dest, fetched["body"])
        result = ingest_official_bytes(
            title=display_title,
            body=fetched["body"],
            filename=filename,
            connection=connection,
            registry=registry,
            chunker=chunker,
            aliaser=aliaser,
        )
        result["case_ids"] = item.get("case_ids")
        result["source_url"] = fetched.get("url")
        result["file_sha256"] = fetched.get("sha256")
        if result.get("ok"):
            ingested.append(result)
            already_titled.add(canonical_title_key(display_title))
        else:
            failed.append(result)
        connection.commit()

    connection.commit()
    connection.close()
    sources = [
        {
            "source_version_id": row["source_version_id"],
            "title": row["title"],
            "identity_verified": True,
            "currentness_verified": False,
            "full_current_law_verification_eligible": False,
            "provision_extent_status": "unverified",
            "jurisdiction": "United Kingdom",
            "lane": "primary_authority",
            "review_status": "staged",
            "admitted": False,
            "legal_gold": False,
            "canonical_url": row.get("source_url"),
            "stable_identifier": row["title"],
            "authority_identity_id": row["title"],
            "unapplied_effect_count": None,
        }
        for row in ingested
    ]
    results_relative = str(results_path)
    resolved_results = results_path.resolve()
    resolved_root = project_root.resolve()
    if resolved_results.is_relative_to(resolved_root):
        results_relative = str(resolved_results.relative_to(resolved_root))
    manifest = {
        "schema": "legalbot.ge-factual-gap-fill.v1",
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "results_path": results_relative,
        "live_catalogue_insert": False,
        "writes_active": False,
        "embeddings_enqueued": False,
        "admitted": False,
        "legal_gold": False,
        "full_current_law_eligible": False,
        "qualified_legal_review": False,
        "answer_weight_training": False,
        "factual_requirement": "exact_official_bytes_and_locator_bound_operative_chunks_only",
        "wrong_routes_indexed": False,
        "wrong_route_count": len(scanned.get("wrong_routes") or []),
        "ingested_count": len(ingested),
        "failed_count": len(failed),
        "skipped_count": len(skipped),
        "sources": sources,
        "chunks_sqlite": "chunks.sqlite3",
    }
    _write_json(output / "STAGED-SOURCE-MANIFEST.json", manifest)
    _write_json(
        output / "GAP-FILL-LOG.json",
        {
            "scanned": {
                "missing_count": len(scanned.get("missing") or []),
                "wrong_route_count": len(scanned.get("wrong_routes") or []),
            },
            "ingested": ingested,
            "failed": failed,
            "skipped": skipped,
            "wrong_routes": scanned.get("wrong_routes") or [],
        },
    )
    _write_text(
        output / "README.md",
        """# Factual knowledge-gap fill

Create-only evaluation sidecar. Official allowlisted bytes only.
Wrong-route quotations are recorded, not indexed as authority.
Not gold, not admitted, not ACTIVE.
""",
    )
    if ingested:
        write_index_pointer(output, project_root=project_root)
    return manifest


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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
