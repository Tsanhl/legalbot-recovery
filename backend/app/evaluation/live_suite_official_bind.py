"""Mechanical official-text bind for remaining Path-B selected issues.

Gold is an exact catalogue or accepted v2-repair chunk. Downloaded official
XML/HTML is a candidate until hashes match. Catalogue absence is not by itself
a knowledge gap; unmatched official bytes may be ingested as new source
versions and then exact-matched. This module never writes ACTIVE,
O-04, D1-D15 owner_authored, or overlay seal, and it does not invent later
treatment.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import date
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .live30 import assert_safe_evaluation_payload
from .live_suite import load_live_evaluation_bundle
from .live_suite_evidence_pack import (
    _catalogue_candidate,
    _chunks_for_source,
    _eligible_source_versions,
    _title_match_score,
)
from .live_suite_final_check import (
    CASE_LATER_TREATMENT,
    FINAL_CHECK_SCHEMA,
    OWNER_FINAL_CHECK_TOKEN,
    _eligible_row,
    _public_candidate,
    _sha256_bytes,
    _sha256_text,
    _write_json,
    import_owner_final_check,
    is_cross_ref_fragment,
    locator_key,
    locator_matches_target,
    provision_keys,
)
from .live_suite_owner_review import HELD_STATUTORY_PROVISIONS
from .live_suite_path_b import LIVE60_ROOT, selected_generation_case_ids
from .live_suite_reviewer_identity import build_owner_reviewer_identity

OFFICIAL_BIND_RESULT_SCHEMA = "legalbot.live60-remaining-official-bind-result.v1"
LEGISLATION_NS = "http://www.legislation.gov.uk/namespaces/legislation"
AYINDE_FCL_URL = "https://caselaw.nationalarchives.gov.uk/ewhc/admin/2025/1383"
AYINDE_NEUTRAL_CITATION = "[2025] EWHC 1383 (Admin)"
CPA_2026_S250_URL = "https://www.legislation.gov.uk/ukpga/2026/20/section/250"
ECCTA_S196_URL = "https://www.legislation.gov.uk/ukpga/2023/56/section/196"
CRA_S31_URL = "https://www.legislation.gov.uk/ukpga/2015/15/section/31"
CRA_S47_URL = "https://www.legislation.gov.uk/ukpga/2015/15/section/47"
CRA_S57_URL = "https://www.legislation.gov.uk/ukpga/2015/15/section/57"
LIMITATION_S4A_URL = "https://www.legislation.gov.uk/ukpga/1980/58/section/4A"
PROCUREMENT_PART9 = {
    "s 101": "https://www.legislation.gov.uk/ukpga/2023/54/section/101",
    "s 102": "https://www.legislation.gov.uk/ukpga/2023/54/section/102",
    "s 103": "https://www.legislation.gov.uk/ukpga/2023/54/section/103",
    "s 104": "https://www.legislation.gov.uk/ukpga/2023/54/section/104",
}
CPR_GOLD_HOST = "https://www.legislation.gov.uk/uksi/1998/3132"
USER_AGENT = "LegalBot-New official-source check (legislation.gov.uk / Find Case Law)"
_DOTS = re.compile(r"^(?:\.|\s)+$")
_PARA_LETTER = re.compile(r"\(([a-z]|[ivx]+)\)\s*", re.IGNORECASE)
_SPLICED_JOIN = re.compile(r"—but\s|–but\s|-but\s")
_JUSTICE_CPR = re.compile(
    r"https?://www\.justice\.gov\.uk/courts/procedure-rules/civil/rules/part(\d+)",
    re.IGNORECASE,
)
_RULE_LOCATOR = re.compile(
    r"\br(?:ule)?\.?\s*(\d+)\.(\d+)(?:\s*\(([^)]+)\))?",
    re.IGNORECASE,
)
_PATH_PROVISION = re.compile(
    r"/(section|article|regulation|rule|paragraph)/([^/]+)",
    re.IGNORECASE,
)
_SECTIONS_RANGE_PATH = re.compile(
    r"^(https://www\.legislation\.gov\.uk/.+)/sections/([^/]+)$",
    re.IGNORECASE,
)
_PROVISION_PATH = re.compile(
    r"^(https://www\.legislation\.gov\.uk/.+)/(section|article|regulation|rule|paragraph)/([^/]+)$",
    re.IGNORECASE,
)
_SUBSECTION_RANGE = re.compile(
    r"\b(?P<kind>ss?|arts?|regs?)\s+(?P<num>\d+[A-Za-z]*)\((?P<a>\d+[A-Za-z]*)\)\s*-\s*\((?P<b>\d+[A-Za-z]*)\)",
    re.IGNORECASE,
)
_PARA_LOCATOR = re.compile(
    r"\b(?:sch(?:edule)?\s+)?(?P<sch>b1)\b.*\bpara(?:graph)?\s+(?P<num>\d+[A-Za-z]*)"
    r"(?:\s*\((?P<sub>[^)]+)\))?",
    re.IGNORECASE,
)
_KIND_FROM_PATH = {
    "section": "s",
    "article": "art",
    "regulation": "reg",
    "rule": "r",
    "paragraph": "para",
}
_OMITTED_DOTS = re.compile(r"(?:\.\s*){4,}")
_SERVICES_EXCLUSION = re.compile(
    r"contract to supply a service is not binding.*section 49.*50.*52",
    re.IGNORECASE | re.DOTALL,
)
_DIGITAL_CONTENT_EXCLUSION = re.compile(
    r"contract to supply digital content is not binding",
    re.IGNORECASE,
)
_LIMITATION_4A_OPENING = "the time limit under section 2 of this act shall not apply"
AYINDE_PACK_PARA7_PARAPHRASE = (
    "those who use artificial intelligence tools to conduct legal research "
    "therefore have a professional responsibility"
)
AYINDE_FCL_PARA7_STEM = (
    "those who use artificial intelligence to conduct legal research "
    "notwithstanding these risks have a professional duty therefore"
)
HELD_LOCATOR_KEYS = {
    "held-provision-01": ("limitation act 1980", "s 2"),
    "held-provision-02": ("limitation act 1980", "s 14a"),
    "held-provision-03": ("trustee act 2000", "s 1"),
    "held-provision-04": (
        "inheritance (provision for family and dependants) act 1975",
        "s 1",
    ),
}


def collapsed(value: str) -> str:
    return " ".join(value.replace("\u00a0", " ").split())


def normalise_marks(value: str) -> str:
    text = value.replace("\u2018", "'").replace("\u2019", "'")
    text = text.replace("\u201c", '"').replace("\u201d", '"')
    text = text.replace("\u2013", "—").replace("\u2014", "—").replace("\u2212", "—")
    return collapsed(text)


def strip_para_letters(value: str) -> str:
    return collapsed(_PARA_LETTER.sub(" ", value))


def comparable(value: str) -> str:
    return strip_para_letters(normalise_marks(value)).casefold()


def contains_omitted_dots(value: str) -> bool:
    return bool(_OMITTED_DOTS.search(value or ""))


def is_omitted_official_text(value: str) -> bool:
    stripped = collapsed(value).replace("\u00a0", " ")
    if not stripped:
        return False
    if "omitted" in stripped.casefold() and len(stripped) < 80:
        return True
    if contains_omitted_dots(stripped) and len(strip_para_letters(stripped)) < 80:
        return True
    return bool(_DOTS.fullmatch(stripped.replace("section 196", "").strip()))


def is_spliced_join(value: str) -> bool:
    return bool(_SPLICED_JOIN.search(normalise_marks(value)))


def strip_locator_prefix(text: str, locator: str) -> str:
    collapsed_text = collapsed(text)
    prefixes = [collapsed(locator)]
    key = locator_key(locator)
    if key:
        prefixes.append(key)
        prefixes.append(key.replace("s ", "section "))
        prefixes.append(key.replace("reg ", "regulation "))
        prefixes.append(key.replace("r ", "rule "))
        prefixes.append(key.replace("art ", "article "))
    for prefix in prefixes:
        if prefix and collapsed_text.casefold().startswith(prefix.casefold() + " "):
            return collapsed_text[len(prefix) :].lstrip()
    return collapsed_text


def limitation_4a_uses_official_opening(value: str) -> bool:
    return comparable(value).startswith(_LIMITATION_4A_OPENING)


def pack_quote_is_services_exclusion(value: str) -> bool:
    return bool(_SERVICES_EXCLUSION.search(normalise_marks(value)))


def official_s47_is_digital_content(value: str) -> bool:
    return bool(_DIGITAL_CONTENT_EXCLUSION.search(normalise_marks(value)))


def ayinde_quote_is_paraphrase(quote: str, official_paragraph: str) -> bool:
    quoted = comparable(quote)
    official = comparable(official_paragraph)
    if not quoted or not official:
        return True
    if quoted == official or quoted in official or official in quoted:
        return False
    if AYINDE_PACK_PARA7_PARAPHRASE in quoted and AYINDE_FCL_PARA7_STEM in official:
        return True
    return quoted != official


def rule_keys(value: str) -> tuple[str, ...]:
    keys: list[str] = []
    for match in _RULE_LOCATOR.finditer(value):
        key = f"r {match.group(1)}.{match.group(2)}"
        if match.group(3):
            key = f"{key}({collapsed(match.group(3)).casefold()})"
        if key not in keys:
            keys.append(key)
    return tuple(keys)


def _add_unique(keys: list[str], key: str) -> None:
    if key and key not in keys:
        keys.append(key)


def bind_targets(locator: str, url: str = "") -> tuple[str, ...]:
    """Section, article, regulation and CPR rule keys from a locator and URL."""

    keys: list[str] = []
    for key in (*rule_keys(locator), *provision_keys(locator)):
        _add_unique(keys, key)
    for match in _SUBSECTION_RANGE.finditer(locator or ""):
        kind = {"ss": "s", "s": "s", "arts": "art", "art": "art", "regs": "reg", "reg": "reg"}[
            match.group("kind").casefold()
        ]
        number = match.group("num").casefold()
        _add_unique(keys, f"{kind} {number}({match.group('a').casefold()})")
        _add_unique(keys, f"{kind} {number}({match.group('b').casefold()})")
    para = _PARA_LOCATOR.search(locator or "")
    if para:
        key = f"para {para.group('num').casefold()}"
        if para.group("sub"):
            key = f"{key}({collapsed(para.group('sub')).casefold()})"
        _add_unique(keys, key)
        _add_unique(keys, f"sch {para.group('sch').casefold()} {key}")
    for match in _PATH_PROVISION.finditer(url or ""):
        if keys:
            break
        path_kind = _KIND_FROM_PATH.get(match.group(1).casefold())
        if not path_kind:
            continue
        number = match.group(2).casefold()
        if path_kind == "r":
            _add_unique(keys, f"r {number}")
        elif path_kind == "para":
            _add_unique(keys, f"para {number}")
        else:
            _add_unique(keys, f"{path_kind} {number}")
    return tuple(keys)


def lookup_subsection(subsections: Mapping[str, str], target: str) -> str:
    if not target or not subsections:
        return ""
    folded = {str(key).casefold(): value for key, value in subsections.items()}
    wanted = target.casefold()
    if wanted in folded:
        return folded[wanted]
    if "(" not in wanted:
        return folded.get(wanted, "") or folded.get(f"{wanted}(1)", "")
    parent = wanted.rsplit("(", 1)[0]
    return folded.get(parent, "")


def split_source_urls(source_url: str) -> list[str]:
    urls: list[str] = []
    for raw in re.split(r"\s*;\s*", source_url or ""):
        part = raw.strip().split()[0] if raw.strip() else ""
        if part:
            urls.append(part.rstrip("/"))
    return urls


def official_page_urls(source_url: str, locator: str, source_title: str) -> list[str]:
    """Expand multi-section and mixed-instrument URLs into fetchable pages."""

    urls: list[str] = []
    targets = bind_targets(locator, source_url)
    raw_urls = split_source_urls(source_url)
    wants_cpr = any(key.startswith("r ") for key in (*rule_keys(locator), *targets))
    title = source_title.casefold()
    if wants_cpr and (
        not raw_urls
        or any("justice.gov.uk" in item or "/schedule/" in item for item in raw_urls)
        or "civil procedure" in title
    ):
        _add_unique(urls, cpr_gold_url(locator))
    for url in raw_urls:
        if "justice.gov.uk" in url:
            continue
        if wants_cpr and "/schedule/" in url:
            continue
        range_match = _SECTIONS_RANGE_PATH.match(url)
        if range_match:
            prefix = range_match.group(1)
            numbers = [key[2:].split("(", 1)[0] for key in targets if key.startswith("s ")]
            if not numbers:
                span = range_match.group(2)
                numbers = span.split("-", 1) if "-" in span else [span]
            for number in dict.fromkeys(numbers):
                _add_unique(urls, f"{prefix}/section/{number}")
            continue
        _add_unique(urls, url)
        path_match = _PROVISION_PATH.match(url)
        if not path_match:
            continue
        prefix = path_match.group(1)
        path_kind = path_match.group(2).casefold()
        sibling_kind = {"section": "s", "article": "art", "regulation": "reg"}.get(path_kind)
        if not sibling_kind:
            continue
        for key in targets:
            if not key.startswith(f"{sibling_kind} "):
                continue
            number = key.split(" ", 1)[1].split("(", 1)[0]
            _add_unique(urls, f"{prefix}/{path_kind}/{number}")
    if "arbitration act 1996" in title and any(key.startswith("s 6a") for key in targets):
        _add_unique(urls, "https://www.legislation.gov.uk/ukpga/1996/23/section/6A")
    return urls


def cpr_gold_url(rule: str) -> str:
    match = _RULE_LOCATOR.search(rule)
    if not match:
        return CPR_GOLD_HOST
    number = f"{match.group(1)}.{match.group(2)}"
    return f"{CPR_GOLD_HOST}/rule/{number}"


def legislation_data_xml_url(page_url: str) -> str:
    cleaned = page_url.strip().rstrip("/")
    if cleaned.endswith("/data.xml"):
        return cleaned
    if "legislation.gov.uk" not in cleaned:
        return ""
    return f"{cleaned}/data.xml"


def _local_tag(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _element_text(element: ET.Element) -> str:
    parts: list[str] = []
    skip_first_number = True
    for node in element.iter():
        name = _local_tag(node.tag)
        if name in {"CommentaryRef", "Number", "Title", "IncludedDocument"}:
            continue
        if name == "Pnumber":
            number = collapsed("".join(node.itertext()))
            if skip_first_number:
                skip_first_number = False
                continue
            if number and not number.isdigit():
                parts.append(f"({number})")
            continue
        if name == "Text":
            parts.append("".join(node.itertext()))
    return collapsed(" ".join(parts))


def _ident_keys(ident: str) -> tuple[str, ...]:
    ident = ident.strip()
    ident_cf = ident.casefold()
    if not ident_cf:
        return ()
    mapping = (
        ("section-", "s"),
        ("article-", "art"),
        ("regulation-", "reg"),
        ("rule-", "r"),
    )
    kind = ""
    rest = ""
    for prefix, mapped in mapping:
        if ident_cf.startswith(prefix):
            kind = mapped
            rest = ident[len(prefix) :]
            break
    if not kind:
        schedule = re.match(
            r"schedule-([^-]+)-paragraph-(\d+[a-z]*)(?:-([a-z0-9]+))?",
            ident_cf,
        )
        if not schedule:
            return ()
        key = f"para {schedule.group(2)}"
        if schedule.group(3):
            key = f"{key}({schedule.group(3)})"
        return (key, f"sch {schedule.group(1)} {key}")
    tokens = [token for token in rest.split("-") if token]
    if not tokens:
        return ()
    number = tokens[0]
    keys = [f"{kind} {number}", f"{kind} {number.casefold()}"]
    if len(tokens) >= 2:
        nested = f"{kind} {number}({tokens[1]})"
        keys.extend((nested, f"{kind} {number.casefold()}({tokens[1].casefold()})"))
    if len(tokens) >= 3:
        letter = (
            f"{kind} {number}({tokens[1]})({tokens[2]})",
            f"{kind} {number}({tokens[1]}({tokens[2]}))",
            f"{kind} {number.casefold()}({tokens[1].casefold()})({tokens[2].casefold()})",
            f"{kind} {number.casefold()}({tokens[1].casefold()}({tokens[2].casefold()}))",
        )
        keys.extend(letter)
    return tuple(dict.fromkeys(keys))


def extract_legislation_subsections(xml_text: str) -> dict[str, str]:
    """Map locators such as 's 50(1)' to exact official subsection text."""

    payload = xml_text.encode("utf-8") if isinstance(xml_text, str) else xml_text
    root = ET.fromstring(payload)
    found: dict[str, str] = {}
    omitted = False
    for node in root.iter():
        name = _local_tag(node.tag)
        ident = str(node.attrib.get("id") or "")
        if name == "Text" and is_omitted_official_text("".join(node.itertext())):
            omitted = True
        if name not in {"P1", "P2", "P3", "P", "Article", "Rule"}:
            continue
        text = _element_text(node)
        if not text:
            continue
        for key in _ident_keys(ident):
            found.setdefault(key, text)
    if omitted and "s 196" not in found:
        found["s 196"] = ". . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ."
        found["s 196(1)"] = found["s 196"]
    return found


class _FclParagraphParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.paragraphs: dict[int, list[str]] = {}
        self._current: int | None = None
        self._capture = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        mapping = dict(attrs)
        ident = str(mapping.get("id") or "")
        if ident.startswith("para_"):
            try:
                self._current = int(ident.split("_", 1)[1])
            except ValueError:
                self._current = None
            else:
                self.paragraphs.setdefault(self._current, [])
                self._capture = True
        if tag == "sup":
            self._capture = False

    def handle_endtag(self, tag: str) -> None:
        if tag == "sup" and self._current is not None:
            self._capture = True
        if tag in {"section", "article"} and self._current is not None:
            self._current = None
            self._capture = False

    def handle_data(self, data: str) -> None:
        if self._current is None or not self._capture:
            return
        self.paragraphs[self._current].append(data)


def extract_fcl_paragraphs(html: str) -> dict[int, str]:
    parser = _FclParagraphParser()
    parser.feed(html)
    extracted: dict[int, str] = {}
    for number, parts in parser.paragraphs.items():
        text = collapsed("".join(parts))
        text = re.sub(rf"^{number}\.\s*", "", text)
        if text:
            extracted[number] = text
    return extracted


def official_page_is_omitted(xml_text: str) -> bool:
    lowered = xml_text.casefold()
    if "omitted (29.6.2026)" in collapsed(lowered) or "omitted (29.6.2026)" in lowered:
        return True
    subsections = extract_legislation_subsections(xml_text)
    return any(is_omitted_official_text(text) for text in subsections.values())


def cache_stem(url: str) -> str:
    path = urlparse(url).path.strip("/")
    if path.endswith("/data.xml"):
        path = path[: -len("/data.xml")]
    if path.endswith("/data.html"):
        path = path[: -len("/data.html")]
    return path.replace("/", "_")


def cached_official_bytes(url: str, search_dirs: Sequence[Path]) -> bytes | None:
    stem = cache_stem(url)
    names = (
        f"{stem}_data.xml",
        f"{stem}.xml",
        f"{stem}_data.html",
        f"{stem}.html",
        "Ayinde-EWHC-1383-Admin-2025.html" if "1383" in url else "",
        "ECCTA-s196-omitted.xml" if "2023/56/section/196" in url else "",
        "Crime-and-Policing-Act-2026-s250.xml" if "2026/20/section/250" in url else "",
        "CRA-2015-s57.xml" if "2015/15/section/57" in url else "",
        "PA2023-s101.xml" if url.endswith("section/101") else "",
        "PA2023-s102.xml" if url.endswith("section/102") else "",
        "PA2023-s103.xml" if url.endswith("section/103") else "",
        "PA2023-s104.xml" if url.endswith("section/104") else "",
    )
    for directory in search_dirs:
        if not directory.is_dir():
            continue
        for name in names:
            if not name:
                continue
            path = directory / name
            if path.is_file() and path.stat().st_size > 0:
                return path.read_bytes()
    return None


def download_official(url: str, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read()
    destination.write_bytes(payload)
    os.chmod(destination, 0o600)
    return destination


def official_search_dirs(project_root: Path) -> tuple[Path, ...]:
    from ..config import Settings

    settings = Settings(project_root=project_root)
    ordered: list[Path] = [Path("/tmp/leg-xml"), project_root / "tmp" / "leg-xml"]
    suffixes = (
        Path("Official Legislation"),
        Path("Official Legislation") / "live60-remaining-bind-2026-08-17",
        Path("Official Legislation") / "live60-official-check-2026-08-17",
        Path("Official Legislation") / "live60-acquired-2026-08-16",
    )
    for root in settings.source_roots:
        ordered.append(root)
        for suffix in suffixes:
            ordered.append(root / suffix)
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in ordered:
        resolved = path
        if resolved not in seen:
            seen.add(resolved)
            unique.append(resolved)
    return tuple(unique)


def locator_covers(chunk_locator: str, target: str) -> bool:
    if locator_matches_target(chunk_locator, target) or locator_matches_target(
        target, chunk_locator
    ):
        return True
    loc = locator_key(chunk_locator)
    tgt = locator_key(target)
    if not loc or not tgt:
        return False
    if tgt.startswith(loc + "(") or loc.startswith(tgt + "("):
        return True
    loc_base = loc.split("(")[0].strip()
    tgt_base = tgt.split("(")[0].strip()
    return bool(loc_base and loc_base == tgt_base)


def held_reason(source_title: str, locator: str) -> str:
    title = source_title.casefold()
    loc = locator_key(locator)
    for held_id, (held_title, held_loc) in HELD_LOCATOR_KEYS.items():
        if held_title in title and (
            loc == held_loc or loc.startswith(held_loc + "(") or loc.startswith(held_loc + " ")
        ):
            if held_id == "held-provision-01" and loc.startswith("s 4a"):
                continue
            return held_id
    return ""


def later_treatment_token(value: str) -> str:
    lowered = value.casefold()
    if lowered.startswith("confirmed_current"):
        return "confirmed_current"
    if lowered.startswith("qualified_current"):
        return "qualified_current"
    return ""


def _chunk_body(row: Mapping[str, Any]) -> str:
    return strip_locator_prefix(str(row["markdown_text"] or ""), str(row["locator"] or ""))


def _bodies_equal_official(bodies: Sequence[str], official: str) -> bool:
    joined = collapsed(" ".join(bodies))
    return comparable(joined) == comparable(official)


def match_official_to_chunks(
    *,
    official_text: str,
    rows: Sequence[Any],
) -> list[Any]:
    """Return the smallest exact catalogue window equal to official text."""

    if not official_text or not rows:
        return []
    eligible = []
    for row in rows:
        excerpt = str(row["markdown_text"] or "")
        if (
            is_omitted_official_text(excerpt)
            or is_spliced_join(excerpt)
            or contains_omitted_dots(excerpt)
        ):
            continue
        if is_cross_ref_fragment(excerpt):
            continue
        eligible.append(row)
    for row in eligible:
        body = _chunk_body(row)
        if _bodies_equal_official((body,), official_text) or comparable(
            str(row["markdown_text"] or "")
        ) == comparable(official_text):
            return [row]
    ordered = sorted(eligible, key=lambda item: (int(item["ordinal"] or 0), str(item["chunk_id"])))
    for start in range(len(ordered)):
        bodies: list[str] = []
        window: list[Any] = []
        previous_ordinal: int | None = None
        for row in ordered[start:]:
            ordinal = int(row["ordinal"] or 0)
            if previous_ordinal is not None and ordinal != previous_ordinal + 1:
                break
            previous_ordinal = ordinal
            window.append(row)
            bodies.append(_chunk_body(row))
            if _bodies_equal_official(bodies, official_text):
                return window
            if len(comparable(" ".join(bodies))) > len(comparable(official_text)) + 40:
                break
    return []


def _candidate_from_row(
    *,
    row: Any,
    case_id: str,
    issue_id: str,
    source_name: str,
    pinpoint: str,
    origin: str,
) -> dict[str, Any]:
    candidate = _catalogue_candidate(
        row=row,
        case_id=case_id,
        issue_id=issue_id,
        source_name=source_name,
        source_kind="legislation",
        candidate_origin=origin,
        map_rank="",
        map_pinpoint=pinpoint,
    )
    return _public_candidate(candidate)


def run_remaining_official_bind(
    *,
    project_root: Path,
    catalog_path: Path,
    owner_answers_path: Path,
    review_export_path: Path,
    imported_rows_path: Path,
    as_of_date: date,
    download_dir: Path,
    result_path: Path,
    pack_path: Path,
    import_out_path: Path,
    evidence_map_path: Path | None = None,
    overwrite: bool = False,
    fetch_missing: bool = True,
) -> dict[str, Any]:
    """Match remaining 293 issues to official text and import hash-exact gold only."""

    owner = json.loads(owner_answers_path.read_text(encoding="utf-8"))
    imported = json.loads(imported_rows_path.read_text(encoding="utf-8"))
    records = {str(item["issue_key"]): item for item in owner.get("records") or ()}
    already_qualified = {
        str(row["row_id"]): row
        for row in imported.get("rows") or ()
        if row.get("status") == "qualified"
    }
    search_dirs = (*official_search_dirs(project_root), download_dir)
    download_dir.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(f"file:{catalog_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    source_versions = _eligible_source_versions(connection)
    source_cache: dict[str, list[Any]] = {}

    def versions_for(title: str, url: str) -> list[Any]:
        wanted_url = url.rstrip("/")
        matches: list[tuple[float, Any]] = []
        for version in source_versions:
            score = _title_match_score(title, str(version["title"] or ""))
            canonical = str(version["canonical_url"] or "").rstrip("/")
            url_hit = bool(wanted_url and canonical and wanted_url.startswith(canonical))
            if score < 0.7 and not url_hit:
                continue
            matches.append((1.0 if url_hit else score, version))
        matches.sort(
            key=lambda item: (
                -item[0],
                0
                if str(item[1]["currentness_status"] or "") == "latest_available_revised_snapshot"
                else 1,
                str(item[1]["source_version_id"]),
            )
        )
        return [item[1] for item in matches[:2]]

    def catalogue_match(target: str, official: str, title: str, page_url: str) -> list[Any]:
        if not official:
            return []
        matched: list[Any] = []
        for version in versions_for(title, page_url):
            rows = []
            for item in _chunks_for_source(
                connection, str(version["source_version_id"]), cache=source_cache
            ):
                if not locator_covers(str(item["locator"] or ""), target):
                    continue
                if (
                    _eligible_row(
                        connection=connection,
                        row=item,
                        chunk_id=str(item["chunk_id"]),
                        source_type="legislation",
                        as_of_date=as_of_date,
                        exclusions=Counter(),
                    )
                    is None
                ):
                    continue
                rows.append(item)
            matched = match_official_to_chunks(official_text=official, rows=rows)
            if matched:
                return matched
        return []

    def load_official(page_url: str) -> tuple[str, str, str]:
        xml_url = (
            legislation_data_xml_url(page_url) if "legislation.gov.uk" in page_url else page_url
        )
        if "caselaw.nationalarchives.gov.uk" in page_url and not page_url.endswith(
            (".xml", ".html")
        ):
            xml_url = page_url.rstrip("/") + "/data.html"
        cached = cached_official_bytes(xml_url or page_url, search_dirs)
        if cached is None and fetch_missing and xml_url:
            stem = cache_stem(xml_url)
            suffix = ".html" if xml_url.endswith(".html") else ".xml"
            try:
                path = download_official(xml_url, download_dir / f"{stem}_data{suffix}")
                cached = path.read_bytes()
                tmp = Path("/tmp/leg-xml") / path.name
                tmp.parent.mkdir(parents=True, exist_ok=True)
                tmp.write_bytes(cached)
            except (urllib.error.URLError, TimeoutError, OSError):
                cached = None
        if cached is None:
            return "", xml_url, "official_bytes_missing"
        text = cached.decode("utf-8", errors="replace")
        return text, xml_url, "official_bytes_present"

    issue_reports: list[dict[str, Any]] = []
    gold_by_row: dict[str, dict[str, Any]] = {}

    for row_id, record in records.items():
        report: dict[str, Any] = {
            "row_id": row_id,
            "answer_status": record.get("answer_status") or "",
            "owner_reviewer_decision": record.get("owner_reviewer_decision") or "",
            "bind_status": "keep_gap",
            "reason": "",
            "correction": "",
            "official_url": "",
            "official_locator": "",
            "official_text": "",
            "candidate_chunk_ids": [],
            "gold_candidate_ids": [],
        }
        source_title = str(record.get("source_title") or "")
        locator = str(record.get("legal_locator") or "")
        owner_text = str(record.get("operative_text") or "")
        source_url = str(record.get("official_source_url") or "")
        source_type = str(record.get("source_type") or "")
        later = later_treatment_token(str(record.get("later_treatment_status") or ""))

        held = held_reason(source_title, locator)
        if held:
            report["bind_status"] = "keep_gap"
            report["reason"] = f"held_statute_{held}"
            issue_reports.append(report)
            continue

        if row_id in {"live30-q29:issue-01", "live60-q48:issue-07"}:
            xml_text, xml_url, _status = load_official(ECCTA_S196_URL)
            cpa_text, cpa_url, _cpa_status = load_official(CPA_2026_S250_URL)
            report["correction"] = "eccta_s196_omitted_cpa_2026_s250_current"
            report["official_url"] = cpa_url or CPA_2026_S250_URL
            subsections = extract_legislation_subsections(cpa_text) if cpa_text else {}
            official = subsections.get("s 250(1)") or subsections.get("s 250") or ""
            report["official_locator"] = "s 250(1)"
            report["official_text"] = official
            if xml_text and official_page_is_omitted(xml_text):
                report["reason"] = "omitted_provision_no_approved_current_chunk"
            versions = versions_for("Crime and Policing Act 2026", CPA_2026_S250_URL)
            matched: list[Any] = []
            for version in versions:
                rows = [
                    item
                    for item in _chunks_for_source(
                        connection, str(version["source_version_id"]), cache=source_cache
                    )
                    if locator_covers(str(item["locator"] or ""), "s 250")
                ]
                eligible_rows = [
                    item
                    for item in rows
                    if _eligible_row(
                        connection=connection,
                        row=item,
                        chunk_id=str(item["chunk_id"]),
                        source_type="legislation",
                        as_of_date=as_of_date,
                        exclusions=Counter(),
                    )
                    is not None
                ]
                matched = match_official_to_chunks(official_text=official, rows=eligible_rows)
                if matched:
                    break
            if matched and official:
                candidates = [
                    _candidate_from_row(
                        row=row,
                        case_id=record["case_id"],
                        issue_id=record["issue_id"],
                        source_name="Crime and Policing Act 2026",
                        pinpoint="s 250(1)",
                        origin="official_current_omitted_replacement",
                    )
                    for row in matched
                ]
                gold_by_row[row_id] = {
                    "candidates": candidates,
                    "approved_candidate_ids": [item["candidate_id"] for item in candidates],
                    "owner_legal_role": "statutory_text",
                    "source_name": "Crime and Policing Act 2026",
                }
                report["bind_status"] = "gold"
                report["reason"] = "exact_catalogue_chunk"
                report["gold_candidate_ids"] = [item["candidate_id"] for item in candidates]
                report["candidate_chunk_ids"] = [str(row["chunk_id"]) for row in matched]
            else:
                report["bind_status"] = "candidate"
                report["reason"] = "official_exact_text_no_approved_catalogue_hash"
            issue_reports.append(report)
            continue

        if row_id == "live30-q02:issue-09":
            s47_xml, _, _ = load_official(CRA_S47_URL)
            s31_xml, _, _ = load_official(CRA_S31_URL)
            s57_xml, _, _ = load_official(CRA_S57_URL)
            s47 = extract_legislation_subsections(s47_xml)
            s31 = extract_legislation_subsections(s31_xml)
            s57 = extract_legislation_subsections(s57_xml)
            report["correction"] = "cra_s47_digital_content_not_services_s57"
            report["official_url"] = CRA_S47_URL
            official_s47 = s47.get("s 47(1)") or ""
            official_s31 = s31.get("s 31(1)") or ""
            report["official_locator"] = "s 31(1); s 47(1)"
            report["official_text"] = collapsed(f"{official_s31} {official_s47}").strip()
            if pack_quote_is_services_exclusion(owner_text):
                report["reason"] = "owner_quote_was_services_exclusion_not_s47"
            versions = versions_for("Consumer Rights Act 2015", CRA_S47_URL)
            matched_rows: list[Any] = []
            for version in versions:
                chunks = _chunks_for_source(
                    connection, str(version["source_version_id"]), cache=source_cache
                )
                for target, official in (("s 31", official_s31), ("s 47", official_s47)):
                    rows = [
                        item
                        for item in chunks
                        if locator_covers(str(item["locator"] or ""), target)
                        and _eligible_row(
                            connection=connection,
                            row=item,
                            chunk_id=str(item["chunk_id"]),
                            source_type="legislation",
                            as_of_date=as_of_date,
                            exclusions=Counter(),
                        )
                        is not None
                    ]
                    hit = match_official_to_chunks(official_text=official, rows=rows)
                    if hit:
                        matched_rows.extend(hit)
            if matched_rows and official_s47:
                candidates = [
                    _candidate_from_row(
                        row=row,
                        case_id=record["case_id"],
                        issue_id=record["issue_id"],
                        source_name="Consumer Rights Act 2015",
                        pinpoint="ss 31 and 47",
                        origin="official_corrected_s31_s47",
                    )
                    for row in matched_rows
                ]
                if all(item.get("cross_ref_fragment") is not True for item in candidates):
                    gold_by_row[row_id] = {
                        "candidates": candidates,
                        "approved_candidate_ids": [item["candidate_id"] for item in candidates],
                        "owner_legal_role": "statutory_text",
                        "source_name": "Consumer Rights Act 2015",
                    }
                    report["bind_status"] = "gold"
                    report["reason"] = "exact_catalogue_chunk"
                    report["gold_candidate_ids"] = [item["candidate_id"] for item in candidates]
                    report["candidate_chunk_ids"] = [str(row["chunk_id"]) for row in matched_rows]
                else:
                    report["bind_status"] = "candidate"
                    report["reason"] = "official_subsections_split_into_cross_ref_fragments"
            else:
                report["bind_status"] = "candidate"
                report["reason"] = "official_s31_s47_no_single_non_fragment_chunk"
                report["s57_1"] = s57.get("s 57(1)") or ""
                report["s57_2"] = s57.get("s 57(2)") or ""
                report["s57_3"] = s57.get("s 57(3)") or ""
            issue_reports.append(report)
            continue

        if row_id in {"live30-q24:issue-02", "live30-q24:issue-03", "live30-q24:issue-09"}:
            html, fcl_url, _ = load_official(AYINDE_FCL_URL)
            paragraphs = extract_fcl_paragraphs(html) if html else {}
            wanted = 7 if row_id != "live30-q24:issue-03" else 6
            official = paragraphs.get(wanted) or ""
            if row_id == "live30-q24:issue-03":
                official = collapsed(" ".join(paragraphs[n] for n in (6, 7) if n in paragraphs))
            report["correction"] = "ayinde_fcl_exact_not_judiciary_paraphrase"
            report["official_url"] = AYINDE_FCL_URL
            report["official_locator"] = (
                f"[{wanted}]" if row_id != "live30-q24:issue-03" else "[6]-[7]"
            )
            report["official_text"] = official
            if owner_text and official and ayinde_quote_is_paraphrase(owner_text, official):
                report["reason"] = "pack_quote_is_paraphrase_of_fcl"
            versions = versions_for("Ayinde", AYINDE_FCL_URL)
            if not versions:
                report["bind_status"] = "candidate"
                report["reason"] = (report["reason"] + "; " if report["reason"] else "") + (
                    "fcl_bytes_saved_no_catalogue_chunk"
                )
                report["owner_later_treatment_copied_not_gold"] = later or ""
                issue_reports.append(report)
                continue
            issue_reports.append(report)
            continue

        if row_id == "live60-q32:issue-08":
            xml_text, xml_url, _ = load_official(LIMITATION_S4A_URL)
            subsections = extract_legislation_subsections(xml_text) if xml_text else {}
            official = subsections.get("s 4A") or subsections.get("s 4A(1)") or ""
            report["correction"] = "limitation_s4a_official_opening"
            report["official_url"] = xml_url or LIMITATION_S4A_URL
            report["official_locator"] = "s 4A"
            report["official_text"] = official
            if owner_text and not limitation_4a_uses_official_opening(owner_text):
                report["reason"] = "pack_rewrote_s4a_opening"
            versions = versions_for("Limitation Act 1980", LIMITATION_S4A_URL)
            matched = []
            for version in versions:
                rows = [
                    item
                    for item in _chunks_for_source(
                        connection, str(version["source_version_id"]), cache=source_cache
                    )
                    if locator_covers(str(item["locator"] or ""), "s 4A")
                    and _eligible_row(
                        connection=connection,
                        row=item,
                        chunk_id=str(item["chunk_id"]),
                        source_type="legislation",
                        as_of_date=as_of_date,
                        exclusions=Counter(),
                    )
                    is not None
                ]
                matched = match_official_to_chunks(official_text=official, rows=rows)
                if matched:
                    break
            if matched and official:
                candidates = [
                    _candidate_from_row(
                        row=row,
                        case_id=record["case_id"],
                        issue_id=record["issue_id"],
                        source_name="Limitation Act 1980",
                        pinpoint="s 4A",
                        origin="official_s4a",
                    )
                    for row in matched
                ]
                gold_by_row[row_id] = {
                    "candidates": candidates,
                    "approved_candidate_ids": [item["candidate_id"] for item in candidates],
                    "owner_legal_role": "statutory_text",
                    "source_name": "Limitation Act 1980",
                }
                report["bind_status"] = "gold"
                report["reason"] = "exact_catalogue_chunk"
                report["gold_candidate_ids"] = [item["candidate_id"] for item in candidates]
            else:
                report["bind_status"] = "candidate"
                report["reason"] = report["reason"] or "s4a_spliced_or_no_exact_chunk"
            issue_reports.append(report)
            continue

        if row_id in {"live30-q21:issue-06", "live30-q21:issue-07", "live30-q21:issue-08"}:
            locator_map = {
                "live30-q21:issue-06": ("s 101", "s 102"),
                "live30-q21:issue-07": ("s 103",),
                "live30-q21:issue-08": ("s 104",),
            }
            wanted_keys = locator_map[row_id]
            texts: list[str] = []
            urls: list[str] = []
            for key in wanted_keys:
                xml_text, xml_url, _ = load_official(PROCUREMENT_PART9[key])
                part9_subsections = extract_legislation_subsections(xml_text) if xml_text else {}
                official = part9_subsections.get(f"{key}(1)") or part9_subsections.get(key) or ""
                texts.append(official)
                urls.append(xml_url or PROCUREMENT_PART9[key])
            report["correction"] = "procurement_act_2023_part9_exact_subsections"
            report["official_url"] = urls[0] if urls else ""
            report["official_locator"] = "; ".join(f"{item}(1)" for item in wanted_keys)
            report["official_text"] = collapsed(" ".join(texts))
            if row_id == "live30-q21:issue-07":
                report["bind_status"] = "candidate"
                report["reason"] = (
                    "damages_is_not_one_complete_rule_s103_recorded_not_over_qualified"
                )
                issue_reports.append(report)
                continue
            versions = versions_for("Procurement Act 2023", PROCUREMENT_PART9[wanted_keys[0]])
            matched = []
            official = texts[0]
            for version in versions:
                rows = [
                    item
                    for item in _chunks_for_source(
                        connection, str(version["source_version_id"]), cache=source_cache
                    )
                    if locator_covers(str(item["locator"] or ""), wanted_keys[0])
                    and _eligible_row(
                        connection=connection,
                        row=item,
                        chunk_id=str(item["chunk_id"]),
                        source_type="legislation",
                        as_of_date=as_of_date,
                        exclusions=Counter(),
                    )
                    is not None
                ]
                matched = match_official_to_chunks(official_text=official, rows=rows)
                if matched:
                    break
            if matched and official:
                candidates = [
                    _candidate_from_row(
                        row=row,
                        case_id=record["case_id"],
                        issue_id=record["issue_id"],
                        source_name="Procurement Act 2023",
                        pinpoint=wanted_keys[0],
                        origin="official_part9",
                    )
                    for row in matched
                ]
                gold_by_row[row_id] = {
                    "candidates": candidates,
                    "approved_candidate_ids": [item["candidate_id"] for item in candidates],
                    "owner_legal_role": "statutory_text",
                    "source_name": "Procurement Act 2023",
                }
                report["bind_status"] = "gold"
                report["reason"] = "exact_catalogue_chunk"
            else:
                report["bind_status"] = "candidate"
                report["reason"] = "official_exact_text_staged_or_unapproved_source"
            issue_reports.append(report)
            continue

        if source_type == "case_law" or "caselaw.nationalarchives.gov.uk" in source_url:
            if later not in CASE_LATER_TREATMENT:
                report["bind_status"] = "keep_gap"
                report["reason"] = "case_later_treatment_uncertain_or_missing"
                issue_reports.append(report)
                continue
            if later == "qualified_current":
                report["bind_status"] = "keep_gap"
                report["reason"] = "qualified_current_missing_limiting_authority_ids"
                issue_reports.append(report)
                continue
            fcl_url = (
                source_url.split()[0] if "caselaw.nationalarchives.gov.uk" in source_url else ""
            )
            html = ""
            if fcl_url:
                html, _, _ = load_official(fcl_url)
            report["official_url"] = fcl_url
            report["official_text"] = owner_text
            report["bind_status"] = "keep_gap" if not fcl_url else "candidate"
            report["reason"] = "case_law_requires_exact_fcl_paragraph_and_catalogue_hash"
            if later:
                report["owner_later_treatment_copied_not_gold"] = later
            issue_reports.append(report)
            continue

        if source_type not in {"legislation_or_procedural_instrument", "procedural_rule"}:
            report["bind_status"] = "keep_gap"
            report["reason"] = "keep_gap_no_safe_operative_span"
            issue_reports.append(report)
            continue

        page_urls = official_page_urls(source_url, locator, source_title)
        if (
            any("justice.gov.uk" in item for item in split_source_urls(source_url))
            or any(item.startswith(CPR_GOLD_HOST) and "/rule/" in item for item in page_urls)
        ) and ("justice.gov.uk" in source_url or "civil procedure" in source_title.casefold()):
            report["correction"] = "cpr_gold_is_legislation_gov_uk_uksi_1998_3132"
        subsections = {}
        xml_url = ""
        status = "no_url"
        xml_texts: list[str] = []
        for page_url in page_urls:
            xml_text, fetched_url, status = load_official(page_url)
            xml_url = xml_url or fetched_url or page_url
            if xml_text:
                xml_texts.append(xml_text)
                subsections.update(extract_legislation_subsections(xml_text))
        report["official_url"] = xml_url or (page_urls[0] if page_urls else "")
        targets = bind_targets(locator, " ".join(page_urls) or source_url)
        extracted: list[tuple[str, str]] = []
        for target in targets:
            official = lookup_subsection(subsections, target)
            if official:
                extracted.append((target, official))
        if (
            not extracted
            and owner_text
            and xml_texts
            and any(comparable(owner_text) in comparable(xml_text) for xml_text in xml_texts)
        ):
            extracted.append((locator or (targets[0] if targets else ""), collapsed(owner_text)))
        report["official_locator"] = "; ".join(item[0] for item in extracted) or locator
        report["official_text"] = collapsed(" ".join(item[1] for item in extracted))
        if not extracted:
            report["bind_status"] = (
                "keep_gap" if record.get("answer_status") == "KEEP_GAP" else "candidate"
            )
            report["reason"] = (
                status
                if status != "official_bytes_present"
                else "official_subsection_not_extracted"
            )
            issue_reports.append(report)
            continue
        if any(contains_omitted_dots(text) for _target, text in extracted):
            report["bind_status"] = "candidate"
            report["reason"] = "omitted_bytes_in_official_text"
            issue_reports.append(report)
            continue
        if (
            owner_text
            and extracted
            and comparable(owner_text) != comparable(extracted[0][1])
            and comparable(owner_text) not in comparable(extracted[0][1])
        ):
            report["reason"] = "owner_text_not_exact_official_subsection"
        title = (
            source_title
            if source_title != "Civil Procedure Rules"
            else "The Civil Procedure Rules 1998"
        )
        matched_rows = []
        matched_targets: list[str] = []
        missing_targets: list[str] = []
        any_version = False
        for target, official in extracted:
            target_title = "The Civil Procedure Rules 1998" if target.startswith("r ") else title
            target_url = ""
            needle = ""
            if target.startswith("s "):
                needle = "/section/" + target[2:].split("(", 1)[0]
            elif target.startswith("art "):
                needle = "/article/" + target[4:].split("(", 1)[0]
            elif target.startswith("reg "):
                needle = "/regulation/" + target[4:].split("(", 1)[0]
            elif target.startswith("r "):
                needle = "/rule/" + target[2:].split("(", 1)[0]
            if needle:
                for page_url in page_urls:
                    if needle.casefold() in page_url.casefold():
                        target_url = page_url
                        break
            target_url = target_url or (page_urls[0] if page_urls else "")
            if versions_for(target_title, target_url):
                any_version = True
            hit = catalogue_match(target, official, target_title, target_url)
            if hit:
                matched_rows.extend(hit)
                matched_targets.append(target)
            else:
                missing_targets.append(target)
        if matched_rows and not missing_targets and len(matched_targets) == len(extracted):
            candidates = [
                _candidate_from_row(
                    row=row,
                    case_id=record["case_id"],
                    issue_id=record["issue_id"],
                    source_name=title,
                    pinpoint=report["official_locator"],
                    origin="official_catalogue_exact",
                )
                for row in matched_rows
            ]
            if any(item.get("cross_ref_fragment") is True for item in candidates):
                report["bind_status"] = "candidate"
                report["reason"] = "matched_window_contains_cross_ref_fragment"
            else:
                gold_by_row[row_id] = {
                    "candidates": candidates,
                    "approved_candidate_ids": [item["candidate_id"] for item in candidates],
                    "owner_legal_role": "statutory_text",
                    "source_name": title,
                }
                report["bind_status"] = "gold"
                report["reason"] = "exact_catalogue_chunk"
                report["gold_candidate_ids"] = [item["candidate_id"] for item in candidates]
                report["candidate_chunk_ids"] = [str(row["chunk_id"]) for row in matched_rows]
        else:
            report["bind_status"] = "candidate" if extracted else "keep_gap"
            if missing_targets and matched_targets:
                report["reason"] = report["reason"] or "official_exact_text_partial_catalogue_hash"
                report["matched_targets"] = matched_targets
                report["missing_targets"] = missing_targets
            else:
                report["reason"] = report["reason"] or (
                    "official_exact_text_no_approved_catalogue_hash"
                    if any_version
                    else "no_approved_current_source_version"
                )
        issue_reports.append(report)

    connection.close()

    counts = Counter(item["bind_status"] for item in issue_reports)
    result = {
        "schema": OFFICIAL_BIND_RESULT_SCHEMA,
        "as_of_date": as_of_date.isoformat(),
        "ai_role": "mechanical_accuracy_verifier_only",
        "gold": False,
        "seals_expert_gold": False,
        "ready_for_overlay_seal": False,
        "automatic_knowledge_gap": False,
        "writes_active": False,
        "writes_o04": False,
        "remaining_selected_issues": len(issue_reports),
        "bind_counts": {
            "gold": int(counts["gold"]),
            "candidate": int(counts["candidate"]),
            "keep_gap": int(counts["keep_gap"]),
        },
        "already_qualified_selected": len(already_qualified),
        "issues": issue_reports,
        "d1_d15_blocked": True,
        "d1_d15_reason": "CONFIRM_OWNER_AUTHORED_SEAL_absent",
        "overlay_blocked": True,
        "stage_a_blocked": True,
    }
    _write_json(result_path, result)

    pack = _build_import_pack(
        project_root=project_root,
        catalog_path=catalog_path,
        evidence_map_path=evidence_map_path
        or project_root
        / "Live60-2026-08-16"
        / "go-execution"
        / "issue-candidate-evidence-map.json",
        imported=imported,
        gold_by_row=gold_by_row,
        as_of_date=as_of_date,
    )
    _write_json(pack_path, pack)
    imported_payload = import_owner_final_check(
        project_root=project_root,
        catalog_path=catalog_path,
        pack_path=pack_path,
        review_export_path=review_export_path,
        as_of_date=as_of_date,
        confirmation_token=OWNER_FINAL_CHECK_TOKEN,
    )
    if import_out_path.exists() and not overwrite:
        raise FileExistsError("reviewed remaining-bind rows already exist")
    raw = _write_json(import_out_path, imported_payload)
    result["import"] = {
        "selected_qualified_issue_count": imported_payload["selected_qualified_issue_count"],
        "selected_knowledge_gap_issue_count": imported_payload[
            "selected_knowledge_gap_issue_count"
        ],
        "selected_evidence_complete": imported_payload["selected_evidence_complete"],
        "ready_for_overlay_seal": imported_payload["ready_for_overlay_seal"],
        "reviewed_rows_sha256": _sha256_bytes(raw),
        "path": str(import_out_path),
    }
    result["pack_path"] = str(pack_path)
    result["result_path"] = str(result_path)
    _write_json(result_path, result)
    return result


def _candidate_from_chunk_id(
    *,
    connection: sqlite3.Connection,
    chunk_id: str,
    case_id: str,
    issue_id: str,
    source_name: str,
    pinpoint: str,
    as_of_date: date,
) -> dict[str, Any] | None:
    from .live_suite_final_check import _CATALOGUE_ROW_SQL

    row = connection.execute(_CATALOGUE_ROW_SQL, (chunk_id,)).fetchone()
    eligible = _eligible_row(
        connection=connection,
        row=row,
        chunk_id=chunk_id,
        source_type="legislation" if "p " not in pinpoint.casefold() else "case",
        as_of_date=as_of_date,
        exclusions=Counter(),
    )
    if eligible is None:
        return None
    source_kind = (
        "case"
        if str(eligible["currentness_status"] or "")
        in {
            "historical",
            "point_in_time",
        }
        and "p " in str(eligible["locator"] or "").casefold()
        else "legislation"
    )
    if str(eligible["locator"] or "").casefold().startswith("p "):
        source_kind = "case"
    candidate = _catalogue_candidate(
        row=eligible,
        case_id=case_id,
        issue_id=issue_id,
        source_name=source_name,
        source_kind=source_kind,
        candidate_origin="existing_qualified_span",
        map_rank="",
        map_pinpoint=pinpoint,
    )
    return _public_candidate(candidate)


def _build_import_pack(
    *,
    project_root: Path,
    catalog_path: Path,
    evidence_map_path: Path,
    imported: Mapping[str, Any],
    gold_by_row: Mapping[str, Mapping[str, Any]],
    as_of_date: date,
    repair: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    bundle = load_live_evaluation_bundle(project_root / LIVE60_ROOT)
    evidence_map_bytes = evidence_map_path.read_bytes()
    identity = build_owner_reviewer_identity(as_of_date=as_of_date)
    selected_ids = selected_generation_case_ids(bundle)
    imported_rows = {str(row["row_id"]): row for row in imported.get("rows") or ()}
    connection = sqlite3.connect(f"file:{catalog_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    cases: list[dict[str, Any]] = []
    try:
        for case in bundle.registry.cases:
            if case.case_id not in selected_ids:
                continue
            issues: list[dict[str, Any]] = []
            for number, topic in enumerate(case.must_cover_issues, start=1):
                issue_id = f"issue-{number:02d}"
                row_id = f"{case.case_id}:{issue_id}"
                existing = imported_rows.get(row_id) or {}
                gold = gold_by_row.get(row_id)
                if existing.get("status") == "qualified" and existing.get("exact_gold_spans"):
                    candidates = []
                    selected_ids_for_row = []
                    later = ""
                    role = ""
                    proposition = ""
                    for span in existing["exact_gold_spans"]:
                        candidate = _candidate_from_chunk_id(
                            connection=connection,
                            chunk_id=str(span["chunk_id"]),
                            case_id=case.case_id,
                            issue_id=issue_id,
                            source_name=str(span.get("legal_authority_id") or ""),
                            pinpoint=str(span.get("legal_locator") or ""),
                            as_of_date=as_of_date,
                        )
                        if candidate is None:
                            continue
                        candidates.append(candidate)
                        selected_ids_for_row.append(candidate["candidate_id"])
                        review = span.get("case_currentness_review") or {}
                        later = str(review.get("later_treatment_status") or later)
                        role = str(span.get("legal_role") or role)
                        proposition = collapsed(str(candidate.get("excerpt") or ""))
                    action = "accept_qualify" if selected_ids_for_row else "reject_keep_gap"
                    issues.append(
                        {
                            "row_id": row_id,
                            "case_id": case.case_id,
                            "issue_id": issue_id,
                            "topic": topic,
                            "topic_sha256": _sha256_text(topic),
                            "proposed_action": action,
                            "owner_action": action,
                            "owner_later_treatment": later if action == "accept_qualify" else "",
                            "owner_legal_role": role if action == "accept_qualify" else "",
                            "owner_exact_proposition": proposition if later else "",
                            "cannot_fill_reason": ""
                            if action == "accept_qualify"
                            else "existing_qualified_span_not_reverified",
                            "excluded_reason_counts": {},
                            "proposed_candidate_id": selected_ids_for_row[0]
                            if selected_ids_for_row
                            else "",
                            "approved_candidate_ids": selected_ids_for_row,
                            "candidates": candidates,
                            "seals_expert_gold": False,
                        }
                    )
                    continue
                if gold:
                    candidates = list(gold["candidates"])
                    selected = list(gold["approved_candidate_ids"])
                    issues.append(
                        {
                            "row_id": row_id,
                            "case_id": case.case_id,
                            "issue_id": issue_id,
                            "topic": topic,
                            "topic_sha256": _sha256_text(topic),
                            "proposed_action": "accept_qualify",
                            "owner_action": "accept_qualify",
                            "owner_later_treatment": "",
                            "owner_legal_role": gold.get("owner_legal_role") or "statutory_text",
                            "owner_exact_proposition": "",
                            "cannot_fill_reason": "",
                            "excluded_reason_counts": {},
                            "proposed_candidate_id": selected[0],
                            "approved_candidate_ids": selected,
                            "candidates": candidates,
                            "seals_expert_gold": False,
                        }
                    )
                    continue
                issues.append(
                    {
                        "row_id": row_id,
                        "case_id": case.case_id,
                        "issue_id": issue_id,
                        "topic": topic,
                        "topic_sha256": _sha256_text(topic),
                        "proposed_action": "cannot_fill_keep_gap",
                        "owner_action": "reject_keep_gap",
                        "owner_later_treatment": "",
                        "owner_legal_role": "",
                        "owner_exact_proposition": "",
                        "cannot_fill_reason": existing.get("reason_code")
                        or "owner_rejected_or_unfilled_final_check",
                        "excluded_reason_counts": {},
                        "proposed_candidate_id": "",
                        "approved_candidate_ids": [],
                        "candidates": [],
                        "seals_expert_gold": False,
                    }
                )
            cases.append(
                {
                    "case_id": case.case_id,
                    "subject": case.subject,
                    "task_type": case.task_type,
                    "expected_research_route": case.expected_research_route,
                    "question_sha256": case.question_sha256,
                    "record_sha256": case.record_sha256,
                    "issues": issues,
                }
            )
    finally:
        connection.close()

    payload = {
        "schema": FINAL_CHECK_SCHEMA,
        "suite_id": "live-evaluation-60-v1",
        "as_of_date": as_of_date.isoformat(),
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "evidence_map_sha256": _sha256_bytes(evidence_map_bytes),
        "status": "owner_adopted_official_exact_bind",
        "word_is_gold": False,
        "word_is_import_surface": False,
        "owner_confirmation_token": OWNER_FINAL_CHECK_TOKEN,
        "reviewer_role": identity["approval_reviewer_role"],
        "reviewer_ref": identity["approval_reviewer_ref"],
        "selected_case_count": len(cases),
        "selected_issue_count": sum(len(case["issues"]) for case in cases),
        "bucket_counts": {},
        "held_statutes": [
            {
                "held_id": held_id,
                "proposed_action": "cannot_fill_keep_gap",
                "owner_action": "hold",
            }
            for held_id, _title, _note in HELD_STATUTORY_PROVISIONS
        ],
        "cases": cases,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "owner_is_primary_reviewer": True,
        "seals_expert_gold": False,
        "ready_for_overlay_seal": False,
        "generation_authorised": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "writes_active": False,
        "writes_o04": False,
    }
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key not in {"cases", "held_statutes"}}
    )
    return payload
