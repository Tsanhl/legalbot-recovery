from __future__ import annotations

import html
import re
from collections.abc import Iterable, Mapping
from datetime import date
from typing import Any
from urllib.parse import urlparse

from ..types import EvidenceSpan, RenderedAnswer, StructuredDraft

OSCOLA_POLICY_VERSION = "oscola-5.0-2026-03.v2"


class CitationMetadataError(ValueError):
    pass


def _clean(value: Any) -> str:
    return " ".join(str(value or "").split())


def _require(data: Mapping[str, Any], *keys: str) -> list[str]:
    values = [_clean(data.get(key)) for key in keys]
    missing = [key for key, value in zip(keys, values, strict=True) if not value]
    if missing:
        raise CitationMetadataError(f"Missing OSCOLA fields: {', '.join(missing)}")
    return values


def _date_text(value: Any, field: str) -> str:
    cleaned = _clean(value)
    if not cleaned:
        raise CitationMetadataError(f"Missing OSCOLA fields: {field}")
    try:
        parsed = date.fromisoformat(cleaned)
    except ValueError:
        return cleaned
    return f"{parsed.day} {parsed.strftime('%B')} {parsed.year}"


def _normalise_range(value: str) -> str:
    return re.sub(r"(?<=\d)[-–](?=\d)", "–", value)


def _secondary_pinpoint(value: str) -> str:
    pinpoint = _normalise_range(_clean(value))
    return re.sub(r"^(?:pp?|pages?)\.?\s+", "", pinpoint, flags=re.IGNORECASE)


def _legislation_pinpoint(value: str) -> str:
    pinpoint = _normalise_range(_clean(value))
    replacements = (
        (r"^sections?\s+", "ss " if re.match(r"^sections\s+", pinpoint, re.I) else "s "),
        (r"^regulations?\s+", "regs " if re.match(r"^regulations\s+", pinpoint, re.I) else "reg "),
        (r"^rules?\s+", "rr " if re.match(r"^rules\s+", pinpoint, re.I) else "r "),
        (r"^articles?\s+", "arts " if re.match(r"^articles\s+", pinpoint, re.I) else "art "),
        (r"^paragraphs?\s+", "paras " if re.match(r"^paragraphs\s+", pinpoint, re.I) else "para "),
        (r"^schedules?\s+", "schs " if re.match(r"^schedules\s+", pinpoint, re.I) else "sch "),
    )
    for pattern, replacement in replacements:
        if re.match(pattern, pinpoint, re.IGNORECASE):
            return re.sub(pattern, replacement, pinpoint, count=1, flags=re.IGNORECASE)
    return pinpoint


def _case_pinpoint(value: str, data: Mapping[str, Any]) -> str:
    pinpoint = _normalise_range(_clean(value))
    if not pinpoint:
        return ""
    paragraph_match = re.fullmatch(r"paras?\.?\s+(.+)", pinpoint, re.IGNORECASE)
    if paragraph_match:
        pinpoint = paragraph_match.group(1)
        values = [part.strip() for part in pinpoint.split(",") if part.strip()]
        formatted: list[str] = []
        for item in values:
            range_match = re.fullmatch(r"(\d+[A-Za-z]?)[–-](\d+[A-Za-z]?)", item)
            if range_match:
                formatted.append(f"[{range_match.group(1)}]–[{range_match.group(2)}]")
            elif re.fullmatch(r"\d+[A-Za-z]?", item):
                formatted.append(f"[{item}]")
            else:
                raise CitationMetadataError(
                    "Case paragraph pinpoints must contain paragraph numbers"
                )
        return ", ".join(formatted)
    if _clean(data.get("pinpoint_type")).lower() == "paragraph":
        if not re.fullmatch(r"\d+[A-Za-z]?", pinpoint):
            raise CitationMetadataError("A paragraph pinpoint must be a single paragraph number")
        return f"[{pinpoint}]"
    if pinpoint.startswith("["):
        return pinpoint
    return _secondary_pinpoint(pinpoint)


def _year_token(data: Mapping[str, Any]) -> str:
    year = _clean(data.get("year"))
    if re.fullmatch(r"(?:\[\d{4}\]|\(\d{4}\))", year):
        return year
    if not re.fullmatch(r"\d{4}", year):
        raise CitationMetadataError("Journal year must be four digits or already bracketed")
    year_format = _clean(data.get("year_format")).lower()
    if year_format == "square":
        return f"[{year}]"
    if year_format == "round":
        return f"({year})"
    raise CitationMetadataError("Journal year_format must be square or round")


def _publication_details(data: Mapping[str, Any], *, include_people: bool = True) -> str:
    publisher, year = _require(data, "publisher", "year")
    prefixes: list[str] = []
    if include_people:
        prefixes.extend((_clean(data.get("translator")), _clean(data.get("editor"))))
    prefixes.extend((_clean(data.get("additional_information")), _clean(data.get("edition"))))
    details = [item for item in prefixes if item]
    details.append(f"{publisher} {year}")
    return f"({', '.join(details)})"


def _online_suffix(data: Mapping[str, Any], *, required: bool) -> str:
    doi = _clean(data.get("doi"))
    url = _clean(data.get("url"))
    if doi and url:
        raise CitationMetadataError("Supply either DOI or URL, not both")
    if doi:
        if _clean(data.get("accessed")):
            raise CitationMetadataError("Persistent DOI citations must not include an access date")
        return f" DOI: {doi.removeprefix('DOI:').strip()}"
    if not url:
        if required:
            raise CitationMetadataError("An online source requires DOI or URL")
        return ""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise CitationMetadataError("OSCOLA website URLs must be absolute HTTPS URLs")
    if parsed.path.casefold().endswith(".pdf"):
        raise CitationMetadataError("Cite the page hosting online content, not a downloaded PDF")
    persistent = data.get("url_is_persistent") is True or parsed.hostname.casefold() == "perma.cc"
    accessed = _clean(data.get("accessed"))
    if persistent and accessed:
        raise CitationMetadataError("Persistent links must not include an access date")
    if not persistent and not accessed:
        raise CitationMetadataError("A non-persistent website URL requires an accessed date")
    suffix = f" <{url}>"
    if accessed:
        suffix += f" accessed {_date_text(accessed, 'accessed')}"
    return suffix


def _title(value: str, style: str) -> str:
    if style == "italic":
        return f"*{value}*"
    if style == "quoted":
        return f"‘{value}’"
    raise CitationMetadataError("title_style must be italic or quoted")


def render_oscola(data: Mapping[str, Any], locator: str | None = None) -> str:
    """Render citation metadata supplied by a verified source record, never generated prose."""
    source_type = _clean(data.get("source_type")).lower()
    raw_pinpoint = _clean(locator or data.get("pinpoint"))

    if source_type == "case":
        case_name = _clean(data.get("case_name") or data.get("title"))
        neutral = _clean(data.get("neutral_citation"))
        report = _clean(data.get("report_citation"))
        decision_date = _clean(data.get("decision_date"))
        if not case_name or not (neutral or report or decision_date):
            raise CitationMetadataError(
                "A case requires its name and a verified neutral, report or unreported-decision citation"
            )
        if neutral and not re.match(r"^\[\d{4}\]\s+", neutral):
            raise CitationMetadataError("A medium neutral citation must start with [year]")
        if report and not re.match(r"^(?:\[\d{4}\]|\(\d{4}\))\s+", report):
            raise CitationMetadataError("A report citation must start with [year] or (year)")
        neutral_court = _clean(data.get("neutral_court_identifier"))
        neutral_part = neutral + (f" ({neutral_court})" if neutral_court else "")
        base = f"*{case_name}* {neutral_part or report}"
        if neutral and report:
            base = f"*{case_name}* {neutral_part}, {report}"
        if not neutral:
            court = _clean(data.get("court_identifier"))
            if report:
                if not court and data.get("court_identifier_not_required") is not True:
                    raise CitationMetadataError(
                        "A reported case without a neutral citation requires court_identifier"
                    )
                if court:
                    base += f" ({court})"
            elif decision_date:
                if not court:
                    raise CitationMetadataError("An unreported case requires court_identifier")
                base = f"*{case_name}* ({court}, {_date_text(decision_date, 'decision_date')})"
        pinpoint = _case_pinpoint(raw_pinpoint, data)
        return f"{base} {pinpoint}".strip()

    if source_type == "legislation":
        (title,) = _require(data, "title")
        provision = _legislation_pinpoint(raw_pinpoint or _clean(data.get("provision")))
        return f"{title}{f', {provision}' if provision else ''}"

    if source_type == "statutory_instrument":
        title, instrument_number = _require(data, "title", "instrument_number")
        if not re.match(r"^(?:SI|SSI|SR(?:\s*&\s*O)?)\s+\d{4}/", instrument_number):
            raise CitationMetadataError("instrument_number must include SI, SSI, SR or SR & O")
        provision = _legislation_pinpoint(raw_pinpoint or _clean(data.get("provision")))
        return f"{title}, {instrument_number}{f', {provision}' if provision else ''}"

    if source_type == "rule":
        (title,) = _require(data, "title")
        provision = _clean(raw_pinpoint or data.get("provision"))
        if not provision:
            raise CitationMetadataError("A court rule citation requires provision")
        return f"{title} {provision}"

    if source_type == "journal":
        author, title, journal = _require(data, "author", "title", "journal")
        year = _year_token(data)
        volume = _clean(data.get("volume"))
        issue = _clean(data.get("issue"))
        first_page = _clean(data.get("first_page"))
        if issue and not volume:
            raise CitationMetadataError("A journal issue requires a volume")
        if not first_page and data.get("online_only") is not True:
            raise CitationMetadataError("A journal article requires first_page or online_only=true")
        vol_issue = volume + (f"({issue})" if issue else "")
        bibliographic = " ".join(part for part in (year, vol_issue, journal, first_page) if part)
        pinpoint = _secondary_pinpoint(raw_pinpoint)
        suffix = f", {pinpoint}" if pinpoint else ""
        return f"{author}, ‘{title}’ {bibliographic}{suffix}"

    if source_type == "book":
        author, title = _require(data, "author", "title")
        publication = _publication_details(data)
        volume = _clean(data.get("volume"))
        volume_text = f" vol {volume}" if volume else ""
        pinpoint = _secondary_pinpoint(raw_pinpoint)
        suffix = f" {pinpoint}" if pinpoint else ""
        return f"{author}, *{title}* {publication}{volume_text}{suffix}"

    if source_type == "book_chapter":
        author, chapter_title, editor, book_title = _require(
            data, "author", "title", "editor", "book_title"
        )
        editor_role = _clean(data.get("editor_role") or "ed")
        if editor_role not in {"ed", "eds"}:
            raise CitationMetadataError("editor_role must be ed or eds")
        publication = _publication_details(data, include_people=False)
        pinpoint = _secondary_pinpoint(raw_pinpoint)
        suffix = f" {pinpoint}" if pinpoint else ""
        return (
            f"{author}, ‘{chapter_title}’ in {editor} ({editor_role}), "
            f"*{book_title}* {publication}{suffix}"
        )

    if source_type == "web":
        (title,) = _require(data, "title")
        body = _clean(data.get("author"))
        website = _clean(data.get("website"))
        publication_date = _clean(data.get("publication_date"))
        context = [item for item in (website and f"*{website}*", publication_date) if item]
        prefix = f"{body}, " if body else ""
        suffix = _online_suffix(data, required=True)
        return f"{prefix}‘{title}’{f' ({", ".join(context)})' if context else ''}{suffix}"

    if source_type == "official_guidance":
        body, title, publication_date = _require(
            data, "author_or_body", "title", "publication_date"
        )
        title_text = _title(title, _clean(data.get("title_style") or "quoted").lower())
        pinpoint = _secondary_pinpoint(raw_pinpoint)
        suffix = f" {pinpoint}" if pinpoint else ""
        return (
            f"{body}, {title_text} ({_date_text(publication_date, 'publication_date')})"
            f"{suffix}{_online_suffix(data, required=False)}"
        )

    if source_type == "report":
        report_type = _clean(data.get("report_type")).lower()
        body, title = _require(data, "author_or_body", "title")
        pinpoint = _secondary_pinpoint(raw_pinpoint)
        suffix = f" {pinpoint}" if pinpoint else ""
        if report_type in {"law_commission", "command_paper"}:
            number, year = _require(data, "report_number", "year")
            additional = _clean(data.get("additional_information"))
            inside = ", ".join(item for item in (additional, number, year) if item)
            return f"{body}, *{title}* ({inside}){suffix}"
        if report_type == "select_committee":
            session, paper_number = _require(data, "session", "paper_number")
            return f"{body}, *{title}* ({session}, {paper_number}){suffix}"
        if report_type == "government_publication":
            publication_date = _date_text(data.get("publication_date"), "publication_date")
            style = _clean(data.get("title_style") or "italic").lower()
            return (
                f"{body}, {_title(title, style)} ({publication_date}){suffix}"
                f"{_online_suffix(data, required=False)}"
            )
        raise CitationMetadataError(
            "report_type must be law_commission, command_paper, select_committee or government_publication"
        )

    if source_type == "parliamentary":
        parliamentary_type = _clean(data.get("parliamentary_type")).lower()
        if parliamentary_type == "hansard":
            house, debate_date, volume = _require(data, "house", "date", "volume")
            if house not in {"HC", "HL"}:
                raise CitationMetadataError("Hansard house must be HC or HL")
            column = _clean(raw_pinpoint or data.get("column") or data.get("columns"))
            if not column:
                raise CitationMetadataError("Hansard requires column or columns")
            label = "cols" if data.get("columns") or re.search(r"[,–-]", column) else "col"
            return (
                f"{house} Deb {_date_text(debate_date, 'date')}, vol {volume}, "
                f"{label} {_normalise_range(column)}"
            )
        if parliamentary_type == "bill_debate":
            title, debate_date = _require(data, "title", "date")
            columns = _clean(raw_pinpoint or data.get("column") or data.get("columns"))
            if not columns:
                raise CitationMetadataError("A Bill debate requires column or columns")
            label = "cols" if data.get("columns") or re.search(r"[,–-]", columns) else "col"
            return (
                f"{title} Deb {_date_text(debate_date, 'date')}, "
                f"{label} {_normalise_range(columns)}"
            )
        raise CitationMetadataError("parliamentary_type must be hansard or bill_debate")

    raise CitationMetadataError(f"Unsupported OSCOLA source type: {source_type or 'missing'}")


def _strip_terminal_punctuation(text: str) -> tuple[str, str]:
    match = re.search(r"([.!?])\s*$", text)
    if not match:
        return text.rstrip(), "."
    return text[: match.start()].rstrip(), match.group(1)


def _citation_token(evidence: Iterable[EvidenceSpan]) -> tuple[str, list[str]]:
    parts: list[str] = []
    ids: list[str] = []
    for span in evidence:
        if not span.citation_data:
            raise CitationMetadataError("Verified evidence is missing structured OSCOLA metadata")
        canonical = render_oscola(span.citation_data)
        if span.canonical_citation and _clean(span.canonical_citation) != canonical:
            raise CitationMetadataError(
                "Stored canonical citation does not match structured OSCOLA metadata"
            )
        citation = render_oscola(span.citation_data, span.locator)
        safe_citation = html.escape(citation, quote=False)
        parts.append(f"[{safe_citation}](#evidence-{span.id})")
        ids.append(span.id)
    return "; ".join(parts), ids


def render_answer(
    draft: StructuredDraft,
    evidence_by_id: Mapping[str, EvidenceSpan],
) -> RenderedAnswer:
    lines = [f"# {draft.title}", ""]
    used: list[str] = []
    for section in draft.sections:
        lines.extend((f"## {section.heading}", ""))
        for claim in section.claims:
            bound = [evidence_by_id[item] for item in claim.evidence_ids if item in evidence_by_id]
            body, punctuation = _strip_terminal_punctuation(claim.text)
            if bound:
                citation_text, citation_ids = _citation_token(bound)
                lines.append(f"{body} ({citation_text}){punctuation}")
                used.extend(citation_ids)
            else:
                lines.append(f"{body}{punctuation}")
            lines.append("")
    if draft.limitations:
        lines.extend(("## Evidence limitations", ""))
        lines.extend(f"- {item}" for item in draft.limitations)
        lines.append("")
    markdown = "\n".join(lines).rstrip() + "\n"
    words = len(re.findall(r"\b[\w’'-]+\b", re.sub(r"\[[^]]+\]\([^)]*\)", "", markdown)))
    return RenderedAnswer(
        markdown=markdown, word_count=words, evidence_ids=list(dict.fromkeys(used))
    )
