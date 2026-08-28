"""Parser contracts and conservative built-in document adapters.

The adapters intentionally quarantine encrypted, image-only, malformed, and
dependency-blocked material.  A parser failure is never converted into an
empty successful document.
"""

from __future__ import annotations

import io
import re
import zipfile
from abc import ABC, abstractmethod
from collections.abc import Iterable
from html.parser import HTMLParser
from pathlib import Path
from typing import ClassVar
from xml.etree import ElementTree as ET

from .models import (
    Annotation,
    BlockKind,
    DocumentFormat,
    ParseResult,
    ParseStatus,
    Revision,
    StructuralBlock,
)
from .privacy import PIIAliaser
from .sanitation import sanitize_parse_result, sanitize_text

MAX_ARCHIVE_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
PDF_BOILERPLATE_SCHEMA = "legalbot.pdf-boilerplate.v1"
PDF_REVIEW_ANNOTATION_SCHEMA = "legalbot.pdf-review-annotations.v2"
_PDF_REVIEW_ANNOTATION_SUBTYPES = frozenset(
    {"/Text", "/FreeText", "/Highlight", "/Underline", "/Squiggly", "/StrikeOut"}
)


def _clean(value: str) -> str:
    return re.sub(r"[\t\r\f\v ]+", " ", sanitize_text(value)).strip()


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _attr(element: ET.Element, name: str) -> str | None:
    for key, value in element.attrib.items():
        if _local_name(key) == name:
            return value
    return None


def _all_text(element: ET.Element, *, excluded: set[str] | None = None) -> str:
    excluded = excluded or set()
    pieces: list[str] = []

    def visit(node: ET.Element) -> None:
        if _local_name(node.tag) in excluded:
            return
        if node.text:
            pieces.append(node.text)
        for child in node:
            visit(child)
            if child.tail:
                pieces.append(child.tail)

    visit(element)
    return _clean("".join(pieces))


def detect_format(filename: str) -> DocumentFormat:
    suffix = Path(filename).suffix.lower()
    return {
        ".pdf": DocumentFormat.PDF,
        ".docx": DocumentFormat.DOCX,
        ".doc": DocumentFormat.DOC,
        ".pptx": DocumentFormat.PPTX,
        ".ppt": DocumentFormat.PPT,
        ".html": DocumentFormat.HTML,
        ".htm": DocumentFormat.HTML,
        ".xml": DocumentFormat.XML,
        ".md": DocumentFormat.MARKDOWN,
        ".markdown": DocumentFormat.MARKDOWN,
        ".txt": DocumentFormat.TEXT,
        ".odt": DocumentFormat.ODT,
    }.get(suffix, DocumentFormat.UNKNOWN)


def _decode_text(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


class DocumentParser(ABC):
    document_format: DocumentFormat

    @abstractmethod
    def parse(
        self, data: bytes, *, filename: str, aliaser: PIIAliaser | None = None
    ) -> ParseResult:
        raise NotImplementedError


class ParserRegistry:
    schema = "legalbot.parser-registry.v1"

    def __init__(self, parsers: Iterable[DocumentParser] = ()) -> None:
        self._parsers = {parser.document_format: parser for parser in parsers}

    @classmethod
    def default(cls) -> ParserRegistry:
        return cls(
            (
                PdfParser(),
                DocxParser(),
                LegacyOfficeParser(DocumentFormat.DOC),
                PptxParser(),
                LegacyOfficeParser(DocumentFormat.PPT),
                HtmlDocumentParser(),
                LegislationXmlParser(),
                MarkdownParser(),
                TextParser(),
                OdtParser(),
            )
        )

    def register(self, parser: DocumentParser) -> None:
        self._parsers[parser.document_format] = parser

    def parse(
        self, data: bytes, *, filename: str, aliaser: PIIAliaser | None = None
    ) -> ParseResult:
        document_format = detect_format(filename)
        parser = self._parsers.get(document_format)
        if parser is None:
            return ParseResult(
                ParseStatus.UNSUPPORTED,
                document_format,
                diagnostics=(f"unsupported extension for {filename!r}",),
            )
        try:
            return sanitize_parse_result(parser.parse(data, filename=filename, aliaser=aliaser))
        # Inputs are untrusted.  Third-party parsers expose their own exception
        # hierarchies (for example ``pypdf.errors.PdfReadError``), so failures
        # must cross the contract as quarantined-invalid rather than escaping.
        except Exception as exc:
            return ParseResult(
                ParseStatus.INVALID,
                document_format,
                diagnostics=(f"{type(exc).__name__}: {exc}",),
            )


class TextParser(DocumentParser):
    document_format = DocumentFormat.TEXT

    def parse(
        self, data: bytes, *, filename: str, aliaser: PIIAliaser | None = None
    ) -> ParseResult:
        text = data.decode("utf-8-sig")
        blocks = _plain_text_blocks(text)
        status = ParseStatus.READY if blocks else ParseStatus.INVALID
        return ParseResult(
            status,
            self.document_format,
            tuple(blocks),
            diagnostics=(() if blocks else ("no text",)),
        )


class MarkdownParser(DocumentParser):
    document_format = DocumentFormat.MARKDOWN

    def parse(
        self, data: bytes, *, filename: str, aliaser: PIIAliaser | None = None
    ) -> ParseResult:
        text = data.decode("utf-8-sig")
        comments: list[Annotation] = []

        def remove_comment(match: re.Match[str]) -> str:
            value = _clean(match.group(1))
            if value:
                comments.append(Annotation(f"md-comment-{len(comments) + 1}", value))
            return "\n"

        body = re.sub(r"<!--(.*?)-->", remove_comment, text, flags=re.S)
        blocks: list[StructuralBlock] = []
        heading_path: list[str] = []
        paragraph: list[str] = []

        def flush() -> None:
            value = _clean(" ".join(paragraph))
            paragraph.clear()
            if value:
                blocks.append(
                    StructuralBlock(len(blocks), BlockKind.PARAGRAPH, value, tuple(heading_path))
                )

        for line in body.splitlines():
            heading = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
            if heading:
                flush()
                level = len(heading.group(1))
                value = _clean(heading.group(2))
                heading_path[:] = heading_path[: level - 1]
                heading_path.append(value)
                blocks.append(
                    StructuralBlock(
                        len(blocks),
                        BlockKind.TITLE if level == 1 and not blocks else BlockKind.HEADING,
                        value,
                        tuple(heading_path),
                        metadata={"level": level},
                    )
                )
            elif not line.strip():
                flush()
            else:
                paragraph.append(line)
        flush()
        return ParseResult(
            ParseStatus.READY if blocks else ParseStatus.INVALID,
            self.document_format,
            tuple(blocks),
            tuple(comments),
            diagnostics=(() if blocks else ("no text",)),
        )


class _SemanticHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.blocks: list[tuple[BlockKind, str, int | None]] = []
        self.comments: list[str] = []
        self._capture_tag: str | None = None
        self._pieces: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "noscript"}:
            self._ignored_depth += 1
            return
        if self._ignored_depth:
            return
        if (
            tag in {"p", "li", "pre", "blockquote", "td", "th"} or re.fullmatch(r"h[1-6]", tag)
        ) and self._capture_tag is None:
            self._capture_tag = tag
            self._pieces = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "noscript"}:
            self._ignored_depth = max(0, self._ignored_depth - 1)
            return
        if self._ignored_depth or tag != self._capture_tag:
            return
        value = _clean(" ".join(self._pieces))
        if value:
            if re.fullmatch(r"h[1-6]", tag):
                kind, level = BlockKind.HEADING, int(tag[1])
            elif tag == "li":
                kind, level = BlockKind.LIST_ITEM, None
            elif tag in {"td", "th"}:
                kind, level = BlockKind.TABLE, None
            elif tag == "pre":
                kind, level = BlockKind.CODE, None
            else:
                kind, level = BlockKind.PARAGRAPH, None
            self.blocks.append((kind, value, level))
        self._capture_tag = None
        self._pieces = []

    def handle_data(self, data: str) -> None:
        if self._capture_tag and not self._ignored_depth:
            self._pieces.append(data)

    def handle_comment(self, data: str) -> None:
        value = _clean(data)
        if value:
            self.comments.append(value)


class HtmlDocumentParser(DocumentParser):
    document_format = DocumentFormat.HTML

    def parse(
        self, data: bytes, *, filename: str, aliaser: PIIAliaser | None = None
    ) -> ParseResult:
        parser = _SemanticHTMLParser()
        parser.feed(_decode_text(data))
        heading_path: list[str] = []
        blocks: list[StructuralBlock] = []
        for kind, text, level in parser.blocks:
            if level:
                heading_path[:] = heading_path[: level - 1]
                heading_path.append(text)
                if level == 1 and not blocks:
                    kind = BlockKind.TITLE
            blocks.append(
                StructuralBlock(
                    len(blocks),
                    kind,
                    text,
                    tuple(heading_path),
                    metadata=({"level": level} if level else {}),
                )
            )
        comments = tuple(
            Annotation(f"html-comment-{index + 1}", text)
            for index, text in enumerate(parser.comments)
        )
        return ParseResult(
            ParseStatus.READY if blocks else ParseStatus.INVALID,
            self.document_format,
            tuple(blocks),
            comments,
            diagnostics=(() if blocks else ("no semantic text blocks",)),
        )


class LegislationXmlParser(DocumentParser):
    """Extract locator-addressable text from official UK legal XML.

    The accepted roots are Legislation.gov.uk CLML and Find Case Law Akoma
    Ntoso judgments. Raw XML remains immutable. Editorial metadata,
    commentary, headers and footnotes are excluded from the authority stream;
    currentness and later-treatment qualifications are reviewed separately.
    """

    document_format = DocumentFormat.XML
    _PROVISION = re.compile(r"P[1-7]")
    _CONTAINER_LEVELS: ClassVar[dict[str, int]] = {
        "Part": 2,
        "Chapter": 3,
        "Schedule": 2,
        "Pblock": 4,
    }
    _SKIP: ClassVar[set[str]] = {
        "Metadata",
        "Commentaries",
        "Commentary",
        "Footnotes",
        "Footnote",
        "MarginNotes",
        "Resources",
    }
    _CASELAW_DOCUMENT_URI = re.compile(
        r"https://caselaw\.nationalarchives\.gov\.uk/(?:"
        r"(?:uksc|ukpc)/\d{4}/\d+|"
        r"ewca/(?:civ|crim)/\d{4}/\d+|"
        r"ewhc/[a-z0-9-]+/\d{4}/\d+"
        r")"
    )
    _NEUTRAL_CITATION = re.compile(
        r"\[\d{4}\]\s+(?:UKSC|UKPC|UKHL|EWCA\s+(?:Civ|Crim)|EWHC)\s+"
        r"\d+(?:\s+\([A-Za-z]+\))?",
        re.IGNORECASE,
    )

    def parse(
        self, data: bytes, *, filename: str, aliaser: PIIAliaser | None = None
    ) -> ParseResult:
        opening = data[:100_000].upper()
        if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
            return ParseResult(
                ParseStatus.INVALID,
                self.document_format,
                diagnostics=("DTD and entity declarations are not permitted",),
            )
        root = ET.fromstring(data)
        if _local_name(root.tag) == "akomaNtoso":
            return self._parse_akn_judgment(root)
        if _local_name(root.tag) != "Legislation":
            return ParseResult(
                ParseStatus.INVALID,
                self.document_format,
                diagnostics=("XML is not supported official UK legal XML",),
            )
        document_uri = str(root.attrib.get("DocumentURI") or "")
        if not re.fullmatch(r"https?://www\.legislation\.gov\.uk/.+", document_uri):
            return ParseResult(
                ParseStatus.INVALID,
                self.document_format,
                diagnostics=("official legislation DocumentURI is missing or invalid",),
            )

        title = self._metadata_value(root, "title")
        if not title:
            return ParseResult(
                ParseStatus.INVALID,
                self.document_format,
                diagnostics=("official legislation title is missing",),
            )
        secure_document_uri = document_uri.replace("http://", "https://")
        blocks: list[StructuralBlock] = [
            StructuralBlock(
                0,
                BlockKind.TITLE,
                title,
                (title,),
                source_anchor=secure_document_uri,
                metadata={
                    "level": 1,
                    "official_document_uri": secure_document_uri,
                    "source_modified": self._metadata_value(root, "modified"),
                    "source_valid_from": self._metadata_value(root, "valid"),
                },
            )
        ]

        def walk(element: ET.Element, heading_path: tuple[str, ...]) -> None:
            local = _local_name(element.tag)
            if local in self._SKIP:
                return
            next_heading = heading_path
            level = self._CONTAINER_LEVELS.get(local)
            if level is not None:
                heading = self._container_heading(element)
                if heading:
                    next_heading = (*heading_path[: max(0, level - 2)], heading)
                    blocks.append(
                        StructuralBlock(
                            len(blocks),
                            BlockKind.HEADING,
                            heading,
                            next_heading,
                            source_anchor=self._official_anchor(element),
                            metadata={"level": level},
                        )
                    )
            if self._PROVISION.fullmatch(local) and self._official_anchor(element):
                locator = self._provision_locator(element)
                own_text = self._provision_text(element)
                if own_text:
                    display = f"{locator} {own_text}" if locator else own_text
                    metadata: dict[str, object] = {}
                    if locator:
                        metadata = {
                            "legal_locator_kind": "legislative_provision",
                            "legal_locator": locator,
                        }
                    blocks.append(
                        StructuralBlock(
                            len(blocks),
                            BlockKind.PARAGRAPH,
                            display,
                            next_heading,
                            source_anchor=self._official_anchor(element),
                            metadata=metadata,
                        )
                    )
            for child in element:
                walk(child, next_heading)

        for child in root:
            walk(child, (title,))
        return ParseResult(
            ParseStatus.READY if len(blocks) > 1 else ParseStatus.INVALID,
            self.document_format,
            tuple(blocks),
            diagnostics=(() if len(blocks) > 1 else ("no legislative provisions",)),
        )

    def _parse_akn_judgment(self, root: ET.Element) -> ParseResult:
        judgment = self._first_descendant(root, "judgment")
        work = self._first_descendant(judgment, "FRBRWork") if judgment is not None else None
        expression = (
            self._first_descendant(judgment, "FRBRExpression")
            if judgment is not None
            else None
        )
        body = self._first_descendant(judgment, "judgmentBody") if judgment is not None else None
        if judgment is None or work is None or expression is None or body is None:
            return ParseResult(
                ParseStatus.INVALID,
                self.document_format,
                diagnostics=("official judgment structure is incomplete",),
            )

        title_element = self._first_descendant(work, "FRBRname")
        uri_element = self._first_descendant(expression, "FRBRthis")
        title = (
            _clean(str(_attr(title_element, "value") or ""))
            if title_element is not None
            else ""
        )
        document_uri = (
            str(_attr(uri_element, "value") or "")
            if uri_element is not None
            else ""
        )
        if not title:
            return ParseResult(
                ParseStatus.INVALID,
                self.document_format,
                diagnostics=("official judgment title is missing",),
            )
        if not self._CASELAW_DOCUMENT_URI.fullmatch(document_uri):
            return ParseResult(
                ParseStatus.INVALID,
                self.document_format,
                diagnostics=("official judgment document URI is missing or invalid",),
            )

        citation = self._akn_citation(judgment)
        if not citation or not self._NEUTRAL_CITATION.fullmatch(citation):
            return ParseResult(
                ParseStatus.INVALID,
                self.document_format,
                diagnostics=("official judgment neutral citation is missing or invalid",),
            )
        judgment_date = self._akn_judgment_date(work)
        blocks: list[StructuralBlock] = [
            StructuralBlock(
                0,
                BlockKind.TITLE,
                title,
                (title,),
                source_anchor=document_uri,
                metadata={
                    "level": 1,
                    "official_document_uri": document_uri,
                    "neutral_citation": citation,
                    "judgment_date": judgment_date,
                    "legal_locator_kind": "judgment",
                    "legal_locator": citation,
                },
            )
        ]

        def walk(element: ET.Element, heading_path: tuple[str, ...]) -> None:
            local = _local_name(element.tag)
            next_heading = heading_path
            if local == "level":
                heading = self._direct_child_text(element, {"heading"})
                if heading:
                    next_heading = (*heading_path, heading)
                    blocks.append(
                        StructuralBlock(
                            len(blocks),
                            BlockKind.HEADING,
                            heading,
                            next_heading,
                            source_anchor=self._akn_anchor(document_uri, element),
                            metadata={"level": min(len(next_heading), 6)},
                        )
                    )
            if local == "paragraph":
                number = self._direct_child_text(element, {"num"})
                text = self._akn_paragraph_text(element)
                if text:
                    locator = self._judgment_paragraph_locator(number, element)
                    display = f"{locator} {text}" if locator else text
                    metadata: dict[str, object] = {
                        "neutral_citation": citation,
                        "judgment_date": judgment_date,
                    }
                    if locator:
                        metadata.update(
                            {
                                "legal_locator_kind": "judgment_paragraph",
                                "legal_locator": locator,
                            }
                        )
                    blocks.append(
                        StructuralBlock(
                            len(blocks),
                            BlockKind.PARAGRAPH,
                            display,
                            next_heading,
                            source_anchor=self._akn_anchor(document_uri, element),
                            metadata=metadata,
                        )
                    )
                return
            for child in element:
                walk(child, next_heading)

        walk(body, (title,))
        return ParseResult(
            ParseStatus.READY if len(blocks) > 1 else ParseStatus.INVALID,
            self.document_format,
            tuple(blocks),
            diagnostics=(() if len(blocks) > 1 else ("no judgment paragraphs",)),
        )

    @staticmethod
    def _first_descendant(
        root: ET.Element | None, local_name: str
    ) -> ET.Element | None:
        if root is None:
            return None
        for element in root.iter():
            if _local_name(element.tag) == local_name:
                return element
        return None

    @classmethod
    def _akn_citation(cls, judgment: ET.Element) -> str:
        proprietary = cls._first_descendant(judgment, "proprietary")
        if proprietary is not None:
            cite = cls._first_descendant(proprietary, "cite")
            value = _all_text(cite) if cite is not None else ""
            if value:
                return value
        header = cls._first_descendant(judgment, "header")
        citation = cls._first_descendant(header, "neutralCitation")
        return _all_text(citation) if citation is not None else ""

    @staticmethod
    def _akn_judgment_date(work: ET.Element) -> str:
        for element in work.iter():
            if _local_name(element.tag) != "FRBRdate":
                continue
            if _attr(element, "name") == "judgment":
                return _clean(str(_attr(element, "date") or ""))
        return ""

    @staticmethod
    def _akn_anchor(document_uri: str, element: ET.Element) -> str:
        element_id = str(_attr(element, "eId") or "")
        if re.fullmatch(r"[A-Za-z0-9_.:-]+", element_id):
            return f"{document_uri}#{element_id}"
        return document_uri

    @staticmethod
    def _judgment_paragraph_locator(number: str, element: ET.Element) -> str:
        cleaned = _clean(number).strip(".[]() ")
        if cleaned:
            return f"paragraph {cleaned}"
        element_id = str(_attr(element, "eId") or "")
        match = re.fullmatch(r"para[_-](\d+[A-Za-z]?)", element_id)
        return f"paragraph {match.group(1)}" if match else ""

    @staticmethod
    def _akn_paragraph_text(element: ET.Element) -> str:
        pieces: list[str] = []

        def visit(node: ET.Element, *, is_root: bool = False) -> None:
            local = _local_name(node.tag)
            if local in {"authorialNote", "note", "num"}:
                return
            if not is_root and local == "paragraph":
                return
            if node.text:
                pieces.append(node.text)
            for child in node:
                visit(child)
                if child.tail:
                    pieces.append(child.tail)

        visit(element, is_root=True)
        return _clean("".join(pieces))

    @staticmethod
    def _metadata_value(root: ET.Element, local_name: str) -> str:
        for element in root.iter():
            if _local_name(element.tag) == local_name:
                value = _all_text(element)
                if value:
                    return value
        return ""

    @staticmethod
    def _official_anchor(element: ET.Element) -> str:
        value = str(element.attrib.get("DocumentURI") or "")
        return value.replace("http://", "https://") if value else ""

    @staticmethod
    def _direct_child_text(element: ET.Element, local_names: set[str]) -> str:
        pieces: list[str] = []
        for child in element:
            if _local_name(child.tag) in local_names:
                value = _all_text(child)
                if value:
                    pieces.append(value)
        return _clean(" ".join(pieces))

    def _container_heading(self, element: ET.Element) -> str:
        number = self._direct_child_text(element, {"Number"})
        title = self._direct_child_text(element, {"Title", "TitleBlock"})
        return _clean(" ".join(value for value in (number, title) if value))

    def _provision_locator(self, element: ET.Element) -> str:
        relative = self._official_anchor(element).split("www.legislation.gov.uk/", 1)[-1]
        pairs = re.findall(
            r"/(section|regulation|article|rule|schedule|paragraph)/([^/]+)", relative
        )
        if not pairs:
            number = self._direct_child_text(element, {"Pnumber"})
            return f"provision {number}" if number else ""
        output: list[str] = []
        for label, number in pairs:
            if label == "paragraph" and output and output[-1].startswith("paragraph "):
                output[-1] += f"({number})"
            else:
                output.append(f"{label} {number}")
        return " ".join(output)

    def _provision_text(self, element: ET.Element) -> str:
        pieces: list[str] = []

        def visit(node: ET.Element, *, is_root: bool = False) -> None:
            local = _local_name(node.tag)
            if local in self._SKIP or local == "Pnumber":
                return
            if not is_root and self._PROVISION.fullmatch(local) and self._official_anchor(node):
                return
            if node.text:
                pieces.append(node.text)
            for child in node:
                visit(child)
                if child.tail:
                    pieces.append(child.tail)

        visit(element, is_root=True)
        return _clean("".join(pieces))


class PdfParser(DocumentParser):
    document_format = DocumentFormat.PDF

    def parse(
        self, data: bytes, *, filename: str, aliaser: PIIAliaser | None = None
    ) -> ParseResult:
        if not data.startswith(b"%PDF-"):
            return ParseResult(
                ParseStatus.INVALID, self.document_format, diagnostics=("missing PDF header",)
            )
        if b"/Encrypt" in data[-65536:]:
            return ParseResult(
                ParseStatus.ENCRYPTED, self.document_format, diagnostics=("encrypted PDF",)
            )
        try:
            from pypdf import PdfReader
        except ImportError:
            return ParseResult(
                ParseStatus.PARSER_UNAVAILABLE,
                self.document_format,
                diagnostics=("pypdf is required; source remains quarantined",),
            )
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            return ParseResult(
                ParseStatus.ENCRYPTED, self.document_format, diagnostics=("encrypted PDF",)
            )
        blocks: list[StructuralBlock] = []
        comments: list[Annotation] = []
        blank_pages: list[int] = []
        jstor_notice_pages: list[int] = []
        for page_number, page in enumerate(reader.pages, 1):
            extracted, notice_removed = _strip_jstor_access_notice(page.extract_text() or "")
            if notice_removed:
                jstor_notice_pages.append(page_number)
            text = _clean(extracted)
            if text:
                blocks.append(
                    StructuralBlock(
                        len(blocks),
                        BlockKind.PAGE,
                        text,
                        page=page_number,
                        source_anchor=f"page={page_number}",
                    )
                )
            else:
                blank_pages.append(page_number)
            annotations = page.get("/Annots") or []
            for raw in annotations:
                try:
                    resolved = raw.get_object()
                    # Link, widget and navigation annotations frequently expose
                    # headings or URLs through /Contents.  They are document
                    # structure, not marker feedback, and must never become
                    # assessment rules.
                    if str(resolved.get("/Subtype") or "") not in _PDF_REVIEW_ANNOTATION_SUBTYPES:
                        continue
                    contents = _clean(str(resolved.get("/Contents") or ""))
                    author = str(resolved.get("/T") or "")
                except Exception:  # malformed annotations must not fail body extraction
                    continue
                if contents:
                    comments.append(
                        Annotation(
                            f"pdf-comment-{len(comments) + 1}",
                            contents,
                            author_alias=(aliaser.alias(author) if author and aliaser else None),
                            page=page_number,
                        )
                    )
        if not blocks:
            return ParseResult(
                ParseStatus.OCR_REQUIRED,
                self.document_format,
                comments=tuple(comments),
                diagnostics=("no extractable text; OCR required",),
            )
        diagnostics: tuple[str, ...] = ()
        if blank_pages:
            diagnostics += (f"pages without extractable text: {blank_pages}",)
        if jstor_notice_pages:
            pages = ",".join(str(page) for page in jstor_notice_pages)
            diagnostics += (f"jstor_access_notice_removed_pages={pages}",)
        return ParseResult(
            ParseStatus.READY,
            self.document_format,
            tuple(blocks),
            tuple(comments),
            diagnostics=diagnostics,
        )


_JSTOR_NOTICE_RE = re.compile(
    r"This content downloaded from.{0,640}?"
    r"All use subject to https?://about\.jstor\.org/terms/?",
    re.IGNORECASE | re.DOTALL,
)
_JSTOR_EDGE_WINDOW = 1_024


def _strip_jstor_access_notice(value: str) -> tuple[str, bool]:
    """Remove one exact, bounded JSTOR access notice only at a page edge."""

    match = _JSTOR_NOTICE_RE.search(value)
    if match is None:
        return value, False
    if match.start() > _JSTOR_EDGE_WINDOW and len(value) - match.end() > _JSTOR_EDGE_WINDOW:
        return value, False
    before = value[: match.start()].rstrip()
    after = value[match.end() :].lstrip()
    separator = "\n" if before and after else ""
    return f"{before}{separator}{after}", True


class LegacyOfficeParser(DocumentParser):
    def __init__(self, document_format: DocumentFormat) -> None:
        if document_format not in {DocumentFormat.DOC, DocumentFormat.PPT}:
            raise ValueError("legacy parser supports DOC or PPT only")
        self.document_format = document_format

    def parse(
        self, data: bytes, *, filename: str, aliaser: PIIAliaser | None = None
    ) -> ParseResult:
        return ParseResult(
            ParseStatus.PARSER_UNAVAILABLE,
            self.document_format,
            diagnostics=(
                "legacy binary Office conversion requires a sandboxed LibreOffice adapter; source remains quarantined",
            ),
        )


def _checked_zip(data: bytes) -> zipfile.ZipFile:
    archive = zipfile.ZipFile(io.BytesIO(data))
    total = sum(info.file_size for info in archive.infolist())
    if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
        archive.close()
        raise ValueError("archive exceeds uncompressed size limit")
    if any(
        ".." in Path(info.filename).parts or info.filename.startswith("/")
        for info in archive.infolist()
    ):
        archive.close()
        raise ValueError("unsafe archive member path")
    return archive


class DocxParser(DocumentParser):
    document_format = DocumentFormat.DOCX

    def parse(
        self, data: bytes, *, filename: str, aliaser: PIIAliaser | None = None
    ) -> ParseResult:
        if data.startswith(bytes.fromhex("D0CF11E0")):
            return ParseResult(
                ParseStatus.ENCRYPTED,
                self.document_format,
                diagnostics=("encrypted OOXML package",),
            )
        with _checked_zip(data) as archive:
            if "word/document.xml" not in archive.namelist():
                return ParseResult(
                    ParseStatus.INVALID,
                    self.document_format,
                    diagnostics=("missing word/document.xml",),
                )
            root = ET.fromstring(archive.read("word/document.xml"))
            blocks, revisions = self._document(root, aliaser)
            comments = self._comments(archive, aliaser)
        return ParseResult(
            ParseStatus.READY if blocks else ParseStatus.INVALID,
            self.document_format,
            tuple(blocks),
            tuple(comments),
            tuple(revisions),
            (() if blocks else ("no document text",)),
        )

    @staticmethod
    def _document(
        root: ET.Element, aliaser: PIIAliaser | None
    ) -> tuple[list[StructuralBlock], list[Revision]]:
        blocks: list[StructuralBlock] = []
        revisions: list[Revision] = []
        heading_path: list[str] = []
        parents = {child: parent for parent in root.iter() for child in parent}

        def has_ancestor(element: ET.Element, names: set[str]) -> bool:
            parent = parents.get(element)
            while parent is not None:
                if _local_name(parent.tag) in names:
                    return True
                parent = parents.get(parent)
            return False

        for paragraph in (element for element in root.iter() if _local_name(element.tag) == "p"):
            if has_ancestor(paragraph, {"del", "moveFrom"}):
                continue
            # Current-view body: inserted text is included; deleted text is not.
            text = _all_text(paragraph, excluded={"del", "delText", "moveFrom"})
            if not text:
                continue
            style = None
            for element in paragraph.iter():
                if _local_name(element.tag) == "pStyle":
                    style = _attr(element, "val")
                    break
            heading = re.match(r"heading\s*([1-6])", style or "", flags=re.I)
            if heading:
                level = int(heading.group(1))
                heading_path[:] = heading_path[: level - 1]
                heading_path.append(text)
                kind = BlockKind.TITLE if level == 1 and not blocks else BlockKind.HEADING
                metadata = {"level": level, "style": style}
            else:
                kind, metadata = BlockKind.PARAGRAPH, ({"style": style} if style else {})
            blocks.append(
                StructuralBlock(len(blocks), kind, text, tuple(heading_path), metadata=metadata)
            )

        for element in root.iter():
            operation = _local_name(element.tag)
            if operation not in {"ins", "del", "moveFrom", "moveTo"}:
                continue
            text = _all_text(element)
            if not text:
                continue
            author = _attr(element, "author")
            revisions.append(
                Revision(
                    _attr(element, "id") or f"docx-revision-{len(revisions) + 1}",
                    operation,
                    text,
                    author_alias=(aliaser.alias(author) if author and aliaser else None),
                    created_at=_attr(element, "date"),
                )
            )
        return blocks, revisions

    @staticmethod
    def _comments(archive: zipfile.ZipFile, aliaser: PIIAliaser | None) -> list[Annotation]:
        if "word/comments.xml" not in archive.namelist():
            return []
        root = ET.fromstring(archive.read("word/comments.xml"))
        comments: list[Annotation] = []
        for element in root.iter():
            if _local_name(element.tag) != "comment":
                continue
            text = _all_text(element)
            if not text:
                continue
            author = _attr(element, "author")
            comments.append(
                Annotation(
                    _attr(element, "id") or f"docx-comment-{len(comments) + 1}",
                    text,
                    author_alias=(aliaser.alias(author) if author and aliaser else None),
                    created_at=_attr(element, "date"),
                )
            )
        return comments


class PptxParser(DocumentParser):
    document_format = DocumentFormat.PPTX

    def parse(
        self, data: bytes, *, filename: str, aliaser: PIIAliaser | None = None
    ) -> ParseResult:
        if data.startswith(bytes.fromhex("D0CF11E0")):
            return ParseResult(
                ParseStatus.ENCRYPTED,
                self.document_format,
                diagnostics=("encrypted OOXML package",),
            )
        blocks: list[StructuralBlock] = []
        comments: list[Annotation] = []
        with _checked_zip(data) as archive:
            slide_names = sorted(
                (
                    name
                    for name in archive.namelist()
                    if re.fullmatch(r"ppt/slides/slide\d+\.xml", name)
                ),
                key=lambda name: int(re.search(r"(\d+)", name.rsplit("/", 1)[-1]).group(1)),  # type: ignore[union-attr]
            )
            for slide_number, name in enumerate(slide_names, 1):
                root = ET.fromstring(archive.read(name))
                text = _clean(
                    " ".join(
                        element.text or ""
                        for element in root.iter()
                        if _local_name(element.tag) == "t"
                    )
                )
                if text:
                    blocks.append(
                        StructuralBlock(
                            len(blocks),
                            BlockKind.PAGE,
                            text,
                            page=slide_number,
                            source_anchor=f"slide={slide_number}",
                        )
                    )
            comment_names = sorted(
                name
                for name in archive.namelist()
                if name.startswith("ppt/comments/") and name.endswith(".xml")
            )
            for name in comment_names:
                root = ET.fromstring(archive.read(name))
                for element in root.iter():
                    if _local_name(element.tag) not in {"cm", "comment"}:
                        continue
                    text = _all_text(element) or _clean(_attr(element, "text") or "")
                    if text:
                        comments.append(
                            Annotation(
                                _attr(element, "idx") or f"pptx-comment-{len(comments) + 1}",
                                text,
                                author_alias=None,
                                created_at=_attr(element, "dt"),
                            )
                        )
        return ParseResult(
            ParseStatus.READY if blocks else ParseStatus.INVALID,
            self.document_format,
            tuple(blocks),
            tuple(comments),
            diagnostics=(() if blocks else ("no slide text",)),
        )


class OdtParser(DocumentParser):
    document_format = DocumentFormat.ODT

    def parse(
        self, data: bytes, *, filename: str, aliaser: PIIAliaser | None = None
    ) -> ParseResult:
        with _checked_zip(data) as archive:
            if "META-INF/manifest.xml" in archive.namelist():
                manifest = ET.fromstring(archive.read("META-INF/manifest.xml"))
                if any(
                    _local_name(element.tag) == "encryption-data" for element in manifest.iter()
                ):
                    return ParseResult(
                        ParseStatus.ENCRYPTED,
                        self.document_format,
                        diagnostics=("encrypted ODT package",),
                    )
            if "content.xml" not in archive.namelist():
                return ParseResult(
                    ParseStatus.INVALID, self.document_format, diagnostics=("missing content.xml",)
                )
            root = ET.fromstring(archive.read("content.xml"))
        comments: list[Annotation] = []
        revisions: list[Revision] = []
        parents = {child: parent for parent in root.iter() for child in parent}

        def has_ancestor(element: ET.Element, names: set[str]) -> bool:
            parent = parents.get(element)
            while parent is not None:
                if _local_name(parent.tag) in names:
                    return True
                parent = parents.get(parent)
            return False

        for element in root.iter():
            local = _local_name(element.tag)
            if local == "annotation":
                text = _all_text(element)
                if text:
                    creator = next(
                        (
                            _all_text(child)
                            for child in element.iter()
                            if _local_name(child.tag) == "creator"
                        ),
                        "",
                    )
                    comments.append(
                        Annotation(
                            f"odt-comment-{len(comments) + 1}",
                            text,
                            author_alias=(aliaser.alias(creator) if creator and aliaser else None),
                        )
                    )
            elif local == "changed-region":
                operation_element = next(iter(element), None)
                if operation_element is not None:
                    text = _all_text(operation_element)
                    if text:
                        revisions.append(
                            Revision(
                                _attr(element, "id") or f"odt-revision-{len(revisions) + 1}",
                                _local_name(operation_element.tag),
                                text,
                            )
                        )
        blocks: list[StructuralBlock] = []
        heading_path: list[str] = []
        for element in root.iter():
            local = _local_name(element.tag)
            # ODT list items normally contain paragraphs.  Index the paragraph
            # once and derive list semantics from its ancestors.
            if local not in {"h", "p"}:
                continue
            if has_ancestor(element, {"annotation", "tracked-changes", "changed-region"}):
                continue
            text = _all_text(element, excluded={"annotation", "tracked-changes", "changed-region"})
            if not text:
                continue
            if local == "h":
                try:
                    level = int(_attr(element, "outline-level") or "1")
                except ValueError:
                    level = 1
                level = max(1, min(6, level))
                heading_path[:] = heading_path[: level - 1]
                heading_path.append(text)
                kind = BlockKind.TITLE if level == 1 and not blocks else BlockKind.HEADING
                metadata = {"level": level}
            elif has_ancestor(element, {"list-item"}):
                kind, metadata = BlockKind.LIST_ITEM, {}
            else:
                kind, metadata = BlockKind.PARAGRAPH, {}
            blocks.append(
                StructuralBlock(len(blocks), kind, text, tuple(heading_path), metadata=metadata)
            )
        return ParseResult(
            ParseStatus.READY if blocks else ParseStatus.INVALID,
            self.document_format,
            tuple(blocks),
            tuple(comments),
            tuple(revisions),
            (() if blocks else ("no document text",)),
        )


def _plain_text_blocks(text: str) -> list[StructuralBlock]:
    blocks: list[StructuralBlock] = []
    for match in re.finditer(r"\S(?:.*?\S)?(?=\n\s*\n|\Z)", text, flags=re.S):
        value = _clean(match.group(0).replace("\n", " "))
        if value:
            blocks.append(
                StructuralBlock(
                    len(blocks),
                    BlockKind.PARAGRAPH,
                    value,
                    char_start=match.start(),
                    char_end=match.end(),
                )
            )
    if not blocks and _clean(text):
        value = _clean(text)
        blocks.append(
            StructuralBlock(0, BlockKind.PARAGRAPH, value, char_start=0, char_end=len(text))
        )
    return blocks
