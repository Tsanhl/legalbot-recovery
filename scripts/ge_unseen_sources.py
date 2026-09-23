"""Official-source transport helpers for the UK + USA evaluation only.

Host eligibility and successful extraction are CAPTURED_NOT_LEGAL_VERIFIED:
neither establishes jurisdiction, currentness, authority, or legal correctness.
EUR-Lex/Curia are retained only for relevant UK/US cross-border issues; callers
must enforce that relevance, since a URL alone cannot establish domestic scope.

No fetching, DNS resolution, filesystem access, subprocesses, or runtime imports
occur here. A fetcher must check every redirect *before following it*, enforce
network/address and timeout limits, and preserve raw capture bytes separately.
PDF size/page/text limits are not a process memory/CPU sandbox; an untrusted PDF
parser should run inside the caller's resource-limited capture worker.
"""

from __future__ import annotations

import codecs
import io
import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit
from xml.etree import ElementTree

__all__ = ["SourceTextError", "is_allowed_source_url", "redirect_allowed", "source_text"]

MAX_URL_CHARS = 8_192
MAX_SOURCE_BYTES = 8_000_000  # Matches the existing capture envelope.
MAX_TEXT_CHARS = 2_000_000
MAX_PDF_PAGES = 500
MAX_PDF_CONTENT_BYTES = 16_000_000

# Exact UK courts and the four regulator/advisory hosts in the existing runner.
# Their www aliases are allowed, never arbitrary descendants of these hosts.
_UK_EXACT_BASE_HOSTS = frozenset({
    "gov.scot", "gov.wales",
    "judiciary.scot", "judiciaryni.uk", "judiciary.uk", "supremecourt.uk",
    "fca.org.uk", "financial-ombudsman.org.uk", "ico.org.uk", "acas.org.uk",
})

# Official pages verified 2026-09-05 (host identity only, not substantive law):
# https://www.judiciary.scot/ ; https://www.judiciaryni.uk/
# https://www.leg.state.fl.us/ (Florida Legislature, Online Sunshine)
# https://www.legis.state.pa.us/ -> https://www.palegis.us/ (General Assembly)
# https://www.pacourts.us/ (Unified Judicial System of Pennsylvania)
# https://www.courts.state.va.us/ (Virginia Court System)
# https://www.courts.state.md.us/ (Maryland Courts)
# https://www.legislature.state.al.us/ -> https://alison.legislature.state.al.us/
# https://www.sccourts.org/ (South Carolina Judicial Branch)
# https://www.leg.state.nv.us/ (Nevada Legislature; NRS and court rules)
# https://gencourt.state.nh.us/ -> https://gc.nh.gov/ (General Court of NH)
# https://www.njleg.state.nj.us/ (New Jersey Legislature)
# Legacy and successor hosts are independently eligible. Cross-host redirects
# require a hold except for the exact verified pairs below, never *.us/*.org.
_US_EXACT_BASE_HOSTS = frozenset({
    "leg.state.fl.us", "legis.state.pa.us", "palegis.us", "pacourts.us",
    "courts.state.va.us", "courts.state.md.us", "legislature.state.al.us",
    "sccourts.org", "leg.state.nv.us", "gencourt.state.nh.us", "njleg.state.nj.us",
})
_EXACT_HOSTS = frozenset(
    host
    for base in _UK_EXACT_BASE_HOSTS | _US_EXACT_BASE_HOSTS
    for host in (base, "www." + base)
) | {
    "alison.legislature.state.al.us",
    # Host identity verified 2026-09-05, not legal/currentness verification:
    # https://pub.njleg.state.nj.us/statutes/_READ_ME.txt identifies the NJ
    # Legislature and links https://www.njleg.state.nj.us/ .
    "pub.njleg.state.nj.us",
    # https://www.gov.uk/government/organisations/competition-appeal-tribunal
    # links the Tribunal site; https://www.catribunal.org.uk/about confirms it.
    "www.catribunal.org.uk",
}
# Live 301s verified 2026-09-05 from both legacy hosts to https://gc.nh.gov/,
# whose 200 page identifies the General Court of New Hampshire. gc.nh.gov is
# already eligible under .gov. These are directed pairs, not host families.
_VERIFIED_CROSS_HOST_REDIRECTS = frozenset({
    ("gencourt.state.nh.us", "gc.nh.gov"),
    ("www.gencourt.state.nh.us", "gc.nh.gov"),
})
_EU_CROSS_BORDER_HOSTS = frozenset({"eur-lex.europa.eu", "curia.europa.eu"})
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ENCODED_CONTROL = re.compile(r"%(?:0[0-9a-f]|1[0-9a-f]|7f)", re.IGNORECASE)


def _allowed_host(url: str) -> str | None:
    # urlsplit otherwise silently strips some leading/control whitespace.
    if not isinstance(url, str) or not url or len(url) > MAX_URL_CHARS:
        return None
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url):
        return None
    if "\\" in url or _ENCODED_CONTROL.search(url):
        return None
    if re.search(r"%(?![0-9a-fA-F]{2})", url):
        return None
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.netloc:
            return None
        # Reject all userinfo, ports (including :443 and empty :), escaped host
        # bytes, IPv6 brackets, and Unicode/IDNA ambiguity before normalization.
        authority = parsed.netloc
        if not authority.isascii() or any(char in authority for char in "@:%[]"):
            return None
        host = parsed.hostname
        if not host or len(host) > 253 or authority.lower() != host:
            return None
        labels = host.split(".")
        if any(not _DNS_LABEL.fullmatch(label) for label in labels):
            return None
        if any(label == "localhost" or label.startswith("xn--") for label in labels):
            return None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return None
    except ValueError:
        return None
    if (host == "gov.uk" or host.endswith(".gov.uk")
            or host.endswith(".gov")
            or host in _EXACT_HOSTS or host in _EU_CROSS_BORDER_HOSTS):
        return host
    return None


def is_allowed_source_url(url: str) -> bool:
    """Return transport eligibility for an absolute HTTPS URL, without I/O.

Allow UK gov.uk (including its apex), US .gov, and listed exact exceptions.
All explicit ports are rejected. This is not a legal/relevance verification.
"""
    return _allowed_host(url) is not None


def redirect_allowed(original: str, final: str) -> bool:
    """Allow eligible same-host/www redirects and exact verified directed pairs.

Both arguments must be absolute URLs. False means capture hold, even if two
different hosts are both official but not a verified pair. Check each hop before
fetching it; checking only the final response cannot protect an already-followed redirect.
"""
    original_host, final_host = _allowed_host(original), _allowed_host(final)
    if original_host is None or final_host is None:
        return False
    return (original_host == final_host or original_host == "www." + final_host
            or final_host == "www." + original_host
            or (original_host, final_host) in _VERIFIED_CROSS_HOST_REDIRECTS)


class SourceTextError(ValueError):
    """Bounded, capture-hold extraction error; never returns partial/binary text."""


def _clean_text(text: str) -> str:
    if len(text) > MAX_TEXT_CHARS:
        raise SourceTextError("SOURCE_TEXT_TOO_LARGE")
    if any((ord(char) < 32 and char not in "\t\r\n\f")
           or 127 <= ord(char) < 160 or char == "\ufffd" for char in text):
        raise SourceTextError("SOURCE_TEXT_INVALID_CHARACTERS")
    text = " ".join(text.split())
    if not text:
        raise SourceTextError("SOURCE_TEXT_EMPTY: OCR or source review may be required")
    return text


def _pdf_text(raw: bytes) -> str:
    try:
        from pypdf import PdfReader  # Lazy: HTML/XML work without this dependency.
    except ImportError:
        raise SourceTextError(
            "PDF_EXTRACTION_UNAVAILABLE: pypdf is required; use the bundled Python runtime"
        ) from None
    try:
        reader = PdfReader(io.BytesIO(raw), strict=True)
        if reader.is_encrypted:
            raise SourceTextError("PDF_ENCRYPTED")
        if not 0 < len(reader.pages) <= MAX_PDF_PAGES:
            raise SourceTextError("PDF_PAGE_LIMIT")
        parts: list[str] = []
        char_count = content_bytes = 0
        for page in reader.pages:
            # pypdf recommends checking decoded streams before text extraction:
            # https://pypdf.readthedocs.io/en/stable/user/extract-text.html
            # Decompression itself still needs the caller's process limits.
            contents = page.get_contents()
            if contents is not None:
                content_bytes += len(contents.get_data())
                if content_bytes > MAX_PDF_CONTENT_BYTES:
                    raise SourceTextError("PDF_CONTENT_TOO_LARGE")
            text = page.extract_text() or ""
            char_count += len(text) + 1
            if char_count > MAX_TEXT_CHARS:
                raise SourceTextError("SOURCE_TEXT_TOO_LARGE")
            parts.append(text)
        return _clean_text("\n".join(parts))
    except SourceTextError:
        raise
    except Exception:
        # Library diagnostics can contain arbitrary source bytes or huge strings.
        raise SourceTextError("PDF_EXTRACTION_FAILED") from None


class _NoDTDBuilder(ElementTree.TreeBuilder):
    def doctype(self, name: str, pubid: str | None, system: str | None) -> None:
        raise SourceTextError("XML_DTD_FORBIDDEN")


_HTML_TAGS = frozenset({
    "html", "head", "body", "title", "p", "div", "span", "a", "b", "i", "em",
    "strong", "section", "article", "h1", "h2", "h3", "h4", "h5", "h6",
    "table", "ul", "ol", "li", "br", "script", "style",
})
_HTML_START = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)\b")
# Structure observed on the live OLRC view.xhtml page on 2026-09-05:
# https://uscode.house.gov/view.xhtml?req=granuleid:USC-prelim-title1-section1&num=0&edition=prelim
# This declaration is only a format marker. Never load its DTD or feed it to XML.
_XHTML_DOCTYPE = re.compile(
    r'''<!DOCTYPE\s+html\s+PUBLIC\s+(?P<public_quote>["'])'''
    r'''-//W3C//DTD XHTML 1\.0 Transitional//EN(?P=public_quote)\s+'''
    r'''(?P<system_quote>["'])http://www\.w3\.org/TR/xhtml1/DTD/'''
    r'''xhtml1-transitional\.dtd(?P=system_quote)\s*>'''
)


def _has_known_xhtml_doctype(text: str) -> bool:
    # Check decoded text so UTF-16/32 cannot bypass the declaration guard.
    # There is no fallback for entities, internal subsets or unrecognized DTDs.
    if re.search(r"<!\s*ENTITY\b", text, re.IGNORECASE):
        raise SourceTextError("XML_DTD_FORBIDDEN")
    doctype_start = re.compile(r"<!\s*DOCTYPE\b", re.IGNORECASE)
    match = doctype_start.search(text)
    if not match:
        return False
    if doctype_start.search(text, match.end()):
        raise SourceTextError("XML_DTD_FORBIDDEN")
    end = text.find(">", match.end())
    declaration = text[match.start():end + 1]
    known_xhtml = bool(_XHTML_DOCTYPE.fullmatch(declaration))
    if not known_xhtml and not re.fullmatch(r"<!DOCTYPE\s+html\s*>", declaration, re.IGNORECASE):
        raise SourceTextError("XML_DTD_FORBIDDEN")
    # A declaration hidden inside a comment/element is not a document doctype.
    # Only whitespace, an optional XML declaration, and complete comments may
    # precede it. Use bounded string scans rather than parsing a DTD.
    whitespace = re.compile(r"\s*")
    position = whitespace.match(text).end()
    if text.startswith("<?xml", position) and text[position + 5:position + 6].isspace():
        xml_end = text.find("?>", position + 6, match.start())
        if xml_end < 0:
            raise SourceTextError("XML_DTD_FORBIDDEN")
        position = whitespace.match(text, xml_end + 2).end()
    while text.startswith("<!--", position):
        comment_end = text.find("-->", position + 4, match.start())
        if comment_end < 0:
            raise SourceTextError("XML_DTD_FORBIDDEN")
        position = whitespace.match(text, comment_end + 3).end()
    if position != match.start():
        raise SourceTextError("XML_DTD_FORBIDDEN")
    return known_xhtml


class _HTMLText(HTMLParser):
    _IGNORE = frozenset({"script", "style", "template", "noscript", "iframe", "svg"})
    _BLOCKS = frozenset({
        "p", "div", "br", "hr", "li", "ul", "ol", "dl", "dt", "dd", "table",
        "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "section",
        "article", "header", "footer", "blockquote", "pre", "title",
    })

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.ignored: list[str] = []
        self.char_count = 0
        self.root_tag: str | None = None
        self.root_namespaces: list[str | None] = []
        self.text_before_root = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if self.root_tag is None:
            self.root_tag = tag
            self.root_namespaces = [value for name, value in attrs if name == "xmlns"]
        if tag in self._IGNORE:
            self.ignored.append(tag)
        if tag in self._BLOCKS:
            self.handle_data(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in self.ignored:
            index = len(self.ignored) - 1 - self.ignored[::-1].index(tag)
            self.ignored = self.ignored[:index]
        if tag in self._BLOCKS:
            self.handle_data(" ")

    def handle_startendtag(self, tag: str, attrs: list) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self.root_tag is None and data.strip():
            self.text_before_root = True
        if not self.ignored:
            self.char_count += len(data)
            if self.char_count > MAX_TEXT_CHARS:
                raise SourceTextError("SOURCE_TEXT_TOO_LARGE")
            self.parts.append(data)


def _decode_markup(raw: bytes) -> str:
    encoding = "utf-8-sig"
    # UTF-32 must precede UTF-16 because their BOM prefixes overlap.
    for boms, name in (((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE), "utf-32"),
                       ((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE), "utf-16")):
        if raw.startswith(boms):
            encoding = name
            break
    else:
        declaration = re.search(
            br"(?:<\?xml\b[^>]*\bencoding\s*=|<meta\b[^>]*\bcharset\s*=)"
            br"\s*[\"']?([a-zA-Z0-9_-]+)", raw[:2_048], re.IGNORECASE,
        )
        if declaration:
            declared = declaration.group(1).decode("ascii").lower()
            # Explicit encodings only; never a permissive Latin-1 binary fallback.
            encodings = {"utf-8": "utf-8-sig", "utf8": "utf-8-sig",
                         "us-ascii": "ascii", "ascii": "ascii",
                         "iso-8859-1": "iso-8859-1", "windows-1252": "cp1252"}
            if declared not in encodings:
                raise SourceTextError("SOURCE_ENCODING_UNSUPPORTED")
            encoding = encodings[declared]
    try:
        return raw.decode(encoding, errors="strict")
    except UnicodeError:
        raise SourceTextError("SOURCE_ENCODING_INVALID") from None


def source_text(raw: bytes) -> str:
    """Extract readable XML/HTML/PDF text, or raise SourceTextError for a hold.

No OCR, best-effort PDF byte decoding, external XML entities, partial results,
or automatic dependency installation. PDFs require pypdf only when requested.
Non-markup plain text, other binary formats and undecodable input are rejected.
The known XHTML doctype is a marker for inert HTML parsing, not XML DTD support.
"""
    if not isinstance(raw, bytes):
        raise SourceTextError("SOURCE_BYTES_REQUIRED")
    if not raw or len(raw) > MAX_SOURCE_BYTES:
        raise SourceTextError("SOURCE_BYTE_LIMIT")
    if raw.startswith(b"%PDF-"):
        return _pdf_text(raw)
    text = _decode_markup(raw)
    if not text.lstrip().startswith("<"):
        raise SourceTextError("SOURCE_FORMAT_UNSUPPORTED")
    known_xhtml = _has_known_xhtml_doctype(text)
    first_tag = _HTML_START.search(text)
    is_html = bool(first_tag and first_tag.group(1).lower() in _HTML_TAGS)
    # Only a known-doctype XHTML document can bypass strict XML parsing when
    # it has an XML declaration. Its actual root is checked by the HTML parser.
    if not known_xhtml and (not is_html or text.lstrip().startswith("<?xml")):
        try:
            root = ElementTree.fromstring(text, parser=ElementTree.XMLParser(target=_NoDTDBuilder()))
        except ElementTree.ParseError:
            raise SourceTextError("XML_PARSE_FAILED") from None
        if root.tag.rsplit("}", 1)[-1].lower() != "html":
            return _clean_text(" ".join(root.itertext()))
    parser = _HTMLText()
    try:
        parser.feed(text)
        parser.close()
    except SourceTextError:
        raise
    except Exception:
        raise SourceTextError("HTML_PARSE_FAILED") from None
    if known_xhtml and (parser.root_tag != "html" or parser.text_before_root
                        or parser.root_namespaces != ["http://www.w3.org/1999/xhtml"]):
        raise SourceTextError("XML_DTD_FORBIDDEN")
    return _clean_text("".join(parser.parts))
