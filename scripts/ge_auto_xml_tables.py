"""Append omitted CLML legal tables without changing or approving a base parse.

Pure, bounded adapter for a separately bound parser mode. Row text is a JSON
array of actual effective cell texts, in column order. Metadata retains physical
cells, spanning-cell origins, headers and the surrounding legal context. XML
positions are capture-local locators, never invented statutory paragraph numbers.
No network, storage, index admission, currentness decisions or parser registration.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from backend.app.ingestion.models import BlockKind, DocumentFormat, ParseResult, StructuralBlock

from scripts.ge_unseen_sources import SourceTextError, _decode_markup, _NoDTDBuilder

SCHEMA = "legalbot.clml-missing-tables.v1"
CLML = "http://www.legislation.gov.uk/namespaces/legislation"
HTML = "http://www.w3.org/1999/xhtml"
MAX_XML_BYTES = 8_000_000
MAX_XML_NODES = 100_000
MAX_XML_DEPTH = 96
MAX_XML_TEXT = 2_000_000
MAX_TABLES = 128
MAX_ROWS = 2_048
MAX_CELLS = 16_384
MAX_COLUMNS = 128
MAX_CELL_TEXT = 32_000
MAX_OUTPUT_TEXT = 2_000_000
MAX_OUTPUT_METADATA_BYTES = 8_000_000
MAX_BASE_BLOCKS = 20_000

_EXCLUDED = frozenset(
    {
        "Metadata",
        "Commentaries",
        "Commentary",
        "CommentaryRef",
        "Footnotes",
        "Footnote",
        "MarginNotes",
        "Resources",
        "Versions",
        "Version",
        "ExplanatoryNotes",
        "ExplanatoryNote",
        "EarlierOrders",
        "UnappliedEffects",
        "UnappliedEffect",
        "Effects",
        "Effect",
        "Amendments",
        "Amendment",
        "Changes",
        "PrimaryPrelims",
        "SecondaryPrelims",
        "SignedSection",
    }
)
_TEXT_BREAKS = frozenset({"Text", "P", "Para", "p", "div", "li", "br"})
_CONTEXT_TAGS = frozenset({"Text", "Number", "Title", "Reference", "TitleBlock"})
_SOURCE_ATTRIBUTES = frozenset(
    {
        "id",
        "DocumentURI",
        "IdURI",
        "RestrictExtent",
        "RestrictStartDate",
        "RestrictEndDate",
        "Status",
        "AltVersionRefs",
    }
)


def _name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(raw_sha256: str, path: str) -> str:
    return _sha((raw_sha256 + "\n" + path).encode())


class _BoundedBuilder(_NoDTDBuilder):
    """Reuse the transport's no-DTD policy, with limits during tree construction."""

    def __init__(self) -> None:
        super().__init__()
        self.depth = self.nodes = self.characters = 0

    def start(self, tag, attrs):
        self.depth += 1
        self.nodes += 1
        if (
            self.depth > MAX_XML_DEPTH
            or self.nodes > MAX_XML_NODES
            or len(tag) > 512
            or len(attrs) > 128
        ):
            raise SourceTextError("XML_TABLE_TREE_LIMIT")
        return super().start(tag, attrs)

    def end(self, tag):
        result = super().end(tag)
        self.depth -= 1
        return result

    def data(self, data):
        self.characters += len(data)
        if self.characters > MAX_XML_TEXT:
            raise SourceTextError("XML_TABLE_TEXT_LIMIT")
        return super().data(data)


def _read_xml(raw: bytes, raw_sha256: str) -> ET.Element:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_XML_BYTES:
        raise SourceTextError("XML_TABLE_BYTE_LIMIT")
    if _sha(raw) != raw_sha256:
        raise SourceTextError("XML_TABLE_RAW_HASH_MISMATCH")
    text = _decode_markup(raw)
    # Full decoded input, including UTF-16/32 and declarations after large comments.
    # Unlike the HTML transport, this XML-only adapter has no benign-DTD exception.
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
        raise SourceTextError("XML_DTD_FORBIDDEN")
    try:
        root = ET.fromstring(text, parser=ET.XMLParser(target=_BoundedBuilder()))
    except ET.ParseError:
        raise SourceTextError("XML_TABLE_PARSE_FAILED") from None
    if root.tag != f"{{{CLML}}}Legislation":
        raise SourceTextError("XML_TABLE_CLML_REQUIRED")
    return root


def _official_uri(value: str) -> str:
    parts = urlsplit(value)
    if (
        parts.scheme not in {"http", "https"}
        or parts.netloc != "www.legislation.gov.uk"
        or parts.query
        or parts.fragment
        or "%" in parts.path
        or any(p in {".", ".."} for p in parts.path.split("/"))
    ):
        raise SourceTextError("XML_TABLE_OFFICIAL_URI_REQUIRED")
    return "https://www.legislation.gov.uk" + parts.path


def _document_key(value: str) -> tuple[str, ...]:
    parts = urlsplit(_official_uri(value)).path.strip("/").split("/")
    if parts and parts[0] == "id":
        parts = parts[1:]
    if len(parts) < 3:
        raise SourceTextError("XML_TABLE_DOCUMENT_ID_REQUIRED")
    return tuple(parts[:3])


def _text(element: ET.Element) -> str:
    """Keep inline joins (e.g. pre<Emphasis>fix) and explicit block boundaries."""
    pieces: list[str] = []

    def visit(node: ET.Element) -> None:
        if _name(node) in _EXCLUDED or node.tag == f"{{{HTML}}}table":
            return
        boundary = _name(node) in _TEXT_BREAKS
        if boundary:
            pieces.append("\n")
        if node.text:
            pieces.append(node.text)
        for child in node:
            visit(child)
            if child.tail:
                pieces.append(child.tail)
        if boundary:
            pieces.append("\n")

    visit(element)
    value = "\n".join(" ".join(line.split()) for line in "".join(pieces).splitlines())
    value = re.sub(r"\n+", "\n", value).strip()
    if len(value) > MAX_CELL_TEXT:
        raise SourceTextError("XML_TABLE_CELL_TEXT_LIMIT")
    if "\ufffd" in value or any(ord(c) < 32 and c != "\n" for c in value):
        raise SourceTextError("XML_TABLE_INVALID_CHARACTERS")
    return value


def _tree_positions(root):
    namespaces = sorted({n.tag[1:].split("}", 1)[0] for n in root.iter() if n.tag.startswith("{")})
    if len(namespaces) > 32:
        raise SourceTextError("XML_TABLE_NAMESPACE_LIMIT")
    aliases = {uri: f"n{i}" for i, uri in enumerate(namespaces)}
    aliases[CLML] = "leg"
    aliases[HTML] = "html"

    def qname(tag):
        if tag.startswith("{"):
            uri, local = tag[1:].split("}", 1)
            return aliases[uri] + ":" + local
        return tag

    parents = {}
    paths = {root: f"/{qname(root.tag)}[1]"}
    for node in root.iter():
        counts = {}
        for child in node:
            counts[child.tag] = counts.get(child.tag, 0) + 1
            parents[child] = node
            paths[child] = f"{paths[node]}/{qname(child.tag)}[{counts[child.tag]}]"
    return parents, paths, {prefix: uri for uri, prefix in aliases.items()}


def _ancestors(node, parents):
    chain = [node]
    while node in parents:
        node = parents[node]
        chain.append(node)
    return list(reversed(chain))


def _legal_chain(chain) -> bool:
    # A table below Metadata/Effects/etc. is never accepted even if it mimics Body.
    if any(not n.tag.startswith(f"{{{CLML}}}") or _name(n) in _EXCLUDED for n in chain):
        return False
    names = [_name(n) for n in chain]
    return (
        len(names) > 2
        and names[1] in {"Primary", "Secondary"}
        and ("Body" in names[2:] or ("Schedule" in names and "ScheduleBody" in names))
    )


def _owner(chain):
    for node in reversed(chain):
        if _name(node) == "Schedule":
            return node
    for node in reversed(chain):
        if _name(node) in {"P1", "Schedule", "Body"}:
            return node
    raise SourceTextError("XML_TABLE_LEGAL_CONTAINER_MISSING")


def _scope_anchor(chain, key):
    for node in reversed(chain):
        if uri := node.get("DocumentURI"):
            if _document_key(uri) != key:
                raise SourceTextError("XML_TABLE_FOREIGN_DOCUMENT_URI")
            return _official_uri(uri)
    raise SourceTextError("XML_TABLE_PARENT_LOCATOR_MISSING")


def _context_elements(owner):
    """Keep context before AND after a table, including conditions/definitions."""

    def walk(node):
        if (
            _name(node) in _EXCLUDED
            or node.tag == f"{{{HTML}}}table"
            or not node.tag.startswith(f"{{{CLML}}}")
        ):
            return
        if _name(node) in _CONTEXT_TAGS:
            yield node
            return
        for child in node:
            yield from walk(child)

    return list(walk(owner))


def _normal(text):
    return " ".join(text.split())


def _occurrences(needle, haystack):
    # A partial word is not evidence that a complete source row/context survived.
    left = r"(?<!\w)" if needle and re.match(r"\w", needle[0]) else ""
    right = r"(?!\w)" if needle and re.match(r"\w", needle[-1]) else ""
    return re.finditer(left + re.escape(needle) + right, haystack)


def _within(anchor, scope):
    return bool(anchor and (anchor == scope or anchor.startswith(scope.rstrip("/") + "/")))


def _span(cell, attribute, limit):
    value = cell.get(attribute, "1")
    if not re.fullmatch(r"[1-9][0-9]{0,4}", value) or int(value) > limit:
        raise SourceTextError("XML_TABLE_SPAN_LIMIT")
    return int(value)


def _rows(table, paths, raw_hash):
    """Build a bounded grid, retaining groups and origins of every spanning cell."""
    groups = []
    direct = []
    for child in table:
        if child.tag == f"{{{HTML}}}tr":
            direct.append(child)
        elif child.tag in {f"{{{HTML}}}{n}" for n in ("thead", "tbody", "tfoot")}:
            if direct:
                groups.append((table, list(direct)))
                direct.clear()
            if any(c.tag != f"{{{HTML}}}tr" for c in child):
                raise SourceTextError("XML_TABLE_ROW_STRUCTURE_UNSUPPORTED")
            groups.append((child, list(child)))
        elif child.tag not in {f"{{{HTML}}}{n}" for n in ("caption", "colgroup", "col")}:
            raise SourceTextError("XML_TABLE_STRUCTURE_UNSUPPORTED")
    if direct:
        groups.append((table, direct))
    if sum(len(rows) for _, rows in groups) > MAX_ROWS:
        raise SourceTextError("XML_TABLE_ROW_LIMIT")
    rows_out = []
    cells_total = 0
    row_index = 0
    for group, rows in groups:
        occupied = {}
        for group_index, row in enumerate(rows):
            physical = []
            column = 0
            for cell in row:
                if cell.tag not in {f"{{{HTML}}}td", f"{{{HTML}}}th"}:
                    raise SourceTextError("XML_TABLE_CELL_STRUCTURE_UNSUPPORTED")
                if any(n.tag == f"{{{HTML}}}table" for n in cell.iter()):
                    raise SourceTextError("XML_TABLE_NESTED_TABLE_UNSUPPORTED")
                cells_total += 1
                if cells_total > MAX_CELLS:
                    raise SourceTextError("XML_TABLE_CELL_LIMIT")
                while (group_index, column) in occupied:
                    column += 1
                colspan = _span(cell, "colspan", MAX_COLUMNS)
                rowspan = _span(cell, "rowspan", MAX_ROWS)
                if column + colspan > MAX_COLUMNS or group_index + rowspan > len(rows):
                    raise SourceTextError("XML_TABLE_SPAN_OUT_OF_GROUP")
                value = dict(
                    cell_id=_identity(raw_hash, paths[cell]),
                    xml_path=paths[cell],
                    source_element_id=cell.get("id"),
                    tag=_name(cell),
                    text=_text(cell),
                    xml_character_data="".join(cell.itertext()),
                    row_start=row_index,
                    row_end_exclusive=row_index + rowspan,
                    column_start=column,
                    column_end_exclusive=column + colspan,
                    rowspan=rowspan,
                    colspan=colspan,
                    source_attributes=dict(cell.attrib),
                    reference_ids=[
                        dict(n.attrib)
                        for n in cell.iter()
                        if _name(n) in {"FootnoteRef", "CommentaryRef"}
                    ],
                )
                for rr in range(group_index, group_index + rowspan):
                    for cc in range(column, column + colspan):
                        if (rr, cc) in occupied:
                            raise SourceTextError("XML_TABLE_OVERLAPPING_SPANS")
                        occupied[rr, cc] = value
                physical.append(value)
                column += colspan
            if not physical and not any(rr == group_index for rr, _ in occupied):
                raise SourceTextError("XML_TABLE_EMPTY_ROW")
            grid = [occupied.get((group_index, col)) for col in range(MAX_COLUMNS)]
            while grid and grid[-1] is None:
                grid.pop()
            # Interior unfilled slots are explicit; they are not invented blank cells.
            effective = []
            for cell in grid:
                if cell is not None and (
                    not effective or effective[-1]["cell_id"] != cell["cell_id"]
                ):
                    effective.append(cell)
            rows_out.append(
                dict(
                    element=row,
                    row_id=_identity(raw_hash, paths[row]),
                    xml_path=paths[row],
                    source_element_id=row.get("id"),
                    row_index=row_index,
                    row_group=_name(group),
                    row_group_path=paths[group],
                    group_row_index=group_index,
                    is_header=_name(group) == "thead"
                    or bool(physical and all(c["tag"] == "th" for c in physical)),
                    cells=physical,
                    effective_cells=effective,
                    column_cell_ids=[cell["cell_id"] if cell else None for cell in grid],
                )
            )
            row_index += 1
    return rows_out, cells_total


def append_missing_legal_tables(
    raw: bytes,
    parsed: ParseResult,
    source_url: str,
    raw_sha256: str,
) -> ParseResult:
    """Return an append-only derivative, or raise SourceTextError on unsafe input.

    Existing blocks (including metadata), status, diagnostics and annotation
    streams stay untouched. Not-ready parses are never promoted. Limits apply to
    the entire invocation; unsupported/malformed tables return no partial result.
    The caller must bind this mode and its output to new independent review.
    """
    root = _read_xml(raw, raw_sha256)  # Safety guard also runs for held base parses.
    if parsed.document_format != DocumentFormat.XML:
        raise SourceTextError("XML_TABLE_BASE_FORMAT_MISMATCH")
    key = _document_key(source_url)
    if not source_url.startswith("https://") or _document_key(root.get("DocumentURI", "")) != key:
        raise SourceTextError("XML_TABLE_SOURCE_DOCUMENT_MISMATCH")
    if not parsed.is_ready:
        return parsed
    if (
        len(parsed.body_blocks) > MAX_BASE_BLOCKS
        or sum(len(b.text) for b in parsed.body_blocks) > MAX_XML_BYTES
    ):
        raise SourceTextError("XML_TABLE_BASE_LIMIT")
    ords = [b.ordinal for b in parsed.body_blocks]
    if any(type(n) is not int or n < 0 for n in ords) or len(set(ords)) != len(ords):
        raise SourceTextError("XML_TABLE_BASE_ORDINALS_INVALID")
    parents, paths, namespaces = _tree_positions(root)
    tables = []
    for node in root.iter(f"{{{HTML}}}table"):
        chain = _ancestors(node, parents)[:-1]
        if _legal_chain(chain):
            tables.append((node, chain))
    if len(tables) > MAX_TABLES:
        raise SourceTextError("XML_TABLE_COUNT_LIMIT")
    added = []
    next_ordinal = max(ords, default=-1) + 1
    output_chars = output_metadata_bytes = total_rows = total_cells = 0
    represented_spans = {}
    known = {}
    for block in parsed.body_blocks:
        if block.metadata.get("xml_table_schema") == SCHEMA:
            ident = block.metadata.get("row_id") or block.metadata.get("context_id")
            if not ident or ident in known:
                raise SourceTextError("XML_TABLE_DUPLICATE_IDENTITY")
            known[ident] = block

    def append(text, anchor, heading, metadata):
        nonlocal next_ordinal, output_chars, output_metadata_bytes
        output_chars += len(text)
        output_metadata_bytes += len(json.dumps(metadata, ensure_ascii=False).encode())
        if output_chars > MAX_OUTPUT_TEXT or output_metadata_bytes > MAX_OUTPUT_METADATA_BYTES:
            raise SourceTextError("XML_TABLE_OUTPUT_LIMIT")
        b = StructuralBlock(
            next_ordinal,
            BlockKind.TABLE if "row_id" in metadata else BlockKind.PARAGRAPH,
            text,
            heading,
            source_anchor=anchor,
            metadata=metadata,
        )
        added.append(b)
        next_ordinal += 1
        return b.ordinal

    for table, chain in tables:
        owner = _owner(chain)
        owner_chain = _ancestors(owner, parents)
        scope = _scope_anchor(owner_chain, key)
        table_id = _identity(raw_sha256, paths[table])
        rows, cell_count = _rows(table, paths, raw_sha256)
        total_rows += len(rows)
        total_cells += cell_count
        if total_rows > MAX_ROWS or total_cells > MAX_CELLS:
            raise SourceTextError("XML_TABLE_TOTAL_ROWS_OR_CELLS_LIMIT")
        common = dict(
            xml_table_schema=SCHEMA,
            raw_sha256=raw_sha256,
            canonical_source_url=source_url,
            table_id=table_id,
            table_xml_path=paths[table],
            xml_path_namespaces=namespaces,
            parent_official_locator=scope,
            source_table_attributes=dict(table.attrib),
            context_scope="ENCLOSING_SCHEDULE_OR_PROVISION; cross-reference resolution not performed",
            source_context_attributes=[
                {k: v for k, v in n.attrib.items() if k in _SOURCE_ATTRIBUTES}
                for n in chain
                if any(k in _SOURCE_ATTRIBUTES for k in n.attrib)
            ],
        )
        context = []
        context_ordinals = []
        headings = []
        elements = _context_elements(owner)
        elements.extend(c for c in table if c.tag == f"{{{HTML}}}caption")
        for element in elements:
            text = _text(element)
            if not text:
                continue
            ident = _identity(raw_sha256, paths[element])
            if _name(element) in {"Number", "Title", "TitleBlock", "caption"}:
                headings.append(text)
            matches = [
                b.ordinal
                for b in parsed.body_blocks
                if b.metadata.get("xml_table_schema") != SCHEMA
                and _within(b.source_anchor, scope)
                and next(_occurrences(_normal(text), _normal(b.text)), None) is not None
            ]
            if ident in known:
                block = known[ident]
                if block.text != text or block.metadata.get("raw_sha256") != raw_sha256:
                    raise SourceTextError("XML_TABLE_EXISTING_CONTEXT_MISMATCH")
                matches.append(block.ordinal)
            if not matches:
                meta = {
                    **common,
                    "context_id": ident,
                    "context_xml_path": paths[element],
                    "source_context_tag": _name(element),
                    "locator_kind": "CAPTURE_LOCAL_XML_CONTEXT",
                    "reference_ids": [
                        dict(n.attrib)
                        for n in element.iter()
                        if _name(n) in {"FootnoteRef", "CommentaryRef"}
                    ],
                }
                number = append(
                    text, f"capture-sha256:{raw_sha256}#xml-context-{ident}", tuple(headings), meta
                )
                known[ident] = added[-1]
                matches = [number]
            context.append(
                dict(context_id=ident, xml_path=paths[element], text=text, block_ordinals=matches)
            )
            context_ordinals.extend(matches)
        header_ids = [r["row_id"] for r in rows if r["is_header"]]
        headers = [{k: v for k, v in r.items() if k != "element"} for r in rows if r["is_header"]]
        row_ordinals = {}
        table_added_start = len(added)
        for row in rows:
            text = json.dumps([c["text"] for c in row["effective_cells"]], ensure_ascii=False)
            element = row["element"]
            row_id = row["row_id"]
            if row_id in known:
                b = known[row_id]
                if (
                    b.text != text
                    or b.metadata.get("raw_sha256") != raw_sha256
                    or b.metadata.get("cells") != row["cells"]
                ):
                    raise SourceTextError("XML_TABLE_EXISTING_ROW_MISMATCH")
                row_ordinals[row_id] = b.ordinal
                continue
            # Recognise contiguous cell text already emitted inside a scoped base
            # provision, not merely the same cell words scattered across a document.
            variants = tuple(
                dict.fromkeys(
                    (
                        text,
                        _normal("".join(element.itertext())),
                        _normal(" ".join(c["text"] for c in row["cells"])),
                    )
                )
            )
            represented = False
            for b in parsed.body_blocks:
                if b.metadata.get("xml_table_schema") == SCHEMA or not _within(
                    b.source_anchor, scope
                ):
                    continue
                body = _normal(b.text)
                for variant in variants:
                    if not variant:
                        continue
                    # A spanning row is represented only when inherited context is
                    # also present, or the block explicitly has the effective row.
                    if len(row["effective_cells"]) != len(row["cells"]) and body != text:
                        continue
                    if len(row["cells"]) == 1 and body != variant:
                        continue
                    for match in _occurrences(variant, body):
                        span = match.span()
                        used = represented_spans.setdefault(b.ordinal, [])
                        if any(span[0] < end and start < span[1] for start, end in used):
                            continue
                        used.append(span)
                        represented = True
                        row_ordinals[row_id] = b.ordinal
                        break
                    if represented:
                        break
                if represented:
                    break
            if represented:
                continue
            anchor = (
                _official_uri(element.get("DocumentURI"))
                if element.get("DocumentURI")
                else f"capture-sha256:{raw_sha256}#xml-row-{row_id}"
            )
            if element.get("DocumentURI") and _document_key(element.get("DocumentURI")) != key:
                raise SourceTextError("XML_TABLE_FOREIGN_ROW_URI")
            meta = {
                **common,
                **{k: v for k, v in row.items() if k != "element"},
                "locator_kind": "OFFICIAL_XML_ROW_URI"
                if element.get("DocumentURI")
                else "CAPTURE_LOCAL_XML_TABLE_ROW",
                "text_format": "JSON_ARRAY_OF_EFFECTIVE_CELL_TEXT_IN_COLUMN_ORDER",
                "context": context,
                "context_block_ordinals": sorted(set(context_ordinals)),
                "header_row_ids": header_ids,
                "header_rows": headers,
            }
            row_ordinals[row_id] = append(text, anchor, tuple(headings), meta)
        header_ordinals = [row_ordinals[row_id] for row_id in header_ids]
        for index in range(table_added_start, len(added)):
            block = added[index]
            added[index] = replace(
                block,
                metadata={
                    **block.metadata,
                    "header_block_ordinals": header_ordinals,
                    "context_block_ordinals": sorted(set(context_ordinals + header_ordinals)),
                },
            )
            output_metadata_bytes += len(
                json.dumps(added[index].metadata, ensure_ascii=False).encode()
            ) - len(json.dumps(block.metadata, ensure_ascii=False).encode())
            if output_metadata_bytes > MAX_OUTPUT_METADATA_BYTES:
                raise SourceTextError("XML_TABLE_OUTPUT_LIMIT")
    return replace(parsed, body_blocks=(*parsed.body_blocks, *added)) if added else parsed
