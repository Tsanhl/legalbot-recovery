"""Bounded table-adapter checks; real input is the explicitly visible NI capture.

All other XML is synthetic and in memory. No index, model, authority review,
network, private bank or other evaluation pack is used.
"""

from __future__ import annotations

import json
from dataclasses import asdict, replace
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest
from backend.app.ingestion.models import (
    Annotation,
    BlockKind,
    DocumentFormat,
    ParseResult,
    ParseStatus,
    StructuralBlock,
)
from scripts import ge_auto_xml_tables as adapter
from scripts.ge_unseen_sources import SourceTextError

ROOT = Path(__file__).resolve().parents[2]
VISIBLE = ROOT / "data/evaluations/general-enquiries/ge-auto-research-visible-20260905"
SOURCE_ID = "038c9a36cc8c3730dc919a0043e9b307e03d54dd1a658f0f04a171baec602c20"
RAW_SHA = "adef519541b5eb2da926a9d725c502a3bd001c02c982427911f12f5bea7c9240"
DOC = "https://www.legislation.gov.uk/nisr/2023/20"
URL = DOC + "/data.xml"
SCOPE = DOC + "/schedule"
TABLE = """<h:table><h:thead><h:tr><h:th>Provision</h:th><h:th>Subject</h:th></h:tr></h:thead>
<h:tbody><h:tr><h:td>Section 4</h:td><h:td>Deposit limit</h:td></h:tr></h:tbody></h:table>"""


def document(content):
    return (
        f'<Legislation xmlns="{adapter.CLML}" xmlns:h="{adapter.HTML}" '
        f'DocumentURI="{DOC}">{content}</Legislation>'
    ).encode()


def schedule(table=TABLE, before="", after=""):
    return document(
        f'<Secondary><Schedules><Schedule DocumentURI="{SCOPE}"><Number>SCHEDULE</Number>'
        f"<ScheduleBody>{before}<P><Tabular>{table}</Tabular></P>{after}"
        "</ScheduleBody></Schedule></Schedules></Secondary>"
    )


def base(*blocks, status=ParseStatus.READY):
    return ParseResult(
        status,
        DocumentFormat.XML,
        blocks or (StructuralBlock(0, BlockKind.HEADING, "SCHEDULE", source_anchor=SCOPE),),
        comments=(Annotation("synthetic-comment", "Comment remains separate"),),
        diagnostics=("SYNTHETIC_NOT_LEGAL_REVIEWED",),
    )


def run(raw, initial=None):
    return adapter.append_missing_legal_tables(raw, initial or base(), URL, adapter._sha(raw))


def table_rows(result):
    return [b for b in result.body_blocks if "row_id" in b.metadata]


def load_visible():
    raw = (VISIBLE / "author-research/sources" / f"{SOURCE_ID}.bytes").read_bytes()
    saved = json.loads((VISIBLE / "structural-review-input" / f"{SOURCE_ID}.json").read_text())
    value = saved["parsed"]
    assert value["comments"] == value["revisions"] == []
    initial = ParseResult(
        ParseStatus(value["status"]),
        DocumentFormat(value["document_format"]),
        tuple(
            StructuralBlock(
                **{**b, "kind": BlockKind(b["kind"]), "heading_path": tuple(b["heading_path"])}
            )
            for b in value["body_blocks"]
        ),
        diagnostics=tuple(value["diagnostics"]),
    )
    return raw, initial


def test_visible_ni_missing_schedule_rows_and_exact_source_bindings():
    raw, initial = load_visible()
    assert adapter._sha(raw) == RAW_SHA
    assert len(initial.body_blocks) == 4
    assert not any("Limit on tenancy deposit amount" in b.text for b in initial.body_blocks)
    frozen = asdict(initial)
    result = run(raw, initial)
    assert asdict(initial) == frozen
    assert all(a is b for a, b in zip(initial.body_blocks, result.body_blocks, strict=False))
    rows = table_rows(result)
    assert len(rows) == 8
    assert sum(not b.metadata["is_header"] for b in rows) == 7
    # Independently resolve every emitted row/cell XPath against the pinned bytes.
    # Do not use the adapter's text or path builders as the verification oracle.
    root = ET.fromstring(raw)
    for block in rows:
        meta = block.metadata
        namespaces = meta["xml_path_namespaces"]
        node = root.find("./" + meta["xml_path"].split("/", 2)[2], namespaces)
        assert node is not None
        assert json.loads(block.text) == [" ".join("".join(c.itertext()).split()) for c in node]
        for cell in meta["cells"]:
            raw_cell = root.find("./" + cell["xml_path"].split("/", 2)[2], namespaces)
            assert raw_cell is not None
            assert "".join(raw_cell.itertext()) == cell["xml_character_data"]
            assert adapter._identity(RAW_SHA, cell["xml_path"]) == cell["cell_id"]
    row = next(
        b for b in rows if json.loads(b.text) == ["Section 4", "Limit on tenancy deposit amount"]
    )
    assert row.metadata["row_index"] == 4
    assert row.metadata["group_row_index"] == 3
    assert row.metadata["parent_official_locator"] == SCOPE
    assert row.metadata["raw_sha256"] == RAW_SHA
    assert row.source_anchor.startswith(f"capture-sha256:{RAW_SHA}#xml-row-")
    assert row.metadata["locator_kind"] == "CAPTURE_LOCAL_XML_TABLE_ROW"
    assert [
        (c["column_start"], c["column_end_exclusive"], c["rowspan"], c["colspan"])
        for c in row.metadata["cells"]
    ] == [(0, 1, 1, 1), (1, 2, 1, 1)]
    blocks = {b.ordinal: b for b in result.body_blocks}
    context = [blocks[n].text for n in row.metadata["context_block_ordinals"]]
    assert "Article 2" in context
    assert any("coming into operation on 1st April 2023." in text for text in context)
    assert any(
        json.loads(blocks[n].text) == ["Provisions of the Act", "Subject Matter"]
        for n in row.metadata["header_block_ordinals"]
    )
    assert adapter.append_missing_legal_tables(raw, result, URL, RAW_SHA) is result


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32"])
@pytest.mark.parametrize(
    "declaration",
    [
        '<!DOCTYPE Legislation SYSTEM "file:///must-not-read">',
        '<!DOCTYPE Legislation [<!ENTITY payload SYSTEM "https://must-not-fetch.invalid/">]>',
        '<!ENTITY payload "unsafe">',
    ],
)
def test_dtd_entities_rejected_before_parsing_even_for_held_input(encoding, declaration):
    text = "<!--" + ("x" * 100_100) + "-->" + declaration + schedule().decode()
    raw = text.encode(encoding)
    with pytest.raises(SourceTextError, match="XML_DTD_FORBIDDEN"):
        run(raw, base(status=ParseStatus.QUARANTINED))


@pytest.mark.parametrize(
    "wrapper",
    [
        "Metadata",
        "UnappliedEffects",
        "Effects",
        "Amendments",
        "Commentaries",
        "Footnotes",
        "ExplanatoryNotes",
        "Versions",
    ],
)
def test_metadata_effects_and_nonoperative_tables_excluded(wrapper):
    fake = f"<{wrapper}><Body><Tabular>{TABLE}</Tabular></Body></{wrapper}>"
    raw = document(f"<Secondary>{fake}</Secondary>")
    initial = base()
    assert run(raw, initial) is initial


def test_foreign_namespace_body_and_table_not_mistaken_for_operative_clml():
    raw = document(
        f'<Secondary><m:Body xmlns:m="urn:metadata"><Tabular>{TABLE}</Tabular></m:Body>'
        "<Body><Tabular><table><tr><td>Unnamespaced trap</td></tr></table></Tabular></Body>"
        "</Secondary>"
    )
    initial = base()
    assert run(raw, initial) is initial


def test_real_body_table_and_existing_ordinals_metadata_and_flags_untouched():
    scope = DOC + "/article/2"
    raw = document(
        f'<Secondary><Body><P1 DocumentURI="{scope}"><P1para>'
        f"<Tabular>{TABLE}</Tabular></P1para></P1></Body></Secondary>"
    )
    blocks = (
        StructuralBlock(
            19,
            BlockKind.PARAGRAPH,
            "Existing\ntext",
            source_anchor=scope,
            metadata={"admitted": False, "legal_gold": False, "currentness": "HOLD"},
        ),
        StructuralBlock(4, BlockKind.HEADING, "Original heading", source_anchor=DOC),
    )
    initial = base(*blocks)
    result = run(raw, initial)
    assert result.body_blocks[:2] == blocks
    assert all(result.body_blocks[i] is blocks[i] for i in range(2))
    assert [b.ordinal for b in result.body_blocks[2:]] == [20, 21]
    assert result.comments is initial.comments
    assert result.revisions is initial.revisions
    assert result.diagnostics is initial.diagnostics
    assert result.status is initial.status
    for b in result.body_blocks[2:]:
        assert (
            not {
                "admitted",
                "legal_gold",
                "qualified_legal_review",
                "currentness",
                "authority_type",
            }
            & b.metadata.keys()
        )


def test_headers_conditions_definitions_and_cell_spans_preserve_relations():
    table = """<h:table><h:thead><h:tr><h:th colspan="2">Application</h:th><h:th>Exception</h:th></h:tr>
    <h:tr><h:th>Provision</h:th><h:th>Meaning</h:th><h:th>Condition</h:th></h:tr></h:thead>
    <h:tbody><h:tr><h:td rowspan="2">Section 4</h:td><h:td>pre<Emphasis>fix</Emphasis></h:td>
    <h:td><Text>First condition.</Text><Text>Second condition.</Text></h:td></h:tr>
    <h:tr><h:td>Second meaning</h:td><h:td>Only if paid</h:td></h:tr></h:tbody></h:table>"""
    raw = schedule(
        table,
        before="<P><Text>In this Schedule, deposit means security.</Text></P>",
        after="<P><Text>Except where an earlier obligation exists.</Text></P>",
    )
    result = run(raw)
    rows = table_rows(result)
    assert len(rows) == 4
    first, last = rows[-2:]
    assert first.metadata["cells"][0]["rowspan"] == 2
    assert json.loads(first.text) == ["Section 4", "prefix", "First condition.\nSecond condition."]
    assert json.loads(last.text) == ["Section 4", "Second meaning", "Only if paid"]
    assert last.metadata["column_cell_ids"][0] == first.metadata["cells"][0]["cell_id"]
    assert last.metadata["effective_cells"][0]["row_start"] == 2
    assert len(last.metadata["cells"]) == 2
    assert rows[0].metadata["cells"][0]["colspan"] == 2
    assert len(last.metadata["header_block_ordinals"]) == 2
    contexts = [c["text"] for c in last.metadata["context"]]
    assert "In this Schedule, deposit means security." in contexts
    assert "Except where an earlier obligation exists." in contexts


def test_existing_contiguous_rows_not_duplicated_but_unrelated_words_do_not_suppress():
    raw = schedule()
    initial = base(
        StructuralBlock(
            0, BlockKind.PARAGRAPH, "ProvisionSubject Section 4Deposit limit", source_anchor=SCOPE
        )
    )
    assert not table_rows(run(raw, initial))
    wrong = base(
        StructuralBlock(
            0, BlockKind.PARAGRAPH, "Section 4Deposit limit", source_anchor=DOC + "/article/1"
        )
    )
    assert len(table_rows(run(raw, wrong))) == 2
    scattered = base(
        StructuralBlock(
            0,
            BlockKind.PARAGRAPH,
            "Section 4 is unrelated to the later words Deposit limit",
            source_anchor=SCOPE,
        )
    )
    assert len(table_rows(run(raw, scattered))) == 2


def test_repeated_identical_rows_are_distinct_source_rows():
    table = (
        "<h:table><h:tbody>"
        + ("<h:tr><h:td>A</h:td><h:td>B</h:td></h:tr>" * 2)
        + "</h:tbody></h:table>"
    )
    initial = base(StructuralBlock(0, BlockKind.PARAGRAPH, "AB", source_anchor=SCOPE))
    rows = table_rows(run(schedule(table), initial))
    assert len(rows) == 1
    assert rows[0].metadata["row_index"] == 1


def test_partial_word_matches_do_not_erase_distinct_rows_or_context():
    initial = base(
        StructuralBlock(
            0, BlockKind.PARAGRAPH, "SCHEDULE Section 4Deposit limits", source_anchor=SCOPE
        )
    )
    raw = schedule(before="<P><Text>limit</Text></P>")
    result = run(raw, initial)
    assert len(table_rows(result)) == 2
    assert any(b.text == "limit" for b in result.body_blocks)


def test_table_nested_in_text_has_separate_rows_and_surrounding_context():
    raw = schedule(
        f"<Text>Only for the listed provisions.{TABLE}Except existing obligations.</Text>"
    )
    result = run(raw)
    assert len(table_rows(result)) == 2
    contexts = [c["text"] for c in table_rows(result)[-1].metadata["context"]]
    assert any(
        "Only for the listed provisions." in text and "Except existing obligations." in text
        for text in contexts
    )
    assert not any("Deposit limit" in text for text in contexts)


def test_final_header_links_are_included_in_metadata_budget(monkeypatch):
    raw = schedule()
    result = run(raw)
    final_size = sum(
        len(json.dumps(b.metadata, ensure_ascii=False).encode()) for b in result.body_blocks[1:]
    )
    monkeypatch.setattr(adapter, "MAX_OUTPUT_METADATA_BYTES", final_size - 1)
    with pytest.raises(SourceTextError, match="OUTPUT_LIMIT"):
        run(raw)


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("rowspan", "0"),
        ("rowspan", "999999"),
        ("colspan", "-1"),
        ("colspan", "129"),
        ("rowspan", "2"),
    ],
)
def test_invalid_or_cross_group_spans_fail_closed(attribute, value):
    table = f'<h:table><h:tr><h:td {attribute}="{value}">A</h:td></h:tr></h:table>'
    with pytest.raises(SourceTextError, match="XML_TABLE_SPAN"):
        run(schedule(table))


def test_overlapping_spans_and_nested_table_are_rejected_without_mutation():
    overlap = """<h:table><h:tbody><h:tr><h:td>A</h:td><h:td rowspan="2">B</h:td></h:tr>
    <h:tr><h:td colspan="2">C</h:td></h:tr></h:tbody></h:table>"""
    for table, message in [
        (overlap, "OVERLAPPING"),
        (f"<h:table><h:tr><h:td>{TABLE}</h:td></h:tr></h:table>", "NESTED"),
    ]:
        initial = base()
        frozen = asdict(initial)
        with pytest.raises(SourceTextError, match=message):
            run(schedule(table), initial)
        assert asdict(initial) == frozen


@pytest.mark.parametrize(
    "limit,value,message",
    [
        ("MAX_XML_BYTES", 20, "BYTE_LIMIT"),
        ("MAX_XML_NODES", 5, "TREE_LIMIT"),
        ("MAX_XML_DEPTH", 4, "TREE_LIMIT"),
        ("MAX_XML_TEXT", 10, "TEXT_LIMIT"),
        ("MAX_ROWS", 1, "ROW_LIMIT"),
        ("MAX_CELLS", 1, "CELL_LIMIT"),
        ("MAX_TABLES", 0, "COUNT_LIMIT"),
        ("MAX_OUTPUT_TEXT", 5, "OUTPUT_LIMIT"),
        ("MAX_OUTPUT_METADATA_BYTES", 20, "OUTPUT_LIMIT"),
        ("MAX_CELL_TEXT", 2, "CELL_TEXT_LIMIT"),
    ],
)
def test_resource_limits_are_enforced_without_partial_result(monkeypatch, limit, value, message):
    monkeypatch.setattr(adapter, limit, value)
    initial = base()
    frozen = asdict(initial)
    with pytest.raises(SourceTextError, match=message):
        run(schedule(), initial)
    assert asdict(initial) == frozen


def test_global_row_budget_across_tables(monkeypatch):
    monkeypatch.setattr(adapter, "MAX_ROWS", 3)
    raw = schedule(TABLE + TABLE)
    with pytest.raises(SourceTextError, match="TOTAL_ROWS_OR_CELLS_LIMIT"):
        run(raw)


def test_hash_document_identity_malformed_xml_and_base_integrity():
    raw = schedule()
    with pytest.raises(SourceTextError, match="RAW_HASH_MISMATCH"):
        adapter.append_missing_legal_tables(raw, base(), URL, "0" * 64)
    with pytest.raises(SourceTextError, match="SOURCE_DOCUMENT_MISMATCH"):
        adapter.append_missing_legal_tables(
            raw, base(), URL.replace("/2023/20", "/2023/21"), adapter._sha(raw)
        )
    with pytest.raises(SourceTextError, match="PARSE_FAILED"):
        run(raw[:-10])
    with pytest.raises(SourceTextError, match="BASE_ORDINALS_INVALID"):
        run(
            raw,
            base(
                StructuralBlock(0, BlockKind.TITLE, "A"), StructuralBlock(0, BlockKind.TITLE, "B")
            ),
        )
    initial = base(status=ParseStatus.INVALID)
    assert run(raw, initial) is initial


def test_already_appended_row_tampering_is_not_accepted_as_deduplication():
    raw = schedule()
    result = run(raw)
    last = result.body_blocks[-1]
    modified = replace(
        result, body_blocks=(*result.body_blocks[:-1], replace(last, text="False substitute"))
    )
    with pytest.raises(SourceTextError, match="EXISTING_ROW_MISMATCH"):
        run(raw, modified)
