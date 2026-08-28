from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import stat
import struct
import subprocess
import zipfile
import zlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from lxml import etree
from pypdf import PdfWriter

import app.evaluation.owner_quality_canary_docx as docx_module
from app.evaluation.owner_quality_canary_authorization import OwnerDecisionRequired
from app.evaluation.owner_quality_canary_docx import (
    CONTENT_WIDTH_DXA,
    TABLE_HORIZONTAL_MARGIN_DXA,
    TABLE_INDENT_DXA,
    TABLE_WIDTH_DXA,
    export_owner_quality_canary_docx,
    record_owner_quality_canary_docx_inspection,
    record_owner_quality_canary_docx_render,
)
from app.evaluation.owner_quality_canary_intake import create_owner_review_companion
from app.evaluation.owner_quality_canary_synthetic_fixture import (
    create_synthetic_owner_canary_review_fixture,
)

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS = {"w": W}


def _chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def _png(width: int = 600, height: int = 800) -> bytes:
    rows = b"".join(b"\x00" + b"\xff\xff\xff" * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _chunk(b"IDAT", zlib.compress(rows, level=9))
        + _chunk(b"IEND", b"")
    )


def _document_xml(path: Path) -> etree._Element:
    with zipfile.ZipFile(path) as archive:
        return etree.fromstring(archive.read("word/document.xml"))


def _install_owned_renderer_stub(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    page_pngs: tuple[bytes, ...],
) -> None:
    identity = tmp_path / "approved-renderer-identity.bin"
    identity.write_bytes(b"fixed synthetic renderer identity")

    def _open_identity(_path: Path, *, expected_sha256: str) -> tuple[int, bytes]:
        assert expected_sha256
        return os.open(identity, os.O_RDONLY), identity.read_bytes()

    monkeypatch.setattr(docx_module, "_open_verified_regular_file", _open_identity)

    def _write_at(directory_fd: int, name: str, data: bytes) -> None:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            os.write(descriptor, data)
        finally:
            os.close(descriptor)

    def _run(
        command: tuple[str, ...],
        *,
        pass_fds: tuple[int, ...],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        output_fd = pass_fds[-1]
        writer = PdfWriter()
        for _png_bytes in page_pngs:
            writer.add_blank_page(width=612, height=792)
        pdf = io.BytesIO()
        writer.write(pdf)
        _write_at(output_fd, "render-input.pdf", pdf.getvalue())
        for ordinal, png in enumerate(page_pngs, start=1):
            _write_at(output_fd, f"page-{ordinal}.png", png)
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(docx_module.subprocess, "run", _run)


def test_docx_is_create_only_answer_only_exact_three_by_ten_and_deterministic(
    tmp_path: Path,
) -> None:
    first = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "first",
        run_id="development-docx-001",
    )
    first_docx, first_control_path, control = export_owner_quality_canary_docx(
        workspace=first.workspace,
        package=first.package,
    )
    assert tuple(len(group) for group in control.annex_case_ids) == (10, 10, 10)
    assert tuple(item for group in control.annex_case_ids for item in group) == control.case_ids
    assert control.case_ids == first.package.case_ids
    assert control.answer_sha256s == first.package.answer_sha256s
    assert control.answer_only and not control.plaintext_questions_included
    assert stat.S_IMODE(first_docx.stat().st_mode) == 0o600
    assert stat.S_IMODE(first_control_path.stat().st_mode) == 0o600

    root = _document_xml(first_docx)
    visible_text = "".join(root.itertext())
    for case_id, answer in first.answers.items():
        assert case_id in visible_text
        assert answer in visible_text
    assert "sample-manifest" not in visible_text
    assert "held private draft content" not in visible_text.casefold()
    assert visible_text.count("Annex A") == 1
    assert visible_text.count("Annex B") == 1
    assert visible_text.count("Annex C") == 1

    tables = root.xpath(".//w:tbl", namespaces=NS)
    assert len(tables) == 61
    for table in tables:
        width = table.xpath("./w:tblPr/w:tblW/@w:w", namespaces=NS)
        indent = table.xpath("./w:tblPr/w:tblInd/@w:w", namespaces=NS)
        grid = [int(value) for value in table.xpath("./w:tblGrid/w:gridCol/@w:w", namespaces=NS)]
        assert width == [str(TABLE_WIDTH_DXA)]
        assert indent == [str(TABLE_INDENT_DXA)]
        assert sum(grid) == TABLE_WIDTH_DXA
        assert sum(grid) + TABLE_INDENT_DXA + TABLE_HORIZONTAL_MARGIN_DXA == CONTENT_WIDTH_DXA
        for row in table.xpath("./w:tr", namespaces=NS):
            cell_widths = [
                int(value) for value in row.xpath("./w:tc/w:tcPr/w:tcW/@w:w", namespaces=NS)
            ]
            assert cell_widths == grid

    with pytest.raises(FileExistsError, match="create-only"):
        export_owner_quality_canary_docx(
            workspace=first.workspace,
            package=first.package,
        )

    second = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "second",
        run_id="development-docx-001",
    )
    second_docx, _path, second_control = export_owner_quality_canary_docx(
        workspace=second.workspace,
        package=second.package,
    )
    assert second_docx.read_bytes() == first_docx.read_bytes()
    assert second_control.document_sha256 == control.document_sha256


def test_docx_render_receipt_binds_real_page_bytes_and_is_create_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(inspect.signature(record_owner_quality_canary_docx_render).parameters) == (
        "workspace",
        "control",
        "rendered_at",
    )
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "fixture",
        run_id="development-render-001",
    )
    docx_path, _control_path, control = export_owner_quality_canary_docx(
        workspace=fixture.workspace,
        package=fixture.package,
    )
    _install_owned_renderer_stub(
        monkeypatch,
        tmp_path,
        page_pngs=tuple(_png(width=600 + ordinal, height=800 + ordinal) for ordinal in range(1, 4)),
    )
    receipt_path, receipt = record_owner_quality_canary_docx_render(
        workspace=fixture.workspace,
        control=control,
        rendered_at=datetime(2026, 8, 20, 12, 0, tzinfo=UTC),
    )
    assert receipt.page_count == 3
    assert receipt.document_sha256 == hashlib.sha256(docx_path.read_bytes()).hexdigest()
    assert [page.width_px for page in receipt.pages] == [601, 602, 603]
    serialized = json.loads(receipt_path.read_text())
    assert serialized["technical_render_passed"] is True
    assert serialized["trusted_owner_visual_inspection_verified"] is False
    assert serialized["authorizes_owner_review_companion"] is False
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600

    with pytest.raises(OwnerDecisionRequired) as blocked:
        record_owner_quality_canary_docx_inspection(
            workspace=fixture.workspace,
            control=control,
            receipt=receipt,
            owner_ref="owner:" + "a" * 64,
            inspected_at=datetime(2026, 8, 20, 12, 1, tzinfo=UTC),
            inspected_page_count=3,
            all_pages_inspected_at_full_size=True,
            visual_inspection_passed=True,
            no_clipped_text=True,
            no_overlapping_objects=True,
            no_broken_tables=True,
            no_missing_glyphs=True,
            signature_algorithm="owner-signature-v1",
            signature="synthetic-signature",
        )
    assert blocked.value.reason_code == "trusted_owner_docx_inspection_signature_verifier_missing"
    with pytest.raises(OwnerDecisionRequired) as companion_blocked:
        create_owner_review_companion(
            workspace=fixture.workspace,
            package=fixture.package,
        )
    assert (
        companion_blocked.value.reason_code
        == "trusted_owner_docx_inspection_signature_verifier_missing"
    )

    with pytest.raises(FileExistsError, match="create-only"):
        record_owner_quality_canary_docx_render(
            workspace=fixture.workspace,
            control=control,
            rendered_at=datetime(2026, 8, 20, 12, 1, tzinfo=UTC),
        )


def test_every_table_row_and_cell_paragraph_has_no_split_geometry(
    tmp_path: Path,
) -> None:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "pagination-geometry",
        run_id="development-docx-pagination-001",
    )
    docx_path, _control_path, _control = export_owner_quality_canary_docx(
        workspace=fixture.workspace,
        package=fixture.package,
    )
    root = _document_xml(docx_path)
    assert len(root.xpath(".//w:br[@w:type='page']", namespaces=NS)) == 30
    tables = root.xpath(".//w:tbl", namespaces=NS)
    assert tables
    assert len(tables[0].xpath("./w:tr", namespaces=NS)) == 5
    for table_index, table in enumerate(tables):
        if table_index:
            rows = table.xpath("./w:tr", namespaces=NS)
            assert len(rows) == 1
            cells = rows[0].xpath("./w:tc", namespaces=NS)
            expected_cells = 4 if table_index % 2 else 2
            expected_breaks = 2 if table_index % 2 else 1
            assert len(cells) == expected_cells
            for cell in cells:
                assert len(cell.xpath("./w:p/w:r/w:br", namespaces=NS)) == expected_breaks
        assert table.xpath(
            "./w:tblPr/w:tblCellSpacing[@w:w='0' and @w:type='dxa']",
            namespaces=NS,
        )
        assert table.xpath(
            "./w:tblPr/w:tblLook[@w:firstColumn='0' and @w:firstRow='0' "
            "and @w:lastColumn='0' and @w:lastRow='0' and @w:noHBand='1' "
            "and @w:noVBand='1' and @w:val='0000']",
            namespaces=NS,
        )
        rows = table.xpath("./w:tr", namespaces=NS)
        for row in rows:
            assert row.xpath("./w:trPr/w:cantSplit[@w:val='1']", namespaces=NS)
            for paragraph in row.xpath("./w:tc/w:p", namespaces=NS):
                indents = paragraph.xpath("./w:pPr/w:ind", namespaces=NS)
                assert len(indents) == 1
                indent = indents[0]
                assert indent.get(f"{{{W}}}left") == "0"
                assert indent.get(f"{{{W}}}right") == "0"
                assert indent.get(f"{{{W}}}firstLine") == "0"
                assert paragraph.xpath("./w:pPr/w:keepLines[@w:val='1']", namespaces=NS)
                keep_next = paragraph.xpath("./w:pPr/w:keepNext", namespaces=NS)
                assert len(keep_next) == 1
                assert keep_next[0].get(f"{{{W}}}val") == "0"
                widow_control = paragraph.xpath("./w:pPr/w:widowControl", namespaces=NS)
                assert len(widow_control) == 1
                assert widow_control[0].get(f"{{{W}}}val") == "0"


def test_docx_fails_closed_when_persisted_final_package_is_missing(tmp_path: Path) -> None:
    fixture = create_synthetic_owner_canary_review_fixture(
        root=tmp_path / "missing-package",
        run_id="development-docx-missing-001",
    )
    package_path = fixture.workspace.root / "safe-metrics" / "final-review-package.json"
    package_path.unlink()
    with pytest.raises(FileNotFoundError):
        export_owner_quality_canary_docx(
            workspace=fixture.workspace,
            package=fixture.package,
        )
