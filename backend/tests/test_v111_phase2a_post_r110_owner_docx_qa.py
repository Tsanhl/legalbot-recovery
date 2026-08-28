from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from PIL import Image, ImageDraw
from scripts import finalize_v111_phase2a_post_r110_owner_docx_qa as finalizer


def _copy_package(tmp_path: Path) -> Path:
    package = tmp_path / "package"
    package.mkdir()
    for name in (
        finalizer.DOCX_NAME,
        finalizer.BUILD_NAME,
        "OUTCOME.txt",
    ):
        shutil.copy2(finalizer.PACKAGE_ROOT / name, package / name)
    return package


def _fake_render(tmp_path: Path) -> Path:
    render = tmp_path / "render"
    render.mkdir()
    for number in range(1, finalizer.PAGE_COUNT + 1):
        image = Image.new("RGB", finalizer.PAGE_SIZE, "white")
        draw = ImageDraw.Draw(image)
        draw.rectangle((180, 92, 1364, 1910), outline="black")
        image.save(render / f"page-{number}.png")
    (render / "packet.pdf").write_bytes(b"%PDF-1.7\nsynthetic-test\n")
    return render


def test_finalizer_seals_visual_qa_and_keeps_gates_closed(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    render = _fake_render(tmp_path)
    result = finalizer.finalize(
        package_root=package,
        render_root=render,
        visual_inspection_confirmed=True,
    )

    assert result["status"] == ("VISUAL_AND_STRUCTURAL_QA_PASS_OWNER_DECISION_REQUIRED")
    assert result["owner_batch_content_sha256"] == (finalizer.EXPECTED_OWNER_BATCH_SHA256)
    assert result["owner_approved"] is False
    assert result["source_admission_authorized"] is False
    assert result["phase2b_authorized"] is False
    qa = json.loads((package / "DOCX-VISUAL-QA.json").read_bytes())
    assert qa["render_page_count"] == 13
    assert qa["manual_visual_inspection"]["all_pages_inspected"] is True
    assert qa["deterministic_audits"]["accessibility_medium_findings"] == 0


def test_finalizer_requires_visual_confirmation(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="phase2a_r112b_qa_visual_inspection_required"):
        finalizer.finalize(
            package_root=_copy_package(tmp_path),
            render_root=_fake_render(tmp_path),
            visual_inspection_confirmed=False,
        )


def test_finalizer_checksums_cover_every_package_file(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    finalizer.finalize(
        package_root=package,
        render_root=_fake_render(tmp_path),
        visual_inspection_confirmed=True,
    )

    names = set()
    for line in (package / "SHA256SUMS.txt").read_text().splitlines():
        digest, name = line.split("  ", 1)
        names.add(name)
        assert finalizer._sha256_file(package / name) == digest
    assert names == {
        path.name for path in package.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt"
    }
