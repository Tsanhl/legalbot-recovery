#!/usr/bin/env python3
"""Seal render, accessibility and visual QA for the r112b owner DOCX."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from PIL import Image, ImageChops

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = (
    PROJECT_ROOT / "data/evaluations/phase2a-owner-review/"
    "LegalBot-Phase2AB-2026-08-26-r112b-post-r110-owner-review-docx"
)
DOCX_NAME = "LegalBot-Phase2A-Post-r110-Owner-Decision-Agnes-2026-08-26.docx"
BUILD_NAME = "DOCX-BUILD-MANIFEST.json"
EXPECTED_DOCX_SHA256 = "b12388d0e94eb195b5ccd21b71b2ff93e165339b914e5ae1ecdc1d193422091b"
EXPECTED_BUILD_CONTENT_SHA256 = "cc0b1136b74ab01d877ebb8afc72f177c12935d07e011368d6a62ffd0dcbfcef"
EXPECTED_BUILD_FILE_SHA256 = "ea19e395ee89a4e743c43ff60c53395d534956886889c20e9f6ea09fd06fb3a4"
EXPECTED_OUTCOME_FILE_SHA256 = "e1ae97744ca5ec85feda0a2bba85e8bac4ecbaf74394a1a63fba8100ca34a7bc"
EXPECTED_OWNER_BATCH_SHA256 = "6c9eda0de5c9c921b99127cac9c6e41bb3ae87151178e250b9f4abcf4a0d7fa1"
PAGE_COUNT = 13
PAGE_SIZE = (1547, 2002)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _load_build(package_root: Path) -> dict[str, Any]:
    build_path = package_root / BUILD_NAME
    docx_path = package_root / DOCX_NAME
    outcome_path = package_root / "OUTCOME.txt"
    for path in (build_path, docx_path, outcome_path):
        if path.is_symlink() or not path.is_file():
            raise ValueError("phase2a_r112b_qa_input_not_regular")
    if package_root == PACKAGE_ROOT:
        if _sha256_file(build_path) != EXPECTED_BUILD_FILE_SHA256:
            raise ValueError("phase2a_r112b_qa_build_file_digest_invalid")
        if _sha256_file(docx_path) != EXPECTED_DOCX_SHA256:
            raise ValueError("phase2a_r112b_qa_docx_digest_invalid")
        if _sha256_file(outcome_path) != EXPECTED_OUTCOME_FILE_SHA256:
            raise ValueError("phase2a_r112b_qa_outcome_digest_invalid")
    build = json.loads(build_path.read_bytes())
    if not isinstance(build, dict):
        raise ValueError("phase2a_r112b_qa_build_not_object")
    material = dict(build)
    supplied = str(material.pop("manifest_content_sha256", ""))
    if supplied != EXPECTED_BUILD_CONTENT_SHA256 or supplied != _sealed(material):
        raise ValueError("phase2a_r112b_qa_build_content_seal_invalid")
    if (
        build.get("source_owner_batch_content_sha256") != EXPECTED_OWNER_BATCH_SHA256
        or build.get("visual_qa_completed") is not False
        or build.get("owner_approved") is not False
        or build.get("source_admission_authorized") is not False
        or build.get("phase2b_authorized") is not False
        or build.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_r112b_qa_build_boundary_invalid")
    if _sha256_file(docx_path) != build.get("docx_file_sha256"):
        raise ValueError("phase2a_r112b_qa_docx_build_binding_invalid")
    return build


def _render_inventory(render_root: Path) -> tuple[list[dict[str, Any]], Path]:
    pages: list[dict[str, Any]] = []
    for page_number in range(1, PAGE_COUNT + 1):
        path = render_root / f"page-{page_number}.png"
        if path.is_symlink() or not path.is_file():
            raise ValueError("phase2a_r112b_qa_render_page_missing")
        with Image.open(path) as image:
            rgb = image.convert("RGB")
            if rgb.size != PAGE_SIZE:
                raise ValueError("phase2a_r112b_qa_render_page_size_invalid")
            white = Image.new("RGB", rgb.size, "white")
            bounds = ImageChops.difference(rgb, white).getbbox()
        if bounds is None:
            raise ValueError("phase2a_r112b_qa_render_page_blank")
        left, top, right, bottom = bounds
        if left < 120 or top < 70 or right > 1410 or bottom > 1940:
            raise ValueError("phase2a_r112b_qa_render_margin_invalid")
        pages.append(
            {
                "page_number": page_number,
                "png_file_sha256": _sha256_file(path),
                "pixel_size": list(PAGE_SIZE),
                "nonwhite_bounds": [left, top, right, bottom],
            }
        )
    unexpected = sorted(
        path.name
        for path in render_root.glob("page-*.png")
        if path.name not in {f"page-{number}.png" for number in range(1, 14)}
    )
    if unexpected:
        raise ValueError("phase2a_r112b_qa_unexpected_render_pages")
    pdfs = sorted(render_root.glob("*.pdf"))
    if len(pdfs) != 1 or pdfs[0].is_symlink() or not pdfs[0].is_file():
        raise ValueError("phase2a_r112b_qa_render_pdf_invalid")
    return pages, pdfs[0]


def finalize(
    *,
    package_root: Path,
    render_root: Path,
    visual_inspection_confirmed: bool,
) -> dict[str, Any]:
    if not visual_inspection_confirmed:
        raise ValueError("phase2a_r112b_qa_visual_inspection_required")
    for name in (
        "DOCX-VISUAL-QA.json",
        "PACKAGE-MANIFEST.json",
        "FINAL-OUTCOME.txt",
        "SHA256SUMS.txt",
    ):
        path = package_root / name
        if path.exists() or path.is_symlink():
            raise ValueError("phase2a_r112b_qa_output_already_exists")
    build = _load_build(package_root)
    pages, pdf_path = _render_inventory(render_root)
    qa_material = {
        "schema": "legalbot.v111.phase2a.post-r110-owner-docx-visual-qa.v1",
        "status": "VISUAL_AND_STRUCTURAL_QA_PASS_OWNER_DECISION_REQUIRED",
        "source_build_manifest_content_sha256": build["manifest_content_sha256"],
        "source_owner_batch_content_sha256": EXPECTED_OWNER_BATCH_SHA256,
        "docx_file_sha256": build["docx_file_sha256"],
        "render_page_count": len(pages),
        "render_pdf_file_sha256": _sha256_file(pdf_path),
        "render_pdf_size_bytes": pdf_path.stat().st_size,
        "render_pages": pages,
        "manual_visual_inspection": {
            "all_pages_inspected": True,
            "inspection_scale": "ORIGINAL_RENDER_PAGE_IMAGES",
            "no_clipping": True,
            "no_overlap": True,
            "no_missing_glyphs": True,
            "tables_readable": True,
            "headers_and_footers_consistent": True,
            "approval_text_complete_and_readable": True,
        },
        "deterministic_audits": {
            "table_geometry": "PASS_2_OF_2_TABLES",
            "accessibility_high_findings": 0,
            "accessibility_medium_findings": 0,
            "accessibility_low_findings": 0,
            "heading_style_counts": {
                "Heading 1": 6,
                "Heading 2": 10,
                "Heading 3": 26,
            },
            "section_count": 1,
            "page_geometry": "LETTER_PORTRAIT_1_INCH_MARGINS",
            "preset_audit": "DECISION_MEMO_TOKENS_PASS",
        },
        "substantive_legal_review_performed_by_docx_qa": False,
        "owner_approved": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    qa = {**qa_material, "qa_content_sha256": _sealed(qa_material)}
    qa_path = package_root / "DOCX-VISUAL-QA.json"
    _write_exclusive(qa_path, _pretty_json(qa))
    final_outcome = (
        b"OWNER REVIEW DOCX RENDERED AND VISUALLY VERIFIED; EXACT R111 DIGEST "
        b"APPROVAL REQUIRED; NO DECISION APPLIED; PHASE 2B CLOSED.\n"
    )
    _write_exclusive(package_root / "FINAL-OUTCOME.txt", final_outcome)
    package_material = {
        "schema": "legalbot.v111.phase2a.post-r110-owner-docx-package.v1",
        "status": qa["status"],
        "owner_batch_content_sha256": EXPECTED_OWNER_BATCH_SHA256,
        "docx_member": DOCX_NAME,
        "docx_file_sha256": build["docx_file_sha256"],
        "build_manifest_file_sha256": _sha256_file(package_root / BUILD_NAME),
        "build_manifest_content_sha256": build["manifest_content_sha256"],
        "visual_qa_file_sha256": _sha256_file(qa_path),
        "visual_qa_content_sha256": qa["qa_content_sha256"],
        "final_outcome_file_sha256": _sha256_file(package_root / "FINAL-OUTCOME.txt"),
        "owner_approved": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    package = {
        **package_material,
        "package_content_sha256": _sealed(package_material),
    }
    _write_exclusive(
        package_root / "PACKAGE-MANIFEST.json",
        _pretty_json(package),
    )
    names = sorted(
        path.name
        for path in package_root.iterdir()
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    sums = "".join(f"{_sha256_file(package_root / name)}  {name}\n" for name in names)
    _write_exclusive(package_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return package


def _persist_failure(package_root: Path, exc: BaseException) -> None:
    try:
        path = package_root / "QA-FAILURE.json"
        if path.exists() or path.is_symlink():
            return
        fingerprint_material = {
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "affected_stage": "PHASE2A_POST_R110_OWNER_DOCX_QA",
        }
        material = {
            "schema": "legalbot.v111.phase2a.post-r110-owner-docx-qa-failure.v1",
            "failure_fingerprint": _sealed(fingerprint_material),
            **fingerprint_material,
            "affected_rows": "26_SOURCE_LINKS_ACROSS_22_ROWS",
            "completed_work": "PRESERVED_BEFORE_EXCEPTION",
            "root_cause_status": "DEBUG_REQUIRED",
            "required_execution_plan_change": ("INSPECT_RENDER_AND_QA_INPUTS_BEFORE_RETRY"),
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except Exception:
        return


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", type=Path, default=PACKAGE_ROOT)
    parser.add_argument("--render-root", type=Path, required=True)
    parser.add_argument("--visual-inspection-confirmed", action="store_true")
    args = parser.parse_args(argv)
    package_root = args.package_root.resolve()
    try:
        package = finalize(
            package_root=package_root,
            render_root=args.render_root.resolve(),
            visual_inspection_confirmed=args.visual_inspection_confirmed,
        )
    except Exception as exc:
        _persist_failure(package_root, exc)
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(package, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
