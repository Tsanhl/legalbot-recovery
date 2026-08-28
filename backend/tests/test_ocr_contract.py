from __future__ import annotations

import pytest

from app.ingestion.ocr import OcrMyPdfProcessor, OcrUnavailableError


def test_ocr_is_explicitly_unavailable_without_system_binaries() -> None:
    processor = OcrMyPdfProcessor(executable="")
    with pytest.raises(OcrUnavailableError):
        processor.process(b"%PDF-1.7\n")


def test_ocr_rejects_non_pdf_before_invocation() -> None:
    processor = OcrMyPdfProcessor(executable="/usr/bin/false")
    with pytest.raises(ValueError, match="OCR input is not a PDF"):
        processor.process(b"not a pdf")
