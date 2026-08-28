from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from app.ingestion.ocr import OcrMyPdfProcessor, OcrUnavailableError

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _make_toolchain(prefix: Path) -> Path:
    bin_dir = prefix / "bin"
    bin_dir.mkdir(parents=True)
    for name in ("ocrmypdf", "tesseract", "gs", "qpdf"):
        executable = bin_dir / name
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)
    return bin_dir


def test_discovers_only_complete_project_local_toolchain(tmp_path: Path) -> None:
    bin_dir = _make_toolchain(tmp_path / "tools" / "ocr")

    processor = OcrMyPdfProcessor(project_root=tmp_path)

    assert processor.ready
    assert processor.executable == str(bin_dir / "ocrmypdf")
    assert processor.tesseract == str(bin_dir / "tesseract")
    assert processor.ghostscript == str(bin_dir / "gs")
    assert processor.qpdf == str(bin_dir / "qpdf")


def test_explicit_environment_prefix_takes_priority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    explicit_bin = _make_toolchain(tmp_path / "approved-ocr")
    _make_toolchain(tmp_path / "project" / "tools" / "ocr")
    monkeypatch.setenv("LEGALBOT_OCR_TOOL_DIR", str(explicit_bin.parent))

    processor = OcrMyPdfProcessor(project_root=tmp_path / "project")

    assert processor.ready
    assert processor.tool_bin == explicit_bin


def test_incomplete_local_toolchain_fails_closed(tmp_path: Path) -> None:
    bin_dir = tmp_path / "tools" / "ocr" / "bin"
    bin_dir.mkdir(parents=True)
    executable = bin_dir / "ocrmypdf"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)

    processor = OcrMyPdfProcessor(project_root=tmp_path)

    assert not processor.ready
    with pytest.raises(OcrUnavailableError, match="project-local"):
        processor.process(b"%PDF-1.7\n")


def test_process_uses_controlled_environment_and_private_temp_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = _make_toolchain(tmp_path / "tools" / "ocr")
    processor = OcrMyPdfProcessor(project_root=tmp_path, timeout_seconds=37)
    observed: dict[str, Any] = {}
    monkeypatch.setenv("PATH", "/private/ambient/should-not-leak")
    monkeypatch.setenv("HOME", "/private/owner-name")

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        observed["command"] = command
        observed.update(kwargs)
        Path(command[-1]).write_bytes(b"%PDF-1.7\nOCR")
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr("app.ingestion.ocr.subprocess.run", fake_run)

    result = processor.process(b"%PDF-1.7\nsource")

    assert result.pdf_bytes.endswith(b"OCR")
    assert observed["timeout"] == 37
    assert observed["stdin"] == subprocess.DEVNULL
    assert observed["cwd"] == Path(str(observed["env"]["TMPDIR"]))
    assert observed["env"]["PATH"] == f"{bin_dir}:/usr/bin:/bin"
    assert "HOME" not in observed["env"]
    assert "/private/ambient" not in observed["env"]["PATH"]
    assert "/private/owner-name" not in json.dumps(observed, default=str)
    assert [Path(value).name for value in observed["command"][-2:]] == [
        "source.pdf",
        "ocr.pdf",
    ]


def test_setup_script_defaults_to_non_mutating_dry_run() -> None:
    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "setup_ocr_toolchain.py")],
        capture_output=True,
        check=False,
        cwd=PROJECT_ROOT,
        env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0
    plan = json.loads(result.stdout)
    assert plan["mode"] == "dry-run"
    assert plan["mutates_system"] is False
    assert plan["prefix"] == "tools/ocr"
    assert plan["resolver_version"] == "2.8.1"
    assert plan["resolver_sha256"] == (
        "de71a646b73af92dd663e6ddc78993a6a4d47ea28b5d8908c3cc2b9c3077e528"
    )
    assert plan["packages"] == [
        "python=3.13",
        "tesseract=5.5.3",
        "ghostscript=10.07.1",
        "qpdf=12.3.2",
        "pip",
    ]
    assert plan["python_packages"] == ["ocrmypdf==17.8.1"]
