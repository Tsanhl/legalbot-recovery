from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


class OcrUnavailableError(RuntimeError):
    pass


class OcrFailedError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class OcrResult:
    pdf_bytes: bytes
    engine: str
    deskewed: bool


class OcrMyPdfProcessor:
    """Project-local OCR adapter; private filenames never enter diagnostics or logs."""

    def __init__(
        self,
        executable: str | None = None,
        *,
        tool_dir: str | Path | None = None,
        project_root: str | Path | None = None,
        timeout_seconds: int = 900,
    ) -> None:
        if not 1 <= timeout_seconds <= 3_600:
            raise ValueError("OCR timeout must be between 1 and 3600 seconds")

        self.timeout_seconds = timeout_seconds
        root = Path(project_root or Path(__file__).parents[3]).expanduser().resolve()
        env_tool_dir = os.environ.get("LEGALBOT_OCR_TOOL_DIR")

        # An explicit empty executable remains a supported fail-closed switch.
        if executable is not None:
            executable_path = Path(executable).expanduser().resolve() if executable else None
            bin_dir = executable_path.parent if executable_path else None
            confined_prefix: Path | None = None
        else:
            selected = tool_dir or env_tool_dir
            if selected:
                selected_path = Path(selected).expanduser().resolve()
                bin_dir = selected_path if selected_path.name == "bin" else selected_path / "bin"
                confined_prefix = None  # An operator explicitly selected this toolchain.
            else:
                confined_prefix = (root / "tools" / "ocr").resolve()
                bin_dir = confined_prefix / "bin"
            executable_path = bin_dir / "ocrmypdf" if bin_dir else None

        if confined_prefix is not None and bin_dir is not None:
            try:
                bin_dir.resolve().relative_to(confined_prefix)
            except ValueError:
                # A project-local symlink must not silently escape into a system install.
                bin_dir = None
                executable_path = None

        self.tool_bin = bin_dir
        self.executable = str(executable_path) if executable_path else None
        self.tesseract = str(bin_dir / "tesseract") if bin_dir else None
        self.ghostscript = str(bin_dir / "gs") if bin_dir else None
        self.qpdf = str(bin_dir / "qpdf") if bin_dir else None

    @property
    def ready(self) -> bool:
        return all(
            _is_executable_file(candidate)
            for candidate in (self.executable, self.tesseract, self.ghostscript, self.qpdf)
        )

    def process(self, pdf_bytes: bytes) -> OcrResult:
        if not pdf_bytes.startswith(b"%PDF-"):
            raise ValueError("OCR input is not a PDF")
        if not self.ready or not self.executable or self.tool_bin is None:
            raise OcrUnavailableError(
                "The project-local OCRmyPDF, Tesseract, Ghostscript and QPDF toolchain is required"
            )
        with tempfile.TemporaryDirectory(prefix="legalbot-ocr-") as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "ocr.pdf"
            cache = root / "cache"
            config = root / "config"
            cache.mkdir(mode=0o700)
            config.mkdir(mode=0o700)
            source.write_bytes(pdf_bytes)
            controlled_env = {
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": f"{self.tool_bin}:/usr/bin:/bin",
                "PYTHONNOUSERSITE": "1",
                "TMPDIR": str(root),
                "XDG_CACHE_HOME": str(cache),
                "XDG_CONFIG_HOME": str(config),
            }
            try:
                result = subprocess.run(
                    [
                        self.executable,
                        "--deskew",
                        "--skip-text",
                        "--output-type",
                        "pdf",
                        "--",
                        str(source),
                        str(output),
                    ],
                    capture_output=True,
                    check=False,
                    cwd=root,
                    env=controlled_env,
                    stdin=subprocess.DEVNULL,
                    timeout=self.timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise OcrFailedError("OCR timed out before producing a derivative") from exc
            if result.returncode != 0 or not output.is_file():
                raise OcrFailedError(f"OCR failed with exit code {result.returncode}")
            value = output.read_bytes()
            if not value.startswith(b"%PDF-"):
                raise OcrFailedError("OCR output did not pass PDF validation")
            return OcrResult(
                pdf_bytes=value,
                engine="ocrmypdf+tesseract+ghostscript(project-local)",
                deskewed=True,
            )


def _is_executable_file(candidate: str | None) -> bool:
    if not candidate:
        return False
    path = Path(candidate)
    return path.is_file() and os.access(path, os.X_OK)
