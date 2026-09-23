"""Create-only synthetic uploads and byte-based DIAGNOSTIC extraction, not product ingestion.

render_uploads(specs, dest) accepts {title, pages: [str], format: PDF|PNG}.
Each input page starts a fresh page; overflow is paginated, including long tokens.
PDFs contain all physical pages. PNGs produce one manifest entry per physical page,
with document_index/document_page_number/document_page_count linking the images.
Titles are metadata, never inserted into the body (a blank page remains blank).

extract_uploads(files, directory) accepts relative paths or render manifests. It
only reads actual file bytes; extra fields, including any supplied text, are ignored.
An optional manifest sha256/format/page_count is checked before text is released.
qa_uploads(files, directory) is read-only and returns actual raster hashes and
edge checks, without extracted text. Render QA PNGs are retained in *.qa folders.
Receipts contain no source specifications, absolute input paths or exception text.

Native PDF extraction has confidence=None: extraction is not a correctness score.
PNG OCR uses Tesseract if available, otherwise Apple Vision on macOS; confidence
is the engine's character-weighted recognition score, not factual assurance.
Image-only PDFs are flagged OCR_REQUIRED, never represented as extracted text.
Page numbers are one-based. page_sha256 hashes the actual rendered PNG bytes;
page_provenance_sha256 additionally binds the raw file hash and page number.
text_sha256 hashes the exact returned UTF-8 text, without Unicode normalization.

No files are overwritten or deleted, including after errors. A retry must use a
fresh destination. No bank enumeration, training, model invocation or admission.
Dependencies: reportlab/Pillow; PyMuPDF OR pypdf+pdftoppm; optional Tesseract.
GE_FIXTURE_FONT, GE_FIXTURE_PDFTOPPM, GE_FIXTURE_TESSERACT select explicit tools.
The existing LEGALBOT_OCR_TOOL_DIR convention is also respected.
"""

from __future__ import annotations

import csv
import ctypes
import hashlib
import importlib
import io
import json
import math
import os
import platform
import shutil
import stat
import subprocess
import sys
import unicodedata
from functools import lru_cache
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFont

_ROOT = Path(__file__).resolve().parents[1]
_BUNDLE = Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies"
_PAGE = (595, 842)
_MARGIN = 48
_FONT_SIZE = 11
_LEADING = 17
_PNG_SCALE = 2
_MAX_BYTES = 64 * 1024 * 1024
_MAX_PAGES = 128
_MAX_PIXELS = 40_000_000
_TIMEOUT = 60
_SCHEMA = "legalbot.diagnostic-upload.v1"


class FixtureError(ValueError):
    """A stable code with no source text. Existing artifacts must be preserved."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_sha(value: dict) -> str:
    return _sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(data)


@lru_cache(maxsize=8)
def _font_at(path: str) -> tuple[str, str]:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    raw = Path(path).read_bytes()
    digest = _sha(raw)
    name = "GEFixture_" + digest[:20]
    if name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(name, io.BytesIO(raw)))
    return name, digest


def _select_font(text: str) -> tuple[Path, str, str]:
    from reportlab.pdfbase import pdfmetrics
    explicit = os.environ.get("GE_FIXTURE_FONT")
    candidates = [Path(explicit)] if explicit else [
        _BUNDLE / "native/poppler/poppler/fonts/DejaVuSans.ttf",
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/System/Library/Fonts/Supplemental/Arial Unicode.ttf"),
    ]
    required = {ord(c) for c in text if c != "\n"}
    for path in candidates:
        if not path.is_file():
            continue
        name, digest = _font_at(str(path))
        glyphs = pdfmetrics.getFont(name).face.charToGlyph
        if all(glyphs.get(code, 0) for code in required):
            return path, name, digest
    raise FixtureError("UNSUPPORTED_UNICODE_OR_FONT_UNAVAILABLE")


def _body(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n").expandtabs(4)
    if any(unicodedata.category(c) in {"Cc", "Cs", "Cf"} for c in text if c != "\n"):
        raise FixtureError("UNSUPPORTED_CONTROL_CHARACTER")
    # ReportLab's plain text path does not provide bidirectional/complex shaping.
    if any(unicodedata.bidirectional(c) in {"R", "AL", "AN"} for c in text):
        raise FixtureError("UNSUPPORTED_BIDIRECTIONAL_LAYOUT")
    return text


def _wrap(text: str, width) -> list[str]:
    """Wrap by measured glyph widths, preserving explicit blank lines."""
    lines = []
    for paragraph in text.split("\n"):
        if not paragraph:
            lines.append("")
            continue
        while paragraph:
            lo, hi = 0, len(paragraph)
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if width(paragraph[:mid]) <= _PAGE[0] - 2 * _MARGIN:
                    lo = mid
                else:
                    hi = mid - 1
            if not lo:
                raise FixtureError("GLYPH_EXCEEDS_LINE_WIDTH")
            end = lo
            if lo < len(paragraph):
                space = paragraph.rfind(" ", 0, lo + 1)
                if space > 0:
                    end = space + 1
                # Do not start a continuation with an orphan combining mark.
                while 0 < end < len(paragraph) and unicodedata.combining(paragraph[end]):
                    end -= 1
                if end == 0:
                    raise FixtureError("GRAPHEME_EXCEEDS_LINE_WIDTH")
            lines.append(paragraph[:end].rstrip(" "))
            paragraph = paragraph[end:]
    return lines


def _layout(spec: dict) -> dict:
    from reportlab.pdfbase import pdfmetrics
    if not isinstance(spec, dict) or spec.get("format") not in {"PDF", "PNG"}:
        raise FixtureError("INVALID_SPEC_FORMAT")
    if not isinstance(spec.get("title"), str):
        raise FixtureError("INVALID_SPEC_TITLE")
    pages = spec.get("pages")
    if not isinstance(pages, list) or not pages or not all(isinstance(p, str) for p in pages):
        raise FixtureError("INVALID_SPEC_PAGES")
    bodies = [_body(p) for p in pages]
    font_path, font_name, font_hash = _select_font("\n".join(bodies))
    pil_font = ImageFont.truetype(str(font_path), _FONT_SIZE * _PNG_SCALE)

    def width(line):
        return max(
            pdfmetrics.stringWidth(line, font_name, _FONT_SIZE),
            pil_font.getlength(line) / _PNG_SCALE,
        )

    capacity = int((_PAGE[1] - 2 * _MARGIN - _FONT_SIZE) // _LEADING)
    physical = []
    for number, body in enumerate(bodies, 1):
        lines = _wrap(body, width)
        for offset in range(0, len(lines), capacity):
            physical.append({"source_page_number": number, "lines": lines[offset:offset + capacity]})
    if len(physical) > _MAX_PAGES:
        raise FixtureError("PAGE_LIMIT_EXCEEDED")
    return {"title": spec["title"], "format": spec["format"], "pages": physical,
            "font_path": font_path, "font_name": font_name, "font_sha256": font_hash}


def _render_pdf(plan: dict) -> bytes:
    from reportlab.pdfgen import canvas
    buffer = io.BytesIO()
    doc = canvas.Canvas(buffer, pagesize=_PAGE, pageCompression=1, invariant=1)
    doc.setTitle(plan["title"])
    doc.setAuthor("Synthetic diagnostic fixture")
    for page in plan["pages"]:
        doc.setFont(plan["font_name"], _FONT_SIZE)
        doc.setFillColorRGB(0, 0, 0)
        for i, line in enumerate(page["lines"]):
            doc.drawString(_MARGIN, _PAGE[1] - _MARGIN - _FONT_SIZE - i * _LEADING, line)
        doc.showPage()
    doc.save()
    return buffer.getvalue()


def _png_bytes(image: Image.Image) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _render_png(plan: dict, page: dict) -> bytes:
    image = Image.new("RGB", tuple(n * _PNG_SCALE for n in _PAGE), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype(str(plan["font_path"]), _FONT_SIZE * _PNG_SCALE)
    for i, line in enumerate(page["lines"]):
        xy = (_MARGIN * _PNG_SCALE, (_MARGIN + _FONT_SIZE + i * _LEADING) * _PNG_SCALE)
        box = draw.textbbox(xy, line, font=font, anchor="ls")
        if box[0] < 0 or box[1] < 0 or box[2] >= image.width or box[3] >= image.height:
            raise FixtureError("LAYOUT_CLIPPING")
        draw.text(xy, line, fill="black", font=font, anchor="ls")
    return _png_bytes(image)


def _tool(name: str) -> str | None:
    explicit = os.environ.get("GE_FIXTURE_" + name.upper())
    if explicit:
        candidates = [Path(explicit)]
    elif name == "pdftoppm":
        candidates = [_BUNDLE / "bin/override/pdftoppm"]
    else:
        configured = os.environ.get("LEGALBOT_OCR_TOOL_DIR")
        prefix = Path(configured) if configured else _ROOT / "tools/ocr"
        candidates = [(prefix if prefix.name == "bin" else prefix / "bin") / name]
    if not explicit and (found := shutil.which(name)):
        candidates.append(Path(found))
    return next((str(p) for p in candidates if p.is_file() and os.access(p, os.X_OK)), None)


def _run(args: list[str], data: bytes) -> bytes:
    try:
        result = subprocess.run(args, input=data, capture_output=True,
                                timeout=_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        raise FixtureError("TOOL_TIMEOUT") from None
    except OSError:
        raise FixtureError("TOOL_UNAVAILABLE") from None
    if result.returncode:
        raise FixtureError("TOOL_FAILED")
    return result.stdout


def _image(raw: bytes) -> Image.Image:
    with Image.open(io.BytesIO(raw)) as image:
        if image.format != "PNG" or getattr(image, "n_frames", 1) != 1:
            raise FixtureError("UNSUPPORTED_IMAGE_FORMAT_OR_MULTIFRAME")
        if image.width * image.height > _MAX_PIXELS:
            raise FixtureError("PIXEL_LIMIT_EXCEEDED")
        image.load()
        rgba = image.convert("RGBA")
        white = Image.new("RGBA", image.size, "white")
        return Image.alpha_composite(white, rgba).convert("RGB")


def _raster_qa(raw: bytes) -> dict:
    image = _image(raw)
    ink = ImageChops.invert(image.convert("L")).point(lambda n: 255 if n >= 16 else 0)
    box = ink.getbbox()
    touches = bool(box and (box[0] < 3 or box[1] < 3 or box[2] > image.width - 3
                           or box[3] > image.height - 3))
    return {"width": image.width, "height": image.height, "ink_bbox_pixels": box,
            "blank": box is None, "clipping_suspected": touches,
            "clipping_check": "ink_within_3_pixels_of_page_edge; not_a_completeness_proof"}


def _pdf_pages(raw: bytes):
    try:
        fitz = importlib.import_module("fitz")
    except ImportError:
        fitz = None
    if fitz is not None:
        with fitz.open(stream=raw, filetype="pdf") as doc:
            if doc.needs_pass:
                raise FixtureError("ENCRYPTED_PDF")
            if doc.is_repaired:
                raise FixtureError("CORRUPT_PDF_REQUIRES_REPAIR")
            if not 0 < len(doc) <= _MAX_PAGES:
                raise FixtureError("INVALID_PAGE_COUNT")
            for page in doc:
                number = page.number + 1
                try:
                    if page.rect.width * page.rect.height * 4 > _MAX_PIXELS:
                        raise FixtureError("PIXEL_LIMIT_EXCEEDED")
                    raster = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False).tobytes("png")
                    yield number, page.get_text("text", sort=True), raster, "pymupdf", str(fitz.VersionBind), None
                except Exception as exc:
                    yield number, "", None, "pymupdf", str(fitz.VersionBind), _error(exc, "PDF_PAGE_UNREADABLE")
    else:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(raw), strict=True)
        if reader.is_encrypted:
            raise FixtureError("ENCRYPTED_PDF")
        if not 0 < len(reader.pages) <= _MAX_PAGES:
            raise FixtureError("INVALID_PAGE_COUNT")
        executable = _tool("pdftoppm")
        if not executable:
            raise FixtureError("PDF_RENDERER_UNAVAILABLE")
        for number, page in enumerate(reader.pages, 1):
            try:
                box = page.mediabox
                if float(box.width) * float(box.height) * 4 > _MAX_PIXELS:
                    raise FixtureError("PIXEL_LIMIT_EXCEEDED")
                raster = _run([executable, "-q", "-png", "-r", "144", "-cropbox", "-singlefile",
                               "-f", str(number), "-l", str(number), "-"], raw)
                yield number, page.extract_text() or "", raster, "pypdf+pdftoppm", pypdf.__version__, None
            except Exception as exc:
                yield number, "", None, "pypdf+pdftoppm", pypdf.__version__, _error(exc, "PDF_PAGE_UNREADABLE")


def _tesseract(raw: bytes, executable: str) -> tuple[str, float, dict]:
    data = _run([executable, "stdin", "stdout", "-l", "eng", "--psm", "6", "tsv"], raw)
    rows = csv.DictReader(io.StringIO(data.decode("utf-8")), delimiter="\t")
    lines: dict[tuple, list[str]] = {}
    scores = []
    for row in rows:
        word = row.get("text", "").strip()
        if not word or row.get("level") != "5":
            continue
        confidence = float(row["conf"])
        if not math.isfinite(confidence) or not 0 <= confidence <= 100:
            raise FixtureError("INVALID_OCR_CONFIDENCE")
        key = tuple(row[k] for k in ("page_num", "block_num", "par_num", "line_num"))
        lines.setdefault(key, []).append(word)
        scores.append((len(word), confidence / 100))
    total = sum(n for n, _ in scores)
    return "\n".join(" ".join(words) for words in lines.values()), (
        sum(n * c for n, c in scores) / total if total else 0.0
    ), {"engine": "tesseract", "language": "eng", "page_segmentation_mode": 6}


def _vision(raw: bytes) -> tuple[str, float, dict]:
    """Apple's native framework via its C ABI; no PyObjC or temporary files.

    https://developer.apple.com/documentation/vision/vnrecognizetextrequest
    Only pointer/integer/scalar selectors are used (no struct-return ABI).
    """
    objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
    ctypes.CDLL("/System/Library/Frameworks/Foundation.framework/Foundation")
    ctypes.CDLL("/System/Library/Frameworks/Vision.framework/Vision")
    ptr, ulong = ctypes.c_void_p, ctypes.c_ulong
    objc.objc_getClass.argtypes, objc.objc_getClass.restype = [ctypes.c_char_p], ptr
    objc.sel_registerName.argtypes, objc.sel_registerName.restype = [ctypes.c_char_p], ptr

    def cls(name):
        value = objc.objc_getClass(name.encode())
        if not value:
            raise FixtureError("VISION_UNAVAILABLE")
        return value

    def msg(obj, name, result=ptr, types=(), args=()):
        call = ctypes.CFUNCTYPE(result, ptr, ptr, *types)(("objc_msgSend", objc))
        return call(obj, objc.sel_registerName(name.encode()), *args)

    pool = msg(msg(cls("NSAutoreleasePool"), "alloc"), "init")
    request = handler = None
    try:
        buffer = ctypes.create_string_buffer(raw)
        data = msg(cls("NSData"), "dataWithBytes:length:", types=(ptr, ulong), args=(buffer, len(raw)))
        options = msg(cls("NSDictionary"), "dictionary")
        handler = msg(msg(cls("VNImageRequestHandler"), "alloc"), "initWithData:options:",
                      types=(ptr, ptr), args=(data, options))
        request = msg(msg(cls("VNRecognizeTextRequest"), "alloc"), "init")
        if not handler or not request:
            raise FixtureError("VISION_INITIALIZATION_FAILED")
        msg(request, "setRecognitionLevel:", None, (ctypes.c_long,), (0,))  # accurate
        msg(request, "setUsesLanguageCorrection:", None, (ctypes.c_bool,), (False,))
        language = msg(cls("NSString"), "stringWithUTF8String:", types=(ctypes.c_char_p,), args=(b"en-GB",))
        languages = msg(cls("NSArray"), "arrayWithObject:", types=(ptr,), args=(language,))
        msg(request, "setRecognitionLanguages:", None, (ptr,), (languages,))
        requests = msg(cls("NSArray"), "arrayWithObject:", types=(ptr,), args=(request,))
        error = ptr()
        ok = msg(handler, "performRequests:error:", ctypes.c_bool, (ptr, ctypes.POINTER(ptr)),
                 (requests, ctypes.byref(error)))
        if not ok or error.value:
            raise FixtureError("VISION_OCR_FAILED")
        observations = msg(request, "results")
        words, scores = [], []
        for i in range(msg(observations, "count", ulong)):
            observation = msg(observations, "objectAtIndex:", types=(ulong,), args=(i,))
            candidates = msg(observation, "topCandidates:", types=(ulong,), args=(1,))
            if not msg(candidates, "count", ulong):
                continue
            candidate = msg(candidates, "objectAtIndex:", types=(ulong,), args=(0,))
            string = msg(candidate, "string")
            text = (msg(string, "UTF8String", ctypes.c_char_p) or b"").decode("utf-8")
            confidence = float(msg(candidate, "confidence", ctypes.c_float))
            if not math.isfinite(confidence) or not 0 <= confidence <= 1:
                raise FixtureError("INVALID_OCR_CONFIDENCE")
            if text.strip():
                words.append(text)
                scores.append((len(text), confidence))
        total = sum(n for n, _ in scores)
        return "\n".join(words), sum(n * c for n, c in scores) / total if total else 0.0, {
            "engine": "apple_vision", "os_version": platform.mac_ver()[0],
            "request_revision": msg(request, "revision", ulong),
            "language": "en-GB", "language_correction": False,
        }
    finally:
        if request:
            msg(request, "release", None)
        if handler:
            msg(handler, "release", None)
        msg(pool, "drain", None)


def _ocr(raw: bytes) -> tuple[str, float, dict]:
    if executable := _tool("tesseract"):
        return _tesseract(raw, executable)
    if os.environ.get("GE_FIXTURE_TESSERACT"):
        raise FixtureError("REQUESTED_OCR_TOOL_UNAVAILABLE")
    if sys.platform == "darwin":
        return _vision(raw)
    raise FixtureError("OCR_UNAVAILABLE")


def _error(exc: Exception, default: str) -> str:
    return str(exc) if isinstance(exc, FixtureError) else default


def _read_file(item, directory: Path) -> tuple[str, bytes, dict]:
    metadata = item if isinstance(item, dict) else {}
    name = metadata.get("relative_path", metadata.get("path")) if metadata else item
    if not isinstance(name, str | Path):
        raise FixtureError("INVALID_RELATIVE_PATH")
    path = Path(name)
    if path.is_absolute() or not path.parts or any(p in {"..", "."} for p in path.parts):
        raise FixtureError("INVALID_RELATIVE_PATH")
    # Open every component without following symlinks, including intermediate dirs.
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_BYTES:
                raise FixtureError("INVALID_FILE_OR_SIZE_LIMIT")
            raw = stream.read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            raise FixtureError("FILE_SIZE_LIMIT_EXCEEDED")
        return path.as_posix(), raw, metadata
    finally:
        os.close(descriptor)


def _page_receipt(file_hash: str, number: int, raster: bytes | None, text: str,
                  method: str, confidence, error: str | None, engine: dict) -> dict:
    page_hash = _sha(raster) if raster is not None else None
    binding = {"file_sha256": file_hash, "page_number": number, "page_sha256": page_hash}
    qa = _raster_qa(raster) if raster is not None else None
    if error is None and qa:
        if qa["blank"]:
            error = "BLANK_PAGE"
        elif qa["clipping_suspected"]:
            error = "CLIPPING_SUSPECTED"
        elif not text.strip():
            error = "NO_EXTRACTABLE_TEXT_OCR_REQUIRED" if method.startswith(("pypdf", "pymupdf")) else "NO_TEXT_RECOGNIZED"
        elif "\ufffd" in text or "\x00" in text:
            error = "UNRELIABLE_TEXT_ENCODING"
    return {**binding, "page_provenance_sha256": _json_sha(binding),
            "text": text, "text_sha256": _sha(text.encode("utf-8")),
            "extraction_method": method, "confidence": confidence,
            "confidence_basis": "engine_recognition_score" if method in {"apple_vision", "tesseract"}
            else "native_text_has_no_probability" if method.startswith(("pypdf", "pymupdf")) else "not_scored",
            "engine": engine, "qa": qa, "error": error}


def _inspect(item, directory: Path, *, extract: bool) -> tuple[dict, list[bytes | None]]:
    receipt = {"schema": _SCHEMA, "file_sha256": None, "path": None, "pages": [], "error": None}
    rasters = []
    try:
        name, raw, metadata = _read_file(item, directory)
        digest = _sha(raw)
        receipt.update(file_sha256=digest, path=name)
        if metadata.get("sha256") is not None and metadata["sha256"] != digest:
            raise FixtureError("FILE_HASH_MISMATCH")
        fmt = "PNG" if raw.startswith(b"\x89PNG\r\n\x1a\n") else "PDF" if raw.startswith(b"%PDF-") else None
        if fmt is None:
            raise FixtureError("UNSUPPORTED_OR_CORRUPT_FILE")
        receipt["format"] = fmt
        if metadata.get("format") is not None and metadata["format"] != fmt:
            raise FixtureError("FILE_FORMAT_MISMATCH")
        if fmt == "PDF":
            for number, text, raster, method, version, error in _pdf_pages(raw):
                receipt["pages"].append(_page_receipt(digest, number, raster, text, method, None, error,
                                                     {"engine": method, "version": version}))
                rasters.append(raster)
        else:
            # Fully decode before OCR. Pass these same raw bytes to the real engine.
            qa = _raster_qa(raw)
            text, confidence, engine, error = "", None, {"engine": "none"}, None
            if extract and not qa["blank"]:
                try:
                    text, confidence, engine = _ocr(raw)
                except Exception as exc:
                    error = _error(exc, "OCR_FAILED")
            page = _page_receipt(digest, 1, raw, text, engine["engine"], confidence, error, engine)
            if not extract and page["error"] == "NO_TEXT_RECOGNIZED":
                page["error"] = None
            receipt["pages"].append(page)
            rasters.append(raw)
        receipt["page_count"] = len(receipt["pages"])
        if metadata.get("page_count") is not None and metadata["page_count"] != receipt["page_count"]:
            # Do not release text against the wrong declared document shape.
            receipt["pages"] = []
            raise FixtureError("FILE_PAGE_COUNT_MISMATCH")
        errors = sorted({p["error"] for p in receipt["pages"] if p["error"]})
        receipt["error"] = ";".join(errors) or None
    except Exception as exc:
        receipt["error"] = _error(exc, "FILE_UNREADABLE")
    return receipt, rasters


def extract_uploads(files: list, directory: Path) -> list[dict]:
    """Return actual-byte extraction receipts only; never consult fixture specs."""
    if not isinstance(files, list):
        raise TypeError("files must be a list")
    return [_inspect(item, Path(directory), extract=True)[0] for item in files]


def _qa_only(receipt: dict) -> dict:
    result = dict(receipt)
    result["pages"] = [{k: v for k, v in page.items()
                        if k not in {"text", "text_sha256", "confidence", "confidence_basis"}}
                       for page in receipt["pages"]]
    return result


def qa_uploads(files: list, directory: Path) -> list[dict]:
    """Read-only actual-byte raster QA/provenance; contains no extracted body text."""
    if not isinstance(files, list):
        raise TypeError("files must be a list")
    return [_qa_only(_inspect(item, Path(directory), extract=False)[0]) for item in files]


def render_uploads(specs: list, dest: Path) -> list[dict]:
    """Write new files/QA PNGs and return manifests; collisions never overwrite."""
    if not isinstance(specs, list):
        raise TypeError("specs must be a list")
    plans = [_layout(spec) for spec in specs]
    if not plans:
        return []
    dest = Path(dest)
    if any(p.is_symlink() for p in (dest, *dest.parents)):
        raise FixtureError("SYMLINK_DESTINATION_REFUSED")
    jobs = []
    for index, plan in enumerate(plans, 1):
        if plan["format"] == "PDF":
            jobs.append((f"upload-{index:04d}.pdf", plan, plan["pages"], index, None))
        else:
            for number, page in enumerate(plan["pages"], 1):
                jobs.append((f"upload-{index:04d}-page-{number:04d}.png", plan, [page], index, number))
    for name, *_ in jobs:
        for path in (dest / name, dest / (name + ".qa")):
            if os.path.lexists(path):
                raise FileExistsError("CREATE_ONLY_DESTINATION_COLLISION")
    dest.mkdir(parents=True, exist_ok=True)
    manifests = []
    for name, plan, pages, index, number in jobs:
        # Reserve the sidecar before the file; partial results survive failures.
        qa_dir = dest / (name + ".qa")
        qa_dir.mkdir()
        raw = _render_pdf(plan) if plan["format"] == "PDF" else _render_png(plan, pages[0])
        _write_new(dest / name, raw)
        manifest = {"relative_path": name, "sha256": _sha(raw), "format": plan["format"],
                    "page_count": len(pages), "title": plan["title"], "document_index": index,
                    "document_page_number": number, "document_page_count": len(plan["pages"]),
                    "renderer": "reportlab" if plan["format"] == "PDF" else "pillow",
                    "font_sha256": plan["font_sha256"], "diagnostic_only": True}
        receipt, rasters = _inspect(manifest, dest, extract=False)
        for offset, (page, raster) in enumerate(zip(receipt["pages"], rasters, strict=True)):
            if offset >= len(pages):
                raise FixtureError("RENDER_PAGE_COUNT_MISMATCH")
            original = pages[offset]
            if raster is not None:
                qa_path = qa_dir / f"page-{page['page_number']:04d}.png"
                _write_new(qa_path, raster)
                page["render_relative_path"] = qa_path.relative_to(dest).as_posix()
            page["source_page_number"] = original["source_page_number"]
            if plan["format"] == "PDF":
                observed = "".join(page["text"].split())
                expected = "".join("".join(original["lines"]).split())
                page["text_roundtrip_matches_layout"] = observed == expected
                if observed != expected:
                    page["error"] = "RENDER_TEXT_ROUNDTRIP_MISMATCH"
        errors = {p["error"] for p in receipt["pages"] if p["error"]}
        if receipt["error"]:
            errors.update(receipt["error"].split(";"))
        receipt["error"] = ";".join(sorted(errors)) or None
        manifest["qa"] = _qa_only(receipt)
        # Save a text-free QA receipt even when a rendering check fails.
        _write_new(qa_dir / "receipt.json", json.dumps(manifest["qa"], ensure_ascii=True,
                                                      indent=2).encode("utf-8") + b"\n")
        errors.discard("BLANK_PAGE")
        if errors:
            raise FixtureError("RENDER_QA_FAILED:" + ";".join(sorted(errors)))
        manifests.append(manifest)
    return manifests
