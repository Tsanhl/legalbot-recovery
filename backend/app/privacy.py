from __future__ import annotations

import fnmatch
import hashlib
import re
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any

EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{6,}\d)(?!\w)")
YEAR_RANGE_RE = re.compile(r"\b(?:1\d{3}|20\d{2})\s*[-–—]\s*(?:1\d{3}|20\d{2})\b")
# Allow spaces inside macOS path components and consume the complete path up
# to a structural delimiter. The earlier whitespace-delimited expression left
# filename tails behind for paths such as ``.../My Folder/private file.pdf``.
MAC_PATH_RE = re.compile(r"/Users/[^/\r\n]+(?:/[^\r\n\]\[)>,;:'\"]+)+")
WINDOWS_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\(?:[^\s\\]+\\)*[^\s\\]+")
INJECTION_PATTERNS = (
    re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions"),
    re.compile(r"(?i)(?:reveal|print|show)\s+(?:the\s+)?(?:system|developer)\s+prompt"),
    re.compile(r"(?i)you\s+are\s+now\s+(?:a|an)\b"),
    re.compile(r"(?i)<\s*/?\s*(?:system|assistant|developer)\s*>"),
)


def _scrub_phone_candidates(value: str) -> str:
    """Redact plausible phones without corrupting legal citation numbers.

    Legal source text frequently contains year ranges and parenthesised law
    report coordinates such as ``1765-1769`` or ``(2001) 117 LQR 412``.  The
    earlier broad expression treated those coordinates as telephone numbers,
    altering exact evidence bytes in derived indexes.  Keep eight-digit local
    numbers supported, but require a phone-shaped grouping and reject clear
    year ranges and decimal/report-coordinate shapes.
    """

    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        digits = re.sub(r"\D", "", candidate)
        stripped = candidate.strip()
        if len(digits) < 8 or len(digits) > 15:
            return candidate
        if YEAR_RANGE_RE.search(candidate):
            return candidate
        if len(digits) == 8:
            if "." in candidate:
                return candidate
            compact = re.sub(r"\s", "", stripped)
            four_four = re.fullmatch(r"\d{4}[\s-]\d{4}", stripped)
            if not (compact.isdigit() or four_four):
                return candidate
        return "[PHONE]"

    return PHONE_RE.sub(replace, value)


def scrub_pii(value: str, owner_identifiers: Sequence[str] = ()) -> str:
    """Remove common owner identifiers before values enter logs or review queues."""
    value = MAC_PATH_RE.sub("[LOCAL_PATH]", value)
    value = WINDOWS_PATH_RE.sub("[LOCAL_PATH]", value)
    value = EMAIL_RE.sub("[EMAIL]", value)
    value = _scrub_phone_candidates(value)
    for identifier in sorted(
        {item.strip() for item in owner_identifiers if len(item.strip()) >= 3},
        key=len,
        reverse=True,
    ):
        value = re.sub(re.escape(identifier), "[OWNER_IDENTIFIER]", value, flags=re.IGNORECASE)
    return value


def scrub_prompt_data(value: Any, owner_identifiers: Sequence[str] = ()) -> Any:
    """Recursively remove local identifiers from a JSON-compatible model payload."""

    if isinstance(value, str):
        return scrub_pii(value, owner_identifiers)
    if isinstance(value, Mapping):
        return {
            str(scrub_pii(str(key), owner_identifiers)): scrub_prompt_data(item, owner_identifiers)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [scrub_prompt_data(item, owner_identifiers) for item in value]
    return value


def safe_summary(value: str, limit: int = 180) -> str:
    cleaned = " ".join(scrub_pii(value).split())
    return cleaned if len(cleaned) <= limit else f"{cleaned[: limit - 1]}…"


def safe_source_name(path: Path, content_sha256: str) -> str:
    """Create a non-identifying label; source paths remain encrypted catalogue aliases."""
    suffix = path.suffix.lower() or ".bin"
    return f"source-{content_sha256[:12]}{suffix}"


def path_fingerprint(path: Path) -> str:
    return hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()


def prompt_injection_hits(text: str) -> list[str]:
    return [pattern.pattern for pattern in INJECTION_PATTERNS if pattern.search(text)]


def assert_review_payload_safe(payload: str) -> None:
    if payload != scrub_pii(payload):
        raise ValueError("Review payload contains personal data or an absolute path")


PRIVATE_QUESTION_SUMMARY = "Private encrypted question"
CANARY_QUERY_REDACTED = "[CANARY-QUERY-REDACTED]"
OWNER_OPERATIONAL_DIR_NAMES = frozenset({"expert-review"})
OWNER_OPERATIONAL_NAME_PREFIXES = ("owner-view", "owner-approval")


def contains_absolute_private_path(value: str) -> bool:
    """True when a public field would expose a host filesystem path."""
    return bool(MAC_PATH_RE.search(value) or WINDOWS_PATH_RE.search(value))


def redact_instruction_like_text(value: str) -> str:
    """Replace prompt-injection canaries; keep surrounding owner-view structure."""
    if not prompt_injection_hits(value):
        return value
    redacted = value
    for pattern in INJECTION_PATTERNS:
        redacted = pattern.sub(CANARY_QUERY_REDACTED, redacted)
    return redacted


# Structural corpus-discovery exclusions (path globs, not string-suppress).
# These paths must never enter ingestion/source discovery.
CORPUS_DISCOVERY_EXCLUSION_GLOBS: tuple[str, ...] = (
    "data/review_queue/**",
    "**/OWNER-VIEW*.md",
    "**/OWNER-APPROVAL*.docx",
    "**/OCR-OWNER-REVIEW*",
    "**/A2-OWNER-REVIEW*",
    "**/*backlog*",
    "**/*seal-checklist*",
)


def _posix_casefold(path: Path) -> str:
    return path.as_posix().replace("\\", "/").casefold()


def _fnmatch_ci(value: str, pattern: str) -> bool:
    return fnmatch.fnmatch(value.casefold(), pattern.casefold())


def is_excluded_from_corpus_discovery(
    path: Path, *, data_dir: Path | None = None, project_root: Path | None = None
) -> bool:
    """True when a path is structurally excluded from corpus discovery."""
    posix = _posix_casefold(path)
    name = path.name.casefold()
    parts = [part.casefold() for part in path.parts]
    relatives: list[str] = [posix, name]
    roots: list[Path] = []
    if project_root is not None:
        roots.append(Path(project_root))
    if data_dir is not None:
        roots.append(Path(data_dir))
        roots.append(Path(data_dir).parent)
    for root in roots:
        with suppress(OSError, ValueError):
            relatives.append(path.resolve().relative_to(root.resolve()).as_posix().casefold())

    if "review_queue" in parts:
        idx = parts.index("review_queue")
        if idx > 0 and parts[idx - 1] == "data":
            return True
        if data_dir is not None:
            try:
                path.resolve().relative_to((Path(data_dir) / "review_queue").resolve())
                return True
            except (OSError, ValueError):
                pass

    for rel in relatives:
        if _fnmatch_ci(rel, "data/review_queue/**") or rel.startswith("data/review_queue/"):
            return True
        if _fnmatch_ci(rel, "**/owner-view*.md") or _fnmatch_ci(Path(rel).name, "owner-view*.md"):
            return True
        if _fnmatch_ci(Path(rel).name, "*owner-view*.md"):
            return True
        if _fnmatch_ci(rel, "**/owner-approval*.docx") or _fnmatch_ci(
            Path(rel).name, "owner-approval*.docx"
        ):
            return True
        if _fnmatch_ci(Path(rel).name, "*owner-approval*.docx"):
            return True
        if _fnmatch_ci(rel, "**/ocr-owner-review*") or _fnmatch_ci(
            Path(rel).name, "ocr-owner-review*"
        ):
            return True
        if _fnmatch_ci(rel, "**/a2-owner-review*") or _fnmatch_ci(
            Path(rel).name, "a2-owner-review*"
        ):
            return True
        if _fnmatch_ci(rel, "**/*backlog*") or _fnmatch_ci(Path(rel).name, "*backlog*"):
            return True
        if _fnmatch_ci(rel, "**/*seal-checklist*") or _fnmatch_ci(
            Path(rel).name, "*seal-checklist*"
        ):
            return True
    return any(
        _fnmatch_ci(part, "*backlog*") or _fnmatch_ci(part, "*seal-checklist*") for part in parts
    )


def is_owner_operational_artifact(path: Path, *, data_dir: Path | None = None) -> bool:
    """Owner views, review packs, backlogs and eval sidecars are not corpus material."""
    if is_excluded_from_corpus_discovery(path, data_dir=data_dir):
        return True
    name = path.name.casefold()
    parts = [part.casefold() for part in path.parts]
    if name.startswith(OWNER_OPERATIONAL_NAME_PREFIXES):
        return True
    if "expert-review" in parts:
        return True
    if name.endswith(("-backlog.md", "-backlog.json")):
        return True
    if name in {"ingestion-exclusion.md", "recommendations.jsonl"} and "expert-review" in parts:
        return True
    if data_dir is not None:
        try:
            relative = path.resolve().relative_to(Path(data_dir).resolve())
        except ValueError:
            relative = None
        if relative is not None:
            rel_parts = [part.casefold() for part in relative.parts]
            if rel_parts and rel_parts[0] == "evaluation":
                return True
            if "expert-review" in rel_parts:
                return True
    return False
