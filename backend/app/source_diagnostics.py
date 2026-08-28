"""Stable, privacy-safe diagnostics for files excluded from source ingestion."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .privacy import scrub_pii

EXCLUSION_STATUSES = frozenset({"unsupported", "quarantined", "encrypted", "ocr_required"})


@dataclass(frozen=True, slots=True)
class ExclusionDiagnostic:
    statuses: frozenset[str]
    explanation: str
    corrective_action: str


DIAGNOSTICS: dict[str, ExclusionDiagnostic] = {
    "unsupported_file_type": ExclusionDiagnostic(
        frozenset({"unsupported"}),
        "The file format has no clean-room parser and was not indexed.",
        "Convert it to PDF, DOCX, PPTX, ODT, HTML, Markdown or plain text, then rescan.",
    ),
    "temporary_file_excluded": ExclusionDiagnostic(
        frozenset({"unsupported"}),
        "An operating-system or Office temporary file was excluded as non-source material.",
        "No action is needed; retain the corresponding substantive document instead.",
    ),
    "metadata_file_excluded": ExclusionDiagnostic(
        frozenset({"unsupported"}),
        "A filesystem metadata file was excluded because it contains no legal source content.",
        "No action is needed.",
    ),
    "parser_dependency_unavailable": ExclusionDiagnostic(
        frozenset({"unsupported"}),
        "The required local parser is not installed, so the file was not indexed.",
        "Install the named clean-room parser dependency or convert the file, then rescan.",
    ),
    "encrypted_or_restricted": ExclusionDiagnostic(
        frozenset({"encrypted"}),
        "The file is encrypted or access-restricted and was not opened.",
        "Supply a lawfully accessible, decrypted copy and rescan it.",
    ),
    "ocr_toolchain_unavailable": ExclusionDiagnostic(
        frozenset({"ocr_required"}),
        "The PDF needs OCR, but the local OCR toolchain is unavailable.",
        "Install the project OCR toolchain and rescan.",
    ),
    "ocr_processing_failed": ExclusionDiagnostic(
        frozenset({"ocr_required"}),
        "The local OCR process did not produce a valid readable derivative.",
        "Inspect the PDF, repair it if necessary, then retry OCR.",
    ),
    "ocr_output_unreadable": ExclusionDiagnostic(
        frozenset({"ocr_required"}),
        "OCR completed but the derivative still contained no extractable source text.",
        "Use a higher-quality scan or manually provide an accessible text version.",
    ),
    "ocr_required": ExclusionDiagnostic(
        frozenset({"ocr_required"}),
        "The PDF contains insufficient extractable text and still requires OCR.",
        "Run the local OCR workflow and rescan.",
    ),
    "parse_failed": ExclusionDiagnostic(
        frozenset({"quarantined"}),
        "The parser could not safely extract the document content.",
        "Inspect or repair the file, convert it to a supported format, and rescan.",
    ),
    "malformed_or_unreadable": ExclusionDiagnostic(
        frozenset({"quarantined"}),
        "The file was malformed, empty or unreadable and was quarantined.",
        "Replace it with a valid readable copy and rescan.",
    ),
    "restricted_access": ExclusionDiagnostic(
        frozenset({"quarantined"}),
        "Local access to the source was restricted, so its content was not read.",
        "Correct the local access permissions or provide an accessible copy, then rescan.",
    ),
    "file_read_failed": ExclusionDiagnostic(
        frozenset({"quarantined"}),
        "The scanner could not read the file bytes and quarantined the source.",
        "Check the file integrity and local permissions, then rescan.",
    ),
    "symlink_not_followed": ExclusionDiagnostic(
        frozenset({"quarantined"}),
        "A symbolic link was recorded but not followed across the source boundary.",
        "Place the intended document directly inside an approved source root and rescan.",
    ),
    "file_too_large": ExclusionDiagnostic(
        frozenset({"quarantined"}),
        "The file exceeds the bounded local parser size limit and was quarantined.",
        "Split or optimise the document into smaller source files, then rescan.",
    ),
    "source_identity_conflict": ExclusionDiagnostic(
        frozenset({"quarantined"}),
        "The source identity resolved to conflicting content and requires review.",
        "Choose the authoritative representation and rescan after resolving the conflict.",
    ),
    "owner_operational_artifact_excluded": ExclusionDiagnostic(
        frozenset({"unsupported"}),
        "Owner-view, review-pack, backlog or decision files are excluded from discovery.",
        "Keep them outside source roots; they are never indexed for RAG or training.",
    ),
    "processing_policy_rollback_refused": ExclusionDiagnostic(
        frozenset({"quarantined"}),
        "A superseded processing policy cannot be rolled back for this representation.",
        "Keep the current processed version; do not restore the superseded policy.",
    ),
}

_CODE = re.compile(r"[a-z][a-z0-9_]{2,79}")
_LEGACY = ExclusionDiagnostic(
    EXCLUSION_STATUSES,
    "A legacy exclusion has no recognised stable diagnostic code.",
    "Rescan the source to produce a precise corrective action.",
)


def validate_exclusion_reason(status: str, reason_code: str | None) -> str | None:
    """Require a recognised reason for every non-ready source accounting status."""

    if status not in EXCLUSION_STATUSES:
        return reason_code
    if not reason_code or not _CODE.fullmatch(reason_code):
        raise ValueError(f"{status} source rows require a stable exclusion reason code")
    diagnostic = DIAGNOSTICS.get(reason_code)
    if diagnostic is None or status not in diagnostic.statuses:
        raise ValueError(f"exclusion reason code is not valid for status {status}")
    return reason_code


def safe_exclusion_payload(status: str, reason_code: str | None) -> dict[str, str] | None:
    """Return admin-safe text; never reflect a legacy/raw parser message."""

    if status not in EXCLUSION_STATUSES:
        return None
    candidate = DIAGNOSTICS.get(reason_code or "")
    if candidate is None or status not in candidate.statuses:
        diagnostic = _LEGACY
        code = "legacy_exclusion_reason_missing"
    else:
        diagnostic = candidate
        code = reason_code or "legacy_exclusion_reason_missing"
    payload = {
        "reason_code": code,
        "explanation": diagnostic.explanation,
        "corrective_action": diagnostic.corrective_action,
    }
    if any(scrub_pii(value) != value for value in payload.values()):  # fixed text invariant
        raise RuntimeError("source diagnostic text must remain privacy-safe")
    return payload
