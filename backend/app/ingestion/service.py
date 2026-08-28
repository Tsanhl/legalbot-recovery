"""Concrete clean-room filesystem ingestion for the API and CLI.

The scanner treats every configured path as untrusted input.  Local path
aliases are encrypted before persistence, while raw bytes and canonical
Markdown are stored in the immutable SHA-256 vault.  Nothing in this module
writes an index or grants source approval.
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ..assessment.rules import (
    ASSESSMENT_RULE_SCHEMA,
    AssessmentRule,
    FeedbackBodyExtractor,
    FeedbackRuleExtractor,
    RubricRuleExtractor,
)
from ..config import Settings
from ..crypto import LocalCipher
from ..db import Database, utc_iso
from ..privacy import (
    is_owner_operational_artifact,
    path_fingerprint,
    safe_source_name,
    safe_summary,
)
from ..types import DocumentStatus
from ..types import MaterialLane as CatalogLane
from .chunking import StructuralChunker
from .identity import private_locator_digest
from .markdown import CanonicalMarkdownConverter
from .models import (
    BlockKind,
    Jurisdiction,
    MaterialLane,
    ParseResult,
    ParseStatus,
    Provenance,
    SourceIdentity,
    StructuralChunk,
)
from .ocr import OcrFailedError, OcrMyPdfProcessor, OcrUnavailableError
from .parsers import (
    PDF_BOILERPLATE_SCHEMA,
    PDF_REVIEW_ANNOTATION_SCHEMA,
    ParserRegistry,
    detect_format,
)
from .privacy import PIIAliaser
from .sanitation import TEXT_SANITATION_SCHEMA, sanitize_parse_result
from .vault import ContentAddressedVault, DedupeLedger, VaultObject

MAX_PARSE_BYTES = 512 * 1024 * 1024
_WORD_RE = re.compile(r"\b[\w'-]+\b", re.UNICODE)
CONTENT_CLASSIFICATION_SCHEMA = "legalbot.content-classification.v10"
LOCAL_SOURCE_VERSION_SCHEMA = "legalbot.local-source-version.v2"
SOURCE_PROCESSING_SCHEMA = "legalbot.source-processing.v1"
UNAVAILABLE_SOURCE_SCHEMA = "legalbot.unavailable-source.v2"
RECOVERY_OCCURRENCE_SCHEMA = "legalbot.recovery-occurrence.v1"
CONTENT_RESTORATION_OCCURRENCE_SCHEMA = "legalbot.content-restoration-occurrence.v1"
SOURCE_PROCESSING_COMPONENTS = {
    "canonical_markdown": CanonicalMarkdownConverter.schema,
    "assessment_rules": ASSESSMENT_RULE_SCHEMA,
    "classification": CONTENT_CLASSIFICATION_SCHEMA,
    "local_source_version": LOCAL_SOURCE_VERSION_SCHEMA,
    "orchestration": SOURCE_PROCESSING_SCHEMA,
    "pdf_boilerplate": PDF_BOILERPLATE_SCHEMA,
    "pdf_review_annotations": PDF_REVIEW_ANNOTATION_SCHEMA,
    "structural_chunker": StructuralChunker.schema,
    "text_sanitation": TEXT_SANITATION_SCHEMA,
    "source_rights": "legalbot.ai-use-rights.v1",
}
SOURCE_PROCESSING_FINGERPRINT = hashlib.sha256(
    json.dumps(
        SOURCE_PROCESSING_COMPONENTS,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
).hexdigest()


@dataclass(frozen=True, slots=True)
class _Classification:
    lane: CatalogLane
    ingestion_lane: MaterialLane
    subject: str
    jurisdiction: str
    ingestion_jurisdiction: Jurisdiction
    reason: str
    signal_codes: tuple[str, ...] = ()
    confidence: str = "path_only"
    material_type_candidate: str = "course_note"
    subject_secondary: tuple[str, ...] = ()
    subject_signal_codes: tuple[str, ...] = ()
    subject_confidence: str = "path_only"

    @property
    def ready_status(self) -> DocumentStatus:
        if self.lane is CatalogLane.ASSESSMENT_GUIDANCE:
            return DocumentStatus.ASSESSMENT_GUIDANCE
        if self.lane is CatalogLane.PRIVATE_TEACHING:
            return DocumentStatus.PRIVATE_TEACHING
        return DocumentStatus.CITABLE


def scan_configured_sources(
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    scan_id: str,
    ocr_processor: OcrMyPdfProcessor | None = None,
) -> dict[str, Any]:
    """Recursively account for every regular file in ``settings.source_roots``.

    The return value is useful to the CLI and tests; the background API may
    ignore it.  Per-file parser failures become catalogue statuses and do not
    abort the rest of a scan.  Storage or database failures still surface.
    """

    settings.ensure_runtime_dirs()
    safe_scan_id = safe_summary(scan_id, 120)
    vault = ContentAddressedVault(settings.vault_dir)
    ledger = DedupeLedger(settings.vault_dir / "dedupe-ledger.json")
    parsers = ParserRegistry.default()
    converter = CanonicalMarkdownConverter()
    chunker = StructuralChunker()
    aliaser = PIIAliaser(_load_alias_secret(settings, cipher))
    ocr = ocr_processor or OcrMyPdfProcessor()

    root_descriptors = database.create_source_scan(safe_scan_id, settings.source_roots)
    scan_row = database.fetchone(
        "SELECT resumed_from_scan_id FROM source_scans WHERE id=?", (safe_scan_id,)
    )
    resumed_from_scan_id = (
        str(scan_row["resumed_from_scan_id"])
        if scan_row is not None and scan_row["resumed_from_scan_id"]
        else None
    )
    resumable_rows = {
        str(row["path_fingerprint"]): row
        for row in (
            database.source_scan_files(resumed_from_scan_id)
            if resumed_from_scan_id is not None
            else ()
        )
    }
    roots: list[tuple[Path, dict[str, str]]] = []
    missing: list[dict[str, str]] = []
    for source_root, descriptor in zip(settings.source_roots, root_descriptors, strict=True):
        root = source_root.expanduser().absolute()
        if not root.exists() and not root.is_symlink():
            missing.append(descriptor)
        else:
            roots.append((root, descriptor))
    if missing:
        database.start_source_scan(
            safe_scan_id,
            roots_seen=[descriptor for _, descriptor in roots],
            expected_file_count=0,
        )
        labels = ", ".join(item["id"] for item in missing)
        database.fail_source_scan(
            safe_scan_id,
            error_code="missing_source_root",
            error_message=f"Required source root is missing: {labels}",
        )
        raise FileNotFoundError(f"Required source root is missing: {labels}")

    empty_chunk_repair = database.repair_empty_chunks(settings.data_dir / "backups")

    seen_paths: set[str] = set()
    configured_files: list[Path] = []
    for root, _ in roots:
        for path in _configured_files(root):
            path_key = str(path.absolute())
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            configured_files.append(path)
    database.start_source_scan(
        safe_scan_id,
        roots_seen=[descriptor for _, descriptor in roots],
        expected_file_count=len(configured_files),
    )

    resumed_files_reused = 0
    try:
        for path in configured_files:
            fingerprint = _path_fingerprint(path)
            classification = _classify(path)
            media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            content_sha256: str | None = None
            reason: str | None = None
            resumable = _resumable_source_scan_file(
                database,
                resumable_rows.get(fingerprint),
                path_fingerprint_value=fingerprint,
            )
            if resumable is not None and not path.is_symlink():
                try:
                    resume_raw = _put_file(vault, path)
                except OSError:
                    resume_raw = None
                if resume_raw is not None and resume_raw.sha256 == str(resumable["content_sha256"]):
                    database.record_source_scan_file(
                        safe_scan_id,
                        path_fingerprint=fingerprint,
                        document_id=str(resumable["document_id"]),
                        status=str(resumable["status"]),
                        content_sha256=resume_raw.sha256,
                        reason=None,
                    )
                    resumed_files_reused += 1
                    continue
            if path.is_symlink():
                reason = "symlink_not_followed"
                status = _persist_unreadable(
                    settings=settings,
                    database=database,
                    cipher=cipher,
                    path=path,
                    fingerprint=fingerprint,
                    media_type=media_type,
                    classification=classification,
                    reason=reason,
                    vault=vault,
                )
                if status is DocumentStatus.DUPLICATE:
                    reason = None
            else:
                try:
                    raw = _put_file(vault, path)
                except OSError as exc:
                    reason = (
                        "restricted_access"
                        if isinstance(exc, PermissionError)
                        else "file_read_failed"
                    )
                    status = _persist_unreadable(
                        settings=settings,
                        database=database,
                        cipher=cipher,
                        path=path,
                        fingerprint=fingerprint,
                        media_type=media_type,
                        classification=classification,
                        reason=reason,
                        vault=vault,
                    )
                    if status is DocumentStatus.DUPLICATE:
                        reason = None
                else:
                    content_sha256 = raw.sha256
                    try:
                        status, reason = _ingest_file(
                            settings=settings,
                            database=database,
                            cipher=cipher,
                            path=path,
                            fingerprint=fingerprint,
                            media_type=media_type,
                            classification=classification,
                            raw=raw,
                            vault=vault,
                            ledger=ledger,
                            parsers=parsers,
                            converter=converter,
                            chunker=chunker,
                            aliaser=aliaser,
                            scan_id=safe_scan_id,
                            ocr_processor=ocr,
                        )
                    except RuntimeError as exc:
                        if "rollback refused" not in str(exc).casefold():
                            raise
                        status = DocumentStatus.QUARANTINED
                        reason = "processing_policy_rollback_refused"
            alias = database.fetchone(
                "SELECT document_id FROM source_aliases WHERE path_fingerprint=?", (fingerprint,)
            )
            database.record_source_scan_file(
                safe_scan_id,
                path_fingerprint=fingerprint,
                document_id=str(alias["document_id"]) if alias else None,
                status=status.value,
                content_sha256=content_sha256,
                reason=reason,
            )
        result = database.complete_source_scan(safe_scan_id)
        result["roots_seen"] = len(roots)
        result["empty_chunk_repair"] = empty_chunk_repair
        result["resumed_from_scan_id"] = resumed_from_scan_id
        result["resumed_files_reused"] = resumed_files_reused
        return result
    except (Exception, KeyboardInterrupt) as exc:
        row = database.fetchone("SELECT status FROM source_scans WHERE id=?", (safe_scan_id,))
        if row is not None and row["status"] != "failed":
            database.fail_source_scan(
                safe_scan_id,
                error_code=type(exc).__name__,
                error_message="Source scan failed; durable accounting is available for resume",
            )
        raise


_RESUMABLE_SOURCE_STATUSES = frozenset(
    {
        DocumentStatus.CITABLE.value,
        DocumentStatus.PRIVATE_TEACHING.value,
        DocumentStatus.ASSESSMENT_GUIDANCE.value,
    }
)


def _resumable_source_scan_file(
    database: Database,
    prior_row: Any | None,
    *,
    path_fingerprint_value: str,
) -> Any | None:
    """Return a prior successful row only when its current v10 artefacts remain exact.

    A linked resume still enumerates every configured path and re-hashes any row it
    proposes to reuse.  Non-ready outcomes, superseded versions, old processing
    schemas and changed catalogue state are deliberately reprocessed.
    """

    if (
        prior_row is None
        or str(prior_row["status"]) not in _RESUMABLE_SOURCE_STATUSES
        or prior_row["reason"] is not None
        or not prior_row["document_id"]
        or not prior_row["content_sha256"]
    ):
        return None
    current = database.fetchone(
        """
        SELECT d.status, sv.version_sha256, sv.processing_fingerprint,
               sv.canonical_markdown_path, sv.metadata_json,
               (SELECT COUNT(*) FROM chunks c WHERE c.source_version_id=sv.id)
                 AS persisted_chunk_count
        FROM source_aliases sa
        JOIN documents d ON d.id=sa.document_id
        JOIN source_versions sv
          ON sv.document_id=d.id AND sv.superseded_by IS NULL
        WHERE sa.path_fingerprint=? AND d.id=?
        ORDER BY sv.created_at DESC, sv.id DESC
        LIMIT 1
        """,
        (path_fingerprint_value, str(prior_row["document_id"])),
    )
    if (
        current is None
        or str(current["status"]) != str(prior_row["status"])
        or str(current["version_sha256"]) != str(prior_row["content_sha256"])
        or _requires_content_reclassification(current)
        or _requires_persistence_repair(current, str(current["processing_fingerprint"]))
    ):
        return None
    metadata = _metadata_object(current["metadata_json"])
    processing_base = str(
        metadata.get("processing_base_fingerprint") or current["processing_fingerprint"]
    )
    if processing_base != SOURCE_PROCESSING_FINGERPRINT:
        return None
    return prior_row


def ingest_explicit_paths(
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    scan_id: str,
    paths: Sequence[Path],
    ocr_processor: OcrMyPdfProcessor | None = None,
) -> dict[str, Any]:
    """Ingest named files already inside configured roots.

    Used for newly acquired official materials without requiring a full
    source-root rescan.  Does not approve sources, write an index, or skip the
    rollback guard for files that would reanimate a superseded policy.
    """

    settings.ensure_runtime_dirs()
    safe_scan_id = safe_summary(scan_id, 120)
    vault = ContentAddressedVault(settings.vault_dir)
    ledger = DedupeLedger(settings.vault_dir / "dedupe-ledger.json")
    parsers = ParserRegistry.default()
    converter = CanonicalMarkdownConverter()
    chunker = StructuralChunker()
    aliaser = PIIAliaser(_load_alias_secret(settings, cipher))
    ocr = ocr_processor or OcrMyPdfProcessor()
    allowed_roots = tuple(root.expanduser().absolute() for root in settings.source_roots)
    items: list[dict[str, Any]] = []
    for raw_path in paths:
        path = raw_path.expanduser().absolute()
        if not path.is_file():
            items.append(
                {
                    "path_suffix": path.suffix,
                    "status": "missing",
                    "reason": "file_not_found",
                    "content_sha256": None,
                }
            )
            continue
        if not any(path == root or root in path.parents for root in allowed_roots):
            items.append(
                {
                    "path_suffix": path.suffix,
                    "status": "rejected",
                    "reason": "path_outside_configured_source_roots",
                    "content_sha256": None,
                }
            )
            continue
        fingerprint = _path_fingerprint(path)
        classification = _classify(path)
        media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        content_sha256: str | None = None
        reason: str | None = None
        try:
            raw = _put_file(vault, path)
            content_sha256 = raw.sha256
            status, reason = _ingest_file(
                settings=settings,
                database=database,
                cipher=cipher,
                path=path,
                fingerprint=fingerprint,
                media_type=media_type,
                classification=classification,
                raw=raw,
                vault=vault,
                ledger=ledger,
                parsers=parsers,
                converter=converter,
                chunker=chunker,
                aliaser=aliaser,
                scan_id=safe_scan_id,
                ocr_processor=ocr,
            )
        except RuntimeError as exc:
            message = str(exc)
            if "rollback refused" in message.casefold():
                items.append(
                    {
                        "path_suffix": path.suffix,
                        "status": "skipped",
                        "reason": "processing_policy_rollback_refused",
                        "content_sha256": content_sha256,
                    }
                )
                continue
            raise
        items.append(
            {
                "path_suffix": path.suffix,
                "status": status.value,
                "reason": reason,
                "content_sha256": content_sha256,
            }
        )
    return {
        "scan_id": safe_scan_id,
        "file_count": len(paths),
        "ingested": sum(
            1 for item in items if item["status"] not in {"missing", "rejected", "skipped"}
        ),
        "items": items,
        "wrote_active": False,
        "seals_expert_gold": False,
    }


def _configured_files(root: Path) -> Iterable[Path]:
    if root.is_file() or root.is_symlink():
        yield root
        return
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if path.is_symlink() or path.is_file():
            yield path


def _put_file(vault: ContentAddressedVault, path: Path) -> VaultObject:
    """Stream a file into the immutable vault without loading it all in RAM."""

    vault.root.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".source-incoming-", dir=vault.root)
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(descriptor, "wb") as destination, path.open("rb") as source:
            while block := source.read(1024 * 1024):
                destination.write(block)
                digest.update(block)
                size += len(block)
            destination.flush()
            os.fsync(destination.fileno())
        sha256 = digest.hexdigest()
        target = vault.object_path(sha256)
        target.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(temporary, 0o444)
        try:
            os.link(temporary, target)
        except FileExistsError:
            if (
                target.stat().st_size != size
                or hashlib.sha256(target.read_bytes()).hexdigest() != sha256
            ):
                raise OSError("immutable vault collision or corruption") from None
        _fsync_directory(target.parent)
        return VaultObject(sha256, size, target)
    finally:
        temporary.unlink(missing_ok=True)


def _ingest_file(
    *,
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    path: Path,
    fingerprint: str,
    media_type: str,
    classification: _Classification,
    raw: VaultObject,
    vault: ContentAddressedVault,
    ledger: DedupeLedger,
    parsers: ParserRegistry,
    converter: CanonicalMarkdownConverter,
    chunker: StructuralChunker,
    aliaser: PIIAliaser,
    scan_id: str,
    ocr_processor: OcrMyPdfProcessor,
) -> tuple[DocumentStatus, str | None]:
    path_representation_group = _representation_identity(path)
    (
        processing_fingerprint,
        occurrence_from_source_version_id,
        processing_occurrence_schema,
    ) = _resolve_processing_occurrence(
        database=database,
        path_fingerprint_value=fingerprint,
        version_sha256=raw.sha256,
    )
    existing = database.fetchone(
        """
        SELECT d.id AS document_id, d.content_sha256 AS document_sha256,
               d.status, d.lane, d.duplicate_of, d.source_identity_id,
               d.representation_group_id, d.retrieval_canonical,
               d.has_annotations, d.searchable_text, d.dedupe_status,
               sv.id AS source_version_id, sv.metadata_json,
               sv.processing_fingerprint, sv.superseded_by, sv.canonical_markdown_path,
               (SELECT COUNT(*) FROM chunks c
                WHERE c.source_version_id=sv.id
                  AND COALESCE(json_extract(c.metadata_json,'$.schema'),'')=
                      'legalbot.structural-chunk.v1')
                 AS persisted_chunk_count,
               (SELECT COUNT(*) FROM source_versions current_sv
                WHERE current_sv.document_id=d.id
                  AND current_sv.superseded_by IS NULL) AS current_processing_count
        FROM source_aliases sa
        JOIN documents d ON d.id=sa.document_id
        JOIN source_versions sv ON sv.document_id=d.id
        WHERE sa.path_fingerprint=? AND sv.version_sha256=?
        ORDER BY CASE WHEN sv.processing_fingerprint=? THEN 0 ELSE 1 END,
                 sv.created_at DESC, sv.id DESC
        LIMIT 1
        """,
        (fingerprint, raw.sha256, processing_fingerprint),
    )
    if (
        existing is not None
        and existing["processing_fingerprint"] == processing_fingerprint
        and existing["superseded_by"] is not None
    ):
        raise RuntimeError(
            "Processing policy rollback refused because the matching representation "
            "was already superseded"
        )
    if existing is not None and int(existing["current_processing_count"]) != 1:
        raise RuntimeError("Source processing lineage does not have exactly one current version")
    if (
        existing is not None
        and existing["processing_fingerprint"] == processing_fingerprint
        and existing["superseded_by"] is None
        and existing["document_sha256"] == raw.sha256
        and str(existing["status"])
        in {
            DocumentStatus.CITABLE.value,
            DocumentStatus.PRIVATE_TEACHING.value,
            DocumentStatus.ASSESSMENT_GUIDANCE.value,
            DocumentStatus.DUPLICATE.value,
        }
        and not _requires_identity_migration(existing)
        and not _requires_content_reclassification(existing)
        and not _requires_persistence_repair(existing, processing_fingerprint)
    ):
        existing_status = (
            DocumentStatus.DUPLICATE
            if existing["duplicate_of"]
            else DocumentStatus(str(existing["status"]))
        )
        return existing_status, _default_exclusion_reason(existing_status)
    ocr_object: VaultObject | None = None
    ocr_engine: str | None = None
    exclusion_reason: str | None = None
    non_source_reason = _non_source_exclusion_reason(path)
    if non_source_reason is not None:
        exclusion_reason = non_source_reason
        parsed = ParseResult(ParseStatus.UNSUPPORTED, detect_format(path.name))
    elif raw.size > MAX_PARSE_BYTES:
        exclusion_reason = "file_too_large"
        parsed = ParseResult(
            ParseStatus.QUARANTINED,
            detect_format(path.name),
            diagnostics=(f"file exceeds parser limit of {MAX_PARSE_BYTES} bytes",),
        )
    else:
        raw_bytes = vault.read_bytes(raw.sha256)
        parsed = sanitize_parse_result(
            parsers.parse(raw_bytes, filename=path.name, aliaser=aliaser)
        )
        if parsed.status is ParseStatus.OCR_REQUIRED and parsed.document_format.value == "pdf":
            try:
                ocr_result = ocr_processor.process(raw_bytes)
            except OcrUnavailableError:
                exclusion_reason = "ocr_toolchain_unavailable"
            except OcrFailedError:
                exclusion_reason = "ocr_processing_failed"
            else:
                ocr_object = vault.put_bytes(ocr_result.pdf_bytes)
                ocr_engine = ocr_result.engine
                reparsed = sanitize_parse_result(
                    parsers.parse(
                        ocr_result.pdf_bytes,
                        filename=path.name,
                        aliaser=aliaser,
                    )
                )
                parsed = reparsed
                if reparsed.status is ParseStatus.OCR_REQUIRED:
                    exclusion_reason = "ocr_output_unreadable"
    classification = _refine_classification(classification, parsed)
    ai_use_policy, ai_use_restriction_codes = _ai_use_policy(parsed)
    content_identity = _content_source_identity(parsed, classification)
    public_identifier_candidate = _public_identifier_candidate(parsed, classification)
    source_identity_id = content_identity or f"content-sha256:{raw.sha256}"
    representation_group_id = content_identity or path_representation_group
    source_identity = SourceIdentity("catalog", source_identity_id, version=raw.sha256)
    representation_identity = SourceIdentity("catalog", representation_group_id)
    dedupe = ledger.register_representation(representation_identity, raw.sha256)
    parser_status = _document_status(parsed.status, classification)
    document_id, duplicate_of = _upsert_document_and_alias(
        database=database,
        cipher=cipher,
        path=path,
        fingerprint=fingerprint,
        content_sha256=raw.sha256,
        media_type=media_type,
        status=parser_status,
        classification=classification,
        source_identity_id=source_identity_id,
        representation_group_id=representation_group_id,
        dedupe_status=dedupe.status.value,
        has_annotations=bool(parsed.comments or parsed.revisions),
        searchable_text=parsed.is_ready and any(block.text.strip() for block in parsed.body_blocks),
    )
    visible_status = DocumentStatus.DUPLICATE if duplicate_of else parser_status
    if not parsed.is_ready:
        current_predecessor = database.fetchone(
            """
            SELECT id FROM source_versions
            WHERE document_id=? AND superseded_by IS NULL AND version_sha256<>?
            LIMIT 1
            """,
            (document_id, raw.sha256),
        )
        if current_predecessor is not None:
            _persist_unavailable_revision(
                settings=settings,
                database=database,
                path=path,
                fingerprint=fingerprint,
                document_id=document_id,
                raw=raw,
                vault=vault,
                parsed=parsed,
                classification=classification,
            )
        reason = (
            None
            if visible_status is DocumentStatus.DUPLICATE
            else (exclusion_reason or _parse_exclusion_reason(path, parsed))
        )
        return visible_status, reason

    source_version_id = _stable_id(
        "source-version", document_id, raw.sha256, processing_fingerprint
    )
    existing_version = database.fetchone(
        "SELECT metadata_json, review_status FROM source_versions WHERE id=?", (source_version_id,)
    )
    previous_lane = str(existing["lane"]) if existing is not None else None
    classification_changed = (
        previous_lane is not None and previous_lane != classification.lane.value
    )

    title = (
        safe_source_name(path, raw.sha256)
        if classification.lane is CatalogLane.ASSESSMENT_GUIDANCE
        else _document_title(parsed, safe_source_name(path, raw.sha256))
    )
    provenance = Provenance.now(
        source_identity=source_identity,
        title=title,
        source_kind=classification.reason,
        jurisdiction=classification.ingestion_jurisdiction,
        material_lane=classification.ingestion_lane,
        content_sha256=raw.sha256,
        private_locator_digest=private_locator_digest(
            str(path.absolute()), salt=fingerprint.encode("ascii")
        ),
        public_aliases={"display_name": safe_source_name(path, raw.sha256)},
        extra={"parser_format": parsed.document_format.value},
    )
    bundle = converter.convert(parsed, provenance)
    body_object = vault.put_bytes(bundle.body_markdown.encode("utf-8"))
    comments_object = vault.put_bytes(bundle.comments_markdown.encode("utf-8"))
    revisions_object = vault.put_bytes(bundle.revisions_markdown.encode("utf-8"))
    provenance_object = vault.put_bytes(bundle.provenance_json.encode("utf-8"))
    metadata: dict[str, Any] = {
        "schema": LOCAL_SOURCE_VERSION_SCHEMA,
        "processing_schema": SOURCE_PROCESSING_SCHEMA,
        "processing_fingerprint": processing_fingerprint,
        "processing_base_fingerprint": SOURCE_PROCESSING_FINGERPRINT,
        "processing_components": SOURCE_PROCESSING_COMPONENTS,
        "text_sanitation_schema": TEXT_SANITATION_SCHEMA,
        "pdf_boilerplate_schema": PDF_BOILERPLATE_SCHEMA,
        "canonical_markdown_schema": converter.schema,
        "structural_chunker_schema": chunker.schema,
        "scan_id": scan_id,
        "parser_status": parsed.status.value,
        "parser_format": parsed.document_format.value,
        "parser_diagnostics": [safe_summary(value, 240) for value in parsed.diagnostics],
        "classification_schema": CONTENT_CLASSIFICATION_SCHEMA,
        "classification_reason": classification.reason,
        "classification_signal_codes": list(classification.signal_codes),
        "classification_confidence": classification.confidence,
        "material_type_candidate": classification.material_type_candidate,
        "subject_primary_candidate": classification.subject,
        "subject_secondary_candidates": list(classification.subject_secondary),
        "subject_signal_codes": list(classification.subject_signal_codes),
        "subject_confidence": classification.subject_confidence,
        "raw_object_sha256": raw.sha256,
        "raw_vault_path": _relative_path(settings, raw.path),
        "body_sha256": body_object.sha256,
        "comments_markdown_path": _relative_path(settings, comments_object.path),
        "comments_sha256": comments_object.sha256,
        "revisions_markdown_path": _relative_path(settings, revisions_object.path),
        "revisions_sha256": revisions_object.sha256,
        "provenance_path": _relative_path(settings, provenance_object.path),
        "provenance_sha256": provenance_object.sha256,
        "source_identity": source_identity.canonical_key,
        "representation_group_id": representation_group_id,
        "dedupe_status": dedupe.status.value,
        "identity_verified": False,
        "currentness_verified": False,
        "currentness_applicable": False,
        "authority_eligible": False,
        "citation_rendering_enabled": False,
        "citation_data": {},
        "canonical_citation": None,
        "ai_use_policy": ai_use_policy,
        "ai_use_restriction_codes": list(ai_use_restriction_codes),
        "eligible_for_model_use": ai_use_policy != "prohibited",
    }
    if occurrence_from_source_version_id is not None:
        if processing_occurrence_schema == RECOVERY_OCCURRENCE_SCHEMA:
            metadata.update(
                {
                    "recovery_occurrence_schema": RECOVERY_OCCURRENCE_SCHEMA,
                    "recovery_from_source_version_id": occurrence_from_source_version_id,
                }
            )
        elif processing_occurrence_schema == CONTENT_RESTORATION_OCCURRENCE_SCHEMA:
            metadata.update(
                {
                    "content_restoration_occurrence_schema": (
                        CONTENT_RESTORATION_OCCURRENCE_SCHEMA
                    ),
                    "content_restoration_from_source_version_id": (
                        occurrence_from_source_version_id
                    ),
                }
            )
    if public_identifier_candidate is not None:
        metadata["public_identifier_candidate"] = public_identifier_candidate
    approval_invalidated = False
    if existing_version is not None:
        try:
            previous_metadata = json.loads(existing_version["metadata_json"])
        except (TypeError, json.JSONDecodeError):
            previous_metadata = {}
        if isinstance(previous_metadata, dict):
            approval_invalidated = existing_version[
                "review_status"
            ] == "approved" and not _approved_classification_compatible(
                previous_metadata,
                classification,
                previous_lane=previous_lane,
            )
            for key in (
                "identity_verified",
                "currentness_verified",
                "currentness_applicable",
                "authority_eligible",
                "citation_rendering_enabled",
                "citation_data",
                "canonical_citation",
                "approval_as_of_date",
                "material_type",
                "identity_title",
            ):
                if key in previous_metadata and not approval_invalidated:
                    metadata[key] = previous_metadata[key]
    if ai_use_policy == "prohibited":
        approval_invalidated = True
    if ocr_object is not None:
        metadata.update(
            {
                "ocr_engine": ocr_engine,
                "ocr_derivative_sha256": ocr_object.sha256,
                "ocr_derivative_vault_path": _relative_path(settings, ocr_object.path),
                "ocr_original_sha256": raw.sha256,
            }
        )
    explicit_rubric = classification.material_type_candidate == "rubric"
    marker_feedback = classification.material_type_candidate == "marker_feedback"
    feedback_body_extractor = FeedbackBodyExtractor()
    feedback_body_comments = (
        feedback_body_extractor.extract(parsed.body_blocks) if marker_feedback else ()
    )
    feedback_grade_text = (
        feedback_body_extractor.grade_text(parsed.body_blocks) if marker_feedback else None
    )
    review_comments = (*parsed.comments, *feedback_body_comments) if marker_feedback else ()
    review_parse = replace(parsed, comments=tuple(review_comments), revisions=())
    review_annotation_chunks = tuple(
        chunker.chunk_comments(review_parse, document_sha256=raw.sha256)
    )
    preserved_annotation_chunks = (
        *chunker.chunk_comments(parsed, document_sha256=raw.sha256),
        *chunker.chunk_revisions(parsed, document_sha256=raw.sha256),
    )
    metadata["assessment_rule_schema"] = ASSESSMENT_RULE_SCHEMA
    metadata["feedback_body_comment_count"] = len(feedback_body_comments)
    metadata["eligible_reviewer_comment_count"] = len(review_comments)
    if classification.lane is CatalogLane.ASSESSMENT_GUIDANCE:
        if review_comments:
            selected_chunks = review_annotation_chunks
        elif explicit_rubric:
            selected_chunks = (
                *chunker.chunk_body(parsed, document_sha256=raw.sha256),
                *review_annotation_chunks,
            )
        else:
            # A student answer or ordinary feedback body is never training or
            # retrieval material. Annotations remain separately preserved;
            # only marker comments can later cross the assessment boundary.
            selected_chunks = review_annotation_chunks
    else:
        selected_chunks = (
            *chunker.chunk_body(parsed, document_sha256=raw.sha256),
            *preserved_annotation_chunks,
        )
    nonempty_chunks = tuple(
        chunk for chunk in selected_chunks if chunk.text.strip() and _WORD_RE.search(chunk.text)
    )
    metadata["selected_chunk_count"] = len(nonempty_chunks)
    metadata["chunk_manifest_sha256"] = _chunk_manifest_sha256(nonempty_chunks)
    assessment_rules: tuple[AssessmentRule, ...] = ()
    if classification.lane is CatalogLane.ASSESSMENT_GUIDANCE:
        if review_comments:
            assessment_rules += FeedbackRuleExtractor().extract(
                tuple(review_comments),
                subject=classification.subject,
                document_grade_text=feedback_grade_text,
            )
        if explicit_rubric:
            assessment_rules += RubricRuleExtractor().extract(
                parsed.body_blocks, subject=classification.subject
            )
    now = utc_iso()
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO source_versions(
              id, document_id, version_sha256, canonical_markdown_path, title,
              stable_identifier, currentness_status, review_status,
              processing_fingerprint, superseded_by, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'unknown', 'staged', ?, NULL, ?, ?)
            ON CONFLICT(document_id, version_sha256, processing_fingerprint) DO UPDATE SET
              canonical_markdown_path=excluded.canonical_markdown_path,
              title=excluded.title,
              metadata_json=excluded.metadata_json
            """,
            (
                source_version_id,
                document_id,
                raw.sha256,
                _relative_path(settings, body_object.path),
                title,
                f"local-path-sha256:{fingerprint}",
                processing_fingerprint,
                json.dumps(metadata, ensure_ascii=False, sort_keys=True),
                now,
            ),
        )
        connection.execute(
            """
            UPDATE source_versions SET superseded_by=?
            WHERE document_id=? AND id<>? AND superseded_by IS NULL
            """,
            (
                source_version_id,
                document_id,
                source_version_id,
            ),
        )
        _retire_superseded_review_state(connection, source_version_id, now)
        current_processing_count = int(
            connection.execute(
                """
                SELECT COUNT(*) AS n FROM source_versions
                WHERE document_id=? AND superseded_by IS NULL
                """,
                (document_id,),
            ).fetchone()["n"]
        )
        if current_processing_count != 1:
            raise RuntimeError(
                "Source processing transition did not produce exactly one current version"
            )
        current_version = connection.execute(
            """
            SELECT id, version_sha256 FROM source_versions
            WHERE document_id=? AND superseded_by IS NULL
            """,
            (document_id,),
        ).fetchone()
        if current_version is None or current_version["id"] != source_version_id:
            raise RuntimeError(
                "Source processing transition selected an inconsistent current version"
            )
        if current_version["version_sha256"] != raw.sha256:
            raise RuntimeError("Current source version does not match the document content hash")
        if approval_invalidated:
            connection.execute(
                """
                UPDATE source_versions
                SET stable_identifier=?, as_of_date=NULL, canonical_url=NULL,
                    currentness_status='unknown', licence_name=NULL, licence_url=NULL,
                    review_status='staged'
                WHERE id=?
                """,
                (f"local-path-sha256:{fingerprint}", source_version_id),
            )
        if classification_changed and previous_lane == CatalogLane.ASSESSMENT_GUIDANCE.value:
            connection.execute(
                "UPDATE rubric_rules SET review_status='rejected' WHERE source_version_id=?",
                (source_version_id,),
            )
            connection.execute(
                """
                UPDATE reviews SET status='rejected',
                    decision_note='Source no longer classifies as assessment guidance',
                    decided_at=?
                WHERE review_type='assessment_rule' AND target_id IN (
                  SELECT id FROM rubric_rules WHERE source_version_id=?
                )
                """,
                (now, source_version_id),
            )
        referenced_chunks = int(
            connection.execute(
                """
                SELECT COUNT(*) AS n FROM evidence_spans es
                JOIN chunks c ON c.id=es.chunk_id WHERE c.source_version_id=?
                """,
                (source_version_id,),
            ).fetchone()["n"]
        )
        if referenced_chunks:
            raise RuntimeError(
                "Cannot migrate source chunks while persisted evidence references this representation"
            )
        connection.execute("DELETE FROM chunks WHERE source_version_id=?", (source_version_id,))
        for ordinal, chunk in enumerate(nonempty_chunks):
            chunk_id = _stable_id("chunk", source_version_id, chunk.chunk_id)
            locator = _chunk_locator(
                chunk.heading_path,
                chunk.page_start,
                chunk.page_end,
                ordinal,
                chunk.metadata,
            )
            chunk_metadata = {
                "schema": "legalbot.structural-chunk.v1",
                "structural_chunk_id": chunk.chunk_id,
                "stream": chunk.stream,
                "block_ordinals": list(chunk.block_ordinals),
                "page_start": chunk.page_start,
                "page_end": chunk.page_end,
                "char_start": chunk.char_start,
                "char_end": chunk.char_end,
                **dict(chunk.metadata),
            }
            connection.execute(
                """
                INSERT INTO chunks(
                  id, source_version_id, ordinal, heading_path, locator, text_sha256,
                  markdown_text, token_count, stream, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chunk_id,
                    source_version_id,
                    ordinal,
                    json.dumps(list(chunk.heading_path), ensure_ascii=False),
                    locator,
                    hashlib.sha256(chunk.text.encode("utf-8")).hexdigest(),
                    chunk.text,
                    len(_WORD_RE.findall(chunk.text)),
                    chunk.stream,
                    json.dumps(chunk_metadata, ensure_ascii=False, sort_keys=True),
                ),
            )
        for rule in assessment_rules:
            rule_id = _stable_id(
                "assessment-rule",
                source_version_id,
                rule.source_comment_id,
                rule.criterion,
                rule.rule_text,
            )
            connection.execute(
                """
                INSERT INTO rubric_rules(
                  id, task_type, subject, criterion, polarity, grade_band, rule_text,
                  remediation_text, source_version_id, review_status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'staged', ?)
                ON CONFLICT(id) DO UPDATE SET
                  task_type=excluded.task_type,
                  subject=excluded.subject,
                  criterion=excluded.criterion,
                  polarity=excluded.polarity,
                  grade_band=excluded.grade_band,
                  rule_text=excluded.rule_text,
                  remediation_text=excluded.remediation_text
                """,
                (
                    rule_id,
                    rule.task_type,
                    rule.subject,
                    rule.criterion,
                    rule.polarity.value,
                    rule.grade_band.value,
                    rule.rule_text,
                    rule.remediation_text,
                    source_version_id,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO reviews(
                  id, review_type, target_id, status, reason, created_at
                )
                VALUES (?, 'assessment_rule', ?, 'pending', ?, ?)
                """,
                (
                    _stable_id("review-assessment-rule", rule_id),
                    rule_id,
                    "Marker-comment rule requires human approval before use",
                    now,
                ),
            )
        if duplicate_of is None:
            connection.execute(
                """
                INSERT OR IGNORE INTO reviews(
                  id, review_type, target_id, status, reason, created_at
                ) VALUES (?, 'source_version', ?, 'pending', ?, ?)
                """,
                (
                    _stable_id("review", source_version_id),
                    source_version_id,
                    f"Source-admission review required before {classification.lane.value} enters a candidate build",
                    now,
                ),
            )
            if approval_invalidated:
                connection.execute(
                    """
                    UPDATE reviews
                    SET status='pending', decision_note=NULL, decided_at=NULL,
                        reason=?
                    WHERE review_type='source_version' AND target_id=?
                    """,
                    (
                        "Source classification changed; identity, currentness, rights and citation metadata require renewed human approval",
                        source_version_id,
                    ),
                )
            elif classification_changed:
                connection.execute(
                    """
                    UPDATE reviews SET reason=?
                    WHERE review_type='source_version' AND target_id=? AND status='pending'
                    """,
                    (
                        f"Source-admission review required before {classification.lane.value} enters a candidate build",
                        source_version_id,
                    ),
                )
            if ai_use_policy == "prohibited":
                connection.execute(
                    """
                    UPDATE source_versions
                    SET review_status='rejected', currentness_status='not_applicable'
                    WHERE id=?
                    """,
                    (source_version_id,),
                )
                connection.execute(
                    """
                    UPDATE reviews
                    SET status='rejected',
                        reason='Source notice prohibits AI model training or response generation',
                        decision_note='Excluded automatically by source-rights policy',
                        decided_at=?
                    WHERE review_type='source_version' AND target_id=?
                    """,
                    (now, source_version_id),
                )
    return visible_status, None


def _ai_use_policy(parsed: ParseResult) -> tuple[str, tuple[str, ...]]:
    """Classify only explicit model-use restrictions; silence remains reviewable."""

    if not parsed.is_ready:
        return "unreviewed", ()
    text = " ".join(block.text for block in parsed.body_blocks[:80])
    folded = " ".join(text.casefold().split())[:80_000]
    codes: list[str] = []
    model_use = (
        r"(?:artificial intelligence|large language (?:model|module)|"
        r"language model|response generation)"
    )
    prohibition = r"(?:must not|may not|prohibited|not permitted|without (?:express )?permission)"
    if re.search(
        rf"\b{prohibition}\b.{{0,240}}\b{model_use}\b|"
        rf"\b{model_use}\b.{{0,240}}\b{prohibition}\b",
        folded,
    ):
        codes.append("explicit_prohibitory_language")
    return ("prohibited", tuple(sorted(set(codes)))) if codes else ("unreviewed", ())


def _upsert_document_and_alias(
    *,
    database: Database,
    cipher: LocalCipher,
    path: Path,
    fingerprint: str,
    content_sha256: str,
    media_type: str,
    status: DocumentStatus,
    classification: _Classification,
    source_identity_id: str | None = None,
    representation_group_id: str | None = None,
    dedupe_status: str = "new",
    has_annotations: bool = False,
    searchable_text: bool = False,
) -> tuple[str, str | None]:
    alias_row = database.fetchone(
        "SELECT document_id FROM source_aliases WHERE path_fingerprint=?", (fingerprint,)
    )
    document_id = (
        str(alias_row["document_id"]) if alias_row else _stable_id("document", fingerprint)
    )
    now = utc_iso()
    display_name = safe_source_name(path, content_sha256)
    new_representation_group = representation_group_id or _representation_identity(path)
    with database.transaction() as connection:
        previous = connection.execute(
            """
            SELECT content_sha256, representation_group_id, lane, jurisdiction, subject_primary
            FROM documents WHERE id=?
            """,
            (document_id,),
        ).fetchone()
        previous_representation_group = (
            str(previous["representation_group_id"])
            if previous is not None and previous["representation_group_id"]
            else None
        )
        new_semantic_partition = (
            content_sha256,
            classification.lane.value,
            classification.jurisdiction,
            classification.subject,
        )
        previous_semantic_partition = (
            (
                str(previous["content_sha256"]),
                str(previous["lane"] or ""),
                str(previous["jurisdiction"] or ""),
                str(previous["subject_primary"] or ""),
            )
            if previous is not None
            else None
        )
        provisional_canonical = connection.execute(
            """
            SELECT id FROM documents
            WHERE content_sha256=?
              AND COALESCE(lane, '')=?
              AND COALESCE(jurisdiction, '')=?
              AND COALESCE(subject_primary, '')=?
              AND duplicate_of IS NULL AND id<>?
            ORDER BY created_at, id LIMIT 1
            """,
            (*new_semantic_partition, document_id),
        ).fetchone()
        provisional_duplicate_of = (
            str(provisional_canonical["id"]) if provisional_canonical is not None else None
        )
        provisional_status = (
            DocumentStatus.DUPLICATE if provisional_duplicate_of is not None else status
        )
        connection.execute(
            """
            INSERT INTO documents(
              id, content_sha256, source_identity_id, representation_group_id,
              safe_display_name, media_type,
              status, lane, subject_primary, subject_secondary_json, jurisdiction,
              duplicate_of, retrieval_canonical, has_annotations, searchable_text,
              dedupe_status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              content_sha256=excluded.content_sha256,
              source_identity_id=excluded.source_identity_id,
              representation_group_id=excluded.representation_group_id,
              safe_display_name=excluded.safe_display_name,
              media_type=excluded.media_type,
              status=excluded.status,
              lane=excluded.lane,
              subject_primary=excluded.subject_primary,
              subject_secondary_json=excluded.subject_secondary_json,
              jurisdiction=excluded.jurisdiction,
              duplicate_of=excluded.duplicate_of,
              retrieval_canonical=0,
              has_annotations=excluded.has_annotations,
              searchable_text=excluded.searchable_text,
              dedupe_status=excluded.dedupe_status,
              updated_at=excluded.updated_at
            """,
            (
                document_id,
                content_sha256,
                source_identity_id or f"content-sha256:{content_sha256}",
                new_representation_group,
                display_name,
                media_type,
                provisional_status.value,
                classification.lane.value,
                classification.subject,
                json.dumps(list(classification.subject_secondary), ensure_ascii=False),
                classification.jurisdiction,
                provisional_duplicate_of,
                int(has_annotations),
                int(searchable_text),
                dedupe_status,
                now,
                now,
            ),
        )
        connection.execute(
            """
            INSERT INTO source_aliases(id, document_id, path_fingerprint, encrypted_path, imported_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(path_fingerprint) DO UPDATE SET
              document_id=excluded.document_id,
              encrypted_path=excluded.encrypted_path,
              imported_at=excluded.imported_at
            """,
            (
                _stable_id("alias", fingerprint),
                document_id,
                fingerprint,
                cipher.encrypt_text(str(path.absolute())),
                now,
            ),
        )
        affected_semantic_partitions = {new_semantic_partition}
        if previous_semantic_partition is not None:
            affected_semantic_partitions.add(previous_semantic_partition)
        affected_representation_groups = {new_representation_group}
        if previous_representation_group is not None:
            affected_representation_groups.add(previous_representation_group)
        for affected_partition in sorted(affected_semantic_partitions):
            affected_representation_groups.update(
                _reconcile_content_dedupe_group(
                    connection,
                    content_sha256=affected_partition[0],
                    lane=affected_partition[1],
                    jurisdiction=affected_partition[2],
                    subject_primary=affected_partition[3],
                    now=now,
                    status_overrides={document_id: status},
                )
            )
        for affected_group in sorted(affected_representation_groups):
            _refresh_retrieval_canonical_group(connection, affected_group)
        final_document = connection.execute(
            "SELECT duplicate_of FROM documents WHERE id=?", (document_id,)
        ).fetchone()
        if final_document is None:
            raise RuntimeError("Document upsert did not persist the target document")
        duplicate_of = (
            str(final_document["duplicate_of"])
            if final_document["duplicate_of"] is not None
            else None
        )
        for affected_partition in affected_semantic_partitions:
            mismatch = connection.execute(
                """
                SELECT 1 FROM documents child
                JOIN documents parent ON parent.id=child.duplicate_of
                WHERE child.content_sha256=?
                  AND (
                    child.content_sha256<>parent.content_sha256
                    OR COALESCE(child.lane, '')<>COALESCE(parent.lane, '')
                    OR COALESCE(child.jurisdiction, '')<>COALESCE(parent.jurisdiction, '')
                    OR COALESCE(child.subject_primary, '')<>COALESCE(parent.subject_primary, '')
                  )
                LIMIT 1
                """,
                (affected_partition[0],),
            ).fetchone()
            if mismatch is not None:
                raise RuntimeError("Exact-deduplication lineage contains a content mismatch")
    return document_id, duplicate_of


def _reconcile_content_dedupe_group(
    connection: Any,
    *,
    content_sha256: str,
    lane: str,
    jurisdiction: str,
    subject_primary: str,
    now: str,
    status_overrides: Mapping[str, DocumentStatus] | None = None,
) -> set[str]:
    """Elect one canonical inside a logical exact-content partition."""

    rows = connection.execute(
        """
        SELECT id, status, lane, representation_group_id, media_type,
               has_annotations, searchable_text, created_at
        FROM documents
        WHERE content_sha256=?
          AND COALESCE(lane, '')=?
          AND COALESCE(jurisdiction, '')=?
          AND COALESCE(subject_primary, '')=?
        ORDER BY created_at, id
        """,
        (content_sha256, lane, jurisdiction, subject_primary),
    ).fetchall()
    if not rows:
        return set()
    overrides = status_overrides or {}
    effective_statuses = {
        str(row["id"]): overrides.get(str(row["id"])) or _restored_canonical_status(connection, row)
        for row in rows
    }
    canonical = min(
        rows,
        key=lambda row: _canonical_representation_rank(row, effective_statuses[str(row["id"])]),
    )
    canonical_id = str(canonical["id"])
    canonical_status = effective_statuses[canonical_id]
    for row in rows:
        if str(row["id"]) == canonical_id:
            continue
        connection.execute(
            """
            UPDATE documents
            SET duplicate_of=?, status=?, retrieval_canonical=0
            WHERE id=?
            """,
            (canonical_id, DocumentStatus.DUPLICATE.value, row["id"]),
        )
        _reject_duplicate_source_reviews(connection, str(row["id"]), now)
    connection.execute(
        "UPDATE documents SET duplicate_of=NULL, status=? WHERE id=?",
        (canonical_status.value, canonical_id),
    )
    canonical_count = int(
        connection.execute(
            """
            SELECT COUNT(*) AS n FROM documents
            WHERE content_sha256=?
              AND COALESCE(lane, '')=?
              AND COALESCE(jurisdiction, '')=?
              AND COALESCE(subject_primary, '')=?
              AND duplicate_of IS NULL
            """,
            (content_sha256, lane, jurisdiction, subject_primary),
        ).fetchone()["n"]
    )
    if canonical_count != 1:
        raise RuntimeError("Exact-content group does not have exactly one canonical")
    if canonical_status in {
        DocumentStatus.CITABLE,
        DocumentStatus.PRIVATE_TEACHING,
        DocumentStatus.ASSESSMENT_GUIDANCE,
    }:
        _ensure_current_canonical_review(
            connection,
            document_id=canonical_id,
            lane=str(canonical["lane"]),
            now=now,
        )
    return {str(row["representation_group_id"]) for row in rows if row["representation_group_id"]}


def _canonical_representation_rank(
    row: Mapping[str, Any], effective_status: DocumentStatus
) -> tuple[int, int, int, str, str, str]:
    """Prefer a usable representation; arrival order is only a final tie-break."""

    status_rank = {
        DocumentStatus.CITABLE: 0,
        DocumentStatus.PRIVATE_TEACHING: 1,
        DocumentStatus.ASSESSMENT_GUIDANCE: 2,
        DocumentStatus.OCR_REQUIRED: 3,
        DocumentStatus.ENCRYPTED: 4,
        DocumentStatus.UNSUPPORTED: 5,
        DocumentStatus.QUARANTINED: 6,
        DocumentStatus.DUPLICATE: 7,
    }[effective_status]
    annotated_feedback = (
        str(row["lane"]) == CatalogLane.ASSESSMENT_GUIDANCE.value
        and str(row["media_type"])
        == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        and bool(row["has_annotations"])
    )
    searchable_pdf = str(row["media_type"]) == "application/pdf" and bool(row["searchable_text"])
    source_preference = 0 if annotated_feedback else 1 if searchable_pdf else 2
    searchable_rank = 0 if bool(row["searchable_text"]) or annotated_feedback else 1
    return (
        status_rank,
        searchable_rank,
        source_preference,
        str(row["media_type"]),
        str(row["created_at"]),
        str(row["id"]),
    )


def _restored_canonical_status(connection: Any, row: Mapping[str, Any]) -> DocumentStatus:
    current_status = DocumentStatus(str(row["status"]))
    if current_status is not DocumentStatus.DUPLICATE:
        return current_status
    current_version = connection.execute(
        """
        SELECT metadata_json FROM source_versions
        WHERE document_id=? AND superseded_by IS NULL
        ORDER BY created_at DESC, id DESC LIMIT 1
        """,
        (row["id"],),
    ).fetchone()
    if current_version is None:
        return DocumentStatus.QUARANTINED
    parser_status_value = _metadata_object(current_version["metadata_json"]).get("parser_status")
    if parser_status_value == ParseStatus.READY.value:
        return {
            CatalogLane.ASSESSMENT_GUIDANCE.value: DocumentStatus.ASSESSMENT_GUIDANCE,
            CatalogLane.PRIVATE_TEACHING.value: DocumentStatus.PRIVATE_TEACHING,
        }.get(str(row["lane"]), DocumentStatus.CITABLE)
    return {
        ParseStatus.OCR_REQUIRED.value: DocumentStatus.OCR_REQUIRED,
        ParseStatus.ENCRYPTED.value: DocumentStatus.ENCRYPTED,
        ParseStatus.UNSUPPORTED.value: DocumentStatus.UNSUPPORTED,
        ParseStatus.PARSER_UNAVAILABLE.value: DocumentStatus.UNSUPPORTED,
    }.get(str(parser_status_value), DocumentStatus.QUARANTINED)


def _reject_duplicate_source_reviews(connection: Any, document_id: str, now: str) -> None:
    connection.execute(
        """
        UPDATE reviews
        SET status='rejected',
            reason='Logical duplicate within semantic partition; review the canonical source',
            decision_note='Superseded by the semantic-partition canonical',
            decided_at=?
        WHERE review_type='source_version' AND status='pending'
          AND target_id IN (
            SELECT id FROM source_versions
            WHERE document_id=? AND superseded_by IS NULL
          )
        """,
        (now, document_id),
    )


def _ensure_current_canonical_review(
    connection: Any, *, document_id: str, lane: str, now: str
) -> None:
    current_version = connection.execute(
        """
        SELECT id FROM source_versions
        WHERE document_id=? AND superseded_by IS NULL AND review_status='staged'
        ORDER BY created_at DESC, id DESC LIMIT 1
        """,
        (document_id,),
    ).fetchone()
    if current_version is None:
        return
    source_version_id = str(current_version["id"])
    review_id = _stable_id("review", source_version_id)
    reason = f"Source-admission review required before {lane} enters a candidate build"
    connection.execute(
        """
        INSERT OR IGNORE INTO reviews(
          id, review_type, target_id, status, reason, created_at
        ) VALUES (?, 'source_version', ?, 'pending', ?, ?)
        """,
        (
            review_id,
            source_version_id,
            reason,
            now,
        ),
    )
    connection.execute(
        """
        UPDATE reviews
        SET status='pending', reason=?, decision_note=NULL, decided_at=NULL
        WHERE id=? AND review_type='source_version' AND target_id=?
        """,
        (reason, review_id, source_version_id),
    )
    connection.execute(
        """
        UPDATE reviews
        SET status='rejected',
            reason='Duplicate review record retired for the canonical source',
            decision_note='Canonical source uses one actionable review',
            decided_at=?
        WHERE review_type='source_version' AND target_id=?
          AND status='pending' AND id<>?
        """,
        (now, source_version_id, review_id),
    )


def _refresh_retrieval_canonical_group(connection: Any, representation_group_id: str) -> None:
    """Elect exactly one body representation without discarding other streams."""

    rows = connection.execute(
        """
        SELECT id, media_type, status, lane, jurisdiction, subject_primary,
               has_annotations, searchable_text, created_at
        FROM documents
        WHERE representation_group_id=? AND duplicate_of IS NULL
        """,
        (representation_group_id,),
    ).fetchall()
    connection.execute(
        "UPDATE documents SET retrieval_canonical=0 WHERE representation_group_id=?",
        (representation_group_id,),
    )
    if not rows:
        return

    partitions: dict[tuple[str, str, str], list[Any]] = {}
    for row in rows:
        key = (
            str(row["lane"] or ""),
            str(row["jurisdiction"] or ""),
            str(row["subject_primary"] or ""),
        )
        partitions.setdefault(key, []).append(row)
    for partition, partition_rows in partitions.items():
        winner = min(
            partition_rows,
            key=lambda row: _canonical_representation_rank(
                row, _restored_canonical_status(connection, row)
            ),
        )
        connection.execute("UPDATE documents SET retrieval_canonical=1 WHERE id=?", (winner["id"],))
        canonical_count = int(
            connection.execute(
                """
                SELECT COUNT(*) AS n FROM documents
                WHERE representation_group_id=?
                  AND COALESCE(lane, '')=?
                  AND COALESCE(jurisdiction, '')=?
                  AND COALESCE(subject_primary, '')=?
                  AND duplicate_of IS NULL AND retrieval_canonical=1
                """,
                (representation_group_id, *partition),
            ).fetchone()["n"]
        )
        if canonical_count != 1:
            raise RuntimeError(
                "Semantic representation partition does not have exactly one canonical"
            )


def _requires_identity_migration(row: Any) -> bool:
    source_identity = str(row["source_identity_id"] or "")
    representation_group = str(row["representation_group_id"] or "")
    modern_source = source_identity.startswith(
        ("content-sha256:", "doi-sha256:", "neutral-citation-sha256:")
    )
    modern_group = representation_group.startswith(
        ("local-representation-sha256:", "doi-sha256:", "neutral-citation-sha256:")
    )
    return not (modern_source and modern_group)


def _requires_content_reclassification(row: Any) -> bool:
    try:
        metadata = json.loads(str(row["metadata_json"] or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return True
    return (
        not isinstance(metadata, dict)
        or metadata.get("classification_schema") != CONTENT_CLASSIFICATION_SCHEMA
    )


def _requires_persistence_repair(row: Any, processing_fingerprint: str) -> bool:
    try:
        metadata = json.loads(str(row["metadata_json"] or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return True
    return (
        not isinstance(metadata, dict)
        or metadata.get("schema") != LOCAL_SOURCE_VERSION_SCHEMA
        or metadata.get("processing_schema") != SOURCE_PROCESSING_SCHEMA
        or metadata.get("processing_fingerprint") != processing_fingerprint
        or metadata.get("text_sanitation_schema") != TEXT_SANITATION_SCHEMA
        or metadata.get("canonical_markdown_schema") != CanonicalMarkdownConverter.schema
        or metadata.get("structural_chunker_schema") != StructuralChunker.schema
        or metadata.get("selected_chunk_count") != int(row["persisted_chunk_count"])
        or Path(str(row["canonical_markdown_path"])).name != metadata.get("body_sha256")
    )


def _resolve_processing_occurrence(
    *,
    database: Database,
    path_fingerprint_value: str,
    version_sha256: str,
) -> tuple[str, str | None, str | None]:
    """Choose a representation fingerprint without reanimating old approval.

    A transiently unavailable source is represented by a nonretrievable current
    tombstone.  If bytes later become readable, or valid content returns to a
    historical raw hash, this creates a distinct staged occurrence tied to the
    current predecessor.  Processing-policy rollback remains forbidden across
    the whole document lineage, not merely within one raw hash.
    """

    current_rows = database.fetchall(
        """
        SELECT sv.id, sv.document_id, sv.version_sha256,
               sv.processing_fingerprint, sv.metadata_json
        FROM source_aliases sa
        JOIN source_versions sv ON sv.document_id=sa.document_id
        WHERE sa.path_fingerprint=? AND sv.superseded_by IS NULL
        ORDER BY sv.created_at DESC, sv.id DESC
        """,
        (path_fingerprint_value,),
    )
    if len(current_rows) > 1:
        raise RuntimeError("Source processing lineage does not have exactly one current version")
    if not current_rows:
        return SOURCE_PROCESSING_FINGERPRINT, None, None

    current = current_rows[0]
    metadata = _metadata_object(current["metadata_json"])
    current_fingerprint = str(current["processing_fingerprint"])
    current_base_fingerprint = str(
        metadata.get("processing_base_fingerprint") or current_fingerprint
    )
    if current_base_fingerprint != SOURCE_PROCESSING_FINGERPRINT:
        lineage = database.fetchall(
            """
            SELECT processing_fingerprint, metadata_json
            FROM source_versions WHERE document_id=?
            """,
            (current["document_id"],),
        )
        requested_policy_seen = any(
            str(
                _metadata_object(row["metadata_json"]).get("processing_base_fingerprint")
                or row["processing_fingerprint"]
            )
            == SOURCE_PROCESSING_FINGERPRINT
            for row in lineage
        )
        if requested_policy_seen:
            raise RuntimeError(
                "Processing policy rollback refused because that policy was already superseded"
            )

    if str(current["version_sha256"]) == version_sha256:
        if (
            metadata.get("recovery_occurrence_schema") == RECOVERY_OCCURRENCE_SCHEMA
            and metadata.get("processing_base_fingerprint") == SOURCE_PROCESSING_FINGERPRINT
        ):
            recovery_from = metadata.get("recovery_from_source_version_id")
            if isinstance(recovery_from, str) and recovery_from:
                return current_fingerprint, recovery_from, RECOVERY_OCCURRENCE_SCHEMA
        if (
            metadata.get("content_restoration_occurrence_schema")
            == CONTENT_RESTORATION_OCCURRENCE_SCHEMA
            and metadata.get("processing_base_fingerprint") == SOURCE_PROCESSING_FINGERPRINT
        ):
            restoration_from = metadata.get("content_restoration_from_source_version_id")
            if isinstance(restoration_from, str) and restoration_from:
                return (
                    current_fingerprint,
                    restoration_from,
                    CONTENT_RESTORATION_OCCURRENCE_SCHEMA,
                )
        return SOURCE_PROCESSING_FINGERPRINT, None, None

    occurrence_from = str(current["id"])
    if _is_unavailable_representation(metadata):
        recovery_fingerprint = hashlib.sha256(
            (
                f"{SOURCE_PROCESSING_FINGERPRINT}\0{RECOVERY_OCCURRENCE_SCHEMA}\0{occurrence_from}"
            ).encode("ascii")
        ).hexdigest()
        return recovery_fingerprint, occurrence_from, RECOVERY_OCCURRENCE_SCHEMA

    historical_match = database.fetchone(
        """
        SELECT id FROM source_versions
        WHERE document_id=? AND version_sha256=? AND superseded_by IS NOT NULL
        ORDER BY created_at DESC, id DESC LIMIT 1
        """,
        (current["document_id"], version_sha256),
    )
    if historical_match is None:
        return SOURCE_PROCESSING_FINGERPRINT, None, None

    restoration_fingerprint = hashlib.sha256(
        (
            f"{SOURCE_PROCESSING_FINGERPRINT}\0"
            f"{CONTENT_RESTORATION_OCCURRENCE_SCHEMA}\0{occurrence_from}"
        ).encode("ascii")
    ).hexdigest()
    return (
        restoration_fingerprint,
        occurrence_from,
        CONTENT_RESTORATION_OCCURRENCE_SCHEMA,
    )


def _metadata_object(value: Any) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _is_unavailable_representation(metadata: Mapping[str, Any]) -> bool:
    return (
        metadata.get("availability_tombstone") is True
        or metadata.get("canonical_markdown_schema")
        in {"legalbot.unavailable-source.v1", UNAVAILABLE_SOURCE_SCHEMA}
        or (
            metadata.get("retrieval_eligible") is False
            and metadata.get("selected_chunk_count") == 0
            and metadata.get("parser_status") != ParseStatus.READY.value
        )
    )


def _persist_unavailable_revision(
    *,
    settings: Settings,
    database: Database,
    path: Path,
    fingerprint: str,
    document_id: str,
    raw: VaultObject,
    vault: ContentAddressedVault,
    parsed: ParseResult,
    classification: _Classification,
) -> None:
    """Create a nonretrievable lineage tombstone for a newly unreadable revision."""

    unavailable_schema = UNAVAILABLE_SOURCE_SCHEMA
    current_predecessors = database.fetchall(
        """
        SELECT id FROM source_versions
        WHERE document_id=? AND superseded_by IS NULL
        ORDER BY created_at DESC, id DESC
        """,
        (document_id,),
    )
    if len(current_predecessors) != 1:
        raise RuntimeError("Unavailable source transition requires exactly one current predecessor")
    unavailable_from_source_version_id = str(current_predecessors[0]["id"])
    unavailable_fingerprint = hashlib.sha256(
        (
            f"{SOURCE_PROCESSING_FINGERPRINT}\0{unavailable_schema}\0"
            f"{unavailable_from_source_version_id}"
        ).encode("ascii")
    ).hexdigest()
    source_version_id = _stable_id(
        "source-version", document_id, raw.sha256, unavailable_fingerprint
    )
    marker = {
        "content_sha256": raw.sha256,
        "processing_fingerprint": unavailable_fingerprint,
        "processing_base_fingerprint": SOURCE_PROCESSING_FINGERPRINT,
        "schema": unavailable_schema,
        "status": parsed.status.value,
        "unavailable_from_source_version_id": unavailable_from_source_version_id,
    }
    safe_markdown = (
        f"<!-- legalbot-unavailable "
        f"{json.dumps(marker, ensure_ascii=True, separators=(',', ':'), sort_keys=True)} -->\n\n"
        "# Source unavailable for retrieval\n"
    )
    body_object = vault.put_bytes(safe_markdown.encode("utf-8"))
    metadata: dict[str, Any] = {
        "schema": LOCAL_SOURCE_VERSION_SCHEMA,
        "processing_schema": SOURCE_PROCESSING_SCHEMA,
        "processing_fingerprint": unavailable_fingerprint,
        "processing_base_fingerprint": SOURCE_PROCESSING_FINGERPRINT,
        "processing_components": SOURCE_PROCESSING_COMPONENTS,
        "text_sanitation_schema": TEXT_SANITATION_SCHEMA,
        "pdf_boilerplate_schema": PDF_BOILERPLATE_SCHEMA,
        "canonical_markdown_schema": unavailable_schema,
        "structural_chunker_schema": StructuralChunker.schema,
        "classification_schema": CONTENT_CLASSIFICATION_SCHEMA,
        "classification_reason": classification.reason,
        "classification_signal_codes": list(classification.signal_codes),
        "parser_status": parsed.status.value,
        "parser_format": parsed.document_format.value,
        "parser_diagnostics": [safe_summary(value, 240) for value in parsed.diagnostics],
        "raw_object_sha256": raw.sha256,
        "raw_vault_path": _relative_path(settings, raw.path),
        "body_sha256": body_object.sha256,
        "selected_chunk_count": 0,
        "chunk_manifest_sha256": _chunk_manifest_sha256(()),
        "retrieval_eligible": False,
        "availability_tombstone": True,
        "unavailable_from_source_version_id": unavailable_from_source_version_id,
    }
    now = utc_iso()
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO source_versions(
              id, document_id, version_sha256, canonical_markdown_path, title,
              stable_identifier, currentness_status, review_status,
              processing_fingerprint, superseded_by, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'unknown', 'rejected', ?, NULL, ?, ?)
            ON CONFLICT(document_id, version_sha256, processing_fingerprint) DO UPDATE SET
              canonical_markdown_path=excluded.canonical_markdown_path,
              metadata_json=excluded.metadata_json,
              review_status='rejected'
            """,
            (
                source_version_id,
                document_id,
                raw.sha256,
                _relative_path(settings, body_object.path),
                safe_source_name(path, raw.sha256),
                f"local-path-sha256:{fingerprint}",
                unavailable_fingerprint,
                json.dumps(metadata, ensure_ascii=False, sort_keys=True),
                now,
            ),
        )
        connection.execute(
            """
            UPDATE source_versions SET superseded_by=?
            WHERE document_id=? AND id<>? AND superseded_by IS NULL
            """,
            (source_version_id, document_id, source_version_id),
        )
        connection.execute("DELETE FROM chunks WHERE source_version_id=?", (source_version_id,))
        _retire_superseded_review_state(connection, source_version_id, now)
        current = connection.execute(
            """
            SELECT id, version_sha256 FROM source_versions
            WHERE document_id=? AND superseded_by IS NULL
            """,
            (document_id,),
        ).fetchall()
        if len(current) != 1 or current[0]["id"] != source_version_id:
            raise RuntimeError(
                "Unavailable source revision did not become the sole current version"
            )
        if current[0]["version_sha256"] != raw.sha256:
            raise RuntimeError("Unavailable source revision content identity is inconsistent")


def _retire_superseded_review_state(connection: Any, source_version_id: str, now: str) -> None:
    connection.execute(
        """
        UPDATE reviews
        SET status='rejected',
            reason='Processing representation superseded; review the current successor',
            decision_note='Superseded by a newer processing representation',
            decided_at=?
        WHERE review_type='source_version' AND status='pending'
          AND target_id IN (
            SELECT id FROM source_versions WHERE superseded_by=?
          )
        """,
        (now, source_version_id),
    )
    connection.execute(
        """
        UPDATE rubric_rules SET review_status='rejected'
        WHERE source_version_id IN (
          SELECT id FROM source_versions WHERE superseded_by=?
        ) AND review_status='staged'
        """,
        (source_version_id,),
    )
    connection.execute(
        """
        UPDATE reviews
        SET status='rejected',
            reason='Assessment rule source representation was superseded',
            decision_note='Superseded by a newer processing representation',
            decided_at=?
        WHERE review_type='assessment_rule' AND status='pending'
          AND target_id IN (
            SELECT rr.id FROM rubric_rules rr
            JOIN source_versions sv ON sv.id=rr.source_version_id
            WHERE sv.superseded_by=?
          )
        """,
        (now, source_version_id),
    )


def _persist_unreadable(
    *,
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    path: Path,
    fingerprint: str,
    media_type: str,
    classification: _Classification,
    reason: str,
    vault: ContentAddressedVault,
) -> DocumentStatus:
    marker_payload = json.dumps(
        {
            "path_fingerprint": fingerprint,
            "reason": reason,
            "schema": "legalbot.pre-read-unavailable.v1",
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    marker_object = vault.put_bytes(marker_payload)
    document_id, duplicate_of = _upsert_document_and_alias(
        database=database,
        cipher=cipher,
        path=path,
        fingerprint=fingerprint,
        content_sha256=marker_object.sha256,
        media_type=media_type,
        status=DocumentStatus.QUARANTINED,
        classification=classification,
    )
    current_predecessor = database.fetchone(
        """
        SELECT id FROM source_versions
        WHERE document_id=? AND superseded_by IS NULL AND version_sha256<>?
        LIMIT 1
        """,
        (document_id, marker_object.sha256),
    )
    if current_predecessor is not None:
        _persist_unavailable_revision(
            settings=settings,
            database=database,
            path=path,
            fingerprint=fingerprint,
            document_id=document_id,
            raw=marker_object,
            vault=vault,
            parsed=ParseResult(
                ParseStatus.QUARANTINED,
                detect_format(path.name),
                diagnostics=(reason,),
            ),
            classification=classification,
        )
    return DocumentStatus.DUPLICATE if duplicate_of else DocumentStatus.QUARANTINED


_SUBJECT_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "biolaw",
        (
            r"\bbiolaw\b",
            r"\bbioethics\b",
            r"\bgene editing\b",
            r"\bgenomic(?:s| medicine)?\b",
            r"\bneuro(?:science|technology|law)\b",
            r"\bhuman enhancement\b",
        ),
    ),
    ("pensions", (r"\bpensions? law\b", r"\boccupational pensions?\b", r"\bpension schemes?\b")),
    (
        "mediation and ADR",
        (r"\bmediation\b", r"\balternative dispute resolution\b", r"\bADR\b"),
    ),
    (
        "ai and data protection",
        (
            r"\bartificial intelligence\b",
            r"\bmachine learning\b",
            r"\bdata protection\b",
            r"\bGDPR\b",
            r"\bautomated decision(?:-| )making\b",
        ),
    ),
    (
        "private international law",
        (r"\bprivate international law\b", r"\bconflict of laws\b", r"\bchoice of law\b"),
    ),
    (
        "financial services",
        (r"\bfinancial services law\b", r"\bfinancial regulation\b", r"\bbanking law\b"),
    ),
    (
        "consumer",
        (r"\bconsumer law\b", r"\bconsumer rights\b", r"\bunfair trading\b"),
    ),
    (
        "criminal evidence",
        (r"\bcriminal evidence law\b", r"\bcriminal evidence\b"),
    ),
    (
        "company and insolvency",
        (
            r"\bcompany law\b",
            r"\bcorporate law\b",
            r"\binsolvency law\b",
            r"\bcorporate insolvency\b",
        ),
    ),
    (
        "wills and succession",
        (r"\bwills? and succession law\b", r"\bsuccession law\b", r"\bprobate law\b"),
    ),
    (
        "civil litigation",
        (r"\bcivil litigation law\b", r"\bcivil procedure\b", r"\bcivil litigation\b"),
    ),
    ("professional negligence", (r"\bprofessional negligence law\b",)),
    ("medical law", (r"\bmedical law\b", r"\bhealth law\b", r"\bclinical negligence\b")),
    ("trusts", (r"\btrusts? law\b", r"\bequitable trusts?\b")),
    ("land", (r"\bland law\b", r"\bconveyancing\b", r"\bregistered land\b")),
    ("criminal", (r"\bcriminal law\b", r"\bcriminal responsibility\b", r"\bmens rea\b")),
    (
        "eu and internal market",
        (r"\bEU law\b", r"\beuropean union law\b", r"\binternal market\b", r"\bfree movement\b"),
    ),
    ("competition", (r"\bcompetition law\b", r"\bantitrust\b", r"\babuse of dominance\b")),
    ("commercial", (r"\bcommercial law\b", r"\bsale of goods\b", r"\bcommercial transactions?\b")),
    ("contract", (r"\bcontract law\b", r"\bcontractual obligations?\b")),
    ("tort", (r"\btort law\b", r"\blaw of torts?\b", r"\bduty of care\b")),
    (
        "employment and business",
        (r"\bemployment law\b", r"\blabour law\b", r"\bbusiness law\b"),
    ),
    ("public international law", (r"\bpublic international law\b",)),
    (
        "intellectual property",
        (r"\bintellectual property law\b", r"\bpatent law\b", r"\bcopyright law\b"),
    ),
    (
        "constitutional",
        (r"\bconstitutional law\b", r"\bjudicial review\b", r"\badministrative law\b"),
    ),
    ("evidence", (r"\bevidence law\b",)),
    ("family", (r"\bfamily law\b",)),
    ("tax", (r"\btax law\b", r"\btaxation law\b")),
)


_JURISDICTION_PATTERNS: tuple[tuple[str, Jurisdiction, tuple[str, ...]], ...] = (
    ("Scotland", Jurisdiction.SCOTLAND, (r"\bscotland\b", r"\bscottish\b")),
    (
        "Northern Ireland",
        Jurisdiction.NORTHERN_IRELAND,
        (r"\bnorthern ireland\b", r"\bnorthern irish\b"),
    ),
    (
        "England and Wales",
        Jurisdiction.ENGLAND_WALES,
        (r"\bengland and wales\b", r"\benglish and welsh\b"),
    ),
    (
        "United Kingdom",
        Jurisdiction.UNITED_KINGDOM,
        (r"\bunited kingdom\b", r"\buk wide\b", r"\buk law\b"),
    ),
    (
        "European Union",
        Jurisdiction.EUROPEAN_UNION,
        (r"\beuropean union\b", r"\beu law\b", r"\beu competition\b"),
    ),
    (
        "United States",
        Jurisdiction.COMPARATIVE,
        (r"\bunited states\b", r"\busa\b", r"\bamerican law\b"),
    ),
    ("Australia", Jurisdiction.COMPARATIVE, (r"\baustralia\b", r"\baustralian\b")),
    ("Austria", Jurisdiction.COMPARATIVE, (r"\baustria\b", r"\baustrian\b")),
    ("Armenia", Jurisdiction.COMPARATIVE, (r"\barmenia\b", r"\barmenian\b")),
    ("Brazil", Jurisdiction.COMPARATIVE, (r"\bbrazil\b", r"\bbrazilian\b")),
    ("China", Jurisdiction.COMPARATIVE, (r"\bchina\b", r"\bchinese\b")),
    ("Cyprus", Jurisdiction.COMPARATIVE, (r"\bcyprus\b", r"\bcypriot\b")),
    ("France", Jurisdiction.COMPARATIVE, (r"\bfrance\b", r"\bfrench\b")),
    ("Georgia", Jurisdiction.COMPARATIVE, (r"\bgeorgia\b", r"\bgeorgian\b")),
    ("Germany", Jurisdiction.COMPARATIVE, (r"\bgermany\b", r"\bgerman\b")),
    ("Hong Kong", Jurisdiction.COMPARATIVE, (r"\bhong kong\b",)),
    ("India", Jurisdiction.COMPARATIVE, (r"\bindia\b", r"\bindian\b")),
    ("Italy", Jurisdiction.COMPARATIVE, (r"\bitaly\b", r"\bitalian\b")),
    ("Kazakhstan", Jurisdiction.COMPARATIVE, (r"\bkazakhstan\b", r"\bkazakh\b")),
    ("Luxembourg", Jurisdiction.COMPARATIVE, (r"\bluxembourg\b",)),
    ("Mexico", Jurisdiction.COMPARATIVE, (r"\bmexico\b", r"\bmexican\b")),
    ("Netherlands", Jurisdiction.COMPARATIVE, (r"\bnetherlands\b", r"\bdutch\b")),
    ("Nigeria", Jurisdiction.COMPARATIVE, (r"\bnigeria\b", r"\bnigerian\b")),
    ("South Africa", Jurisdiction.COMPARATIVE, (r"\bsouth africa\b", r"\bsouth african\b")),
    ("Sweden", Jurisdiction.COMPARATIVE, (r"\bsweden\b", r"\bswedish\b")),
    ("Turkey", Jurisdiction.COMPARATIVE, (r"\bturkiye\b", r"\bturkey\b", r"\bturkish\b")),
    ("Ukraine", Jurisdiction.COMPARATIVE, (r"\bukraine\b", r"\bukrainian\b")),
)


def _jurisdiction_classification(value: str) -> tuple[str, Jurisdiction]:
    matches = [
        (name, broad)
        for name, broad, patterns in _JURISDICTION_PATTERNS
        if any(re.search(pattern, value, re.IGNORECASE) for pattern in patterns)
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1 or re.search(r"\b(?:comparative|international)\b", value, re.IGNORECASE):
        return "Comparative", Jurisdiction.COMPARATIVE
    return "England and Wales", Jurisdiction.ENGLAND_WALES


def _subject_classification(value: str) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    tags: list[str] = []
    codes: list[str] = []
    for subject, patterns in _SUBJECT_PATTERNS:
        if any(re.search(pattern, value, re.IGNORECASE) for pattern in patterns):
            tags.append(subject)
            code = re.sub(r"[^a-z0-9]+", "_", subject.casefold()).strip("_")
            codes.append(f"subject_{code}")

    if "biolaw" in tags:
        cross_labels: tuple[tuple[str, tuple[str, ...]], ...] = (
            ("medical law", (r"\b(?:clinical|medical|bioethics|genomic|gene editing)\b",)),
            ("criminal", (r"\b(?:criminal responsibility|neuroscience|neurotechnology)\b",)),
            ("environment and energy", (r"\b(?:environment|energy|climate|biodiversity)\b",)),
            (
                "ai and data protection",
                (r"\b(?:genetic privacy|health data|data protection|artificial intelligence)\b",),
            ),
        )
        for subject, patterns in cross_labels:
            if subject not in tags and any(
                re.search(pattern, value, re.IGNORECASE) for pattern in patterns
            ):
                tags.append(subject)
                code = re.sub(r"[^a-z0-9]+", "_", subject.casefold()).strip("_")
                codes.append(f"subject_{code}")
    if not tags:
        return "general", (), ("subject_uncertain",)
    return tags[0], tuple(tags[1:]), tuple(codes)


def _refine_subject_classification(base: _Classification, text: str) -> _Classification:
    content_primary, content_secondary, content_codes = _subject_classification(text)
    if content_primary == "general":
        return base
    content_tags = (content_primary, *content_secondary)
    if base.subject == "general":
        return replace(
            base,
            subject=content_primary,
            subject_secondary=content_secondary,
            subject_signal_codes=content_codes,
            subject_confidence="content_signal",
        )
    secondary = tuple(
        dict.fromkeys(
            (*base.subject_secondary, *(tag for tag in content_tags if tag != base.subject))
        )
    )
    return replace(
        base,
        subject_secondary=secondary,
        subject_signal_codes=tuple(dict.fromkeys((*base.subject_signal_codes, *content_codes))),
        subject_confidence="path_and_content",
    )


def _classify(path: Path) -> _Classification:
    value = " ".join(part.casefold().replace("_", " ").replace("-", " ") for part in path.parts)
    parent_value = " ".join(
        part.casefold().replace("_", " ").replace("-", " ") for part in path.parts[:-1]
    )
    name_value = path.stem.casefold().replace("_", " ").replace("-", " ")
    assessment_parent = bool(
        re.search(
            r"\b(feedback|feedforward|examiner|marking|marked|grademark|rubric|grade|assessment)\b",
            parent_value,
        )
    )
    assessment_filename = bool(
        re.search(
            r"\b(feedback|feedforward|examiner|marking|marked|grademark|rubric|grade)\b",
            name_value,
        )
        or re.search(
            r"\bassessment (?:brief|criteria|feedback|instructions?|rubric)\b",
            name_value,
        )
    )
    scholarship_parent = bool(
        re.search(
            r"\b(journal(?:s)?|article(?:s)?|book(?:s)?|chapter(?:s)?|thesis|dissertation|treatise)\b",
            parent_value,
        )
    )
    if assessment_parent or assessment_filename:
        lane, ingestion_lane, reason = (
            CatalogLane.ASSESSMENT_GUIDANCE,
            MaterialLane.ASSESSMENT_FEEDBACK,
            "assessment_feedback_path",
        )
        if _is_explicit_rubric(path):
            material_type = "rubric"
        elif _is_explicit_feedback_path(path):
            material_type = "marker_feedback"
        else:
            material_type = "assessment"
    elif scholarship_parent:
        lane, ingestion_lane, reason = (
            CatalogLane.SCHOLARSHIP,
            MaterialLane.SECONDARY_SCHOLARSHIP,
            "scholarship_path",
        )
        material_type = "book" if re.search(r"\b(book|chapter|treatise)\b", value) else "journal"
    elif re.search(
        r"\b(case(?:s| law)?|judgment(?:s)?|legislation|statute(?:s)?|regulation(?:s)?)\b", value
    ):
        lane, ingestion_lane, reason = (
            CatalogLane.PRIMARY_AUTHORITY,
            MaterialLane.PRIMARY_AUTHORITY,
            "primary_authority_path",
        )
        if re.search(r"\b(case(?:s| law)?|judgment(?:s)?)\b", value):
            material_type = "case"
        elif re.search(r"\b(regulation(?:s)?|rules?)\b", value):
            material_type = "rule"
        else:
            material_type = "legislation"
    elif re.search(
        r"\b(law commission|judiciary|government guidance|official guidance|regulator)\b", value
    ):
        lane, ingestion_lane, reason = (
            CatalogLane.OFFICIAL_SECONDARY,
            MaterialLane.OFFICIAL_GUIDANCE,
            "official_secondary_path",
        )
        material_type = "official_guidance"
    elif re.search(
        r"\b(journal(?:s)?|article(?:s)?|book(?:s)?|chapter(?:s)?|thesis|dissertation|treatise)\b",
        value,
    ):
        lane, ingestion_lane, reason = (
            CatalogLane.SCHOLARSHIP,
            MaterialLane.SECONDARY_SCHOLARSHIP,
            "scholarship_path",
        )
        material_type = "book" if re.search(r"\b(book|chapter|treatise)\b", value) else "journal"
    else:
        lane, ingestion_lane, reason = (
            CatalogLane.PRIVATE_TEACHING,
            MaterialLane.LECTURE_NOTE,
            "conservative_private_teaching_default",
        )
        if re.search(r"\bseminar\b", value):
            material_type = "seminar"
        elif re.search(r"\btutorial\b", value):
            material_type = "tutorial"
        elif re.search(r"\blecture\b", value):
            material_type = "lecture"
        else:
            material_type = "course_note"

    subject, subject_secondary, subject_codes = _subject_classification(value)

    jurisdiction, ingestion_jurisdiction = _jurisdiction_classification(value)
    return _Classification(
        lane,
        ingestion_lane,
        subject,
        jurisdiction,
        ingestion_jurisdiction,
        reason,
        (reason,),
        "path_only",
        material_type,
        subject_secondary,
        subject_codes,
        "path_only" if subject != "general" else "uncertain",
    )


def _refine_classification(
    path_classification: _Classification, parsed: ParseResult
) -> _Classification:
    """Apply conservative, deterministic content signals after parsing.

    Only fixed signal codes are persisted. Source prose is inspected in memory
    and never copied into classification metadata or review reasons.
    """

    if not parsed.is_ready:
        return replace(
            path_classification,
            signal_codes=("content_unavailable",),
            confidence="unavailable",
        )
    text = "\n".join(block.text for block in parsed.body_blocks)[:300_000]
    path_classification = _refine_subject_classification(path_classification, text)
    folded = " ".join(text.casefold().split())
    opening = " ".join(text[:20_000].casefold().split())

    explicit_teaching_document = bool(
        path_classification.material_type_candidate
        in {"lecture", "seminar", "tutorial", "course_note"}
        and re.search(
            r"\b(?:seminar|lecture|tutorial|module|course)\b.{0,80}"
            r"\b(?:handbook|slides?|notes?|materials?|learning outcomes?)\b|"
            r"\b(?:handbook|slides?|learning outcomes?)\b",
            opening,
        )
    )
    if explicit_teaching_document:
        marker = next(
            (value for value in ("seminar", "lecture", "tutorial") if value in opening),
            path_classification.material_type_candidate,
        )
        return _content_override(
            path_classification,
            lane=CatalogLane.PRIVATE_TEACHING,
            ingestion_lane=MaterialLane.LECTURE_NOTE,
            reason="private_teaching_document_high_confidence",
            signal_codes=("teaching_document_header",),
            material_type=(
                marker if marker in {"seminar", "lecture", "tutorial"} else "course_note"
            ),
        )

    journal_publication = bool(
        re.search(
            r"\binternational company and commercial law review\b|\bi\.c\.c\.l\.r\.",
            opening,
        )
    )
    if path_classification.lane is CatalogLane.SCHOLARSHIP and journal_publication:
        return _content_override(
            path_classification,
            lane=CatalogLane.SCHOLARSHIP,
            ingestion_lane=MaterialLane.SECONDARY_SCHOLARSHIP,
            reason="journal_content_high_confidence",
            signal_codes=("scholarship_path", "named_journal_header"),
            material_type="journal",
        )

    neutral = re.search(
        r"\[(?:19|20)\d{2}\]\s+(?:UKSC|UKHL|UKPC|EWCA\s+(?:Civ|Crim)|UKUT|UKFTT|EWHC\s+\d+\s+\([A-Za-z]+\)|EUECJ)\s+\d*",
        text[:5_000],
        re.IGNORECASE,
    )
    judgment_heading = bool(
        re.search(
            r"\b(?:approved judgment|judgment of the court|neutral citation number|handed down)\b",
            opening,
        )
    )
    court_heading = bool(
        re.search(
            r"\bin the (?:supreme court|court of appeal|high court|upper tribunal|first-tier tribunal)\b",
            opening,
        )
    )
    numbered_paragraphs = len(
        re.findall(r"(?<!\S)\[(?:[1-9]\d{0,2}[A-Za-z]?)\]\s+", text[:150_000])
    )
    path_case_corroboration = (
        path_classification.lane is CatalogLane.PRIMARY_AUTHORITY
        and path_classification.material_type_candidate == "case"
    )
    if neutral and (
        judgment_heading or court_heading or (path_case_corroboration and numbered_paragraphs >= 2)
    ):
        codes = ["neutral_citation"]
        if judgment_heading:
            codes.append("judgment_heading")
        if court_heading:
            codes.append("court_heading")
        if numbered_paragraphs >= 2:
            codes.append("numbered_judgment_paragraphs")
        if path_case_corroboration:
            codes.append("case_path_corroboration")
        return _content_override(
            path_classification,
            lane=CatalogLane.PRIMARY_AUTHORITY,
            ingestion_lane=MaterialLane.PRIMARY_AUTHORITY,
            reason="case_content_high_confidence",
            signal_codes=codes,
            material_type="case",
        )

    act_header = bool(
        re.search(
            r"\b(?:19|20)\d{2}\s+chapter\s+\d+[a-z]?\b|"
            r"\bb\s*e\s+it\s+enacted\s+by\s+the\s+"
            r"(?:k\s*i\s*n\s*g|queen).{0,80}m\s*o\s*s\s*t\s+excellent\s+majesty\b",
            opening,
        )
    )
    if (
        not act_header
        and path_classification.lane is CatalogLane.PRIMARY_AUTHORITY
        and path_classification.material_type_candidate == "legislation"
    ):
        act_header = bool(
            re.search(r"\ban\s+act\s+to\b", opening[:4_000])
            and re.search(r"\bchapter\s+\d+[a-z]?\b", opening[:4_000])
        )
    instrument_header = bool(
        re.search(
            r"\b(?:statutory instruments?|draft statutory instrument|the .{3,120} regulations (?:19|20)\d{2})\b",
            opening,
        )
    )
    rules_header = bool(
        re.search(
            r"\b(?:rules of court|procedure rules|the .{3,120} rules (?:19|20)\d{2})\b", opening
        )
    )
    provision_markers = len(
        re.findall(r"\b(?:section|regulation|article|rule)\s+\d+[A-Za-z]?\b", text[:150_000], re.I)
    )
    manifest_legislation = (
        path_classification.lane is CatalogLane.PRIMARY_AUTHORITY
        and path_classification.material_type_candidate == "legislation"
        and provision_markers >= 2
    )
    if act_header or instrument_header or rules_header or manifest_legislation:
        codes = []
        if act_header:
            codes.append("enactment_header")
        if instrument_header:
            codes.append("statutory_instrument_header")
        if rules_header:
            codes.append("rules_header")
        if provision_markers:
            codes.append("explicit_provision_markers")
        if manifest_legislation:
            codes.append("legislation_path_corroboration")
        material_type = (
            "rule"
            if rules_header and not (act_header or instrument_header or manifest_legislation)
            else "legislation"
        )
        return _content_override(
            path_classification,
            lane=CatalogLane.PRIMARY_AUTHORITY,
            ingestion_lane=MaterialLane.PRIMARY_AUTHORITY,
            reason="legislation_content_high_confidence",
            signal_codes=codes,
            material_type=material_type,
        )

    official_body = bool(
        re.search(
            r"\b(?:law commission|ministry of justice|judiciary of england and wales|financial conduct authority|competition and markets authority|information commissioner's office|uk parliament|house of commons|house of lords)\b",
            opening,
        )
    )
    official_document = bool(
        re.search(
            r"\b(?:official guidance|guidance|consultation paper|command paper|report)\b", opening
        )
    )
    if official_body and official_document and not path_case_corroboration:
        return _content_override(
            path_classification,
            lane=CatalogLane.OFFICIAL_SECONDARY,
            ingestion_lane=MaterialLane.OFFICIAL_GUIDANCE,
            reason="official_guidance_content_high_confidence",
            signal_codes=("official_body", "official_document_type"),
            material_type="official_guidance",
        )

    doi = bool(re.search(r"\b10\.\d{4,9}/[-._;()/:A-Z0-9]+", text, re.I))
    abstract = bool(re.search(r"(?:^|\n)\s*abstract\b", text[:80_000], re.I))
    keywords = bool(re.search(r"(?:^|\n)\s*key\s*words?\b|\bkeywords\s*:", text[:80_000], re.I))
    isbn = bool(
        re.search(r"\bISBN(?:-1[03])?\s*:?[\s-]*(?:97[89][\s-]*)?\d[\d\s-]{8,16}\b", text, re.I)
    )
    if doi and (abstract or keywords):
        codes = ["doi"]
        if abstract:
            codes.append("abstract_heading")
        if keywords:
            codes.append("keywords_heading")
        return _content_override(
            path_classification,
            lane=CatalogLane.SCHOLARSHIP,
            ingestion_lane=MaterialLane.SECONDARY_SCHOLARSHIP,
            reason="journal_content_high_confidence",
            signal_codes=codes,
            material_type="journal",
        )
    if isbn and re.search(r"\b(?:published by|copyright|table of contents)\b", opening):
        return _content_override(
            path_classification,
            lane=CatalogLane.SCHOLARSHIP,
            ingestion_lane=MaterialLane.BOOK_OR_TREATISE,
            reason="book_content_high_confidence",
            signal_codes=("isbn", "book_front_matter"),
            material_type="book",
        )

    rubric = bool(
        re.search(
            r"\b(?:marking criteria|mark scheme|assessment criteria|grade descriptors?)\b",
            folded,
        )
        and re.search(
            r"\b(?:70\+|70\s*(?:-|–)\s*79|first(?:-| )class|60\s*(?:-|–)\s*69)\b",
            folded,
        )
    )
    explicit_feedback = bool(
        re.search(
            r"(?:^|\n)\s*(?:marker feedback|examiner comments?|feedback comments?|"
            r"areas for improvement|final grade|grademark report|formative(?:\s+\d+)?"
            r"\s*:?\s*feedback|feedback\s*(?:&|and)\s*feedforward)\b",
            text[:80_000],
            re.IGNORECASE,
        )
    )
    comment_text = " ".join(comment.text.casefold() for comment in parsed.comments)
    marker_annotations = bool(parsed.comments) and (
        path_classification.material_type_candidate == "marker_feedback"
        and bool(
            re.search(
                r"\b(?:mark|grade|first(?:-| )class|analysis|authority|counterargument|improv)\w*\b",
                comment_text,
            )
        )
    )
    explicit_feedback_path = path_classification.material_type_candidate == "marker_feedback"
    if marker_annotations or rubric or explicit_feedback or explicit_feedback_path:
        if marker_annotations:
            material_type = "marker_feedback"
            codes = ["reviewer_annotations"]
        elif rubric:
            material_type = "rubric"
            codes = ["rubric_heading", "grade_band_descriptors"]
        elif explicit_feedback:
            material_type = "marker_feedback"
            codes = ["explicit_feedback_heading"]
        else:
            material_type = "marker_feedback"
            codes = ["explicit_feedback_path"]
        return _content_override(
            path_classification,
            lane=CatalogLane.ASSESSMENT_GUIDANCE,
            ingestion_lane=MaterialLane.ASSESSMENT_FEEDBACK,
            reason="assessment_content_high_confidence",
            signal_codes=codes,
            material_type=material_type,
        )

    teaching = re.search(
        r"\b(lecture|seminar|tutorial)\s+(?:notes?|materials?|\d+)|\blearning outcomes?\b",
        opening,
    )
    if teaching:
        marker = teaching.group(1) or "course"
        material_type = marker if marker in {"lecture", "seminar", "tutorial"} else "course_note"
        return _content_override(
            path_classification,
            lane=CatalogLane.PRIVATE_TEACHING,
            ingestion_lane=MaterialLane.LECTURE_NOTE,
            reason="private_teaching_content_high_confidence",
            signal_codes=("teaching_heading",),
            material_type=material_type,
        )

    if path_classification.lane is CatalogLane.ASSESSMENT_GUIDANCE:
        # The body may be a raw student answer. Keep it in the assessment lane
        # so the body-exclusion policy applies, but do not call it feedback.
        return replace(
            path_classification,
            reason="assessment_path_body_excluded",
            signal_codes=("assessment_path_guard", "no_marker_signal"),
            confidence="medium",
            material_type_candidate="assessment",
        )
    if path_classification.lane in {
        CatalogLane.PRIMARY_AUTHORITY,
        CatalogLane.OFFICIAL_SECONDARY,
        CatalogLane.SCHOLARSHIP,
    }:
        # Explicit source folders remain staged candidates, never approved
        # evidence. The medium-confidence code tells reviewers that content did
        # not independently establish the material type.
        return replace(
            path_classification,
            reason="path_candidate_content_unconfirmed",
            signal_codes=("path_material_candidate", "no_high_confidence_material_signal"),
            confidence="medium",
        )
    return replace(
        path_classification,
        lane=CatalogLane.PRIVATE_TEACHING,
        ingestion_lane=MaterialLane.LECTURE_NOTE,
        reason="content_uncertain_private_fallback",
        signal_codes=("no_high_confidence_material_signal",),
        confidence="low",
        material_type_candidate="course_note",
    )


def _content_override(
    base: _Classification,
    *,
    lane: CatalogLane,
    ingestion_lane: MaterialLane,
    reason: str,
    signal_codes: Iterable[str],
    material_type: str,
) -> _Classification:
    return replace(
        base,
        lane=lane,
        ingestion_lane=ingestion_lane,
        reason=reason,
        signal_codes=tuple(sorted(set(signal_codes))),
        confidence="high",
        material_type_candidate=material_type,
    )


def _approved_classification_compatible(
    metadata: Mapping[str, Any],
    classification: _Classification,
    *,
    previous_lane: str | None,
) -> bool:
    allowed = {
        CatalogLane.PRIMARY_AUTHORITY: {"case", "legislation", "rule"},
        CatalogLane.OFFICIAL_SECONDARY: {"official_guidance"},
        CatalogLane.SCHOLARSHIP: {"journal", "book"},
        CatalogLane.PRIVATE_TEACHING: {"lecture", "tutorial", "seminar", "course_note"},
        CatalogLane.ASSESSMENT_GUIDANCE: {"assessment", "rubric", "marker_feedback"},
    }
    reviewed_type = str(metadata.get("material_type") or "").strip().casefold()
    if not reviewed_type:
        # Legacy reviews pre-dating typed approval may survive only when the
        # lane itself did not change. They remain non-citable until a later
        # review supplies the now-required typed identity metadata.
        return previous_lane == classification.lane.value
    if reviewed_type not in allowed[classification.lane]:
        return False
    if classification.confidence == "high":
        return reviewed_type == classification.material_type_candidate
    return True


def _document_status(status: ParseStatus, classification: _Classification) -> DocumentStatus:
    if status is ParseStatus.READY:
        return classification.ready_status
    if status is ParseStatus.OCR_REQUIRED:
        return DocumentStatus.OCR_REQUIRED
    if status is ParseStatus.ENCRYPTED:
        return DocumentStatus.ENCRYPTED
    if status in {ParseStatus.UNSUPPORTED, ParseStatus.PARSER_UNAVAILABLE}:
        return DocumentStatus.UNSUPPORTED
    return DocumentStatus.QUARANTINED


def _default_exclusion_reason(status: DocumentStatus) -> str | None:
    return {
        DocumentStatus.OCR_REQUIRED: "ocr_required",
        DocumentStatus.ENCRYPTED: "encrypted_or_restricted",
        DocumentStatus.UNSUPPORTED: "unsupported_file_type",
        DocumentStatus.QUARANTINED: "parse_failed",
    }.get(status)


def _parse_exclusion_reason(path: Path, parsed: ParseResult) -> str:
    non_source_reason = _non_source_exclusion_reason(path)
    if non_source_reason is not None:
        return non_source_reason
    if parsed.status is ParseStatus.ENCRYPTED:
        return "encrypted_or_restricted"
    if parsed.status is ParseStatus.OCR_REQUIRED:
        return "ocr_required"
    if parsed.status is ParseStatus.PARSER_UNAVAILABLE:
        return "parser_dependency_unavailable"
    if parsed.status is ParseStatus.UNSUPPORTED:
        return "unsupported_file_type"
    diagnostics = " ".join(parsed.diagnostics).casefold()
    if any(
        marker in diagnostics
        for marker in ("empty", "malformed", "missing", "unreadable", "invalid header")
    ):
        return "malformed_or_unreadable"
    return "parse_failed"


def _non_source_exclusion_reason(path: Path) -> str | None:
    name = path.name.casefold()
    if name in {".ds_store", ".localized", "desktop.ini", "thumbs.db"}:
        return "metadata_file_excluded"
    if name.startswith(("~$", ".~lock.")) or path.suffix.casefold() in {
        ".lock",
        ".part",
        ".temp",
        ".tmp",
    }:
        return "temporary_file_excluded"
    if is_owner_operational_artifact(path):
        return "owner_operational_artifact_excluded"
    return None


def _document_title(parsed: ParseResult, fallback: str) -> str:
    for block in parsed.body_blocks:
        if block.kind in {BlockKind.TITLE, BlockKind.HEADING} and block.text.strip():
            return safe_summary(block.text, 300)
    return fallback


def _is_explicit_rubric(path: Path) -> bool:
    name = path.stem.casefold().replace("_", " ").replace("-", " ")
    return bool(
        re.search(
            r"\b(rubric|marking (?:criteria|scheme)|assessment criteria|grade descriptors?)\b",
            name,
        )
    )


def _is_explicit_feedback_path(path: Path) -> bool:
    value = " ".join(part.casefold().replace("_", " ").replace("-", " ") for part in path.parts)
    return bool(
        re.search(
            r"\b(feedback|feedforward|examiner comments?|marker comments?|marked|grademark)\b",
            value,
        )
    )


def _chunk_locator(
    heading_path: tuple[str, ...],
    page_start: int | None,
    page_end: int | None,
    ordinal: int,
    metadata: Mapping[str, Any] | None = None,
) -> str:
    legal_locator = str((metadata or {}).get("legal_locator") or "")
    if re.fullmatch(
        r"(?:para [1-9]\d{0,2}[A-Za-z]?|(?:section|regulation|article|rule|schedule) "
        r"\d+[A-Za-z]?(?:\.\d+)?(?:\([0-9A-Za-z]+\))*)",
        legal_locator,
    ):
        return legal_locator
    if page_start is not None:
        return (
            f"p {page_start}" if page_end in {None, page_start} else f"pp {page_start}–{page_end}"
        )
    if heading_path:
        return " > ".join(safe_summary(value, 100) for value in heading_path)
    return f"chunk {ordinal + 1}"


def _path_fingerprint(path: Path) -> str:
    if path.is_symlink():
        return hashlib.sha256(str(path.absolute()).encode("utf-8", "surrogatepass")).hexdigest()
    return path_fingerprint(path)


def _representation_identity(path: Path) -> str:
    """Group privacy-safe same-parent/same-stem representations without storing the stem."""

    stem = " ".join(path.stem.casefold().replace("_", " ").split())
    payload = f"{path.parent.absolute()}\0{stem}".encode("utf-8", "surrogatepass")
    return f"local-representation-sha256:{hashlib.sha256(payload).hexdigest()}"


def _content_source_identity(
    parsed: ParseResult, classification: _Classification | None = None
) -> str | None:
    """Return only a hash of a confidently detected DOI or neutral citation."""

    doi, neutral = _detected_public_identifiers(parsed)
    if doi is not None and (
        classification is None
        or (
            classification.confidence == "high"
            and classification.material_type_candidate in {"journal", "book"}
        )
    ):
        normalized = doi.casefold()
        return f"doi-sha256:{hashlib.sha256(normalized.encode('utf-8')).hexdigest()}"
    if neutral is not None and (
        classification is None
        or (
            classification.confidence == "high" and classification.material_type_candidate == "case"
        )
    ):
        normalized = neutral
        return f"neutral-citation-sha256:{hashlib.sha256(normalized.encode('utf-8')).hexdigest()}"
    return None


def _public_identifier_candidate(
    parsed: ParseResult, classification: _Classification
) -> dict[str, str] | None:
    """Expose only a high-confidence public identifier for human-review prefill."""

    if classification.confidence != "high":
        return None
    doi, neutral = _detected_public_identifiers(parsed)
    if classification.material_type_candidate in {"journal", "book"} and doi is not None:
        return {"scheme": "doi", "value": doi, "stable_identifier": f"doi:{doi}"}
    if classification.material_type_candidate == "case" and neutral is not None:
        return {
            "scheme": "neutral_citation",
            "value": neutral,
            "stable_identifier": f"neutral-citation:{neutral}",
        }
    return None


def _detected_public_identifiers(parsed: ParseResult) -> tuple[str | None, str | None]:
    text = "\n".join(block.text for block in parsed.body_blocks[:80])[:100_000]
    doi_match = re.search(r"(?i)\b10\.\d{4,9}/[-._;()/:A-Z0-9]+", text)
    doi = doi_match.group(0).rstrip(".,;)").casefold() if doi_match else None
    neutral_match = re.search(
        r"(?i)\[(?:19|20)\d{2}\]\s+(?:(?:UKSC|UKHL|UKPC|EWCA\s+(?:Civ|Crim)|UKUT|UKFTT|EUECJ)\s+\d+|EWHC\s+\d+\s+\([A-Za-z]+\))",
        text,
    )
    neutral = " ".join(neutral_match.group(0).upper().split()) if neutral_match else None
    return doi, neutral


def _load_alias_secret(settings: Settings, cipher: LocalCipher) -> bytes:
    """Load a stable deployment secret without persisting it in plaintext."""

    secret_path = settings.vault_dir / "alias-secret.enc"

    def read_existing() -> bytes:
        try:
            value = bytes.fromhex(cipher.decrypt_text(secret_path.read_bytes()))
        except (OSError, ValueError) as exc:
            raise RuntimeError("encrypted ingestion alias secret is unreadable") from exc
        if len(value) != 32:
            raise RuntimeError("encrypted ingestion alias secret is invalid")
        return value

    if secret_path.exists():
        return read_existing()
    value = os.urandom(32)
    encrypted = cipher.encrypt_text(value.hex())
    try:
        descriptor = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return read_existing()
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encrypted)
        handle.flush()
        os.fsync(handle.fileno())
    return value


def _stable_id(prefix: str, *values: str) -> str:
    digest = hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:40]}"


def _chunk_manifest_sha256(chunks: tuple[StructuralChunk, ...]) -> str:
    payload = [
        {
            "heading_path": list(chunk.heading_path),
            "ordinal": ordinal,
            "stream": chunk.stream,
            "structural_chunk_id": chunk.chunk_id,
            "text_sha256": hashlib.sha256(chunk.text.encode("utf-8")).hexdigest(),
        }
        for ordinal, chunk in enumerate(chunks)
    ]
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _relative_path(settings: Settings, path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(settings.project_root.resolve()))
    except ValueError:
        # Custom Settings used by embedding applications may place data on a
        # separate volume.  The path contains only vault hashes, never aliases.
        return str(resolved)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
