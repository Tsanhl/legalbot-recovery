"""Fail-closed, answer-scoped processing for user uploads.

Question uploads are deliberately kept outside the source catalogue and every
immutable index build.  They may provide scrubbed factual/contextual snippets
or fixed-taxonomy issue-spotting signals, but can never become legal evidence
without the ordinary source review and index-promotion workflow.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from sqlite3 import Row

from ..config import Settings
from ..crypto import KeyUnavailableError, LocalCipher
from ..db import Database
from ..ingestion.chunking import StructuralChunker
from ..ingestion.markdown import CanonicalMarkdownConverter
from ..ingestion.models import (
    Jurisdiction,
    ParseResult,
    Provenance,
    SourceIdentity,
    StructuralChunk,
)
from ..ingestion.models import (
    MaterialLane as IngestionLane,
)
from ..ingestion.parsers import ParserRegistry
from ..privacy import prompt_injection_hits, safe_source_name, scrub_pii
from ..types import IssueSpottingNote, MaterialLane, UploadContextSpan
from .upload_vault import migrate_plaintext_upload, read_upload

MAX_UPLOAD_CONTEXT_SPANS = 8
MAX_UPLOAD_CONTEXT_CHARS = 6_000
MAX_CONTEXT_SPAN_CHARS = 1_500
_TOKEN_RE = re.compile(r"[a-z0-9]{2,}", re.IGNORECASE)
_SAFE_DISPLAY_RE = re.compile(r"^source-[0-9a-f]{12}\.[a-z0-9]{1,12}$")
_OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
_GENERIC_UPLOAD_MEDIA_TYPES = frozenset({"", "application/octet-stream"})
_UPLOAD_MEDIA_TYPES: dict[str, tuple[str, frozenset[str]]] = {
    ".pdf": ("application/pdf", frozenset({"application/pdf"})),
    ".docx": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        frozenset(
            {
                "application/zip",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            }
        ),
    ),
    ".doc": ("application/msword", frozenset({"application/msword"})),
    ".pptx": (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        frozenset(
            {
                "application/zip",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            }
        ),
    ),
    ".ppt": (
        "application/vnd.ms-powerpoint",
        frozenset({"application/vnd.ms-powerpoint"}),
    ),
    ".odt": (
        "application/vnd.oasis.opendocument.text",
        frozenset(
            {
                "application/zip",
                "application/vnd.oasis.opendocument.text",
            }
        ),
    ),
    ".html": ("text/html", frozenset({"text/html"})),
    ".htm": ("text/html", frozenset({"text/html"})),
    ".xml": ("application/xml", frozenset({"application/xml", "text/xml"})),
    ".md": ("text/markdown", frozenset({"text/markdown", "text/plain"})),
    ".markdown": (
        "text/markdown",
        frozenset({"text/markdown", "text/plain"}),
    ),
    ".txt": ("text/plain", frozenset({"text/plain"})),
}


class UploadReferenceError(ValueError):
    """An upload row does not resolve to an intact file in the local vault."""


def validate_upload_media(data: bytes, *, filename: str, claimed_media_type: str | None) -> str:
    """Return a canonical media type after extension, MIME and magic checks."""

    suffix = Path(filename).suffix.casefold()
    policy = _UPLOAD_MEDIA_TYPES.get(suffix)
    if policy is None or not data:
        raise UploadReferenceError("Upload type is unsupported or empty")
    canonical, allowed_claims = policy
    claimed = (claimed_media_type or "").split(";", 1)[0].strip().casefold()
    if claimed not in _GENERIC_UPLOAD_MEDIA_TYPES and claimed not in allowed_claims:
        raise UploadReferenceError("Upload MIME type conflicts with its extension")

    stripped = data.lstrip(b"\xef\xbb\xbf\x00\t\r\n ")
    valid = False
    if suffix == ".pdf":
        valid = data.startswith(b"%PDF-")
    elif suffix in {".doc", ".ppt"}:
        valid = data.startswith(_OLE_MAGIC)
    elif suffix in {".docx", ".pptx", ".odt"}:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = archive.infolist()
                names = {item.filename for item in members}
                total_uncompressed = sum(item.file_size for item in members)
                required = (
                    {"[Content_Types].xml", "word/document.xml"}
                    if suffix == ".docx"
                    else {"[Content_Types].xml", "ppt/presentation.xml"}
                    if suffix == ".pptx"
                    else {"mimetype", "content.xml"}
                )
                valid = (
                    len(members) <= 10_000
                    and total_uncompressed <= 256 * 1024 * 1024
                    and required.issubset(names)
                )
        except (OSError, ValueError, zipfile.BadZipFile):
            valid = False
    elif suffix in {".html", ".htm"}:
        prefix = stripped[:512].lower()
        valid = any(
            marker in prefix for marker in (b"<!doctype html", b"<html", b"<head", b"<body")
        )
    elif suffix == ".xml":
        valid = stripped.startswith(b"<") and b"\x00" not in stripped[:4096]
    else:
        try:
            data.decode("utf-8-sig")
            valid = b"\x00" not in data
        except UnicodeDecodeError:
            valid = False
    if not valid:
        raise UploadReferenceError("Upload bytes do not match the declared document type")
    return canonical


@dataclass(frozen=True, slots=True)
class UploadSourceReviewSubmission:
    review_id: str
    status: str
    content_sha256: str
    duplicate: bool


def migrate_legacy_uploads(
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
) -> int:
    """Encrypt legacy plaintext upload blobs under the shared startup lock.

    The file replacement precedes the DB marker.  If a process stops between
    those operations, the next run recognises already-encrypted bytes by
    decrypting and checking the original plaintext hash before setting the
    marker.  No filename or content enters logs.
    """

    rows = database.fetchall(
        """
        SELECT id, content_sha256, byte_size, vault_path
        FROM uploads WHERE encrypted_blob=0
        ORDER BY created_at, id
        """
    )
    migrated = 0
    root = settings.upload_dir.resolve(strict=True)
    for row in rows:
        stored = Path(str(row["vault_path"]))
        try:
            if stored.is_absolute() or ".." in stored.parts:
                raise ValueError
            path = (settings.project_root / stored).resolve(strict=True)
            if not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
                raise ValueError
            expected_digest = str(row["content_sha256"])
            expected_size = int(row["byte_size"])
            on_disk = path.read_bytes()
            if (
                len(on_disk) == expected_size
                and hashlib.sha256(on_disk).hexdigest() == expected_digest
            ):
                migrate_plaintext_upload(path, cipher=cipher)
            else:
                plaintext = cipher.decrypt_bytes(on_disk)
                if (
                    len(plaintext) != expected_size
                    or hashlib.sha256(plaintext).hexdigest() != expected_digest
                ):
                    raise ValueError
        except (KeyUnavailableError, OSError, TypeError, ValueError):
            raise UploadReferenceError("A legacy upload failed encrypted-vault migration") from None
        database.execute(
            """
            UPDATE uploads
            SET encrypted_blob=1,
                retention_until=COALESCE(retention_until, ?),
                quarantine_status=CASE
                  WHEN quarantine_status='' THEN 'unreviewed'
                  ELSE quarantine_status END
            WHERE id=? AND encrypted_blob=0
            """,
            (
                (datetime.now(UTC) + timedelta(days=30)).isoformat(),
                str(row["id"]),
            ),
        )
        migrated += 1
    return migrated


def purge_expired_uploads(
    settings: Settings,
    database: Database,
    *,
    now: datetime | None = None,
) -> int:
    """Expire unpinned uploads and remove only unreferenced encrypted blobs."""

    cutoff = (now or datetime.now(UTC)).isoformat()
    rows = database.fetchall(
        """
        SELECT id, vault_path FROM uploads
        WHERE review_pinned=0 AND retention_until IS NOT NULL
          AND retention_until<=? AND status IN ('staged', 'expired')
        ORDER BY retention_until, id
        """,
        (cutoff,),
    )
    root = settings.upload_dir.resolve(strict=True)
    expired = 0
    for row in rows:
        upload_id = str(row["id"])
        database.execute(
            """
            UPDATE uploads SET status='expired', quarantine_status='expired'
            WHERE id=? AND review_pinned=0
            """,
            (upload_id,),
        )
        still_referenced = database.fetchone(
            """
            SELECT COUNT(*) AS n FROM uploads
            WHERE vault_path=? AND id<>? AND status<>'expired'
            """,
            (str(row["vault_path"]), upload_id),
        )
        if still_referenced is None:
            raise RuntimeError("upload reference count disappeared")
        if int(still_referenced["n"] or 0) == 0:
            stored = Path(str(row["vault_path"]))
            try:
                if stored.is_absolute() or ".." in stored.parts:
                    raise ValueError
                path = (settings.project_root / stored).resolve(strict=False)
                if not path.is_relative_to(root):
                    raise ValueError
                path.unlink(missing_ok=True)
            except (OSError, ValueError):
                # The row remains explicitly expired. A later startup retries
                # the exact path; no broad directory deletion is attempted.
                continue
        expired += 1
    return expired


@dataclass(frozen=True, slots=True)
class ValidatedUpload:
    id: str
    content_sha256: str
    safe_display_name: str
    media_type: str
    byte_size: int
    path: Path
    encrypted_blob: bool


@dataclass(frozen=True, slots=True)
class UploadPreparation:
    contexts: tuple[UploadContextSpan, ...]
    issue_notes: tuple[IssueSpottingNote, ...]
    review_reasons: tuple[str, ...]
    uploads_considered: int

    @property
    def needs_review(self) -> bool:
        return bool(self.review_reasons)


def validate_upload_references(
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    upload_ids: Sequence[str],
) -> tuple[ValidatedUpload, ...]:
    """Resolve upload IDs to hash-verified files below ``data/uploads``.

    Error text is intentionally generic so a forged ID cannot reveal paths,
    filenames, digests, or whether a particular local file exists.
    """

    if len(set(upload_ids)) != len(upload_ids):
        raise UploadReferenceError("Upload references must be unique")
    return tuple(_validate_one(settings, database, cipher, upload_id) for upload_id in upload_ids)


def submit_upload_for_source_review(
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    upload_id: str,
) -> UploadSourceReviewSubmission:
    """Submit a verified content hash without creating a canonical source.

    This queue records only that an owner wants the encrypted object assessed
    for source intake.  It cannot establish legal identity, rights,
    jurisdiction, currentness, citation metadata, index eligibility or ACTIVE
    promotion; those remain in the ordinary immutable source workflow.
    """

    upload = _validate_one(settings, database, cipher, upload_id)
    data = read_upload(upload.path, cipher=cipher, encrypted=upload.encrypted_blob)
    parsed = ParserRegistry.default().parse(data, filename=upload.safe_display_name)
    if not parsed.is_ready:
        database.update_upload_lifecycle(upload.id, quarantine_status="held")
        raise UploadReferenceError("Upload requires parser or OCR review before source intake")
    extracted = "\n".join(block.text for block in parsed.body_blocks)
    if prompt_injection_hits(extracted):
        database.update_upload_lifecycle(upload.id, quarantine_status="blocked")
        raise UploadReferenceError("Upload failed document-instruction quarantine checks")

    review_id = f"review-upload-source-{upload.content_sha256}"
    duplicate = False
    with database.transaction() as conn:
        existing = conn.execute(
            "SELECT status, decided_at FROM reviews WHERE id=?", (review_id,)
        ).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO reviews(
                  id, review_type, target_id, status, reason, created_at
                ) VALUES (?, 'upload_source_candidate', ?, 'pending', ?, ?)
                """,
                (
                    review_id,
                    upload.content_sha256,
                    "Verified encrypted upload submitted for source-intake review only; "
                    "identity, rights, jurisdiction, currentness and citation remain unverified",
                    datetime.now(UTC).isoformat(),
                ),
            )
            review_status = "pending"
        else:
            duplicate = True
            review_status = str(existing["status"])
        if review_status == "pending":
            conn.execute(
                """
                UPDATE uploads SET review_pinned=1, quarantine_status='passed',
                  review_completed_at=NULL
                WHERE content_sha256=? AND status='staged'
                """,
                (upload.content_sha256,),
            )
        elif review_status in {"approved", "rejected"}:
            # A duplicate upload inherits the completed intake decision. It
            # must never re-pin bytes indefinitely or revive a rejected object
            # as usable request context.
            completed_at = str(existing["decided_at"] or datetime.now(UTC).isoformat())
            retention_until = (datetime.now(UTC) + timedelta(days=30)).isoformat()
            conn.execute(
                """
                UPDATE uploads SET review_pinned=0, review_completed_at=?,
                  retention_until=?, quarantine_status=?
                WHERE content_sha256=? AND status='staged'
                """,
                (
                    completed_at,
                    retention_until,
                    "passed" if review_status == "approved" else "rejected",
                    upload.content_sha256,
                ),
            )
        else:
            raise UploadReferenceError("Upload source-intake review has an invalid status")
    return UploadSourceReviewSubmission(
        review_id=review_id,
        status=review_status,
        content_sha256=upload.content_sha256,
        duplicate=duplicate,
    )


class QuestionUploadProcessor:
    def __init__(self, *, settings: Settings, database: Database, cipher: LocalCipher) -> None:
        self.settings = settings
        self.database = database
        self.cipher = cipher
        self.parsers = ParserRegistry.default()
        self.converter = CanonicalMarkdownConverter()
        self.chunker = StructuralChunker()

    def prepare(
        self,
        *,
        job_id: str | None = None,
        upload_ids: Sequence[str],
        question: str,
        jurisdiction: str,
        subject: str | None,
    ) -> UploadPreparation:
        contexts: list[UploadContextSpan] = []
        notes: list[IssueSpottingNote] = []
        reasons: list[str] = []
        total_chars = 0

        expected_bindings: dict[str, Row] = {}
        if job_id is not None:
            binding_rows = self.database.job_upload_bindings(job_id)
            if tuple(str(row["upload_id"]) for row in binding_rows) != tuple(upload_ids):
                raise UploadReferenceError("Job upload snapshot differs from its admitted request")
            expected_bindings = {str(row["upload_id"]): row for row in binding_rows}

        for ordinal, upload_id in enumerate(upload_ids, 1):
            label = f"Attached material {ordinal}"
            try:
                upload = _validate_one(self.settings, self.database, self.cipher, upload_id)
            except UploadReferenceError:
                if job_id is not None:
                    raise UploadReferenceError(
                        "Job upload snapshot failed local-vault integrity replay"
                    ) from None
                reasons.append(f"{label} was unavailable or failed local-vault integrity checks")
                continue
            expected = expected_bindings.get(upload_id)
            if expected is not None and (
                upload.content_sha256 != str(expected["content_sha256"])
                or upload.byte_size != int(expected["byte_size"])
                or upload.media_type != str(expected["media_type"])
            ):
                raise UploadReferenceError("Job upload snapshot changed after admission")

            data = read_upload(
                upload.path,
                cipher=self.cipher,
                encrypted=upload.encrypted_blob,
            )
            parsed = self.parsers.parse(data, filename=upload.safe_display_name)
            if not parsed.is_ready:
                reasons.append(
                    f"{label} could not be used as context because parsing ended with "
                    f"the named status '{parsed.status.value}'"
                )
                continue

            lane = self._material_lane(upload, parsed)
            # Canonicalisation is mandatory but answer-scoped: the Markdown is
            # created in memory and is never inserted into source_versions or an index.
            provenance = Provenance.now(
                source_identity=SourceIdentity("question-upload-sha256", upload.content_sha256),
                title=upload.safe_display_name,
                source_kind="answer_scoped_upload",
                jurisdiction=_ingestion_jurisdiction(jurisdiction),
                material_lane=_ingestion_lane(lane),
                content_sha256=upload.content_sha256,
                private_locator_digest=hashlib.sha256(upload.id.encode()).hexdigest(),
                extra={"authority": False, "persistence": "answer_scoped"},
            )
            bundle = self.converter.convert(parsed, provenance)
            if prompt_injection_hits(bundle.body_markdown):
                reasons.append(
                    f"{label} was excluded because it contained document-borne instruction patterns"
                )
                continue

            chunks = self.chunker.chunk_body(parsed, document_sha256=upload.content_sha256)
            selected = _select_chunks(chunks, question, MAX_UPLOAD_CONTEXT_SPANS - len(contexts))
            for chunk in selected:
                remaining = MAX_UPLOAD_CONTEXT_CHARS - total_chars
                if remaining <= 0:
                    break
                safe_text = scrub_pii(chunk.text, self.settings.owner_identifiers).strip()[
                    : min(MAX_CONTEXT_SPAN_CHARS, remaining)
                ]
                if not safe_text or prompt_injection_hits(safe_text):
                    continue
                context_id = _stable_id("upload-context", upload.id, chunk.chunk_id)
                locator = _safe_locator(chunk)
                context = UploadContextSpan(
                    id=context_id,
                    text=safe_text,
                    lane=lane,
                    locator=locator,
                    subject=subject,
                    jurisdiction=jurisdiction,
                )
                contexts.append(context)
                notes.append(
                    IssueSpottingNote(
                        id=_stable_id("upload-issue", upload.id, chunk.chunk_id),
                        source_version_id=_stable_id("upload-transient", upload.id),
                        chunk_id=chunk.chunk_id,
                        text=safe_text,
                        jurisdiction=jurisdiction,
                        subject=subject or "general",
                        content_sha256=upload.content_sha256,
                        index_build_id="answer-scoped-upload",
                    )
                )
                total_chars += len(safe_text)
                if len(contexts) >= MAX_UPLOAD_CONTEXT_SPANS:
                    break

            if lane in {
                MaterialLane.PRIMARY_AUTHORITY,
                MaterialLane.OFFICIAL_SECONDARY,
                MaterialLane.SCHOLARSHIP,
            } and not self._has_reviewed_identity(upload.content_sha256):
                reasons.append(
                    f"{label} appears potentially citable but remains context-only until its "
                    "identity, currentness, rights and citation metadata are human-reviewed and "
                    "promoted through an immutable index build"
                )
            if len(contexts) >= MAX_UPLOAD_CONTEXT_SPANS:
                break

        return UploadPreparation(
            contexts=tuple(contexts),
            issue_notes=tuple(notes),
            review_reasons=tuple(dict.fromkeys(reasons)),
            uploads_considered=len(upload_ids),
        )

    def _material_lane(self, upload: ValidatedUpload, parsed: ParseResult) -> MaterialLane:
        row = self.database.fetchone(
            """
            SELECT lane FROM documents
            WHERE content_sha256=? AND duplicate_of IS NULL
            ORDER BY CASE lane
              WHEN 'primary_authority' THEN 1
              WHEN 'official_secondary' THEN 2
              WHEN 'scholarship' THEN 3
              WHEN 'assessment_guidance' THEN 4
              ELSE 5 END
            LIMIT 1
            """,
            (upload.content_sha256,),
        )
        if row is not None and str(row["lane"] or "") in {item.value for item in MaterialLane}:
            return MaterialLane(str(row["lane"]))
        return _infer_lane(parsed)

    def _has_reviewed_identity(self, content_sha256: str) -> bool:
        rows = self.database.fetchall(
            """
            SELECT sv.review_status, sv.currentness_status, sv.stable_identifier,
                   sv.metadata_json
            FROM source_versions sv
            JOIN documents d ON d.id=sv.document_id
            WHERE d.content_sha256=? AND d.duplicate_of IS NULL
              AND sv.superseded_by IS NULL
              AND sv.version_sha256=d.content_sha256
            """,
            (content_sha256,),
        )
        for row in rows:
            try:
                metadata = json.loads(str(row["metadata_json"] or "{}"))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if (
                row["review_status"] == "approved"
                and bool(row["stable_identifier"])
                and bool(metadata.get("identity_verified"))
                and bool(metadata.get("currentness_verified"))
                and isinstance(metadata.get("citation_data"), dict)
                and bool(metadata["citation_data"])
            ):
                return True
        return False


def _validate_one(
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    upload_id: str,
) -> ValidatedUpload:
    row = database.fetchone("SELECT * FROM uploads WHERE id=?", (upload_id,))
    if row is None or row["status"] != "staged":
        raise UploadReferenceError("Upload reference is unavailable")
    return _validate_row(settings, row, cipher)


def _validate_row(settings: Settings, row: Row, cipher: LocalCipher) -> ValidatedUpload:
    try:
        digest = str(row["content_sha256"])
        display = str(row["safe_display_name"])
        stored = Path(str(row["vault_path"]))
        expected_size = int(row["byte_size"])
        encrypted_blob = bool(row["encrypted_blob"])
        retention_until = str(row["retention_until"] or "")
        review_pinned = bool(row["review_pinned"])
        quarantine_status = str(row["quarantine_status"] or "unreviewed")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError
        if not _SAFE_DISPLAY_RE.fullmatch(display):
            raise ValueError
        if display != safe_source_name(Path(display), digest):
            raise ValueError
        if stored.is_absolute() or ".." in stored.parts:
            raise ValueError
        if quarantine_status in {"blocked", "rejected", "expired"}:
            raise ValueError
        if retention_until and not review_pinned:
            expiry = datetime.fromisoformat(retention_until)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            if expiry <= datetime.now(UTC):
                raise ValueError
        root = settings.upload_dir.resolve(strict=True)
        path = (settings.project_root / stored).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
            raise ValueError
        stat = path.stat()
        if stat.st_size <= 0:
            raise ValueError
        data = read_upload(path, cipher=cipher, encrypted=encrypted_blob)
        if len(data) != expected_size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError
        validate_upload_media(
            data,
            filename=display,
            claimed_media_type=str(row["media_type"]),
        )
    except (KeyUnavailableError, OSError, TypeError, ValueError, UploadReferenceError):
        raise UploadReferenceError("Upload reference failed local-vault validation") from None
    return ValidatedUpload(
        id=str(row["id"]),
        content_sha256=digest,
        safe_display_name=display,
        media_type=str(row["media_type"]),
        byte_size=expected_size,
        path=path,
        encrypted_blob=encrypted_blob,
    )


def _infer_lane(parsed: ParseResult) -> MaterialLane:
    sample = "\n".join(block.text for block in parsed.body_blocks)[:120_000].casefold()
    if (
        parsed.comments
        or parsed.revisions
        or re.search(
            r"\b(marking criteria|mark scheme|examiner feedback|grade descriptor|rubric)\b", sample
        )
    ):
        return MaterialLane.ASSESSMENT_GUIDANCE
    if re.search(
        r"\b(?:uksc|ukpc|ewca|ewhc|ukut|ukftt)\s+\d+\b|\b[a-z][a-z ]+ act 20\d{2}\b|\bneutral citation\b",
        sample,
    ):
        return MaterialLane.PRIMARY_AUTHORITY
    if re.search(r"\b(law commission|official guidance|government guidance|regulator)\b", sample):
        return MaterialLane.OFFICIAL_SECONDARY
    if re.search(
        r"\bdoi:\s*10\.|\babstract\b.{0,200}\bkeywords\b|\blaw quarterly review\b", sample
    ):
        return MaterialLane.SCHOLARSHIP
    return MaterialLane.PRIVATE_TEACHING


def _select_chunks(
    chunks: Sequence[StructuralChunk], question: str, limit: int
) -> tuple[StructuralChunk, ...]:
    if limit <= 0:
        return ()
    query_tokens = set(_TOKEN_RE.findall(question.casefold()))
    ranked: list[tuple[float, int, StructuralChunk]] = []
    for chunk in chunks:
        tokens = set(_TOKEN_RE.findall(chunk.text.casefold()))
        overlap = len(tokens & query_tokens)
        density = overlap / max(1, len(tokens))
        score = float(overlap) + density
        ranked.append((score, -chunk.ordinal, chunk))
    ranked.sort(key=lambda value: (value[0], value[1]), reverse=True)
    selected = [item[2] for item in ranked[:limit]]
    # Restore document order after relevance selection so factual context is coherent.
    return tuple(sorted(selected, key=lambda item: item.ordinal))


def _safe_locator(chunk: StructuralChunk) -> str:
    if chunk.page_start is not None:
        if chunk.page_end in {None, chunk.page_start}:
            return f"attached material p {chunk.page_start}"
        return f"attached material pp {chunk.page_start}–{chunk.page_end}"
    return f"attached material chunk {chunk.ordinal + 1}"


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode()).hexdigest()
    return f"{prefix}-{digest[:40]}"


def _ingestion_jurisdiction(value: str) -> Jurisdiction:
    key = " ".join(value.casefold().split())
    return {
        "england and wales": Jurisdiction.ENGLAND_WALES,
        "united kingdom": Jurisdiction.UNITED_KINGDOM,
        "uk": Jurisdiction.UNITED_KINGDOM,
        "scotland": Jurisdiction.SCOTLAND,
        "northern ireland": Jurisdiction.NORTHERN_IRELAND,
        "european union": Jurisdiction.EUROPEAN_UNION,
        "eu": Jurisdiction.EUROPEAN_UNION,
    }.get(key, Jurisdiction.COMPARATIVE)


def _ingestion_lane(value: MaterialLane) -> IngestionLane:
    return {
        MaterialLane.PRIMARY_AUTHORITY: IngestionLane.PRIMARY_AUTHORITY,
        MaterialLane.OFFICIAL_SECONDARY: IngestionLane.OFFICIAL_GUIDANCE,
        MaterialLane.SCHOLARSHIP: IngestionLane.SECONDARY_SCHOLARSHIP,
        MaterialLane.PRIVATE_TEACHING: IngestionLane.LECTURE_NOTE,
        MaterialLane.ASSESSMENT_GUIDANCE: IngestionLane.ASSESSMENT_FEEDBACK,
    }[value]
