"""Deletion-free, create-only catalogue intake for reviewed research bytes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import Settings
from ..crypto import LocalCipher
from ..db import Database, utc_iso
from ..ingestion.chunking import StructuralChunker
from ..ingestion.identity import private_locator_digest
from ..ingestion.markdown import CanonicalMarkdownConverter
from ..ingestion.models import Jurisdiction, Provenance, SourceIdentity, StructuralChunk
from ..ingestion.parsers import ParserRegistry
from ..ingestion.privacy import PIIAliaser
from ..ingestion.sanitation import TEXT_SANITATION_SCHEMA, sanitize_parse_result
from ..ingestion.service import (
    _ai_use_policy,
    _chunk_locator,
    _chunk_manifest_sha256,
    _classify,
    _document_title,
    _load_alias_secret,
    _refine_classification,
    _stable_id,
)
from ..privacy import path_fingerprint, safe_source_name
from ..types import MaterialLane

CREATE_ONLY_SOURCE_INTAKE_SCHEMA = "legalbot.research-source-create-only-ingestion.v1"
_WORD_RE = re.compile(r"\b[\w'-]+\b", re.UNICODE)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_LANES = frozenset({MaterialLane.PRIMARY_AUTHORITY, MaterialLane.OFFICIAL_SECONDARY})
_PROCESSING_COMPONENTS = {
    "schema": CREATE_ONLY_SOURCE_INTAKE_SCHEMA,
    "parser_registry": ParserRegistry.schema,
    "text_sanitation": TEXT_SANITATION_SCHEMA,
    "canonical_markdown": CanonicalMarkdownConverter.schema,
    "structural_chunker": StructuralChunker.schema,
    "body_chunks_only": True,
}
CREATE_ONLY_PROCESSING_FINGERPRINT = hashlib.sha256(
    json.dumps(_PROCESSING_COMPONENTS, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()


class CreateOnlySourceIntakeError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class CreateOnlySourceIntakeRequest:
    scan_id: str
    path: Path
    content_sha256: str
    content_type: str
    source_identity: str
    canonical_url_sha256: str
    observed_at: str
    subject: str
    jurisdiction: str
    intake_marker: dict[str, str]


@dataclass(frozen=True, slots=True)
class _VaultObject:
    sha256: str
    size: int
    path: Path


class CreateOnlyResearchSourceIngestor:
    """Parse and persist one new staged source using creation operations only."""

    def __init__(self, settings: Settings, database: Database, cipher: LocalCipher) -> None:
        self.settings = settings
        self.database = database
        self.cipher = cipher

    def ingest(self, request: CreateOnlySourceIntakeRequest) -> dict[str, Any]:
        _validate_request(request)
        path = request.path
        if path.is_symlink() or not path.is_file():
            raise CreateOnlySourceIntakeError("source_intake_materialized_file_invalid")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != request.content_sha256:
            raise CreateOnlySourceIntakeError("source_intake_materialized_content_mismatch")

        self.settings.vault_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.settings.vault_dir.is_symlink() or not self.settings.vault_dir.is_dir():
            raise CreateOnlySourceIntakeError("source_intake_vault_root_invalid")
        aliaser = PIIAliaser(_load_alias_secret(self.settings, self.cipher))
        parsed = sanitize_parse_result(
            ParserRegistry.default().parse(raw, filename=path.name, aliaser=aliaser)
        )
        if not parsed.is_ready:
            raise CreateOnlySourceIntakeError(
                f"source_intake_parse_not_ready:{parsed.status.value}"
            )
        classification = _refine_classification(_classify(path), parsed)
        if classification.lane not in _ALLOWED_LANES:
            raise CreateOnlySourceIntakeError("source_intake_non_authority_content_forbidden")
        jurisdiction_name, ingestion_jurisdiction = _jurisdiction(request.jurisdiction)
        classification = replace(
            classification,
            jurisdiction=jurisdiction_name,
            ingestion_jurisdiction=ingestion_jurisdiction,
            subject=(classification.subject if classification.subject != "general" else request.subject),
        )
        ai_use_policy, ai_use_restriction_codes = _ai_use_policy(parsed)
        if ai_use_policy == "prohibited":
            raise CreateOnlySourceIntakeError("source_intake_content_use_prohibited")

        converter = CanonicalMarkdownConverter()
        chunker = StructuralChunker()
        fingerprint = path_fingerprint(path)
        safe_name = safe_source_name(path, request.content_sha256)
        title = _document_title(parsed, safe_name)
        provenance = Provenance(
            source_identity=SourceIdentity(
                "research_intake",
                request.intake_marker["binding_sha256"],
                version=request.content_sha256,
            ),
            title=title,
            source_kind=classification.reason,
            jurisdiction=classification.ingestion_jurisdiction,
            material_lane=classification.ingestion_lane,
            content_sha256=request.content_sha256,
            retrieved_at=request.observed_at,
            private_locator_digest=private_locator_digest(
                str(path.absolute()), salt=fingerprint.encode("ascii")
            ),
            public_aliases={"display_name": safe_name},
            extra={"parser_format": parsed.document_format.value},
        )
        bundle = converter.convert(parsed, provenance)
        chunks = tuple(
            chunk
            for chunk in chunker.chunk_body(parsed, document_sha256=request.content_sha256)
            if chunk.text.strip() and _WORD_RE.search(chunk.text)
        )
        if not chunks:
            raise CreateOnlySourceIntakeError("source_intake_no_authority_chunks")

        vault_root = self.settings.vault_dir.resolve()
        raw_object = _put_create_only(vault_root, raw)
        body_object = _put_create_only(vault_root, bundle.body_markdown.encode())
        comments_object = _put_create_only(vault_root, bundle.comments_markdown.encode())
        revisions_object = _put_create_only(vault_root, bundle.revisions_markdown.encode())
        provenance_object = _put_create_only(vault_root, bundle.provenance_json.encode())

        binding_sha256 = request.intake_marker["binding_sha256"]
        document_id = _stable_id("research-document", binding_sha256)
        source_version_id = _stable_id(
            "research-source-version",
            document_id,
            request.content_sha256,
            CREATE_ONLY_PROCESSING_FINGERPRINT,
        )
        alias_id = _stable_id("research-alias", fingerprint)
        review_id = _stable_id("review", source_version_id)
        chunk_rows = tuple(
            _chunk_row(source_version_id, chunk, ordinal)
            for ordinal, chunk in enumerate(chunks)
        )
        metadata = {
            "schema": CREATE_ONLY_SOURCE_INTAKE_SCHEMA,
            "processing_fingerprint": CREATE_ONLY_PROCESSING_FINGERPRINT,
            "processing_components": _PROCESSING_COMPONENTS,
            "scan_id": request.scan_id,
            "parser_status": parsed.status.value,
            "parser_format": parsed.document_format.value,
            "classification_reason": classification.reason,
            "classification_signal_codes": list(classification.signal_codes),
            "classification_confidence": classification.confidence,
            "material_type_candidate": classification.material_type_candidate,
            "subject_primary_candidate": classification.subject,
            "subject_secondary_candidates": list(classification.subject_secondary),
            "raw_object_sha256": raw_object.sha256,
            "raw_vault_path": _vault_relative(self.settings, raw_object.path),
            "body_sha256": body_object.sha256,
            "canonical_markdown_path": _vault_relative(self.settings, body_object.path),
            "comments_sha256": comments_object.sha256,
            "comments_markdown_path": _vault_relative(self.settings, comments_object.path),
            "revisions_sha256": revisions_object.sha256,
            "revisions_markdown_path": _vault_relative(self.settings, revisions_object.path),
            "provenance_sha256": provenance_object.sha256,
            "provenance_path": _vault_relative(self.settings, provenance_object.path),
            "selected_chunk_count": len(chunks),
            "chunk_manifest_sha256": _chunk_manifest_sha256(chunks),
            "content_type": request.content_type,
            "official_source_identity_sha256": hashlib.sha256(
                request.source_identity.encode()
            ).hexdigest(),
            "official_canonical_url_sha256": request.canonical_url_sha256,
            "identity_verified": False,
            "currentness_verified": False,
            "currentness_applicable": False,
            "authority_eligible": False,
            "citation_rendering_enabled": False,
            "citation_data": {},
            "canonical_citation": None,
            "ai_use_policy": ai_use_policy,
            "ai_use_restriction_codes": list(ai_use_restriction_codes),
            "eligible_for_model_use": True,
            "research_source_intake": request.intake_marker,
            "comments_preserved_non_authority": True,
            "revisions_preserved_non_authority": True,
        }
        metadata_json = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
        now = utc_iso()
        encrypted_path = self.cipher.encrypt_text(str(path.absolute()))
        already_present = False
        with self.database.transaction() as connection:
            existing_alias = connection.execute(
                "SELECT document_id FROM source_aliases WHERE path_fingerprint=?", (fingerprint,)
            ).fetchone()
            if existing_alias is not None:
                _verify_existing_catalogue(
                    connection,
                    document_id=document_id,
                    source_version_id=source_version_id,
                    review_id=review_id,
                    fingerprint=fingerprint,
                    content_sha256=request.content_sha256,
                    processing_fingerprint=CREATE_ONLY_PROCESSING_FINGERPRINT,
                    marker=request.intake_marker,
                    expected_chunk_rows=chunk_rows,
                )
                already_present = True
            else:
                _assert_catalogue_identities_absent(
                    connection,
                    document_id=document_id,
                    source_version_id=source_version_id,
                    alias_id=alias_id,
                    review_id=review_id,
                    chunk_rows=chunk_rows,
                    content_sha256=request.content_sha256,
                    lane=classification.lane.value,
                    jurisdiction=classification.jurisdiction,
                    subject=classification.subject,
                )
                connection.execute(
                    """
                    INSERT INTO documents(
                      id, content_sha256, source_identity_id, representation_group_id,
                      safe_display_name, media_type, status, lane, subject_primary,
                      subject_secondary_json, jurisdiction, duplicate_of,
                      retrieval_canonical, has_annotations, searchable_text,
                      dedupe_status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, ?, 1, 'new', ?, ?)
                    """,
                    (
                        document_id,
                        request.content_sha256,
                        f"research-intake:{binding_sha256}",
                        f"research-intake:{binding_sha256}",
                        safe_name,
                        request.content_type,
                        classification.ready_status.value,
                        classification.lane.value,
                        classification.subject,
                        json.dumps(list(classification.subject_secondary)),
                        classification.jurisdiction,
                        int(bool(parsed.comments or parsed.revisions)),
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO source_aliases(
                      id, document_id, path_fingerprint, encrypted_path, imported_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (alias_id, document_id, fingerprint, encrypted_path, now),
                )
                connection.execute(
                    """
                    INSERT INTO source_versions(
                      id, document_id, authority_identity_id, version_sha256,
                      canonical_markdown_path, title, stable_identifier,
                      currentness_status, review_status, processing_fingerprint,
                      metadata_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'unknown', 'staged', ?, ?, ?)
                    """,
                    (
                        source_version_id,
                        document_id,
                        request.source_identity,
                        request.content_sha256,
                        _vault_relative(self.settings, body_object.path),
                        title,
                        f"research-intake-sha256:{binding_sha256}",
                        CREATE_ONLY_PROCESSING_FINGERPRINT,
                        metadata_json,
                        now,
                    ),
                )
                for chunk_row in chunk_rows:
                    connection.execute(
                        """
                        INSERT INTO chunks(
                          id, source_version_id, ordinal, heading_path, locator,
                          text_sha256, markdown_text, token_count, stream, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        chunk_row,
                    )
                connection.execute(
                    """
                    INSERT INTO reviews(
                      id, review_type, target_id, status, reason, created_at
                    ) VALUES (?, 'source_version', ?, 'pending', ?, ?)
                    """,
                    (
                        review_id,
                        source_version_id,
                        "Source-admission review required before official research material enters a candidate build",
                        now,
                    ),
                )
        return {
            "scan_id": request.scan_id,
            "file_count": 1,
            "ingested": 0 if already_present else 1,
            "items": [
                {
                    "path_suffix": path.suffix,
                    "status": "already_staged" if already_present else classification.ready_status.value,
                    "reason": None,
                    "content_sha256": request.content_sha256,
                }
            ],
            "wrote_active": False,
            "seals_expert_gold": False,
            "writes_index": False,
            "enqueues_embedding": False,
            "approves_source": False,
            "source_version_id": source_version_id,
            "source_review_id": review_id,
        }


def _validate_request(request: CreateOnlySourceIntakeRequest) -> None:
    if (
        not _SHA256.fullmatch(request.content_sha256)
        or not _SHA256.fullmatch(request.canonical_url_sha256)
        or not request.scan_id.startswith("research-intake-")
        or request.content_type not in {
            "application/akn+xml",
            "application/json",
            "application/ld+json",
            "application/pdf",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/xhtml+xml",
            "application/xml",
            "text/html",
            "text/plain",
            "text/xml",
        }
        or not request.subject.strip()
        or not request.source_identity.strip()
        or request.intake_marker.get("schema")
        != "legalbot.research-source-intake-bridge.v1"
        or request.intake_marker.get("content_sha256") != request.content_sha256
    ):
        raise CreateOnlySourceIntakeError("source_intake_create_only_request_invalid")
    try:
        datetime.fromisoformat(request.observed_at)
    except ValueError as exc:
        raise CreateOnlySourceIntakeError("source_intake_observed_time_invalid") from exc


def _jurisdiction(value: str) -> tuple[str, Jurisdiction]:
    normalized = " ".join(value.casefold().replace("&", "and").split())
    mapping = {
        "england and wales": ("England and Wales", Jurisdiction.ENGLAND_WALES),
        "united kingdom": ("United Kingdom", Jurisdiction.UNITED_KINGDOM),
        "scotland": ("Scotland", Jurisdiction.SCOTLAND),
        "northern ireland": ("Northern Ireland", Jurisdiction.NORTHERN_IRELAND),
        "european union": ("European Union", Jurisdiction.EUROPEAN_UNION),
        "comparative": ("Comparative", Jurisdiction.COMPARATIVE),
        "general": ("General", Jurisdiction.GENERAL),
    }
    try:
        return mapping[normalized]
    except KeyError as exc:
        raise CreateOnlySourceIntakeError("source_intake_jurisdiction_invalid") from exc


def _put_create_only(vault_root: Path, content: bytes) -> _VaultObject:
    digest = hashlib.sha256(content).hexdigest()
    root = vault_root / "objects" / "sha256"
    target = root / digest[:2] / digest
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not target.parent.resolve(strict=True).is_relative_to(vault_root.resolve(strict=True)):
        raise CreateOnlySourceIntakeError("source_intake_vault_parent_invalid")
    if target.exists() or target.is_symlink():
        _verify_file(target, digest, len(content))
        return _VaultObject(digest, len(content), target)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags, 0o400)
    except FileExistsError:
        _verify_file(target, digest, len(content))
        return _VaultObject(digest, len(content), target)
    except OSError as exc:
        raise CreateOnlySourceIntakeError("source_intake_vault_create_failed") from exc
    try:
        view = memoryview(content)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
    except OSError as exc:
        raise CreateOnlySourceIntakeError("source_intake_vault_create_failed") from exc
    finally:
        os.close(descriptor)
    _fsync_directory(target.parent)
    return _VaultObject(digest, len(content), target)


def _verify_file(path: Path, digest: str, size: int) -> None:
    try:
        details = path.lstat()
    except OSError as exc:
        raise CreateOnlySourceIntakeError("source_intake_vault_conflict") from exc
    if (
        not stat.S_ISREG(details.st_mode)
        or path.is_symlink()
        or details.st_size != size
        or hashlib.sha256(path.read_bytes()).hexdigest() != digest
    ):
        raise CreateOnlySourceIntakeError("source_intake_vault_conflict")


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        raise CreateOnlySourceIntakeError("source_intake_vault_create_failed") from exc
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _vault_relative(settings: Settings, path: Path) -> str:
    try:
        return path.resolve(strict=True).relative_to(settings.project_root.resolve(strict=True)).as_posix()
    except (OSError, ValueError) as exc:
        raise CreateOnlySourceIntakeError("source_intake_vault_path_invalid") from exc


def _chunk_row(
    source_version_id: str, chunk: StructuralChunk, ordinal: int
) -> tuple[Any, ...]:
    chunk_id = _stable_id("chunk", source_version_id, chunk.chunk_id)
    metadata = {
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
    return (
        chunk_id,
        source_version_id,
        ordinal,
        json.dumps(list(chunk.heading_path), ensure_ascii=False),
        _chunk_locator(
            chunk.heading_path,
            chunk.page_start,
            chunk.page_end,
            ordinal,
            chunk.metadata,
        ),
        hashlib.sha256(chunk.text.encode()).hexdigest(),
        chunk.text,
        len(_WORD_RE.findall(chunk.text)),
        chunk.stream,
        json.dumps(metadata, ensure_ascii=False, sort_keys=True),
    )


def _assert_catalogue_identities_absent(
    connection: Any,
    *,
    document_id: str,
    source_version_id: str,
    alias_id: str,
    review_id: str,
    chunk_rows: tuple[tuple[Any, ...], ...],
    content_sha256: str,
    lane: str,
    jurisdiction: str,
    subject: str,
) -> None:
    identities = (
        ("documents", document_id),
        ("source_versions", source_version_id),
        ("source_aliases", alias_id),
        ("reviews", review_id),
        *(("chunks", str(row[0])) for row in chunk_rows),
    )
    for table, identity in identities:
        if connection.execute(f"SELECT 1 FROM {table} WHERE id=?", (identity,)).fetchone():
            raise CreateOnlySourceIntakeError("source_intake_catalogue_identity_conflict")
    duplicate = connection.execute(
        """
        SELECT id FROM documents
        WHERE content_sha256=? AND COALESCE(lane, '')=?
          AND COALESCE(jurisdiction, '')=? AND COALESCE(subject_primary, '')=?
          AND duplicate_of IS NULL
        LIMIT 1
        """,
        (content_sha256, lane, jurisdiction, subject),
    ).fetchone()
    if duplicate is not None:
        raise CreateOnlySourceIntakeError("source_intake_existing_content_conflict")


def _verify_existing_catalogue(
    connection: Any,
    *,
    document_id: str,
    source_version_id: str,
    review_id: str,
    fingerprint: str,
    content_sha256: str,
    processing_fingerprint: str,
    marker: dict[str, str],
    expected_chunk_rows: tuple[tuple[Any, ...], ...],
) -> None:
    row = connection.execute(
        """
        SELECT d.id AS document_id, d.content_sha256, sv.id AS source_version_id,
               sv.version_sha256, sv.processing_fingerprint,
               sv.review_status AS source_version_review_status,
               sv.currentness_status, sv.superseded_by, sv.metadata_json,
               r.id AS review_id, r.status AS source_review_status
        FROM source_aliases sa
        JOIN documents d ON d.id=sa.document_id
        JOIN source_versions sv ON sv.document_id=d.id AND sv.superseded_by IS NULL
        LEFT JOIN reviews r ON r.review_type='source_version' AND r.target_id=sv.id
        WHERE sa.path_fingerprint=?
        """,
        (fingerprint,),
    ).fetchone()
    if row is None:
        raise CreateOnlySourceIntakeError("source_intake_catalogue_identity_conflict")
    try:
        metadata = json.loads(row["metadata_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise CreateOnlySourceIntakeError("source_intake_catalogue_identity_conflict") from exc
    if (
        row["document_id"] != document_id
        or row["content_sha256"] != content_sha256
        or row["source_version_id"] != source_version_id
        or row["version_sha256"] != content_sha256
        or row["processing_fingerprint"] != processing_fingerprint
        or row["source_version_review_status"] != "staged"
        or row["currentness_status"] != "unknown"
        or row["superseded_by"] is not None
        or row["review_id"] != review_id
        or row["source_review_status"] != "pending"
        or not isinstance(metadata, dict)
        or metadata.get("research_source_intake") != marker
    ):
        raise CreateOnlySourceIntakeError("source_intake_catalogue_identity_conflict")
    chunks = connection.execute(
        "SELECT id, text_sha256 FROM chunks WHERE source_version_id=? ORDER BY ordinal",
        (source_version_id,),
    ).fetchall()
    expected = [(str(item[0]), str(item[5])) for item in expected_chunk_rows]
    actual = [(str(item["id"]), str(item["text_sha256"])) for item in chunks]
    if actual != expected:
        raise CreateOnlySourceIntakeError("source_intake_catalogue_identity_conflict")
