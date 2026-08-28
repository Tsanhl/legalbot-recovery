"""Typed contracts shared by the clean-room ingestion pipeline.

The contracts deliberately distinguish body text from reviewer comments and
tracked revisions.  Downstream code must opt in to each stream rather than
accidentally treating annotations as authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Jurisdiction(StrEnum):
    ENGLAND_WALES = "england_wales"
    UNITED_KINGDOM = "united_kingdom"
    SCOTLAND = "scotland"
    NORTHERN_IRELAND = "northern_ireland"
    EUROPEAN_UNION = "european_union"
    COMPARATIVE = "comparative"
    GENERAL = "general"


class MaterialLane(StrEnum):
    PRIMARY_AUTHORITY = "primary_authority"
    PROCEDURE_RULE = "procedure_rule"
    REGULATOR_RULE = "regulator_rule"
    OFFICIAL_GUIDANCE = "official_guidance"
    REFORM_MATERIAL = "reform_material"
    SECONDARY_SCHOLARSHIP = "secondary_scholarship"
    BOOK_OR_TREATISE = "book_or_treatise"
    LECTURE_NOTE = "lecture_note"
    ASSESSMENT_FEEDBACK = "assessment_feedback"
    COURSE_INSTRUCTION = "course_instruction"
    GENERAL_INSTRUCTION = "general_instruction"
    PRIVATE_REFERENCE = "private_reference"
    OFFICIAL_METADATA = "official_metadata"


class DocumentFormat(StrEnum):
    PDF = "pdf"
    DOCX = "docx"
    DOC = "doc"
    PPTX = "pptx"
    PPT = "ppt"
    HTML = "html"
    XML = "xml"
    MARKDOWN = "markdown"
    TEXT = "text"
    ODT = "odt"
    UNKNOWN = "unknown"


class ParseStatus(StrEnum):
    READY = "ready"
    OCR_REQUIRED = "ocr_required"
    ENCRYPTED = "encrypted"
    PARSER_UNAVAILABLE = "parser_unavailable"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"
    QUARANTINED = "quarantined"


class BlockKind(StrEnum):
    TITLE = "title"
    HEADING = "heading"
    PARAGRAPH = "paragraph"
    LIST_ITEM = "list_item"
    TABLE = "table"
    PAGE = "page"
    CODE = "code"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    """A stable, non-secret identity such as a DOI or official document URI."""

    scheme: str
    value: str
    version: str | None = None

    @property
    def canonical_key(self) -> str:
        suffix = f"@{self.version}" if self.version else ""
        return f"{self.scheme.lower()}:{self.value}{suffix}"


@dataclass(frozen=True, slots=True)
class LicenceRecord:
    name: str
    version: str | None = None
    url: str | None = None
    attribution: str | None = None
    rights_basis: str | None = None


@dataclass(frozen=True, slots=True)
class Provenance:
    source_identity: SourceIdentity
    title: str
    source_kind: str
    jurisdiction: Jurisdiction
    material_lane: MaterialLane
    content_sha256: str
    retrieved_at: str
    canonical_url: str | None = None
    effective_as_at: str | None = None
    published_at: str | None = None
    modified_at: str | None = None
    private_locator_digest: str | None = None
    licence: LicenceRecord | None = None
    public_aliases: Mapping[str, str] = field(default_factory=dict)
    extra: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def now(
        cls,
        *,
        source_identity: SourceIdentity,
        title: str,
        source_kind: str,
        jurisdiction: Jurisdiction,
        material_lane: MaterialLane,
        content_sha256: str,
        **kwargs: Any,
    ) -> Provenance:
        return cls(
            source_identity=source_identity,
            title=title,
            source_kind=source_kind,
            jurisdiction=jurisdiction,
            material_lane=material_lane,
            content_sha256=content_sha256,
            retrieved_at=datetime.now(UTC).isoformat(),
            **kwargs,
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["jurisdiction"] = self.jurisdiction.value
        result["material_lane"] = self.material_lane.value
        return result

    def to_canonical_dict(self) -> dict[str, Any]:
        """Return stable provenance suitable for content-addressed Markdown.

        Audit timing and scan-run identifiers remain in :meth:`to_dict` and
        therefore in the separate provenance JSON object. They cannot affect
        canonical stream bytes or their SHA-256 keys.
        """

        result = self.to_dict()
        result.pop("retrieved_at", None)
        extra = result.get("extra")
        if isinstance(extra, dict):
            volatile = {
                "retrieved_at",
                "ingested_at",
                "scan_id",
                "scan_timestamp",
                "scan_started_at",
                "scan_completed_at",
            }
            result["extra"] = {key: value for key, value in extra.items() if key not in volatile}
        return result


@dataclass(frozen=True, slots=True)
class StructuralBlock:
    ordinal: int
    kind: BlockKind
    text: str
    heading_path: tuple[str, ...] = ()
    page: int | None = None
    source_anchor: str | None = None
    char_start: int | None = None
    char_end: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Annotation:
    annotation_id: str
    text: str
    author_alias: str | None = None
    created_at: str | None = None
    anchor: str | None = None
    page: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Revision:
    revision_id: str
    operation: str
    text: str
    author_alias: str | None = None
    created_at: str | None = None
    anchor: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ParseResult:
    status: ParseStatus
    document_format: DocumentFormat
    body_blocks: tuple[StructuralBlock, ...] = ()
    comments: tuple[Annotation, ...] = ()
    revisions: tuple[Revision, ...] = ()
    diagnostics: tuple[str, ...] = ()

    @property
    def is_ready(self) -> bool:
        return self.status is ParseStatus.READY


@dataclass(frozen=True, slots=True)
class CanonicalMarkdownBundle:
    body_markdown: str
    comments_markdown: str
    revisions_markdown: str
    provenance_json: str
    body_sha256: str
    comments_sha256: str
    revisions_sha256: str


@dataclass(frozen=True, slots=True)
class StructuralChunk:
    chunk_id: str
    document_sha256: str
    ordinal: int
    text: str
    block_ordinals: tuple[int, ...]
    heading_path: tuple[str, ...]
    page_start: int | None
    page_end: int | None
    char_start: int | None = None
    char_end: int | None = None
    stream: str = "body"
    metadata: Mapping[str, Any] = field(default_factory=dict)
