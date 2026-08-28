"""Clean-room legal document ingestion primitives."""

from .chunking import StructuralChunker
from .identity import canonical_source_identity, canonical_url, private_locator_digest
from .markdown import CanonicalMarkdownConverter
from .models import (
    Annotation,
    BlockKind,
    CanonicalMarkdownBundle,
    DocumentFormat,
    Jurisdiction,
    LicenceRecord,
    MaterialLane,
    ParseResult,
    ParseStatus,
    Provenance,
    Revision,
    SourceIdentity,
    StructuralBlock,
    StructuralChunk,
)
from .parsers import DocumentParser, ParserRegistry, detect_format
from .pipeline import IngestionOutcome, IngestionOutcomeStatus, IngestionPipeline, IngestionRequest
from .privacy import PIIAliaser
from .sanitation import TEXT_SANITATION_SCHEMA, sanitize_parse_result, sanitize_text
from .vault import ContentAddressedVault, DedupeDecision, DedupeLedger, DedupeStatus, VaultObject

__all__ = [
    "TEXT_SANITATION_SCHEMA",
    "Annotation",
    "BlockKind",
    "CanonicalMarkdownBundle",
    "CanonicalMarkdownConverter",
    "ContentAddressedVault",
    "DedupeDecision",
    "DedupeLedger",
    "DedupeStatus",
    "DocumentFormat",
    "DocumentParser",
    "IngestionOutcome",
    "IngestionOutcomeStatus",
    "IngestionPipeline",
    "IngestionRequest",
    "Jurisdiction",
    "LicenceRecord",
    "MaterialLane",
    "PIIAliaser",
    "ParseResult",
    "ParseStatus",
    "ParserRegistry",
    "Provenance",
    "Revision",
    "SourceIdentity",
    "StructuralBlock",
    "StructuralChunk",
    "StructuralChunker",
    "VaultObject",
    "canonical_source_identity",
    "canonical_url",
    "detect_format",
    "private_locator_digest",
    "sanitize_parse_result",
    "sanitize_text",
]
