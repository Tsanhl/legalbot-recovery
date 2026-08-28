"""Staging-only ingestion orchestration.

This module has no index-writing capability.  Successful output is a staged,
content-addressed bundle that another reviewed build process may consume.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .markdown import CanonicalMarkdownConverter
from .models import (
    Jurisdiction,
    LicenceRecord,
    MaterialLane,
    ParseResult,
    Provenance,
    SourceIdentity,
)
from .parsers import ParserRegistry
from .privacy import PIIAliaser
from .sanitation import sanitize_parse_result
from .vault import ContentAddressedVault, DedupeDecision, DedupeLedger, DedupeStatus, VaultObject


class IngestionOutcomeStatus(StrEnum):
    STAGED = "staged"
    DUPLICATE = "duplicate"
    QUARANTINED = "quarantined"


@dataclass(frozen=True, slots=True)
class IngestionRequest:
    filename: str
    data: bytes
    source_identity: SourceIdentity
    title: str
    source_kind: str
    jurisdiction: Jurisdiction
    material_lane: MaterialLane
    canonical_url: str | None = None
    effective_as_at: str | None = None
    published_at: str | None = None
    modified_at: str | None = None
    private_locator_digest: str | None = None
    licence: LicenceRecord | None = None


@dataclass(frozen=True, slots=True)
class StagedObjects:
    raw: VaultObject
    body_markdown: VaultObject | None = None
    comments_markdown: VaultObject | None = None
    revisions_markdown: VaultObject | None = None
    provenance: VaultObject | None = None


@dataclass(frozen=True, slots=True)
class IngestionOutcome:
    status: IngestionOutcomeStatus
    objects: StagedObjects
    dedupe: DedupeDecision
    parsed: ParseResult | None = None
    provenance: Provenance | None = None
    quarantine_reason: str | None = None


class IngestionPipeline:
    def __init__(
        self,
        *,
        vault: ContentAddressedVault,
        dedupe_ledger: DedupeLedger,
        parser_registry: ParserRegistry | None = None,
        aliaser: PIIAliaser | None = None,
        converter: CanonicalMarkdownConverter | None = None,
    ) -> None:
        self.vault = vault
        self.dedupe_ledger = dedupe_ledger
        self.parsers = parser_registry or ParserRegistry.default()
        self.aliaser = aliaser
        self.converter = converter or CanonicalMarkdownConverter()

    def stage(self, request: IngestionRequest) -> IngestionOutcome:
        raw = self.vault.put_bytes(request.data)
        decision = self.dedupe_ledger.register(request.source_identity, raw.sha256)
        objects = StagedObjects(raw)
        if decision.status is not DedupeStatus.NEW:
            reason = (
                "source identity resolves to conflicting bytes"
                if decision.status is DedupeStatus.IDENTITY_CONFLICT
                else None
            )
            return IngestionOutcome(
                IngestionOutcomeStatus.QUARANTINED if reason else IngestionOutcomeStatus.DUPLICATE,
                objects,
                decision,
                quarantine_reason=reason,
            )

        parsed = sanitize_parse_result(
            self.parsers.parse(request.data, filename=request.filename, aliaser=self.aliaser)
        )
        if not parsed.is_ready:
            return IngestionOutcome(
                IngestionOutcomeStatus.QUARANTINED,
                objects,
                decision,
                parsed=parsed,
                quarantine_reason=parsed.status.value,
            )

        provenance = Provenance.now(
            source_identity=request.source_identity,
            title=request.title,
            source_kind=request.source_kind,
            jurisdiction=request.jurisdiction,
            material_lane=request.material_lane,
            content_sha256=raw.sha256,
            canonical_url=request.canonical_url,
            effective_as_at=request.effective_as_at,
            published_at=request.published_at,
            modified_at=request.modified_at,
            private_locator_digest=request.private_locator_digest,
            licence=request.licence,
        )
        bundle = self.converter.convert(parsed, provenance)
        objects = StagedObjects(
            raw,
            self.vault.put_bytes(bundle.body_markdown.encode("utf-8")),
            self.vault.put_bytes(bundle.comments_markdown.encode("utf-8")),
            self.vault.put_bytes(bundle.revisions_markdown.encode("utf-8")),
            self.vault.put_bytes(bundle.provenance_json.encode("utf-8")),
        )
        return IngestionOutcome(
            IngestionOutcomeStatus.STAGED, objects, decision, parsed, provenance
        )
