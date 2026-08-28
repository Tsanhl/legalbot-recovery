from __future__ import annotations

import json
from dataclasses import replace

from app.ingestion import (
    Annotation,
    BlockKind,
    CanonicalMarkdownConverter,
    ContentAddressedVault,
    DocumentFormat,
    Jurisdiction,
    MaterialLane,
    ParseResult,
    ParseStatus,
    Provenance,
    Revision,
    SourceIdentity,
    StructuralBlock,
)


def test_canonical_streams_are_exactly_reproducible_across_audit_runs(tmp_path) -> None:
    parsed = ParseResult(
        ParseStatus.READY,
        DocumentFormat.DOCX,
        body_blocks=(
            StructuralBlock(0, BlockKind.HEADING, "Contract", metadata={"level": 1}),
            StructuralBlock(1, BlockKind.PARAGRAPH, "A stable proposition."),
        ),
        comments=(Annotation("comment-1", "Explain the counterargument."),),
        revisions=(Revision("revision-1", "insert", "Added qualification."),),
    )
    first_provenance = Provenance(
        source_identity=SourceIdentity("catalog", f"content-sha256:{'a' * 64}"),
        title="Stable title",
        source_kind="private_teaching",
        jurisdiction=Jurisdiction.ENGLAND_WALES,
        material_lane=MaterialLane.LECTURE_NOTE,
        content_sha256="a" * 64,
        retrieved_at="2026-08-11T01:00:00+00:00",
        extra={"parser_format": "docx", "scan_id": "first-scan"},
    )
    second_provenance = replace(
        first_provenance,
        retrieved_at="2026-08-11T02:00:00+00:00",
        extra={"parser_format": "docx", "scan_id": "second-scan"},
    )
    converter = CanonicalMarkdownConverter()

    first = converter.convert(parsed, first_provenance)
    second = converter.convert(parsed, second_provenance)

    assert first.body_markdown == second.body_markdown
    assert first.comments_markdown == second.comments_markdown
    assert first.revisions_markdown == second.revisions_markdown
    assert first.body_sha256 == second.body_sha256
    assert first.comments_sha256 == second.comments_sha256
    assert first.revisions_sha256 == second.revisions_sha256
    assert "legalbot.canonical-markdown.v3" in first.body_markdown
    assert "retrieved_at" not in first.body_markdown
    assert "first-scan" not in first.body_markdown
    assert "second-scan" not in second.body_markdown
    assert '"parser_format":"docx"' in first.body_markdown

    first_audit = json.loads(first.provenance_json)
    second_audit = json.loads(second.provenance_json)
    assert first.provenance_json != second.provenance_json
    assert first_audit["schema"] == "legalbot.provenance-audit.v1"
    assert first_audit["canonical_markdown_schema"] == "legalbot.canonical-markdown.v3"
    assert first_audit["provenance"]["retrieved_at"] != second_audit["provenance"]["retrieved_at"]
    assert first_audit["provenance"]["extra"]["scan_id"] == "first-scan"
    assert second_audit["provenance"]["extra"]["scan_id"] == "second-scan"

    vault = ContentAddressedVault(tmp_path / "vault")
    assert vault.put_bytes(first.body_markdown.encode()) == vault.put_bytes(
        second.body_markdown.encode()
    )
    assert vault.put_bytes(first.comments_markdown.encode()) == vault.put_bytes(
        second.comments_markdown.encode()
    )
    assert vault.put_bytes(first.revisions_markdown.encode()) == vault.put_bytes(
        second.revisions_markdown.encode()
    )
    assert (
        vault.put_bytes(first.provenance_json.encode()).sha256
        != vault.put_bytes(second.provenance_json.encode()).sha256
    )
