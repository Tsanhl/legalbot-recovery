"""Structure-aware chunking with stable content-derived identifiers."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import replace

from .models import Annotation, ParseResult, StructuralBlock, StructuralChunk
from .sanitation import sanitize_parse_result

_JUDGMENT_PARAGRAPH_RE = re.compile(r"(?<!\S)\[(?P<number>[1-9]\d{0,2}[A-Za-z]?)\]\s+")
_PROVISION_RE = re.compile(
    r"^\s*(?P<label>section|regulation|article|rule|schedule)\s+"
    r"(?P<number>\d+[A-Za-z]?(?:\.\d+)?(?:\([0-9A-Za-z]+\))*)(?![0-9A-Za-z.(])",
    re.IGNORECASE,
)


class StructuralChunker:
    schema = "legalbot.structural-chunker.v2"

    def __init__(self, *, max_chars: int = 1_800, min_chars: int = 160) -> None:
        if max_chars < 256 or min_chars < 1 or min_chars >= max_chars:
            raise ValueError("invalid chunk size bounds")
        self.max_chars = max_chars
        self.min_chars = min_chars

    def chunk_body(
        self, parsed: ParseResult, *, document_sha256: str
    ) -> tuple[StructuralChunk, ...]:
        parsed = sanitize_parse_result(parsed)
        if not parsed.is_ready:
            raise ValueError("only ready documents can be chunked")
        expanded: list[StructuralBlock] = []
        for block in parsed.body_blocks:
            for legal_block in self._legal_anchor_blocks(block):
                expanded.extend(self._split_block(legal_block))

        chunks: list[StructuralChunk] = []
        group: list[StructuralBlock] = []
        group_length = 0
        for block in expanded:
            structural_boundary = block.kind.value in {"title", "heading", "page"} or bool(
                block.metadata.get("legal_locator")
            )
            path_changed = bool(group and block.heading_path != group[-1].heading_path)
            would_overflow = group_length + len(block.text) + (2 if group else 0) > self.max_chars
            if group and (would_overflow or path_changed or structural_boundary):
                chunks.append(self._make_chunk(group, document_sha256, len(chunks)))
                group, group_length = [], 0
            group.append(block)
            group_length += len(block.text) + (2 if group_length else 0)
            if structural_boundary or group_length >= self.max_chars:
                chunks.append(self._make_chunk(group, document_sha256, len(chunks)))
                group, group_length = [], 0
        if group:
            chunks.append(self._make_chunk(group, document_sha256, len(chunks)))
        return tuple(chunks)

    @staticmethod
    def _legal_anchor_blocks(block: StructuralBlock) -> tuple[StructuralBlock, ...]:
        """Split only explicit legal anchors; never infer a pinpoint from prose."""

        paragraph_matches = list(_JUDGMENT_PARAGRAPH_RE.finditer(block.text))
        if paragraph_matches and (paragraph_matches[0].start() == 0 or len(paragraph_matches) >= 2):
            output: list[StructuralBlock] = []
            if paragraph_matches[0].start() > 0:
                prefix = block.text[: paragraph_matches[0].start()].strip()
                if prefix:
                    output.append(replace(block, text=prefix))
            for index, match in enumerate(paragraph_matches):
                end = (
                    paragraph_matches[index + 1].start()
                    if index + 1 < len(paragraph_matches)
                    else len(block.text)
                )
                text = block.text[match.start() : end].strip()
                number = match.group("number")
                metadata = {
                    **dict(block.metadata),
                    "legal_locator_kind": "judgment_paragraph",
                    "legal_locator": f"para {number}",
                }
                output.append(
                    replace(
                        block,
                        text=text,
                        source_anchor=f"judgment-paragraph={number}",
                        metadata=metadata,
                    )
                )
            return tuple(output)

        provision = _PROVISION_RE.match(block.text)
        if provision is None and block.heading_path:
            provision = _PROVISION_RE.match(block.heading_path[-1])
        if provision is not None:
            label = provision.group("label").casefold()
            number = provision.group("number")
            metadata = {
                **dict(block.metadata),
                "legal_locator_kind": "legislative_provision",
                "legal_locator": f"{label} {number}",
            }
            return (
                replace(
                    block,
                    source_anchor=f"{label}={number}",
                    metadata=metadata,
                ),
            )
        return (block,)

    def chunk_comments(
        self, parsed: ParseResult, *, document_sha256: str
    ) -> tuple[StructuralChunk, ...]:
        parsed = sanitize_parse_result(parsed)
        return self._annotation_chunks(parsed.comments, document_sha256, stream="comments")

    def chunk_revisions(
        self, parsed: ParseResult, *, document_sha256: str
    ) -> tuple[StructuralChunk, ...]:
        parsed = sanitize_parse_result(parsed)
        annotations = tuple(
            Annotation(
                revision.revision_id,
                revision.text,
                revision.author_alias,
                revision.created_at,
                revision.anchor,
                metadata={"operation": revision.operation, **dict(revision.metadata)},
            )
            for revision in parsed.revisions
        )
        return self._annotation_chunks(annotations, document_sha256, stream="revisions")

    def _split_block(self, block: StructuralBlock) -> list[StructuralBlock]:
        if len(block.text) <= self.max_chars:
            return [block]
        sentences = [
            part.strip()
            for part in re.split(r"(?<=[.!?])\s+(?=[A-Z0-9\[])|\n+", block.text)
            if part.strip()
        ]
        if len(sentences) == 1:
            sentences = [
                block.text[index : index + self.max_chars]
                for index in range(0, len(block.text), self.max_chars)
            ]
        output: list[StructuralBlock] = []
        current = ""
        offset = 0
        for sentence in sentences:
            if current and len(current) + len(sentence) + 1 > self.max_chars:
                output.append(
                    replace(block, text=current, char_start=offset, char_end=offset + len(current))
                )
                offset += len(current)
                current = ""
            if len(sentence) > self.max_chars:
                for index in range(0, len(sentence), self.max_chars):
                    piece = sentence[index : index + self.max_chars]
                    output.append(
                        replace(block, text=piece, char_start=offset, char_end=offset + len(piece))
                    )
                    offset += len(piece)
            else:
                current = f"{current} {sentence}".strip()
        if current:
            output.append(
                replace(block, text=current, char_start=offset, char_end=offset + len(current))
            )
        return output

    @staticmethod
    def _make_chunk(
        blocks: list[StructuralBlock], document_sha256: str, ordinal: int
    ) -> StructuralChunk:
        text = "\n\n".join(block.text for block in blocks)
        pages = [block.page for block in blocks if block.page is not None]
        raw_id = f"{document_sha256}\0body\0{ordinal}\0{text}".encode()
        legal_locators = tuple(
            dict.fromkeys(
                str(block.metadata["legal_locator"])
                for block in blocks
                if block.metadata.get("legal_locator")
            )
        )
        metadata: dict[str, object] = {
            "anchors": [block.source_anchor for block in blocks if block.source_anchor]
        }
        if len(legal_locators) == 1:
            metadata["legal_locator"] = legal_locators[0]
            metadata["legal_locator_kind"] = str(
                next(
                    block.metadata["legal_locator_kind"]
                    for block in blocks
                    if block.metadata.get("legal_locator") == legal_locators[0]
                )
            )
        return StructuralChunk(
            f"sha256:{hashlib.sha256(raw_id).hexdigest()}",
            document_sha256,
            ordinal,
            text,
            tuple(block.ordinal for block in blocks),
            blocks[-1].heading_path,
            min(pages) if pages else None,
            max(pages) if pages else None,
            char_start=blocks[0].char_start,
            char_end=blocks[-1].char_end,
            metadata=metadata,
        )

    @staticmethod
    def _annotation_chunks(
        annotations: Iterable[Annotation], document_sha256: str, *, stream: str
    ) -> tuple[StructuralChunk, ...]:
        chunks: list[StructuralChunk] = []
        for ordinal, annotation in enumerate(annotations):
            raw_id = f"{document_sha256}\0{stream}\0{annotation.annotation_id}\0{annotation.text}".encode()
            chunks.append(
                StructuralChunk(
                    f"sha256:{hashlib.sha256(raw_id).hexdigest()}",
                    document_sha256,
                    ordinal,
                    annotation.text,
                    (),
                    (),
                    annotation.page,
                    annotation.page,
                    stream=stream,
                    metadata={
                        "annotation_id": annotation.annotation_id,
                        "author_alias": annotation.author_alias,
                        **dict(annotation.metadata),
                    },
                )
            )
        return tuple(chunks)
