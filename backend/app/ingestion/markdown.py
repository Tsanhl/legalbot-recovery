"""Deterministic provenance-preserving conversion to canonical Markdown."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from .models import (
    Annotation,
    CanonicalMarkdownBundle,
    ParseResult,
    Provenance,
    Revision,
    StructuralBlock,
)
from .sanitation import sanitize_parse_result


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _safe_comment(value: str) -> str:
    return value.replace("--", "—").replace("<!--", "‹!--").replace("-->", "--›")


class CanonicalMarkdownConverter:
    schema = "legalbot.canonical-markdown.v3"
    audit_schema = "legalbot.provenance-audit.v1"

    def convert(self, parsed: ParseResult, provenance: Provenance) -> CanonicalMarkdownBundle:
        parsed = sanitize_parse_result(parsed)
        if not parsed.is_ready:
            raise ValueError(f"cannot canonicalise parse status {parsed.status.value}")
        streams: dict[str, object] = {
            "body": {"blocks": len(parsed.body_blocks)},
            "comments": {"annotations": len(parsed.comments), "authority": False},
            "revisions": {"annotations": len(parsed.revisions), "authority": False},
        }
        canonical_payload: dict[str, object] = {
            "schema": self.schema,
            "provenance": provenance.to_canonical_dict(),
            "streams": streams,
        }
        audit_payload: dict[str, object] = {
            "schema": self.audit_schema,
            "canonical_markdown_schema": self.schema,
            "provenance": provenance.to_dict(),
            "streams": streams,
        }
        provenance_json = (
            json.dumps(audit_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        )
        body = self._body(parsed.body_blocks, canonical_payload)
        comments = self._comments(parsed.comments, canonical_payload)
        revisions = self._revisions(parsed.revisions, canonical_payload)
        return CanonicalMarkdownBundle(
            body,
            comments,
            revisions,
            provenance_json,
            hashlib.sha256(body.encode("utf-8")).hexdigest(),
            hashlib.sha256(comments.encode("utf-8")).hexdigest(),
            hashlib.sha256(revisions.encode("utf-8")).hexdigest(),
        )

    def _header(self, payload: Mapping[str, object], *, stream: str) -> str:
        marker: dict[str, object] = {"stream": stream}
        marker.update(payload)
        compact = _safe_comment(_canonical_json(marker))
        return f"<!-- legalbot-canonical {compact} -->\n\n"

    def _body(self, blocks: tuple[StructuralBlock, ...], payload: Mapping[str, object]) -> str:
        output = [self._header(payload, stream="body")]
        for block in blocks:
            marker = {
                "ordinal": block.ordinal,
                "kind": block.kind.value,
                "heading_path": block.heading_path,
                "page": block.page,
                "source_anchor": block.source_anchor,
                "char_start": block.char_start,
                "char_end": block.char_end,
                "metadata": dict(block.metadata),
            }
            output.append(f"<!-- legalbot-block {_safe_comment(_canonical_json(marker))} -->\n")
            level = (
                int(block.metadata.get("level", 2))
                if block.kind.value in {"title", "heading"}
                else 0
            )
            if block.kind.value == "title":
                output.append(f"# {block.text}\n\n")
            elif block.kind.value == "heading":
                output.append(f"{'#' * max(2, min(6, level))} {block.text}\n\n")
            elif block.kind.value == "list_item":
                output.append(f"- {block.text}\n\n")
            elif block.kind.value == "code":
                output.append(f"```text\n{block.text}\n```\n\n")
            else:
                output.append(f"{block.text}\n\n")
        return "".join(output).rstrip() + "\n"

    def _comments(self, comments: tuple[Annotation, ...], payload: Mapping[str, object]) -> str:
        output = [
            self._header(payload, stream="comments"),
            "# Reviewer comments (non-authoritative)\n\n",
        ]
        for comment in comments:
            marker = {
                "annotation_id": comment.annotation_id,
                "author_alias": comment.author_alias,
                "created_at": comment.created_at,
                "anchor": comment.anchor,
                "page": comment.page,
                "metadata": dict(comment.metadata),
            }
            output.append(f"<!-- legalbot-comment {_safe_comment(_canonical_json(marker))} -->\n")
            output.append(f"- {comment.text}\n")
        return "".join(output).rstrip() + "\n"

    def _revisions(self, revisions: tuple[Revision, ...], payload: Mapping[str, object]) -> str:
        output = [
            self._header(payload, stream="revisions"),
            "# Tracked revisions (non-authoritative)\n\n",
        ]
        for revision in revisions:
            marker = {
                "revision_id": revision.revision_id,
                "operation": revision.operation,
                "author_alias": revision.author_alias,
                "created_at": revision.created_at,
                "anchor": revision.anchor,
                "metadata": dict(revision.metadata),
            }
            output.append(f"<!-- legalbot-revision {_safe_comment(_canonical_json(marker))} -->\n")
            output.append(f"- **{revision.operation}:** {revision.text}\n")
        return "".join(output).rstrip() + "\n"
