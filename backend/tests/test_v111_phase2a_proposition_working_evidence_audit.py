from __future__ import annotations

import hashlib

import pytest
from scripts.audit_v111_phase2a_proposition_working_evidence import (
    _audit_evidence_item,
    _sha256_text,
    _span_index,
)


def _span_corpus(text: str) -> dict:
    exact = text[2:7]
    return {
        "records": [
            {
                "source_version_id": "source-v1",
                "chunk_id": "chunk-1",
                "exact_span_options": [
                    {
                        "span_id": "span-canonical",
                        "start_character": 2,
                        "end_character_exclusive": 7,
                        "exact_text": exact,
                        "exact_text_sha256": hashlib.sha256(exact.encode("utf-8")).hexdigest(),
                    }
                ],
            }
        ]
    }


def _rows(text: str) -> dict[str, dict]:
    return {
        "chunk-1": {
            "chunk_id": "chunk-1",
            "source_version_id": "source-v1",
            "authority_identity_id": "authority-1",
            "text": text,
        }
    }


def test_audit_accepts_whole_sealed_chunk() -> None:
    text = "abcdefghij"
    evidence = {
        "source_version_id": "source-v1",
        "authority_identity_id": "authority-1",
        "chunk_id": "chunk-1",
        "exact_text_sha256": _sha256_text(text),
    }

    result = _audit_evidence_item(
        evidence,
        row_id="case:issue",
        lance_rows=_rows(text),
        spans=_span_index(_span_corpus(text)),
    )

    assert result["text_match_type"] == "WHOLE_LANCE_CHUNK"


def test_audit_reproduces_corpus_span_and_flags_old_identity() -> None:
    text = "abcdefghij"
    exact = text[2:7]
    evidence = {
        "source_version_id": "source-v1",
        "authority_identity_id": "authority-1",
        "chunk_id": "chunk-1",
        "span_id": "span-old",
        "exact_text_sha256": _sha256_text(exact),
    }

    result = _audit_evidence_item(
        evidence,
        row_id="case:issue",
        lance_rows=_rows(text),
        spans=_span_index(_span_corpus(text)),
    )

    assert result["text_match_type"] == "BYTE_REPRODUCED_CORPUS_SPAN"
    assert result["declared_span_identity_matches_corpus"] is False
    assert result["canonical_span_ids"] == ["span-canonical"]


def test_audit_rejects_unbound_exact_digest() -> None:
    text = "abcdefghij"
    evidence = {
        "source_version_id": "source-v1",
        "authority_identity_id": "authority-1",
        "chunk_id": "chunk-1",
        "exact_text_sha256": "0" * 64,
    }

    with pytest.raises(ValueError, match="neither a sealed chunk nor corpus span"):
        _audit_evidence_item(
            evidence,
            row_id="case:issue",
            lance_rows=_rows(text),
            spans=_span_index(_span_corpus(text)),
        )


def test_audit_rejects_source_mismatch() -> None:
    text = "abcdefghij"
    evidence = {
        "source_version_id": "wrong-source",
        "authority_identity_id": "authority-1",
        "chunk_id": "chunk-1",
        "exact_text_sha256": _sha256_text(text),
    }

    with pytest.raises(ValueError, match="chunk/source mismatch"):
        _audit_evidence_item(
            evidence,
            row_id="case:issue",
            lance_rows=_rows(text),
            spans=_span_index(_span_corpus(text)),
        )
