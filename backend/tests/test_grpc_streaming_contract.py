from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app.model_runtime.contracts import GenerateResponse, Usage
from app.model_runtime.grpc_streaming import (
    GRPC_ACTIVATION_STOP,
    GRPC_UDS_TRANSPORT_INTENT,
    GrpcFrameKind,
    GrpcStreamAccumulator,
    GrpcStreamContractError,
    GrpcStreamFrame,
    SentenceDiagnostic,
)


def _response(text: str, *, ttft: int = 42) -> GenerateResponse:
    return GenerateResponse(
        request_id="request-owner-1",
        model_version="model@test",
        backend="test",
        raw_text=text,
        structured={"answer": text},
        rubric_scores={},
        finish_reason="complete",
        usage=Usage(input_tokens=10, output_tokens=2),
        generation_ms=100,
        deterministic=True,
        time_to_first_token_ms=ttft,
    )


def test_stream_tracks_ttft_and_sentence_evidence_without_browser_tokens() -> None:
    text = "Supported answer."
    sentence = SentenceDiagnostic(
        sentence_id="sentence-1",
        sentence_sha256=hashlib.sha256(text.encode()).hexdigest(),
        validation_status="supported",
        start_char=0,
        end_char=len(text),
        evidence_ids=("evidence-1",),
        standard_ids=("standard-evidence-binding",),
    )
    accumulator = GrpcStreamAccumulator("request-owner-1")
    accumulator.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=1,
            kind=GrpcFrameKind.TOKEN,
            elapsed_ms=42,
            token_text="Supported ",
        )
    )
    accumulator.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=2,
            kind=GrpcFrameKind.TOKEN,
            elapsed_ms=55,
            token_text="answer.",
        )
    )
    accumulator.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=3,
            kind=GrpcFrameKind.SENTENCE,
            elapsed_ms=70,
            sentence=sentence,
        )
    )
    accumulator.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=4,
            kind=GrpcFrameKind.DIAGNOSTIC,
            elapsed_ms=75,
            diagnostic_code="evidence_binding_complete",
            safe_metrics={"bound_claims": 1},
        )
    )
    accumulator.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=5,
            kind=GrpcFrameKind.FINAL,
            elapsed_ms=100,
            final_response=_response(text),
        )
    )

    result = accumulator.result()
    debug = result.safe_debug_log()
    assert result.time_to_first_token_ms == 42
    assert result.releaseable is True
    assert result.token_frame_count == 2
    assert debug["raw_token_text_persisted"] is False
    assert debug["browser_token_stream_allowed"] is False
    assert text not in repr(debug)


def test_knowledge_hurdle_makes_stream_nonreleaseable() -> None:
    text = "Possible unsupported answer."
    accumulator = GrpcStreamAccumulator("request-owner-1")
    accumulator.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=1,
            kind=GrpcFrameKind.TOKEN,
            elapsed_ms=5,
            token_text=text,
        )
    )
    accumulator.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=2,
            kind=GrpcFrameKind.SENTENCE,
            elapsed_ms=8,
            sentence=SentenceDiagnostic(
                sentence_id="sentence-gap-1",
                sentence_sha256=hashlib.sha256(text.encode()).hexdigest(),
                validation_status="knowledge_gap",
                start_char=0,
                end_char=len(text),
                hurdle_codes=("no_threshold_qualified_evidence",),
            ),
        )
    )
    accumulator.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=3,
            kind=GrpcFrameKind.FINAL,
            elapsed_ms=10,
            final_response=_response(text, ttft=5),
        )
    )

    assert accumulator.result().releaseable is False


def test_sequence_gap_and_final_text_mismatch_fail_closed() -> None:
    accumulator = GrpcStreamAccumulator("request-owner-1")
    with pytest.raises(GrpcStreamContractError, match="sequence"):
        accumulator.accept(
            GrpcStreamFrame(
                request_id="request-owner-1",
                sequence=2,
                kind=GrpcFrameKind.TOKEN,
                elapsed_ms=1,
                token_text="out of order",
            )
        )


def test_stream_requires_exact_gap_free_diagnostic_binding() -> None:
    text = "Supported answer. Unsupported tail."

    no_diagnostics = GrpcStreamAccumulator("request-owner-1")
    no_diagnostics.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=1,
            kind=GrpcFrameKind.TOKEN,
            elapsed_ms=1,
            token_text=text,
        )
    )
    with pytest.raises(GrpcStreamContractError, match="no sentence diagnostics"):
        no_diagnostics.accept(
            GrpcStreamFrame(
                request_id="request-owner-1",
                sequence=2,
                kind=GrpcFrameKind.FINAL,
                elapsed_ms=2,
                final_response=_response(text, ttft=1),
            )
        )

    prefix = "Supported answer."
    incomplete = GrpcStreamAccumulator("request-owner-1")
    incomplete.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=1,
            kind=GrpcFrameKind.TOKEN,
            elapsed_ms=1,
            token_text=text,
        )
    )
    incomplete.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=2,
            kind=GrpcFrameKind.SENTENCE,
            elapsed_ms=2,
            sentence=SentenceDiagnostic(
                sentence_id="sentence-prefix-1",
                sentence_sha256=hashlib.sha256(prefix.encode()).hexdigest(),
                validation_status="supported",
                start_char=0,
                end_char=len(prefix),
                evidence_ids=("evidence-1",),
            ),
        )
    )
    with pytest.raises(GrpcStreamContractError, match="exactly cover"):
        incomplete.accept(
            GrpcStreamFrame(
                request_id="request-owner-1",
                sequence=3,
                kind=GrpcFrameKind.FINAL,
                elapsed_ms=3,
                final_response=_response(text, ttft=1),
            )
        )


def test_stream_rejects_diagnostic_digest_for_different_text() -> None:
    text = "Supported answer."
    accumulator = GrpcStreamAccumulator("request-owner-1")
    accumulator.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=1,
            kind=GrpcFrameKind.TOKEN,
            elapsed_ms=1,
            token_text=text,
        )
    )
    accumulator.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=2,
            kind=GrpcFrameKind.SENTENCE,
            elapsed_ms=2,
            sentence=SentenceDiagnostic(
                sentence_id="sentence-wrong-hash-1",
                sentence_sha256=hashlib.sha256(b"Different answer.").hexdigest(),
                validation_status="supported",
                start_char=0,
                end_char=len(text),
                evidence_ids=("evidence-1",),
            ),
        )
    )
    with pytest.raises(GrpcStreamContractError, match="digest differs"):
        accumulator.accept(
            GrpcStreamFrame(
                request_id="request-owner-1",
                sequence=3,
                kind=GrpcFrameKind.FINAL,
                elapsed_ms=3,
                final_response=_response(text, ttft=1),
            )
        )

    accumulator = GrpcStreamAccumulator("request-owner-1")
    accumulator.accept(
        GrpcStreamFrame(
            request_id="request-owner-1",
            sequence=1,
            kind=GrpcFrameKind.TOKEN,
            elapsed_ms=1,
            token_text="streamed",
        )
    )
    with pytest.raises(GrpcStreamContractError, match="differs"):
        accumulator.accept(
            GrpcStreamFrame(
                request_id="request-owner-1",
                sequence=2,
                kind=GrpcFrameKind.FINAL,
                elapsed_ms=2,
                final_response=_response("different", ttft=1),
            )
        )


def test_proto_and_transport_intent_are_uds_only_and_non_authorizing() -> None:
    project_root = Path(__file__).resolve().parents[2]
    proto = (
        project_root / "backend/app/model_runtime/proto/legalbot_model_runtime.proto"
    ).read_text(encoding="utf-8")

    assert "rpc GenerateStream" in proto
    assert "stream GenerateStreamFrame" in proto
    assert "time_to_first_token_ms" in proto
    assert "SentenceDiagnosticFrame" in proto
    assert GRPC_UDS_TRANSPORT_INTENT.uds_only is True
    assert GRPC_UDS_TRANSPORT_INTENT.network_fallback_allowed is False
    assert GRPC_UDS_TRANSPORT_INTENT.authorizing is False
    assert GRPC_UDS_TRANSPORT_INTENT.activation_requirement == GRPC_ACTIVATION_STOP
