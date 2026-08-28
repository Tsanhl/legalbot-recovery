"""Release-boundary validation for the private gRPC model stream.

Generated protobuf/grpc modules and the technically complete UDS server/client
now exist, but their production activation capability remains unavailable in
Phase 2A. This module freezes sequencing, TTFT, sentence-level diagnostics and
the no-browser-token rule that the exact Phase-2B gate must bind and activate.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

from .contracts import GenerateResponse

GRPC_CONTRACT_SCHEMA = "legalbot.private-model-grpc-stream.v1"
GRPC_SERVICE_NAME: Literal["legalbot.modelruntime.v1.LegalBotModelRuntime"] = (
    "legalbot.modelruntime.v1.LegalBotModelRuntime"
)
GRPC_ACTIVATION_STOP: Literal["phase2b_exact_owner_payload_required"] = (
    "phase2b_exact_owner_payload_required"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9._:-]{1,127}$")
_VALIDATION_STATUSES = frozenset(
    {"pending_validation", "supported", "not_material", "knowledge_gap", "unsupported"}
)


class GrpcStreamContractError(RuntimeError):
    pass


class GrpcFrameKind(StrEnum):
    TOKEN = "token"
    SENTENCE = "sentence"
    DIAGNOSTIC = "diagnostic"
    FINAL = "final"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class SentenceDiagnostic:
    sentence_id: str
    sentence_sha256: str
    validation_status: str
    start_char: int
    end_char: int
    evidence_ids: tuple[str, ...] = ()
    standard_ids: tuple[str, ...] = ()
    hurdle_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.sentence_id):
            raise ValueError("sentence diagnostic ID is invalid")
        if not _SHA256.fullmatch(self.sentence_sha256):
            raise ValueError("sentence diagnostic digest is invalid")
        if self.validation_status not in _VALIDATION_STATUSES:
            raise ValueError("sentence validation status is invalid")
        if self.start_char < 0 or self.end_char <= self.start_char:
            raise ValueError("sentence diagnostic character range is invalid")
        if len(self.evidence_ids) > 50 or len(self.standard_ids) > 50:
            raise ValueError("sentence diagnostic binding count is invalid")
        if any(not _SAFE_ID.fullmatch(value) for value in self.evidence_ids):
            raise ValueError("sentence evidence identity is invalid")
        if any(not _SAFE_ID.fullmatch(value) for value in self.standard_ids):
            raise ValueError("sentence standard identity is invalid")
        if any(not _SAFE_CODE.fullmatch(value) for value in self.hurdle_codes):
            raise ValueError("sentence hurdle code is invalid")
        if self.validation_status == "supported" and not self.evidence_ids:
            raise ValueError("supported sentence requires exact evidence identities")
        if self.validation_status in {"knowledge_gap", "unsupported"} and not self.hurdle_codes:
            raise ValueError("blocked sentence requires a knowledge/evidence hurdle code")


@dataclass(frozen=True, slots=True)
class GrpcStreamFrame:
    request_id: str
    sequence: int
    kind: GrpcFrameKind
    elapsed_ms: int
    token_text: str | None = field(default=None, repr=False)
    sentence: SentenceDiagnostic | None = None
    diagnostic_code: str | None = None
    safe_metrics: dict[str, int | float | str | bool | None] = field(default_factory=dict)
    final_response: GenerateResponse | None = field(default=None, repr=False)
    error_code: str | None = None
    retryable: bool = False

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.request_id):
            raise ValueError("gRPC stream request ID is invalid")
        if self.sequence < 1 or self.elapsed_ms < 0:
            raise ValueError("gRPC stream sequence or elapsed time is invalid")
        populated = sum(
            value is not None
            for value in (
                self.token_text,
                self.sentence,
                self.diagnostic_code,
                self.final_response,
                self.error_code,
            )
        )
        if populated != 1:
            raise ValueError("gRPC stream frame must contain exactly one payload")
        expected = {
            GrpcFrameKind.TOKEN: self.token_text is not None,
            GrpcFrameKind.SENTENCE: self.sentence is not None,
            GrpcFrameKind.DIAGNOSTIC: self.diagnostic_code is not None,
            GrpcFrameKind.FINAL: self.final_response is not None,
            GrpcFrameKind.ERROR: self.error_code is not None,
        }
        if not expected[self.kind]:
            raise ValueError("gRPC stream frame kind and payload differ")
        if self.token_text is not None and (not self.token_text or len(self.token_text) > 16_384):
            raise ValueError("gRPC token frame is empty or too large")
        for code in (self.diagnostic_code, self.error_code):
            if code is not None and not _SAFE_CODE.fullmatch(code):
                raise ValueError("gRPC diagnostic code is invalid")
        try:
            encoded_metrics = json.dumps(
                self.safe_metrics, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("gRPC safe metrics are not JSON") from exc
        if len(encoded_metrics) > 16_384:
            raise ValueError("gRPC safe metrics are too large")


@dataclass(frozen=True, slots=True)
class GrpcStreamResult:
    response: GenerateResponse = field(repr=False)
    time_to_first_token_ms: int
    sentence_diagnostics: tuple[SentenceDiagnostic, ...]
    runtime_diagnostic_codes: tuple[str, ...]
    token_frame_count: int
    generated_character_count: int
    releaseable: bool

    def safe_debug_log(self) -> dict[str, Any]:
        return {
            "schema": GRPC_CONTRACT_SCHEMA,
            "request_id": self.response.request_id,
            "model_version": self.response.model_version,
            "backend": self.response.backend,
            "time_to_first_token_ms": self.time_to_first_token_ms,
            "generation_ms": self.response.generation_ms,
            "token_frame_count": self.token_frame_count,
            "generated_character_count": self.generated_character_count,
            "sentence_diagnostics": [
                {
                    "sentence_id": item.sentence_id,
                    "sentence_sha256": item.sentence_sha256,
                    "validation_status": item.validation_status,
                    "start_char": item.start_char,
                    "end_char": item.end_char,
                    "evidence_ids": list(item.evidence_ids),
                    "standard_ids": list(item.standard_ids),
                    "hurdle_codes": list(item.hurdle_codes),
                }
                for item in self.sentence_diagnostics
            ],
            "runtime_diagnostic_codes": list(self.runtime_diagnostic_codes),
            "releaseable": self.releaseable,
            "raw_token_text_persisted": False,
            "browser_token_stream_allowed": False,
        }


class GrpcStreamAccumulator:
    """Validate one ordered server stream and expose only a final result."""

    def __init__(self, request_id: str, *, max_generated_characters: int = 1_000_000) -> None:
        if not _SAFE_ID.fullmatch(request_id):
            raise ValueError("gRPC stream request ID is invalid")
        if not 1_024 <= max_generated_characters <= 4_000_000:
            raise ValueError("gRPC stream character cap is invalid")
        self.request_id = request_id
        self.max_generated_characters = max_generated_characters
        self._next_sequence = 1
        self._token_parts: list[str] = []
        self._generated_characters = 0
        self._first_token_ms: int | None = None
        self._sentences: list[SentenceDiagnostic] = []
        self._diagnostics: list[str] = []
        self._final: GenerateResponse | None = None
        self._failed = False

    def accept(self, frame: GrpcStreamFrame) -> None:
        if self._final is not None or self._failed:
            raise GrpcStreamContractError("gRPC stream continued after a terminal frame")
        if frame.request_id != self.request_id:
            raise GrpcStreamContractError("gRPC stream request identity changed")
        if frame.sequence != self._next_sequence:
            raise GrpcStreamContractError("gRPC stream sequence is not contiguous")
        self._next_sequence += 1
        if frame.kind is GrpcFrameKind.TOKEN:
            assert frame.token_text is not None
            self._generated_characters += len(frame.token_text)
            if self._generated_characters > self.max_generated_characters:
                raise GrpcStreamContractError("gRPC stream exceeded its character cap")
            if self._first_token_ms is None:
                self._first_token_ms = frame.elapsed_ms
            self._token_parts.append(frame.token_text)
            return
        if frame.kind is GrpcFrameKind.SENTENCE:
            assert frame.sentence is not None
            if any(item.sentence_id == frame.sentence.sentence_id for item in self._sentences):
                raise GrpcStreamContractError("gRPC sentence diagnostic ID was repeated")
            self._sentences.append(frame.sentence)
            return
        if frame.kind is GrpcFrameKind.DIAGNOSTIC:
            assert frame.diagnostic_code is not None
            self._diagnostics.append(frame.diagnostic_code)
            return
        if frame.kind is GrpcFrameKind.ERROR:
            self._failed = True
            raise GrpcStreamContractError(frame.error_code or "gRPC model runtime error")
        assert frame.final_response is not None
        response = frame.final_response
        if response.request_id != self.request_id:
            raise GrpcStreamContractError("gRPC final response request identity changed")
        if self._first_token_ms is None:
            raise GrpcStreamContractError("gRPC final response arrived before a token")
        streamed = "".join(self._token_parts)
        if streamed != response.raw_text:
            raise GrpcStreamContractError("gRPC token stream differs from final response")
        self._validate_sentence_coverage(streamed)
        if (
            response.time_to_first_token_ms is not None
            and response.time_to_first_token_ms != self._first_token_ms
        ):
            raise GrpcStreamContractError("gRPC TTFT differs from the final response")
        self._final = response

    def _validate_sentence_coverage(self, raw_text: str) -> None:
        """Bind every output character to one ordered diagnostic before release."""

        if not self._sentences:
            raise GrpcStreamContractError("gRPC final response has no sentence diagnostics")
        cursor = 0
        for item in self._sentences:
            if item.start_char != cursor or item.end_char > len(raw_text):
                raise GrpcStreamContractError(
                    "gRPC sentence diagnostics do not exactly cover final response"
                )
            exact_text = raw_text[item.start_char : item.end_char]
            exact_digest = hashlib.sha256(exact_text.encode()).hexdigest()
            if exact_digest != item.sentence_sha256:
                raise GrpcStreamContractError(
                    "gRPC sentence diagnostic digest differs from final response"
                )
            cursor = item.end_char
        if cursor != len(raw_text):
            raise GrpcStreamContractError(
                "gRPC sentence diagnostics do not exactly cover final response"
            )

    def result(self) -> GrpcStreamResult:
        if self._final is None:
            raise GrpcStreamContractError("gRPC stream has no final response")
        assert self._first_token_ms is not None
        blocked = not self._sentences or any(
            item.validation_status in {"pending_validation", "knowledge_gap", "unsupported"}
            for item in self._sentences
        )
        return GrpcStreamResult(
            response=self._final,
            time_to_first_token_ms=self._first_token_ms,
            sentence_diagnostics=tuple(self._sentences),
            runtime_diagnostic_codes=tuple(self._diagnostics),
            token_frame_count=len(self._token_parts),
            generated_character_count=self._generated_characters,
            releaseable=not blocked,
        )


@dataclass(frozen=True, slots=True)
class GrpcUdsTransportIntent:
    schema: Literal["legalbot.private-model-grpc-uds-intent.v1"] = (
        "legalbot.private-model-grpc-uds-intent.v1"
    )
    service_name: Literal["legalbot.modelruntime.v1.LegalBotModelRuntime"] = GRPC_SERVICE_NAME
    uds_only: Literal[True] = True
    network_fallback_allowed: Literal[False] = False
    browser_raw_token_forwarding_allowed: Literal[False] = False
    activation_requirement: Literal["phase2b_exact_owner_payload_required"] = GRPC_ACTIVATION_STOP
    authorizing: Literal[False] = False

    @property
    def identity_sha256(self) -> str:
        payload = {
            "schema": self.schema,
            "service_name": self.service_name,
            "uds_only": self.uds_only,
            "network_fallback_allowed": self.network_fallback_allowed,
            "browser_raw_token_forwarding_allowed": self.browser_raw_token_forwarding_allowed,
            "activation_requirement": self.activation_requirement,
            "authorizing": self.authorizing,
        }
        return hashlib.sha256(
            (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest()


GRPC_UDS_TRANSPORT_INTENT = GrpcUdsTransportIntent()
