from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class HealthRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HealthReply(_message.Message):
    __slots__ = ("status", "model_id", "model_version", "model_loaded")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MODEL_ID_FIELD_NUMBER: _ClassVar[int]
    MODEL_VERSION_FIELD_NUMBER: _ClassVar[int]
    MODEL_LOADED_FIELD_NUMBER: _ClassVar[int]
    status: str
    model_id: str
    model_version: str
    model_loaded: bool
    def __init__(
        self,
        status: _Optional[str] = ...,
        model_id: _Optional[str] = ...,
        model_version: _Optional[str] = ...,
        model_loaded: _Optional[bool] = ...,
    ) -> None: ...

class ChatMessage(_message.Message):
    __slots__ = ("role", "content")
    ROLE_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    role: str
    content: str
    def __init__(self, role: _Optional[str] = ..., content: _Optional[str] = ...) -> None: ...

class GenerateStreamRequest(_message.Message):
    __slots__ = (
        "request_id",
        "mode",
        "payload_json",
        "messages",
        "max_tokens",
        "temperature",
        "top_p",
        "seed",
        "stop",
        "prompt_sha256",
        "candidate_sha256",
    )
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_JSON_FIELD_NUMBER: _ClassVar[int]
    MESSAGES_FIELD_NUMBER: _ClassVar[int]
    MAX_TOKENS_FIELD_NUMBER: _ClassVar[int]
    TEMPERATURE_FIELD_NUMBER: _ClassVar[int]
    TOP_P_FIELD_NUMBER: _ClassVar[int]
    SEED_FIELD_NUMBER: _ClassVar[int]
    STOP_FIELD_NUMBER: _ClassVar[int]
    PROMPT_SHA256_FIELD_NUMBER: _ClassVar[int]
    CANDIDATE_SHA256_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    mode: str
    payload_json: bytes
    messages: _containers.RepeatedCompositeFieldContainer[ChatMessage]
    max_tokens: int
    temperature: float
    top_p: float
    seed: int
    stop: _containers.RepeatedScalarFieldContainer[str]
    prompt_sha256: str
    candidate_sha256: str
    def __init__(
        self,
        request_id: _Optional[str] = ...,
        mode: _Optional[str] = ...,
        payload_json: _Optional[bytes] = ...,
        messages: _Optional[_Iterable[_Union[ChatMessage, _Mapping]]] = ...,
        max_tokens: _Optional[int] = ...,
        temperature: _Optional[float] = ...,
        top_p: _Optional[float] = ...,
        seed: _Optional[int] = ...,
        stop: _Optional[_Iterable[str]] = ...,
        prompt_sha256: _Optional[str] = ...,
        candidate_sha256: _Optional[str] = ...,
    ) -> None: ...

class TokenFrame(_message.Message):
    __slots__ = ("text", "elapsed_ms")
    TEXT_FIELD_NUMBER: _ClassVar[int]
    ELAPSED_MS_FIELD_NUMBER: _ClassVar[int]
    text: str
    elapsed_ms: int
    def __init__(self, text: _Optional[str] = ..., elapsed_ms: _Optional[int] = ...) -> None: ...

class SentenceDiagnosticFrame(_message.Message):
    __slots__ = (
        "sentence_id",
        "sentence_sha256",
        "validation_status",
        "evidence_ids",
        "standard_ids",
        "hurdle_codes",
        "start_char",
        "end_char",
    )
    SENTENCE_ID_FIELD_NUMBER: _ClassVar[int]
    SENTENCE_SHA256_FIELD_NUMBER: _ClassVar[int]
    VALIDATION_STATUS_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_IDS_FIELD_NUMBER: _ClassVar[int]
    STANDARD_IDS_FIELD_NUMBER: _ClassVar[int]
    HURDLE_CODES_FIELD_NUMBER: _ClassVar[int]
    START_CHAR_FIELD_NUMBER: _ClassVar[int]
    END_CHAR_FIELD_NUMBER: _ClassVar[int]
    sentence_id: str
    sentence_sha256: str
    validation_status: str
    evidence_ids: _containers.RepeatedScalarFieldContainer[str]
    standard_ids: _containers.RepeatedScalarFieldContainer[str]
    hurdle_codes: _containers.RepeatedScalarFieldContainer[str]
    start_char: int
    end_char: int
    def __init__(
        self,
        sentence_id: _Optional[str] = ...,
        sentence_sha256: _Optional[str] = ...,
        validation_status: _Optional[str] = ...,
        evidence_ids: _Optional[_Iterable[str]] = ...,
        standard_ids: _Optional[_Iterable[str]] = ...,
        hurdle_codes: _Optional[_Iterable[str]] = ...,
        start_char: _Optional[int] = ...,
        end_char: _Optional[int] = ...,
    ) -> None: ...

class RuntimeDiagnosticFrame(_message.Message):
    __slots__ = ("code", "elapsed_ms", "safe_metrics_json")
    CODE_FIELD_NUMBER: _ClassVar[int]
    ELAPSED_MS_FIELD_NUMBER: _ClassVar[int]
    SAFE_METRICS_JSON_FIELD_NUMBER: _ClassVar[int]
    code: str
    elapsed_ms: int
    safe_metrics_json: bytes
    def __init__(
        self,
        code: _Optional[str] = ...,
        elapsed_ms: _Optional[int] = ...,
        safe_metrics_json: _Optional[bytes] = ...,
    ) -> None: ...

class FinalFrame(_message.Message):
    __slots__ = (
        "model_version",
        "backend",
        "raw_text_sha256",
        "structured_json",
        "input_tokens",
        "output_tokens",
        "generation_ms",
        "time_to_first_token_ms",
        "finish_reason",
        "deterministic",
    )
    MODEL_VERSION_FIELD_NUMBER: _ClassVar[int]
    BACKEND_FIELD_NUMBER: _ClassVar[int]
    RAW_TEXT_SHA256_FIELD_NUMBER: _ClassVar[int]
    STRUCTURED_JSON_FIELD_NUMBER: _ClassVar[int]
    INPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    GENERATION_MS_FIELD_NUMBER: _ClassVar[int]
    TIME_TO_FIRST_TOKEN_MS_FIELD_NUMBER: _ClassVar[int]
    FINISH_REASON_FIELD_NUMBER: _ClassVar[int]
    DETERMINISTIC_FIELD_NUMBER: _ClassVar[int]
    model_version: str
    backend: str
    raw_text_sha256: str
    structured_json: bytes
    input_tokens: int
    output_tokens: int
    generation_ms: int
    time_to_first_token_ms: int
    finish_reason: str
    deterministic: bool
    def __init__(
        self,
        model_version: _Optional[str] = ...,
        backend: _Optional[str] = ...,
        raw_text_sha256: _Optional[str] = ...,
        structured_json: _Optional[bytes] = ...,
        input_tokens: _Optional[int] = ...,
        output_tokens: _Optional[int] = ...,
        generation_ms: _Optional[int] = ...,
        time_to_first_token_ms: _Optional[int] = ...,
        finish_reason: _Optional[str] = ...,
        deterministic: _Optional[bool] = ...,
    ) -> None: ...

class ErrorFrame(_message.Message):
    __slots__ = ("code", "retryable")
    CODE_FIELD_NUMBER: _ClassVar[int]
    RETRYABLE_FIELD_NUMBER: _ClassVar[int]
    code: str
    retryable: bool
    def __init__(self, code: _Optional[str] = ..., retryable: _Optional[bool] = ...) -> None: ...

class GenerateStreamFrame(_message.Message):
    __slots__ = ("request_id", "sequence", "token", "sentence", "diagnostic", "final", "error")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    SENTENCE_FIELD_NUMBER: _ClassVar[int]
    DIAGNOSTIC_FIELD_NUMBER: _ClassVar[int]
    FINAL_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    sequence: int
    token: TokenFrame
    sentence: SentenceDiagnosticFrame
    diagnostic: RuntimeDiagnosticFrame
    final: FinalFrame
    error: ErrorFrame
    def __init__(
        self,
        request_id: _Optional[str] = ...,
        sequence: _Optional[int] = ...,
        token: _Optional[_Union[TokenFrame, _Mapping]] = ...,
        sentence: _Optional[_Union[SentenceDiagnosticFrame, _Mapping]] = ...,
        diagnostic: _Optional[_Union[RuntimeDiagnosticFrame, _Mapping]] = ...,
        final: _Optional[_Union[FinalFrame, _Mapping]] = ...,
        error: _Optional[_Union[ErrorFrame, _Mapping]] = ...,
    ) -> None: ...
