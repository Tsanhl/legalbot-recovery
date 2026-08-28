"""Versioned local model-runtime service for LegalBot-New."""

from .adapters import MlxModelBackend, StubModelBackend, build_backend
from .config import ModelRuntimeConfig, SafeMemoryConfig
from .contracts import (
    API_VERSION,
    GenerateRequest,
    GenerateResponse,
    HealthResponse,
    Message,
    Usage,
)
from .grpc_streaming import (
    GRPC_ACTIVATION_STOP,
    GRPC_CONTRACT_SCHEMA,
    GRPC_UDS_TRANSPORT_INTENT,
    GrpcFrameKind,
    GrpcStreamAccumulator,
    GrpcStreamContractError,
    GrpcStreamFrame,
    GrpcStreamResult,
    SentenceDiagnostic,
)

__all__ = [
    "API_VERSION",
    "GRPC_ACTIVATION_STOP",
    "GRPC_CONTRACT_SCHEMA",
    "GRPC_UDS_TRANSPORT_INTENT",
    "GenerateRequest",
    "GenerateResponse",
    "GrpcFrameKind",
    "GrpcStreamAccumulator",
    "GrpcStreamContractError",
    "GrpcStreamFrame",
    "GrpcStreamResult",
    "HealthResponse",
    "Message",
    "MlxModelBackend",
    "ModelRuntimeConfig",
    "SafeMemoryConfig",
    "SentenceDiagnostic",
    "StubModelBackend",
    "Usage",
    "build_backend",
]
