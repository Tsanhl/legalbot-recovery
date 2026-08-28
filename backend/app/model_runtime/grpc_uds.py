"""Private gRPC Unix-socket server/client, technically complete but gate-disabled."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
import time
from concurrent import futures
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import grpc  # type: ignore[import-untyped]

from .adapters import (
    GenerationCancelledError,
    ModelBackend,
    RequestLimitError,
    RuntimeNotReadyError,
)
from .contracts import ContractError, GenerateRequest, GenerateResponse, Usage
from .proto import legalbot_model_runtime_pb2 as pb2
from .proto import legalbot_model_runtime_pb2_grpc as pb2_grpc

PHASE2B_GRPC_ACTIVATION_STOP = "phase2b_exact_owner_payload_required"
_AUTHORITY_TOKEN = object()
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class GrpcUdsError(RuntimeError):
    pass


class VerifiedGrpcTransportActivation:
    """Opaque activation capability; no production factory exists before Phase 2B."""

    __slots__ = ("_test_only", "_token")

    def __init__(self, *, test_only: bool, token: object) -> None:
        if token is not _AUTHORITY_TOKEN:
            raise TypeError("verified Phase-2B gRPC transport authority is required")
        self._test_only = test_only
        self._token = token


def technical_test_activation(*, test_mode: bool) -> VerifiedGrpcTransportActivation:
    if not test_mode:
        raise RuntimeError(PHASE2B_GRPC_ACTIVATION_STOP)
    return VerifiedGrpcTransportActivation(test_only=True, token=_AUTHORITY_TOKEN)


@dataclass(frozen=True, slots=True)
class GrpcUdsConfig:
    socket_path: Path
    project_root: Path
    test_mode: bool = False
    max_request_bytes: int = 1_048_576
    max_response_bytes: int = 4_194_304
    default_deadline_seconds: float = 300.0

    def __post_init__(self) -> None:
        socket_path = self.socket_path.expanduser()
        project_root = self.project_root.resolve(strict=True)
        if not socket_path.is_absolute() or len(os.fsencode(socket_path)) > 103:
            raise ValueError("gRPC UDS path must be one short absolute filesystem path")
        parent = socket_path.parent.resolve(strict=True)
        metadata = parent.stat(follow_symlinks=False)
        if (
            socket_path.parent != parent
            or socket_path.name in {"", ".", ".."}
            or parent.is_symlink()
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError("gRPC UDS parent must be one owner-only 0700 directory")
        if not self.test_mode and parent.is_relative_to(project_root):
            raise ValueError("production gRPC UDS must be outside the project worktree")
        if self.max_request_bytes < 1024 or self.max_response_bytes < 1024:
            raise ValueError("gRPC message limits are invalid")
        if not 0.05 <= self.default_deadline_seconds <= 600:
            raise ValueError("gRPC default deadline is invalid")
        object.__setattr__(self, "socket_path", parent / socket_path.name)
        object.__setattr__(self, "project_root", project_root)


def _require_activation(
    value: object,
    *,
    config: GrpcUdsConfig,
) -> VerifiedGrpcTransportActivation:
    if (
        type(value) is not VerifiedGrpcTransportActivation
        or value._token is not _AUTHORITY_TOKEN
        or (value._test_only and not config.test_mode)
    ):
        raise RuntimeError(PHASE2B_GRPC_ACTIVATION_STOP)
    return value


def _target(path: Path) -> str:
    return f"unix://{path}"


def _channel_options(config: GrpcUdsConfig) -> tuple[tuple[str, int], ...]:
    return (
        ("grpc.max_send_message_length", config.max_request_bytes),
        ("grpc.max_receive_message_length", config.max_response_bytes),
        ("grpc.enable_retries", 0),
        ("grpc.max_reconnect_backoff_ms", 1000),
    )


def _request_from_proto(value: pb2.GenerateStreamRequest) -> GenerateRequest:
    try:
        payload = json.loads(bytes(value.payload_json or b"{}").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("payload_json must be one UTF-8 JSON object") from exc
    request = GenerateRequest.from_dict(
        {
            "request_id": value.request_id,
            "mode": value.mode,
            "payload": payload,
            "messages": [
                {"role": message.role, "content": message.content} for message in value.messages
            ],
            "max_tokens": value.max_tokens,
            "temperature": value.temperature,
            "top_p": value.top_p,
            "seed": value.seed,
            "stop": list(value.stop),
        }
    )
    for label, digest in (
        ("prompt_sha256", value.prompt_sha256),
        ("candidate_sha256", value.candidate_sha256),
    ):
        if digest and _SHA256.fullmatch(digest) is None:
            raise ContractError(f"{label} is invalid")
    return request


class _Servicer(pb2_grpc.LegalBotModelRuntimeServicer):
    def __init__(self, backend: ModelBackend) -> None:
        self.backend = backend
        self._generation_slot = threading.BoundedSemaphore(1)

    def Health(self, request: pb2.HealthRequest, context: grpc.ServicerContext) -> pb2.HealthReply:
        del request
        health = self.backend.health()
        return pb2.HealthReply(
            status=health.status,
            model_id=health.model_id,
            model_version=health.model_id,
            model_loaded=health.model_loaded,
        )

    def GenerateStream(
        self,
        request: pb2.GenerateStreamRequest,
        context: grpc.ServicerContext,
    ) -> Any:
        if not self._generation_slot.acquire(blocking=False):
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "model generation is at capacity")
        started = time.monotonic()
        sequence = 0
        try:
            parsed = _request_from_proto(request)

            def cancelled() -> bool:
                remaining = context.time_remaining()
                return not context.is_active() or (remaining is not None and remaining <= 0)

            stream = self.backend.generate_stream(parsed, cancelled)
            token_parts: list[str] = []
            while True:
                if cancelled():
                    raise GenerationCancelledError("gRPC generation cancelled")
                try:
                    token = next(stream)
                except StopIteration as completed:
                    response = completed.value
                    break
                if not token:
                    continue
                token_parts.append(token)
                sequence += 1
                yield pb2.GenerateStreamFrame(
                    request_id=parsed.request_id,
                    sequence=sequence,
                    token=pb2.TokenFrame(
                        text=token,
                        elapsed_ms=round((time.monotonic() - started) * 1000),
                    ),
                )
            raw_text = "".join(token_parts)
            if raw_text != response.raw_text:
                context.abort(grpc.StatusCode.DATA_LOSS, "stream and final response differ")
            sequence += 1
            yield pb2.GenerateStreamFrame(
                request_id=parsed.request_id,
                sequence=sequence,
                final=pb2.FinalFrame(
                    model_version=response.model_version,
                    backend=response.backend,
                    raw_text_sha256=hashlib.sha256(raw_text.encode()).hexdigest(),
                    structured_json=json.dumps(
                        dict(response.structured),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode(),
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    generation_ms=response.generation_ms,
                    time_to_first_token_ms=response.time_to_first_token_ms or 0,
                    finish_reason=response.finish_reason,
                    deterministic=response.deterministic,
                ),
            )
        except GenerationCancelledError:
            context.abort(grpc.StatusCode.CANCELLED, "model generation cancelled")
        except (ContractError, RequestLimitError, ValueError):
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "model request contract rejected")
        except RuntimeNotReadyError:
            context.abort(grpc.StatusCode.UNAVAILABLE, "model runtime unavailable")
        except grpc.RpcError:
            raise
        except Exception:
            # A backend may observe the cancellation callback and unwind with
            # its own exception type. Preserve the transport cancellation
            # semantics instead of misreporting that path as a model fault.
            remaining = context.time_remaining()
            if not context.is_active() or (remaining is not None and remaining <= 0):
                context.abort(grpc.StatusCode.CANCELLED, "model generation cancelled")
            context.abort(grpc.StatusCode.INTERNAL, "model runtime failed")
        finally:
            self._generation_slot.release()


class GrpcUdsServer:
    def __init__(
        self,
        config: GrpcUdsConfig,
        backend: ModelBackend,
        activation: object,
    ) -> None:
        _require_activation(activation, config=config)
        self.config = config
        self.backend = backend
        self._server: grpc.Server | None = None
        self._socket_identity: tuple[int, int] | None = None

    def start(self) -> None:
        if self._server is not None:
            raise GrpcUdsError("gRPC UDS server is already started")
        path = self.config.socket_path
        if path.exists() or path.is_symlink():
            raise GrpcUdsError("gRPC UDS path already exists")
        server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="legalbot-grpc"),
            # One generation is admitted by the servicer semaphore while a
            # second RPC slot remains available for Health during backpressure.
            maximum_concurrent_rpcs=2,
            options=_channel_options(self.config),
        )
        pb2_grpc.add_LegalBotModelRuntimeServicer_to_server(  # type: ignore[no-untyped-call]
            _Servicer(self.backend), server
        )
        if server.add_insecure_port(_target(path)) != 1:
            raise GrpcUdsError("gRPC UDS bind failed")
        server.start()
        deadline = time.monotonic() + 2
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        if not path.exists():
            server.stop(grace=None)
            raise GrpcUdsError("gRPC UDS socket was not created")
        path.chmod(0o600)
        metadata = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            server.stop(grace=None)
            raise GrpcUdsError("gRPC UDS socket identity is unsafe")
        self._socket_identity = (metadata.st_dev, metadata.st_ino)
        self._server = server

    def stop(self, *, grace_seconds: float = 0.0) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.stop(grace_seconds).wait(timeout=max(1.0, grace_seconds + 1.0))
        path = self.config.socket_path
        if path.exists() and self._socket_identity is not None:
            metadata = path.stat(follow_symlinks=False)
            if (metadata.st_dev, metadata.st_ino) == self._socket_identity:
                path.unlink()
        self._socket_identity = None


class GrpcUdsClient:
    def __init__(self, config: GrpcUdsConfig, activation: object) -> None:
        _require_activation(activation, config=config)
        self.config = config
        self._channel = grpc.insecure_channel(
            _target(config.socket_path), options=_channel_options(config)
        )
        self._stub = pb2_grpc.LegalBotModelRuntimeStub(  # type: ignore[no-untyped-call]
            self._channel
        )

    def close(self) -> None:
        self._channel.close()

    def health(self, *, timeout: float = 3.0) -> pb2.HealthReply:
        return cast(
            pb2.HealthReply,
            self._stub.Health(pb2.HealthRequest(), timeout=timeout, wait_for_ready=False),
        )

    def open_stream(
        self,
        request: GenerateRequest,
        *,
        timeout: float | None = None,
        prompt_sha256: str = "",
        candidate_sha256: str = "",
    ) -> Any:
        value = pb2.GenerateStreamRequest(
            request_id=request.request_id,
            mode=request.mode,
            payload_json=json.dumps(
                dict(request.payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode(),
            messages=[pb2.ChatMessage(role=item.role, content=item.content) for item in request.messages],
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            top_p=request.top_p,
            seed=request.seed,
            stop=list(request.stop),
            prompt_sha256=prompt_sha256,
            candidate_sha256=candidate_sha256,
        )
        return self._stub.GenerateStream(
            value,
            timeout=timeout or self.config.default_deadline_seconds,
            wait_for_ready=False,
        )

    def generate(
        self,
        request: GenerateRequest,
        *,
        timeout: float | None = None,
    ) -> GenerateResponse:
        call = self.open_stream(request, timeout=timeout)
        tokens: list[str] = []
        expected_sequence = 1
        final: pb2.FinalFrame | None = None
        for frame in call:
            if frame.request_id != request.request_id or frame.sequence != expected_sequence:
                raise GrpcUdsError("gRPC stream identity or sequence is invalid")
            expected_sequence += 1
            kind = frame.WhichOneof("frame")
            if kind == "token":
                tokens.append(frame.token.text)
            elif kind == "final" and final is None:
                final = frame.final
            else:
                raise GrpcUdsError("gRPC stream contained an unsupported frame")
        if final is None:
            raise GrpcUdsError("gRPC stream ended without a final frame")
        raw_text = "".join(tokens)
        if hashlib.sha256(raw_text.encode()).hexdigest() != final.raw_text_sha256:
            raise GrpcUdsError("gRPC final text digest does not match streamed tokens")
        structured = json.loads(bytes(final.structured_json or b"{}").decode())
        if not isinstance(structured, dict):
            raise GrpcUdsError("gRPC structured response is not an object")
        return GenerateResponse(
            request_id=request.request_id,
            model_version=final.model_version,
            backend=final.backend,
            raw_text=raw_text,
            structured=structured,
            rubric_scores={},
            finish_reason=final.finish_reason,
            usage=Usage(input_tokens=final.input_tokens, output_tokens=final.output_tokens),
            generation_ms=final.generation_ms,
            deterministic=final.deterministic,
            time_to_first_token_ms=final.time_to_first_token_ms,
        )
