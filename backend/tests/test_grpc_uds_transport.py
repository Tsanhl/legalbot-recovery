from __future__ import annotations

import tempfile
import threading
import time
from collections.abc import Callable, Generator
from pathlib import Path

import grpc
import pytest

from app.model_runtime.adapters import StubModelBackend
from app.model_runtime.config import ModelRuntimeConfig
from app.model_runtime.contracts import (
    GenerateRequest,
    GenerateResponse,
    HealthResponse,
    Usage,
)
from app.model_runtime.grpc_uds import (
    GrpcUdsClient,
    GrpcUdsConfig,
    GrpcUdsServer,
    technical_test_activation,
)


@pytest.fixture
def short_root() -> Generator[Path]:
    with tempfile.TemporaryDirectory(prefix="lbg-", dir="/private/tmp") as value:
        yield Path(value)


def _config(tmp_path: Path) -> GrpcUdsConfig:
    tmp_path.mkdir(parents=True, exist_ok=True)
    project = tmp_path / "project"
    project.mkdir()
    parent = tmp_path / "uds"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    return GrpcUdsConfig(
        socket_path=parent / "model.sock",
        project_root=project,
        test_mode=True,
        default_deadline_seconds=1,
    )


def _request() -> GenerateRequest:
    return GenerateRequest.from_dict(
        {
            "request_id": "request-grpc-1",
            "mode": "semantic_verify",
            "payload": {"purpose": "transport-test"},
            "messages": [{"role": "user", "content": "transport test"}],
            "max_tokens": 8,
            "temperature": 0,
            "top_p": 1,
            "seed": 0,
            "stop": [],
        }
    )


def _response(request: GenerateRequest, text: str) -> GenerateResponse:
    return GenerateResponse(
        request_id=request.request_id,
        model_version="test/model@1",
        backend="test",
        raw_text=text,
        structured={"ok": True},
        rubric_scores={},
        finish_reason="complete",
        usage=Usage(input_tokens=2, output_tokens=1),
        generation_ms=1,
        deterministic=True,
        time_to_first_token_ms=1,
    )


class _ControlledBackend:
    def __init__(self, *, blocked: bool = False, slow: bool = False) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.blocked = blocked
        self.slow = slow

    def health(self) -> HealthResponse:
        return HealthResponse(
            status="ok",
            backend="test",
            model_id="test/model",
            model_loaded=True,
            stub_mode=True,
            memory_profile={},
        )

    def generate(self, request: GenerateRequest) -> GenerateResponse:
        stream = self.generate_stream(request, lambda: False)
        while True:
            try:
                next(stream)
            except StopIteration as complete:
                return complete.value

    def generate_stream(
        self,
        request: GenerateRequest,
        cancelled: Callable[[], bool],
    ) -> Generator[str, None, GenerateResponse]:
        self.entered.set()
        if self.blocked:
            while not self.release.wait(0.01):
                if cancelled():
                    raise RuntimeError("cancelled")
        if self.slow:
            for _ in range(100):
                if cancelled():
                    raise RuntimeError("cancelled")
                time.sleep(0.01)
        yield "transport ok"
        return _response(request, "transport ok")


def test_grpc_uds_health_generation_permissions_and_crash(short_root: Path) -> None:
    config = _config(short_root)
    activation = technical_test_activation(test_mode=True)
    backend = StubModelBackend(ModelRuntimeConfig(mode="stub", eager_load=False))
    server = GrpcUdsServer(config, backend, activation)
    server.start()
    client = GrpcUdsClient(config, activation)
    try:
        assert client.health().status == "ok"
        assert client.generate(_request()).backend == "deterministic_stub"
        assert config.socket_path.stat().st_mode & 0o777 == 0o600
        server.stop()
        with pytest.raises(grpc.RpcError) as stopped:
            client.health(timeout=0.1)
        assert stopped.value.code() == grpc.StatusCode.UNAVAILABLE
    finally:
        client.close()
        server.stop()


def test_grpc_deadline_and_explicit_cancellation(short_root: Path) -> None:
    config = _config(short_root)
    activation = technical_test_activation(test_mode=True)
    backend = _ControlledBackend(slow=True)
    server = GrpcUdsServer(config, backend, activation)
    server.start()
    client = GrpcUdsClient(config, activation)
    try:
        with pytest.raises(grpc.RpcError) as deadline:
            client.generate(_request(), timeout=0.05)
        assert deadline.value.code() in {grpc.StatusCode.DEADLINE_EXCEEDED, grpc.StatusCode.CANCELLED}
    finally:
        client.close()
        server.stop()

    config = _config(short_root / "second")
    activation = technical_test_activation(test_mode=True)
    server = GrpcUdsServer(config, StubModelBackend(ModelRuntimeConfig(mode="stub")), activation)
    server.start()
    client = GrpcUdsClient(config, activation)
    try:
        call = client.open_stream(_request(), timeout=1)
        call.cancel()
        with pytest.raises(grpc.RpcError) as cancelled:
            next(call)
        assert cancelled.value.code() == grpc.StatusCode.CANCELLED
    finally:
        client.close()
        server.stop()


def test_grpc_backpressure_rejects_second_generation(short_root: Path) -> None:
    config = _config(short_root)
    activation = technical_test_activation(test_mode=True)
    backend = _ControlledBackend(blocked=True)
    server = GrpcUdsServer(config, backend, activation)
    server.start()
    first_client = GrpcUdsClient(config, activation)
    second_client = GrpcUdsClient(config, activation)
    first_error: list[BaseException] = []

    def first_call() -> None:
        try:
            first_client.generate(_request(), timeout=2)
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            first_error.append(exc)

    thread = threading.Thread(target=first_call)
    thread.start()
    assert backend.entered.wait(1)
    try:
        assert second_client.health(timeout=0.5).status == "ok"
        with pytest.raises(grpc.RpcError) as capacity:
            second_client.generate(_request(), timeout=0.5)
        assert capacity.value.code() == grpc.StatusCode.RESOURCE_EXHAUSTED
    finally:
        backend.release.set()
        thread.join(timeout=2)
        first_client.close()
        second_client.close()
        server.stop()
    assert not thread.is_alive()
    assert not first_error
