"""Deterministic test backend and the production MLX-LM backend."""

from __future__ import annotations

import gc
import hashlib
import importlib
import json
import threading
import time
from collections.abc import Callable, Generator
from contextlib import suppress
from types import ModuleType
from typing import Any, Protocol, cast

from .config import ModelRuntimeConfig
from .contracts import GenerateRequest, GenerateResponse, HealthResponse, Usage


class RuntimeNotReadyError(RuntimeError):
    """The configured model is unavailable or failed provenance checks."""


class RequestLimitError(ValueError):
    """A valid v1 request exceeds this host's safe runtime limits."""


class GenerationCancelledError(RuntimeError):
    """Generation was cancelled between streamed model tokens."""


class ModelBackend(Protocol):
    def health(self) -> HealthResponse: ...

    def generate(self, request: GenerateRequest) -> GenerateResponse: ...

    def generate_stream(
        self,
        request: GenerateRequest,
        cancelled: Callable[[], bool],
    ) -> Generator[str, None, GenerateResponse]: ...


def _consume_stream(stream: Generator[str, None, GenerateResponse]) -> GenerateResponse:
    while True:
        try:
            next(stream)
        except StopIteration as completed:
            return completed.value


def _earliest_stop(text: str, stop: tuple[str, ...]) -> tuple[str, bool]:
    positions = [position for marker in stop if (position := text.find(marker)) >= 0]
    if not positions:
        return text, False
    return text[: min(positions)], True


def _structured_json(text: str) -> dict[str, Any]:
    candidate = text.strip()
    if candidate.startswith("```json") and candidate.endswith("```"):
        candidate = candidate[7:-3].strip()
    try:
        value: object = json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        return {}
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        return {}
    return cast(dict[str, Any], value)


class StubModelBackend:
    """No-model backend whose output is stable across runs and machines."""

    backend_name = "deterministic_stub"

    def __init__(self, config: ModelRuntimeConfig):
        self.config = config

    def health(self) -> HealthResponse:
        return HealthResponse(
            status="ok",
            backend=self.backend_name,
            model_id="stub/legalbot-v1",
            model_loaded=True,
            stub_mode=True,
            memory_profile=self.config.memory.to_dict(),
            detail="deterministic test mode; no model weights are loaded",
        )

    def generate(self, request: GenerateRequest) -> GenerateResponse:
        return _consume_stream(self.generate_stream(request, lambda: False))

    def generate_stream(
        self,
        request: GenerateRequest,
        cancelled: Callable[[], bool],
    ) -> Generator[str, None, GenerateResponse]:
        if request.max_tokens > self.config.memory.max_output_tokens:
            raise RequestLimitError(
                f"max_tokens exceeds this host's {self.config.memory.max_output_tokens}-token cap"
            )
        input_tokens = sum(max(1, len(m.content.split())) for m in request.messages)
        if input_tokens + request.max_tokens > self.config.memory.context_window_tokens:
            raise RequestLimitError(
                "request exceeds the deterministic stub's configured context window"
            )
        canonical = json.dumps(
            request.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()[:16]
        text = (
            f"Deterministic stub response {digest}. "
            "Production model execution is disabled in stub mode."
        )
        text, stopped = _earliest_stop(text, request.stop)
        if cancelled():
            raise GenerationCancelledError("stub generation cancelled")
        yield text
        output_tokens = max(1, len(text.split()))
        return GenerateResponse(
            request_id=request.request_id,
            model_version="stub/legalbot-v1",
            backend=self.backend_name,
            raw_text=text,
            structured={"mode": request.mode, "stub": True},
            rubric_scores={},
            finish_reason="stop" if stopped else "complete",
            usage=Usage(input_tokens=input_tokens, output_tokens=output_tokens),
            generation_ms=0,
            deterministic=True,
            time_to_first_token_ms=0,
            warnings=("stub_mode",),
        )


class UnavailableModelBackend:
    """Keeps the health endpoint alive when the local artifact cannot start."""

    backend_name = "mlx_lm"

    def __init__(self, config: ModelRuntimeConfig, detail: str):
        self.config = config
        self.detail = detail

    def health(self) -> HealthResponse:
        return HealthResponse(
            status="unavailable",
            backend=self.backend_name,
            model_id=self.config.model_id,
            model_loaded=False,
            stub_mode=False,
            memory_profile=self.config.memory.to_dict(),
            detail=self.detail,
        )

    def generate(self, _request: GenerateRequest) -> GenerateResponse:
        raise RuntimeNotReadyError(self.detail)

    def generate_stream(
        self,
        request: GenerateRequest,
        cancelled: Callable[[], bool],
    ) -> Generator[str, None, GenerateResponse]:
        del request, cancelled
        raise RuntimeNotReadyError(self.detail)
        yield  # pragma: no cover


class MlxModelBackend:
    """Single-flight, local-only adapter for the pinned post-trained 4-bit model."""

    backend_name = "mlx_lm"

    def __init__(self, config: ModelRuntimeConfig):
        self.config = config
        self._lock = threading.RLock()
        self._model: Any | None = None
        self._tokenizer: Any | None = None
        self._mlx_lm: ModuleType | None = None
        self._mx: ModuleType | None = None
        self._make_sampler: Callable[..., Any] | None = None
        self._load_error: str | None = None
        self._validate_local_artifact()

    def _validate_local_artifact(self) -> None:
        model_path = self.config.model_path
        if not model_path.is_dir():
            raise RuntimeNotReadyError(f"local model directory does not exist: {model_path}")
        config_path = model_path / "config.json"
        provenance_path = model_path / "runtime-model.json"
        if not config_path.is_file() or not provenance_path.is_file():
            raise RuntimeNotReadyError(
                "model directory must contain config.json and runtime-model.json"
            )
        if not any(model_path.glob("*.safetensors")):
            raise RuntimeNotReadyError("model directory contains no SafeTensors weights")

        try:
            model_config = json.loads(config_path.read_text(encoding="utf-8"))
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeNotReadyError(f"invalid model metadata: {exc}") from exc

        quantization = model_config.get("quantization") or model_config.get(
            "quantization_config", {}
        )
        if quantization.get("bits") != 4:
            raise RuntimeNotReadyError("production runtime requires a 4-bit model")
        if model_config.get("model_type") != "qwen3_5":
            raise RuntimeNotReadyError("runtime artifact is not a qwen3_5 model")
        if provenance.get("source_repo") != self.config.model_id:
            raise RuntimeNotReadyError("runtime model repository does not match the pin")
        if provenance.get("revision") != self.config.model_revision:
            raise RuntimeNotReadyError("runtime model revision does not match the pin")
        if provenance.get("post_trained") is not True:
            raise RuntimeNotReadyError("runtime artifact is not marked post-trained")

    def load(self) -> None:
        with self._lock:
            if self._model is not None:
                return
            try:
                self._mlx_lm = importlib.import_module("mlx_lm")
                self._mx = importlib.import_module("mlx.core")
                sample_utils = importlib.import_module("mlx_lm.sample_utils")
                self._make_sampler = sample_utils.make_sampler
                kwargs: dict[str, str] = {}
                if self.config.adapter_path is not None:
                    if not self.config.adapter_path.is_dir():
                        raise RuntimeNotReadyError(
                            f"adapter directory does not exist: {self.config.adapter_path}"
                        )
                    kwargs["adapter_path"] = str(self.config.adapter_path)
                self._model, self._tokenizer = self._mlx_lm.load(
                    str(self.config.model_path), **kwargs
                )
                self._load_error = None
            except Exception as exc:
                self._load_error = f"{type(exc).__name__}: {exc}"
                raise RuntimeNotReadyError(self._load_error) from exc

    def health(self) -> HealthResponse:
        loaded = self._model is not None
        return HealthResponse(
            status="ok" if loaded else "unavailable",
            backend=self.backend_name,
            model_id=self.config.model_id,
            model_loaded=loaded,
            stub_mode=False,
            memory_profile=self.config.memory.to_dict(),
            detail=self._load_error or (None if loaded else "model is not loaded"),
        )

    def _render_prompt(self, request: GenerateRequest) -> str:
        assert self._tokenizer is not None
        messages = [message.to_dict() for message in request.messages]
        try:
            return cast(
                str,
                self._tokenizer.apply_chat_template(
                    messages,
                    tokenize=False,
                    add_generation_prompt=True,
                    enable_thinking=False,
                ),
            )
        except TypeError:
            return cast(
                str,
                self._tokenizer.apply_chat_template(
                    messages, tokenize=False, add_generation_prompt=True
                ),
            )

    def generate(self, request: GenerateRequest) -> GenerateResponse:
        return _consume_stream(self.generate_stream(request, lambda: False))

    def generate_stream(
        self,
        request: GenerateRequest,
        cancelled: Callable[[], bool],
    ) -> Generator[str, None, GenerateResponse]:
        if request.max_tokens > self.config.memory.max_output_tokens:
            raise RequestLimitError(
                f"max_tokens exceeds this host's {self.config.memory.max_output_tokens}-token cap"
            )
        self.load()
        assert self._tokenizer is not None
        assert self._mlx_lm is not None
        assert self._mx is not None
        assert self._make_sampler is not None

        with self._lock:
            prompt = self._render_prompt(request)
            prompt_tokens = self._tokenizer.encode(prompt, add_special_tokens=False)
            total_budget = len(prompt_tokens) + request.max_tokens
            if total_budget > self.config.memory.context_window_tokens:
                raise RequestLimitError(
                    "prompt plus requested output exceeds the safe "
                    f"{self.config.memory.context_window_tokens}-token context window"
                )

            self._mx.random.seed(request.seed)
            sampler = self._make_sampler(
                temp=request.temperature,
                top_p=request.top_p,
            )
            started = time.perf_counter()
            chunks: list[str] = []
            final = None
            item = None
            stream = None
            first_token_ms: int | None = None
            response: GenerateResponse | None = None
            try:
                stream = self._mlx_lm.stream_generate(
                    self._model,
                    self._tokenizer,
                    prompt,
                    max_tokens=request.max_tokens,
                    sampler=sampler,
                    max_kv_size=self.config.memory.context_window_tokens,
                    prefill_step_size=self.config.memory.prefill_step_size,
                    kv_bits=self.config.memory.kv_cache_bits,
                    kv_group_size=self.config.memory.kv_group_size,
                    quantized_kv_start=0,
                )
                for item in stream:
                    if cancelled():
                        raise GenerationCancelledError("MLX generation cancelled")
                    if first_token_ms is None:
                        first_token_ms = round((time.perf_counter() - started) * 1000)
                    chunks.append(item.text)
                    yield item.text
                    final = item
                text, stopped = _earliest_stop("".join(chunks), request.stop)
                output_tokens = len(self._tokenizer.encode(text, add_special_tokens=False))
                finish_reason = "stop" if stopped else getattr(final, "finish_reason", "complete")
                peak_memory = getattr(final, "peak_memory", None)
                response = GenerateResponse(
                    request_id=request.request_id,
                    model_version=(f"{self.config.model_id}@{self.config.model_revision[:12]}"),
                    backend=self.backend_name,
                    raw_text=text,
                    structured=_structured_json(text),
                    rubric_scores={},
                    finish_reason=finish_reason or "complete",
                    usage=Usage(
                        input_tokens=len(prompt_tokens),
                        output_tokens=output_tokens,
                    ),
                    generation_ms=round((time.perf_counter() - started) * 1000),
                    deterministic=request.temperature == 0.0,
                    time_to_first_token_ms=first_token_ms,
                    peak_memory_gb=(float(peak_memory) if peak_memory is not None else None),
                    warnings=("rubric_scoring_is_external",),
                )
            finally:
                close = getattr(stream, "close", None)
                if callable(close):
                    with suppress(Exception):
                        close()
                if self.config.memory.clear_cache_after_request:
                    synchronize = getattr(self._mx, "synchronize", None)
                    if callable(synchronize):
                        synchronize()
                    chunks.clear()
                    item = None
                    final = None
                    stream = None
                    sampler = None
                    prompt_tokens.clear()
                    prompt = ""
                    gc.collect()
                    self._mx.clear_cache()
                    gc.collect()
            if response is None:
                raise AssertionError("model generation completed without a response")
            return response


def build_backend(config: ModelRuntimeConfig) -> ModelBackend:
    if config.mode == "stub":
        return StubModelBackend(config)
    try:
        backend = MlxModelBackend(config)
    except RuntimeNotReadyError as exc:
        return UnavailableModelBackend(config, str(exc))
    if config.eager_load:
        with suppress(RuntimeNotReadyError):
            backend.load()
    return backend
