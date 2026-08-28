"""Configuration with conservative limits for a 16 GB Apple-silicon host."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

PINNED_RUNTIME_REPO = "mlx-community/Qwen3.5-9B-4bit"
PINNED_RUNTIME_REVISION = "8b2b98c00a6b4d291155e4890773ca8f769aee53"
PINNED_RUNTIME_MODEL_VERSION = f"{PINNED_RUNTIME_REPO}@{PINNED_RUNTIME_REVISION[:12]}"
PROJECT_ROOT = Path(__file__).resolve().parents[3]

ABSOLUTE_CONTEXT_CAP = 8192
ABSOLUTE_OUTPUT_CAP = 2048
ABSOLUTE_PREFILL_CAP = 1024
DEFAULT_CONTEXT_TOKENS = 8192
DEFAULT_MAX_OUTPUT_TOKENS = 2048
DEFAULT_PREFILL_STEP_SIZE = 512
DEFAULT_KV_CACHE_BITS = 8
DEFAULT_KV_GROUP_SIZE = 64


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


@dataclass(frozen=True, slots=True)
class SafeMemoryConfig:
    context_window_tokens: int = DEFAULT_CONTEXT_TOKENS
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS
    prefill_step_size: int = DEFAULT_PREFILL_STEP_SIZE
    kv_cache_bits: int = DEFAULT_KV_CACHE_BITS
    kv_group_size: int = DEFAULT_KV_GROUP_SIZE
    clear_cache_after_request: bool = True

    def __post_init__(self) -> None:
        if not 512 <= self.context_window_tokens <= ABSOLUTE_CONTEXT_CAP:
            raise ValueError(
                f"context_window_tokens must be between 512 and {ABSOLUTE_CONTEXT_CAP}"
            )
        if not 1 <= self.max_output_tokens <= ABSOLUTE_OUTPUT_CAP:
            raise ValueError(f"max_output_tokens must be between 1 and {ABSOLUTE_OUTPUT_CAP}")
        if self.max_output_tokens >= self.context_window_tokens:
            raise ValueError("max_output_tokens must be smaller than the context window")
        if not 64 <= self.prefill_step_size <= ABSOLUTE_PREFILL_CAP:
            raise ValueError(f"prefill_step_size must be between 64 and {ABSOLUTE_PREFILL_CAP}")
        if self.kv_cache_bits not in {4, 8}:
            raise ValueError("kv_cache_bits must be 4 or 8")
        if self.kv_group_size not in {32, 64, 128}:
            raise ValueError("kv_group_size must be 32, 64, or 128")

    @classmethod
    def from_env(cls) -> SafeMemoryConfig:
        return cls(
            context_window_tokens=_env_int("LEGALBOT_MODEL_CONTEXT_TOKENS", DEFAULT_CONTEXT_TOKENS),
            max_output_tokens=_env_int(
                "LEGALBOT_MODEL_MAX_OUTPUT_TOKENS", DEFAULT_MAX_OUTPUT_TOKENS
            ),
            prefill_step_size=_env_int(
                "LEGALBOT_MODEL_PREFILL_STEP_SIZE", DEFAULT_PREFILL_STEP_SIZE
            ),
            kv_cache_bits=_env_int("LEGALBOT_MODEL_KV_BITS", DEFAULT_KV_CACHE_BITS),
            kv_group_size=_env_int("LEGALBOT_MODEL_KV_GROUP_SIZE", DEFAULT_KV_GROUP_SIZE),
            clear_cache_after_request=_env_bool("LEGALBOT_MODEL_CLEAR_CACHE", True),
        )

    def to_dict(self) -> dict[str, int | bool]:
        return {
            "context_window_tokens": self.context_window_tokens,
            "max_output_tokens": self.max_output_tokens,
            "prefill_step_size": self.prefill_step_size,
            "kv_cache_bits": self.kv_cache_bits,
            "kv_group_size": self.kv_group_size,
            "clear_cache_after_request": self.clear_cache_after_request,
            "single_flight_generation": True,
        }


@dataclass(frozen=True, slots=True)
class ModelRuntimeConfig:
    mode: str = "stub"
    host: str = "127.0.0.1"
    port: int = 8778
    model_id: str = PINNED_RUNTIME_REPO
    model_revision: str = PINNED_RUNTIME_REVISION
    model_path: Path = PROJECT_ROOT / "models" / "runtime" / "Qwen3.5-9B-4bit"
    adapter_path: Path | None = None
    eager_load: bool = True
    max_body_bytes: int = 1_048_576
    memory: SafeMemoryConfig = SafeMemoryConfig()

    def __post_init__(self) -> None:
        if self.mode not in {"stub", "mlx"}:
            raise ValueError("mode must be stub or mlx")
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise ValueError("host must be a literal loopback IP address") from exc
        if not address.is_loopback or address.version != 4:
            raise ValueError("model runtime may bind only to an IPv4 loopback address")
        if not 0 <= self.port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        if self.max_body_bytes < 1024:
            raise ValueError("max_body_bytes must be at least 1024")
        object.__setattr__(self, "model_path", self.model_path.expanduser().resolve())
        if self.adapter_path is not None:
            object.__setattr__(self, "adapter_path", self.adapter_path.expanduser().resolve())

    @classmethod
    def from_env(cls) -> ModelRuntimeConfig:
        model_path = Path(
            os.environ.get(
                "LEGALBOT_MODEL_PATH",
                str(PROJECT_ROOT / "models" / "runtime" / "Qwen3.5-9B-4bit"),
            )
        )
        adapter_raw = os.environ.get("LEGALBOT_MODEL_ADAPTER_PATH", "").strip()
        return cls(
            mode=os.environ.get("LEGALBOT_MODEL_MODE", "stub").strip().lower(),
            host=os.environ.get("LEGALBOT_MODEL_HOST", "127.0.0.1").strip(),
            port=_env_int("LEGALBOT_MODEL_PORT", 8778),
            model_id=os.environ.get("LEGALBOT_MODEL_ID", PINNED_RUNTIME_REPO),
            model_revision=os.environ.get("LEGALBOT_MODEL_REVISION", PINNED_RUNTIME_REVISION),
            model_path=model_path,
            adapter_path=Path(adapter_raw) if adapter_raw else None,
            eager_load=_env_bool("LEGALBOT_MODEL_EAGER_LOAD", True),
            max_body_bytes=_env_int("LEGALBOT_MODEL_MAX_BODY_BYTES", 1_048_576),
            memory=SafeMemoryConfig.from_env(),
        )
