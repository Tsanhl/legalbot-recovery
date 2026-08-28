from __future__ import annotations

import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.app.model_runtime import adapters as adapters_module
from backend.app.model_runtime.adapters import (
    MlxModelBackend,
    RuntimeNotReadyError,
    build_backend,
)
from backend.app.model_runtime.config import (
    PINNED_RUNTIME_REPO,
    PINNED_RUNTIME_REVISION,
    ModelRuntimeConfig,
    SafeMemoryConfig,
)
from backend.app.model_runtime.contracts import GenerateRequest


class FakeTokenizer:
    def __init__(self) -> None:
        self.rendered = None

    def apply_chat_template(self, messages, **_kwargs):
        self.rendered = messages
        return "\n".join(item["content"] for item in messages) + "\nassistant:"

    def encode(self, text, add_special_tokens=False):
        del add_special_tokens
        return list(range(max(1, len(text.split()))))


class FakeRandom:
    def __init__(self) -> None:
        self.last_seed = None

    def seed(self, value):
        self.last_seed = value


class MlxBackendTests(unittest.TestCase):
    def make_artifact(self, root: Path, *, bits: int = 4) -> Path:
        root.mkdir()
        (root / "config.json").write_text(
            json.dumps(
                {
                    "model_type": "qwen3_5",
                    "quantization": {"bits": bits, "group_size": 64},
                }
            ),
            encoding="utf-8",
        )
        (root / "runtime-model.json").write_text(
            json.dumps(
                {
                    "source_repo": PINNED_RUNTIME_REPO,
                    "revision": PINNED_RUNTIME_REVISION,
                    "post_trained": True,
                }
            ),
            encoding="utf-8",
        )
        (root / "model.safetensors").write_bytes(b"test-only")
        return root

    def config(self, path: Path) -> ModelRuntimeConfig:
        return ModelRuntimeConfig(
            mode="mlx",
            model_path=path,
            eager_load=False,
            memory=SafeMemoryConfig(
                context_window_tokens=512,
                max_output_tokens=64,
                prefill_step_size=64,
            ),
        )

    def test_rejects_non_four_bit_artifact_before_importing_mlx(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = self.make_artifact(Path(directory) / "model", bits=8)
            with self.assertRaisesRegex(RuntimeNotReadyError, "4-bit"):
                MlxModelBackend(self.config(artifact))

    def test_builder_keeps_health_available_when_artifact_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            backend = build_backend(self.config(missing))
            health = backend.health()
            self.assertEqual(health.status, "unavailable")
            self.assertFalse(health.model_loaded)

    def test_generate_uses_chat_template_seed_and_safe_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = self.make_artifact(Path(directory) / "model")
            tokenizer = FakeTokenizer()
            calls = {}

            def stream_generate(_model, _tokenizer, prompt, **kwargs):
                calls["prompt"] = prompt
                calls["kwargs"] = kwargs
                yield types.SimpleNamespace(
                    text="Verified response.",
                    finish_reason="stop",
                    peak_memory=6.25,
                )

            fake_mlx_lm = types.SimpleNamespace(
                load=lambda _path, **_kwargs: (object(), tokenizer),
                stream_generate=stream_generate,
            )
            fake_random = FakeRandom()
            fake_mx = types.SimpleNamespace(
                random=fake_random,
                synchronize=MagicMock(),
                clear_cache=MagicMock(),
            )
            fake_sample = types.SimpleNamespace(make_sampler=lambda **kwargs: ("sampler", kwargs))

            def fake_import(name):
                return {
                    "mlx_lm": fake_mlx_lm,
                    "mlx.core": fake_mx,
                    "mlx_lm.sample_utils": fake_sample,
                }[name]

            backend = MlxModelBackend(self.config(artifact))
            request = GenerateRequest.from_dict(
                {
                    "request_id": "mlx-1",
                    "mode": "draft",
                    "payload": {"prompt": "Question"},
                    "messages": [{"role": "user", "content": "Question"}],
                    "max_tokens": 20,
                    "temperature": 0,
                    "seed": 91,
                }
            )
            with (
                patch(
                    "backend.app.model_runtime.adapters.importlib.import_module",
                    side_effect=fake_import,
                ),
                patch.object(adapters_module.gc, "collect") as collect,
            ):
                response = backend.generate(request)

            self.assertEqual(response.raw_text, "Verified response.")
            self.assertEqual(response.peak_memory_gb, 6.25)
            self.assertEqual(fake_random.last_seed, 91)
            self.assertEqual(calls["kwargs"]["max_kv_size"], 512)
            self.assertEqual(calls["kwargs"]["kv_bits"], 8)
            self.assertEqual(tokenizer.rendered[0]["role"], "user")
            self.assertEqual(backend.health().status, "ok")
            fake_mx.synchronize.assert_called_once_with()
            fake_mx.clear_cache.assert_called_once_with()
            self.assertEqual(collect.call_count, 2)

    def test_generate_closes_stream_and_clears_cache_after_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = self.make_artifact(Path(directory) / "model")
            tokenizer = FakeTokenizer()

            class FailingStream:
                def __init__(self) -> None:
                    self.closed = False

                def __iter__(self):
                    return self

                def __next__(self):
                    raise RuntimeError("generation failed")

                def close(self) -> None:
                    self.closed = True

            stream = FailingStream()
            fake_mlx_lm = types.SimpleNamespace(
                load=lambda _path, **_kwargs: (object(), tokenizer),
                stream_generate=lambda *_args, **_kwargs: stream,
            )
            fake_random = FakeRandom()
            fake_mx = types.SimpleNamespace(
                random=fake_random,
                synchronize=MagicMock(),
                clear_cache=MagicMock(),
            )
            fake_sample = types.SimpleNamespace(make_sampler=lambda **kwargs: ("sampler", kwargs))

            def fake_import(name):
                return {
                    "mlx_lm": fake_mlx_lm,
                    "mlx.core": fake_mx,
                    "mlx_lm.sample_utils": fake_sample,
                }[name]

            backend = MlxModelBackend(self.config(artifact))
            request = GenerateRequest.from_dict(
                {
                    "request_id": "mlx-failure",
                    "mode": "semantic_verify",
                    "payload": {"prompt": "Question"},
                    "messages": [{"role": "user", "content": "Question"}],
                    "max_tokens": 20,
                    "temperature": 0,
                    "seed": 91,
                }
            )
            with (
                patch(
                    "backend.app.model_runtime.adapters.importlib.import_module",
                    side_effect=fake_import,
                ),
                patch.object(adapters_module.gc, "collect") as collect,
                self.assertRaisesRegex(RuntimeError, "generation failed"),
            ):
                backend.generate(request)

            self.assertTrue(stream.closed)
            fake_mx.synchronize.assert_called_once_with()
            fake_mx.clear_cache.assert_called_once_with()
            self.assertEqual(collect.call_count, 2)


if __name__ == "__main__":
    unittest.main()
