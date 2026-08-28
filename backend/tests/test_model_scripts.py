from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.model.download_retrieval_models import (
    download_one as download_retrieval_model,
)
from scripts.model.download_retrieval_models import load_spec as load_retrieval_spec
from scripts.model.download_runtime_model import execute_download, load_spec
from scripts.model.recover_base_shards import (
    ShardSpec,
    recover,
    verify_source,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class BaseRecoveryTests(unittest.TestCase):
    def test_recovery_copies_verified_shards_without_touching_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            cache = source / ".cache" / "huggingface" / "download"
            cache.mkdir(parents=True)
            (source / "config.json").write_text("{}", encoding="utf-8")

            specs = []
            source_paths = []
            for index in range(4):
                content = f"shard-{index}".encode()
                digest = hashlib.sha256(content).hexdigest()
                spec = ShardSpec(
                    filename=f"model-{index + 1:05d}-of-00004.safetensors",
                    size=len(content),
                    sha256=digest,
                )
                path = cache / f"cache-key.{digest}.test.incomplete"
                path.write_bytes(content)
                specs.append(spec)
                source_paths.append(path)

            manifest = {
                "source_repo": "example/base",
                "revision": "a" * 40,
                "required_metadata": ["config.json"],
            }
            verified, _ = verify_source(source, manifest, tuple(specs))
            self.assertEqual(len(verified), 4)

            destination = root / "archive" / "base"
            recover(
                source=source,
                destination=destination,
                manifest=manifest,
                shards=tuple(specs),
                copier=lambda src, dst: shutil.copy2(src, dst),
            )
            for path, spec in zip(source_paths, specs, strict=True):
                self.assertTrue(path.exists())
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), spec.sha256)
                self.assertTrue((destination / spec.filename).exists())
            archived = json.loads(
                (destination / "archive-manifest.json").read_text(encoding="utf-8")
            )
            self.assertFalse(archived["source_was_modified"])
            self.assertFalse(archived["runtime_eligible"])


class RuntimeDownloadTests(unittest.TestCase):
    def test_pinned_download_uses_one_worker_and_writes_provenance(self) -> None:
        spec = load_spec(
            PROJECT_ROOT / "scripts" / "model" / "manifests" / "qwen3.5-9b-runtime.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = {}

            def fake_snapshot_download(**kwargs):
                calls.update(kwargs)
                target = Path(kwargs["local_dir"])
                for filename in spec["required_files"]:
                    path = target / filename
                    if filename == "config.json":
                        path.write_text(
                            json.dumps(
                                {
                                    "model_type": "qwen3_5",
                                    "quantization": {"bits": 4},
                                }
                            ),
                            encoding="utf-8",
                        )
                    else:
                        path.write_text("test", encoding="utf-8")
                (target / "model-00001-of-00001.safetensors").write_bytes(b"weights")

            target = execute_download(
                spec=spec,
                project_root=root,
                snapshot_download=fake_snapshot_download,
            )
            self.assertEqual(calls["max_workers"], 1)
            self.assertEqual(calls["revision"], spec["revision"])
            provenance = json.loads((target / "runtime-model.json").read_text(encoding="utf-8"))
            self.assertEqual(provenance["source_repo"], spec["source_repo"])
            self.assertEqual(provenance["revision"], spec["revision"])
            self.assertTrue(provenance["hf_hub_disable_xet"])


class RetrievalModelDownloadTests(unittest.TestCase):
    def test_both_models_are_revision_pinned_and_download_one_worker(self) -> None:
        spec = load_retrieval_spec(
            PROJECT_ROOT / "scripts" / "model" / "manifests" / "qwen3-retrieval-models.json"
        )
        self.assertEqual({item["role"] for item in spec["models"]}, {"embedding", "reranker"})
        for item in spec["models"]:
            with self.subTest(role=item["role"]), tempfile.TemporaryDirectory() as directory:
                calls = {}

                def fake_snapshot_download(*, item=item, calls=calls, **kwargs):
                    calls.update(kwargs)
                    target = Path(kwargs["local_dir"])
                    for filename in item["required_files"]:
                        path = target / filename
                        path.parent.mkdir(parents=True, exist_ok=True)
                        if filename == "config.json":
                            path.write_text(json.dumps({"model_type": "qwen3"}), encoding="utf-8")
                        else:
                            path.write_text("test", encoding="utf-8")
                    (target / "model.safetensors").write_bytes(b"weights")

                target = download_retrieval_model(
                    item=item,
                    project_root=Path(directory),
                    snapshot_download=fake_snapshot_download,
                )
                self.assertEqual(calls["max_workers"], 1)
                self.assertEqual(calls["revision"], item["revision"])
                provenance = json.loads(
                    (target / "retrieval-model.json").read_text(encoding="utf-8")
                )
                self.assertEqual(provenance["source_repo"], item["source_repo"])
                self.assertEqual(provenance["revision"], item["revision"])


if __name__ == "__main__":
    unittest.main()
