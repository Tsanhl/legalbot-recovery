"""Pinned local embedding inference for the owner-authorized non-live research lane.

No download, model training, corpus scan, release pointer or production index.
The caller must separately validate source review and store capability.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / "scripts/model/manifests/qwen3-retrieval-models.json"
MAX_TOKENS = 2048


def _safe(path):
    if not path.is_absolute() or not path.is_relative_to(ROOT) or ".." in path.parts:
        raise ValueError("embedding path outside workspace")
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("embedding symlink refused")


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verified_model_identity():
    from scripts.model.download_retrieval_models import (
        _file_manifest_sha256,
        _recursive_file_manifest,
        _validate,
        load_spec,
    )
    _safe(PIN)
    spec = load_spec(PIN)
    item = next(model for model in spec["models"] if model["role"] == "embedding")
    root = ROOT / item["directory"]
    _safe(root)
    _validate(root, item)
    actual = _file_manifest_sha256(_recursive_file_manifest(root))
    if actual != item["file_manifest_sha256"] or item.get("dimensions") != 1024:
        raise RuntimeError("pinned embedding file identity mismatch")
    saved = json.loads((root / "retrieval-model.json").read_text())
    if saved["source_repo"] != item["source_repo"] or saved["revision"] != item["revision"]:
        raise RuntimeError("installed embedding revision mismatch")
    identity = {"source_repo": item["source_repo"], "revision": item["revision"],
                "file_manifest_sha256": actual, "directory": item["directory"],
                "dimensions": 1024, "local_files_only": True, "device": "cpu",
                "max_tokens": MAX_TOKENS, "batch_size": 1, "torch_threads": 2,
                "normalise_embeddings": True, "training": False}
    return {**identity, "identity_sha256": _digest(identity)}


class PinnedEmbeddingSession:
    """One inference process per workspace, acquired before loading the model."""

    dimensions = 1024

    def __init__(self):
        self.identity = None
        self.provider = None
        self.lock = None
        self.calls = []

    @property
    def pin(self):
        if self.identity is None:
            raise RuntimeError("model not verified and loaded")
        from backend.app.research.ge_auto_index import ModelPin
        return ModelPin.from_runtime_identity(self.identity)

    def verify_binding(self):
        return self.provider is not None and verified_model_identity() == self.identity

    def __enter__(self):
        lock_path = ROOT / "data/research/ge-auto-research/embedding.lock"
        _safe(lock_path)
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # The lock file is retained; releasing a lock never deletes evidence.
        self.lock = lock_path.open("a+")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.identity = verified_model_identity()
            import torch
            from backend.app.retrieval.qwen import QwenEmbeddingProvider
            from sentence_transformers import SentenceTransformer
            torch.set_num_threads(2)
            model = SentenceTransformer(str(ROOT / self.identity["directory"]),
                                        device="cpu", local_files_only=True,
                                        trust_remote_code=False)
            model.max_seq_length = MAX_TOKENS
            model.eval()
            self.provider = QwenEmbeddingProvider(
                model_name=self.identity["source_repo"], device="cpu", model=model)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        self.provider = None
        if self.lock is not None:
            fcntl.flock(self.lock, fcntl.LOCK_UN)
            self.lock.close()
            self.lock = None

    def _tokens(self, text, query=False):
        if self.provider is None or not isinstance(text, str) or not text.strip():
            raise ValueError("active pinned model and nonempty input required")
        from backend.app.retrieval.qwen import LEGAL_RETRIEVAL_INSTRUCTION
        value = f"Instruct: {LEGAL_RETRIEVAL_INSTRUCTION}\nQuery:{text}" if query else text
        tokens = len(self.provider.model.tokenizer(value, truncation=False)["input_ids"])
        if tokens > MAX_TOKENS:
            raise ValueError("structural chunk exceeds embedding context; refuse silent truncation")
        return tokens

    def embed_documents(self, texts):
        vectors = []
        for text in texts:
            tokens = self._tokens(text)
            start = time.monotonic()
            vector = self.provider.embed_documents([text])[0]
            vectors.append(vector)
            self.calls.append({"kind": "document", "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                               "tokens": tokens, "vector_sha256": _digest(vector),
                               "seconds": round(time.monotonic() - start, 6)})
        return tuple(vectors)

    def embed_query(self, text):
        tokens = self._tokens(text, query=True)
        start = time.monotonic()
        vector = self.provider.embed_query(text)
        self.calls.append({"kind": "query", "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                           "tokens": tokens, "vector_sha256": _digest(vector),
                           "seconds": round(time.monotonic() - start, 6)})
        return vector

    def receipt(self):
        return {"schema": "legalbot.ge-auto-research-embedding-inference.v1",
                "model_identity": self.identity, "calls": list(self.calls),
                "actual_inference_calls": len(self.calls), "training": False,
                "provider": "PINNED_LOCAL_QWEN", "synthetic_vectors": False}
