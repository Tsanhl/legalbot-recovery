"""Immutable LanceDB build seam with atomic active-generation promotion."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import tempfile
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .interfaces import LanceSessionFactory
from .models import VECTOR_DIMENSIONS, IndexedChunk

_GE_SELECTION_POLICY = "exact-owner-approved-ge-source-versions-and-lanes"
_BUILD_BOUNDARY_FILENAME = "build-boundary.json"


@dataclass(frozen=True, slots=True)
class IndexBuildManifest:
    schema: str
    build_id: str
    created_at: str
    chunk_count: int
    vector_dimensions: int
    embedding_model: str
    reranker_model: str
    source_manifest_sha256: str
    source_scan_id: str | None = None
    source_scan_manifest_sha256: str | None = None
    sealed: bool = True


@dataclass(frozen=True, slots=True)
class ActiveGeneration:
    build_id: str
    manifest_sha256: str
    promoted_at: str


class ImmutableLanceRepository:
    """Owns immutable build directories and atomically replaced pointers."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.builds = self.root / "builds"
        self.active_pointer = self.root / "ACTIVE.json"
        self.previous_pointer = self.root / "PREVIOUS.json"
        self.builds.mkdir(parents=True, exist_ok=True)

    def staging_path(self, build_id: str) -> Path:
        self._validate_build_id(build_id)
        final_path = self.builds / build_id
        if final_path.exists():
            return final_path
        return self.builds / f".{build_id}.incomplete"

    def prepare_staging(self, build_id: str) -> Path:
        """Create empty staging. Never deletes an existing incomplete directory."""

        return self.prepare_new_staging(build_id)

    def prepare_new_staging(self, build_id: str) -> Path:
        self._validate_build_id(build_id)
        final_path = self.builds / build_id
        if final_path.exists():
            raise FileExistsError(f"build is immutable and already exists: {build_id}")
        staging_path = self.builds / f".{build_id}.incomplete"
        if staging_path.exists():
            raise FileExistsError(
                "incomplete staging already exists; refuse automatic delete. "
                "Use open_resumable_staging or archive_incomplete_staging"
            )
        staging_path.mkdir(parents=True, exist_ok=True)
        return staging_path

    def open_resumable_staging(self, build_id: str) -> Path:
        self._validate_build_id(build_id)
        final_path = self.builds / build_id
        if final_path.exists():
            raise FileExistsError(f"build is immutable and already exists: {build_id}")
        staging_path = self.builds / f".{build_id}.incomplete"
        if not staging_path.is_dir():
            raise FileNotFoundError(f"incomplete build missing: {build_id}")
        return staging_path

    def archive_incomplete_staging(self, build_id: str, *, stamp: str | None = None) -> Path:
        """Owner-explicit archive. Normal build start must never call this."""

        self._validate_build_id(build_id)
        staging_path = self.builds / f".{build_id}.incomplete"
        if not staging_path.exists():
            raise FileNotFoundError(f"incomplete build missing: {build_id}")
        self._require_generic_control_allowed(staging_path, operation="archive")
        archive_root = self.builds / "archive"
        archive_root.mkdir(parents=True, exist_ok=True)
        suffix = stamp or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        destination = archive_root / f"{build_id}-{suffix}"
        if destination.exists():
            raise FileExistsError(f"archive destination already exists: {destination.name}")
        shutil.move(str(staging_path), str(destination))
        self._fsync_directory(archive_root)
        return destination

    def seal_staging(
        self,
        build_id: str,
        *,
        chunk_count: int,
        embedding_model: str,
        reranker_model: str,
        source_manifest_sha256: str,
        source_scan_id: str | None = None,
        source_scan_manifest_sha256: str | None = None,
        finalize: bool = True,
    ) -> IndexBuildManifest:
        self._validate_build_id(build_id)
        if not re.fullmatch(r"[0-9a-f]{64}", source_manifest_sha256):
            raise ValueError("source manifest SHA-256 is required")
        staging_path = self.builds / f".{build_id}.incomplete"
        final_path = self.builds / build_id
        if final_path.exists():
            raise FileExistsError(f"build is immutable and already exists: {build_id}")
        if not staging_path.exists():
            raise FileNotFoundError(f"incomplete build missing: {build_id}")
        manifest = IndexBuildManifest(
            "legalbot.lance-build.v1",
            build_id,
            datetime.now(UTC).isoformat(),
            chunk_count,
            VECTOR_DIMENSIONS,
            embedding_model,
            reranker_model,
            source_manifest_sha256,
            source_scan_id,
            source_scan_manifest_sha256,
        )
        self._write_new(staging_path / "manifest.json", self._encode(asdict(manifest)))
        if finalize:
            os.rename(staging_path, final_path)
            self._fsync_directory(self.builds)
        return manifest

    def finalize_staging(self, build_id: str) -> Path:
        """Atomically publish a completely sealed staging directory once."""

        self._validate_build_id(build_id)
        staging_path = self.builds / f".{build_id}.incomplete"
        final_path = self.builds / build_id
        if final_path.exists():
            raise FileExistsError(f"build is immutable and already exists: {build_id}")
        if not staging_path.is_dir():
            raise FileNotFoundError(f"incomplete build missing: {build_id}")
        os.rename(staging_path, final_path)
        self._fsync_directory(self.builds)
        return final_path

    def create_lexical_indexes(self, lance_path: Path, lancedb_module: Any) -> dict[str, int]:
        return self._create_indexes(lance_path, lancedb_module, kind="lexical")

    def create_vector_indexes(self, lance_path: Path, lancedb_module: Any) -> dict[str, int]:
        return self._create_indexes(lance_path, lancedb_module, kind="vector")

    def _create_indexes(
        self, lance_path: Path, lancedb_module: Any, *, kind: str
    ) -> dict[str, int]:
        def existing_index_types(table: Any, column: str) -> tuple[str, ...]:
            list_indices = getattr(table, "list_indices", None)
            if not callable(list_indices):
                return ()
            matching: list[str] = []
            for value in list_indices():
                if isinstance(value, dict):
                    raw_columns = value.get("columns")
                    raw_type = value.get("index_type") or value.get("type")
                else:
                    raw_columns = getattr(value, "columns", None)
                    raw_type = getattr(value, "index_type", None) or getattr(
                        value, "type", None
                    )
                columns = (
                    tuple(str(item) for item in raw_columns)
                    if isinstance(raw_columns, list | tuple)
                    else ()
                )
                if columns == (column,):
                    matching.append(str(raw_type or ""))
            return tuple(matching)

        counts: dict[str, int] = {}
        for lane_dir in sorted(path for path in lance_path.iterdir() if path.is_dir()):
            connection = lancedb_module.connect(str(lane_dir))
            names = set(connection.table_names()) if hasattr(connection, "table_names") else set()
            if names and "chunks" not in names:
                continue
            try:
                table = connection.open_table("chunks")
            except (ValueError, FileNotFoundError, OSError):
                continue
            row_count = int(table.count_rows()) if hasattr(table, "count_rows") else 0
            if row_count == 0 and hasattr(table, "to_pandas"):
                row_count = len(table.to_pandas())
            counts[lane_dir.name] = row_count
            if kind == "lexical":
                existing = existing_index_types(table, "text")
                if len(existing) > 1 or (
                    existing and "fts" not in existing[0].casefold()
                ):
                    raise RuntimeError("existing lexical index is not the frozen FTS index")
                if not existing:
                    table.create_fts_index("text", replace=False)
            else:
                existing = existing_index_types(table, "vector")
                normalised = existing[0].casefold().replace("_", "") if existing else ""
                if len(existing) > 1 or (existing and "ivfflat" not in normalised):
                    raise RuntimeError("existing vector index is not the frozen IVF_FLAT index")
                if not existing:
                    table.create_index(
                        metric="cosine",
                        num_partitions=max(
                            1, min(256, int(math.sqrt(row_count or 1)) or 1)
                        ),
                        vector_column_name="vector",
                        index_type="IVF_FLAT",
                        replace=False,
                    )
        return counts

    def build(
        self,
        *,
        build_id: str,
        chunks: Iterable[IndexedChunk],
        embedding_model: str,
        reranker_model: str,
        source_manifest_sha256: str,
        session_factory: LanceSessionFactory,
        source_scan_id: str | None = None,
        source_scan_manifest_sha256: str | None = None,
    ) -> IndexBuildManifest:
        if not re.fullmatch(r"[0-9a-f]{64}", source_manifest_sha256):
            raise ValueError("source manifest SHA-256 is required")
        if source_scan_manifest_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", source_scan_manifest_sha256
        ):
            raise ValueError("source scan manifest SHA-256 is invalid")
        staging_path = self.prepare_staging(build_id)
        session = session_factory.create(staging_path / "lance")
        validated_count = 0

        def validated_chunks() -> Iterable[IndexedChunk]:
            nonlocal validated_count
            for chunk in self._validated(chunks):
                validated_count += 1
                yield chunk

        try:
            chunk_count = session.write_chunks(validated_chunks())
            if chunk_count != validated_count:
                raise OSError(
                    f"Lance session reported {chunk_count} rows after consuming {validated_count} chunks"
                )
            session.create_indexes()
        except Exception:
            session.close()
            raise
        else:
            session.close()
        return self.seal_staging(
            build_id,
            chunk_count=chunk_count,
            embedding_model=embedding_model,
            reranker_model=reranker_model,
            source_manifest_sha256=source_manifest_sha256,
            source_scan_id=source_scan_id,
            source_scan_manifest_sha256=source_scan_manifest_sha256,
        )

    def promote(self, build_id: str, *, expected_previous: str | None = None) -> ActiveGeneration:
        self._validate_build_id(build_id)
        build_path = self.builds / build_id
        self._require_generic_control_allowed(build_path, operation="promote")
        manifest_path = build_path / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"sealed build not found: {build_id}")
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        if (
            manifest.get("schema") != "legalbot.lance-build.v1"
            or manifest.get("sealed") is not True
            or manifest.get("build_id") != build_id
            or manifest.get("vector_dimensions") != VECTOR_DIMENSIONS
            or not manifest.get("embedding_model")
            or not manifest.get("reranker_model")
        ):
            raise ValueError("build manifest is not sealed or does not match build id")
        previous = self.read_active()
        if expected_previous is not None and (
            previous is None or previous.build_id != expected_previous
        ):
            raise RuntimeError("active generation changed; refusing non-atomic promotion")
        if previous is not None:
            self._atomic_replace(self.previous_pointer, self._encode(asdict(previous)))
        active = ActiveGeneration(
            build_id,
            hashlib.sha256(manifest_bytes).hexdigest(),
            datetime.now(UTC).isoformat(),
        )
        self._atomic_replace(self.active_pointer, self._encode(asdict(active)))
        return active

    def read_active(self) -> ActiveGeneration | None:
        return self._read_pointer(self.active_pointer, label="ACTIVE")

    def read_previous(self) -> ActiveGeneration | None:
        return self._read_pointer(self.previous_pointer, label="PREVIOUS")

    def rollback_build(self) -> ActiveGeneration:
        """Restore ACTIVE from PREVIOUS. Does not delete the superseded generation."""

        previous = self.read_previous()
        if previous is None:
            raise FileNotFoundError("PREVIOUS pointer is missing; rollback refused")
        current = self.read_active()
        self._require_generic_control_allowed(
            self.builds / previous.build_id, operation="rollback"
        )
        if current is not None:
            self._require_generic_control_allowed(
                self.builds / current.build_id, operation="rollback"
            )
        manifest_path = self.builds / previous.build_id / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"previous sealed build not found: {previous.build_id}")
        if hashlib.sha256(manifest_path.read_bytes()).hexdigest() != previous.manifest_sha256:
            raise OSError("PREVIOUS pointer references a modified build")
        if current is not None:
            self._atomic_replace(self.previous_pointer, self._encode(asdict(current)))
        restored = ActiveGeneration(
            previous.build_id,
            previous.manifest_sha256,
            datetime.now(UTC).isoformat(),
        )
        self._atomic_replace(self.active_pointer, self._encode(asdict(restored)))
        return restored

    def _require_generic_control_allowed(self, build_path: Path, *, operation: str) -> None:
        """Keep held GE scope outside every generic pointer/archive seam."""

        if operation not in {"promote", "rollback", "archive"}:
            raise ValueError("unknown index control operation")
        if self._is_ge_held_or_scope_build(build_path):
            raise PermissionError(
                f"GE held/scope index build cannot use generic {operation} control"
            )

    def _is_ge_held_or_scope_build(self, build_path: Path) -> bool:
        if build_path.exists() and (build_path.is_symlink() or not build_path.is_dir()):
            raise RuntimeError("index build path is not a regular directory")

        def read_object(path: Path, *, label: str) -> dict[str, Any] | None:
            if not path.exists():
                return None
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f"{label} is not a regular immutable file")
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"{label} is invalid") from exc
            if not isinstance(value, dict):
                raise RuntimeError(f"{label} is not an object")
            return value

        def marks_ge(value: dict[str, Any]) -> bool:
            return bool(
                value.get("selection_policy") == _GE_SELECTION_POLICY
                or value.get("ge_held_scope") is True
                or value.get("successor_must_remain_non_active") is True
                or (
                    value.get("active_or_previous_write_authorized") is False
                    and value.get("promotion_authorized") is False
                    and value.get("ge_source_scope_content_sha256") is not None
                )
            )

        boundary = read_object(
            build_path / _BUILD_BOUNDARY_FILENAME, label="index build boundary"
        )
        if boundary is not None:
            if boundary.get("schema") != "legalbot.index-build-boundary.v1":
                raise RuntimeError("index build boundary schema is invalid")
            if marks_ge(boundary):
                return True
        source_manifest = read_object(
            build_path / "approved-source-manifest.json",
            label="approved source manifest",
        )
        if source_manifest is not None and marks_ge(source_manifest):
            return True
        evaluation = read_object(build_path / "evaluation.json", label="index evaluation")
        integrity = evaluation.get("integrity") if evaluation is not None else None
        if isinstance(integrity, dict) and marks_ge(integrity):
            return True

        # Pre-boundary incomplete builds can still be identified from their
        # immutable checkpoint and the create-only approved manifest snapshot.
        checkpoint = read_object(
            build_path / "lance" / "embedding-progress.v1.json",
            label="embedding checkpoint",
        )
        source_sha256 = (
            str(checkpoint.get("source_manifest_sha256") or "")
            if checkpoint is not None
            else ""
        )
        if re.fullmatch(r"[0-9a-f]{64}", source_sha256):
            review_root = self.root.parent / "review_queue"
            if review_root.is_dir() and not review_root.is_symlink():
                for path in sorted(review_root.glob("approved-source-manifest-*.json")):
                    reviewed = read_object(path, label="approved source manifest snapshot")
                    if (
                        reviewed is not None
                        and reviewed.get("manifest_sha256") == source_sha256
                        and marks_ge(reviewed)
                    ):
                        return True
        return False

    def _read_pointer(self, path: Path, *, label: str) -> ActiveGeneration | None:
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        active = ActiveGeneration(**payload)
        self._validate_build_id(active.build_id)
        manifest_path = self.builds / active.build_id / "manifest.json"
        if (
            not manifest_path.exists()
            or hashlib.sha256(manifest_path.read_bytes()).hexdigest() != active.manifest_sha256
        ):
            raise OSError(f"{label} pointer references a missing or modified build")
        return active

    @staticmethod
    def _validate_build_id(build_id: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", build_id):
            raise ValueError("unsafe build id")

    @staticmethod
    def _validated(chunks: Iterable[IndexedChunk]) -> Iterable[IndexedChunk]:
        for chunk in chunks:
            chunk.validate()
            yield chunk

    @staticmethod
    def _encode(payload: dict[str, object]) -> bytes:
        return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )

    @staticmethod
    def _write_new(path: Path, data: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

    def _atomic_replace(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, path)
            self._fsync_directory(path.parent)
        finally:
            Path(temporary_name).unlink(missing_ok=True)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
