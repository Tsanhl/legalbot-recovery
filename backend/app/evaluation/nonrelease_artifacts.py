"""Create-only, privacy-safe storage for non-release evaluation tooling.

These helpers deliberately support only machine-safe JSON.  They never append
to application logs and never overwrite an earlier run artifact.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from .live30 import _exclusive_write, _private_directory, assert_safe_evaluation_payload
from .live_suite import sealed_sha256

_SAFE_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")


def sealed_safe_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return a safe copy with a canonical self-seal."""

    payload = dict(value)
    payload["seal_sha256"] = sealed_sha256(payload)
    assert_safe_evaluation_payload(payload)
    return payload


def safe_json_bytes(value: Mapping[str, Any]) -> bytes:
    assert_safe_evaluation_payload(value)
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


class CreateOnlyRunDirectory:
    """A private run directory whose JSON members can only be created once."""

    def __init__(self, *, root: Path, run_id: str, resume: bool) -> None:
        if not _SAFE_RUN_ID.fullmatch(run_id):
            raise ValueError("run ID must be a safe opaque identifier")
        _private_directory(root)
        resolved_root = root.resolve()
        run_dir = root / run_id
        if run_dir.exists():
            if not resume or not run_dir.is_dir() or run_dir.is_symlink():
                raise FileExistsError("non-release run directory already exists")
        else:
            run_dir.mkdir(mode=0o700)
        run_dir.chmod(0o700)
        if run_dir.resolve().parent != resolved_root:
            raise ValueError("non-release run directory escapes its private root")
        self.root = resolved_root
        self.run_id = run_id
        self.path = run_dir.resolve()

    def _member(self, relative_name: str) -> Path:
        relative = PurePosixPath(relative_name)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ValueError("artifact name must be a safe relative path")
        if any(not part or part in {".", ".."} for part in relative.parts):
            raise ValueError("artifact name contains an unsafe component")
        target = self.path.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        current = target.parent
        while current != self.path:
            if current.is_symlink():
                raise ValueError("artifact parent cannot be a symlink")
            current.chmod(0o700)
            current = current.parent
        if not target.parent.resolve().is_relative_to(self.path):
            raise ValueError("artifact path escapes the private run directory")
        return target

    def write_json(self, relative_name: str, value: Mapping[str, Any]) -> Path:
        target = self._member(relative_name)
        _exclusive_write(target, safe_json_bytes(value))
        target.chmod(0o600)
        return target

    def read_json(self, relative_name: str) -> dict[str, Any]:
        target = self._member(relative_name)
        try:
            raw = target.read_bytes()
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("non-release artifact is missing or invalid") from exc
        if not isinstance(value, dict):
            raise ValueError("non-release artifact must be a JSON object")
        assert_safe_evaluation_payload(value)
        return value

    def exists(self, relative_name: str) -> bool:
        return self._member(relative_name).is_file()


def verify_sealed_artifact(
    value: Mapping[str, Any], *, schema: str | None = None
) -> dict[str, Any]:
    payload = dict(value)
    if schema is not None and payload.get("schema") != schema:
        raise ValueError("non-release artifact schema mismatch")
    if payload.get("seal_sha256") != sealed_sha256(payload):
        raise ValueError("non-release artifact seal mismatch")
    assert_safe_evaluation_payload(payload)
    return payload
