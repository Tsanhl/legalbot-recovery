#!/usr/bin/env python3
"""Bind the existing four provision qualifications to the exact held successor."""

from __future__ import annotations

import hashlib
import json
import os
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from backend.app.config import settings
from backend.app.retrieval.candidate_qualification import (
    load_candidate_provision_qualifications,
)

BUILD_ID = "current-law-ew-full-fp16-v111-20260827-phase2a-a"
PREDECESSOR_BUILD_ID = "current-law-ew-full-fp16-v111-20260818-a"
RUN_NAME = "LegalBot-Phase2A-2026-08-27-candidate-provision-qualification-roll-forward"
FAILURE_FINGERPRINT = "4c32a571c5c2d8770676b48ffb8b0566fb024d70ba0a240b8253fa678fd7692f"
EXPECTED_ACTIVE_SHA256 = "91468882d1a6e9e57057f24e098936df14abe07d50c5a76b14ee03dc57e91b2b"
EXPECTED_MANIFEST_SHA256 = "acc4b0aee4f43a00b21c56663a354e4b232c0c2d82f52a792779ea3088929d00"
EXPECTED_SEAL_SHA256 = "b7a8dfabcd5b91c4bebe81cba5817ca35a4366dd8855acd24a2aeda7f7d91b13"
EXPECTED_SOURCE_MANIFEST_SHA256 = "0bbb1edb169c84a26e5f1d42e367f9e2f83fcdd9c652a9061980652f15979b21"
EXPECTED_PROVISION_REGISTRY_SHA256 = (
    "1bb3c036a555cd67bc618a7edff1f1f5a0274ea4061c0775bccf8f722f7f88ac"
)
EXPECTED_LANCE_TREE_SHA256 = "2f561a0ec55743ad2897ddd59789e0d41eecb465c4c0c4b6e23b7bf304010da3"
ARCHIVE_RELATIVE = (
    "config/archive/provision-verification/"
    "candidate-provision-qualification-current-law-ew-full-fp16-v111-20260818-a.v1.json"
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("successor candidate tree contains a symbolic link")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        file_digest = bytes.fromhex(_sha256_file(path))
        digest.update(len(file_digest).to_bytes(8, "big"))
        digest.update(file_digest)
    return digest.hexdigest()


def _write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _write_new_json(path: Path, value: Any) -> None:
    _write_new(path, _pretty_json(value))


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"required regular file is unavailable: {path.name}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError(f"required JSON is not an object: {path.name}")
    return value


def _sealed(value: dict[str, Any], *, field: str) -> dict[str, Any]:
    output = dict(value)
    output[field] = _sha256(_canonical_json(output))
    return output


def _pointer_snapshot() -> dict[str, Any]:
    output: dict[str, Any] = {}
    for name in ("ACTIVE.json", "PREVIOUS.json"):
        path = settings.index_dir / name
        if path.is_symlink():
            raise RuntimeError("index pointer is a symbolic link")
        output[name] = {
            "exists": path.exists(),
            "sha256": _sha256_file(path) if path.is_file() else None,
        }
    return output


def _active_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("active candidate provision qualification is missing or unsafe")
    raw = path.read_bytes()
    if _sha256(raw) != EXPECTED_ACTIVE_SHA256:
        raise RuntimeError("active candidate provision qualification identity changed")
    return raw


def _successor_payload(predecessor: dict[str, Any]) -> dict[str, Any]:
    payload = deepcopy(predecessor)
    candidate = payload.get("candidate")
    records = payload.get("records")
    if (
        payload.get("schema") != "legalbot.candidate-provision-qualification.v1"
        or payload.get("status") != "active"
        or not isinstance(candidate, dict)
        or candidate.get("build_id") != PREDECESSOR_BUILD_ID
        or not isinstance(records, list)
        or len(records) != 4
        or payload.get("record_count") != 4
    ):
        raise RuntimeError("predecessor candidate qualification boundary changed")
    payload["version"] = "1.1.0"
    payload["candidate"] = {
        "build_id": BUILD_ID,
        "embedded_provision_registry_sha256": EXPECTED_PROVISION_REGISTRY_SHA256,
        "lance_tree_sha256": EXPECTED_LANCE_TREE_SHA256,
        "manifest_file_sha256": EXPECTED_MANIFEST_SHA256,
        "seal_file_sha256": EXPECTED_SEAL_SHA256,
        "source_manifest_file_sha256": EXPECTED_SOURCE_MANIFEST_SHA256,
    }
    payload["predecessor_candidate_qualification"] = {
        "relative_path": ARCHIVE_RELATIVE,
        "sha256": EXPECTED_ACTIVE_SHA256,
        "build_id": PREDECESSOR_BUILD_ID,
        "status": "immutable_historical",
    }
    payload["candidate_binding_roll_forward_policy"] = (
        "same_four_records_and_official_provision_snapshots_new_sealed_candidate_only"
    )
    return payload


def _validate_candidate_files(build_path: Path) -> None:
    expected = {
        "manifest.json": EXPECTED_MANIFEST_SHA256,
        "seal.json": EXPECTED_SEAL_SHA256,
        "approved-source-manifest.json": EXPECTED_SOURCE_MANIFEST_SHA256,
        "provision-verification.v1.json": EXPECTED_PROVISION_REGISTRY_SHA256,
    }
    for name, digest in expected.items():
        if _sha256_file(build_path / name) != digest:
            raise RuntimeError(f"successor candidate file identity changed: {name}")
    seal = _load_object(build_path / "seal.json")
    if (
        seal.get("build_id") != BUILD_ID
        or seal.get("manifest_sha256") != EXPECTED_MANIFEST_SHA256
        or seal.get("lance_tree_sha256") != EXPECTED_LANCE_TREE_SHA256
    ):
        raise RuntimeError("successor candidate seal binding changed")


def _package_index(root: Path) -> dict[str, Any]:
    files = {
        path.name: {"sha256": _sha256_file(path), "size": path.stat().st_size}
        for path in sorted(root.iterdir())
        if path.is_file() and path.name not in {"PACKAGE-INDEX.json", "SHA256SUMS.txt"}
    }
    return _sealed(
        {
            "schema": "legalbot.v111.phase2a.candidate-qualification-roll-forward-package.v1",
            "status": "PASSED_SAME_FOUR_RECORDS_SUCCESSOR_BINDING_ACTIVE",
            "build_id": BUILD_ID,
            "files": files,
            "new_provision_or_source_admitted": False,
            "candidate_bytes_changed": False,
            "source_scope_changed": False,
            "source_scan_repeated": False,
            "active_or_previous_written": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
        field="package_content_sha256",
    )


def _write_sums(root: Path) -> None:
    rows = [
        f"{_sha256_file(path)}  {path.name}"
        for path in sorted(root.iterdir())
        if path.is_file() and path.name != "SHA256SUMS.txt"
    ]
    _write_new(root / "SHA256SUMS.txt", ("\n".join(rows) + "\n").encode())


def main() -> None:
    evidence_root = settings.evaluation_dir / "phase2a-owner-review" / RUN_NAME
    if evidence_root.exists():
        raise FileExistsError("candidate qualification roll-forward evidence already exists")
    evidence_root.mkdir(parents=True, mode=0o700)
    active_path = settings.project_root / "config/candidate_provision_qualification.v1.json"
    archive_path = settings.project_root / ARCHIVE_RELATIVE
    build_path = settings.index_dir / "builds" / BUILD_ID
    predecessor_build_path = settings.index_dir / "builds" / PREDECESSOR_BUILD_ID
    _write_new_json(
        evidence_root / "INTENT.json",
        {
            "schema": "legalbot.v111.phase2a.candidate-qualification-roll-forward-intent.v1",
            "created_at": datetime.now(UTC).isoformat(),
            "repair_of_failure_fingerprint": FAILURE_FINGERPRINT,
            "predecessor_build_id": PREDECESSOR_BUILD_ID,
            "successor_build_id": BUILD_ID,
            "record_count": 4,
            "new_provision_or_source_admission_authorized": False,
            "candidate_bytes_change_authorized": False,
            "source_scope_change_authorized": False,
            "source_scan_authorized": False,
            "active_or_previous_write_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )
    active_replaced = False
    try:
        predecessor_raw = _active_bytes(active_path)
        predecessor = json.loads(predecessor_raw)
        if not isinstance(predecessor, dict):
            raise RuntimeError("predecessor candidate qualification is not an object")
        if archive_path.exists() or archive_path.is_symlink():
            raise RuntimeError("candidate qualification archive target already exists")
        _validate_candidate_files(build_path)
        candidate_tree_before = _tree_sha256(build_path)
        pointers_before = _pointer_snapshot()
        if any(value["exists"] for value in pointers_before.values()):
            raise RuntimeError("ACTIVE or PREVIOUS pointer exists before qualification repair")

        predecessor_records, predecessor_replay_sha256 = load_candidate_provision_qualifications(
            settings.project_root,
            build_path=predecessor_build_path,
            build_id=PREDECESSOR_BUILD_ID,
        )
        if predecessor_replay_sha256 != EXPECTED_ACTIVE_SHA256 or len(predecessor_records) != 4:
            raise RuntimeError("predecessor qualification deterministic replay changed")

        successor = _successor_payload(predecessor)
        successor_raw = _pretty_json(successor)
        staged_path = evidence_root / "SUCCESSOR-CANDIDATE-PROVISION-QUALIFICATION.json"
        _write_new(staged_path, successor_raw)
        successor_records, successor_replay_sha256 = load_candidate_provision_qualifications(
            settings.project_root,
            build_path=build_path,
            build_id=BUILD_ID,
            qualification_path=staged_path,
        )
        if successor_records != predecessor_records or len(successor_records) != 4:
            raise RuntimeError("successor qualification changes the reviewed record set")
        if successor_replay_sha256 != _sha256(successor_raw):
            raise RuntimeError("successor qualification replay digest changed")

        _write_new(archive_path, predecessor_raw)
        temporary = active_path.with_suffix(active_path.suffix + ".phase2a-roll-forward.tmp")
        if temporary.exists() or temporary.is_symlink():
            raise RuntimeError("candidate qualification temporary target already exists")
        _write_new(temporary, successor_raw)
        os.replace(temporary, active_path)
        active_replaced = True

        active_records, active_sha256 = load_candidate_provision_qualifications(
            settings.project_root,
            build_path=build_path,
            build_id=BUILD_ID,
        )
        candidate_tree_after = _tree_sha256(build_path)
        pointers_after = _pointer_snapshot()
        if (
            active_records != predecessor_records
            or active_sha256 != successor_replay_sha256
            or _sha256_file(archive_path) != EXPECTED_ACTIVE_SHA256
            or candidate_tree_after != candidate_tree_before
            or pointers_after != pointers_before
        ):
            raise RuntimeError("candidate qualification roll-forward postcondition failed")

        record = _sealed(
            {
                "schema": "legalbot.v111.phase2a.candidate-qualification-roll-forward.v1",
                "repair_of_failure_fingerprint": FAILURE_FINGERPRINT,
                "predecessor_build_id": PREDECESSOR_BUILD_ID,
                "successor_build_id": BUILD_ID,
                "predecessor_artifact_sha256": EXPECTED_ACTIVE_SHA256,
                "successor_artifact_sha256": active_sha256,
                "record_count": 4,
                "records_byte_identical": successor["records"] == predecessor["records"],
                "deterministic_replay_equal": active_records == predecessor_records,
                "archive_relative_path": ARCHIVE_RELATIVE,
                "candidate_tree_sha256_before": candidate_tree_before,
                "candidate_tree_sha256_after": candidate_tree_after,
                "candidate_bytes_changed": False,
                "new_provision_or_source_admitted": False,
                "source_scope_changed": False,
                "source_scan_repeated": False,
                "active_or_previous_written": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
            field="record_content_sha256",
        )
        _write_new_json(evidence_root / "ROLL-FORWARD.json", record)
        _write_new(
            evidence_root / "OUTCOME.txt",
            b"PASSED - SAME FOUR QUALIFICATIONS BOUND TO HELD SUCCESSOR\n",
        )
        package = _package_index(evidence_root)
        _write_new_json(evidence_root / "PACKAGE-INDEX.json", package)
        _write_sums(evidence_root)
        print(
            json.dumps(
                {
                    "status": package["status"],
                    "successor_build_id": BUILD_ID,
                    "successor_artifact_sha256": active_sha256,
                    "record_count": 4,
                    "records_changed": False,
                    "candidate_bytes_changed": False,
                    "package_content_sha256": package["package_content_sha256"],
                },
                indent=2,
                sort_keys=True,
            ),
            flush=True,
        )
    except BaseException as exc:
        failure = {
            "schema": "legalbot.v111.phase2a.candidate-qualification-roll-forward-failure.v1",
            "created_at": datetime.now(UTC).isoformat(),
            "repair_of_failure_fingerprint": FAILURE_FINGERPRINT,
            "exception_type": type(exc).__name__,
            "exception_message": str(exc),
            "active_artifact_replaced_before_failure": active_replaced,
            "candidate_bytes_changed": False,
            "source_scope_changed": False,
            "source_scan_repeated": False,
            "active_or_previous_written": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        failure["failure_fingerprint"] = _sha256(_canonical_json(failure))
        failure_path = evidence_root / "FAILURE-REPORT.json"
        if not failure_path.exists():
            _write_new_json(failure_path, failure)
        raise


if __name__ == "__main__":
    main()
