#!/usr/bin/env python3
"""Create one locked, integrity-checked v1.11 re-attestation backup receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import Settings  # noqa: E402
from app.evaluation.candidate_completion_authority import (  # noqa: E402
    write_create_only_private_safe_json,
)
from app.evaluation.live_suite import canonical_json  # noqa: E402
from app.governance.existing_catalogue_read import (  # noqa: E402
    open_existing_catalogue_read_database,
)
from app.retrieval.service import _file_sha256, _tree_sha256  # noqa: E402

_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_SAFE_BUILD = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_SAFE_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{2,159}$")
_RECEIPT_SCHEMA = "legalbot.v111-retrieval-reattest-backup-receipt.v2"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tag", required=True)
    parser.add_argument("--verification-report", required=True, type=Path)
    parser.add_argument("--scorer-closure-manifest", required=True, type=Path)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--out", required=True, type=Path)
    return parser


def _git(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _relative(path: Path) -> str:
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(PROJECT_ROOT):
        raise ValueError("backup evidence path escaped the project")
    return resolved.relative_to(PROJECT_ROOT).as_posix()


def _load_object(path: Path, *, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not one JSON object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(8 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _sidecars(catalogue: Path) -> list[str]:
    found: list[str] = []
    for suffix in ("-wal", "-shm", "-journal"):
        member = Path(f"{catalogue}{suffix}")
        if member.exists():
            found.append(member.name)
    return found


def _writer_processes(catalogue: Path) -> tuple[int, ...]:
    executable = shutil.which("lsof")
    if executable is None:
        raise RuntimeError("lsof is required to prove the catalogue has no open process")
    result = subprocess.run(
        [executable, "-t", "--", str(catalogue)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode not in {0, 1}:
        raise RuntimeError("catalogue process inspection failed")
    try:
        return tuple(sorted({int(value) for value in result.stdout.split()}))
    except ValueError as exc:
        raise RuntimeError("catalogue process inspection returned an invalid PID") from exc


def _count(reader: Any, sql: str, params: Sequence[Any] = ()) -> int:
    row = reader.fetchone(sql, params)
    if row is None:
        raise RuntimeError("catalogue count query returned no row")
    return int(row[0])


def _require_private_file(path: Path, *, label: str) -> os.stat_result:
    metadata = path.stat(follow_symlinks=False)
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise RuntimeError(f"{label} is not one private owner file")
    return metadata


def _require_immutable_candidate_file(path: Path, *, label: str) -> os.stat_result:
    metadata = path.stat(follow_symlinks=False)
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o444
        or metadata.st_nlink != 1
    ):
        raise RuntimeError(f"{label} is not one immutable owner file")
    return metadata


def _create_backup(reader: Any, destination: Path) -> None:
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    target = sqlite3.connect(destination)
    try:
        reader.backup(target)
        target.commit()
    finally:
        target.close()
    destination.chmod(0o600)


def _backup_checks(path: Path) -> tuple[str, int, int, int]:
    connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    try:
        integrity_rows = tuple(str(row[0]) for row in connection.execute("PRAGMA integrity_check"))
        foreign_key_rows = tuple(connection.execute("PRAGMA foreign_key_check"))
        history_rows = int(
            connection.execute("SELECT COUNT(*) FROM retrieval_attestation_history").fetchone()[0]
        )
        selection_rows = int(
            connection.execute("SELECT COUNT(*) FROM retrieval_attestation_selections").fetchone()[
                0
            ]
        )
    finally:
        connection.close()
    if integrity_rows != ("ok",):
        raise RuntimeError("catalogue backup integrity check failed")
    if foreign_key_rows:
        raise RuntimeError("catalogue backup foreign-key check failed")
    return integrity_rows[0], len(foreign_key_rows), history_rows, selection_rows


def _require_evidence(
    *,
    report_path: Path,
    closure_path: Path,
    expected_head: str,
    expected_tree: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    report = _load_object(report_path, label="verification report")
    if (
        report.get("passed") is not True
        or report.get("status") != "passed"
        or report.get("failed_check_ids") != []
        or report.get("check_count") != 18
        or not isinstance(report.get("git"), Mapping)
        or report["git"].get("commit") != expected_head
        or report["git"].get("tree") != expected_tree
        or report["git"].get("exact_snapshot_passed") is not True
    ):
        raise RuntimeError("verification report does not bind the exact passing checkpoint")
    closure = _load_object(closure_path, label="scorer closure")
    if (
        closure.get("schema") != "legalbot.scorer-closure-manifest.v1"
        or closure.get("integration_baseline_commit") != expected_head
        or closure.get("integration_baseline_tree") != expected_tree
        or closure.get("equivalence_proven") is not False
        or closure.get("reattestation_required") is not True
        or not isinstance(closure.get("integration_baseline_closure"), Mapping)
    ):
        raise RuntimeError("scorer closure does not require re-attestation for this checkpoint")
    return report, closure


def _execute(args: argparse.Namespace) -> dict[str, Any]:
    expected_head = str(args.expected_head)
    expected_tag = str(args.expected_tag)
    build_id = str(args.build_id)
    if _GIT_SHA.fullmatch(expected_head) is None:
        raise ValueError("expected HEAD is invalid")
    if _SAFE_TAG.fullmatch(expected_tag) is None or _SAFE_BUILD.fullmatch(build_id) is None:
        raise ValueError("checkpoint tag or build identity is invalid")
    if _git("rev-parse", "HEAD") != expected_head or _git("status", "--porcelain=v1"):
        raise RuntimeError("backup requires the exact clean checkpoint")
    expected_tree = _git("rev-parse", "HEAD^{tree}")
    if _git("rev-parse", f"{expected_tag}^{{}}") != expected_head:
        raise RuntimeError("checkpoint tag does not resolve to the exact HEAD")
    tag_object = _git("rev-parse", f"refs/tags/{expected_tag}")

    report_path = args.verification_report.resolve(strict=True)
    closure_path = args.scorer_closure_manifest.resolve(strict=True)
    report, closure = _require_evidence(
        report_path=report_path,
        closure_path=closure_path,
        expected_head=expected_head,
        expected_tree=expected_tree,
    )
    settings = Settings(project_root=PROJECT_ROOT)
    catalogue = settings.database_path.resolve(strict=True)
    candidate = (settings.index_dir / "builds" / build_id).resolve(strict=True)
    if not candidate.is_dir() or candidate.is_symlink():
        raise RuntimeError("candidate build directory is invalid")
    seal_path = candidate / "seal.json"
    manifest_path = candidate / "approved-source-manifest.json"
    lance_path = candidate / "lance"
    for path, label in ((seal_path, "candidate seal"), (manifest_path, "candidate manifest")):
        _require_immutable_candidate_file(path, label=label)
    if not lance_path.is_dir() or lance_path.is_symlink():
        raise RuntimeError("candidate Lance tree is invalid")

    output = args.out.absolute()
    allowed_output = (PROJECT_ROOT / "data/backups").resolve(strict=True)
    if (
        output.parent.resolve(strict=True) != allowed_output
        or output.exists()
        or output.is_symlink()
    ):
        raise ValueError("backup output must be one new direct child of data/backups")
    sidecars_before = _sidecars(catalogue)
    writer_pids = _writer_processes(catalogue)
    if sidecars_before or writer_pids:
        raise RuntimeError("catalogue backup requires no sidecars and no open process")

    started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    source_before = _sha256(catalogue)
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    backup_path = output / "catalog.sqlite3"
    reader = open_existing_catalogue_read_database(catalogue, exclusive_lock=True)
    try:
        preconditions = {
            "active_builds": _count(
                reader, "SELECT COUNT(*) FROM index_builds WHERE status='active'"
            ),
            "active_jobs": _count(
                reader, "SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')"
            ),
            "active_scans": _count(
                reader, "SELECT COUNT(*) FROM source_scans WHERE status='running'"
            ),
            "attestation_history_rows": _count(
                reader, "SELECT COUNT(*) FROM retrieval_attestation_history"
            ),
            "attestation_selection_rows": _count(
                reader, "SELECT COUNT(*) FROM retrieval_attestation_selections"
            ),
            "candidate_rows": _count(
                reader,
                "SELECT COUNT(*) FROM index_builds WHERE id=? AND status='candidate'",
                (build_id,),
            ),
        }
        if (
            preconditions["active_builds"] != 0
            or preconditions["active_jobs"] != 0
            or preconditions["active_scans"] != 0
            or preconditions["candidate_rows"] != 1
        ):
            raise RuntimeError("catalogue writer/candidate preconditions failed")
        _create_backup(reader, backup_path)
        reader.total_changes()
        source_after = _sha256(catalogue)
    finally:
        reader.close()
    if source_before != source_after:
        raise RuntimeError("catalogue bytes changed during backup")
    sidecars_after = _sidecars(catalogue)
    if sidecars_after:
        raise RuntimeError("catalogue sidecars appeared during locked backup")

    integrity, foreign_key_count, history_rows, selection_rows = _backup_checks(backup_path)
    backup_metadata = _require_private_file(backup_path, label="catalogue backup")
    suite_path = (PROJECT_ROOT / "benchmarks/retrieval/v1.1.jsonl").resolve(strict=True)
    suite_rows = sum(1 for line in suite_path.read_bytes().splitlines() if line.strip())
    if suite_rows != 24:
        raise RuntimeError("frozen retrieval suite no longer has 24 cases")
    closure_value = closure["integration_baseline_closure"]
    finished_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    receipt: dict[str, Any] = {
        "schema": _RECEIPT_SCHEMA,
        "authorizing": False,
        "method": "sqlite-online-backup-api-through-pinned-immutable-reader",
        "started_at": started_at,
        "finished_at": finished_at,
        "writer_process_count": len(writer_pids),
        "writer_preconditions": preconditions,
        "checkpoint": {
            "commit": expected_head,
            "tree": expected_tree,
            "tag": expected_tag,
            "tag_object": tag_object,
        },
        "catalogue": {
            "relative_path": _relative(catalogue),
            "sha256_before": source_before,
            "sha256_after": source_after,
            "size": catalogue.stat().st_size,
            "sidecars_before": sidecars_before,
            "sidecars_after": sidecars_after,
            "shm_is_persistent_content": False,
        },
        "backup": {
            "relative_path": _relative(backup_path),
            "sha256": _sha256(backup_path),
            "size": backup_metadata.st_size,
            "mode": oct(stat.S_IMODE(backup_metadata.st_mode)),
            "link_count": backup_metadata.st_nlink,
            "integrity_check": integrity,
            "foreign_key_violation_count": foreign_key_count,
            "attestation_history_rows": history_rows,
            "attestation_selection_rows": selection_rows,
        },
        "candidate": {
            "build_id": build_id,
            "seal_file_sha256": _file_sha256(seal_path),
            "manifest_file_sha256": _file_sha256(manifest_path),
            "lance_tree_sha256": _tree_sha256(lance_path),
        },
        "verification": {
            "relative_path": _relative(report_path),
            "file_sha256": _sha256(report_path),
            "report_sha256": report["report_sha256"],
            "check_count": report["check_count"],
            "failed_check_count": len(report["failed_check_ids"]),
        },
        "scorer_closure": {
            "relative_path": _relative(closure_path),
            "file_sha256": _sha256(closure_path),
            "manifest_sha256": closure["manifest_sha256"],
            "aggregate_sha256": closure_value["aggregate_sha256"],
            "member_count": closure_value["member_count"],
        },
        "suite": {
            "identity": "Frozen Retrieval v1.1",
            "relative_path": _relative(suite_path),
            "sha256": _sha256(suite_path),
            "row_count": suite_rows,
        },
    }
    receipt["receipt_sha256"] = hashlib.sha256(canonical_json(receipt)).hexdigest()
    write_create_only_private_safe_json(output / "backup-receipt.json", receipt)
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        receipt = _execute(args)
        print(
            json.dumps(
                {
                    "schema": receipt["schema"],
                    "authorizing": False,
                    "receipt_sha256": receipt["receipt_sha256"],
                    "backup_sha256": receipt["backup"]["sha256"],
                    "status": "complete",
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema": "legalbot.v111-retrieval-reattest-backup-stop.v1",
                    "authorizing": False,
                    "status": "stopped",
                    "reason_code": type(exc).__name__.casefold(),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
