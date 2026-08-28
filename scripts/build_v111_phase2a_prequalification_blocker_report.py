#!/usr/bin/env python3
"""Create the immutable read-only Phase-2A prequalification blocker report."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

_IMPORT_ROOT = Path(__file__).resolve().parents[1]
if str(_IMPORT_ROOT) not in sys.path:
    sys.path.insert(0, str(_IMPORT_ROOT))

from backend.app.evaluation.phase2a_prequalification_blockers import (  # noqa: E402
    build_report_from_paths,
)
from backend.app.evaluation.phase2a_successor_qualification import (  # noqa: E402
    canonical_json,
    sealed,
)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _input(path: Path, *, project_root: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not resolved.is_file() or not resolved.is_relative_to(project_root):
        raise ValueError(f"{label} must be one non-symbolic project file")
    return resolved


def _output(path: Path, *, project_root: Path) -> Path:
    allowed = (project_root / "data/evaluations/phase2a-owner-review").resolve(strict=True)
    resolved = path.absolute() if path.is_absolute() else (project_root / path).absolute()
    parent = resolved.parent.resolve(strict=True)
    if parent != allowed or resolved.exists() or resolved.is_symlink():
        raise ValueError("output must be one new direct Phase-2A owner-review directory")
    resolved.mkdir(mode=0o700)
    return resolved


def _write_new(path: Path, value: Any) -> None:
    with path.open("xb") as handle:
        handle.write(canonical_json(value))
    os.chmod(path, 0o600)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seal a read-only deterministic Phase-2A prequalification blocker report"
    )
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--original-packet", required=True, type=Path)
    parser.add_argument("--final-packet", required=True, type=Path)
    parser.add_argument("--owner-receipt", required=True, type=Path)
    parser.add_argument("--execution-authority", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_root = args.project_root.resolve(strict=True)
    original = _input(args.original_packet, project_root=project_root, label="original packet")
    final = _input(args.final_packet, project_root=project_root, label="final packet")
    receipt = _input(args.owner_receipt, project_root=project_root, label="owner receipt")
    authority = _input(
        args.execution_authority,
        project_root=project_root,
        label="execution authority",
    )
    report = build_report_from_paths(
        original_packet_path=original,
        final_packet_path=final,
        owner_receipt_path=receipt,
        execution_authority_path=authority,
        project_root=project_root,
    )
    output = _output(args.output_root, project_root=project_root)
    report_path = output / "PREQUALIFICATION-BLOCKER-REPORT.json"
    _write_new(report_path, report)
    package = sealed(
        {
            "schema": "legalbot.v111.phase2a.prequalification-blocker-package.v1",
            "status": "BLOCKED_READ_ONLY_EVIDENCE_SEALED",
            "report_content_sha256": report["artifact_content_sha256"],
            "report_file_sha256": _file_sha256(report_path),
            "blocking_row_count": report["counts"]["blocking_row_count"],
            "source_scan_run": False,
            "index_build_run": False,
            "embedding_run": False,
            "retrieval_reattestation_run": False,
            "all585_qualification_run": False,
            "answer_model_run": False,
            "execution_chain_consumed": False,
            "active_pointer_written": False,
            "previous_pointer_written": False,
            "phase2b_authorized": False,
        }
    )
    package_path = output / "PACKAGE-MANIFEST.json"
    _write_new(package_path, package)
    sums_path = output / "SHA256SUMS.txt"
    sums = "\n".join(f"{_file_sha256(path)}  {path.name}" for path in (report_path, package_path))
    with sums_path.open("xb") as handle:
        handle.write((sums + "\n").encode("utf-8"))
    os.chmod(sums_path, 0o600)
    print(
        json.dumps(
            {
                "schema": "legalbot.v111.phase2a.prequalification-blocker-summary.v1",
                "status": report["status"],
                "blocking_row_count": report["counts"]["blocking_row_count"],
                "partial_row_count": report["counts"]["partial_row_count"],
                "none_row_count": report["counts"]["none_row_count"],
                "report_content_sha256": report["artifact_content_sha256"],
                "report_file_sha256": _file_sha256(report_path),
                "package_content_sha256": package["artifact_content_sha256"],
                "execution_chain_consumed": False,
                "output_root": output.relative_to(project_root).as_posix(),
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
