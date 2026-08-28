#!/usr/bin/env python3
"""Roll provision qualifications forward only across identical official XML."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.retrieval.provision_roll_forward import artifact_bytes, build_roll_forward  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-root",
        type=Path,
        default=PROJECT_ROOT / "sources" / "materials-2026-08-12",
    )
    parser.add_argument(
        "--predecessor",
        type=Path,
        default=PROJECT_ROOT / "config" / "provision_verification.v1.json",
    )
    parser.add_argument(
        "--current-pack",
        type=Path,
        default=PROJECT_ROOT / "config" / "current_legislation_pack.json",
    )
    parser.add_argument(
        "--download-report",
        type=Path,
        default=PROJECT_ROOT
        / "config"
        / "archive"
        / "provision-verification"
        / "current-legislation-download-2026-08-14.json",
    )
    parser.add_argument(
        "--download-report-archive",
        type=Path,
        default=PROJECT_ROOT
        / "config"
        / "archive"
        / "provision-verification"
        / "current-legislation-download-2026-08-14.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "config" / "provision_verification.v1.json",
    )
    parser.add_argument(
        "--archive",
        type=Path,
        default=PROJECT_ROOT
        / "config"
        / "archive"
        / "provision-verification"
        / "provision-verification-2026-08-12.v1.json",
    )
    parser.add_argument(
        "--archive-index",
        type=Path,
        default=PROJECT_ROOT / "config" / "archive" / "provision-verification" / "index.json",
    )
    parser.add_argument(
        "--exception-report",
        type=Path,
        default=PROJECT_ROOT
        / "config"
        / "archive"
        / "provision-verification"
        / "provision-verification-roll-forward-2026-08-14.json",
    )
    return parser


def _relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT).as_posix()
    except ValueError as exc:
        raise SystemExit(
            "all output and bound artifacts must remain under the project root"
        ) from exc


def _write_exact(path: Path, raw: bytes, *, allow_existing_identical: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if allow_existing_identical and path.read_bytes() == raw:
            return
        raise SystemExit(f"refusing to overwrite a different audit artifact: {_relative(path)}")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, path)


def _replace_active(path: Path, raw: bytes, *, expected_predecessor: bytes) -> None:
    if path.exists() and path.read_bytes() not in {expected_predecessor, raw}:
        raise SystemExit("active provision registry changed during roll-forward")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, path)


def main() -> None:
    args = _parser().parse_args()
    predecessor_raw = args.predecessor.read_bytes()
    if args.predecessor.resolve() == args.output.resolve() and args.archive.is_file():
        active = json.loads(predecessor_raw)
        current_pack = json.loads(args.current_pack.read_bytes())
        if active.get("as_of_date") == current_pack.get("as_of_date"):
            predecessor_raw = args.archive.read_bytes()
    artifacts = build_roll_forward(
        predecessor_raw=predecessor_raw,
        current_pack_raw=args.current_pack.read_bytes(),
        download_report_raw=args.download_report.read_bytes(),
        source_root=args.source_root,
        predecessor_archive_relative_path=_relative(args.archive),
        exception_report_relative_path=_relative(args.exception_report),
        download_report_relative_path=_relative(args.download_report_archive),
    )
    rendered = artifact_bytes(artifacts)
    _write_exact(args.archive, rendered["predecessor"])
    _write_exact(args.download_report_archive, rendered["download_report"])
    _write_exact(args.exception_report, rendered["exception_report"])
    _write_exact(args.archive_index, rendered["archive_index"])
    _replace_active(args.output, rendered["registry"], expected_predecessor=predecessor_raw)
    print(
        "complete: "
        f"{artifacts.registry['inherited_record_count']} inherited; "
        f"{artifacts.registry['excluded_record_count']} require fresh human review"
    )


if __name__ == "__main__":
    main()
