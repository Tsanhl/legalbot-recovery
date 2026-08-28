#!/usr/bin/env python3
"""Preflight or execute the one dynamic non-ACTIVE Phase-2A qualification chain.

No path, build ID, source count or chunk count is implicit.  ``preflight`` is
read-only.  ``run-retrieval`` and ``qualify`` are separate, create-only steps;
neither command invokes an answer model or writes ACTIVE/PREVIOUS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

_IMPORT_ROOT = Path(__file__).resolve().parents[1]
if str(_IMPORT_ROOT) not in sys.path:
    sys.path.insert(0, str(_IMPORT_ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.evaluation.live_suite import load_live_evaluation_bundle  # noqa: E402
from backend.app.evaluation.phase2a_successor_qualification import (  # noqa: E402
    build_successor_all585_qualification,
    canonical_json,
    sealed,
)
from backend.app.retrieval.phase2a_successor_reattest import (  # noqa: E402
    inspect_successor_candidate,
    run_successor_retrieval_reattestation,
)
from backend.app.retrieval.retrieval_reattest import (  # noqa: E402
    open_existing_retrieval_reattest_database,
)


def _existing_file(path: Path, *, project_root: Path, label: str) -> Path:
    absolute = path.resolve(strict=True)
    if path.is_symlink() or not absolute.is_file() or not absolute.is_relative_to(project_root):
        raise ValueError(f"{label} must be one non-symbolic file inside the project")
    return absolute


def _json(path: Path, *, project_root: Path, label: str) -> dict[str, Any]:
    absolute = _existing_file(path, project_root=project_root, label=label)
    try:
        value = json.loads(absolute.read_bytes())
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _new_output_root(path: Path, *, project_root: Path) -> Path:
    parent = path.parent.resolve(strict=True)
    allowed = (project_root / "data/evaluations/phase2a-owner-review").resolve(strict=True)
    if path.is_absolute():
        absolute = path.absolute()
    else:
        absolute = (project_root / path).absolute()
        parent = absolute.parent.resolve(strict=True)
    if parent != allowed or absolute.exists() or absolute.is_symlink():
        raise ValueError("output must be one new direct Phase-2A owner-review directory")
    absolute.mkdir(mode=0o700)
    return absolute


def _write_new_json(path: Path, value: Any) -> None:
    with path.open("xb") as handle:
        handle.write(canonical_json(value))
    path.chmod(0o600)


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inputs(args: argparse.Namespace, project_root: Path) -> dict[str, Any]:
    return {
        "owner_packet": _json(args.owner_packet, project_root=project_root, label="owner packet"),
        "owner_receipt": _json(
            args.owner_receipt, project_root=project_root, label="owner receipt"
        ),
        "application_ledger": _json(
            args.application_ledger,
            project_root=project_root,
            label="owner application ledger",
        ),
        "scan_attestation": _json(
            args.scan_attestation,
            project_root=project_root,
            label="source scan attestation",
        ),
        "catalogue_snapshot": _json(
            args.catalogue_snapshot,
            project_root=project_root,
            label="source catalogue snapshot",
        ),
    }


def _open(args: argparse.Namespace):
    project_root = args.project_root.resolve(strict=True)
    settings = Settings(project_root=project_root)
    catalogue = _existing_file(args.catalogue, project_root=project_root, label="catalogue")
    if catalogue != settings.database_path.resolve(strict=True):
        raise ValueError("catalogue is not the configured project catalogue")
    bundle_root = args.bundle_root.resolve(strict=True)
    if not bundle_root.is_dir() or not bundle_root.is_relative_to(project_root):
        raise ValueError("bundle root must be one directory inside the project")
    bundle = load_live_evaluation_bundle(bundle_root)
    values = _inputs(args, project_root)
    database = open_existing_retrieval_reattest_database(catalogue)
    return project_root, settings, bundle, values, database


def _summary(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "legalbot.v111.phase2a.successor-preflight-summary.v1",
        "build_id": candidate["build_id"],
        "source_count": candidate["source_count"],
        "chunk_count": candidate["chunk_count"],
        "vector_count": candidate["vector_count"],
        "source_scan_id": candidate["source_scan_id"],
        "candidate_binding_content_sha256": candidate["artifact_content_sha256"],
        "active_pointer_absent": True,
        "previous_pointer_absent": True,
        "answer_release_eligible": False,
        "phase2b_authorized": False,
    }


def _preflight(args: argparse.Namespace) -> None:
    _project, settings, bundle, values, database = _open(args)
    try:
        candidate = inspect_successor_candidate(
            settings,
            database,
            bundle=bundle,
            build_id=args.build_id,
            **values,
        )
    finally:
        database.close()
    print(json.dumps(_summary(candidate), indent=2, sort_keys=True), flush=True)


def _run_retrieval(args: argparse.Namespace) -> None:
    project, settings, bundle, values, database = _open(args)
    try:
        candidate = inspect_successor_candidate(
            settings,
            database,
            bundle=bundle,
            build_id=args.build_id,
            **values,
        )
        reattestation = run_successor_retrieval_reattestation(
            settings,
            database,
            bundle=bundle,
            build_id=args.build_id,
            **values,
        )
    finally:
        database.close()
    output = _new_output_root(args.output_root, project_root=project)
    candidate_path = output / "SUCCESSOR-CANDIDATE-BINDING.json"
    retrieval_path = output / "SUCCESSOR-RETRIEVAL-REATTESTATION.json"
    _write_new_json(candidate_path, candidate)
    _write_new_json(retrieval_path, reattestation)
    package = sealed(
        {
            "schema": "legalbot.v111.phase2a.successor-retrieval-package.v1",
            "build_id": args.build_id,
            "candidate_binding_content_sha256": candidate["artifact_content_sha256"],
            "retrieval_reattestation_content_sha256": reattestation["artifact_content_sha256"],
            "files": {
                candidate_path.name: _file_sha256(candidate_path),
                retrieval_path.name: _file_sha256(retrieval_path),
            },
            "retrieval_quality_passed": True,
            "answer_model_invoked": False,
            "active_pointer_written": False,
            "previous_pointer_written": False,
            "phase2b_authorized": False,
        }
    )
    package_path = output / "PACKAGE-MANIFEST.json"
    _write_new_json(package_path, package)
    print(
        json.dumps(
            {
                **_summary(candidate),
                "retrieval_reattestation_content_sha256": reattestation["artifact_content_sha256"],
                "package_content_sha256": package["artifact_content_sha256"],
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )


def _qualify(args: argparse.Namespace) -> None:
    project, settings, bundle, values, database = _open(args)
    try:
        live_candidate = inspect_successor_candidate(
            settings,
            database,
            bundle=bundle,
            build_id=args.build_id,
            **values,
        )
    finally:
        database.close()
    candidate = _json(
        args.candidate_binding,
        project_root=project,
        label="successor candidate binding",
    )
    if candidate != live_candidate:
        raise ValueError("stored successor candidate binding differs from live preflight")
    retrieval = _json(
        args.retrieval_reattestation,
        project_root=project,
        label="successor retrieval re-attestation",
    )
    result = build_successor_all585_qualification(
        bundle=bundle,
        owner_packet=values["owner_packet"],
        owner_receipt=values["owner_receipt"],
        application_ledger=values["application_ledger"],
        catalogue_snapshot=values["catalogue_snapshot"],
        candidate_binding=candidate,
        retrieval_reattestation=retrieval,
    )
    output = _new_output_root(args.output_root, project_root=project)
    result_path = output / "SUCCESSOR-ALL585-TECHNICAL-QUALIFICATION.json"
    _write_new_json(result_path, result)
    package = sealed(
        {
            "schema": "legalbot.v111.phase2a.successor-all585-package.v1",
            "build_id": args.build_id,
            "qualification_content_sha256": result["artifact_content_sha256"],
            "qualification_file_sha256": _file_sha256(result_path),
            "phase2a_technical_qualification_passed": True,
            "answer_release_eligible": False,
            "active_pointer_written": False,
            "previous_pointer_written": False,
            "phase2b_authorized": False,
        }
    )
    _write_new_json(output / "PACKAGE-MANIFEST.json", package)
    print(
        json.dumps(
            {
                "schema": "legalbot.v111.phase2a.successor-all585-summary.v1",
                "build_id": args.build_id,
                "status_counts": result["status_counts"],
                "material_gap_count": 0,
                "unresolved_owner_decision_count": 0,
                "qualification_content_sha256": result["artifact_content_sha256"],
                "package_content_sha256": package["artifact_content_sha256"],
                "answer_release_eligible": False,
                "phase2b_authorized": False,
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--catalogue", required=True, type=Path)
    parser.add_argument("--bundle-root", required=True, type=Path)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--owner-packet", required=True, type=Path)
    parser.add_argument("--owner-receipt", required=True, type=Path)
    parser.add_argument("--application-ledger", required=True, type=Path)
    parser.add_argument("--scan-attestation", required=True, type=Path)
    parser.add_argument("--catalogue-snapshot", required=True, type=Path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dynamic, successor-bound Phase-2A preflight and qualification"
    )
    commands = parser.add_subparsers(required=True)
    preflight = commands.add_parser("preflight", help="read-only candidate preflight")
    _add_common(preflight)
    preflight.set_defaults(handler=_preflight)
    retrieval = commands.add_parser(
        "run-retrieval", help="run one create-only retrieval re-attestation"
    )
    _add_common(retrieval)
    retrieval.add_argument("--output-root", required=True, type=Path)
    retrieval.set_defaults(handler=_run_retrieval)
    qualify = commands.add_parser("qualify", help="create one all-585 technical qualification")
    _add_common(qualify)
    qualify.add_argument("--candidate-binding", required=True, type=Path)
    qualify.add_argument("--retrieval-reattestation", required=True, type=Path)
    qualify.add_argument("--output-root", required=True, type=Path)
    qualify.set_defaults(handler=_qualify)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
