#!/usr/bin/env python3
"""Run a candidate-pinned generic retrieval-only cold-warm preflight."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from datetime import UTC, date, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import Settings  # noqa: E402
from app.db import Database  # noqa: E402
from app.evaluation.candidate_runtime_preflight import (  # noqa: E402
    run_candidate_runtime_preflight,
)
from app.evaluation.live_suite import load_live_evaluation_bundle  # noqa: E402
from app.evaluation.sealed_candidate import (  # noqa: E402
    load_sealed_candidate_identity,
)
from app.observability.live_metrics import load_slo_policy  # noqa: E402
from app.retrieval.pinned_factory import PinnedRetrieverFactory  # noqa: E402

DEFAULT_BUNDLE = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--candidate-build-id", required=True)
    parser.add_argument("--as-of-date", required=True, type=date.fromisoformat)
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument(
        "--case-id",
        action="append",
        dest="case_ids",
        help=(
            "Additional sealed Live60 case. One deterministic representative per "
            "eligible route/word band is always selected without case-specific preference."
        ),
    )
    return parser


def _git_identity() -> tuple[str, bool]:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    return revision, dirty


def _safe_error_code(exc: BaseException) -> str:
    candidate = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    if isinstance(exc, RuntimeError) and exc.args:
        explicit = str(exc.args[0]).strip().casefold().replace("-", "_")
        if _SAFE_CODE.fullmatch(explicit):
            candidate = explicit
    return candidate if _SAFE_CODE.fullmatch(candidate) else "preflight_failed"


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    settings = Settings(project_root=PROJECT_ROOT)
    database: Database | None = None
    try:
        if settings.online_default != "local_only" or settings.official_research_enabled:
            raise RuntimeError("offline_profile_required")
        if not settings.database_path.is_file():
            raise RuntimeError("catalogue_missing")
        bundle = load_live_evaluation_bundle(args.bundle)
        database = Database(settings.database_path)
        candidate = load_sealed_candidate_identity(
            settings=settings,
            database=database,
            candidate_build_id=str(args.candidate_build_id),
        )
        slo_policy = load_slo_policy(settings.observability_slo_path)
        slo_policy_sha256 = hashlib.sha256(settings.observability_slo_path.read_bytes()).hexdigest()
        retriever = PinnedRetrieverFactory(settings, database).for_build(candidate.build_id)
        code_revision, code_dirty = _git_identity()
        if code_dirty:
            raise RuntimeError("dirty_worktree_refused")
        output_root = (
            settings.evaluation_dir / "runtime-preflight" / datetime.now(UTC).date().isoformat()
        )
        result = asyncio.run(
            run_candidate_runtime_preflight(
                run_id=str(args.run_id),
                output_root=output_root,
                bundle=bundle,
                candidate=candidate,
                retriever=retriever,
                slo_policy=slo_policy,
                slo_policy_sha256=slo_policy_sha256,
                as_of_date=args.as_of_date,
                code_revision=code_revision,
                code_dirty=code_dirty,
                additional_case_ids=args.case_ids,
            )
        )
        passed = result.get("preflight_passed") is True
        print(
            json.dumps(
                {
                    "run_id": args.run_id,
                    "candidate_build_id": candidate.build_id,
                    "status": result.get("status"),
                    "preflight_passed": passed,
                    "artifact_seal_sha256": result.get("seal_sha256"),
                },
                sort_keys=True,
            )
        )
        return 0 if passed else 2
    except Exception as exc:
        print(
            json.dumps(
                {
                    "run_id": args.run_id,
                    "status": "stopped",
                    "error_code": _safe_error_code(exc),
                },
                sort_keys=True,
            )
        )
        return 2
    finally:
        if database is not None:
            database.close()


if __name__ == "__main__":
    raise SystemExit(main())
