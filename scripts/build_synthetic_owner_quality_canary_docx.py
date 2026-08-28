#!/usr/bin/env python3
"""Build one synthetic answer-only owner-canary DOCX for renderer QA."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.evaluation.owner_quality_canary_docx import (  # noqa: E402
    export_owner_quality_canary_docx,
)
from backend.app.evaluation.owner_quality_canary_synthetic_fixture import (  # noqa: E402
    create_synthetic_owner_canary_review_fixture,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        required=True,
        type=Path,
        help="New empty destination for the synthetic private review workspace",
    )
    parser.add_argument(
        "--run-id",
        default="development-synthetic-render-001",
        help="Safe synthetic run identity",
    )
    args = parser.parse_args()
    fixture = create_synthetic_owner_canary_review_fixture(
        root=args.output_root,
        run_id=args.run_id,
    )
    docx_path, control_path, control = export_owner_quality_canary_docx(
        workspace=fixture.workspace,
        package=fixture.package,
    )
    print(
        json.dumps(
            {
                "synthetic": True,
                "release_authority": False,
                "docx_name": docx_path.name,
                "control_name": control_path.name,
                "final_package_seal_sha256": fixture.package.seal_sha256,
                "docx_control_seal_sha256": control.seal_sha256,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
