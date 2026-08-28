#!/usr/bin/env python3
"""Print a privacy-safe LegalBot queue, worker and candidate snapshot."""

from __future__ import annotations

import argparse
import json

from app.config import settings
from app.db import Database
from app.observability.control_plane import build_control_plane_snapshot


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("candidate", "live"), default="candidate")
    parser.add_argument("--check", action="store_true", help="exit non-zero when blockers exist")
    args = parser.parse_args()

    database = Database(settings.database_path)
    database.initialize()
    try:
        snapshot = build_control_plane_snapshot(settings, database, mode=args.mode)
    finally:
        database.close()
    print(json.dumps(snapshot, indent=2, sort_keys=True))
    return 2 if args.check and not snapshot["operationally_clear"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
