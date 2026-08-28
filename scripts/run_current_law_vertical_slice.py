"""Retired unsafe one-shot vertical-slice runner.

The former script mixed build, freeze and evaluation around the superseded v1.0
pack. Keeping it executable would create a second promotion path. Use the
durable v1.1 workflow in docs/CURRENT_STATE.md instead.
"""

from __future__ import annotations


def main() -> int:
    raise SystemExit(
        "Retired: review/freeze retrieval v1.1, enqueue the durable build, then "
        "run `legalbot attest-index BUILD_ID`. This script never builds or scores."
    )


if __name__ == "__main__":
    main()
