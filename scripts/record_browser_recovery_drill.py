#!/usr/bin/env python3
"""Record an owner-observed real-browser recovery drill; never drives a browser."""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.evaluation.browser_recovery import (  # noqa: E402
    BROWSER_RECOVERY_RELATIVE_PATH,
    BrowserRecoveryConfirmations,
    first_live_recorder_settings,
    record_browser_recovery_drill,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--trace-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--suite-canonical-sha256", required=True)
    parser.add_argument("--as-of-date", type=date.fromisoformat, required=True)
    parser.add_argument("--active-build-id", required=True)
    parser.add_argument("--confirm-real-browser", action="store_true")
    parser.add_argument("--confirm-page-reloaded-while-running", action="store_true")
    parser.add_argument("--confirm-same-job-recovered", action="store_true")
    parser.add_argument("--confirm-progress-resumed", action="store_true")
    parser.add_argument("--confirm-terminal-state-visible", action="store_true")
    parser.add_argument("--confirm-no-indefinite-spinner", action="store_true")
    parser.add_argument("--confirm-exactly-one-release", action="store_true")
    parser.add_argument("--confirm-privacy-passed", action="store_true")
    parser.add_argument("--confirm-loopback-only", action="store_true")
    parser.add_argument("--confirm-zero-online-calls", action="store_true")
    args = parser.parse_args()

    confirmations = BrowserRecoveryConfirmations(
        real_browser=args.confirm_real_browser,
        page_reloaded_while_running=args.confirm_page_reloaded_while_running,
        same_job_recovered_after_reload=args.confirm_same_job_recovered,
        progress_resumed=args.confirm_progress_resumed,
        terminal_state_visible=args.confirm_terminal_state_visible,
        no_indefinite_spinner=args.confirm_no_indefinite_spinner,
        exactly_one_release=args.confirm_exactly_one_release,
        privacy_passed=args.confirm_privacy_passed,
        loopback_only=args.confirm_loopback_only,
        zero_online_calls=args.confirm_zero_online_calls,
    )
    record_browser_recovery_drill(
        first_live_recorder_settings(PROJECT_ROOT),
        job_id=args.job_id,
        trace_id=args.trace_id,
        run_id=args.run_id,
        suite_canonical_sha256=args.suite_canonical_sha256,
        as_of_date=args.as_of_date,
        active_build_id=args.active_build_id,
        confirmations=confirmations,
    )
    # Keep console output portable and free of owner filesystem details.
    print(BROWSER_RECOVERY_RELATIVE_PATH.as_posix())


if __name__ == "__main__":
    main()
