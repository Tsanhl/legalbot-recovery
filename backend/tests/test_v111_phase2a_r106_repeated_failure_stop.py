from __future__ import annotations

import json
import shutil
from pathlib import Path

from scripts import seal_v111_phase2a_r106_repeated_failure_stop as stop


def test_seals_exact_two_failure_stop_append_only(tmp_path: Path) -> None:
    root = tmp_path / "r106"
    shutil.copytree(stop.ROOT, root)
    (root / "DEBUG-STOP.json").unlink(missing_ok=True)
    (root / "SHA256SUMS.txt").unlink(missing_ok=True)

    artifact = stop.seal_stop(root)

    assert artifact["failure_fingerprint"] == stop.EXPECTED_FINGERPRINT
    assert artifact["attempt_count"] == 2
    assert artifact["required_execution_plan_change"]["no_identical_third_attempt"] is True
    assert artifact["phase2b_authorized"] is False
    persisted = json.loads((root / "DEBUG-STOP.json").read_bytes())
    assert persisted == artifact
    assert stop.seal_stop(root) == artifact
