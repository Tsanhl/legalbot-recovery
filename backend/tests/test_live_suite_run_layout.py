from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet

from app.crypto import LocalCipher
from app.evaluation import live_suite_store as store_module
from app.evaluation.live_suite_store import LiveSuiteRunStore


def test_live_suite_run_store_keeps_e2e_layout_and_case_json_names(
    tmp_path: Path,
) -> None:
    store = LiveSuiteRunStore(tmp_path, LocalCipher(Fernet(Fernet.generate_key())))
    assert store.runs_root == tmp_path.resolve() / "data/evaluations/e2e/runs"
    assert store.runs_root.name == "runs"
    assert "data/evaluations/e2e/runs" in store.runs_root.as_posix()
    required_case = {
        "coverage.json",
        "retrieval.json",
        "evidence-map.json",
        "metrics.json",
        "outcome.json",
    }
    assert required_case <= store_module._SAFE_CASE_JSON_NAMES
    assert "runtime-status.json" in store_module._SAFE_RUN_JSON_NAMES
    assert "review-export.json" in store_module._SAFE_RUN_JSON_NAMES
