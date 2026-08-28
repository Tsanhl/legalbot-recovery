from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from app.evaluation.live_suite import sealed_sha256
from app.evaluation.v111_integration_verification import (
    CHECK_MATRIX,
    CHECK_MATRIX_SHA256,
    _safe_output_path,
    _semantic_counts,
    _write_create_only_report,
)


def test_fixed_matrix_covers_phase1_without_later_gate_execution() -> None:
    check_ids = {spec.check_id for spec in CHECK_MATRIX}
    assert {
        "integration_records",
        "python_dependency_sync",
        "python_ruff",
        "python_ruff_format",
        "python_mypy_full",
        "python_static_baseline",
        "python_full_suite",
        "immutable_live60_verify",
        "clean_room",
        "workflow_security",
        "workflow_and_artifact_drift",
        "repository_content_scan",
        "web_clean_install",
        "web_lint",
        "web_test",
        "web_build",
        "web_high_severity_audit",
        "repository_diff_check",
    } == check_ids
    command_text = "\n".join(" ".join(spec.argv) for spec in CHECK_MATRIX).casefold()
    assert "stage-a" not in command_text
    assert "stage_a" not in command_text
    assert "all60" not in command_text
    assert "answer" not in command_text
    assert "promotion" not in command_text
    assert " o-04" not in command_text
    assert " active" not in command_text
    assert all(spec.argv and spec.timeout_seconds > 0 for spec in CHECK_MATRIX)
    assert all("--frozen" in spec.argv for spec in CHECK_MATRIX if spec.argv[0] == "uv")


def test_matrix_digest_covers_exact_commands_and_non_authority() -> None:
    expected = sealed_sha256(
        {
            "schema": "legalbot.v111-integration-verification-matrix.v1",
            "checks": [spec.safe_dict(index) for index, spec in enumerate(CHECK_MATRIX, start=1)],
            "retry_count": 0,
            "shell": False,
            "authorizing": False,
        }
    )
    assert expected == CHECK_MATRIX_SHA256


def test_semantic_counts_extract_only_safe_aggregate_results() -> None:
    pytest_counts = _semantic_counts(
        "python_full_suite",
        b"1250 passed, 2 skipped in 10.00s\n",
        b"",
    )
    assert pytest_counts == {"pytest_passed": 1250}
    mypy_counts = _semantic_counts(
        "python_mypy_full",
        b"Success: no issues found in 240 source files\n",
        b"",
    )
    assert mypy_counts == {"mypy_source_files": 240, "mypy_errors": 0}
    audit_counts = _semantic_counts(
        "web_high_severity_audit",
        json.dumps(
            {
                "metadata": {
                    "vulnerabilities": {
                        "low": 0,
                        "moderate": 0,
                        "high": 0,
                        "critical": 0,
                        "total": 0,
                    }
                }
            }
        ).encode(),
        b"",
    )
    assert audit_counts["audit_high"] == 0
    assert audit_counts["audit_critical"] == 0


def test_private_report_path_is_scoped_create_only_and_mode_0600(tmp_path: Path) -> None:
    output = _safe_output_path(tmp_path, "baseline-20260822")
    expected = tmp_path / "data/evaluations/integration-verification/baseline-20260822/report.json"
    assert output == expected
    report = {
        "schema": "legalbot.v111-integration-verification-report.v1",
        "authorizing": False,
        "passed": False,
    }
    _write_create_only_report(output, report)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_bytes()) == report
    with pytest.raises(FileExistsError):
        _write_create_only_report(output, report)
    with pytest.raises(ValueError, match="run ID"):
        _safe_output_path(tmp_path, "../escape")
