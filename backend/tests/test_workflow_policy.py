from __future__ import annotations

from pathlib import Path

from scripts.security.check_workflow_policy import (
    executable_run_scripts,
    scan_workflow_dir,
    scan_workflow_text,
)

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def test_checked_in_workflows_have_no_forbidden_executable_tokens() -> None:
    assert scan_workflow_dir(WORKFLOWS) == []


def test_scanner_detects_prohibited_live_command_in_run_step(tmp_path: Path) -> None:
    path = tmp_path / "bad.yml"
    path.write_text(
        "\n".join(
            [
                "name: Bad",
                "jobs:",
                "  live:",
                "    steps:",
                "      - name: Forbidden generation",
                "        run: legalbot live60 generate --suite live-evaluation-60-v1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    hits = scan_workflow_dir(tmp_path)
    assert hits
    assert any("legalbot live60 generate" in item for item in hits)


def test_scanner_ignores_token_only_in_comment_or_name(tmp_path: Path) -> None:
    path = tmp_path / "comment.yml"
    path.write_text(
        "\n".join(
            [
                "name: Comment only",
                "# legalbot live60 generate ACTIVE.json PREVIOUS.json O-04 start.sh",
                "jobs:",
                "  check:",
                "    steps:",
                "      - name: legalbot live60 generate reminder",
                "        run: python3 scripts/security/check_workflow_policy.py",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert scan_workflow_dir(tmp_path) == []


def test_executable_run_scripts_collect_block_scalars() -> None:
    text = "\n".join(
        [
            "jobs:",
            "  verify:",
            "    steps:",
            "      - name: Block",
            "        run: |",
            "          echo hello",
            "          legalbot promote candidate-1",
            "      - name: Scalar",
            "        run: uv run pytest",
        ]
    )
    scripts = executable_run_scripts(text)
    assert any("legalbot promote" in script for script in scripts)
    assert scan_workflow_text(text) == ["legalbot promote"]
