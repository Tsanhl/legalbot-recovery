from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
FORBIDDEN = (
    "security find-generic-password",
    "security add-generic-password",
    "live_evaluation_suite.py generate",
    "legalbot live60 generate",
    "huggingface.co",
    "openai.com",
    "ACTIVE.json",
    "PREVIOUS.json",
    "O-04",
)


def test_github_workflows_are_sha_pinned_and_avoid_live60_generation() -> None:
    names = ("ci.yml", "security.yml", "artifact-drift.yml")
    for name in names:
        text = (WORKFLOWS / name).read_text(encoding="utf-8")
        assert "uses: actions/" in text or "uses: astral-sh/" in text
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("uses:"):
                assert "@" in stripped
                pin = stripped.split("@", 1)[1].split()[0]
                assert len(pin) == 40 and all(ch in "0123456789abcdef" for ch in pin), stripped
    command_workflows = (
        (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        + "\n"
        + (WORKFLOWS / "artifact-drift.yml").read_text(encoding="utf-8")
    )
    lowered = command_workflows.lower()
    for token in FORBIDDEN:
        assert token.lower() not in lowered
    assert "keychain" not in lowered
