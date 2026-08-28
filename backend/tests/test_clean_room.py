from __future__ import annotations

import importlib.util
from pathlib import Path


def test_no_legacy_runtime_dependency() -> None:
    script = Path(__file__).resolve().parents[2] / "scripts" / "check_clean_room.py"
    spec = importlib.util.spec_from_file_location("clean_room", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.check() == []
