from __future__ import annotations

from pathlib import Path

import pytest

from app.config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from app.observability.phoenix_adapter import PhoenixAdapter
from app.observability.xerj_adapter import XerjAdapter

ROOT = Path(__file__).resolve().parents[2]


def test_xerj_and_phoenix_stay_disabled_before_first_live() -> None:
    settings = Settings(xerj_enabled=False, phoenix_enabled=False)
    assert settings.xerj_enabled is False
    assert settings.phoenix_enabled is False
    xerj = XerjAdapter(enabled=False)
    phoenix = PhoenixAdapter(enabled=False)
    assert xerj.status()["enabled"] is False
    assert xerj.status()["merged"] is False
    assert phoenix.status()["enabled"] is False
    assert phoenix.status()["external_telemetry"] is False
    with pytest.raises(RuntimeError, match="not enabled"):
        XerjAdapter(enabled=True)
    with pytest.raises(RuntimeError, match="not enabled"):
        PhoenixAdapter(enabled=True)
    with pytest.raises(RuntimeError, match="disabled"):
        xerj.start()
    with pytest.raises(RuntimeError, match="disabled"):
        phoenix.start()
    with pytest.raises(ValueError, match="disabled before first live"):
        Settings(
            live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE,
            online_default="local_only",
            official_research_enabled=False,
            xerj_enabled=True,
        )
    with pytest.raises(ValueError, match="never both"):
        Settings(xerj_enabled=True, phoenix_enabled=True)
    assert not (ROOT / "crates").exists()
    adapter = (ROOT / "backend" / "app" / "observability" / "xerj_adapter.py").read_text(
        encoding="utf-8"
    )
    assert "from xerj" not in adapter
    assert "import xerj" not in adapter
