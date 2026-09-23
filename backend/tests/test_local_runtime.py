from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from fastapi import HTTPException, Request
from fastapi.responses import FileResponse, ORJSONResponse

from app.api import main as api_main
from app.config import Settings
from app.model_runtime.config import ModelRuntimeConfig


@pytest.mark.asyncio
async def test_spa_routes_and_assets_are_served_from_the_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index = tmp_path / "index.html"
    asset = tmp_path / "assets" / "app.js"
    asset.parent.mkdir()
    index.write_text("<main>LegalBot-New</main>", encoding="utf-8")
    asset.write_text("console.log('local')", encoding="utf-8")
    monkeypatch.setattr(api_main, "WEB_DIST", tmp_path)

    root = await api_main.local_web_application("")
    with pytest.raises(HTTPException) as admin_error:
        await api_main.local_web_application("admin")
    assert admin_error.value.status_code == 404
    javascript = await api_main.local_web_application("assets/app.js")

    assert isinstance(root, FileResponse)
    assert Path(root.path) == index
    assert Path(javascript.path) == asset


@pytest.mark.asyncio
async def test_spa_does_not_escape_build_or_swallow_unknown_api_routes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index = tmp_path / "index.html"
    index.write_text("safe", encoding="utf-8")
    outside = tmp_path.parent / "private.txt"
    outside.write_text("not public", encoding="utf-8")
    monkeypatch.setattr(api_main, "WEB_DIST", tmp_path)

    traversal = await api_main.local_web_application("../private.txt")
    assert Path(traversal.path) == index

    with pytest.raises(HTTPException) as caught:
        await api_main.local_web_application("api/not-a-route")
    assert caught.value.status_code == 404


@pytest.mark.asyncio
async def test_missing_ui_build_has_an_actionable_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(api_main, "WEB_DIST", tmp_path)
    with pytest.raises(HTTPException) as caught:
        await api_main.local_web_application("")
    assert caught.value.status_code == 503
    assert "npm run build" in str(caught.value.detail)


def test_default_port_contract_and_production_launcher() -> None:
    assert Settings().port == 8777
    assert Settings().model_url == "http://127.0.0.1:8778"
    assert ModelRuntimeConfig().port == 8778

    root = Path(__file__).resolve().parents[2]
    launcher = (root / "scripts" / "start.sh").read_text(encoding="utf-8")
    developer = (root / "scripts" / "dev.sh").read_text(encoding="utf-8")
    smoke = (root / "scripts" / "model" / "smoke_runtime.py").read_text(encoding="utf-8")
    assert 'app_port="${LEGALBOT_PORT:-8777}"' in launcher
    assert 'model_port="${LEGALBOT_MODEL_PORT:-8778}"' in launcher
    assert '--port "$app_port"' in launcher
    assert "LEGALBOT_PORT=8776" in developer
    assert "LEGALBOT_MODEL_PORT=8778" in developer
    assert 'default="http://127.0.0.1:8778"' in smoke
    assert "LEGALBOT_OWNER_CONSOLE_ENABLED=false" in launcher


@pytest.mark.asyncio
async def test_public_mode_denies_owner_routes_but_keeps_public_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_settings = Settings(environment="production", owner_console_enabled=False)
    assert public_settings.owner_console_active is False
    monkeypatch.setattr(api_main, "settings", public_settings)

    async def next_response(_request: Request) -> ORJSONResponse:
        return ORJSONResponse({"ok": True})

    for path in ("/admin", "/admin/overview", "/api/v1/admin/overview"):
        request = Request({
            "type": "http", "method": "GET", "path": path,
            "headers": [(b"host", b"testserver")],
            "client": ("testclient", 1234),
            "query_string": b"",
        })
        response = await api_main.owner_only_and_headers(request, next_response)
        assert response.status_code == 404

    request = Request({
        "type": "http", "method": "GET", "path": "/api/v1/health",
        "headers": [(b"host", b"testserver")],
        "client": ("testclient", 1234),
        "query_string": b"",
    })
    response = await api_main.owner_only_and_headers(request, next_response)
    assert response.status_code == 200

    with pytest.raises(HTTPException) as caught:
        await api_main.local_web_application("admin")
    assert caught.value.status_code == 404


@pytest.mark.parametrize("override,message", [
    ({"LEGALBOT_MODEL_MODE": "stub"}, "selected local Qwen"),
    ({"LEGALBOT_MODEL_ADAPTER_PATH": "/unused"}, "adapters inactive"),
    ({"LEGALBOT_MODEL_ID": "different/model"}, "pinned Qwen model"),
    ({"LEGALBOT_DEVELOPMENT_STATE_ID": ""}, "isolated development store"),
])
def test_development_launcher_rejects_wrong_runtime_before_starting_services(override, message):
    root = Path(__file__).resolve().parents[2]
    env = {key: value for key, value in os.environ.items() if not key.startswith("LEGALBOT_")}
    env["LEGALBOT_DEVELOPMENT_STATE_ID"] = "synthetic-check"
    env.update(override)
    result = subprocess.run(["bash", "scripts/dev.sh"], cwd=root, env=env,
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 2
    assert message in result.stderr
