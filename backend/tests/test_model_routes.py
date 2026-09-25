from __future__ import annotations

import pytest

from app import model_routes
from app.config import Settings
from app.evaluation.ge_development_chat_authority import route_sha256
from app.model_routes import RoutedModelGateway

QWEN_ROUTE = {
    "route_id": "qwen_local", "kind": "qwen_local", "model_id": "qwen",
    "endpoint": "http://127.0.0.1:8778", "credential_env": None,
}


def _gateway(tmp_path, monkeypatch, route):
    monkeypatch.setattr(model_routes, "load_development_chat_route", lambda settings, route_id: dict(route))
    return RoutedModelGateway(Settings(project_root=tmp_path, test_mode=True))


def test_qwen_route_selects_local_gateway(tmp_path, monkeypatch):
    gateway = _gateway(tmp_path, monkeypatch, QWEN_ROUTE)
    token = gateway.select("qwen_local")
    try:
        assert gateway._current() is gateway.qwen
    finally:
        gateway.reset(token)


@pytest.mark.parametrize("kind", ["hosted_api", "anthropic_api", "gemini_api", "codex_bridge", "local_endpoint"])
def test_removed_route_kinds_are_refused(tmp_path, monkeypatch, kind):
    gateway = _gateway(tmp_path, monkeypatch, {**QWEN_ROUTE, "route_id": kind, "kind": kind})
    with pytest.raises(RuntimeError, match="not_authorised"):
        gateway.select(kind)


def test_connection_with_changed_route_is_refused(tmp_path, monkeypatch):
    gateway = _gateway(tmp_path, monkeypatch, QWEN_ROUTE)

    class Store:
        def get(self, connection_id):
            return {"route_id": "qwen_local", "route_sha256": "0" * 64}

    with pytest.raises(RuntimeError, match="connection_route_changed"):
        gateway.select("qwen_local", connection_id="connection-1", connection_store=Store())


def test_connection_with_frozen_route_selects_qwen(tmp_path, monkeypatch):
    gateway = _gateway(tmp_path, monkeypatch, QWEN_ROUTE)

    class Store:
        def get(self, connection_id):
            return {"route_id": "qwen_local", "route_sha256": route_sha256(QWEN_ROUTE)}

    token = gateway.select("qwen_local", connection_id="connection-1", connection_store=Store())
    gateway.reset(token)
