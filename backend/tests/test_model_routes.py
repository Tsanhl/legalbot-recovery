from __future__ import annotations

import json

import httpx
import pytest

from app.config import Settings
from app.model_routes import (
    AnthropicMessagesGateway,
    GeminiGenerateContentGateway,
    LocalEndpointGateway,
    OpenAIResponsesGateway,
)


def test_linked_local_gateway_rejects_identity_substitution(tmp_path):
    gateway = LocalEndpointGateway(Settings(project_root=tmp_path), {
        "endpoint": "http://127.0.0.1:9999", "model_id": "local-model-v1",
    })
    assert gateway._validated_model_version({"model_version": "local-model-v1"}) == "local-model-v1"
    with pytest.raises(RuntimeError, match="identity"):
        gateway._validated_model_version({"model_version": "different-model"})
    gateway = LocalEndpointGateway(Settings(project_root=tmp_path), {
        "endpoint": "http://127.0.0.1:9999", "model_id": "local-model-v1",
        "model_version": "local-model-build-42",
    })
    assert gateway._validated_model_version({"model_version": "local-model-build-42"}) == "local-model-build-42"


@pytest.mark.asyncio
async def test_hosted_route_sends_no_tools_and_requires_exact_model(tmp_path, monkeypatch):
    sent: dict = {}
    gateway = OpenAIResponsesGateway(Settings(project_root=tmp_path), {
        "model_id": "owner-selected-snapshot",
        "endpoint": "https://api.openai.com/v1/responses",
    })
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-test-key")

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, url, *, json, headers):
            sent.update({"url": url, "body": json, "headers": headers})
            return httpx.Response(200, request=httpx.Request("POST", url), json={
                "status": "completed", "model": "owner-selected-snapshot",
                "output": [{"type": "message", "content": [
                    {"type": "output_text", "text": '{"ok":true}'},
                ]}],
                "usage": {"input_tokens": 12, "output_tokens": 4, "total_tokens": 16},
            })

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: FakeClient())
    body = await gateway._generate({"messages": [
        {"role": "system", "content": "Use the guide."},
        {"role": "user", "content": json.dumps({"evidence": ["e1"]})},
    ]})
    assert sent["url"] == "https://api.openai.com/v1/responses"
    assert sent["body"]["store"] is False
    assert sent["body"]["tools"] == []
    assert sent["body"]["background"] is False
    assert body["structured"] == {"ok": True}
    assert gateway._validated_model_version(body) == "openai:owner-selected-snapshot"
    with pytest.raises(RuntimeError, match="identity"):
        gateway._validated_model_version({"model_version": "substituted-model"})


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["anthropic", "gemini"])
async def test_other_hosted_routes_preserve_prompt_and_reject_identity_substitution(tmp_path, monkeypatch, provider):
    sent: dict = {}
    model = "owner-selected-snapshot"
    if provider == "anthropic":
        gateway = AnthropicMessagesGateway(Settings(project_root=tmp_path), {
            "model_id": model, "endpoint": "https://api.anthropic.com/v1/messages",
        })
        monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-test-key")
        result = {"model": model, "stop_reason": "end_turn", "content": [
            {"type": "text", "text": '{"payload":"{\\"ok\\":true}"}'},
        ]}
    else:
        gateway = GeminiGenerateContentGateway(Settings(project_root=tmp_path), {
            "model_id": model, "endpoint": f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        })
        monkeypatch.setenv("GEMINI_API_KEY", "synthetic-test-key")
        result = {"modelVersion": model, "candidates": [{
            "finishReason": "STOP", "content": {"parts": [{"text": '{"ok":true}'}]},
        }]}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, url, *, json, headers):
            sent.update({"url": url, "body": json, "headers": headers})
            return httpx.Response(200, request=httpx.Request("POST", url), json=result)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: FakeClient())
    answer = await gateway._generate({"messages": [
        {"role": "system", "content": "Use selected evidence."},
        {"role": "user", "content": "Question and evidence e1"},
    ]})
    assert answer["structured"] == {"ok": True}
    assert "e1" in answer["transport_projection"]["sent_content"]
    assert "synthetic-test-key" not in answer["transport_projection"]["sent_content"]
    assert gateway._validated_model_version(answer).endswith(model)
    with pytest.raises(RuntimeError, match="identity"):
        gateway._validated_model_version({"model_version": "wrong-model"})
