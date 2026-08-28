#!/usr/bin/env python3
"""Smoke-check a running v1 model-runtime service without external packages."""

from __future__ import annotations

import argparse
import json
import urllib.request


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.load(response)


def post_json(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.load(response)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8778")
    parser.add_argument("--expect-backend")
    args = parser.parse_args()

    health = get_json(f"{args.base_url.rstrip('/')}/api/v1/health")
    assert health["api_version"] == "v1"
    assert health["status"] == "ok"
    if args.expect_backend:
        assert health["backend"] == args.expect_backend

    payload = {
        "request_id": "smoke-determinism-v1",
        "mode": "draft",
        "payload": {"prompt": "Reply with the word ready."},
        "messages": [{"role": "user", "content": "Reply with the word ready."}],
        "max_tokens": 16,
        "temperature": 0,
        "top_p": 1,
        "seed": 17,
    }
    first = post_json(f"{args.base_url.rstrip('/')}/api/v1/generate", payload)
    second = post_json(f"{args.base_url.rstrip('/')}/api/v1/generate", payload)
    assert first["api_version"] == "v1"
    assert first["request_id"] == payload["request_id"]
    assert first["raw_text"] == second["raw_text"]
    assert first["deterministic"] is True
    assert first["usage"]["total_tokens"] >= 1
    print(json.dumps({"health": health, "sample": first}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
