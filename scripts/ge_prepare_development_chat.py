#!/usr/bin/env python3
"""Create one expiring owner-local chat capability for a pinned candidate.

Run with the isolated development environment variables already exported.
The access key is printed once and is never written in plaintext to the file.
Restart both API and worker with the printed authority SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.config import Settings  # noqa: E402
from app.evaluation.ge_development_chat_authority import (  # noqa: E402
    GE_DEVELOPMENT_CHAT_SCHEMA,
    _valid_route,
)
from app.evaluation.live_suite import sealed_sha256  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--owner-scope-sha256", required=True)
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--local-url")
    parser.add_argument("--local-model")
    parser.add_argument("--local-version")
    parser.add_argument("--api-model")
    parser.add_argument("--claude-model")
    parser.add_argument("--gemini-model")
    parser.add_argument("--codex-model")
    parser.add_argument("--codex-auth-mode", choices=("dedicated_api_key", "chatgpt_signin"), default="dedicated_api_key")
    args = parser.parse_args()
    settings = Settings()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}", args.run_id):
        parser.error("--run-id has an invalid format")
    if not re.fullmatch(r"[0-9a-f]{64}", args.owner_scope_sha256):
        parser.error("--owner-scope-sha256 must be a SHA-256 digest")
    if (
        settings.development_state_id is None
        or settings.development_candidate_build_id is None
        or settings.development_retrieval_manifest_sha256 is None
        or settings.development_chat_authority_sha256 is not None
    ):
        parser.error("isolated state, non-ACTIVE candidate and pinned retrieval manifest are required")
    if not 1 <= args.hours <= 168:
        parser.error("--hours must be between 1 and 168")
    if (args.local_url is None) != (args.local_model is None):
        parser.error("--local-url and --local-model must be supplied together")
    if args.local_version is not None and args.local_model is None:
        parser.error("--local-version requires --local-model")
    try:
        with sqlite3.connect(f"file:{settings.database_path}?mode=ro", uri=True) as db:
            row = db.execute(
                "SELECT status FROM index_builds WHERE id=?",
                (settings.development_candidate_build_id,),
            ).fetchone()
    except sqlite3.Error as exc:
        parser.error(f"isolated candidate catalogue is unavailable: {exc}")
    if row is None or row[0] != "candidate":
        parser.error("the configured index is not a non-ACTIVE candidate")
    manifest_path = settings.development_retrieval_manifest_path
    if (
        manifest_path.is_symlink() or not manifest_path.is_file()
        or hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        != settings.development_retrieval_manifest_sha256
    ):
        parser.error("the reviewed retrieval manifest does not match its pin")
    routes = [{
        "route_id": "qwen_local", "kind": "qwen_local",
        "model_id": settings.model_id, "endpoint": settings.model_url.rstrip("/"),
        "credential_env": None,
    }]
    if args.local_url is not None:
        routes.append({
            "route_id": "local_endpoint", "kind": "local_endpoint",
            "model_id": args.local_model, "endpoint": args.local_url,
            "credential_env": None,
            **({"model_version": args.local_version} if args.local_version else {}),
        })
    if args.api_model is not None:
        routes.append({
            "route_id": "hosted_api", "kind": "hosted_api",
            "model_id": args.api_model,
            "endpoint": "https://api.openai.com/v1/responses",
            "credential_env": "OPENAI_API_KEY",
        })
    if args.claude_model is not None:
        routes.append({
            "route_id": "anthropic_api", "kind": "anthropic_api",
            "model_id": args.claude_model,
            "endpoint": "https://api.anthropic.com/v1/messages",
            "credential_env": "ANTHROPIC_API_KEY",
        })
    if args.gemini_model is not None:
        routes.append({
            "route_id": "gemini_api", "kind": "gemini_api",
            "model_id": args.gemini_model,
            "endpoint": f"https://generativelanguage.googleapis.com/v1beta/models/{args.gemini_model}:generateContent",
            "credential_env": "GEMINI_API_KEY",
        })
    if args.codex_model is not None:
        routes.append({
            "route_id": "codex_bridge", "kind": "codex_bridge",
            "model_id": args.codex_model, "endpoint": None,
            "credential_env": (
                None if args.codex_auth_mode == "chatgpt_signin"
                else "LEGALBOT_CODEX_BRIDGE_KEY"
            ),
            "auth_mode": args.codex_auth_mode,
        })
    if not all(_valid_route(settings, route) for route in routes):
        parser.error("a configured route has an invalid model identity or endpoint")
    access_key = secrets.token_urlsafe(40)
    now = datetime.now(UTC)
    authority = {
        "schema": GE_DEVELOPMENT_CHAT_SCHEMA,
        "run_id": args.run_id,
        "owner_scope_sha256": args.owner_scope_sha256,
        "development_state_id": settings.development_state_id,
        "candidate_build_id": settings.development_candidate_build_id,
        "retrieval_manifest_sha256": settings.development_retrieval_manifest_sha256,
        "access_key_sha256": hashlib.sha256(access_key.encode()).hexdigest(),
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=args.hours)).isoformat(),
        "routes": routes,
        "writes_active": False,
        "release_allowed": True,
        "release_audience": "owner_evaluation",
    }
    authority["seal_sha256"] = sealed_sha256(authority)
    path = settings.development_chat_authority_path
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        parser.error("chat authority already exists; use a new isolated state to avoid changing in-flight jobs")
    payload = json.dumps(authority, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    with path.open("x", encoding="utf-8") as handle:
        handle.write(payload)
    path.chmod(0o600)
    print(json.dumps({
        "authority_path": str(path),
        "authority_sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "access_key_once": access_key,
        "route_ids": [route["route_id"] for route in routes],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
