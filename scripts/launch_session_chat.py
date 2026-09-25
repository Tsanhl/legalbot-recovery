"""Launch the real session chat API/worker with a fresh non-ACTIVE candidate.

The initial index remains explicitly scoped to its reviewed jurisdiction/date.
This launcher neither marks missing legal sources reviewed nor writes ACTIVE.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--start-qwen", action="store_true")
    parser.add_argument(
        "--retrieval-manifest",
        type=Path,
        help="Existing reviewed development retrieval manifest; never an ACTIVE build",
    )
    args = parser.parse_args()
    if not __import__("re").fullmatch(r"shared-chat-[a-z0-9-]{3,40}", args.state):
        raise ValueError("Use a fresh shared-chat- state ID")
    run = ROOT / "data/development-runtime" / args.state
    if run.exists():
        raise RuntimeError("State already exists; preserve its attempts and use a new state")
    manifest = (
        args.retrieval_manifest
        or ROOT
        / "data/development-runtime/ge-dev-chat-20260923-r8/GE-QWEN-DEVELOPMENT-RETRIEVAL.json"
    )
    if not manifest.is_file():
        parser.error(
            "A reviewed local retrieval manifest is required. Pass --retrieval-manifest; cloning the public repository does not install private source/index evidence."
        )
    previous = json.loads(manifest.read_bytes())
    py = str(ROOT / ".venv/bin/python")
    candidate = args.state + "-index"
    command = [
        py,
        "-m",
        "scripts.ge_qwen_prepare_development_retrieval",
        "--state-id",
        args.state,
        "--candidate-build-id",
        candidate,
        "--subject",
        previous["subject"],
    ]
    for key in ("generation", "prepared_build", "complete_context"):
        command += ["--" + key.replace("_", "-"), previous[key]["path"]]
    for row in previous["retrievals"]:
        command += ["--retrieval", row["path"]]
    for row in previous["sources"]:
        command += [
            "--source",
            "|".join(
                row[k]
                for k in (
                    "capture_sha256",
                    "source_sha256",
                    "source_identity_id",
                    "title",
                    "canonical_url",
                    "source_type",
                )
            ),
        ]
    prepared = json.loads(subprocess.check_output(command, cwd=ROOT, text=True))
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT / "backend") + ":" + str(ROOT),
        "LEGALBOT_ENV": "development",
        "LEGALBOT_HOST": "127.0.0.1",
        "LEGALBOT_PORT": "8776",
        "LEGALBOT_LIVE_PROFILE": "standard",
        "LEGALBOT_TEST_MODE": "false",
        "LEGALBOT_OWNER_CONSOLE_ENABLED": "false",
        "LEGALBOT_OFFICIAL_RESEARCH_ENABLED": "true",
        "LEGALBOT_ONLINE_MODE": "auto",
        "LEGALBOT_XERJ_ENABLED": "false",
        "LEGALBOT_PHOENIX_ENABLED": "false",
        "LEGALBOT_DEVELOPMENT_STATE_ID": args.state,
        "LEGALBOT_DEVELOPMENT_CANDIDATE_BUILD_ID": candidate,
        "LEGALBOT_DEVELOPMENT_RETRIEVAL_MANIFEST_SHA256": prepared["manifest_sha256"],
        "LEGALBOT_START_QWEN": "1" if args.start_qwen else "0",
        "LEGALBOT_RESEARCH_MODE": "true",
    }
    env.pop("LEGALBOT_DEVELOPMENT_CHAT_AUTHORITY_SHA256", None)
    scope = "Owner approved shared chat implementation: session connections, encrypted conversations, indexed and reviewed online sources, local Qwen only (hosted-API and Codex routes removed 2026-09-25), private diagnostics. No ACTIVE or public live promotion.\n"
    (run / "OWNER-SCOPE.md").write_text(scope)
    authority = json.loads(
        subprocess.check_output(
            [
                py,
                "scripts/ge_prepare_development_chat.py",
                "--run-id",
                args.state,
                "--session-ui",
                "--owner-scope-sha256",
                hashlib.sha256(scope.encode()).hexdigest(),
                "--hours",
                "24",
            ],
            cwd=ROOT,
            env=env,
            text=True,
        )
    )
    env["LEGALBOT_DEVELOPMENT_CHAT_AUTHORITY_SHA256"] = authority["authority_sha256"]
    safe = {
        k: v
        for k, v in env.items()
        if k.startswith("LEGALBOT_")
        and k != "LEGALBOT_OWNER_IDENTIFIERS"
    }
    # Explicit list avoids copying unrelated environment secrets into receipts.
    allowed = (
        "LEGALBOT_ENV",
        "LEGALBOT_HOST",
        "LEGALBOT_PORT",
        "LEGALBOT_LIVE_PROFILE",
        "LEGALBOT_TEST_MODE",
        "LEGALBOT_OWNER_CONSOLE_ENABLED",
        "LEGALBOT_OFFICIAL_RESEARCH_ENABLED",
        "LEGALBOT_ONLINE_MODE",
        "LEGALBOT_XERJ_ENABLED",
        "LEGALBOT_PHOENIX_ENABLED",
        "LEGALBOT_DEVELOPMENT_STATE_ID",
        "LEGALBOT_DEVELOPMENT_CANDIDATE_BUILD_ID",
        "LEGALBOT_DEVELOPMENT_RETRIEVAL_MANIFEST_SHA256",
        "LEGALBOT_START_QWEN",
        "LEGALBOT_RESEARCH_MODE",
        "LEGALBOT_DEVELOPMENT_CHAT_AUTHORITY_SHA256",
    )
    (run / "LAUNCH-CONFIG.json").write_text(
        json.dumps({k: safe[k] for k in allowed}, indent=2) + "\n"
    )
    print(
        json.dumps(
            {
                "state": args.state,
                "url": "http://127.0.0.1:8777/",
                "index_scope": {
                    "jurisdiction": previous["jurisdiction"],
                    "date": previous["as_of_date"],
                },
                "active_written": False,
            }
        ),
        flush=True,
    )
    os.chdir(ROOT)
    os.execve("/bin/bash", ["bash", "scripts/dev_chat.sh"], env)


if __name__ == "__main__":
    main()
