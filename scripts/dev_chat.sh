#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

if [[ "${LEGALBOT_HOST:-127.0.0.1}" != "127.0.0.1" ]] \
  || [[ -z "${LEGALBOT_DEVELOPMENT_STATE_ID:-}" ]] \
  || [[ -z "${LEGALBOT_DEVELOPMENT_CANDIDATE_BUILD_ID:-}" ]] \
  || [[ -z "${LEGALBOT_DEVELOPMENT_RETRIEVAL_MANIFEST_SHA256:-}" ]] \
  || [[ -z "${LEGALBOT_DEVELOPMENT_CHAT_AUTHORITY_SHA256:-}" ]]; then
  echo "A loopback host, isolated state, candidate, retrieval manifest and chat authority pins are required." >&2
  exit 2
fi
if [[ -n "${LEGALBOT_MODEL_ADAPTER_PATH:-}${LEGALBOT_ADAPTER_PATH:-}${LEGALBOT_LORA_PATH:-}" ]]; then
  echo "The development chat route keeps answer adapters inactive." >&2
  exit 2
fi
export LEGALBOT_ENV=development
export LEGALBOT_HOST=127.0.0.1
export LEGALBOT_PORT=8776
export LEGALBOT_LIVE_PROFILE=standard
export LEGALBOT_TEST_MODE=false
export LEGALBOT_OFFICIAL_RESEARCH_ENABLED=false
export LEGALBOT_XERJ_ENABLED=false
export LEGALBOT_PHOENIX_ENABLED=false
export LEGALBOT_ONLINE_MODE=local_only
export LEGALBOT_MODEL_URL=http://127.0.0.1:8778
export LEGALBOT_MODEL_ID=mlx-community/Qwen3.5-9B-4bit

PYTHONPATH=backend .venv/bin/python - <<'PY'
import hashlib
import sqlite3
from app.config import Settings
from app.evaluation.ge_development_chat_authority import _load_authority

settings = Settings()
_load_authority(settings)
manifest = settings.development_retrieval_manifest_path
if manifest.is_symlink() or not manifest.is_file() or hashlib.sha256(manifest.read_bytes()).hexdigest() != settings.development_retrieval_manifest_sha256:
    raise SystemExit("reviewed retrieval manifest pin is missing or changed")
with sqlite3.connect(f"file:{settings.database_path}?mode=ro", uri=True) as db:
    row = db.execute("SELECT status FROM index_builds WHERE id=?", (settings.development_candidate_build_id,)).fetchone()
if row is None or row[0] != "candidate":
    raise SystemExit("configured development index is not a non-ACTIVE candidate")
PY

model_pid=""
api_pid=""
worker_pid=""
web_pid=""

cleanup() {
  trap - EXIT
  set +e
  terminate_tree() {
    local parent_pid="$1"
    local child_pid=""
    while IFS= read -r child_pid; do
      [[ -n "$child_pid" ]] && terminate_tree "$child_pid"
    done < <(pgrep -P "$parent_pid" 2>/dev/null)
    kill -TERM "$parent_pid" 2>/dev/null
  }
  for child_pid in "$web_pid" "$worker_pid" "$api_pid" "$model_pid"; do
    [[ -n "$child_pid" ]] && terminate_tree "$child_pid"
  done
  for child_pid in "$web_pid" "$worker_pid" "$api_pid" "$model_pid"; do
    [[ -n "$child_pid" ]] && wait "$child_pid" 2>/dev/null
  done
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

if [[ "${LEGALBOT_START_QWEN:-0}" == "1" ]]; then
  export LEGALBOT_MODEL_MODE=mlx
  export LEGALBOT_MODEL_EAGER_LOAD=true
  export LEGALBOT_MODEL_REVISION=8b2b98c00a6b4d291155e4890773ca8f769aee53
  export LEGALBOT_MODEL_PATH="$project_dir/models/runtime/Qwen3.5-9B-4bit"
  LEGALBOT_MODEL_HOST=127.0.0.1 LEGALBOT_MODEL_PORT=8778 PYTHONPATH=backend \
    uv run --project model-runtime python -m app.model_runtime &
  model_pid=$!
fi

PYTHONPATH=backend .venv/bin/python -m uvicorn app.api:app \
  --host 127.0.0.1 --port 8776 &
api_pid=$!
PYTHONPATH=backend .venv/bin/python -m app.cli worker &
worker_pid=$!
(cd web && npm run dev) &
web_pid=$!

while kill -0 "$api_pid" 2>/dev/null \
  && kill -0 "$worker_pid" 2>/dev/null \
  && kill -0 "$web_pid" 2>/dev/null; do
  if [[ -n "$model_pid" ]] && ! kill -0 "$model_pid" 2>/dev/null; then
    echo "Qwen model service stopped." >&2
    exit 1
  fi
  sleep 1
done
echo "A development chat process stopped; shutting down its owned processes." >&2
exit 1
