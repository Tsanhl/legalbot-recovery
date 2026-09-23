#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

if [[ "${LEGALBOT_HOST:-127.0.0.1}" != "127.0.0.1" ]]; then
  echo "LegalBot-New v1 is owner-only and must bind to 127.0.0.1" >&2
  exit 2
fi

# Development exercises the selected local-Qwen route. A default stub service
# cannot establish its readiness, and this route does not activate an adapter.
if [[ "${LEGALBOT_MODEL_MODE:-mlx}" != "mlx" ]]; then
  echo "Development requires the selected local Qwen runtime (LEGALBOT_MODEL_MODE=mlx)." >&2
  exit 2
fi
if [[ -n "${LEGALBOT_MODEL_ADAPTER_PATH:-}${LEGALBOT_ADAPTER_PATH:-}${LEGALBOT_LORA_PATH:-}" ]]; then
  echo "The current development route keeps answer adapters inactive." >&2
  exit 2
fi
if [[ -z "${LEGALBOT_DEVELOPMENT_STATE_ID:-}" ]]; then
  echo "Set LEGALBOT_DEVELOPMENT_STATE_ID to a named isolated development store." >&2
  exit 2
fi
export LEGALBOT_MODEL_MODE=mlx
export LEGALBOT_MODEL_EAGER_LOAD=true
export LEGALBOT_ENV=development
export LEGALBOT_LIVE_PROFILE=standard
export LEGALBOT_TEST_MODE=false
if [[ "${LEGALBOT_MODEL_ID:-mlx-community/Qwen3.5-9B-4bit}" != "mlx-community/Qwen3.5-9B-4bit" ]] \
  || [[ "${LEGALBOT_MODEL_REVISION:-8b2b98c00a6b4d291155e4890773ca8f769aee53}" != "8b2b98c00a6b4d291155e4890773ca8f769aee53" ]] \
  || [[ "${LEGALBOT_MODEL_PATH:-$project_dir/models/runtime/Qwen3.5-9B-4bit}" != "$project_dir/models/runtime/Qwen3.5-9B-4bit" ]]; then
  echo "Development requires the pinned Qwen model identity and workspace path." >&2
  exit 2
fi
export LEGALBOT_MODEL_ID=mlx-community/Qwen3.5-9B-4bit
export LEGALBOT_MODEL_REVISION=8b2b98c00a6b4d291155e4890773ca8f769aee53
export LEGALBOT_MODEL_PATH="$project_dir/models/runtime/Qwen3.5-9B-4bit"

model_pid=""
api_pid=""
web_pid=""
worker_pid=""

cleanup() {
  trap - EXIT
  set +e
  for child_pid in "$web_pid" "$worker_pid" "$api_pid" "$model_pid"; do
    if [[ -n "$child_pid" ]] && kill -0 "$child_pid" 2>/dev/null; then
      kill -TERM "$child_pid" 2>/dev/null
    fi
  done
  for child_pid in "$web_pid" "$worker_pid" "$api_pid" "$model_pid"; do
    [[ -n "$child_pid" ]] && wait "$child_pid" 2>/dev/null
  done
}

interrupt() {
  cleanup
  exit 130
}

trap cleanup EXIT
trap interrupt INT TERM

LEGALBOT_MODEL_HOST=127.0.0.1 LEGALBOT_MODEL_PORT=8778 PYTHONPATH=backend \
  uv run --project model-runtime python -m app.model_runtime &
model_pid=$!
LEGALBOT_ENV=development LEGALBOT_HOST=127.0.0.1 LEGALBOT_PORT=8776 \
LEGALBOT_MODEL_URL=http://127.0.0.1:8778 \
  uv run uvicorn app.api:app --app-dir backend --host 127.0.0.1 --port 8776 --reload &
api_pid=$!
LEGALBOT_ENV=development LEGALBOT_MODEL_URL=http://127.0.0.1:8778 PYTHONPATH=backend \
  uv run python -m app.cli worker &
worker_pid=$!
(cd web && npm run dev) &
web_pid=$!

while kill -0 "$model_pid" 2>/dev/null \
  && kill -0 "$api_pid" 2>/dev/null \
  && kill -0 "$worker_pid" 2>/dev/null \
  && kill -0 "$web_pid" 2>/dev/null; do
  sleep 1
done

echo "A LegalBot-New development service exited; stopping the remaining services." >&2
exit 1
