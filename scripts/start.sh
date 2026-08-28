#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

app_host="${LEGALBOT_HOST:-127.0.0.1}"
app_port="${LEGALBOT_PORT:-8777}"
model_host="${LEGALBOT_MODEL_HOST:-127.0.0.1}"
model_port="${LEGALBOT_MODEL_PORT:-8778}"
model_mode="${LEGALBOT_MODEL_MODE:-mlx}"
model_path="$project_dir/models/runtime/Qwen3.5-9B-4bit"
web_index="$project_dir/web/dist/index.html"
live_profile="${LEGALBOT_LIVE_PROFILE:-first_live_local_only}"
online_mode="${LEGALBOT_ONLINE_MODE:-local_only}"
official_research_enabled="${LEGALBOT_OFFICIAL_RESEARCH_ENABLED:-false}"

fail() {
  echo "LegalBot-New cannot start: $1" >&2
  exit 2
}

valid_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 ))
}

[[ "$app_host" == "127.0.0.1" ]] || fail "the application must bind to 127.0.0.1"
[[ "$model_host" == "127.0.0.1" ]] || fail "the model runtime must bind to 127.0.0.1"
valid_port "$app_port" || fail "LEGALBOT_PORT must be an integer from 1 to 65535"
valid_port "$model_port" || fail "LEGALBOT_MODEL_PORT must be an integer from 1 to 65535"
[[ "$app_port" == "8777" ]] || fail "first-live requires LEGALBOT_PORT=8777"
[[ "$model_port" == "8778" ]] || fail "first-live requires LEGALBOT_MODEL_PORT=8778"
[[ "$model_mode" == "mlx" ]] || fail "production requires LEGALBOT_MODEL_MODE=mlx"
[[ -z "${LEGALBOT_MODEL_PATH+x}" ]] || fail \
  "LEGALBOT_MODEL_PATH overrides are forbidden for first live"
[[ -z "${LEGALBOT_MODEL_ADAPTER_PATH+x}" ]] || fail \
  "model adapters are forbidden for first live"
[[ -z "${LEGALBOT_ADAPTER_PATH+x}" ]] || fail \
  "model adapters are forbidden for first live"
[[ -z "${LEGALBOT_LORA_PATH+x}" ]] || fail \
  "LoRA weights are forbidden for first live"
[[ "$live_profile" == "first_live_local_only" ]] || fail \
  "the first release supports only LEGALBOT_LIVE_PROFILE=first_live_local_only"
[[ "$online_mode" == "local_only" ]] || fail \
  "the first-live profile requires LEGALBOT_ONLINE_MODE=local_only"
[[ "$official_research_enabled" == "false" ]] || fail \
  "the first-live profile requires LEGALBOT_OFFICIAL_RESEARCH_ENABLED=false"
command -v uv >/dev/null 2>&1 || fail "uv is not installed or is not on PATH"
[[ -f "$web_index" ]] || fail "web/dist is missing; run 'cd web && npm run build'"
[[ -f "$model_path/config.json" ]] || fail "the pinned runtime model config is missing"
[[ -f "$model_path/runtime-model.json" ]] || fail "the pinned runtime provenance file is missing"
compgen -G "$model_path/*.safetensors" >/dev/null || fail "the runtime model has no SafeTensors weights"
model_python="$project_dir/model-runtime/.venv/bin/python"
[[ -f "$model_python" ]] || fail "the verified model-runtime Python is missing"

export LEGALBOT_LIVE_PROFILE="$live_profile"
export LEGALBOT_ONLINE_MODE="$online_mode"
export LEGALBOT_OFFICIAL_RESEARCH_ENABLED="$official_research_enabled"
export LEGALBOT_HOST="$app_host"
export LEGALBOT_PORT="$app_port"
export LEGALBOT_MODEL_HOST="$model_host"
export LEGALBOT_MODEL_PORT="$model_port"
export LEGALBOT_MODEL_URL="http://$model_host:$model_port"

PYTHONPATH="$project_dir/backend" uv run python scripts/runtime_readiness.py \
  preflight --project-root "$project_dir" || fail "runtime dependency preflight failed"

if [[ "${1:-}" == "--check" ]]; then
  echo "LegalBot-New owner-only authority/artifact preflight passed; model start remains separately guarded."
  exit 0
fi
[[ $# -eq 0 ]] || fail "the only supported argument is --check"

model_pid=""
api_pid=""
worker_pid=""

cleanup() {
  trap - EXIT
  set +e
  if [[ -n "$api_pid" ]] && kill -0 "$api_pid" 2>/dev/null; then
    kill -TERM "$api_pid" 2>/dev/null
  fi
  if [[ -n "$worker_pid" ]] && kill -0 "$worker_pid" 2>/dev/null; then
    kill -TERM "$worker_pid" 2>/dev/null
  fi
  if [[ -n "$model_pid" ]] && kill -0 "$model_pid" 2>/dev/null; then
    kill -TERM "$model_pid" 2>/dev/null
  fi
  [[ -n "$api_pid" ]] && wait "$api_pid" 2>/dev/null
  [[ -n "$worker_pid" ]] && wait "$worker_pid" 2>/dev/null
  [[ -n "$model_pid" ]] && wait "$model_pid" 2>/dev/null
}

interrupt() {
  cleanup
  exit 130
}

trap cleanup EXIT
trap interrupt INT TERM

echo "Starting the private model runtime at http://$model_host:$model_port"
uv run python scripts/runtime_readiness.py launch-model \
  --project-root "$project_dir" \
  || fail "owned model-runtime authority is not admitted"
fail "guarded model launcher returned without replacing its process"

echo "Starting LegalBot-New at http://$app_host:$app_port"
LEGALBOT_ENV=production \
LEGALBOT_HOST="$app_host" \
LEGALBOT_PORT="$app_port" \
LEGALBOT_MODEL_URL="http://$model_host:$model_port" \
  uv run uvicorn app.api:app --app-dir backend --host "$app_host" --port "$app_port" &
api_pid=$!

echo "Starting the durable answer worker"
LEGALBOT_ENV=production \
LEGALBOT_MODEL_URL="http://$model_host:$model_port" \
PYTHONPATH="$project_dir/backend" \
  uv run python -m app.cli worker &
worker_pid=$!

PYTHONPATH="$project_dir/backend" uv run python scripts/runtime_readiness.py \
  wait-health --project-root "$project_dir" \
  --base-url "http://$app_host:$app_port" --timeout 60 \
  || fail "model, worker, API, database, and ACTIVE index did not become ready"

echo "LegalBot-New is ready for owner-only normal live at http://$app_host:$app_port"

while kill -0 "$model_pid" 2>/dev/null \
  && kill -0 "$api_pid" 2>/dev/null \
  && kill -0 "$worker_pid" 2>/dev/null; do
  sleep 1
done

if ! kill -0 "$model_pid" 2>/dev/null; then
  wait "$model_pid" || status=$?
  echo "LegalBot-New stopped because the model runtime exited." >&2
elif ! kill -0 "$worker_pid" 2>/dev/null; then
  wait "$worker_pid" || status=$?
  echo "LegalBot-New stopped because the durable worker exited." >&2
else
  wait "$api_pid" || status=$?
  echo "LegalBot-New stopped because the application server exited." >&2
fi
exit "${status:-1}"
