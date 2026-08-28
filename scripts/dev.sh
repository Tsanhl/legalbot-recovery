#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

if [[ "${LEGALBOT_HOST:-127.0.0.1}" != "127.0.0.1" ]]; then
  echo "LegalBot-New v1 is owner-only and must bind to 127.0.0.1" >&2
  exit 2
fi

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
