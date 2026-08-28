.PHONY: install start start-check dev api web web-build test lint index-scan model-smoke

install:
	uv sync --all-extras
	cd web && npm ci

start:
	./scripts/start.sh

start-check:
	./scripts/start.sh --check

dev:
	./scripts/dev.sh

api:
	uv run uvicorn app.api:app --app-dir backend --host 127.0.0.1 --port 8776 --reload

web:
	cd web && npm run dev

web-build:
	cd web && npm run build

test:
	uv run pytest
	cd web && npm test

lint:
	uv run ruff check backend scripts
	uv run mypy backend/app
	cd web && npm run lint

index-scan:
	uv run legalbot scan

model-smoke:
	PYTHONPATH=backend uv run --project model-runtime python scripts/model/smoke_runtime.py
