from __future__ import annotations

import pytest

from app.api.main import app


def test_openapi_loads_for_schemathesis_without_live60_generation() -> None:
    schemathesis = pytest.importorskip("schemathesis")
    schema = app.openapi()
    paths = schema.get("paths", {})
    assert "/api/v1/health" in paths
    assert "/api/v1/admin/live-evaluations" in paths
    joined = " ".join(paths)
    assert "live60-generate" not in joined
    assert "ACTIVE.json" not in joined
    loaded = schemathesis.openapi.from_dict(schema)
    raw = getattr(loaded, "raw_schema", None) or getattr(loaded, "raw", schema)
    assert str(raw.get("openapi", "")).startswith("3.")
