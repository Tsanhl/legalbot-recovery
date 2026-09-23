from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.evaluation.ge_reconstructed_independent_review import (
    EXPECTED_SOURCE_SHA256,
    prepare_campaign,
)


def test_prepare_campaign_writes_exact_disjoint_shards(tmp_path: Path) -> None:
    result = prepare_campaign(output=tmp_path / "review")
    assert result["source_sha256"] == EXPECTED_SOURCE_SHA256
    assert result["rows"] == 330
    assert result["claims"] == 889
    assert result["shard_count"] == 8
    rows = []
    for shard in result["shards"]:
        path = tmp_path / "review" / shard["filename"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == shard["sha256"]
        rows.extend(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines())
    assert len(rows) == 330
    assert len({row["case_id"] for row in rows}) == 330


def test_prepare_campaign_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "review"
    prepare_campaign(output=output)
    with pytest.raises(RuntimeError, match="already exists"):
        prepare_campaign(output=output)
