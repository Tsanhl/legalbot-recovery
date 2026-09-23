"""Historical retention guards; real local review inputs, no inference in tests."""
from __future__ import annotations

import copy
import sqlite3
from dataclasses import asdict

import pytest
from scripts import ge_auto_superseded_retention as retention


def test_historical_retention_review_is_limited_to_exact_technical_scope():
    gate = retention.HistoricalReviewGate()
    row = gate.reviews[retention.DATES[0]]
    assert retention.scoped_review_eligible(row)
    for changes in (
        {"decision_scope": "CASE_ANSWER"}, {"application_holds": []},
        {"valid_to": "2019-11-10"}, {"as_of_date": "2026-09-05"},
        {"legal_application_decision": "PASS"}, {"full_current_law_eligible": True},
        {"checks": {**row["checks"], "later_treatment": False}},
    ):
        assert not retention.scoped_review_eligible({**row, **changes})


def test_historical_retention_selection_uses_all_original_ordinals_and_rejects_edits():
    gate = retention.HistoricalReviewGate()
    m = gate.materials[retention.DATES[1]]
    recipe = {"ordered_block_ordinals": [b["ordinal"] for b in m["blocks"]],
              "selected_blocks_sha256": retention.digest(m["blocks"])}
    assert retention.reviewed_selection(m["context"], m["full"], recipe) == m["blocks"]
    changed = copy.deepcopy(m["context"])
    changed["groups"]["regulations_1_to_5"][0]["text"] += " synthetic mutation"
    with pytest.raises(retention.visible.ValidationHold, match="TEXT_CHANGED"):
        retention.reviewed_selection(changed, m["full"], recipe)


def test_historical_retention_attestation_change_stops_before_parsing(monkeypatch):
    original = retention.read

    def reject(path, root, expected=None):
        if path.name == "PARENT-REVIEW-BINDING.json":
            assert expected == retention.PARENT_SHA
            raise retention.visible.ValidationHold("FILE_DIGEST")
        return original(path, root, expected)

    monkeypatch.setattr(retention, "read", reject)
    with pytest.raises(retention.visible.ValidationHold, match="FILE_DIGEST"):
        retention.HistoricalReviewGate()


def test_historical_retention_full_preflight_and_derived_receipt_binding(tmp_path, monkeypatch):
    from scripts import ge_auto_research_runtime as runtime

    assert tmp_path.is_relative_to(retention.OUTPUT)

    def no_model(*args, **kwargs):
        raise AssertionError("preflight must not acquire/load a model")

    monkeypatch.setattr(runtime.PinnedEmbeddingSession, "__enter__", no_model)
    gate, identity, policy, units = retention.prepare_run(tmp_path)
    assert len(units) == 2
    assert [len(u["material"]["rows"]) for u in units] == [30, 32]
    for unit in units:
        row = unit["review"]
        assert gate.verify_review(gate.reviewer_id, row)
        assert row["legal_application_decision"] == "HOLD"
        assert len(row["application_holds"]) == 4
        assert retention.digest(asdict(unit["source"].parsed)) != row["binding"]["full_parsed_sha256"]
        assert unit["index"].lineage.as_of_date in retention.DATES
        assert set(row["context_block_ordinals"]) == {
            n for r in unit["material"]["rows"] for n in r["structural_chunk"]["block_ordinals"]}
        assert not gate.verify_review(gate.reviewer_id, {**row, "quote": "synthetic mismatch"})
        assert not gate.verify_review(gate.reviewer_id, {**row, "scope": {**row["scope"], "case_id": "OTHER"}})
        assert not gate.verify_review(gate.reviewer_id, {**row, "valid_to": "2026-09-05"})
        assert unit["index"].status(unit["gap"])["state"] != "CLOSED"


def test_sqlite_generation_object_key_is_distinct_from_internal_generation_hash():
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE objects(digest TEXT,kind TEXT,payload BLOB)")
        generation = {"build_sha256": retention.digest(b"synthetic build"), "synthetic": True}
        generation["generation_sha256"] = retention.digest(generation)
        payload = retention.visible.canonical_json_bytes(generation)
        object_sha = retention.digest(payload)
        assert object_sha != generation["generation_sha256"]
        db.execute("INSERT INTO objects VALUES(?,?,?)", (object_sha, "generation", payload))
        outcomes = [{"build_sha256": generation["build_sha256"], "generation_sha256": generation["generation_sha256"]}]
        counts, found = retention.sqlite_generation_records(db, outcomes)
        assert counts == {"generation": 1}
        assert found[generation["generation_sha256"]]["sqlite_object_sha256"] == object_sha
        with pytest.raises(retention.visible.ValidationHold, match="NOT_RETAINED"):
            retention.sqlite_generation_records(db, [{**outcomes[0], "build_sha256": retention.digest(b"different build")}])
        db.execute("UPDATE objects SET payload=?", (b"synthetic tampered receipt",))
        with pytest.raises(retention.visible.ValidationHold, match="METADATA_READBACK"):
            retention.sqlite_generation_records(db, outcomes)
