"""Synthetic overlay lineage tests; no bank, source or model execution."""
from __future__ import annotations

from types import SimpleNamespace
from copy import deepcopy
from unittest.mock import patch

import pytest

from backend.tests.test_ge_unseen_creation_outcome import Runner
from scripts import ge_unseen_preseal_repair as repair


def setup_lineage():
    r = Runner()
    case = {"case_id": "synthetic:01", "question": "Synthetic unchanged question.", "uploads": []}
    oracle = {"case_id": case["case_id"], "sources": [{"url": "https://official.example/original",
               "currentness_check_urls": []}]}
    review = {"case_id": case["case_id"], "ready": False}
    work = r.PRIVATE / "oracle-repair/shard-01-case-01"
    for stage, value in (("author", {"cases": [case]}), ("oracle", {"oracles": [oracle]}),
                         ("bank-review", {"reviews": [review]})):
        r.write(r.PRIVATE / stage / "shard-01/output.json", value)
    payload = {"parent_shard": "shard-01", "case_number": 1, "cases": [case],
        "original_oracle": oracle, "construction_review": review, "repair_attempt": 1,
        "no_second_repair": True, "question_sha256": r.digest(case["question"]),
        "query_budget": 4, "new_source_capture_budget": 8,
        "evidence": [{"url": "https://official.example/original"}],
        **{key: r.sha(r.PRIVATE/stage/"shard-01/output.json") for key, stage in (
            ("author_output_sha256", "author"), ("oracle_output_sha256", "oracle"),
            ("review_output_sha256", "bank-review"))}}
    r.write(work/"input.json", payload)
    r.write(work/"output.json", {"oracles": [oracle]})
    return r, work, payload, ( [case], {case["case_id"]: oracle}, {case["case_id"]: review})


def test_bound_repair_checks_original_without_mutating_it():
    r, work, _, originals = setup_lineage()
    before = dict(r.files)
    with patch.object(repair, "original_records", return_value=originals):
        repair.validate_lineage(r, work)
    assert r.files == before


@pytest.mark.parametrize("field,value", [("author_output_sha256", "0"*64),
    ("oracle_output_sha256", "0"*64), ("review_output_sha256", "0"*64),
    ("question_sha256", "0"*64), ("query_budget", 5), ("new_source_capture_budget", 9),
    ("repair_attempt", 2), ("no_second_repair", False), ("case_number", True)])
def test_changed_original_or_budget_cannot_receive_lineage_approval(field, value):
    r, work, payload, originals = setup_lineage()
    payload[field] = value
    from backend.tests.test_ge_unseen_creation_outcome import raw
    r.files[work/"input.json"] = raw(payload)
    with patch.object(repair, "original_records", return_value=originals), pytest.raises(RuntimeError):
        repair.validate_lineage(r, work)


def test_currentness_urls_count_toward_new_capture_budget():
    r, work, _, originals = setup_lineage()
    output = r.read(work/"output.json")
    output["oracles"][0]["sources"][0]["currentness_check_urls"] = [f"https://official.example/new-{i}" for i in range(9)]
    from backend.tests.test_ge_unseen_creation_outcome import raw
    r.files[work/"output.json"] = raw(output)
    with patch.object(repair, "original_records", return_value=originals), pytest.raises(RuntimeError, match="budget"):
        repair.validate_lineage(r, work)


def test_invalid_successor_stays_local_hold():
    r = SimpleNamespace(validate_job=lambda _: (_ for _ in ()).throw(ValueError("bad model output")))
    with patch.object(repair, "_complete", return_value=True):
        assert repair._valid_repair(r, object()) is None


def test_changed_oracle_invalidates_old_review_until_fresh_review_exists():
    r = Runner()
    research = r.PRIVATE/"oracle-repair/shard-01-case-01"
    r.write(research/"output.json", {})
    original = [{"case_id": "synthetic:01", "ready": True}, {"case_id": "synthetic:02", "ready": True}]
    with patch.object(repair, "_valid_repair", return_value={"oracles": [{"case_id": "synthetic:01"}]}):
        assert repair.effective_rows(r, "bank-review", original) == original[1:]
    assert original[0]["ready"] is True


def test_invalid_repair_does_not_erase_original_terminal_hold():
    r = Runner()
    r.write(r.PRIVATE/"oracle-repair/shard-01-case-01/output.json", {})
    original = [{"case_id": "synthetic:01", "ready": False}]
    with patch.object(repair, "_valid_repair", return_value=None):
        assert repair.effective_rows(r, "bank-review", original) == original


def schema_failure_fixture():
    from backend.tests.test_ge_unseen_creation_outcome import raw
    from scripts.ge_unseen_fixture_repair import REQUIREMENT_SCHEMA
    r = Runner()
    original = r.PRIVATE / "fixture-inventory/shard-01-case-01"
    old = deepcopy(REQUIREMENT_SCHEMA)
    def remove_types(value):
        if isinstance(value, dict):
            if "const" in value or "enum" in value:
                value.pop("type", None)
            for child in value.values():
                remove_types(child)
        elif isinstance(value, list):
            for child in value:
                remove_types(child)
    remove_types(old)
    for name, value in (("input.json", {"original": True}), ("schema.json", old),
                        ("INVOCATION.json", {}), ("COMPLETION.json", {"returncode": 1, "validated_rows": 0})):
        r.write(original / name, value)
    log = original / "stderr.log"
    r.index(log)
    r.files[log] = b'''"code": "invalid_json_schema"; ('properties', 'schema'); schema must have a 'type' key'''
    def payload(_, name, *, schema_repair=False):
        return {"corrected_context": name} if schema_repair else {"original": True}
    return r, original, payload, raw


def test_schema_correction_is_create_only_idempotent_and_preserves_original_failure():
    r, original, payload, _ = schema_failure_fixture()
    before = {path: data for path, data in r.files.items()}
    with patch.object(repair, "_preseal"), patch.object(repair, "_inventory_input", side_effect=payload):
        assert repair.prepare_fixture_schema_repairs(r) == {"fixture_schema_repairs_prepared": 1}
        assert repair.prepare_fixture_schema_repairs(r) == {"fixture_schema_repairs_prepared": 0}
        work = r.PRIVATE / "fixture-inventory-repair" / original.name
        repair.validate_fixture_schema_repair(r, work)
    assert all(r.files[path] == data for path, data in before.items())


@pytest.mark.parametrize("mutation", ["model_output", "timeout", "changed_schema", "wrong_type"])
def test_schema_retry_cannot_replay_a_model_attempt_or_change_requirements(mutation):
    r, original, payload, raw = schema_failure_fixture()
    if mutation == "model_output":
        r.write(original / "output.json", {})
    elif mutation == "timeout":
        r.files[original / "COMPLETION.json"] = raw({"returncode": 124, "validated_rows": 0})
    elif mutation == "changed_schema":
        schema = r.read(original / "schema.json")
        schema["required"] = []
        r.files[original / "schema.json"] = raw(schema)
    else:
        schema = r.read(original / "schema.json")
        schema["properties"]["schema"]["const"] = False
        r.files[original / "schema.json"] = raw(schema)
    with patch.object(repair, "_preseal"), patch.object(repair, "_inventory_input", side_effect=payload):
        if mutation in ("model_output", "timeout"):
            assert repair.prepare_fixture_schema_repairs(r) == {"fixture_schema_repairs_prepared": 0}
        else:
            with pytest.raises(RuntimeError, match="exceeds"):
                repair.prepare_fixture_schema_repairs(r)
