"""Pure synthetic schemas/outputs; no runner, models, bank data or temp files."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import jsonschema
import pytest
from jsonschema import Draft7Validator, Draft202012Validator
from jsonschema.validators import extend
from scripts import ge_jsonschema_validation as cached


@pytest.fixture(autouse=True)
def empty_cache():
    cached._compiled.cache_clear()
    yield
    cached._compiled.cache_clear()


def observe(monkeypatch, cls=Draft202012Validator):
    calls = {"schema": 0, "output": 0}
    check, validate = cls.check_schema, cls.validate

    def check_schema(schema):
        calls["schema"] += 1
        return check(schema)

    def validate_output(self, instance):
        calls["output"] += 1
        return validate(self, instance)

    monkeypatch.setattr(cls, "check_schema", staticmethod(check_schema))
    monkeypatch.setattr(cls, "validate", validate_output)
    return calls


def test_schema_checked_once_but_same_mutated_output_checked_every_time(monkeypatch):
    calls = observe(monkeypatch)
    schema = {"type": "array", "items": {"type": "string"}, "uniqueItems": True}
    output = ["synthetic"]
    assert cached.validate(output, schema) is None
    assert cached.validate(output, copy.deepcopy(schema)) is None
    output.append("synthetic")
    with pytest.raises(jsonschema.ValidationError, match="non-unique"):
        cached.validate(output, schema)
    assert calls == {"schema": 1, "output": 3}


@pytest.mark.parametrize("schema,valid,invalid", [
    ({"type": "array", "items": {"type": "string"}, "uniqueItems": True}, ["a", "b"], ["a", "a"]),
    ({"type": "array", "minItems": 1, "maxItems": 2}, [1], []),
    ({"type": "array", "maxItems": 2}, [1, 2], [1, 2, 3]),
    ({"type": "array", "items": {"type": "integer"}}, [1], ["1"]),
    ({"type": "string", "minLength": 2, "maxLength": 3}, "ab", "a"),
    ({"type": "string", "maxLength": 3}, "abc", "abcd"),
    ({"type": "string", "pattern": "^[a-f0-9]{4}$"}, "a0ff", "g0ff"),
    ({"type": "number", "minimum": 1, "maximum": 3}, 2, 0),
    ({"type": "number", "maximum": 3}, 3, 4),
    ({"type": "number", "multipleOf": 2}, 4, 3),
    ({"type": "string", "enum": ["PASS", "HOLD"]}, "HOLD", "SKIP"),
    ({"const": {"nested": [True, None]}}, {"nested": [True, None]}, {"nested": [1, None]}),
    ({"anyOf": [{"type": "null"}, {"type": "integer"}]}, None, "unknown"),
    ({"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]}, {"id": 1}, {}),
    ({"type": "object", "properties": {"id": {}}, "additionalProperties": False}, {"id": 1}, {"extra": 1}),
    ({"$defs": {"count": {"type": "integer", "minimum": 1}}, "$ref": "#/$defs/count"}, 1, 0),
])
def test_every_original_constraint_matches_normal_validation(schema, valid, invalid):
    before = copy.deepcopy((schema, valid, invalid))
    jsonschema.validate(valid, schema)
    cached.validate(valid, schema)
    with pytest.raises(jsonschema.ValidationError) as normal:
        jsonschema.validate(invalid, schema)
    with pytest.raises(jsonschema.ValidationError) as actual:
        cached.validate(invalid, schema)
    assert actual.value.validator == normal.value.validator
    assert actual.value.message == normal.value.message
    assert list(actual.value.absolute_path) == list(normal.value.absolute_path)
    assert (schema, valid, invalid) == before


def test_caller_schema_mutation_does_not_change_previous_cached_clone(monkeypatch):
    calls = observe(monkeypatch)
    schema = {"type": "array", "items": {"enum": ["a"]}, "uniqueItems": True}
    original = copy.deepcopy(schema)
    cached.validate(["a"], schema)
    schema["items"]["enum"].append("b")
    schema["uniqueItems"] = False
    cached.validate(["b", "b"], schema)
    with pytest.raises(jsonschema.ValidationError):
        cached.validate(["b"], original)
    with pytest.raises(jsonschema.ValidationError):
        cached.validate(["a", "a"], original)
    assert calls == {"schema": 2, "output": 4}


def test_validation_error_schema_and_nested_context_cannot_mutate_cache():
    schema = {"anyOf": [{"enum": ["a"]}, {"type": "null"}]}
    with pytest.raises(jsonschema.ValidationError) as caught:
        cached.validate("bad", schema)
    assert caught.value.__context__ is None
    caught.value.schema["anyOf"].append({})
    caught.value.context[0].validator_value.append("bad")
    caught.value.context[0].schema.clear()
    with pytest.raises(jsonschema.ValidationError):
        cached.validate("bad", schema)
    assert schema == {"anyOf": [{"enum": ["a"]}, {"type": "null"}]}


def test_key_is_canonical_bytes_not_python_equality_or_input_order(monkeypatch):
    calls = observe(monkeypatch)
    cached.validate(True, {"const": True, "description": "Cafe\u0301"})
    cached.validate(True, {"description": "Cafe\u0301", "const": True})
    cached.validate(1, {"const": 1, "description": "Cafe\u0301"})
    cached.validate(1.0, {"const": 1.0, "description": "Cafe\u0301"})
    cached.validate(True, {"const": True, "description": "Café"})
    assert calls == {"schema": 4, "output": 5}
    assert cached._compiled.cache_info().currsize == 4


def test_installed_version_is_part_of_cache_key(monkeypatch):
    calls = observe(monkeypatch)
    cached.validate(1, {"type": "integer"})
    monkeypatch.setattr(cached, "_JSONSCHEMA_VERSION", "synthetic-other-version")
    cached.validate(1, {"type": "integer"})
    assert calls == {"schema": 2, "output": 2}


def test_dialect_and_explicit_validator_class_selection_are_preserved(monkeypatch):
    calls = observe(monkeypatch, Draft7Validator)
    schema = {"$schema": "http://json-schema.org/draft-07/schema#", "type": "array",
              "items": [{"type": "integer"}], "additionalItems": False}
    cached.validate([1], schema)
    with pytest.raises(jsonschema.ValidationError):
        cached.validate([1, 2], schema)
    with pytest.raises(jsonschema.SchemaError):
        cached.validate([1], schema, cls=Draft202012Validator)
    assert calls == {"schema": 1, "output": 2}


def test_distinct_same_named_validator_classes_do_not_share_entries():
    def deny(validator, value, instance, schema):
        yield jsonschema.ValidationError("synthetic custom constraint")

    first = extend(Draft202012Validator, {})
    second = extend(Draft202012Validator, {"synthetic": deny})
    assert first.__name__ == second.__name__
    schema = {"type": "integer", "synthetic": True}
    cached.validate(1, schema, cls=first)
    with pytest.raises(jsonschema.ValidationError, match="synthetic custom constraint"):
        cached.validate(1, schema, cls=second)
    assert cached._compiled.cache_info().currsize == 2


def test_invalid_schema_never_enters_cache_or_reaches_output_validation(monkeypatch):
    calls = observe(monkeypatch)
    for _ in range(2):
        with pytest.raises(jsonschema.SchemaError):
            cached.validate({}, {"type": "unknown-json-type"})
    assert calls == {"schema": 2, "output": 0}
    assert cached._compiled.cache_info().currsize == 0


@pytest.mark.parametrize("schema", [{"properties": {1: {}}}, {"enum": (1, 2)},
                                   {"const": float("nan")}, {"const": float("inf")}])
def test_non_json_schema_values_are_not_silently_coerced(schema):
    with pytest.raises((TypeError, ValueError)):
        cached.validate(None, schema)
    assert cached._compiled.cache_info().currsize == 0


def test_boolean_schemas_preserve_unconditional_acceptance_and_rejection():
    cached.validate({"anything": [1, None]}, True)
    with pytest.raises(jsonschema.ValidationError):
        cached.validate({"anything": [1, None]}, False)


def test_concurrent_same_schema_miss_checks_schema_once_and_all_outputs(monkeypatch):
    calls = observe(monkeypatch)
    barrier = Barrier(8)
    schema = {"type": "integer", "minimum": 0}

    def run(value):
        barrier.wait(timeout=5)
        try:
            cached.validate(value, schema)
        except jsonschema.ValidationError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(run, range(-4, 4))) == [False] * 4 + [True] * 4
    assert calls == {"schema": 1, "output": 8}


def test_cache_is_bounded_and_evicted_schemas_are_rechecked(monkeypatch):
    calls = observe(monkeypatch)
    for value in range(cached._MAX_SCHEMAS + 1):
        cached.validate(value, {"const": value})
    info = cached._compiled.cache_info()
    assert info.currsize == info.maxsize == cached._MAX_SCHEMAS
    cached.validate(0, {"const": 0})
    assert calls["schema"] == calls["output"] == cached._MAX_SCHEMAS + 2
