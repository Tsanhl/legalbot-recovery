from copy import deepcopy

import jsonschema
import pytest

from scripts.ge_response_transport import response_transport_schema
from scripts.ge_unseen_novelty_review import review_schema


def test_transport_omits_undocumented_keyword_but_local_uniqueness_still_rejects_duplicates():
    original = {"type":"array", "items":{"type":"string"}, "uniqueItems":True, "maxItems":3}
    before = deepcopy(original)
    remote = response_transport_schema(original)
    assert original == before
    assert remote == {"type":"array", "items":{"type":"string"}, "maxItems":3}
    assert jsonschema.Draft202012Validator(remote).is_valid(["same", "same"])
    assert not jsonschema.Draft202012Validator(original).is_valid(["same", "same"])


def test_nested_novelty_projection_preserves_every_other_constraint_and_original():
    original = review_schema()
    before = deepcopy(original)
    result = response_transport_schema(original)
    def check(old, new):
        if isinstance(old, dict):
            assert set(new) == set(old) - {"uniqueItems"}
            for key in new:
                check(old[key], new[key])
        elif isinstance(old, list):
            assert len(old) == len(new)
            for a, b in zip(old, new, strict=True):
                check(a, b)
        else:
            assert old == new
    check(original, result)
    assert original == before


@pytest.mark.parametrize("schema", [{"type":"string", "uniqueItems":True}, {"type":"array", "uniqueItems":1}])
def test_invalid_constraint_is_refused(schema):
    with pytest.raises(ValueError):
        response_transport_schema(schema)
