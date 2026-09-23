"""Small process-local cache for original JSON schemas, never output decisions.

Integration: replace jsonschema.validate(output, original_schema) with
validate(output, original_schema). The optional cls selects the validator just
as in jsonschema.validate; constructor options/transport projection are outside
this helper. Default format handling is unchanged from jsonschema.validate.

Each resident key contains canonical UTF-8 schema bytes, the installed package
version and the actual selected class object. Only successful check_schema and
validator construction are cached. Eviction permits a later schema recheck.
Schemas must be JSON values; serialization never normalizes Unicode or coerces
non-string object keys. Private schema clones and detached validation errors
prevent caller mutations from changing a cached schema. No filesystem/job cache,
model calls, receipt shortcuts or runtime integration occur in this module.
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from functools import lru_cache
from importlib.metadata import version
from threading import RLock

from jsonschema.exceptions import ValidationError
from jsonschema.validators import validator_for

_JSONSCHEMA_VERSION = version("jsonschema")
_CACHE_LOCK = RLock()
_MAX_SCHEMAS = 32


def _canonical(schema):
    def check(value):
        if isinstance(value, dict):
            if any(type(key) is not str for key in value):
                raise TypeError("schema object keys must be strings")
            for child in value.values():
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
        elif type(value) not in (str, int, float, bool, type(None)):
            raise TypeError("schema must contain only JSON values")

    check(schema)
    return json.dumps(schema, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


@dataclass(frozen=True)
class _Compiled:
    validator: object
    lock: object


@lru_cache(maxsize=_MAX_SCHEMAS)
def _compiled(schema_bytes, package_version, cls):
    # Immutable key bytes are the authority; never retain the caller's dict/list.
    schema = json.loads(schema_bytes)
    cls.check_schema(schema)
    return _Compiled(cls(schema), RLock())


def validate(instance, schema, *, cls=None):
    """Validate every instance; propagate schema/output failures without softening.

    A global construction lock prevents duplicate schema checks on concurrent
    misses. Each validator has its own lock so resolver state is not shared
    concurrently. The class and installed library are assumed fixed in process.
    """
    schema_bytes = _canonical(schema)
    selected = cls if cls is not None else validator_for(json.loads(schema_bytes))
    with _CACHE_LOCK:
        compiled = _compiled(schema_bytes, _JSONSCHEMA_VERSION, selected)
    error = None
    with compiled.lock:
        try:
            compiled.validator.validate(instance)
        except ValidationError as exc:
            # Errors expose schema/validator_value, including nested contexts.
            # Detach them too, without modifying the schema or the input output.
            error = deepcopy(exc)
    if error is not None:
        # Raise outside the handler so __context__ does not expose the old error.
        raise error
