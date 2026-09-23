"""One bounded repair of a failed 12-slot author batch; no model calls.

The coordinator must serialize these operations with scheduling. Schedule only
planned ``author-parts`` jobs with AUTHOR_PROMPT (no browsing) and AUTHOR_SCHEMA;
dispatch their input lineage here from ``r.validate_job`` and their output scope
to ``r.validate_author_scope``. Dispatch AUTHOR_PART_ASSEMBLY canonical jobs to
``validate_assembly_lineage``. Neither lineage route validates the canonical job
recursively. The runner supplies the same filesystem/contract helpers as the oracle
parts helper, plus DOMAIN_FAMILIES, coverage_slots, author_input, completion_recheckable and
validate_author_scope. No runner import, bank discovery or execution on import.

Only completed non-recheckable failures in legal shards 01-35 are eligible.
Current-valid attempts retain their exact hashes despite historical scope errors;
recheckable attempts still failing current validation remain held without repair.
Pristine, running, system and previously partitioned jobs are left alone. Preparation and
assembly are create-only; interruptions and failed parts never trigger retries.
Receipts stay in the supplied current root; public results contain counts only.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

PART_SIZE = 2
PART_COUNT = 6
SLOT_COUNT = PART_SIZE * PART_COUNT
ASSEMBLY_OPERATION = "Mechanically join validated author parts in frozen canonical slot order."
_SHARD = r"shard-(0[1-9]|[12][0-9]|3[0-5])"


def _exists(r, path):
    r.safe_path(path)
    return path.exists()


def _mkdir(r, path, *, parents=False, exist_ok=False):
    r.safe_path(path)
    path.mkdir(mode=0o700, parents=parents, exist_ok=exist_ok)


def _preseal(r):
    for name in ("BANK-SEAL.json", "ONE-PASS-START.json"):
        if _exists(r, r.PUBLIC / name):
            raise RuntimeError("author parts prohibited after seal/disclosure")


def _canonical(r, work):
    # Reject lexical identity before opening a caller-supplied path.
    if work.parent != r.PRIVATE / "author" or not re.fullmatch(_SHARD, work.name):
        raise RuntimeError("invalid canonical author path")
    r.safe_path(work)


def _works(r):
    root = r.PRIVATE / "author"
    r.safe_path(root)
    for work in sorted(root.glob("shard-*")):
        if work.name == "shard-36":
            continue  # The separate 23-slot system batch is outside this repair.
        _canonical(r, work)
        yield work


def _paths(r, work):
    return [r.PRIVATE / "author-parts" / f"{work.name}-part-{i + 1:02d}"
            for i in range(PART_COUNT)]


def _existing_parts(r, work):
    root = r.PRIVATE / "author-parts"
    r.safe_path(root)
    paths = sorted(root.glob(work.name + "-part-*"))
    for path in paths:
        r.safe_path(path)
    return paths


def _existing_part_receipts(r, work):
    root = r.PRIVATE / "receipts" / "author-parts"
    r.safe_path(root)
    paths = sorted(root.glob(work.name + "-part-*.json"))
    for path in paths:
        r.safe_path(path)
    return paths


def _ids(rows, key):
    if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
        raise RuntimeError("nonempty row list required")
    ids = [row.get(key) for row in rows]
    if any(not isinstance(cid, str) or not cid for cid in ids) or len(set(ids)) != len(ids):
        raise RuntimeError("nonempty unique ids required")
    return ids


def _parent_input(r, work):
    _canonical(r, work)
    payload = r.read(work / "input.json")
    domain = list(r.DOMAIN_FAMILIES)[int(work.name[-2:]) - 1]
    expected = r.author_input([slot for slot in r.coverage_slots() if slot["domain"] == domain])
    if r.digest(payload) != r.digest(expected):
        raise RuntimeError("canonical author assignments/scope contract changed")
    if len(_ids(payload["slots"], "slot_id")) != SLOT_COUNT:
        raise RuntimeError("author repair requires exactly twelve assigned slots")
    if r.digest(r.read(work / "schema.json")) != r.digest(r.AUTHOR_SCHEMA):
        raise RuntimeError("canonical author schema changed")
    return payload


def _archive(r, work):
    return r.PRIVATE / "author-batch-failure-preserved" / work.name


def _inventory(r, directory):
    return {path.relative_to(directory).as_posix(): r.sha(path) for path in r.safe_files(directory)}


def _copy_bytes(r, source, target):
    r.safe_path(source)
    r.safe_path(target)
    with source.open("rb") as incoming, target.open("xb") as outgoing:
        outgoing.write(incoming.read())
    target.chmod(0o600)
    if r.sha(source) != r.sha(target):
        raise RuntimeError("preserved control copy hash mismatch")


def _move_new(r, source, target):
    r.safe_path(source)
    r.safe_path(target)
    if target.exists():
        raise RuntimeError("preservation target already exists")
    source.rename(target)


def _failed(completion):
    if (not isinstance(completion, dict) or type(completion.get("returncode")) is not int
            or "validation_error" not in completion):
        raise RuntimeError("invalid author completion")
    return completion["returncode"] != 0 or completion["validation_error"] is not None


def _protected_inputs(r, work, receipt, *, logical_work):
    invocation = r.read(work / "INVOCATION.json")
    if (receipt.get("work") != logical_work
            or receipt.get("input_sha256") != r.sha(work / "input.json")
            or receipt.get("schema_sha256") != r.sha(work / "schema.json")
            or invocation.get("input_sha256") != receipt["input_sha256"]
            or not isinstance(invocation.get("prompt_sha256"), str)
            or receipt.get("prompt_sha256") != invocation["prompt_sha256"]):
        raise RuntimeError("protected author input/schema/invocation mismatch")
    inventory = receipt.get("input_inventory")
    if not isinstance(inventory, dict) or not {"input.json", "schema.json", "INVOCATION.json"} <= inventory.keys():
        raise RuntimeError("protected author input inventory incomplete")
    for name, expected in inventory.items():
        relative = PurePosixPath(name)
        if (relative.is_absolute() or ".." in relative.parts
                or not relative.parts or relative.as_posix() != name):
            raise RuntimeError("invalid protected inventory path")
        if r.sha(work / name) != expected:
            raise RuntimeError("protected author input inventory mismatch")


def _protected_terminal(r, work, completion, terminal):
    expected = {**completion, "output_sha256": r.sha(work / "output.json")
                if _exists(r, work / "output.json") else None}
    # invoke() uses unsealed receipts; mechanical assembly uses sealed receipts.
    if r.digest(terminal) not in (r.digest(expected), r.digest(r.seal(expected))):
        raise RuntimeError("protected author completion/output mismatch")


def _original_receipts(r, work, source, receipt_root):
    completion = r.read(source / "COMPLETION.json")
    if not _failed(completion):
        raise RuntimeError("preserved author batch is not a failed attempt")
    if completion.get("stage") != "author" or completion.get("shard") != work.name:
        raise RuntimeError("original author completion identity changed")
    receipt = receipt_root / (work.name + ".json")
    terminal = receipt_root / (work.name + "-complete.json")
    # Legacy failed attempts may lack protected receipts. Preserve and verify
    # every receipt that exists; newly dispatched parts require both receipts.
    if _exists(r, receipt):
        _protected_inputs(r, source, r.read(receipt), logical_work=f"author/{work.name}")
    if _exists(r, terminal):
        _protected_terminal(r, source, completion, r.read(terminal))


def _preserve_failure(r, work):
    archive = _archive(r, work)
    receipt_root = r.PRIVATE / "receipts" / "author"
    _original_receipts(r, work, work, receipt_root)
    hashes = {"canonical/" + name: value for name, value in _inventory(r, work).items()}
    receipts = [receipt_root / (work.name + suffix) for suffix in (".json", "-complete.json")]
    present = [path for path in receipts if _exists(r, path)]
    hashes.update({"receipts/author/" + path.name: r.sha(path) for path in present})
    _mkdir(r, archive.parent, parents=True, exist_ok=True)
    _mkdir(r, archive)  # Exclusive reservation; interruptions are never resumed.
    r.write(archive / "HASH-INVENTORY.json", r.seal({"files": hashes}))
    _move_new(r, work, archive / "canonical")
    if present:
        _mkdir(r, archive / "receipts" / "author", parents=True)
    for source in present:
        _move_new(r, source, archive / "receipts" / "author" / source.name)
    actual = _inventory(r, archive)
    actual.pop("HASH-INVENTORY.json")
    if actual != hashes:
        raise RuntimeError("failed batch preservation inventory mismatch")
    r.write(archive / "PRESERVATION-VERIFIED.json", r.seal({
        "inventory_sha256": r.sha(archive / "HASH-INVENTORY.json"),
        "verified_files": len(hashes), "bytes_unchanged": True}))
    _mkdir(r, work)
    for name in ("input.json", "schema.json"):
        _copy_bytes(r, archive / "canonical" / name, work / name)


def _preservation(r, work):
    archive = _archive(r, work)
    inventory = r.read(archive / "HASH-INVENTORY.json")
    actual = _inventory(r, archive)
    actual.pop("HASH-INVENTORY.json", None)
    actual.pop("PRESERVATION-VERIFIED.json", None)
    if r.digest(inventory) != r.digest(r.seal({"files": actual})):
        raise RuntimeError("preserved author inventory changed")
    proof = r.seal({"inventory_sha256": r.sha(archive / "HASH-INVENTORY.json"),
                    "verified_files": len(actual), "bytes_unchanged": True})
    if r.digest(r.read(archive / "PRESERVATION-VERIFIED.json")) != r.digest(proof):
        raise RuntimeError("author preservation proof mismatch")
    for name in ("input.json", "schema.json"):
        if r.sha(work / name) != r.sha(archive / "canonical" / name):
            raise RuntimeError("canonical author controls differ from original bytes")
    _original_receipts(r, work, archive / "canonical", archive / "receipts" / "author")
    return {"preserved_inventory_sha256": r.sha(archive / "HASH-INVENTORY.json"),
            "preservation_verified_sha256": r.sha(archive / "PRESERVATION-VERIFIED.json")}


def _part_input(r, work, payload, index):
    return {**payload, "slots": payload["slots"][index * PART_SIZE:(index + 1) * PART_SIZE],
            "parent_shard": work.name, "parent_input_sha256": r.sha(work / "input.json"),
            "part_index": index, "part_count": PART_COUNT}


def _plan(r, work, payload):
    preservation = _preservation(r, work)
    paths = _paths(r, work)
    if _existing_parts(r, work) != paths:
        raise RuntimeError("missing or extra author parts")
    entries = []
    for index, part in enumerate(paths):
        expected = _part_input(r, work, payload, index)
        if (r.digest(r.read(part / "input.json")) != r.digest(expected)
                or r.sha(part / "schema.json") != r.sha(work / "schema.json")):
            raise RuntimeError("author part is not the exact canonical subset/schema")
        entries.append({"part_shard": part.name, "part_index": index,
                        "slot_ids": _ids(expected["slots"], "slot_id"),
                        "input_sha256": r.sha(part / "input.json"),
                        "schema_sha256": r.sha(part / "schema.json")})
    return r.seal({"kind": "AUTHOR_PARTS_PLAN", "parent_shard": work.name,
                   "parent_input_sha256": r.sha(work / "input.json"),
                   "parent_schema_sha256": r.sha(work / "schema.json"),
                   **preservation, "part_size": PART_SIZE, "part_count": PART_COUNT, "parts": entries})


def _checked_plan(r, work):
    payload = _parent_input(r, work)
    expected = _plan(r, work, payload)
    if r.digest(r.read(work / "PARTS-PLAN.json")) != r.digest(expected):
        raise RuntimeError("author parts plan/hash mismatch")
    return payload, expected


def checked_plan(r, work) -> dict:
    """Read-only verified plan for outcome accounting, even with pending parts.

    Returns part names, ordered slot IDs and hashes, never authored rows. Missing
    or tampered preparation/preservation raises; pending outputs are not an error.
    This helper neither validates outputs nor schedules, resumes or writes jobs.
    """
    _, plan = _checked_plan(r, work)
    return plan


def validate_part_lineage(r, work) -> None:
    """Validate assignments, full scope, raw controls and preserved failed attempt.

    Suitable before dispatch as well as from validate_job; no output is required.
    It never calls validate_job on its canonical parent.
    """
    match = re.fullmatch(f"({_SHARD})-part-(0[1-6])", work.name)
    if work.parent != r.PRIVATE / "author-parts" or match is None:
        raise RuntimeError("invalid author part path")
    r.safe_path(work)
    _checked_plan(r, r.PRIVATE / "author" / match[1])


def prepare_parts(r) -> dict[str, int]:
    """Preserve each eligible failed batch and prepare six exact two-slot jobs once."""
    _preseal(r)
    counts = {"author_shards_partitioned": 0, "author_parts_prepared": 0,
              "author_failed_batches_preserved": 0, "author_shards_skipped": 0,
              "author_recheckable_holds": 0}
    for work in _works(r):
        if (any(_exists(r, work / name) for name in ("PARTS-PLAN.json", "parts", "ASSEMBLY-LINEAGE.json"))
                or _existing_parts(r, work) or _existing_part_receipts(r, work)
                or _exists(r, _archive(r, work))
                or not _exists(r, work / "COMPLETION.json")):
            counts["author_shards_skipped"] += 1
            continue
        completion = r.read(work / "COMPLETION.json")
        historical_failure = _failed(completion)
        if r.completion_recheckable("author", completion):
            # A legacy UKUSScopeError can now pass the corrected scope gate.
            # Current exact-hash validation, not that historical error string,
            # decides validity. A remaining current defect stays held; it does
            # not grant another author attempt under this batch-size repair.
            try:
                r.validate_job(work)
            except Exception:
                counts["author_recheckable_holds"] += 1
            counts["author_shards_skipped"] += 1
            continue
        if not historical_failure:
            counts["author_shards_skipped"] += 1
            continue
        payload = _parent_input(r, work)
        _preserve_failure(r, work)
        counts["author_failed_batches_preserved"] += 1
        _mkdir(r, r.PRIVATE / "author-parts", parents=True, exist_ok=True)
        for index, part in enumerate(_paths(r, work)):
            _mkdir(r, part)
            r.write(part / "input.json", _part_input(r, work, payload, index))
            _copy_bytes(r, work / "schema.json", part / "schema.json")
        r.write(work / "PARTS-PLAN.json", _plan(r, work, payload))
        counts["author_shards_partitioned"] += 1
        counts["author_parts_prepared"] += PART_COUNT
    return counts


def _snapshot(r, part):
    paths = {"input_sha256": part / "input.json", "schema_sha256": part / "schema.json",
             "output_sha256": part / "output.json", "completion_sha256": part / "COMPLETION.json",
             "invocation_sha256": part / "INVOCATION.json",
             "receipt_sha256": r.PRIVATE / "receipts" / "author-parts" / (part.name + ".json"),
             "complete_receipt_sha256": r.PRIVATE / "receipts" / "author-parts" / (part.name + "-complete.json")}
    return {"part_shard": part.name, **{key: r.sha(path) if _exists(r, path) else None
                                      for key, path in paths.items()}}


def _joined(r, work):
    payload, _ = _checked_plan(r, work)
    rows, failed = [], 0
    for part in _paths(r, work):
        try:
            value = r.validate_job(part)
            completion = r.read(part / "COMPLETION.json")
            scope_rechecked = (completion.get("returncode") == 0
                               and completion.get("validation_error") == "UKUSScopeError")
            if (not r.completion_recheckable("author-parts", completion) or completion.get("stage") != "author-parts"
                    or completion.get("shard") != part.name or completion.get("output_present") is not True
                    or type(completion.get("validated_rows")) is not int
                    or completion["validated_rows"] not in ((0, PART_SIZE) if scope_rechecked else (PART_SIZE,))):
                raise RuntimeError("failed author part")
            if r.digest(value) != r.digest(r.read(part / "output.json")):
                raise RuntimeError("validated author differs from raw output")
            slots = r.read(part / "input.json")["slots"]
            if set(value) != {"cases"} or sorted(_ids(value["cases"], "case_id")) != sorted(_ids(slots, "slot_id")):
                raise RuntimeError("author part row coverage mismatch")
            receipt = r.PRIVATE / "receipts" / "author-parts" / (part.name + ".json")
            _protected_inputs(r, part, r.read(receipt), logical_work=f"author-parts/{part.name}")
            _protected_terminal(r, part, completion, r.read(receipt.with_name(part.name + "-complete.json")))
            r.validate_author_scope(value["cases"], slots)
            rows.extend(value["cases"])
        except Exception:
            # Check every completed part, but never publish exception text/rows.
            failed += 1
    if failed:
        raise RuntimeError("author part validation failed")
    expected = _ids(payload["slots"], "slot_id")
    if sorted(_ids(rows, "case_id")) != sorted(expected):
        raise RuntimeError("author assembly row coverage mismatch")
    by_id = {row["case_id"]: row for row in rows}
    output = {"cases": [by_id[cid] for cid in expected]}
    r.validate_author_scope(output["cases"], payload["slots"])
    return output


def _lineage(r, work, success):
    return r.seal({"kind": "AUTHOR_PART_ASSEMBLY", "status": "VALIDATED" if success else "FAILED",
                   "parent_shard": work.name, "input_sha256": r.sha(work / "input.json"),
                   "schema_sha256": r.sha(work / "schema.json"),
                   "plan_sha256": r.sha(work / "PARTS-PLAN.json"),
                   "parts": [_snapshot(r, part) for part in _paths(r, work)]})


def _invocation(r, work):
    return {"kind": "AUTHOR_PART_ASSEMBLY", "model": "NONE_MECHANICAL_ASSEMBLY",
            "provider": None, "fresh_context": False, "browse": False,
            "input_sha256": r.sha(work / "input.json"),
            "prompt_sha256": r.digest(ASSEMBLY_OPERATION)}


def _receipt(r, work):
    names = ("input.json", "schema.json", "PARTS-PLAN.json", "INVOCATION.json", "ASSEMBLY-LINEAGE.json")
    return r.seal({"input_sha256": r.sha(work / "input.json"),
                   "schema_sha256": r.sha(work / "schema.json"),
                   "prompt_sha256": r.digest(ASSEMBLY_OPERATION),
                   "work": work.relative_to(r.PRIVATE).as_posix(),
                   "input_inventory": {name: r.sha(work / name) for name in names}})


def _completion(work, success):
    return {"stage": "author", "shard": work.name, "returncode": 0 if success else 1,
            "output_present": success, "validated_rows": SLOT_COUNT if success else 0,
            "validation_error": None if success else "AUTHOR_PART_ASSEMBLY_FAILED"}


def assemble_parts(r) -> dict[str, int]:
    """Wait for all six completions, then publish one success or terminal failure."""
    _preseal(r)
    counts = {"author_shards_assembled": 0, "author_assembly_failures": 0,
              "author_shards_waiting": 0, "author_assembly_skipped": 0}
    for work in _works(r):
        if not _exists(r, work / "PARTS-PLAN.json"):
            continue
        receipt = r.PRIVATE / "receipts" / "author" / (work.name + ".json")
        terminal = receipt.with_name(work.name + "-complete.json")
        if (any(_exists(r, work / name) for name in
                ("INVOCATION.json", "COMPLETION.json", "output.json", "ASSEMBLY-LINEAGE.json"))
                or _exists(r, receipt) or _exists(r, terminal)):
            counts["author_assembly_skipped"] += 1
            continue
        try:
            _checked_plan(r, work)
            if not all(_exists(r, part / "COMPLETION.json") for part in _paths(r, work)):
                counts["author_shards_waiting"] += 1
                continue
            output = _joined(r, work)
        except Exception:
            output = None
        success = output is not None
        # Exclusive mechanical reservation. It is not a second author invocation.
        r.write(work / "INVOCATION.json", _invocation(r, work))
        r.write(work / "ASSEMBLY-LINEAGE.json", _lineage(r, work, success))
        r.write(receipt, _receipt(r, work))
        if success:
            r.write(work / "output.json", output)
        completion = _completion(work, success)
        r.write(terminal, r.seal({**completion, "output_sha256": r.sha(work / "output.json") if success else None}))
        r.write(work / "COMPLETION.json", completion)  # Publish last.
        counts["author_shards_assembled" if success else "author_assembly_failures"] += 1
    return counts


def validate_assembly_lineage(r, work) -> None:
    """Recompute exact ordered rows, preservation inventory and protected receipts."""
    _canonical(r, work)
    output = _joined(r, work)
    expected = {"output.json": output, "ASSEMBLY-LINEAGE.json": _lineage(r, work, True),
                "INVOCATION.json": _invocation(r, work), "COMPLETION.json": _completion(work, True)}
    for name, value in expected.items():
        if r.digest(r.read(work / name)) != r.digest(value):
            raise RuntimeError("author assembly content/lineage mismatch")
    receipt = r.PRIVATE / "receipts" / "author" / (work.name + ".json")
    if r.digest(r.read(receipt)) != r.digest(_receipt(r, work)):
        raise RuntimeError("author assembly protected input receipt mismatch")
    terminal = r.seal({**_completion(work, True), "output_sha256": r.sha(work / "output.json")})
    if r.digest(r.read(receipt.with_name(work.name + "-complete.json"))) != r.digest(terminal):
        raise RuntimeError("author assembly protected output receipt mismatch")
