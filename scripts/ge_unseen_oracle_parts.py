"""Bounded oracle work for the existing runner; no model calls or bank discovery.

The coordinator must serialize preparation/assembly with scheduling. Schedule only
planned ``oracle-parts`` jobs, and dispatch their lineage check here from
``r.validate_job``. Dispatch assembled canonical oracle lineage here too. Neither
lineage route calls ``validate_job`` on the canonical oracle (no recursion).
Interrupted writes are retained and never automatically retried. Return values
contain counts only; every receipt stays within the runner's current private root.
"""
from __future__ import annotations

import re

PART_SIZE = 2
ASSEMBLY_OPERATION = "Mechanically join validated oracle parts in frozen canonical case order."


def _exists(r, path) -> bool:
    r.safe_path(path)
    return path.exists()


def _mkdir(r, path, *, parents=False, exist_ok=False) -> None:
    r.safe_path(path)
    path.mkdir(mode=0o700, parents=parents, exist_ok=exist_ok)


def _preseal(r) -> None:
    for name in ("BANK-SEAL.json", "ONE-PASS-START.json"):
        if _exists(r, r.PUBLIC / name):
            raise RuntimeError("oracle parts prohibited after seal/disclosure")


def _canonical(r, work) -> None:
    # Validate the lexical identity before any caller-supplied path is opened.
    if (work.parent != r.PRIVATE / "oracle"
            or not re.fullmatch(r"shard-(0[1-9]|[12][0-9]|3[0-6])", work.name)):
        raise RuntimeError("invalid canonical oracle path")
    r.safe_path(work)


def _works(r):
    root = r.PRIVATE / "oracle"
    r.safe_path(root)
    for work in sorted(root.glob("shard-*")):
        _canonical(r, work)
        yield work


def _part_paths(r, work, count):
    return [r.PRIVATE / "oracle-parts" / f"{work.name}-part-{i + 1:02d}"
            for i in range(count)]


def _existing_parts(r, work):
    root = r.PRIVATE / "oracle-parts"
    r.safe_path(root)
    paths = sorted(root.glob(work.name + "-part-*"))
    for path in paths:
        r.safe_path(path)
    return paths


def _ids(cases):
    ids = [case["case_id"] for case in cases]
    if not ids or any(not isinstance(cid, str) or not cid for cid in ids) or len(set(ids)) != len(ids):
        raise RuntimeError("nonempty unique case ids required")
    return ids


def _parent_input(r, work):
    _canonical(r, work)
    payload = r.read(work / "input.json")
    if set(payload) != {"as_of", "cases", "scenario_frozen_sha256"}:
        raise RuntimeError("canonical oracle input fields changed")
    _ids(payload["cases"])
    if r.digest(r.read(work / "schema.json")) != r.digest(r.ORACLE_SCHEMA):
        raise RuntimeError("canonical oracle schema changed")
    author = r.PRIVATE / "author" / work.name
    original = r.validate_job(author)["cases"]
    if payload["scenario_frozen_sha256"] != r.sha(author / "output.json"):
        raise RuntimeError("canonical author raw hash mismatch")
    assigned = {slot["slot_id"]: slot for slot in r.read(author / "input.json")["slots"]}
    reconstructed = [{**case, "family": assigned[case["case_id"]]["family"],
                      "domain": assigned[case["case_id"]]["domain"]} for case in original]
    if r.digest(payload["cases"]) != r.digest(reconstructed):
        raise RuntimeError("canonical oracle changed authored scenarios")
    return payload


def _part_input(r, work, payload, index, count):
    return {**payload, "cases": payload["cases"][index * PART_SIZE:(index + 1) * PART_SIZE],
            "parent_shard": work.name, "parent_input_sha256": r.sha(work / "input.json"),
            "part_index": index, "part_count": count}


def _plan(r, work, payload):
    count = (len(payload["cases"]) + PART_SIZE - 1) // PART_SIZE
    paths = _part_paths(r, work, count)
    if _existing_parts(r, work) != paths:
        raise RuntimeError("missing or extra oracle parts")
    entries = []
    for index, part in enumerate(paths):
        expected = _part_input(r, work, payload, index, count)
        if (r.digest(r.read(part / "input.json")) != r.digest(expected)
                or r.digest(r.read(part / "schema.json")) != r.digest(r.ORACLE_SCHEMA)):
            raise RuntimeError("part is not the exact canonical subset/schema")
        entries.append({"part_shard": part.name, "part_index": index,
                        "case_ids": _ids(expected["cases"]),
                        "input_sha256": r.sha(part / "input.json"),
                        "schema_sha256": r.sha(part / "schema.json")})
    return r.seal({"kind": "ORACLE_PARTS_PLAN", "parent_shard": work.name,
                   "parent_input_sha256": r.sha(work / "input.json"),
                   "parent_schema_sha256": r.sha(work / "schema.json"),
                   "scenario_frozen_sha256": payload["scenario_frozen_sha256"],
                   "part_size": PART_SIZE, "part_count": count, "parts": entries})


def _checked_plan(r, work):
    payload = _parent_input(r, work)
    expected = _plan(r, work, payload)
    if r.digest(r.read(work / "PARTS-PLAN.json")) != r.digest(expected):
        raise RuntimeError("oracle parts plan/hash mismatch")
    return payload, expected


def validate_part_lineage(r, work) -> None:
    """Check exact subset, raw hashes, schema, plan and independently checked author."""
    match = re.fullmatch(r"(shard-(?:0[1-9]|[12][0-9]|3[0-6]))-part-(\d{2})", work.name)
    if work.parent != r.PRIVATE / "oracle-parts" or match is None:
        raise RuntimeError("invalid oracle part path")
    r.safe_path(work)
    parent = r.PRIVATE / "oracle" / match[1]
    _, plan = _checked_plan(r, parent)
    if work.name not in {entry["part_shard"] for entry in plan["parts"]}:
        raise RuntimeError("unplanned oracle part")


def _inventory(r, directory):
    return {path.relative_to(directory).as_posix(): r.sha(path)
            for path in r.safe_files(directory)}


def _copy_bytes(r, source, target):
    # Re-serializing JSON would change the frozen raw input/schema hashes.
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


def _preserve_failure(r, work):
    """Move the entire failed job and both available protected receipts, byte intact."""
    archive = r.PRIVATE / "oracle-batch-failure-preserved" / work.name
    hashes = {"canonical/" + name: value for name, value in _inventory(r, work).items()}
    receipts = [r.PRIVATE / "receipts" / "oracle" / (work.name + suffix)
                for suffix in (".json", "-complete.json")]
    present = [path for path in receipts if _exists(r, path)]
    for path in present:
        hashes["receipts/oracle/" + path.name] = r.sha(path)
    _mkdir(r, archive.parent, parents=True, exist_ok=True)
    _mkdir(r, archive)  # Exclusive reservation; interrupted preservation cannot retry.
    r.write(archive / "HASH-INVENTORY.json", r.seal({"files": hashes}))
    _move_new(r, work, archive / "canonical")
    if present:
        _mkdir(r, archive / "receipts" / "oracle", parents=True)
    for source in present:
        _move_new(r, source, archive / "receipts" / "oracle" / source.name)
    actual = {"canonical/" + name: value
              for name, value in _inventory(r, archive / "canonical").items()}
    if present:
        actual.update({"receipts/oracle/" + name: value
                       for name, value in _inventory(r, archive / "receipts" / "oracle").items()})
    if actual != hashes:
        raise RuntimeError("failed batch preservation inventory mismatch")
    r.write(archive / "PRESERVATION-VERIFIED.json", r.seal({
        "inventory_sha256": r.sha(archive / "HASH-INVENTORY.json"),
        "verified_files": len(hashes), "bytes_unchanged": True}))
    _mkdir(r, work)
    for name in ("input.json", "schema.json"):
        _copy_bytes(r, archive / "canonical" / name, work / name)


def prepare_parts(r) -> dict[str, int]:
    """Split eligible canonical jobs once; never resume orphan parts or old failures."""
    _preseal(r)
    counts = {"oracle_shards_partitioned": 0, "oracle_parts_prepared": 0,
              "oracle_failed_batches_preserved": 0, "oracle_shards_skipped": 0}
    for work in _works(r):
        archive = r.PRIVATE / "oracle-batch-failure-preserved" / work.name
        if (_exists(r, work / "PARTS-PLAN.json") or _exists(r, work / "parts")
                or _exists(r, work / "ASSEMBLY-LINEAGE.json") or _existing_parts(r, work)
                or _exists(r, archive)):
            counts["oracle_shards_skipped"] += 1
            continue
        completed = _exists(r, work / "COMPLETION.json")
        if completed:
            completion = r.read(work / "COMPLETION.json")
            failed = completion["returncode"] != 0 or completion.get("validation_error") is not None
            if not failed:
                counts["oracle_shards_skipped"] += 1
                continue
        elif (_exists(r, work / "INVOCATION.json")
              or set(_inventory(r, work)) != {"input.json", "schema.json"}
              or any(_exists(r, r.PRIVATE / "receipts" / "oracle" / (work.name + suffix))
                     for suffix in (".json", "-complete.json"))):
            counts["oracle_shards_skipped"] += 1
            continue
        payload = _parent_input(r, work)
        if completed:
            _preserve_failure(r, work)
            counts["oracle_failed_batches_preserved"] += 1
        count = (len(payload["cases"]) + PART_SIZE - 1) // PART_SIZE
        root = r.PRIVATE / "oracle-parts"
        _mkdir(r, root, parents=True, exist_ok=True)
        for index, part in enumerate(_part_paths(r, work, count)):
            _mkdir(r, part)
            r.write(part / "input.json", _part_input(r, work, payload, index, count))
            r.write(part / "schema.json", r.ORACLE_SCHEMA)
        r.write(work / "PARTS-PLAN.json", _plan(r, work, payload))
        counts["oracle_shards_partitioned"] += 1
        counts["oracle_parts_prepared"] += count
    return counts


def _snapshot(r, part):
    paths = {"input_sha256": part / "input.json", "schema_sha256": part / "schema.json",
             "output_sha256": part / "output.json", "completion_sha256": part / "COMPLETION.json",
             "invocation_sha256": part / "INVOCATION.json",
             "receipt_sha256": r.PRIVATE / "receipts" / "oracle-parts" / (part.name + ".json"),
             "complete_receipt_sha256": r.PRIVATE / "receipts" / "oracle-parts" / (part.name + "-complete.json")}
    return {"part_shard": part.name, **{key: r.sha(path) if _exists(r, path) else None
                                      for key, path in paths.items()}}


def _joined(r, work):
    payload, plan = _checked_plan(r, work)
    rows, failed = [], 0
    for part in _part_paths(r, work, plan["part_count"]):
        try:
            value = r.validate_job(part)
            completion = r.read(part / "COMPLETION.json")
            if completion["returncode"] != 0 or completion.get("validation_error") is not None:
                raise RuntimeError("failed oracle part")
            if value != r.read(part / "output.json"):
                raise RuntimeError("validated oracle differs from raw output")
            expected = _ids(r.read(part / "input.json")["cases"])
            if set(value) != {"oracles"} or sorted(_ids(value["oracles"])) != sorted(expected):
                raise RuntimeError("part row coverage mismatch")
            rows.extend(value["oracles"])
        except Exception:
            # Validate every completed part. Never include exception text or rows
            # in a terminal failure, even if a validator quotes private material.
            failed += 1
    if failed:
        raise RuntimeError("oracle part validation failed")
    expected = _ids(payload["cases"])
    if sorted(_ids(rows)) != sorted(expected):
        raise RuntimeError("assembly row coverage mismatch")
    by_id = {row["case_id"]: row for row in rows}
    return {"oracles": [by_id[cid] for cid in expected]}


def _lineage(r, work, paths, success):
    return r.seal({"kind": "ORACLE_PART_ASSEMBLY", "status": "VALIDATED" if success else "FAILED",
                   "parent_shard": work.name, "input_sha256": r.sha(work / "input.json"),
                   "schema_sha256": r.sha(work / "schema.json"),
                   "plan_sha256": r.sha(work / "PARTS-PLAN.json"),
                   "parts": [_snapshot(r, part) for part in paths]})


def _invocation(r, work):
    return {"kind": "ORACLE_PART_ASSEMBLY", "model": "NONE_MECHANICAL_ASSEMBLY",
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


def _completion(work, rows, success):
    return {"stage": "oracle", "shard": work.name, "returncode": 0 if success else 1,
            "output_present": success, "validated_rows": rows if success else 0,
            "validation_error": None if success else "ORACLE_PART_ASSEMBLY_FAILED"}


def assemble_parts(r) -> dict[str, int]:
    """Wait for all parts, then create exactly one canonical success or failure."""
    _preseal(r)
    counts = {"oracle_shards_assembled": 0, "oracle_assembly_failures": 0,
              "oracle_shards_waiting": 0, "oracle_assembly_skipped": 0}
    for work in _works(r):
        if not _exists(r, work / "PARTS-PLAN.json"):
            continue
        receipt = r.PRIVATE / "receipts" / "oracle" / (work.name + ".json")
        terminal = receipt.with_name(work.name + "-complete.json")
        if (any(_exists(r, work / name) for name in
                ("INVOCATION.json", "COMPLETION.json", "output.json", "ASSEMBLY-LINEAGE.json"))
                or _exists(r, receipt) or _exists(r, terminal)):
            counts["oracle_assembly_skipped"] += 1
            continue
        # Derive paths from the canonical case count, never from untrusted names.
        payload = r.read(work / "input.json")
        count = (len(payload["cases"]) + PART_SIZE - 1) // PART_SIZE
        paths = _part_paths(r, work, count)
        if not paths or not all(_exists(r, part / "COMPLETION.json") for part in paths):
            counts["oracle_shards_waiting"] += 1
            continue
        try:
            output = _joined(r, work)
        except Exception:
            output = None
        success = output is not None
        # INVOCATION is an exclusive mechanical-operation reservation, not an AI call.
        r.write(work / "INVOCATION.json", _invocation(r, work))
        r.write(work / "ASSEMBLY-LINEAGE.json", _lineage(r, work, paths, success))
        r.write(receipt, _receipt(r, work))
        if success:
            r.write(work / "output.json", output)
        completion = _completion(work, len(output["oracles"]) if success else 0, success)
        r.write(terminal, r.seal({**completion, "output_sha256": r.sha(work / "output.json") if success else None}))
        # Publish completion last, after all protected receipts exist.
        r.write(work / "COMPLETION.json", completion)
        counts["oracle_shards_assembled" if success else "oracle_assembly_failures"] += 1
    return counts


def validate_assembly_lineage(r, work) -> None:
    """Recompute the exact join and its receipts; flags alone never validate it."""
    _canonical(r, work)
    output = _joined(r, work)
    count = (len(output["oracles"]) + PART_SIZE - 1) // PART_SIZE
    if r.digest(r.read(work / "output.json")) != r.digest(output):
        raise RuntimeError("canonical output is not the exact ordered assembly")
    if r.read(work / "ASSEMBLY-LINEAGE.json") != _lineage(r, work, _part_paths(r, work, count), True):
        raise RuntimeError("assembly lineage/hash mismatch")
    if r.read(work / "INVOCATION.json") != _invocation(r, work):
        raise RuntimeError("assembly mechanical invocation mismatch")
    completion = _completion(work, len(output["oracles"]), True)
    if r.read(work / "COMPLETION.json") != completion:
        raise RuntimeError("assembly completion mismatch")
    receipt = r.PRIVATE / "receipts" / "oracle" / (work.name + ".json")
    if r.read(receipt) != _receipt(r, work):
        raise RuntimeError("assembly protected input receipt mismatch")
    if r.read(receipt.with_name(work.name + "-complete.json")) != r.seal({
            **completion, "output_sha256": r.sha(work / "output.json")}):
        raise RuntimeError("assembly protected output receipt mismatch")
