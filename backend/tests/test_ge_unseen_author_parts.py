"""Synthetic author repair tests; all run artifacts live only in memory."""
from __future__ import annotations

import ast
import fnmatch
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import jsonschema
import pytest
from scripts import ge_unseen_author_parts as parts


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def seal(value):
    body = {key: item for key, item in value.items() if key != "content_sha256"}
    return {**body, "content_sha256": digest(body)}


def scope_contract():
    return {"synthetic_contract": True, "countries": ["UK", "USA"],
            "training": "NOT_AUTHORIZED", "source_before_case_construction": False}


def runner_contracts():
    # Extract only pure code definitions. Never import the runner or read a bank.
    source = Path(__file__).resolve().parents[2] / "scripts" / "run_ge_codex_unseen.py"
    names = {"object_schema", "array_schema", "STRING", "STRINGS", "AUTHOR_SCHEMA", "author_input",
             "completion_recheckable"}
    tree = ast.parse(source.read_text())
    definitions = [node for node in tree.body
                   if (isinstance(node, ast.FunctionDef) and node.name in names)
                   or (isinstance(node, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id in names for t in node.targets))]
    namespace = {"TODAY": "2026-09-05", "scope_contract": scope_contract}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(source), "exec"), namespace)
    return namespace["AUTHOR_SCHEMA"], namespace["author_input"], namespace["completion_recheckable"]


AUTHOR_SCHEMA, author_input, completion_recheckable = runner_contracts()


def coverage_slots():
    # No real domain names, assigned IDs, questions or evaluation data.
    rows = []
    for domain_index in range(1, 36):
        domain = f"synthetic-domain-{domain_index:02d}"
        for index in range(12):
            rows.append({"slot_id": f"{domain}:slot-{index:02d}", "domain": domain,
                         "family": f"synthetic-family-{index // 2}",
                         "jurisdiction_code": "UK-ENG" if index % 2 == 0 else "US-CA",
                         "location_name": "England" if index % 2 == 0 else "California",
                         "synthetic_upload_required": index % 2 == 1,
                         "multi_turn_required": index in (4, 5, 10, 11),
                         "cross_issue_required": index >= 10})
    return rows


class MemoryPath(PurePosixPath):
    """Never perform pathlib filesystem IO, including temporary-file cleanup."""

    fs = None

    def exists(self):
        return self in self.fs.files or self in self.fs.dirs

    def mkdir(self, mode=0o777, parents=False, exist_ok=False):
        if self.exists():
            if exist_ok and self in self.fs.dirs:
                return
            raise FileExistsError("synthetic path exists")
        if not self.parent.exists():
            if not parents:
                raise FileNotFoundError("synthetic parent missing")
            self.parent.mkdir(parents=True, exist_ok=True)
        self.fs.dirs.add(self)

    def glob(self, pattern):
        return iter(sorted(p for p in self.fs.files.keys() | self.fs.dirs
                           if p.parent == self and fnmatch.fnmatchcase(p.name, pattern)))

    def rename(self, target):
        assert not target.exists(), "must never replace an existing destination"
        assert target.parent in self.fs.dirs
        if self in self.fs.files:
            self.fs.files[target] = self.fs.files.pop(self)
        else:
            assert self in self.fs.dirs
            for path in sorted(self.fs.files.copy()):
                if path.is_relative_to(self):
                    self.fs.files[target / path.relative_to(self)] = self.fs.files.pop(path)
            for path in sorted(self.fs.dirs.copy()):
                if path.is_relative_to(self):
                    self.fs.dirs.remove(path)
                    self.fs.dirs.add(target / path.relative_to(self))
        self.fs.moves.append((self, target))
        return target

    def open(self, mode):
        if mode == "rb":
            return io.BytesIO(self.fs.files[self])
        assert mode == "xb", "no overwrite/truncation mode allowed"
        if self.exists():
            raise FileExistsError("synthetic file exists")
        path = self

        class Writer(io.BytesIO):
            def close(self):
                if not self.closed:
                    path.fs.files[path] = self.getvalue()
                super().close()

        return Writer()

    def chmod(self, mode):
        assert mode == 0o600


@pytest.fixture
def memory(monkeypatch):
    fs = SimpleNamespace(files={}, dirs={MemoryPath("/")}, moves=[], symlinks=set(), reads=[])
    monkeypatch.setattr(MemoryPath, "fs", fs)
    r = SimpleNamespace(ROOT=MemoryPath("/synthetic/current"),
                        PRIVATE=MemoryPath("/synthetic/current/private"),
                        PUBLIC=MemoryPath("/synthetic/current/public"),
                        AUTHOR_SCHEMA=AUTHOR_SCHEMA, digest=digest, seal=seal,
                        author_input=author_input, coverage_slots=coverage_slots,
                        completion_recheckable=completion_recheckable,
                        DOMAIN_FAMILIES={f"synthetic-domain-{i:02d}": () for i in range(1, 36)},
                        fs=fs, validation_calls=[], validation_stack=[], scope_checks=[])

    def safe_path(path):
        assert isinstance(path, MemoryPath), "real filesystem path forbidden"
        if not path.is_relative_to(r.ROOT) or ".." in path.parts:
            raise RuntimeError("outside synthetic current run")
        if any(p in fs.symlinks for p in (path, *path.parents)):
            raise RuntimeError("symlink refused")

    def read(path):
        safe_path(path)
        fs.reads.append(path)
        return json.loads(fs.files[path])

    def write(path, value):
        safe_path(path)
        if path.exists():
            raise FileExistsError("synthetic write is create-only")
        path.parent.mkdir(parents=True, exist_ok=True)
        fs.files[path] = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()

    def sha(path):
        safe_path(path)
        return hashlib.sha256(fs.files[path]).hexdigest()

    def safe_files(directory):
        safe_path(directory)
        selected = sorted(p for p in fs.files if p.is_relative_to(directory))
        for path in selected:
            safe_path(path)
        return selected

    def validate_scope(rows, slots):
        r.scope_checks.append(len(slots))
        assigned = {slot["slot_id"]: slot for slot in slots}
        questions = []
        for row in rows:
            slot = assigned[row["case_id"]]
            if row["jurisdiction"] != slot["jurisdiction_code"] or slot["location_name"] not in row["question"]:
                raise RuntimeError("synthetic wrong jurisdiction/location")
            questions.append(row["question"])
        if len(set(questions)) != len(questions):
            raise RuntimeError("synthetic duplicate across parts")

    def validate(work):
        assert work not in r.validation_stack, "recursive canonical/part validation"
        r.validation_calls.append(work)
        r.validation_stack.append(work)
        try:
            value = read(work / "output.json")
            completion = read(work / "COMPLETION.json")
            if not r.completion_recheckable(work.parent.name, completion):
                raise RuntimeError("synthetic failed invocation")
            jsonschema.validate(value, r.AUTHOR_SCHEMA)
            if work.parent.name == "author-parts":
                parts.validate_part_lineage(r, work)
            else:
                assert work.parent.name == "author"
                if (work / "ASSEMBLY-LINEAGE.json").exists():
                    parts.validate_assembly_lineage(r, work)
                else:
                    payload = parts._parent_input(r, work)
                    validate_scope(value["cases"], payload["slots"])
                    assert sorted(row["case_id"] for row in value["cases"]) == sorted(slot["slot_id"] for slot in payload["slots"])
                    receipt = r.PRIVATE / "receipts" / "author" / (work.name + ".json")
                    if receipt.exists():
                        parts._protected_inputs(r, work, read(receipt), logical_work=f"author/{work.name}")
                        parts._protected_terminal(r, work, completion, read(receipt.with_name(work.name + "-complete.json")))
            return value
        finally:
            r.validation_stack.pop()

    r.safe_path, r.read, r.write, r.sha, r.safe_files = safe_path, read, write, sha, safe_files
    r.validate_job, r.validate_author_scope = validate, validate_scope
    return r


def seed(r, shard="shard-01", *, failed=True, receipts=True, no_output=False):
    work = r.PRIVATE / "author" / shard
    domain = list(r.DOMAIN_FAMILIES)[int(shard[-2:]) - 1]
    r.write(work / "input.json", r.author_input([s for s in coverage_slots() if s["domain"] == domain]))
    r.write(work / "schema.json", r.AUTHOR_SCHEMA)
    # Nonstandard JSON whitespace verifies preservation is byte-for-byte.
    r.fs.files[work / "input.json"] += b"\n "
    r.fs.files[work / "schema.json"] += b" \n"
    if failed:
        complete(r, work, returncode=124, receipts=receipts, no_output=no_output)
        r.write(work / "nested" / "partial-evidence.txt", {"synthetic": "retained bytes"})
    return work


def scenario(slot):
    return {"case_id": slot["slot_id"],
            "question": f"Synthetic fixture {slot['slot_id']} concerns my home in {slot['location_name']}.",
            "follow_up": "Synthetic later fact.", "jurisdiction": slot["jurisdiction_code"],
            "relevant_date": "2026-09-05", "secondary_domains": [],
            "uploads": [{"title": "Synthetic document", "pages": ["Synthetic evidence only."], "format": "PDF"}],
            "issues_to_research": ["Synthetic issue"], "material_missing_facts": [],
            "coverage_explanation": "Synthetic fixture", "expected_behavior": "Synthetic author"}


def complete(r, work, *, returncode=0, validation_error=None, rows=None, no_output=False, receipts=True):
    if rows is None:
        rows = [scenario(slot) for slot in reversed(r.read(work / "input.json")["slots"])]
    r.write(work / "INVOCATION.json", {"input_sha256": r.sha(work / "input.json"),
                                       "prompt_sha256": r.digest("synthetic author prompt"), "browse": False})
    receipt = r.PRIVATE / "receipts" / work.parent.name / (work.name + ".json")
    if receipts:
        r.write(receipt, {"input_sha256": r.sha(work / "input.json"),
                          "schema_sha256": r.sha(work / "schema.json"),
                          "prompt_sha256": r.digest("synthetic author prompt"),
                          "work": work.relative_to(r.PRIVATE).as_posix(),
                          "input_inventory": {name: r.sha(work / name)
                                              for name in ("input.json", "schema.json", "INVOCATION.json")}})
    if not no_output:
        r.write(work / "output.json", {"cases": rows})
    completion = {"stage": work.parent.name, "shard": work.name, "returncode": returncode,
                  "output_present": not no_output, "validation_error": validation_error,
                  "validated_rows": len(rows) if not no_output else 0}
    r.write(work / "COMPLETION.json", completion)
    if receipts:
        r.write(receipt.with_name(work.name + "-complete.json"), {
            **completion, "output_sha256": None if no_output else r.sha(work / "output.json")})


def jobs(r, work):
    return sorted((r.PRIVATE / "author-parts").glob(work.name + "-part-*"))


def test_current_valid_parts_with_historical_scope_failure_assemble(memory):
    r = memory
    work = seed(r)
    parts.prepare_parts(r)
    for job in jobs(r, work):
        complete(r, job, validation_error="UKUSScopeError")
        completion = r.read(job / "COMPLETION.json")
        completion["validated_rows"] = 0
        replace(r, job / "COMPLETION.json", completion)
        terminal = r.PRIVATE / "receipts" / "author-parts" / (job.name + "-complete.json")
        replace(r, terminal, {**completion, "output_sha256": r.sha(job / "output.json")})
    before = {p: raw for p, raw in r.fs.files.items() if "author-parts" in p.parts}
    assert parts.assemble_parts(r)["author_shards_assembled"] == 1
    assert len(r.validate_job(work)["cases"]) == 12
    assert all(r.fs.files[p] == raw for p, raw in before.items())


def replace(r, path, value):
    """Adversarial in-memory mutation; never writes to a real file."""
    r.fs.files[path] = json.dumps(value).encode()


def archived(r, work):
    return r.PRIVATE / "author-batch-failure-preserved" / work.name


@pytest.mark.parametrize("shard,receipts,no_output", [("shard-01", True, False),
                                                       ("shard-35", True, True),
                                                       ("shard-12", False, True)])
def test_preserve_split_assemble_and_repeat_are_exact(memory, shard, receipts, no_output):
    r = memory
    work = seed(r, shard, receipts=receipts, no_output=no_output)
    before = dict(r.fs.files)
    payload = r.read(work / "input.json")
    result = parts.prepare_parts(r)
    assert result == {"author_shards_partitioned": 1, "author_parts_prepared": 6,
                      "author_failed_batches_preserved": 1, "author_shards_skipped": 0,
                      "author_recheckable_holds": 0}
    archive = archived(r, work)
    inventory = r.read(archive / "HASH-INVENTORY.json")
    assert inventory == seal(inventory)
    for name, expected in inventory["files"].items():
        source = work / name.removeprefix("canonical/") if name.startswith("canonical/") else r.PRIVATE / name
        assert r.fs.files[archive / name] == before[source]
        assert r.sha(archive / name) == expected
    for name in ("input.json", "schema.json"):
        assert r.fs.files[work / name] == before[work / name]
    assert not (work / "output.json").exists()
    assert not (work / "COMPLETION.json").exists()
    assert len(r.fs.moves) == (3 if receipts else 1)
    plan = r.read(work / "PARTS-PLAN.json")
    assert plan == seal(plan)
    assert plan["preserved_inventory_sha256"] == r.sha(archive / "HASH-INVENTORY.json")
    assert len(jobs(r, work)) == 6
    expected_rows = []
    for index, job in enumerate(jobs(r, work)):
        part_input = r.read(job / "input.json")
        assert part_input == {**payload, "slots": payload["slots"][index * 2:index * 2 + 2],
                              "parent_shard": work.name, "parent_input_sha256": r.sha(work / "input.json"),
                              "part_index": index, "part_count": 6}
        assert "cases" not in part_input
        assert r.fs.files[job / "schema.json"] == before[work / "schema.json"]
        parts.validate_part_lineage(r, job)
        complete(r, job)
        expected_rows.extend(scenario(slot) for slot in part_input["slots"])
    assert parts.assemble_parts(r)["author_shards_assembled"] == 1
    assert r.validate_job(work) == {"cases": expected_rows}
    assert 12 in r.scope_checks  # Scope/novelty also checked across part boundaries.
    invocation = r.read(work / "INVOCATION.json")
    assert invocation["kind"] == "AUTHOR_PART_ASSEMBLY"
    assert invocation["model"] == "NONE_MECHANICAL_ASSEMBLY"
    assert invocation["provider"] is None and invocation["fresh_context"] is False
    assert r.read(work / "COMPLETION.json")["validated_rows"] == 12
    assert all(r.sha(archive / name) == value for name, value in inventory["files"].items())
    frozen = dict(r.fs.files), set(r.fs.dirs), list(r.fs.moves)
    assert parts.prepare_parts(r)["author_shards_skipped"] == 1
    assert parts.assemble_parts(r)["author_assembly_skipped"] == 1
    assert (r.fs.files, r.fs.dirs, r.fs.moves) == frozen
    assert not any(path.is_relative_to(r.PUBLIC) for path in r.fs.files)


def test_wait_for_partial_jobs_without_writing_or_running(memory):
    r = memory
    work = seed(r)
    parts.prepare_parts(r)
    for job in jobs(r, work)[:-1]:
        complete(r, job)
    last = jobs(r, work)[-1]
    r.write(last / "INVOCATION.json", {"synthetic_running": True})
    r.write(last / "output.json", {"cases": []})
    before = dict(r.fs.files), set(r.fs.dirs)
    assert parts.assemble_parts(r)["author_shards_waiting"] == 1
    assert (r.fs.files, r.fs.dirs) == before
    assert not r.validation_calls


def test_checked_plan_accounts_for_pending_parts_read_only(memory):
    r = memory
    work = seed(r)
    parts.prepare_parts(r)
    complete(r, jobs(r, work)[0])
    before = dict(r.fs.files), set(r.fs.dirs), list(r.fs.moves)
    plan = parts.checked_plan(r, work)
    assert plan == r.read(work / "PARTS-PLAN.json")
    assert plan["part_count"] == 6
    assert [entry["part_shard"] for entry in plan["parts"]] == [job.name for job in jobs(r, work)]
    assert sum(len(entry["slot_ids"]) for entry in plan["parts"]) == 12
    assert (r.fs.files, r.fs.dirs, r.fs.moves) == before
    assert not r.validation_calls
    plan["parts"][0]["slot_ids"] = []
    assert len(parts.checked_plan(r, work)["parts"][0]["slot_ids"]) == 2
    r.fs.files[jobs(r, work)[-1] / "input.json"] += b" "
    with pytest.raises(RuntimeError):
        parts.checked_plan(r, work)


@pytest.mark.parametrize("state", ["pristine", "successful", "running", "orphan-output", "orphan-receipt",
                                  "orphan-parts", "orphan-part-receipt", "local-parts", "old-archive", "assembly-receipt"])
def test_skip_existing_or_unfinished_work_without_overwrite(memory, state):
    r = memory
    work = seed(r, failed=False)
    if state == "successful":
        complete(r, work)
    elif state == "running":
        r.write(work / "INVOCATION.json", {"synthetic_running": True})
    elif state == "orphan-output":
        r.write(work / "output.json", {})
    elif state == "orphan-receipt":
        r.write(r.PRIVATE / "receipts" / "author" / (work.name + ".json"), {})
    elif state == "orphan-parts":
        complete(r, work, returncode=124)
        (r.PRIVATE / "author-parts" / (work.name + "-part-01")).mkdir(parents=True)
    elif state == "orphan-part-receipt":
        complete(r, work, returncode=124)
        r.write(r.PRIVATE / "receipts" / "author-parts" / (work.name + "-part-01.json"), {})
    elif state == "local-parts":
        complete(r, work, returncode=124)
        (work / "parts").mkdir()
    elif state == "old-archive":
        complete(r, work, returncode=124)
        archived(r, work).mkdir(parents=True)
    elif state == "assembly-receipt":
        r.write(work / "ASSEMBLY-LINEAGE.json", {"status": "FAILED"})
    before = dict(r.fs.files), set(r.fs.dirs)
    assert parts.prepare_parts(r)["author_shards_skipped"] == 1
    assert (r.fs.files, r.fs.dirs) == before and not r.fs.moves


def test_system_batch_is_untouched_without_reading_it(memory):
    r = memory
    work = r.PRIVATE / "author" / "shard-36"
    r.write(work / "input.json", {"slots": ["synthetic system"] * 23})
    r.write(work / "COMPLETION.json", {"returncode": 124, "validation_error": None})
    before = dict(r.fs.files)
    assert parts.prepare_parts(r)["author_parts_prepared"] == 0
    assert parts.assemble_parts(r)["author_shards_assembled"] == 0
    assert r.fs.files == before and not r.fs.reads


@pytest.mark.parametrize("error", ["ValidationError", "ValueError"])
def test_zero_exit_non_recheckable_failure_can_be_preserved(memory, error):
    r = memory
    work = seed(r, failed=False)
    complete(r, work, validation_error=error)
    assert parts.prepare_parts(r)["author_failed_batches_preserved"] == 1
    assert r.read(archived(r, work) / "canonical" / "COMPLETION.json")["validation_error"] == error


def test_ten_historical_scope_errors_now_valid_keep_hashes_only_timeout_partitioned(memory):
    r = memory
    for number in range(1, 11):
        work = seed(r, f"shard-{number:02d}", failed=False)
        complete(r, work, validation_error="UKUSScopeError")
    valid_bytes = dict(r.fs.files)
    timed_out = seed(r, "shard-30")
    result = parts.prepare_parts(r)
    assert result["author_shards_skipped"] == 10
    assert result["author_recheckable_holds"] == 0
    assert result["author_failed_batches_preserved"] == 1
    assert result["author_parts_prepared"] == 6
    assert len(r.validation_calls) == 10 and timed_out not in r.validation_calls
    assert all(r.fs.files[path] == raw for path, raw in valid_bytes.items())
    assert all(job.name.startswith("shard-30-") for job in (r.PRIVATE / "author-parts").glob("*"))
    for number in range(1, 11):
        assert not archived(r, r.PRIVATE / "author" / f"shard-{number:02d}").exists()


@pytest.mark.parametrize("error", [None, "UKUSScopeError"])
@pytest.mark.parametrize("defect", ["scope", "schema", "receipt", "missing-output"])
def test_recheckable_current_invalid_stays_held_without_reauthoring(memory, error, defect):
    r = memory
    work = seed(r, failed=False)
    rows = [scenario(slot) for slot in r.read(work / "input.json")["slots"]]
    if defect == "scope":
        rows[0]["jurisdiction"] = "US-NY"
    elif defect == "schema":
        rows[0]["uploads"][0]["format"] = "EXE"
    complete(r, work, rows=rows, validation_error=error, no_output=defect == "missing-output")
    if defect == "receipt":
        replace(r, r.PRIVATE / "receipts" / "author" / (work.name + ".json"), {})
    before = dict(r.fs.files), set(r.fs.dirs), list(r.fs.moves)
    result = parts.prepare_parts(r)
    assert result["author_recheckable_holds"] == 1
    assert result["author_shards_skipped"] == 1
    assert result["author_parts_prepared"] == 0
    assert r.validation_calls == [work]
    assert (r.fs.files, r.fs.dirs, r.fs.moves) == before


@pytest.mark.parametrize("defect", ["scope", "jurisdiction-rule", "as-of", "slot-jurisdiction", "slot-family",
                                   "slot-upload", "slot-order", "duplicate-slot", "missing-slot", "extra-slot",
                                   "unexpected-field", "schema"])
def test_original_contract_tamper_rejected_before_preservation(memory, defect):
    r = memory
    work = seed(r, receipts=False)
    payload = r.read(work / "input.json")
    if defect == "scope":
        payload["scope_contract"]["training"] = "AUTHORIZED"
    elif defect == "jurisdiction-rule":
        payload["jurisdiction_rule"] = "HOST_TIMEZONE"
    elif defect == "as-of":
        payload["as_of"] = "2099-01-01"
    elif defect.startswith("slot-") and defect != "slot-order":
        field = {"slot-jurisdiction": "jurisdiction_code", "slot-family": "family", "slot-upload": "synthetic_upload_required"}[defect]
        payload["slots"][0][field] = "changed"
    elif defect == "slot-order":
        payload["slots"].reverse()
    elif defect == "duplicate-slot":
        payload["slots"][1] = payload["slots"][0]
    elif defect == "missing-slot":
        payload["slots"].pop()
    elif defect == "extra-slot":
        payload["slots"].append({"slot_id": "invented"})
    elif defect == "unexpected-field":
        payload["cases"] = []
    elif defect == "schema":
        replace(r, work / "schema.json", {})
    replace(r, work / "input.json", payload)
    before = dict(r.fs.files), set(r.fs.dirs)
    with pytest.raises(RuntimeError):
        parts.prepare_parts(r)
    assert (r.fs.files, r.fs.dirs) == before and not r.fs.moves


@pytest.mark.parametrize("defect", ["slot-content", "slot-order", "slot-bool", "scope", "as-of", "parent-hash",
                                   "parent-shard", "part-index", "index-bool", "part-count", "extra-field",
                                   "schema", "schema-whitespace", "plan", "part-whitespace", "parent-whitespace",
                                   "preserved-bytes", "preserved-extra-file", "preservation-proof", "inventory"])
def test_part_lineage_rejects_contract_raw_hash_and_archive_tamper(memory, defect):
    r = memory
    work = seed(r)
    parts.prepare_parts(r)
    job = jobs(r, work)[0]
    payload = r.read(job / "input.json")
    if defect == "slot-content":
        payload["slots"][0]["jurisdiction_code"] = "US-NY"
    elif defect == "slot-order":
        payload["slots"].reverse()
    elif defect == "slot-bool":
        payload["slots"][0]["synthetic_upload_required"] = 0
    elif defect == "scope":
        payload["scope_contract"]["countries"] = ["UK"]
    elif defect == "as-of":
        payload["as_of"] = "2099-01-01"
    elif defect == "parent-hash":
        payload["parent_input_sha256"] = "0" * 64
    elif defect == "parent-shard":
        payload["parent_shard"] = "shard-02"
    elif defect == "part-index":
        payload["part_index"] = 1
    elif defect == "index-bool":
        payload["part_index"] = False
    elif defect == "part-count":
        payload["part_count"] = 5
    elif defect == "extra-field":
        payload["question"] = "unexpected"
    else:
        if defect == "schema":
            replace(r, job / "schema.json", {})
        elif defect == "schema-whitespace":
            r.fs.files[job / "schema.json"] += b" "
        elif defect == "plan":
            plan = r.read(work / "PARTS-PLAN.json")
            plan["parts"][0]["input_sha256"] = "0" * 64
            replace(r, work / "PARTS-PLAN.json", seal(plan))
        elif defect in ("part-whitespace", "parent-whitespace"):
            r.fs.files[(job if defect == "part-whitespace" else work) / "input.json"] += b" "
        elif defect == "preserved-bytes":
            r.fs.files[archived(r, work) / "canonical" / "nested" / "partial-evidence.txt"] += b" "
        elif defect == "preserved-extra-file":
            r.write(archived(r, work) / "unexpected.txt", {})
        elif defect == "preservation-proof":
            replace(r, archived(r, work) / "PRESERVATION-VERIFIED.json", seal({"bytes_unchanged": True}))
        elif defect == "inventory":
            inventory = r.read(archived(r, work) / "HASH-INVENTORY.json")
            inventory["files"].pop("canonical/nested/partial-evidence.txt")
            replace(r, archived(r, work) / "HASH-INVENTORY.json", seal(inventory))
        with pytest.raises(RuntimeError):
            parts.validate_part_lineage(r, job)
        return
    replace(r, job / "input.json", payload)
    with pytest.raises(RuntimeError):
        parts.validate_part_lineage(r, job)
    assert not r.validation_calls


@pytest.mark.parametrize("defect", ["timeout", "validation-error", "missing-output", "missing-receipts", "duplicate",
                                   "missing", "extra", "wrong-part", "schema", "scope", "cross-part-duplicate"])
def test_failed_part_is_terminal_without_inventing_rows_or_resplit(memory, defect):
    r = memory
    work = seed(r)
    parts.prepare_parts(r)
    part_jobs = jobs(r, work)
    rows = [scenario(slot) for slot in r.read(part_jobs[0] / "input.json")["slots"]]
    kwargs = {}
    if defect == "timeout":
        kwargs["returncode"] = 124
    elif defect == "validation-error":
        kwargs["validation_error"] = "ValidationError"
    elif defect == "missing-output":
        kwargs["no_output"] = True
    elif defect == "missing-receipts":
        kwargs["receipts"] = False
    elif defect == "duplicate":
        rows[1] = rows[0]
    elif defect == "missing":
        rows.pop()
    elif defect == "extra":
        rows.append({**rows[0], "case_id": "invented"})
    elif defect == "wrong-part":
        rows[0]["case_id"] = r.read(part_jobs[1] / "input.json")["slots"][0]["slot_id"]
    elif defect == "schema":
        rows[0]["uploads"][0]["format"] = "EXE"
    elif defect == "scope":
        rows[0]["jurisdiction"] = "US-NY"
    elif defect == "cross-part-duplicate":
        rows[0]["question"] = scenario(r.read(part_jobs[1] / "input.json")["slots"][0])["question"]
    complete(r, part_jobs[0], rows=rows, **kwargs)
    for job in part_jobs[1:]:
        complete(r, job)
    before = dict(r.fs.files)
    assert parts.assemble_parts(r)["author_assembly_failures"] == 1
    assert not (work / "output.json").exists()
    completion = r.read(work / "COMPLETION.json")
    assert completion["validated_rows"] == 0 and completion["validation_error"] == "AUTHOR_PART_ASSEMBLY_FAILED"
    assert r.read(work / "ASSEMBLY-LINEAGE.json")["status"] == "FAILED"
    assert all(job in r.validation_calls for job in part_jobs)
    assert all(r.fs.files[path] == raw for path, raw in before.items())
    frozen = dict(r.fs.files)
    assert parts.assemble_parts(r)["author_assembly_skipped"] == 1
    assert parts.prepare_parts(r)["author_shards_skipped"] == 1
    assert r.fs.files == frozen
    with pytest.raises(RuntimeError):
        parts.validate_assembly_lineage(r, work)


@pytest.mark.parametrize("defect", ["input-receipt", "inventory-empty", "inventory-path", "invocation-prompt",
                                   "complete-receipt", "completion-laundered", "raw-output"])
def test_parts_require_intact_protected_receipts(memory, defect):
    r = memory
    work = seed(r)
    parts.prepare_parts(r)
    for job in jobs(r, work):
        complete(r, job)
    job = jobs(r, work)[0]
    receipt = r.PRIVATE / "receipts" / "author-parts" / (job.name + ".json")
    if defect in ("input-receipt", "inventory-empty", "inventory-path"):
        value = r.read(receipt)
        if defect == "input-receipt":
            value["schema_sha256"] = "0" * 64
        elif defect == "inventory-empty":
            value["input_inventory"] = {}
        else:
            value["input_inventory"]["../../retired/output.json"] = "0" * 64
        replace(r, receipt, value)
    elif defect == "invocation-prompt":
        value = r.read(job / "INVOCATION.json")
        value["prompt_sha256"] = "0" * 64
        replace(r, job / "INVOCATION.json", value)
    elif defect == "complete-receipt":
        replace(r, receipt.with_name(job.name + "-complete.json"), {"output_sha256": r.sha(job / "output.json")})
    elif defect == "completion-laundered":
        value = r.read(receipt.with_name(job.name + "-complete.json"))
        value["returncode"] = 124
        replace(r, receipt.with_name(job.name + "-complete.json"), value)
    else:
        r.fs.files[job / "output.json"] += b" "
    assert parts.assemble_parts(r)["author_assembly_failures"] == 1
    assert not any("retired" in path.parts for path in r.fs.reads)


def test_missing_or_extra_part_directory_is_terminal(memory):
    r = memory
    work = seed(r)
    parts.prepare_parts(r)
    # Move, rather than delete, the synthetic directory to create both defects.
    job = jobs(r, work)[-1]
    job.rename(job.with_name(work.name + "-part-99"))
    with pytest.raises(RuntimeError, match="missing or extra"):
        parts.checked_plan(r, work)
    assert parts.assemble_parts(r)["author_assembly_failures"] == 1
    assert not (work / "output.json").exists()
    frozen = dict(r.fs.files)
    assert parts.assemble_parts(r)["author_assembly_skipped"] == 1
    assert r.fs.files == frozen


@pytest.mark.parametrize("defect", ["row-content", "row-order", "part-output", "lineage", "model", "receipt",
                                   "terminal", "completion", "original-receipt"])
def test_assembled_output_revalidates_preservation_rows_and_receipts(memory, defect):
    r = memory
    work = seed(r)
    parts.prepare_parts(r)
    for job in jobs(r, work):
        complete(r, job)
    parts.assemble_parts(r)
    if defect in ("row-content", "row-order"):
        value = r.read(work / "output.json")
        if defect == "row-content":
            value["cases"][0]["follow_up"] = "Changed later synthetic fact"
        else:
            value["cases"].reverse()
        replace(r, work / "output.json", value)
        terminal = r.PRIVATE / "receipts" / "author" / (work.name + "-complete.json")
        value = r.read(terminal)
        value["output_sha256"] = r.sha(work / "output.json")
        replace(r, terminal, seal(value))
    elif defect == "part-output":
        r.fs.files[jobs(r, work)[0] / "output.json"] += b" "
    elif defect == "lineage":
        value = r.read(work / "ASSEMBLY-LINEAGE.json")
        value["parts"][0]["receipt_sha256"] = "0" * 64
        replace(r, work / "ASSEMBLY-LINEAGE.json", seal(value))
    elif defect == "model":
        value = r.read(work / "INVOCATION.json")
        value["model"] = "CONFIGURED_DEFAULT"
        replace(r, work / "INVOCATION.json", value)
    elif defect in ("receipt", "terminal"):
        suffix = ".json" if defect == "receipt" else "-complete.json"
        replace(r, r.PRIVATE / "receipts" / "author" / (work.name + suffix), {})
    elif defect == "completion":
        value = r.read(work / "COMPLETION.json")
        value["returncode"] = False  # bool must not compare equal to integer zero.
        replace(r, work / "COMPLETION.json", value)
    else:
        r.fs.files[archived(r, work) / "receipts" / "author" / (work.name + ".json")] += b" "
    with pytest.raises(RuntimeError):
        parts.validate_assembly_lineage(r, work)


@pytest.mark.parametrize("phase", ["preservation", "part-write", "plan-write", "assembly"])
def test_interrupted_operations_preserve_evidence_and_never_resume(memory, monkeypatch, phase):
    r = memory
    work = seed(r)
    if phase == "assembly":
        parts.prepare_parts(r)
        for job in jobs(r, work):
            complete(r, job)
    target = {"preservation": archived(r, work) / "PRESERVATION-VERIFIED.json",
              "part-write": r.PRIVATE / "author-parts" / (work.name + "-part-02") / "input.json",
              "plan-write": work / "PARTS-PLAN.json", "assembly": work / "ASSEMBLY-LINEAGE.json"}[phase]
    original = r.write

    def interrupted(path, value):
        if path == target:
            raise OSError("synthetic interrupted write")
        original(path, value)

    monkeypatch.setattr(r, "write", interrupted)
    with pytest.raises(OSError, match="interrupted"):
        (parts.assemble_parts if phase == "assembly" else parts.prepare_parts)(r)
    before = dict(r.fs.files), set(r.fs.dirs), list(r.fs.moves)
    parts.prepare_parts(r)
    parts.assemble_parts(r)
    assert (r.fs.files, r.fs.dirs, r.fs.moves) == before
    assert not (work / "COMPLETION.json").exists()
    assert (archived(r, work) / "HASH-INVENTORY.json").exists()


def test_move_corruption_is_detected_before_canonical_recreation(memory, monkeypatch):
    r = memory
    work = seed(r)
    original = MemoryPath.rename

    def corrupt_after_move(path, target):
        result = original(path, target)
        if target.name == "canonical":
            r.fs.files[target / "input.json"] += b" "
        return result

    monkeypatch.setattr(MemoryPath, "rename", corrupt_after_move)
    with pytest.raises(RuntimeError, match="inventory mismatch"):
        parts.prepare_parts(r)
    assert not work.exists() and not jobs(r, work)
    assert (archived(r, work) / "HASH-INVENTORY.json").exists()


@pytest.mark.parametrize("marker", ["BANK-SEAL.json", "ONE-PASS-START.json"])
def test_seal_or_disclosure_refused_before_run_reads(memory, marker):
    r = memory
    r.write(r.PUBLIC / marker, {})
    for operation in (parts.prepare_parts, parts.assemble_parts):
        with pytest.raises(RuntimeError, match="after seal"):
            operation(r)
    assert not r.fs.reads


def test_invalid_paths_refused_before_read(memory):
    r = memory
    for path in (r.PRIVATE / "author-parts" / "shard-36-part-01",
                 r.PRIVATE / "author-parts" / "shard-01-part-07",
                 r.PRIVATE / "author-parts" / "../retired/shard-01-part-01",
                 MemoryPath("/synthetic/other/private/author-parts/shard-01-part-01")):
        with pytest.raises(RuntimeError):
            parts.validate_part_lineage(r, path)
    for path in (r.PRIVATE / "author" / "shard-36", r.PRIVATE / "retired" / "shard-01"):
        with pytest.raises(RuntimeError):
            parts.validate_assembly_lineage(r, path)
    assert not r.fs.reads


def test_symlink_refused_before_read(memory):
    r = memory
    work = seed(r)
    r.fs.symlinks.add(work)
    r.fs.reads.clear()
    with pytest.raises(RuntimeError, match="symlink"):
        parts.prepare_parts(r)
    assert not r.fs.reads
