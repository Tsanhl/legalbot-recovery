"""Synthetic oracle-parts regressions: an in-memory filesystem, no real bank IO."""
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
from scripts import ge_unseen_oracle_parts as parts


def runner_schema():
    # Read only the authorized code file. Extract pure schema definitions without
    # importing the runner's application/database dependency tree or any bank.
    source = Path(__file__).resolve().parents[2] / "scripts" / "run_ge_codex_unseen.py"
    names = {"object_schema", "array_schema", "STRING", "STRINGS", "SOURCE_SCHEMA", "ORACLE_SCHEMA"}
    tree = ast.parse(source.read_text())
    definitions = [node for node in tree.body
                   if (isinstance(node, ast.FunctionDef) and node.name in names)
                   or (isinstance(node, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id in names for t in node.targets))]
    namespace = {}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(source), "exec"), namespace)
    return namespace["ORACLE_SCHEMA"]


ORACLE_SCHEMA = runner_schema()


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def seal(value):
    body = {key: item for key, item in value.items() if key != "content_sha256"}
    return {**body, "content_sha256": digest(body)}


class MemoryPath(PurePosixPath):
    """Only implement operations exercised by the helper; never touch pathlib IO."""

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
        assert not target.exists(), "rename must never replace a destination"
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
                        ORACLE_SCHEMA=ORACLE_SCHEMA, digest=digest, seal=seal,
                        fs=fs, validation_calls=[], validation_stack=[])

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

    def validate(work):
        assert work not in r.validation_stack, "recursive canonical/part validation"
        r.validation_calls.append(work)
        r.validation_stack.append(work)
        try:
            value = read(work / "output.json")
            completion = read(work / "COMPLETION.json")
            if completion["returncode"] or completion.get("validation_error") is not None:
                raise RuntimeError("synthetic failed invocation")
            if work.parent.name == "author":
                return value
            jsonschema.validate(value, r.ORACLE_SCHEMA)
            invocation = read(work / "INVOCATION.json")
            assert invocation["input_sha256"] == sha(work / "input.json")
            receipt_path = r.PRIVATE / "receipts" / work.parent.name / (work.name + ".json")
            receipt = read(receipt_path)
            assert receipt["input_sha256"] == sha(work / "input.json")
            assert receipt["schema_sha256"] == sha(work / "schema.json")
            for name, expected in receipt["input_inventory"].items():
                assert sha(work / name) == expected
            terminal = read(receipt_path.with_name(work.name + "-complete.json"))
            assert terminal["output_sha256"] == sha(work / "output.json")
            if work.parent.name == "oracle-parts":
                parts.validate_part_lineage(r, work)
            else:
                assert work.parent.name == "oracle"
                parts.validate_assembly_lineage(r, work)
            return value
        finally:
            r.validation_stack.pop()

    r.safe_path, r.read, r.write, r.sha, r.safe_files, r.validate_job = safe_path, read, write, sha, safe_files, validate
    return r


def seed(r, count=12, shard="shard-01"):
    work = r.PRIVATE / "oracle" / shard
    author = r.PRIVATE / "author" / shard
    cases = [{"case_id": f"synthetic-{i:02d}", "question": f"Synthetic question {i}.",
              "follow_up": f"Synthetic later fact {i}.", "uploads": [{"pages": ["Synthetic page"]}]}
             for i in range(count)]
    slots = [{"slot_id": c["case_id"], "family": "synthetic-family", "domain": "synthetic-domain"}
             for c in cases]
    r.write(author / "input.json", {"slots": slots})
    r.write(author / "output.json", {"cases": cases})
    r.write(author / "COMPLETION.json", {"returncode": 0, "validation_error": None})
    enriched = [{**c, "family": "synthetic-family", "domain": "synthetic-domain"} for c in cases]
    r.write(work / "input.json", {"as_of": "2026-09-05", "cases": enriched,
                                  "scenario_frozen_sha256": r.sha(author / "output.json")})
    r.write(work / "schema.json", r.ORACLE_SCHEMA)
    return work


def oracle(case_id):
    return {"case_id": case_id, "required_points": [], "sources": [], "acceptable_alternatives": [],
            "material_limits": [], "prohibited_overclaims": [], "practical_steps": [],
            "case_law_relevance": "Synthetic fixture only", "currentness_status": "UNRESOLVED",
            "source_sufficient": False, "construction_gaps": ["Synthetic hold"], "system_assertions": []}


def part_jobs(r, work):
    return sorted((r.PRIVATE / "oracle-parts").glob(work.name + "-part-*"))


def complete(r, work, *, returncode=0, validation_error=None, rows=None, no_output=False):
    if rows is None:
        rows = [oracle(c["case_id"]) for c in reversed(r.read(work / "input.json")["cases"])]
    r.write(work / "INVOCATION.json", {"input_sha256": r.sha(work / "input.json"),
                                       "prompt_sha256": r.digest("synthetic prompt")})
    receipt = r.PRIVATE / "receipts" / work.parent.name / (work.name + ".json")
    r.write(receipt, {"input_sha256": r.sha(work / "input.json"),
                      "schema_sha256": r.sha(work / "schema.json"),
                      "input_inventory": {name: r.sha(work / name)
                                          for name in ("input.json", "schema.json", "INVOCATION.json")}})
    if not no_output:
        r.write(work / "output.json", {"oracles": rows})
    completion = {"returncode": returncode, "validation_error": validation_error,
                  "validated_rows": len(rows) if not no_output else 0}
    r.write(work / "COMPLETION.json", completion)
    r.write(receipt.with_name(work.name + "-complete.json"), {
        **completion, "output_sha256": None if no_output else r.sha(work / "output.json")})


def replace(r, path, value):
    """Adversarial in-memory alteration, never a disk write."""
    r.fs.files[path] = json.dumps(value).encode()


@pytest.mark.parametrize("count,shard,sizes", [(12, "shard-01", [2] * 6),
                                                (23, "shard-36", [2] * 11 + [1])])
def test_bounded_split_and_exact_mechanical_assembly(memory, count, shard, sizes):
    r = memory
    work = seed(r, count, shard)
    original = dict(r.fs.files)
    prepared = parts.prepare_parts(r)
    assert prepared["oracle_parts_prepared"] == len(sizes)
    jobs = part_jobs(r, work)
    assert [len(r.read(job / "input.json")["cases"]) for job in jobs] == sizes
    plan = r.read(work / "PARTS-PLAN.json")
    assert plan == r.seal(plan)
    for index, job in enumerate(jobs):
        payload = r.read(job / "input.json")
        assert payload["part_index"] == index
        assert payload["part_count"] == len(sizes)
        assert payload["parent_input_sha256"] == r.sha(work / "input.json")
        parts.validate_part_lineage(r, job)
        complete(r, job)
    assert parts.prepare_parts(r)["oracle_parts_prepared"] == 0
    assert parts.assemble_parts(r)["oracle_shards_assembled"] == 1
    output = r.validate_job(work)
    assert [c["case_id"] for c in output["oracles"]] == [c["case_id"] for c in r.read(work / "input.json")["cases"]]
    invocation = r.read(work / "INVOCATION.json")
    assert invocation["kind"] == "ORACLE_PART_ASSEMBLY"
    assert invocation["model"] == "NONE_MECHANICAL_ASSEMBLY"
    assert invocation["fresh_context"] is False and invocation["provider"] is None
    assert r.read(work / "COMPLETION.json")["validated_rows"] == count
    assert all(r.fs.files[path] == raw for path, raw in original.items())
    frozen = dict(r.fs.files)
    assert parts.assemble_parts(r)["oracle_assembly_skipped"] == 1
    assert parts.prepare_parts(r)["oracle_shards_skipped"] == 1
    assert r.fs.files == frozen
    assert all(isinstance(value, int) for value in prepared.values())
    assert not any(path.is_relative_to(r.PUBLIC) for path in r.fs.files)


def test_waits_for_every_completion_without_mutation(memory):
    r = memory
    work = seed(r)
    parts.prepare_parts(r)
    for job in part_jobs(r, work)[:-1]:
        complete(r, job)
    before = dict(r.fs.files)
    assert parts.assemble_parts(r)["oracle_shards_waiting"] == 1
    assert r.fs.files == before


@pytest.mark.parametrize("state", ["successful", "running", "orphan-output", "orphan-receipt", "orphan-parts", "local-parts"])
def test_original_jobs_and_orphans_are_never_overwritten(memory, state):
    r = memory
    work = seed(r)
    if state == "successful":
        complete(r, work)
    elif state == "running":
        r.write(work / "INVOCATION.json", {"synthetic_running": True})
    elif state == "orphan-output":
        r.write(work / "output.json", {"synthetic_partial": True})
    elif state == "orphan-receipt":
        r.write(r.PRIVATE / "receipts" / "oracle" / (work.name + ".json"), {})
    elif state == "orphan-parts":
        (r.PRIVATE / "oracle-parts" / (work.name + "-part-01")).mkdir(parents=True)
    else:
        (work / "parts").mkdir()
    before, dirs = dict(r.fs.files), set(r.fs.dirs)
    assert parts.prepare_parts(r)["oracle_shards_skipped"] == 1
    assert r.fs.files == before and r.fs.dirs == dirs and not r.fs.moves
    assert not r.validation_calls


@pytest.mark.parametrize("returncode,error", [(124, None), (0, "ValidationError")])
def test_failed_batch_preserved_with_raw_controls_and_protected_receipts(memory, returncode, error):
    r = memory
    work = seed(r)
    # Deliberately nonstandard whitespace proves recreation copies the raw bytes.
    payload = r.read(work / "input.json")
    r.fs.files[work / "input.json"] = json.dumps(payload, separators=(",", ":")).encode() + b"\n\n"
    complete(r, work, returncode=returncode, validation_error=error)
    r.write(work / "nested" / "partial-evidence.json", {"synthetic": "preserve all bytes"})
    before = dict(r.fs.files)
    result = parts.prepare_parts(r)
    assert result["oracle_failed_batches_preserved"] == 1
    assert result["oracle_parts_prepared"] == 6
    archive = r.PRIVATE / "oracle-batch-failure-preserved" / work.name
    hashes = r.read(archive / "HASH-INVENTORY.json")["files"]
    for name, expected in hashes.items():
        assert r.sha(archive / name) == expected
        source = work / name.removeprefix("canonical/") if name.startswith("canonical/") else r.PRIVATE / name
        assert r.fs.files[archive / name] == before[source]
    for name in ("input.json", "schema.json"):
        assert r.fs.files[work / name] == before[work / name]
    assert r.read(archive / "PRESERVATION-VERIFIED.json")["verified_files"] == len(hashes)
    assert not (work / "COMPLETION.json").exists()
    assert not (r.PRIVATE / "receipts" / "oracle" / (work.name + ".json")).exists()
    assert len(r.fs.moves) == 3
    for job in part_jobs(r, work):
        complete(r, job)
    assert parts.assemble_parts(r)["oracle_shards_assembled"] == 1
    parts.validate_assembly_lineage(r, work)
    assert all(r.sha(archive / name) == expected for name, expected in hashes.items())


def test_preservation_hash_mismatch_stops_before_recreation(memory, monkeypatch):
    r = memory
    work = seed(r)
    complete(r, work, returncode=124)
    original = MemoryPath.rename

    def corrupt_after_move(path, target):
        result = original(path, target)
        if target.name == "canonical":
            r.fs.files[target / "input.json"] += b" "
        return result

    monkeypatch.setattr(MemoryPath, "rename", corrupt_after_move)
    with pytest.raises(RuntimeError, match="inventory mismatch"):
        parts.prepare_parts(r)
    assert not work.exists()
    assert not part_jobs(r, work)
    assert (r.PRIVATE / "oracle-batch-failure-preserved" / work.name / "HASH-INVENTORY.json").exists()


@pytest.mark.parametrize("defect", ["timeout", "validation-error", "missing-output", "duplicate", "extra", "missing", "schema"])
def test_failed_part_is_terminal_without_fabricated_rows_or_resplit(memory, defect):
    r = memory
    work = seed(r)
    parts.prepare_parts(r)
    jobs = part_jobs(r, work)
    ids = [c["case_id"] for c in r.read(jobs[0] / "input.json")["cases"]]
    rows = [oracle(cid) for cid in ids]
    kwargs = {}
    if defect == "timeout":
        kwargs["returncode"] = 124
    elif defect == "validation-error":
        kwargs["validation_error"] = "ValidationError"
    elif defect == "missing-output":
        kwargs["no_output"] = True
    elif defect == "duplicate":
        rows[1] = rows[0]
    elif defect == "extra":
        rows.append(oracle("synthetic-extra"))
    elif defect == "missing":
        rows = rows[:1]
    elif defect == "schema":
        rows[0]["source_sufficient"] = "not a boolean"
    complete(r, jobs[0], rows=rows, **kwargs)
    for job in jobs[1:]:
        complete(r, job)
    before = dict(r.fs.files)
    assert parts.assemble_parts(r)["oracle_assembly_failures"] == 1
    assert not (work / "output.json").exists()
    assert r.read(work / "COMPLETION.json")["validated_rows"] == 0
    assert r.read(work / "ASSEMBLY-LINEAGE.json")["status"] == "FAILED"
    assert all(job in r.validation_calls for job in jobs)
    assert all(r.fs.files[path] == raw for path, raw in before.items())
    frozen = dict(r.fs.files)
    assert parts.prepare_parts(r)["oracle_shards_skipped"] == 1
    assert parts.assemble_parts(r)["oracle_assembly_skipped"] == 1
    assert r.fs.files == frozen and not r.fs.moves


@pytest.mark.parametrize("defect", ["question", "future-fact", "case-order", "as-of", "parent-hash", "part-index", "index-bool", "part-count", "schema", "plan-hash", "raw-author", "canonical-scenario", "extra-part"])
def test_part_lineage_rejects_tampering(memory, defect):
    r = memory
    work = seed(r)
    parts.prepare_parts(r)
    job = part_jobs(r, work)[0]
    payload = r.read(job / "input.json")
    if defect in ("question", "future-fact"):
        payload["cases"][0]["question" if defect == "question" else "follow_up"] = "Tampered synthetic content"
    elif defect == "case-order":
        payload["cases"].reverse()
    elif defect == "as-of":
        payload["as_of"] = "2099-01-01"
    elif defect == "parent-hash":
        payload["parent_input_sha256"] = "0" * 64
    elif defect == "part-index":
        payload["part_index"] = 1
    elif defect == "index-bool":
        payload["part_index"] = False
    elif defect == "part-count":
        payload["part_count"] = 99
    elif defect == "schema":
        replace(r, job / "schema.json", {})
    elif defect == "plan-hash":
        plan = r.read(work / "PARTS-PLAN.json")
        plan["parts"][0]["input_sha256"] = "0" * 64
        replace(r, work / "PARTS-PLAN.json", r.seal(plan))
    elif defect == "raw-author":
        r.fs.files[r.PRIVATE / "author" / work.name / "output.json"] += b" "
    elif defect == "canonical-scenario":
        canonical = r.read(work / "input.json")
        canonical["cases"][0]["question"] = "Tampered synthetic canonical"
        replace(r, work / "input.json", canonical)
    elif defect == "extra-part":
        (r.PRIVATE / "oracle-parts" / (work.name + "-part-99")).mkdir()
    if defect in {"question", "future-fact", "case-order", "as-of", "parent-hash", "part-index", "index-bool", "part-count"}:
        replace(r, job / "input.json", payload)
    with pytest.raises(RuntimeError):
        parts.validate_part_lineage(r, job)
    assert work not in r.validation_calls


@pytest.mark.parametrize("defect", ["row-content", "row-order", "part-raw-output", "lineage", "fake-model", "receipt", "completion"])
def test_assembly_revalidates_content_and_all_hashes(memory, defect):
    r = memory
    work = seed(r)
    parts.prepare_parts(r)
    jobs = part_jobs(r, work)
    for job in jobs:
        complete(r, job)
    parts.assemble_parts(r)
    if defect in ("row-content", "row-order"):
        value = r.read(work / "output.json")
        if defect == "row-content":
            value["oracles"][0]["construction_gaps"] = ["Tampered synthetic content"]
        else:
            value["oracles"].reverse()
        replace(r, work / "output.json", value)
        # Even a freshly forged complete receipt cannot prove the assembly.
        terminal = r.PRIVATE / "receipts" / "oracle" / (work.name + "-complete.json")
        value = r.read(terminal)
        value["output_sha256"] = r.sha(work / "output.json")
        replace(r, terminal, r.seal(value))
    elif defect == "part-raw-output":
        r.fs.files[jobs[0] / "output.json"] += b" "
    elif defect == "lineage":
        value = r.read(work / "ASSEMBLY-LINEAGE.json")
        value["parts"][0]["input_sha256"] = "0" * 64
        replace(r, work / "ASSEMBLY-LINEAGE.json", r.seal(value))
    elif defect == "fake-model":
        value = r.read(work / "INVOCATION.json")
        value["model"] = "CONFIGURED_DEFAULT"
        replace(r, work / "INVOCATION.json", value)
    elif defect == "receipt":
        replace(r, r.PRIVATE / "receipts" / "oracle" / (work.name + ".json"), {})
    elif defect == "completion":
        value = r.read(work / "COMPLETION.json")
        value["validated_rows"] = 0
        replace(r, work / "COMPLETION.json", value)
    with pytest.raises(RuntimeError):
        parts.validate_assembly_lineage(r, work)


@pytest.mark.parametrize("marker", ["BANK-SEAL.json", "ONE-PASS-START.json"])
def test_sealed_or_consumed_run_refused_before_private_reads(memory, marker):
    r = memory
    r.write(r.PUBLIC / marker, {})
    for operation in (parts.prepare_parts, parts.assemble_parts):
        with pytest.raises(RuntimeError, match="after seal"):
            operation(r)
    assert not r.fs.reads


def test_unassigned_or_external_paths_refused_before_read(memory):
    r = memory
    for work in (r.PRIVATE / "oracle-parts" / "../retired/shard-01-part-01",
                 r.PRIVATE / "retired" / "shard-01-part-01",
                 MemoryPath("/synthetic/other/private/oracle-parts/shard-01-part-01")):
        with pytest.raises(RuntimeError):
            parts.validate_part_lineage(r, work)
    assert not r.fs.reads


def test_symlink_refused_before_private_read(memory):
    r = memory
    work = seed(r)
    r.fs.symlinks.add(work)
    r.fs.reads.clear()
    with pytest.raises(RuntimeError, match="symlink"):
        parts.prepare_parts(r)
    assert not r.fs.reads


def test_interrupted_assembly_is_preserved_and_never_retried(memory, monkeypatch):
    r = memory
    work = seed(r)
    parts.prepare_parts(r)
    for job in part_jobs(r, work):
        complete(r, job)
    original = r.write

    def interrupted(path, value):
        if path == work / "ASSEMBLY-LINEAGE.json":
            raise OSError("synthetic interrupted write")
        original(path, value)

    monkeypatch.setattr(r, "write", interrupted)
    with pytest.raises(OSError, match="interrupted"):
        parts.assemble_parts(r)
    assert (work / "INVOCATION.json").exists()
    before = dict(r.fs.files)
    assert parts.assemble_parts(r)["oracle_assembly_skipped"] == 1
    assert r.fs.files == before
