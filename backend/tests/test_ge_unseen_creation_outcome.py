"""Synthetic in-memory tests; no runner import, bank IO, tmp files or cleanup.

Run with ``python -B -m unittest backend.tests.test_ge_unseen_creation_outcome``.
The injected runner implements the actual runner's read-only API and protected
input/output bindings. Oracle part plans use the existing pure plan verifier.
"""
from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import unittest
import sys
from pathlib import PurePosixPath
from typing import ClassVar
from types import SimpleNamespace

from scripts import ge_unseen_creation_outcome as outcome
from scripts import ge_unseen_oracle_parts as parts
from scripts import ge_unseen_source_repair as repair
from scripts import ge_unseen_preseal_repair as preseal
from scripts import ge_unseen_author_parts as authorparts
from unittest.mock import patch


def raw(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


class MemoryPath(PurePosixPath):
    def exists(self):
        return self in self.fs.files or self in self.fs.dirs

    def glob(self, pattern):
        return iter(sorted(path for path in self.fs.children.get(self, ())
                           if fnmatch.fnmatchcase(path.name, pattern)))

    def open(self, mode):
        assert mode == "rb", "filesystem writes must use create-only runner.write"
        if self not in self.fs.files:
            raise FileNotFoundError("PRIVATE MISSING FILE")
        return io.BytesIO(self.fs.files[self])


class Runner:
    RUN_ID = outcome.RUN_ID
    ORACLE_SCHEMA: ClassVar = {"synthetic_schema": "oracles"}
    AUTHOR_SCHEMA: ClassVar = {"key": "author"}
    DOMAIN_FAMILIES: ClassVar = {f"domain-{i:02d}": () for i in range(1, 36)}
    digest = staticmethod(outcome._digest)

    def __init__(self):
        # A distinct path class per test keeps its in-memory filesystem isolated.
        path_type = type("TestPath", (MemoryPath,), {"fs": self})
        self.ROOT = path_type("/synthetic/workspace")
        self.PRIVATE = self.ROOT / "restricted"
        self.PUBLIC = self.ROOT / "public"
        self.files, self.dirs, self.history = {}, set(), []
        self.children, self.descendants = {}, {}
        self.reads, self.validations, self.writes = [], [], []
        self.symlinks = set()

    def __getattr__(self, name):
        if name == "read_source_capture":
            raise AttributeError(name)  # Optional compatibility hook.
        raise AssertionError("unexpected runner API: " + name)

    def index(self, path):
        self.dirs.update(path.parents)
        for parent in path.parents:
            self.descendants.setdefault(parent, set()).add(path)
        for item in (path, *path.parents):
            if item != item.parent:
                self.children.setdefault(item.parent, set()).add(item)

    def safe_path(self, path):
        if (not isinstance(path, MemoryPath) or not path.is_relative_to(self.ROOT)
                or ".." in path.parts or any(p in self.symlinks for p in (path, *path.parents))):
            raise RuntimeError("PRIVATE ERROR CONTENT MUST NOT ESCAPE")

    def read(self, path):
        self.safe_path(path)
        self.reads.append(path)
        if path not in self.files:
            raise FileNotFoundError("PRIVATE MISSING FILE")
        return json.loads(self.files[path])

    def write(self, path, value):
        self.safe_path(path)
        if path.exists():
            raise FileExistsError("PRIVATE EXISTING FILE")
        self.index(path)
        self.files[path] = raw(value)
        self.writes.append(path)

    def sha(self, path):
        self.safe_path(path)
        if path not in self.files:
            raise FileNotFoundError("PRIVATE HASH ERROR")
        return hashlib.sha256(self.files[path]).hexdigest()

    def safe_files(self, directory):
        self.safe_path(directory)
        found = sorted(self.descendants.get(directory, ()))
        for path in found:
            self.safe_path(path)
        return found

    def seal(self, value):
        body = {k: v for k, v in value.items() if k != "content_sha256"}
        return {**body, "content_sha256": self.digest(body)}

    def coverage_slots(self):
        return [{"slot_id": f"{domain}:{i:02d}", "domain": domain, "family": "synthetic",
                 "country": "UK" if i <= 6 else "USA"}
                for domain in self.DOMAIN_FAMILIES for i in range(1, 13)]

    def system_slots(self):
        return [{"slot_id": f"system:{i:02d}", "domain": "SYSTEM", "family": "synthetic"}
                for i in range(1, 24)]

    @staticmethod
    def author_input(slots):
        return {"slots": slots}

    @staticmethod
    def validate_author_scope(cases, slots):
        if len(cases) != len(slots) or {c["case_id"] for c in cases} != {s["slot_id"] for s in slots}:
            raise ValueError("synthetic scope mismatch")

    @staticmethod
    def completion_recheckable(stage, completion):
        return completion["returncode"] == 0 and (
            completion.get("validation_error") is None
            or (stage == "author" and completion.get("validation_error") == "UKUSScopeError"))

    def validate_job(self, work):
        self.validations.append(work)
        stage = work.parent.name
        completion = self.read(work / "COMPLETION.json")
        if not self.completion_recheckable(stage, completion):
            raise RuntimeError("PRIVATE FAILED WORKER ISSUE")
        invocation = self.read(work / "INVOCATION.json")
        if invocation["input_sha256"] != self.sha(work / "input.json"):
            raise RuntimeError("PRIVATE INPUT MUTATION")
        protected = self.PRIVATE / "receipts" / stage / (work.name + ".json")
        receipt = self.read(protected)
        for name, expected in receipt["input_inventory"].items():
            if self.sha(work / name) != expected:
                raise RuntimeError("PRIVATE PROTECTED INPUT MUTATION")
        terminal = self.read(protected.with_name(work.name + "-complete.json"))
        if terminal["output_sha256"] != self.sha(work / "output.json"):
            raise RuntimeError("PRIVATE OUTPUT MUTATION")
        value = self.read(work / "output.json")
        payload = self.read(work / "input.json")
        expected = ({payload["case"]["case_id"]} if stage in ("fixture-inventory", "fixture-format") else
                    {s["slot_id"] for s in payload["slots"]} if "slots" in payload
                    else {c.get("case_id", c.get("case", {}).get("case_id")) for c in payload["cases"]})
        rows = [value] if outcome.STAGES[stage] is None else value[outcome.STAGES[stage]]
        if len(rows) != len(expected) or {row["case_id"] for row in rows} != expected:
            raise ValueError("PRIVATE COVERAGE ERROR")
        if stage == "oracle":
            author = self.PRIVATE / "author" / work.name
            if payload["scenario_frozen_sha256"] != self.sha(author / "output.json"):
                raise RuntimeError("PRIVATE ORACLE LINEAGE ERROR")
            self.validate_job(author)
            if invocation.get("kind") == "ORACLE_PART_ASSEMBLY":
                parts.validate_assembly_lineage(self, work)
        elif stage == "bank-review":
            for row in payload["cases"]:
                for source in ("author", "oracle"):
                    if row[source + "_output_sha256"] != self.sha(
                            self.PRIVATE / source / work.name / "output.json"):
                        raise RuntimeError("PRIVATE REVIEW LINEAGE ERROR")
        elif stage == "oracle-parts":
            parts.validate_part_lineage(self, work)
        elif stage == "author-parts":
            authorparts.validate_part_lineage(self, work)
        elif stage == "author" and invocation.get("kind") == "AUTHOR_PART_ASSEMBLY":
            authorparts.validate_assembly_lineage(self, work)
        elif stage in ("oracle-repair", "bank-review-repair"):
            preseal.validate_lineage(self, work)
        return value

    def collect(self, stage, key):
        rows = []
        for work in sorted((self.PRIVATE / stage).glob("shard-*")):
            if not (work / "COMPLETION.json").exists():
                continue
            try:
                rows.extend(self.validate_job(work)[key])
            except Exception:
                continue
        return preseal.effective_rows(self, stage, rows)

    def alter(self, path, value=None, *, data=None):
        """Simulate adversarial changes in memory; retain every prior byte value."""
        self.history.append((path, self.files.get(path)))
        self.index(path)
        self.files[path] = raw(value) if data is None else data


def job(r, stage, shard, payload, rows, *, failed=False, active=False):
    work = r.PRIVATE / stage / shard
    r.write(work / "input.json", payload)
    schema = (r.ORACLE_SCHEMA if stage.startswith("oracle") else
              r.AUTHOR_SCHEMA if stage.startswith("author") else {"key": stage})
    r.write(work / "schema.json", schema)
    finish(r, work, rows, failed=failed, active=active)
    return work


def finish(r, work, rows, *, failed=False, active=False):
    stage = work.parent.name
    r.write(work / "INVOCATION.json", {"input_sha256": r.sha(work / "input.json"),
                                      "prompt_sha256": r.digest("synthetic prompt")})
    protected = r.PRIVATE / "receipts" / stage / (work.name + ".json")
    r.write(protected, {"work": work.relative_to(r.PRIVATE).as_posix(),
                       "input_sha256": r.sha(work / "input.json"), "schema_sha256": r.sha(work / "schema.json"),
                       "prompt_sha256": r.digest("synthetic prompt"),
                       "input_inventory": {name: r.sha(work / name)
                                            for name in ("input.json", "schema.json", "INVOCATION.json")}})
    r.write(work / "output.json", rows[0] if outcome.STAGES[stage] is None else {outcome.STAGES[stage]: rows})
    if active:
        return
    complete = {"returncode": 1 if failed else 0, "validation_error": None,
                "validated_rows": len(rows), "stage": stage, "shard": work.name, "output_present": True}
    r.write(protected.with_name(work.name + "-complete.json"), {
        **complete, "output_sha256": r.sha(work / "output.json")})
    r.write(work / "COMPLETION.json", complete)


URL = "https://synthetic.invalid/PRIVATE-SOURCE-URL"
PRIVATE_TEXT = "PRIVATE QUESTION ANSWER SOURCE ISSUE TEXT"


def oracle(cid):
    return {"case_id": cid, "source_sufficient": True, "currentness_status": "VERIFIED",
            "construction_gaps": [], "required_points": [{"point": PRIVATE_TEXT, "source_urls": [URL]}],
            "sources": [{"url": URL, "quote": PRIVATE_TEXT, "currentness_check_urls": [URL]}],
            "system_assertions": [PRIVATE_TEXT] if cid.startswith("system:") else []}


def review(cid):
    return {"case_id": cid, **dict.fromkeys(outcome.REVIEW_CHECKS, True), "issues": [],
            "required_point_checks": [{"point": PRIVATE_TEXT, "supported": True, "reason": PRIVATE_TEXT}]}


def review_stage(r, work, *, active=False, edit=None):
    payload = r.read(work / "input.json")
    enriched = payload["cases"]
    for i, case in enumerate(enriched, 1):
        path = r.PRIVATE / "fixtures" / work.name / f"case-{i:02d}" / "UPLOAD-MANIFEST.json"
        r.write(path, {"case_id": case["case_id"], "raw_case_sha256": r.digest(case),
                       "files": [], "extraction": []})
    reviews = [review(c["case_id"]) for c in enriched]
    if edit:
        edit(reviews[0])
    author = r.PRIVATE / "author" / work.name
    job(r, "bank-review", work.name, {"cases": [{"case": c,
        "author_output_sha256": r.sha(author / "output.json"),
        "oracle_output_sha256": r.sha(work / "output.json")} for c in enriched]}, reviews, active=active)


def seed(*, failed_author=(), failed_oracle=(), absent_review=(), active=(), partition=(),
         failed_part=(), pending_part=(), reviewer_edit=None, oracle_edit=None,
         author_partition=(), pending_author_part=(), failed_author_part=(), first_upload=False):
    r = Runner()
    source = r.PRIVATE / "sources" / hashlib.sha256(URL.encode()).hexdigest()
    r.alter(source.with_suffix(".bytes"), data=PRIVATE_TEXT.encode())
    r.write(source.with_suffix(".json"), {"url": URL, "status": "CAPTURED_NOT_LEGAL_VERIFIED",
                                         "raw_sha256": r.sha(source.with_suffix(".bytes")),
                                         "text": PRIVATE_TEXT, "text_sha256": r.digest(PRIVATE_TEXT)})
    for number in range(1, 37):
        shard = f"shard-{number:02d}"
        slots = ([s for s in r.coverage_slots() if s["domain"] == f"domain-{number:02d}"]
                 if number <= 35 else r.system_slots())
        cases = [{"case_id": s["slot_id"], "question": PRIVATE_TEXT, "follow_up": PRIVATE_TEXT,
                  "uploads": []} for s in slots]
        if first_upload and number == 1:
            cases[0]["uploads"] = [{"title": "synthetic upload"}]
        if number in author_partition:
            author_partition_job(r, shard, slots, cases,
                                 pending=[i for n,i in pending_author_part if n==number],
                                 failed=[i for n,i in failed_author_part if n==number])
            continue
        author = job(r, "author", shard, {"slots": slots}, cases,
                     failed=number in failed_author, active=("author", number) in active)
        if number in failed_author or ("author", number) in active:
            continue
        enriched = [{**case, "family": s["family"], "domain": s["domain"]}
                    for case, s in zip(cases, slots, strict=True)]
        payload = {"as_of": "2026-09-05", "cases": enriched,
                   "scenario_frozen_sha256": r.sha(author / "output.json")}
        oracles = [oracle(c["case_id"]) for c in cases]
        if oracle_edit and number == 1:
            oracle_edit(oracles[0])
        if number in partition:
            work = r.PRIVATE / "oracle" / shard
            r.write(work / "input.json", payload)
            r.write(work / "schema.json", r.ORACLE_SCHEMA)
            count = (len(cases) + 1) // 2
            for i in range(count):
                part = r.PRIVATE / "oracle-parts" / f"{shard}-part-{i + 1:02d}"
                r.write(part / "input.json", parts._part_input(r, work, payload, i, count))
                r.write(part / "schema.json", r.ORACLE_SCHEMA)
                if (number, i + 1) not in pending_part:
                    finish(r, part, oracles[i * 2:(i + 1) * 2], failed=(number, i + 1) in failed_part,
                           active=("oracle-parts", number, i + 1) in active)
            r.write(work / "PARTS-PLAN.json", parts._plan(r, work, payload))
            continue
        work = job(r, "oracle", shard, payload, oracles, failed=number in failed_oracle,
                   active=("oracle", number) in active)
        if number in failed_oracle or ("oracle", number) in active:
            continue
        if number in absent_review:
            continue
        review_stage(r, work, active=("bank-review", number) in active,
                     edit=reviewer_edit if number == 1 else None)
    return r


def author_partition_job(r, shard, slots, cases, *, pending=(), failed=()):
    work = r.PRIVATE / "author" / shard
    r.write(work / "input.json", r.author_input(slots))
    r.write(work / "schema.json", r.AUTHOR_SCHEMA)
    archive = r.PRIVATE / "author-batch-failure-preserved" / shard
    for name in ("input.json", "schema.json"):
        r.write(archive / "canonical" / name, r.read(work / name))
    r.write(archive / "canonical/COMPLETION.json", {
        "stage": "author", "shard": shard, "returncode": 1, "validation_error": None})
    files = {p.relative_to(archive).as_posix(): r.sha(p) for p in r.safe_files(archive)}
    r.write(archive / "HASH-INVENTORY.json", r.seal({"files": files}))
    r.write(archive / "PRESERVATION-VERIFIED.json", r.seal({
        "inventory_sha256": r.sha(archive / "HASH-INVENTORY.json"),
        "verified_files": len(files), "bytes_unchanged": True}))
    payload = r.read(work / "input.json")
    for i, part in enumerate(authorparts._paths(r, work)):
        r.write(part / "input.json", authorparts._part_input(r, work, payload, i))
        r.write(part / "schema.json", r.AUTHOR_SCHEMA)
        if i+1 not in pending:
            finish(r, part, cases[i*2:(i+1)*2], failed=i+1 in failed)
    r.write(work / "PARTS-PLAN.json", authorparts._plan(r, work, payload))
    return work


def targeted_job(r, *, stage="oracle-repair", state="complete", edit=None, shard="shard-01", number=1):
    cases, oracles, reviews = preseal.original_records(r, shard)
    case = cases[number-1]
    cid = case["case_id"]
    name = f"{shard}-case-{number:02d}"
    binding = {"parent_shard": shard, "case_number": number,
               "author_output_sha256": r.sha(r.PRIVATE / "author" / shard / "output.json"),
               "oracle_output_sha256": r.sha(r.PRIVATE / "oracle" / shard / "output.json"),
               "review_output_sha256": r.sha(r.PRIVATE / "bank-review" / shard / "output.json")}
    if stage == "oracle-repair":
        payload = {**binding, "cases": [case], "original_oracle": oracles[cid],
                   "construction_review": reviews[cid], "repair_attempt": 1, "no_second_repair": True,
                   "question_sha256": r.digest(case["question"]), "query_budget": 4,
                   "new_source_capture_budget": 8, "evidence": [{"url": URL}]}
        row = oracle(cid)
    else:
        research = r.PRIVATE / "oracle-repair" / name
        fixed = r.validate_job(research)["oracles"][0] if (research / "COMPLETION.json").exists() else oracles[cid]
        directory = preseal.fixture_directory(r, shard, number)
        payload = {**binding, "cases": [{"case": case, "oracle": fixed}],
                   "repaired_oracle_output_sha256": r.sha(research / "output.json") if research.exists() else None,
                   "fixture_manifest_sha256": r.sha(directory / "UPLOAD-MANIFEST.json"),
                   "fresh_reviewer_no_prior_recommendations": True}
        row = review(cid)
    if edit:
        edit(row)
    work = r.PRIVATE / stage / name
    r.write(work / "input.json", payload)
    r.write(work / "schema.json", r.ORACLE_SCHEMA if stage == "oracle-repair" else {"key": stage})
    if state != "pending":
        finish(r, work, [row], failed=state == "failed", active=state == "active")
    return work


class OutcomeTests(unittest.TestCase):
    def assert_denominator(self, value):
        self.assertEqual(value["denominators"], {"legal": 420, "system": 23, "total": 443})
        for kind, expected in (("legal", 420), ("system", 23)):
            self.assertEqual(sum(value["cases"][kind]["categories"].values()), expected)
            self.assertEqual(value["cases"][kind]["ready"] + value["cases"][kind]["not_ready"], expected)

    def test_all_ready_is_non_authorizing_and_inspection_is_read_only(self):
        r = seed()
        before = dict(r.files)
        result = outcome.inspect_outcome(r)
        self.assertEqual(r.files, before)
        self.assertTrue(result["terminal"])
        self.assertTrue(result["construction_ready"])
        self.assertEqual(result["cases"]["legal"]["ready"], 420)
        self.assertEqual(result["cases"]["system"]["ready"], 23)
        self.assertEqual(result["confirmed_checks"], dict.fromkeys(
            ("authored", "oracle", "sources", "fixtures", "reviewer"), 443))
        for flag in ("authorizing", "bank_sealed", "candidate_executed", "training", "scoring_performed"):
            self.assertIs(result[flag], False)
        self.assert_denominator(result)
        encoded = json.dumps(result)
        for forbidden in (PRIVATE_TEXT, URL, "domain-01", str(r.PRIVATE), "system:01"):
            self.assertNotIn(forbidden, encoded)

    def test_accepted_full_plan_requires_actual_novelty_review_even_when_other_checks_pass(self):
        r = seed()
        r.write(r.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json", {"synthetic_plan": True})
        before = dict(r.files)
        result = outcome.inspect_outcome(r)
        self.assertEqual(r.files, before)
        self.assertTrue(result["terminal"])
        self.assertFalse(result["construction_ready"])
        self.assertEqual(result["novelty_review"], {"required": True, "passed_cases": 0, "denominator": 443})
        self.assertEqual(result["cases"]["legal"]["ready"], 0)
        self.assertEqual(result["cases"]["system"]["ready"], 0)
        self.assert_denominator(result)

    def test_reviewer_exact_true_empty_issues_and_exact_point_coverage(self):
        edits = [lambda row: row.update(ready=1), lambda row: row.update(issues=[PRIVATE_TEXT]),
                 lambda row: row.update(required_point_checks=[]),
                 lambda row: row["required_point_checks"].append(dict(row["required_point_checks"][0])),
                 lambda row: row["required_point_checks"][0].update(supported="true"),
                 lambda row: row.update(currentness_verified=None)]
        for edit in edits:
            with self.subTest(edit=edits.index(edit)):
                result = outcome.inspect_outcome(seed(reviewer_edit=edit))
                self.assertTrue(result["terminal"])
                self.assertFalse(result["construction_ready"])
                self.assertEqual(result["cases"]["legal"]["ready"], 419)
                self.assertEqual(result["cases"]["legal"]["categories"]["review_hold"], 1)
                self.assert_denominator(result)

    def test_oracle_flags_cannot_be_overridden_by_ready_reviewer(self):
        for edit in (lambda o: o.update(source_sufficient=1),
                     lambda o: o.update(currentness_status="UNRESOLVED"),
                     lambda o: o.update(construction_gaps=[PRIVATE_TEXT])):
            result = outcome.inspect_outcome(seed(oracle_edit=edit))
            self.assertEqual(result["cases"]["legal"]["categories"]["oracle_hold"], 1)
            self.assertTrue(result["terminal"])

    def test_absent_authors_keep_full_denominator_and_are_not_terminal(self):
        r = Runner()
        result = outcome.publish_outcome(r)
        self.assertEqual(result["status"], "NOT_TERMINAL")
        self.assertEqual(result["outcome"]["author_shards_completed"], 0)
        self.assertFalse(r.files)
        self.assert_denominator(result["outcome"])

    def test_failed_authors_do_not_wait_for_nonexistent_downstream_jobs(self):
        for failures, expected in (((1,), 408), (tuple(range(1, 37)), 0)):
            with self.subTest(failures=len(failures)):
                result = outcome.inspect_outcome(seed(failed_author=failures))
                self.assertTrue(result["terminal"])
                self.assertEqual(result["author_shards_completed"], 36)
                self.assertEqual(result["stages"]["author"]["failed"], len(failures))
                self.assertEqual(result["cases"]["legal"]["ready"], expected)
                self.assert_denominator(result)

    def test_failed_canonical_oracle_does_not_require_review_attempt(self):
        result = outcome.inspect_outcome(seed(failed_oracle=(1,)))
        self.assertTrue(result["terminal"])
        self.assertEqual(result["stages"]["bank-review"]["upstream_held"], 1)
        self.assertEqual(result["cases"]["legal"]["categories"]["oracle_unavailable"], 12)

    def test_drained_parts_do_not_wait_for_uninvoked_canonical_assembly(self):
        for failed in ((), ((1, 1),)):
            with self.subTest(failed=bool(failed)):
                r = seed(partition=(1,), failed_part=failed)
                result = outcome.inspect_outcome(r)
                self.assertTrue(result["terminal"])
                self.assertFalse(result["construction_ready"])
                self.assertEqual(result["stages"]["oracle-parts"]["completed"], 6)
                self.assertEqual(result["stages"]["oracle-parts"]["failed"], len(failed))
                self.assertEqual(result["cases"]["legal"]["ready"], 408)
                self.assertEqual(result["unassembled_drained_plans"], 0 if failed else 1)
                self.assertFalse((r.PRIVATE / "oracle/shard-01/INVOCATION.json").exists())

    def test_failed_part_does_not_hide_runnable_pending_siblings(self):
        result = outcome.publish_outcome(seed(partition=(1,), failed_part=((1, 1),), pending_part=((1, 2),)))
        self.assertEqual(result["status"], "NOT_TERMINAL")
        self.assertEqual(result["outcome"]["stages"]["oracle-parts"]["pending"], 1)

    def test_validated_real_parts_assembly_can_be_all_ready(self):
        r = seed(partition=(1,))
        self.assertEqual(parts.assemble_parts(r)["oracle_shards_assembled"], 1)
        review_stage(r, r.PRIVATE / "oracle/shard-01")
        result = outcome.inspect_outcome(r)
        self.assertTrue(result["construction_ready"])
        self.assertEqual(result["stages"]["oracle-parts"]["validated_rows"], 12)

    def test_missing_healthy_review_is_pending(self):
        result = outcome.inspect_outcome(seed(absent_review=(1,)))
        self.assertFalse(result["terminal"])
        self.assertEqual(result["stages"]["bank-review"]["pending"], 1)

    def test_any_active_job_blocks_publication_including_assembly_and_unexpected_job(self):
        for stage in ("author", "oracle", "bank-review", "oracle-parts", "unexpected"):
            with self.subTest(stage=stage):
                if stage == "oracle-parts":
                    r = seed(partition=(1,), active=((stage, 1, 1),))
                elif stage == "unexpected":
                    r = seed()
                    r.write(r.PRIVATE / "oracle-parts/shard-99-part-01/INVOCATION.json", {})
                else:
                    r = seed(active=((stage, 1),))
                result = outcome.publish_outcome(r)
                self.assertEqual(result["status"], "NOT_TERMINAL")
                self.assertEqual(result["outcome"]["active_jobs"], 1)
                self.assertFalse((r.PUBLIC / outcome.RECEIPT_NAME).exists())

    def test_active_mechanical_assembly_remains_active_after_parts_finish(self):
        r = seed(partition=(1,))
        r.write(r.PRIVATE / "oracle/shard-01/INVOCATION.json", {"kind": "ORACLE_PART_ASSEMBLY"})
        self.assertEqual(outcome.publish_outcome(r)["status"], "NOT_TERMINAL")

    def test_malformed_completed_job_is_counted_failed_and_does_not_leak_exception(self):
        r = seed()
        r.alter(r.PRIVATE / "author/shard-01/COMPLETION.json", data=b"not JSON " + PRIVATE_TEXT.encode())
        result = outcome.inspect_outcome(r)
        self.assertTrue(result["terminal"])
        self.assertEqual(result["stages"]["author"]["failed"], 1)
        self.assertEqual(result["cases"]["legal"]["ready"], 408)
        self.assertNotIn(PRIVATE_TEXT, json.dumps(result))

    def test_failed_capture_and_fixture_failures_can_hold_absent_review(self):
        for category in ("sources", "fixtures"):
            with self.subTest(category=category):
                r = seed(absent_review=(1,))
                if category == "sources":
                    key = hashlib.sha256(URL.encode()).hexdigest()
                    r.alter(r.PRIVATE / "sources" / (key + ".json"), {"status": "CAPTURE_HOLD"})
                else:
                    r.write(r.PRIVATE / "fixtures/shard-01/case-01/FIXTURE-FAILURE.json", {"error": PRIVATE_TEXT})
                result = outcome.inspect_outcome(r)
                self.assertTrue(result["terminal"])
                self.assertEqual(result["stages"]["bank-review"]["upstream_held"], 1)

    def test_source_bytes_quote_and_currentness_capture_are_required(self):
        edits = [lambda o: o["sources"][0].update(quote="MISSING QUOTE"),
                 lambda o: o["sources"][0].update(currentness_check_urls=[URL + "/MISSING"]),
                 lambda o: o["required_points"][0].update(source_urls=[])]
        for edit in edits:
            result = outcome.inspect_outcome(seed(oracle_edit=edit))
            self.assertEqual(result["cases"]["legal"]["categories"]["source_hold"], 1)
        r = seed()
        key = hashlib.sha256(URL.encode()).hexdigest()
        r.alter(r.PRIVATE / "sources" / (key + ".bytes"), data=b"MUTATED")
        self.assertFalse(outcome.inspect_outcome(r)["construction_ready"])

    def test_several_locators_on_one_page_each_require_their_exact_quote(self):
        r = seed()
        value = oracle("synthetic")
        value["sources"].append({**value["sources"][0], "locator": "another paragraph"})
        self.assertEqual(outcome._source_checks(r, value), (True, False))
        value["sources"][1]["quote"] = "unsupported second locator"
        self.assertEqual(outcome._source_checks(r, value), (False, True))

    def test_publish_create_only_hash_inventory_and_identical_no_op(self):
        r = seed()
        original = dict(r.files)
        first = outcome.publish_outcome(r)
        self.assertEqual(first["status"], "CREATED")
        self.assertEqual(set(r.files) - set(original), {r.PUBLIC / outcome.RECEIPT_NAME})
        self.assertTrue(all(r.files[path] == value for path, value in original.items()))
        entries = [{"path_sha256": r.digest(path.relative_to(r.PRIVATE).as_posix()),
                    "raw_sha256": r.sha(path)} for path in original
                   if path.is_relative_to(r.PRIVATE / "author")]
        entries.sort(key=lambda entry: entry["path_sha256"])
        self.assertEqual(first["outcome"]["input_inventories"]["author"], {
            "files": len(entries), "inventory_sha256": r.digest(entries)})
        before = dict(r.files)
        self.assertEqual(outcome.publish_outcome(r)["status"], "NO_OP")
        self.assertEqual(r.files, before)

    def test_raw_output_and_completion_mutations_conflict_even_with_same_json(self):
        for filename in ("output.json", "COMPLETION.json", "input.json"):
            with self.subTest(filename=filename):
                r = seed()
                outcome.publish_outcome(r)
                saved = r.files[r.PUBLIC / outcome.RECEIPT_NAME]
                path = r.PRIVATE / "author/shard-01" / filename
                r.alter(path, data=r.files[path] + b" ")
                with self.assertRaisesRegex(outcome.OutcomeError, "IDENTITY_MISMATCH"):
                    outcome.publish_outcome(r)
                self.assertEqual(r.files[r.PUBLIC / outcome.RECEIPT_NAME], saved)

    def test_receipt_tampering_wrong_run_and_partial_json_never_overwrite(self):
        for alteration in ("hash", "run", "malformed"):
            with self.subTest(alteration=alteration):
                r = seed()
                outcome.publish_outcome(r)
                path = r.PUBLIC / outcome.RECEIPT_NAME
                saved = r.read(path)
                if alteration == "hash":
                    saved["content_sha256"] = "0" * 64
                    r.alter(path, saved)
                elif alteration == "run":
                    saved["run_id"] = "different"
                    r.alter(path, r.seal(saved))
                else:
                    r.alter(path, data=b"{")
                before = r.files[path]
                with self.assertRaises(outcome.OutcomeError):
                    outcome.publish_outcome(r)
                self.assertEqual(r.files[path], before)

    def test_mutation_during_inspection_is_rejected(self):
        r = seed()
        validate = r.validate_job
        changed = False

        def mutating(work):
            nonlocal changed
            value = validate(work)
            if not changed:
                changed = True
                path = work / "COMPLETION.json"
                r.alter(path, data=r.files[path] + b" ")
            return value

        r.validate_job = mutating
        with self.assertRaisesRegex(outcome.OutcomeError, "INPUTS_CHANGED_DURING_INSPECTION"):
            outcome.publish_outcome(r)
        self.assertFalse((r.PUBLIC / outcome.RECEIPT_NAME).exists())

    def test_concurrent_identical_creation_verifies_winner(self):
        r = seed()
        write = r.write

        def racing(path, value):
            write(path, value)
            raise FileExistsError("synthetic concurrent winner")

        r.write = racing
        self.assertEqual(outcome.publish_outcome(r)["status"], "NO_OP")

    def test_scope_and_seal_guard_are_non_authorizing(self):
        for marker in ("BANK-SEAL.json", "ONE-PASS-START.json", "RUN-FREEZE.json"):
            r = Runner()
            r.write(r.PUBLIC / marker, {})
            with self.assertRaisesRegex(outcome.OutcomeError, "PRESEAL"):
                outcome.inspect_outcome(r)
            self.assertFalse(r.reads)
        r = Runner()
        r.RUN_ID = "different"
        with self.assertRaisesRegex(outcome.OutcomeError, "RUN_ID_MISMATCH"):
            outcome.inspect_outcome(r)
        r = Runner()
        r.coverage_slots = lambda: []
        with self.assertRaisesRegex(outcome.OutcomeError, "DENOMINATOR_MISMATCH"):
            outcome.inspect_outcome(r)

    def test_hash_io_errors_are_sanitized_and_never_publish(self):
        r = seed()
        r.sha = lambda path: (_ for _ in ()).throw(RuntimeError(PRIVATE_TEXT))
        with self.assertRaises(outcome.OutcomeError) as caught:
            outcome.publish_outcome(r)
        self.assertEqual(str(caught.exception), "OUTCOME_INSPECTION_FAILED")
        self.assertFalse((r.PUBLIC / outcome.RECEIPT_NAME).exists())

    def test_effective_capture_hook_accepts_bound_repairs_without_granting_currentness(self):
        r = seed()
        directory = r.PRIVATE / "sources"
        key = hashlib.sha256(URL.encode()).hexdigest()
        original_path = directory / (key + ".json")
        original = {"url": URL, "source_id": key, "status": "CAPTURE_HOLD",
                    "error_message": "XML_DTD_FORBIDDEN", "text": ""}
        r.alter(original_path, original)
        original_bytes = r.files[original_path]
        r.is_allowed_source_url = lambda url: url == URL
        r.redirect_allowed = lambda source, target: source == target == URL
        binding = repair._binding(key, "REEXTRACT_SAVED_RAW", r.sha(original_path),
                                  r.sha(directory / (key + ".bytes")))
        r.write(directory / (key + ".repair-attempt.json"), binding)
        corrected = repair._correction(r, original, key, PRIVATE_TEXT,
                                       binding["original_raw_sha256"], URL, binding)
        r.write(directory / (key + ".repair.json"), corrected)
        self.assertFalse(outcome._source_checks(r, oracle("synthetic"))[0])
        r.read_source_capture = lambda directory, key: repair.read_capture(r, directory, key)
        result = outcome.publish_outcome(r)
        self.assertTrue(result["outcome"]["construction_ready"])
        self.assertEqual(result["outcome"]["input_inventories"]["sources"]["files"], 4)
        held_oracle = oracle("synthetic")
        held_oracle["currentness_status"] = "UNRESOLVED"
        self.assertTrue(outcome._source_checks(r, held_oracle)[0])
        self.assertFalse(outcome._oracle_ready(held_oracle, False))
        self.assertEqual(r.files[original_path], original_bytes)
        corrected["transport_repair"]["prior_receipt_sha256"] = "0" * 64
        r.alter(directory / (key + ".repair.json"), corrected)
        self.assertFalse(outcome._source_checks(r, oracle("synthetic"))[0])
        with self.assertRaisesRegex(outcome.OutcomeError, "IDENTITY_MISMATCH"):
            outcome.publish_outcome(r)

    def test_fixture_checks_bind_uploaded_bytes_and_extraction_and_reject_traversal(self):
        r = Runner()
        directory = r.PRIVATE / "fixtures/shard-01/case-01"
        target = directory / "synthetic.pdf"
        r.alter(target, data=b"synthetic uploaded bytes")
        sha = r.sha(target)
        case = {"case_id": "synthetic", "uploads": [{}]}
        manifest = {"case_id": "synthetic", "raw_case_sha256": r.digest(case),
                    "files": [{"relative_path": "synthetic.pdf", "sha256": sha, "page_count": 1}],
                    "extraction": [{"path": "synthetic.pdf", "file_sha256": sha,
                                    "error": None, "page_count": 1, "pages": [{
                                        "error": None, "file_sha256": sha, "page_number": 1,
                                        "text": PRIVATE_TEXT, "text_sha256": hashlib.sha256(
                                            PRIVATE_TEXT.encode()).hexdigest()}]}]}
        path = directory / "UPLOAD-MANIFEST.json"
        r.write(path, manifest)
        self.assertEqual(outcome._fixture_checks(r, "shard-01", 1, case), (True, False))
        r.alter(target, data=b"changed synthetic bytes")
        self.assertEqual(outcome._fixture_checks(r, "shard-01", 1, case), (False, True))
        manifest["files"][0]["relative_path"] = "../../forbidden"
        r.alter(path, manifest)
        r.sha = lambda path: self.fail("traversal must fail before file hashing")
        self.assertEqual(outcome._fixture_checks(r, "shard-01", 1, case), (False, True))

    def test_input_only_repair_is_pending_without_requiring_output_or_rewriting_original(self):
        r = seed(oracle_edit=lambda row: row.update(source_sufficient=False))
        before = dict(r.files)
        work = targeted_job(r, state="pending")
        result = outcome.publish_outcome(r)
        self.assertEqual(result["status"], "NOT_TERMINAL")
        self.assertEqual(result["outcome"]["stages"]["oracle-repair"]["pending"], 1)
        self.assertEqual(result["outcome"]["lineage"]["invalid_repair_plans_or_renders"], 0)
        self.assertFalse((work / "output.json").exists())
        self.assertFalse(any(p == work / "output.json" for p in r.reads))
        self.assertTrue(all(r.files[p] == value for p,value in before.items()))
        self.assert_denominator(result["outcome"])

    def test_active_repair_and_rereview_block_terminal_publication(self):
        for stage in ("oracle-repair", "bank-review-repair"):
            with self.subTest(stage=stage):
                r = seed(oracle_edit=lambda row: row.update(source_sufficient=False))
                if stage == "bank-review-repair":
                    targeted_job(r)
                targeted_job(r, stage=stage, state="active")
                value = outcome.publish_outcome(r)
                self.assertEqual(value["status"], "NOT_TERMINAL")
                self.assertEqual(value["outcome"]["stages"][stage]["active"], 1)
                self.assert_denominator(value["outcome"])

    def test_validated_oracle_repair_requires_a_fresh_review_and_counts_each_case_once(self):
        r = seed(oracle_edit=lambda row: row.update(source_sufficient=False))
        originals = dict(r.files)
        targeted_job(r)
        value = outcome.inspect_outcome(r)
        self.assertFalse(value["terminal"])
        self.assertEqual(value["effective_rows"], {"oracles": 443, "reviews": 442})
        self.assertEqual(value["stages"]["bank-review-repair"]["pending"], 1)
        self.assertEqual(value["cases"]["legal"]["ready"], 419)
        targeted_job(r, stage="bank-review-repair")
        repaired = outcome.inspect_outcome(r)
        self.assertTrue(repaired["construction_ready"])
        self.assertEqual(repaired["effective_rows"], {"oracles": 443, "reviews": 443})
        self.assertEqual(repaired["confirmed_checks"]["reviewer"], 443)
        self.assertTrue(all(r.files[p] == value for p,value in originals.items()))
        self.assert_denominator(repaired)

    def test_repair_or_fresh_review_hold_is_terminal_and_case_local(self):
        for stage in ("oracle-repair", "bank-review-repair"):
            with self.subTest(stage=stage):
                r = seed(oracle_edit=lambda row: row.update(source_sufficient=False))
                if stage == "oracle-repair":
                    targeted_job(r, state="failed")
                else:
                    targeted_job(r)
                    targeted_job(r, stage=stage, edit=lambda row: row.update(ready=False, issues=[PRIVATE_TEXT]))
                result = outcome.inspect_outcome(r)
                self.assertTrue(result["terminal"])
                self.assertFalse(result["construction_ready"])
                self.assertEqual(result["cases"]["legal"]["ready"], 419)
                self.assertEqual(result["cases"]["system"]["ready"], 23)
                self.assert_denominator(result)

    def test_broken_fixture_blocks_only_its_rereview_without_endless_polling(self):
        r = seed(oracle_edit=lambda row: row.update(source_sufficient=False),
                 reviewer_edit=lambda row: row.update(fixtures_valid=False), first_upload=True)
        targeted_job(r)
        result = outcome.inspect_outcome(r)
        self.assertTrue(result["terminal"])
        self.assertEqual(result["stages"]["bank-review-repair"]["upstream_held"], 1)
        self.assertEqual(result["stages"]["bank-review-repair"]["pending"], 0)
        self.assertEqual(result["cases"]["legal"]["ready"], 419)

    def test_changed_question_or_output_never_becomes_effective_repair(self):
        for defect in ("question", "output"):
            with self.subTest(defect=defect):
                r = seed(oracle_edit=lambda row: row.update(source_sufficient=False))
                work = targeted_job(r)
                if defect == "question":
                    payload = r.read(work / "input.json")
                    payload["cases"][0]["question"] += " changed"
                    r.alter(work / "input.json", payload)
                else:
                    r.alter(work / "output.json", {"oracles": [oracle("different case")]})
                result = outcome.inspect_outcome(r)
                self.assertTrue(result["terminal"])
                self.assertFalse(result["construction_ready"])
                self.assertEqual(result["stages"]["oracle-repair"]["failed"], 1)
                self.assertEqual(result["cases"]["legal"]["ready"], 419)
                self.assertNotIn(PRIVATE_TEXT, json.dumps(result))

    def test_collect_stale_original_review_cannot_approve_changed_oracle(self):
        r = seed(oracle_edit=lambda row: row.update(source_sufficient=False))
        targeted_job(r)
        collect = r.collect
        def stale(stage, key):
            if stage == "bank-review":
                return [row for work in (r.PRIVATE / stage).glob("shard-*")
                        for row in r.validate_job(work)[key]]
            return collect(stage,key)
        r.collect = stale
        result = outcome.inspect_outcome(r)
        self.assertEqual(result["effective_rows"]["reviews"], 442)
        self.assertEqual(result["cases"]["legal"]["ready"], 419)
        self.assertFalse(result["lineage"]["effective_reviews_validated"])

    def test_author_parts_pending_and_drained_plans_use_real_public_lineage_verifier(self):
        r = seed(author_partition=(1,), pending_author_part=((1,2),), failed_author_part=((1,1),))
        before = dict(r.files)
        with patch.object(authorparts,"checked_plan", wraps=authorparts.checked_plan) as checked:
            value = outcome.inspect_outcome(r)
        self.assertTrue(checked.called)
        self.assertFalse(value["terminal"])
        self.assertEqual(value["stages"]["author-parts"]["pending"], 1)
        self.assertEqual(value["stages"]["author-parts"]["failed"], 1)
        self.assertEqual(r.files, before)
        self.assert_denominator(value)
        pending = r.PRIVATE / "author-parts/shard-01-part-02"
        slots = r.read(pending / "input.json")["slots"]
        finish(r, pending, [{"case_id": s["slot_id"]} for s in slots])
        value = outcome.inspect_outcome(r)
        self.assertTrue(value["terminal"])
        self.assertEqual(value["cases"]["legal"]["ready"], 408)

    def test_real_author_parts_assembly_can_restore_full_ready_denominator(self):
        r = seed(author_partition=(1,))
        self.assertEqual(authorparts.assemble_parts(r)["author_shards_assembled"], 1)
        author = r.PRIVATE / "author/shard-01"
        cases = r.validate_job(author)["cases"]
        slots = r.read(author / "input.json")["slots"]
        enriched = [{**case, "family": slot["family"], "domain": slot["domain"]}
                    for case,slot in zip(cases,slots,strict=True)]
        oracle_work = job(r,"oracle","shard-01",{"cases": enriched,
            "as_of": "2026-09-05", "scenario_frozen_sha256": r.sha(author / "output.json")},
            [oracle(case["case_id"]) for case in enriched])
        review_stage(r,oracle_work)
        value = outcome.inspect_outcome(r)
        self.assertTrue(value["construction_ready"])
        self.assertEqual(value["stages"]["author-parts"]["validated_rows"], 12)
        self.assertEqual(value["confirmed_checks"]["authored"], 443)
        self.assert_denominator(value)
        archive = r.PRIVATE / "author-batch-failure-preserved/shard-01/canonical/COMPLETION.json"
        r.alter(archive,data=r.files[archive]+b" ")
        self.assertFalse(outcome.inspect_outcome(r)["construction_ready"])

    def test_rendered_fixture_is_used_only_after_successor_validation_and_fresh_review(self):
        r = seed(reviewer_edit=lambda row: row.update(fixtures_valid=False))
        original = r.PRIVATE / "fixtures/shard-01/case-01/UPLOAD-MANIFEST.json"
        directory = r.PRIVATE / "fixture-repaired/shard-01-case-01"
        r.write(directory / "UPLOAD-MANIFEST.json", r.read(original))
        r.write(r.PRIVATE / "fixtures/shard-01/case-01/FIXTURE-FAILURE.json", {"held": True})
        expected = r.sha(directory / "UPLOAD-MANIFEST.json")
        checks = []
        def validate(r, work):
            checks.append(work)
            if r.sha(work / "UPLOAD-MANIFEST.json") != expected:
                raise ValueError("synthetic rendered bytes changed")
            return r.read(work / "UPLOAD-MANIFEST.json")
        with patch.dict(sys.modules,{"scripts.ge_unseen_fixture_repair": SimpleNamespace(validate_rendered_successor=validate)}):
            before_review = outcome.inspect_outcome(r)
            self.assertFalse(before_review["terminal"])
            self.assertEqual(before_review["stages"]["bank-review-repair"]["pending"], 1)
            targeted_job(r,stage="bank-review-repair")
            value = outcome.inspect_outcome(r)
            self.assertTrue(value["construction_ready"])
            self.assertTrue(checks)
            r.alter(directory / "UPLOAD-MANIFEST.json",data=r.files[directory / "UPLOAD-MANIFEST.json"]+b" ")
            value = outcome.inspect_outcome(r)
            self.assertFalse(value["construction_ready"])
            self.assertEqual(value["cases"]["legal"]["ready"], 419)

    def test_rendered_fixture_with_failed_oracle_repair_does_not_wait_forever_for_review(self):
        r = seed(oracle_edit=lambda row:row.update(source_sufficient=False),
                 reviewer_edit=lambda row:row.update(fixtures_valid=False))
        targeted_job(r,state="failed")
        directory = r.PRIVATE / "fixture-repaired/shard-01-case-01"
        original = r.PRIVATE / "fixtures/shard-01/case-01/UPLOAD-MANIFEST.json"
        r.write(directory / "UPLOAD-MANIFEST.json",r.read(original))
        fixture = SimpleNamespace(validate_rendered_successor=lambda r,p:r.read(p / "UPLOAD-MANIFEST.json"))
        with patch.dict(sys.modules,{"scripts.ge_unseen_fixture_repair":fixture}):
            value = outcome.inspect_outcome(r)
        self.assertTrue(value["terminal"])
        self.assertEqual(value["stages"]["bank-review-repair"]["pending"], 0)
        self.assertEqual(value["stages"]["bank-review-repair"]["upstream_held"], 1)
        self.assertEqual(value["cases"]["legal"]["ready"], 419)
        self.assert_denominator(value)

    def test_resume_publishes_separate_bound_receipt_and_preserves_original_outcome(self):
        r = seed()
        outcome.publish_outcome(r)
        original = r.files[r.PUBLIC / outcome.RECEIPT_NAME]
        r.write(r.PUBLIC / "CONTINUOUS-RUN-START.json", {"synthetic": "original"})
        r.write(r.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json", {"synthetic": "plan"})
        r.write(r.PUBLIC / "CONTINUOUS-PLAN-RESUME-START.json", r.seal({
            "run_id": r.RUN_ID, "resume": True,
            "original_start_sha256": r.sha(r.PUBLIC / "CONTINUOUS-RUN-START.json"),
            "plan_execution_sha256": r.sha(r.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json")}))
        with patch("scripts.ge_unseen_research_gate.require_plan_execution",return_value={}):
            result = outcome.publish_outcome(r,resume=True)
            self.assertEqual(result["status"], "CREATED")
            self.assertEqual(result["outcome"]["original_outcome_sha256"], r.sha(r.PUBLIC / outcome.RECEIPT_NAME))
            self.assertEqual(outcome.publish_outcome(r,resume=True)["status"], "NO_OP")
            self.assertEqual(r.files[r.PUBLIC / outcome.RECEIPT_NAME], original)
            with self.assertRaisesRegex(outcome.OutcomeError,"IDENTITY_MISMATCH"):
                outcome.publish_outcome(r)

    def test_fixture_inventory_pending_active_and_formatter_dependency_cannot_publish_early(self):
        for state in ("pending", "active", "complete", "prepare_hold"):
            with self.subTest(state=state):
                r = seed(first_upload=True, reviewer_edit=lambda row:row.update(fixtures_valid=False))
                case = r.read(r.PRIVATE / "oracle/shard-01/input.json")["cases"][0]
                manifest = r.PRIVATE / "fixtures/shard-01/case-01/UPLOAD-MANIFEST.json"
                binding = {"case_projection_sha256": r.digest(case), "manifest_sha256": r.sha(manifest),
                           "raw_case_sha256": r.read(manifest)["raw_case_sha256"],
                           "inventory_context_id": "inventory-synthetic", "formatter_context_id": "formatter-synthetic"}
                work = r.PRIVATE / "fixture-inventory/shard-01-case-01"
                r.write(work / "input.json", {"case": case, "binding": binding,
                                              "original_binding_sha256": r.digest(binding)})
                r.write(work / "schema.json", {"synthetic": "requirements"})
                if state != "pending":
                    finish(r, work, [{"case_id": case["case_id"], "status": "DRAFT"}], active=state=="active")
                if state == "prepare_hold":
                    r.write(r.PRIVATE / "receipts/fixture-inventory/shard-01-case-01-prepare-hold.json", {"hold": True})
                fixture = SimpleNamespace(REQUIREMENT_SCHEMA={"synthetic": "requirements"},
                    validate_requirement_output=lambda *args: {"state": "INVENTORY_DRAFT_BOUND"})
                with patch.dict(sys.modules, {"scripts.ge_unseen_fixture_repair": fixture}):
                    value = outcome.inspect_outcome(r)
                self.assertIs(value["terminal"], state=="prepare_hold")
                self.assertFalse(value["construction_ready"])
                if state == "complete":
                    self.assertEqual(value["stages"]["fixture-format"]["absent"], 1)
                    self.assertEqual(value["stages"]["fixture-format"]["pending"], 1)
                elif state == "pending":
                    self.assertEqual(value["stages"]["fixture-inventory"]["pending"], 1)
                    self.assertFalse(any(p==work / "output.json" for p in r.reads))
                elif state == "active":
                    self.assertEqual(value["active_jobs"], 1)
                self.assert_denominator(value)

    def test_verified_formatter_waits_for_render_and_failed_render_is_terminal_local_hold(self):
        r = seed(first_upload=True, reviewer_edit=lambda row:row.update(fixtures_valid=False))
        case = r.read(r.PRIVATE / "oracle/shard-01/input.json")["cases"][0]
        work = r.PRIVATE / "fixture-format/shard-01-case-01"
        r.write(work / "input.json", {"case": case})
        r.write(work / "schema.json", {"synthetic": "formatter"})
        finish(r, work, [{"case_id": case["case_id"], "status": "FORMATTED"}])
        value = outcome.inspect_outcome(r)
        self.assertFalse(value["terminal"])
        self.assertEqual(value["stages"]["fixture-format"]["pending"], 1)
        r.write(r.PRIVATE / "receipts/fixture-format/shard-01-case-01-render-failure.json", {"hold": True})
        value = outcome.inspect_outcome(r)
        self.assertTrue(value["terminal"])
        self.assertEqual(value["cases"]["legal"]["ready"], 419)
        self.assertFalse(value["construction_ready"])
        self.assert_denominator(value)


if __name__ == "__main__":
    unittest.main()
