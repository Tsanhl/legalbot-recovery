"""Synthetic memory-only review jobs: no actual bank, evaluation or runner IO."""
from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
from pathlib import PurePosixPath
from types import SimpleNamespace

import jsonschema
import pytest
from scripts import ge_unseen_novelty_review as review
from scripts.ge_response_transport import response_transport_schema


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


class MemoryPath(PurePosixPath):
    fs = None

    def exists(self):
        return self in self.fs.files or self in self.fs.dirs

    def mkdir(self, mode=0o777, parents=False, exist_ok=False):
        if self.exists():
            if exist_ok and self in self.fs.dirs:
                return
            raise FileExistsError("synthetic existing path")
        if not self.parent.exists():
            if not parents:
                raise FileNotFoundError("synthetic missing parent")
            self.parent.mkdir(parents=True, exist_ok=True)
        self.fs.dirs.add(self)

    def glob(self, pattern):
        return iter(sorted(path for path in self.fs.files.keys() | self.fs.dirs
                           if path.parent == self and fnmatch.fnmatchcase(path.name, pattern)))

    def rename(self, target):
        assert not target.exists() and target.parent in self.fs.dirs
        for path in sorted(self.fs.files.copy()):
            if path.is_relative_to(self):
                self.fs.files[target / path.relative_to(self)] = self.fs.files.pop(path)
        for path in sorted(self.fs.dirs.copy()):
            if path.is_relative_to(self):
                self.fs.dirs.remove(path)
                self.fs.dirs.add(target / path.relative_to(self))
        return target


@pytest.fixture
def memory(monkeypatch):
    fs = SimpleNamespace(files={}, dirs={MemoryPath("/")}, symlinks=set(), reads=[])
    monkeypatch.setattr(MemoryPath, "fs", fs)
    r = SimpleNamespace(ROOT=MemoryPath("/synthetic/workspace"),
                        PRIVATE=MemoryPath("/synthetic/workspace/private"),
                        PUBLIC=MemoryPath("/synthetic/workspace/public"), fs=fs,
                        NOVELTY_REVIEW_CONTRACT_SHA256=review.review_contract()["content_sha256"])

    def safe_path(path):
        assert isinstance(path, MemoryPath), "real filesystem access forbidden"
        if not path.is_relative_to(r.ROOT) or ".." in path.parts:
            raise RuntimeError("outside synthetic current root")
        if any(parent in fs.symlinks for parent in (path, *path.parents)):
            raise RuntimeError("symlink refused")

    def read(path):
        safe_path(path)
        fs.reads.append(path)
        if path not in fs.files:
            raise FileNotFoundError(path)
        return json.loads(fs.files[path])

    def write(path, value):
        safe_path(path)
        if path.exists():
            raise FileExistsError("synthetic create-only write")
        path.parent.mkdir(parents=True, exist_ok=True)
        fs.files[path] = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()

    def sha(path):
        safe_path(path)
        if path not in fs.files:
            raise FileNotFoundError(path)
        return hashlib.sha256(fs.files[path]).hexdigest()

    def safe_files(directory):
        safe_path(directory)
        files = sorted(path for path in fs.files if path.is_relative_to(directory))
        for path in files:
            safe_path(path)
        return files

    def no_model_or_recursive_validator(*args, **kwargs):
        raise AssertionError("no model calls or recursive parent validation")

    r.safe_path, r.read, r.write, r.sha, r.safe_files = safe_path, read, write, sha, safe_files
    r.digest, r.seal = digest, lambda value: {**value, "content_sha256": digest(value)}
    r.invoke = r.validate_job = no_model_or_recursive_validator
    return r


def supplied(count=14, *, system=0):
    cases = [{"case_id": f"synthetic-case-{i:02d}", "question": f"Synthetic scenario {i}: a cobalt ceramic bowl.",
              "domain": "synthetic-domain", "family": f"local-family-{i // 2:02d}",
              "pair_family": f"pair-{i // 2:02d}", "case_type": "legal"} for i in range(count)]
    for case in cases[len(cases) - system:] if system else []:
        case["case_type"], case["pair_family"] = "system", None
    return {"cases": cases,
            "exposed_questions": [{"id": "exposed-first", "text": "Synthetic exposed question about amber glazes."},
                                  {"id": "far-reference", "text": "Entirely unrelated supplied text about a violet bicycle."}],
            "trained_answers": [{"id": f"trained-{i:02d}", "text": f"Synthetic previously trained answer {i} about copper boxes."} for i in range(13)],
            "policy_examples": [{"id": "caller-example", "text": "Synthetic caller-provided policy example about a faulty toy."}],
            "input_file_hashes": {"supplied-cases": "a" * 64, "exposed-input": "b" * 64,
                                  "trained-input": "c" * 64, "policy-input": "d" * 64}}


def jobs(r):
    return sorted((r.PRIVATE / "novelty-review").glob("shard-*"))


def controls(r):
    return r.PRIVATE / "novelty-review-control"


def input_receipt(r, work):
    return r.PRIVATE / "receipts" / "novelty-review" / (work.name + ".json")


def decisions(r, work):
    payload = r.read(work / "input.json")
    return [{"case_id": case["case_id"], "question_sha256": case["question_sha256"], "novelty": "PASS",
             "comparison_scope_sha256": case["comparison_scope_sha256"], "full_comparison_completed": True,
             "compared_reference_ids": sorted({flag["reference_id"] for flag in case["material_lexical_flags"]
                                               if flag["reference_in_comparison_scope"]}),
             "flag_reviews": [{"flag_id": flag["flag_id"], "resolved": flag["reference_in_comparison_scope"],
                               "reason": "Synthetic flag resolution for protocol testing; no real novelty conclusion."}
                              for flag in case["material_lexical_flags"]],
             "reason": "Synthetic reviewer compared the supplied facts and found material distinctions without answer clues.",
             "answer_clues_absent": True, "materially_distinct": True} for case in reversed(payload["cases"])]


def complete(r, work, *, rows=None, returncode=0, validation_error=None, transport=False):
    if rows is None:
        rows = decisions(r, work)
    invocation = {"input_sha256": r.sha(work / "input.json"),
                  "prompt_sha256": digest(review.review_prompt()), "fresh_context": True,
                  "browse": False, "provider": "OPENAI", "model": "CONFIGURED_DEFAULT"}
    inventory_names = ["input.json", "schema.json", "INVOCATION.json"]
    if transport:
        r.write(work / "transport-schema.json", response_transport_schema(r.read(work / "schema.json")))
        invocation.update(transport_schema_sha256=r.sha(work / "transport-schema.json"),
                          local_schema_unchanged_sha256=r.sha(work / "schema.json"))
        inventory_names.append("transport-schema.json")
    r.write(work / "INVOCATION.json", invocation)
    r.write(input_receipt(r, work), {
        "work": f"novelty-review/{work.name}", "input_sha256": r.sha(work / "input.json"),
        "schema_sha256": r.sha(work / "schema.json"), "prompt_sha256": digest(review.review_prompt()),
        "input_inventory": {name: r.sha(work / name) for name in inventory_names}})
    r.write(work / "output.json", {"reviews": rows})
    completion = {"stage": "novelty-review", "shard": work.name, "returncode": returncode,
                  "validation_error": validation_error, "output_present": True, "validated_rows": len(rows)}
    r.write(input_receipt(r, work).with_name(work.name + "-complete.json"), {
        **completion, "output_sha256": r.sha(work / "output.json")})
    r.write(work / "COMPLETION.json", completion)


def tamper(r, path, value):
    """Adversarial memory mutation only; never an actual file overwrite."""
    r.fs.files[path] = json.dumps(value).encode()


def test_full_corpus_bounded_jobs_exact_hashes_pair_partition_and_immutable_noop(memory):
    r = memory
    inputs = supplied()
    # Place partners far apart in supplied order: the partition must reunite them.
    inputs["cases"] = inputs["cases"][::2] + inputs["cases"][1::2]
    inputs["cases"][0]["question"] += " Café\u00a0receipt\u200b retained."
    before = copy.deepcopy(inputs)
    result = review.prepare_jobs(r, **inputs)
    assert result == {"status": "PREPARED", "novelty_review_jobs_prepared": 2, "novelty_review_cases": 14}
    assert inputs == before
    plan = review.checked_plan(r)
    assert plan["denominator"] == 14
    assert plan["cases"] == [{"case_id": case["case_id"], "question_sha256": hashlib.sha256(case["question"].encode()).hexdigest(),
                              "case_sha256": digest(case), "case_type": case["case_type"]} for case in inputs["cases"]]
    assignment = {}
    seen = []
    for work in jobs(r):
        payload = r.read(work / "input.json")
        assert 1 <= len(payload["cases"]) <= 12
        for case in payload["cases"]:
            seen.append(case["case_id"])
            assignment[case["case_id"]] = work.name
            original = next(row for row in inputs["cases"] if row["case_id"] == case["case_id"])
            assert case["question"] == original["question"]
        assert payload["full_supplied_corpus"] is True
        for group in ("exposed_questions", "trained_answers", "policy_examples"):
            actual = [{"id": ref["id"], "text": ref["text"]} for ref in payload["references"] if ref["group"] == group]
            assert actual == inputs[group]
        assert len([ref for ref in payload["references"] if ref["group"] == "trained_answers"]) == 13
        assert any(ref["id"] == "far-reference" for ref in payload["references"])
        assert payload["input_file_hashes"] == inputs["input_file_hashes"]
        assert payload["lexical_receipt_sha256"] == r.read(controls(r) / "LEXICAL-RECEIPT.json")["content_sha256"]
        assert payload["lexical_contract_sha256"] == r.read(controls(r) / "LEXICAL-CONTRACT.json")["content_sha256"]
        assert payload["review_contract_sha256"] == r.NOVELTY_REVIEW_CONTRACT_SHA256
        assert r.read(work / "schema.json") == review.review_schema()
        assert not any(key in case for case in payload["cases"] for key in ("follow_up", "uploads", "sources", "answer", "oracle"))
    assert len(seen) == len(set(seen)) == 14
    for i in range(0, 14, 2):
        assert assignment[f"synthetic-case-{i:02d}"] == assignment[f"synthetic-case-{i + 1:02d}"]
    frozen = dict(r.fs.files), set(r.fs.dirs)
    assert review.prepare_jobs(r, **inputs)["status"] == "NO_OP_UNCHANGED_INPUTS"
    assert (r.fs.files, r.fs.dirs) == frozen
    assert all(path.is_relative_to(r.PRIVATE) for path in r.fs.files)


@pytest.mark.parametrize("transport", [False, True])
def test_all_review_pass_aggregates_in_original_order_with_separate_system_counts(memory, transport):
    r = memory
    inputs = supplied(14, system=2)
    review.prepare_jobs(r, **inputs)
    for work in jobs(r):
        complete(r, work, transport=transport)
        assert review.validate_job(r, work) == r.read(work / "output.json")
    before = dict(r.fs.files)
    result = review.aggregate(r)
    assert result["counts"] == {"PASS": 14, "HOLD": 0, "ERROR": 0, "PENDING": 0}
    assert result["all_supplied_cases_review_pass"] is True
    assert result["denominator"] == 14
    assert result["case_type_counts"]["legal"]["PASS"] == 12
    assert result["case_type_counts"]["system"]["PASS"] == 2
    assert [row["case_id"] for row in result["cases"]] == [row["case_id"] for row in inputs["cases"]]
    assert result["universal_novelty_proof"] is result["independent_provider_review"] is False
    assert result["scope"] == "QUESTION_TEXT_AND_PAIR_FAMILY_ONLY"
    assert result["shared_export"] is result["questions_rewritten"] is False
    assert r.fs.files == before


@pytest.mark.parametrize("transport", [False, True])
def test_hold_with_partial_compared_references_is_terminal_without_false_pass(memory, transport):
    r = memory
    review.prepare_jobs(r, **supplied(2))
    work = jobs(r)[0]
    rows = decisions(r, work)
    rows[0].update(novelty="HOLD", compared_reference_ids=[], materially_distinct=False,
                   full_comparison_completed=False,
                   reason="Synthetic reviewer could not complete the comparison, so the question stays held.")
    complete(r, work, rows=rows, transport=transport)
    assert review.validate_job(r, work)["reviews"][0]["novelty"] == "HOLD"
    result = review.aggregate(r)
    assert result["counts"] == {"PASS": 1, "HOLD": 1, "ERROR": 0, "PENDING": 0}
    assert result["status"] == "HOLD" and result["terminal_cases"] == 2
    assert result["all_supplied_cases_review_pass"] is False


def test_pending_and_missing_jobs_remain_in_denominator(memory):
    r = memory
    review.prepare_jobs(r, **supplied())
    complete(r, jobs(r)[0])
    before = dict(r.fs.files)
    result = review.aggregate(r)
    assert result["counts"] == {"PASS": 12, "HOLD": 0, "ERROR": 0, "PENDING": 2}
    assert result["denominator"] == 14 and not result["all_supplied_cases_review_pass"]
    assert r.fs.files == before
    missing = jobs(r)[1]
    missing.rename(r.PRIVATE / "synthetic-preserved-missing-job")
    assert review.checked_plan(r)["denominator"] == 14
    result = review.aggregate(r)
    assert result["counts"] == {"PASS": 12, "HOLD": 0, "ERROR": 2, "PENDING": 0}
    assert result["successfully_reviewed_cases"] == 12 and result["terminal_cases"] == 14
    assert result["status"] == "HOLD"


def test_scheduler_preflight_is_read_only_and_rejects_input_tampering_before_invocation(memory):
    r = memory
    inputs = supplied(2)
    review.prepare_jobs(r, **inputs)
    work = jobs(r)[0]
    before = dict(r.fs.files), set(r.fs.dirs)
    review.validate_input_lineage(r, work)
    assert (r.fs.files, r.fs.dirs) == before
    r.fs.files[work / "input.json"] += b" "
    tampered = dict(r.fs.files), set(r.fs.dirs)
    with pytest.raises(review.NoveltyReviewError, match="changed"):
        review.validate_input_lineage(r, work)
    with pytest.raises(review.NoveltyReviewError, match="changed or missing"):
        review.prepare_jobs(r, **inputs)
    assert (r.fs.files, r.fs.dirs) == tampered
    assert not (work / "INVOCATION.json").exists()


@pytest.mark.parametrize("transport", [False, True])
@pytest.mark.parametrize("defect", ["missing", "duplicate", "unknown-case", "question-hash", "partial-comparison",
                                   "unknown-reference", "duplicate-reference", "answer-clues", "not-distinct",
                                   "string-bool", "blank-reason", "rewrite-question", "scope-hash", "sibling-scope-hash",
                                   "missing-attestation", "string-attestation", "inventory-dump",
                                   "short-reason", "long-reason", "invalid-novelty", "malformed-hash",
                                   "non-string-reference", "non-array-flags"])
def test_schema_or_coverage_defects_cannot_produce_pass(memory, defect, transport):
    r = memory
    review.prepare_jobs(r, **supplied(2))
    work = jobs(r)[0]
    rows = decisions(r, work)
    if defect == "missing":
        rows.pop()
    elif defect == "duplicate":
        rows[1] = rows[0]
    elif defect == "unknown-case":
        rows[0]["case_id"] = "unassigned-case"
    elif defect == "question-hash":
        rows[0]["question_sha256"] = "0" * 64
    elif defect == "partial-comparison":
        rows[0]["full_comparison_completed"] = False
    elif defect == "unknown-reference":
        rows[0]["compared_reference_ids"].append("unseen:invented")
    elif defect == "duplicate-reference":
        rows[0]["compared_reference_ids"] = ["exposed_questions:far-reference"] * 2
    elif defect == "scope-hash":
        rows[0]["comparison_scope_sha256"] = "0" * 64
    elif defect == "sibling-scope-hash":
        rows[0]["comparison_scope_sha256"] = rows[1]["comparison_scope_sha256"]
    elif defect == "missing-attestation":
        rows[0].pop("full_comparison_completed")
    elif defect == "string-attestation":
        rows[0]["full_comparison_completed"] = "true"
    elif defect == "inventory-dump":
        rows[0]["compared_reference_ids"] = [ref["reference_id"] for ref in r.read(work / "input.json")["references"]]
    elif defect == "answer-clues":
        rows[0]["answer_clues_absent"] = False
    elif defect == "not-distinct":
        rows[0]["materially_distinct"] = False
    elif defect == "string-bool":
        rows[0]["materially_distinct"] = "true"
    elif defect == "blank-reason":
        rows[0]["reason"] = " " * 21
    elif defect == "short-reason":
        rows[0]["reason"] = "too short"
    elif defect == "long-reason":
        rows[0]["reason"] = "x" * 4001
    elif defect == "invalid-novelty":
        rows[0]["novelty"] = "APPROVED"
    elif defect == "malformed-hash":
        rows[0]["question_sha256"] = "g" * 64
    elif defect == "non-string-reference":
        rows[0]["compared_reference_ids"] = [True]
    elif defect == "non-array-flags":
        rows[0]["flag_reviews"] = {}
    else:
        rows[0]["question"] = "Attempted synthetic rewrite"
    complete(r, work, rows=rows, transport=transport)
    with pytest.raises((review.NoveltyReviewError, jsonschema.ValidationError)):
        review.validate_job(r, work)
    result = review.aggregate(r)
    assert result["denominator"] == 2 and result["counts"]["ERROR"] == 2
    assert not result["all_supplied_cases_review_pass"]


@pytest.mark.parametrize("transport", [False, True])
@pytest.mark.parametrize("defect", ["input", "family", "corpus", "schema", "invocation", "fresh-context", "browse",
                                   "receipt", "inventory", "output-whitespace", "terminal", "completion"])
def test_job_lineage_and_protected_receipt_tampering_fails_closed(memory, defect, transport):
    r = memory
    review.prepare_jobs(r, **supplied(2))
    work = jobs(r)[0]
    complete(r, work, transport=transport)
    if defect in ("input", "family", "corpus"):
        value = r.read(work / "input.json")
        if defect == "input":
            value["cases"][0]["question"] += " changed"
        elif defect == "family":
            value["cases"][0]["pair_family"] = "changed-pair"
        else:
            value["references"] = [ref for ref in value["references"] if ref["id"] != "far-reference"]
        tamper(r, work / "input.json", value)
    elif defect == "schema":
        tamper(r, work / "schema.json", {})
    elif defect in ("invocation", "fresh-context", "browse"):
        value = r.read(work / "INVOCATION.json")
        value[{"invocation": "prompt_sha256", "fresh-context": "fresh_context", "browse": "browse"}[defect]] = {
            "invocation": "0" * 64, "fresh-context": False, "browse": True}[defect]
        tamper(r, work / "INVOCATION.json", value)
    elif defect in ("receipt", "inventory"):
        value = r.read(input_receipt(r, work))
        if defect == "receipt":
            value["input_sha256"] = "0" * 64
        else:
            value["input_inventory"]["../other-job/input.json"] = "0" * 64
        tamper(r, input_receipt(r, work), value)
    elif defect == "output-whitespace":
        r.fs.files[work / "output.json"] += b" "
    elif defect == "terminal":
        tamper(r, input_receipt(r, work).with_name(work.name + "-complete.json"), {})
    else:
        value = r.read(work / "COMPLETION.json")
        value["returncode"] = False
        tamper(r, work / "COMPLETION.json", value)
    with pytest.raises(review.NoveltyReviewError):
        review.validate_job(r, work)
    result = review.aggregate(r)
    assert result["counts"]["ERROR"] == 2 and not result["all_supplied_cases_review_pass"]
    assert not any("other-job" in path.parts for path in r.fs.reads)


@pytest.mark.parametrize("name", ["REQUEST.json", "LEXICAL-CONTRACT.json", "LEXICAL-RECEIPT.json", "REVIEW-CONTRACT.json", "PLAN.json"])
def test_control_raw_hash_tampering_never_returns_an_aggregate_pass(memory, name):
    r = memory
    review.prepare_jobs(r, **supplied(2))
    complete(r, jobs(r)[0])
    r.fs.files[controls(r) / name] += b" "
    with pytest.raises(review.NoveltyReviewError):
        review.checked_plan(r)
    with pytest.raises(review.NoveltyReviewError):
        review.aggregate(r)


@pytest.mark.parametrize("transport", [False, True])
@pytest.mark.parametrize("kind", ["exposed", "policy", "new-pair", "missing-partner"])
def test_mechanical_exact_and_missing_pair_holds_cannot_be_overridden(memory, kind, transport):
    r = memory
    inputs = supplied(1 if kind == "missing-partner" else 2)
    if kind == "exposed":
        inputs["exposed_questions"][0]["text"] = inputs["cases"][0]["question"]
    elif kind == "policy":
        inputs["policy_examples"][0]["text"] = inputs["cases"][0]["question"]
    elif kind == "new-pair":
        inputs["cases"][1]["question"] = inputs["cases"][0]["question"]
    review.prepare_jobs(r, **inputs)
    work = jobs(r)[0]
    payload = r.read(work / "input.json")
    assert payload["mechanical_holds"][inputs["cases"][0]["case_id"]]
    if kind == "new-pair":
        assert all(payload["mechanical_holds"].values())
    complete(r, work, transport=transport)
    with pytest.raises(review.NoveltyReviewError, match="violates a hold"):
        review.validate_job(r, work)
    assert review.aggregate(r)["all_supplied_cases_review_pass"] is False


def test_incomplete_lexical_check_is_carried_into_review_as_mandatory_hold(memory, monkeypatch):
    from dataclasses import replace

    lexical = review.lexical
    monkeypatch.setattr(lexical, "_POLICY", replace(lexical._POLICY, max_posting_visits=0))
    r = memory
    r.NOVELTY_REVIEW_CONTRACT_SHA256 = review.review_contract()["content_sha256"]
    inputs = supplied(2)
    inputs["exposed_questions"][0]["text"] = inputs["cases"][0]["question"]
    review.prepare_jobs(r, **inputs)
    payload = r.read(jobs(r)[0] / "input.json")
    assert all("LEXICAL_CHECK_INCOMPLETE" in reasons for reasons in payload["mechanical_holds"].values())
    assert r.read(controls(r) / "LEXICAL-RECEIPT.json")["mechanical_check"] == "INCOMPLETE"


def test_cross_job_new_scenario_flag_stays_held_when_peer_text_is_unavailable(memory):
    r = memory
    inputs = supplied(14)
    for index, case in enumerate(inputs["cases"]):
        case["question"] = (
            "I booked an insulated studio for a ceramic workshop and stored glazed bowls "
            "inside a locked kiln cupboard. The caretaker disabled my entry badge after "
            "delivery and moved several fragile pieces into a damp corridor. I retained "
            f"the handwritten checklist and photographs. The additional charge was {index} pounds."
        )
    review.prepare_jobs(r, **inputs)
    for work in jobs(r):
        payload = r.read(work / "input.json")
        assert all("CROSS_JOB_SCENARIO_FLAG_UNREVIEWABLE" in reasons
                   for reasons in payload["mechanical_holds"].values())
        assert not payload["lexical_flags"]["exact_overlaps"]


def test_large_full_corpus_input_uses_compact_hash_attestations_in_every_output_row(memory):
    r = memory
    inputs = supplied(12)
    inputs["exposed_questions"] = [{"id": f"exposed-{i:03d}", "text": f"Unrelated synthetic reference {i} about violet bicycles."}
                                   for i in range(400)]
    review.prepare_jobs(r, **inputs)
    work = jobs(r)[0]
    payload = r.read(work / "input.json")
    assert len(payload["references"]) == 414
    assert [{"id": ref["id"], "text": ref["text"]} for ref in payload["references"]
            if ref["group"] == "exposed_questions"] == inputs["exposed_questions"]
    assert len({case["comparison_scope_sha256"] for case in payload["cases"]}) == 12
    complete(r, work)
    output = review.validate_job(r, work)
    assert all(row["compared_reference_ids"] == row["flag_reviews"] == [] for row in output["reviews"])
    assert all(row["full_comparison_completed"] is True for row in output["reviews"])
    assert len(json.dumps(output).encode()) < 12_000
    report = review.aggregate(r)
    assert report["all_supplied_cases_review_pass"] is True
    assert report["comparison_attestation"] == "AI_DECLARATION_NOT_PROOF_OF_SEMANTIC_COMPARISON"


def test_comparison_scope_hash_binds_far_references_sibling_identity_and_subject_metadata(memory):
    r = memory
    inputs = supplied(2)
    review.prepare_jobs(r, **inputs)
    payload = r.read(jobs(r)[0] / "input.json")
    cases, refs = inputs["cases"], payload["references"]
    original = payload["cases"][0]["comparison_scope_sha256"]
    assert review._comparison_scope_sha256(cases[0], cases, refs) == original
    changed_refs = copy.deepcopy(refs)
    changed_refs[-1]["text"] += " changed"
    assert review._comparison_scope_sha256(cases[0], cases, changed_refs) != original
    changed_cases = copy.deepcopy(cases)
    changed_cases[1]["question"] += " changed sibling"
    assert review._comparison_scope_sha256(cases[0], changed_cases, refs) != original
    changed_cases = copy.deepcopy(cases)
    changed_cases[0]["pair_family"] = "changed-pair"
    assert review._comparison_scope_sha256(changed_cases[0], changed_cases, refs) != original


@pytest.mark.parametrize("transport", [False, True])
@pytest.mark.parametrize("defect", [None, "missing-flag", "duplicate-flag", "unknown-flag", "unresolved",
                                   "blank-flag-reason", "missing-flagged-reference"])
def test_material_flags_require_exact_ids_individual_reasons_and_resolutions_for_pass(memory, defect, transport):
    r = memory
    inputs = supplied(2)
    text = (
        "I booked an insulated studio for a ceramic workshop and stored glazed bowls "
        "inside a locked kiln cupboard. The caretaker disabled my entry badge after "
        "delivery and moved several fragile pieces into a damp corridor. I retained "
        "the handwritten checklist and photographs. The additional charge was 450 pounds."
    )
    inputs["cases"][0]["question"] = text
    inputs["exposed_questions"][0]["text"] = text.replace("450", "650")
    review.prepare_jobs(r, **inputs)
    work = jobs(r)[0]
    rows = decisions(r, work)
    flagged = next(row for row in rows if row["flag_reviews"])
    assert len(flagged["flag_reviews"]) == len(flagged["compared_reference_ids"]) == 1
    if defect == "missing-flag":
        flagged["flag_reviews"] = []
    elif defect == "duplicate-flag":
        flagged["flag_reviews"].append(copy.deepcopy(flagged["flag_reviews"][0]))
    elif defect == "unknown-flag":
        flagged["flag_reviews"][0]["flag_id"] = "0" * 64
    elif defect == "unresolved":
        flagged["flag_reviews"][0]["resolved"] = False
    elif defect == "blank-flag-reason":
        flagged["flag_reviews"][0]["reason"] = " " * 21
    elif defect == "missing-flagged-reference":
        flagged["compared_reference_ids"] = []
    complete(r, work, rows=rows, transport=transport)
    if defect is None:
        assert review.validate_job(r, work)["reviews"] == rows
    else:
        with pytest.raises(review.NoveltyReviewError):
            review.validate_job(r, work)
        assert not review.aggregate(r)["all_supplied_cases_review_pass"]


def test_431_supplied_cases_prepare_without_waiting_for_12_upstream_holds(memory):
    r = memory
    inputs = supplied(431, system=23)
    result = review.prepare_jobs(r, **inputs)
    plan = review.checked_plan(r)
    assert result["novelty_review_cases"] == plan["denominator"] == 431
    assert sum(len(entry["case_ids"]) for entry in plan["jobs"]) == 431
    assert all(len(entry["case_ids"]) <= 12 for entry in plan["jobs"])
    # The parent keeps the other 12 upstream holds in the bank's 443 denominator.
    assert plan["denominator"] + 12 == 443


@pytest.mark.parametrize("field", ["follow_up", "uploads", "sources", "oracle", "answer"])
def test_forbidden_current_bank_fields_are_rejected_before_any_write(memory, field):
    r = memory
    inputs = supplied(2)
    inputs["cases"][0][field] = "forbidden synthetic current content"
    with pytest.raises(review.NoveltyReviewError, match="question-only"):
        review.prepare_jobs(r, **inputs)
    assert not r.fs.files


@pytest.mark.parametrize("defect", ["empty-cases", "empty-exposed", "empty-policy", "twelve-trained", "fourteen-trained",
                                   "source-path", "bad-hash", "duplicate-id", "oversized-pair"])
def test_missing_corpus_or_ambiguous_assignments_are_rejected_without_jobs(memory, defect):
    r = memory
    inputs = supplied(2)
    if defect == "empty-cases":
        inputs["cases"] = []
    elif defect == "empty-exposed":
        inputs["exposed_questions"] = []
    elif defect == "empty-policy":
        inputs["policy_examples"] = []
    elif defect == "twelve-trained":
        inputs["trained_answers"].pop()
    elif defect == "fourteen-trained":
        inputs["trained_answers"].append({"id": "extra", "text": "Extra synthetic text"})
    elif defect == "source-path":
        inputs["input_file_hashes"] = {"/forbidden/actual/path": "a" * 64}
    elif defect == "bad-hash":
        inputs["input_file_hashes"]["supplied-cases"] = "not-a-hash"
    elif defect == "duplicate-id":
        inputs["cases"][1]["case_id"] = inputs["cases"][0]["case_id"]
    else:
        inputs = supplied(4)
        inputs["cases"][2]["pair_family"] = inputs["cases"][0]["pair_family"]
    with pytest.raises(review.NoveltyReviewError):
        review.prepare_jobs(r, **inputs)
    assert not r.fs.files


@pytest.mark.parametrize("limit", ["MAX_JOB_INPUT_BYTES", "MAX_JOB_INPUT_WORD_TOKENS"])
def test_full_corpus_size_overflow_never_truncates_or_writes_jobs(memory, monkeypatch, limit):
    r = memory
    monkeypatch.setattr(review, limit, 10)
    r.NOVELTY_REVIEW_CONTRACT_SHA256 = review.review_contract()["content_sha256"]
    inputs = supplied(2)
    before = copy.deepcopy(inputs)
    with pytest.raises(review.NoveltyReviewSizeError, match="no truncation"):
        review.prepare_jobs(r, **inputs)
    assert inputs == before and not r.fs.files


@pytest.mark.parametrize("stage", ["control", "job", "plan", "publication"])
def test_interrupted_preparation_is_preserved_never_resumed(memory, monkeypatch, stage):
    r = memory
    original = r.write
    target = {"control": controls(r) / "LEXICAL-CONTRACT.json",
              "job": r.PRIVATE / "novelty-review" / "shard-01" / "schema.json",
              "plan": controls(r) / "PLAN.json",
              "publication": r.PRIVATE / "receipts" / "novelty-review-plan.json"}[stage]

    def interrupted(path, value):
        if path == target:
            raise OSError("synthetic interruption")
        original(path, value)

    monkeypatch.setattr(r, "write", interrupted)
    with pytest.raises(OSError):
        review.prepare_jobs(r, **supplied(2))
    frozen = dict(r.fs.files), set(r.fs.dirs)
    with pytest.raises(review.NoveltyReviewError, match="interrupted"):
        review.prepare_jobs(r, **supplied(2))
    assert (r.fs.files, r.fs.dirs) == frozen


@pytest.mark.parametrize("state", ["timeout", "validation-failure", "running", "orphan-output", "orphan-terminal"])
def test_failed_and_partial_attempts_are_retained_without_retry(memory, state):
    r = memory
    inputs = supplied(2)
    review.prepare_jobs(r, **inputs)
    work = jobs(r)[0]
    if state in ("timeout", "validation-failure"):
        complete(r, work, returncode=124 if state == "timeout" else 0,
                 validation_error="ValidationError" if state == "validation-failure" else None)
    elif state == "running":
        r.write(work / "INVOCATION.json", {"synthetic_running": True})
    elif state == "orphan-output":
        r.write(work / "output.json", {"reviews": []})
    else:
        r.write(input_receipt(r, work).with_name(work.name + "-complete.json"), {})
    before = dict(r.fs.files), set(r.fs.dirs)
    result = review.aggregate(r)
    assert result["counts"]["PENDING" if state == "running" else "ERROR"] == 2
    assert result["denominator"] == 2 and not result["all_supplied_cases_review_pass"]
    assert review.prepare_jobs(r, **inputs)["status"] == "NO_OP_UNCHANGED_INPUTS"
    assert (r.fs.files, r.fs.dirs) == before


def test_changed_inputs_cannot_replace_original_preparation(memory):
    r = memory
    inputs = supplied(2)
    review.prepare_jobs(r, **inputs)
    before = dict(r.fs.files), set(r.fs.dirs)
    inputs["input_file_hashes"]["trained-input"] = "e" * 64
    with pytest.raises(review.NoveltyReviewError, match="inputs changed"):
        review.prepare_jobs(r, **inputs)
    assert (r.fs.files, r.fs.dirs) == before


def test_schema_snapshots_and_missing_or_changed_contract(memory):
    r = memory
    schema = review.review_schema()
    schema["properties"].clear()
    assert review.review_schema()["properties"]
    r.NOVELTY_REVIEW_CONTRACT_SHA256 = "0" * 64
    with pytest.raises(review.NoveltyReviewError, match="contract"):
        review.prepare_jobs(r, **supplied(2))
    assert not r.fs.files


@pytest.mark.parametrize("marker", ["BANK-SEAL.json", "ONE-PASS-START.json"])
def test_after_seal_preparation_refused_before_private_reads(memory, marker):
    r = memory
    r.write(r.PUBLIC / marker, {})
    with pytest.raises(review.NoveltyReviewError, match="after seal"):
        review.prepare_jobs(r, **supplied(2))
    assert not r.fs.reads


def test_unknown_outside_and_symlink_paths_fail_before_read(memory):
    r = memory
    for path in (r.PRIVATE / "other-stage" / "shard-01",
                 r.PRIVATE / "novelty-review" / "../other-stage/shard-01",
                 MemoryPath("/synthetic/other/private/novelty-review/shard-01")):
        with pytest.raises(review.NoveltyReviewError):
            review.validate_job(r, path)
    assert not r.fs.reads
    root = r.PRIVATE / "novelty-review-control"
    r.fs.symlinks.add(root)
    with pytest.raises(RuntimeError, match="symlink"):
        review.prepare_jobs(r, **supplied(2))
    assert not r.fs.reads


def test_transport_receipt_passes_with_only_uniqueness_projected_and_frozen_inputs_intact(memory):
    r = memory
    contract = review.review_contract()
    original_schema = review.review_schema()
    review.prepare_jobs(r, **supplied(2))
    frozen = dict(r.fs.files)
    work = jobs(r)[0]
    complete(r, work, transport=True)
    projected = r.read(work / "transport-schema.json")
    expected = copy.deepcopy(original_schema)
    expected["properties"]["reviews"]["items"]["properties"]["compared_reference_ids"].pop("uniqueItems")
    assert projected == expected
    assert review.review_schema() == original_schema
    assert review.review_contract() == contract
    assert all(r.fs.files[path] == raw for path, raw in frozen.items())
    invocation = r.read(work / "INVOCATION.json")
    inventory = r.read(input_receipt(r, work))["input_inventory"]
    assert set(inventory) == {"input.json", "schema.json", "INVOCATION.json", "transport-schema.json"}
    assert invocation["local_schema_unchanged_sha256"] == r.sha(work / "schema.json")
    assert invocation["transport_schema_sha256"] == inventory["transport-schema.json"] == r.sha(work / "transport-schema.json")
    assert inventory["INVOCATION.json"] == r.sha(work / "INVOCATION.json")
    before = dict(r.fs.files), set(r.fs.dirs)
    assert review.validate_job(r, work) == r.read(work / "output.json")
    result = review.aggregate(r)
    assert result["counts"] == {"PASS": 2, "HOLD": 0, "ERROR": 0, "PENDING": 0}
    assert result["denominator"] == 2 and result["all_supplied_cases_review_pass"] is True
    assert (r.fs.files, r.fs.dirs) == before


@pytest.mark.parametrize("defect", ["missing-file", "missing-inventory-entry", "extra-inventory-entry",
                                   "missing-transport-binding", "null-transport-binding", "wrong-transport-binding",
                                   "missing-local-binding", "wrong-local-binding", "transport-bytes",
                                   "transport-inventory-hash", "invocation-inventory-hash", "invocation-bytes"])
def test_transport_missing_and_tampered_bindings_reject_without_false_pass(memory, defect):
    r = memory
    review.prepare_jobs(r, **supplied(2))
    work = jobs(r)[0]
    complete(r, work, transport=True)
    invocation = r.read(work / "INVOCATION.json")
    receipt = r.read(input_receipt(r, work))
    inventory = receipt["input_inventory"]
    match = "protected input bytes changed"
    error = review.NoveltyReviewError
    if defect == "missing-file":
        # Simulate an absent file in memory; no filesystem deletion.
        r.fs.files.pop(work / "transport-schema.json")
        error, match = FileNotFoundError, "transport-schema"
    elif defect == "missing-inventory-entry":
        inventory.pop("transport-schema.json")
        match = "protected input inventory differs"
    elif defect == "extra-inventory-entry":
        inventory["synthetic-answer.json"] = "0" * 64
        match = "protected input inventory differs"
    elif defect in ("missing-transport-binding", "null-transport-binding", "wrong-transport-binding",
                    "missing-local-binding", "wrong-local-binding"):
        key = "local_schema_unchanged_sha256" if "local" in defect else "transport_schema_sha256"
        if defect.startswith("missing"):
            invocation.pop(key)
        else:
            invocation[key] = None if defect.startswith("null") else "0" * 64
        tamper(r, work / "INVOCATION.json", invocation)
        inventory["INVOCATION.json"] = r.sha(work / "INVOCATION.json")
        match = ("protected input inventory differs" if defect in ("missing-transport-binding", "null-transport-binding")
                 else "exact locally validated projection")
    elif defect == "transport-bytes":
        r.fs.files[work / "transport-schema.json"] += b" "
        match = "exact locally validated projection"
    elif defect == "transport-inventory-hash":
        inventory["transport-schema.json"] = "0" * 64
    elif defect == "invocation-inventory-hash":
        inventory["INVOCATION.json"] = "0" * 64
    else:
        r.fs.files[work / "INVOCATION.json"] += b" "
    tamper(r, input_receipt(r, work), receipt)
    before = dict(r.fs.files), set(r.fs.dirs)
    with pytest.raises(error, match=match):
        review.validate_job(r, work)
    result = review.aggregate(r)
    assert result["denominator"] == result["counts"]["ERROR"] == 2
    assert result["counts"]["PASS"] == 0 and result["all_supplied_cases_review_pass"] is False
    assert (r.fs.files, r.fs.dirs) == before
    assert not any(path.name == "synthetic-answer.json" for path in r.fs.reads)


@pytest.mark.parametrize("defect", ["restore-unique-items", "drop-min-length", "change-max-items",
                                   "drop-required", "extra-properties", "change-enum", "false-as-zero"])
def test_changed_transport_projection_rejects_even_with_matching_receipt_hashes(memory, defect):
    r = memory
    review.prepare_jobs(r, **supplied(2))
    work = jobs(r)[0]
    complete(r, work, transport=True)
    projected = r.read(work / "transport-schema.json")
    row_schema = projected["properties"]["reviews"]["items"]
    if defect == "restore-unique-items":
        row_schema["properties"]["compared_reference_ids"]["uniqueItems"] = True
    elif defect == "drop-min-length":
        row_schema["properties"]["reason"].pop("minLength")
    elif defect == "change-max-items":
        projected["properties"]["reviews"]["maxItems"] = review.JOB_SIZE + 1
    elif defect == "drop-required":
        row_schema["required"].remove("full_comparison_completed")
    elif defect == "extra-properties":
        row_schema["additionalProperties"] = True
    elif defect == "change-enum":
        row_schema["properties"]["novelty"]["enum"].append("SKIP")
    else:
        # Python dict equality considers False == 0; JSON schemas distinguish them.
        row_schema["additionalProperties"] = 0
    tamper(r, work / "transport-schema.json", projected)
    invocation = r.read(work / "INVOCATION.json")
    invocation["transport_schema_sha256"] = r.sha(work / "transport-schema.json")
    tamper(r, work / "INVOCATION.json", invocation)
    receipt = r.read(input_receipt(r, work))
    for name in ("transport-schema.json", "INVOCATION.json"):
        receipt["input_inventory"][name] = r.sha(work / name)
    tamper(r, input_receipt(r, work), receipt)
    before = dict(r.fs.files), set(r.fs.dirs)
    with pytest.raises(review.NoveltyReviewError, match="exact locally validated projection"):
        review.validate_job(r, work)
    result = review.aggregate(r)
    assert result["denominator"] == result["counts"]["ERROR"] == 2
    assert not result["all_supplied_cases_review_pass"]
    assert (r.fs.files, r.fs.dirs) == before


@pytest.mark.parametrize("novelty", ["PASS", "HOLD"])
def test_transport_does_not_remove_original_local_uniqueness_constraint(memory, novelty):
    r = memory
    review.prepare_jobs(r, **supplied(2))
    work = jobs(r)[0]
    rows = decisions(r, work)
    rows[0]["novelty"] = novelty
    rows[0]["compared_reference_ids"] = ["exposed_questions:far-reference"] * 2
    complete(r, work, rows=rows, transport=True)
    output = r.read(work / "output.json")
    jsonschema.validate(output, r.read(work / "transport-schema.json"))
    with pytest.raises(jsonschema.ValidationError, match="non-unique"):
        review.validate_job(r, work)
    result = review.aggregate(r)
    assert result["counts"] == {"PASS": 0, "HOLD": 0, "ERROR": 2, "PENDING": 0}
    assert not result["all_supplied_cases_review_pass"]
