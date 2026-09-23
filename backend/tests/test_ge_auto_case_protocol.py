"""Disk-free synthetic dependency fakes: NOT model, research, parse or index proof.

Run: python3 -B -m unittest backend.tests.test_ge_auto_case_protocol -v
No .private/evaluation material, network, provider, database or actual model jobs.
Filesystem syscall tests use mocks. The memory store retains failed bytes and
never calls filesystem cleanup, deletion or overwrite operations.
"""

from __future__ import annotations

import copy
import errno
import os
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import ge_auto_case_protocol as p


H = p.digest(b"synthetic dependency receipt; not real execution evidence")
RETRY = p.digest(b"frozen synthetic changed transport profile")
URL = "https://www.legislation.gov.uk/synthetic-fixture"


class MemoryStore:
    def __init__(self, root="/synthetic/case-A"):
        self.root, self.files, self.dirs = Path(root), {}, {""}
        self.accesses, self.locked = [], False

    def read(self, name):
        p.parts(name)
        self.accesses.append(("read", name))
        if name not in self.files:
            raise FileNotFoundError(name)
        return self.files[name]

    def exists(self, name):
        p.parts(name)
        self.accesses.append(("exists", name))
        return name in self.files or name in self.dirs

    def write_new(self, name, raw):
        p.parts(name)
        self.accesses.append(("write", name))
        if name in self.files or name in self.dirs:
            raise FileExistsError(name)
        if name.rpartition("/")[0] not in self.dirs:
            raise FileNotFoundError(name)
        self.files[name] = bytes(raw)

    def mkdir_new(self, name):
        p.parts(name)
        if name in self.files or name in self.dirs:
            raise FileExistsError(name)
        if name.rpartition("/")[0] not in self.dirs:
            raise FileNotFoundError(name)
        self.dirs.add(name)

    @contextmanager
    def lock(self):
        if self.locked:
            raise BlockingIOError()
        self.locked = True
        try:
            yield
        finally:
            self.locked = False


def request(case_id="opaque-A", turn=1, history=None):
    raw = b"PRIVATE synthetic upload contents"
    return {"schema": p.VERSION, "case_id": case_id, "turn": turn,
        "question": "PRIVATE PERSON ALPHA needs help with a notice in Scotland.",
        "jurisdictions": ["Scotland"], "as_of_date": "2026-09-05",
        "due_uploads": [{"upload_id": "u1", "sha256": p.digest(raw), "media_type": "text/plain",
                         "text": raw.decode(), "text_sha256": p.digest(raw), "extraction_sha256": H}],
        "history": history or []}


def source(url=URL):
    text = "Synthetic source statement. Condition A applies."
    context = "Synthetic revision applies from 2026-01-01 to 2026-12-31."
    return {"canonical_url": url, "final_url": url, "redirect_chain": [],
        "fetched_at": "2026-09-05T00:00:00+00:00", "raw": ("<html>" + text + context + url + "</html>").encode(),
        "parser_sha256": H, "parser_receipt_sha256": H,
        "parts": [{"part_id": "s1", "parent_id": None, "locator": "synthetic section 1", "text": text},
                  {"part_id": "s2", "parent_id": "s1", "locator": "synthetic revision context", "text": context}]}


def span(src, part_id, text=None):
    part = next(part for part in src["parts"] if part["part_id"] == part_id)
    text = text if text is not None else part["text"]
    offset = part["text"].index(text)
    return {"source_sha256": src["source_sha256"], "part_id": part_id,
            "start": offset, "end": offset + len(text), "text": text}


class FakeHost:
    """Intentional trusted-boundary fake. Its assertions are not provider receipts."""
    def __init__(self, store=None, *, retry_profiles=()):
        self.store = store or MemoryStore()
        self.capability = object()
        self.policy = p.FrozenPolicy("synthetic-run", H, H, "EMPTY", p.digest([]), retry_profiles)
        self.events, self.guards, self.jobs = [], [], []
        self.query_count, self.capture_count, self.final_count = 0, 0, 0
        self.role_mutations, self.failures = {}, {}
        self.search_urls = [URL]
        self.deny_action = None
        self.last_index = None
        self.reject_public_private_text = True

    def protocol(self):
        return p.CaseProtocol(case_root=self.store.root, policy=self.policy, capability=self.capability,
                              guard=self.guard, store=self.store)

    def guard(self, capability, binding):
        self.guards.append(copy.deepcopy(binding))
        if capability is not self.capability or binding["case_root"] != str(self.store.root):
            return False
        if binding["action"] == self.deny_action:
            return False
        if binding["action"] == "public_query" and self.reject_public_private_text:
            return "PRIVATE" not in binding["query"]["query"]
        return True

    def marker(self, binding):
        self.events.append("marker")
        self.assert_no_private(binding)
        return {k: binding[k] for k in ("run_id", "policy_sha256", "baseline_sha256")} | {
            "marker_sha256": H, "global_pre_answer_one_pass": True}

    @staticmethod
    def assert_no_private(data):
        assert "PRIVATE" not in p.canonical(data).decode()
        assert "oracle" not in data

    def maybe_fail(self, stage):
        count = self.failures.get(stage, 0)
        if count:
            self.failures[stage] = count - 1
            raise RuntimeError("PRIVATE exception details must not leak into receipts")

    def invoke(self, job):
        self.events.append(job.role)
        self.jobs.append(job)
        assert not job.allow_browsing
        assert p.digest(job.input) == job.input_sha256
        assert job.root.is_relative_to(self.store.root)
        if job.role == "final":
            self.final_count += 1
        self.maybe_fail(job.role)
        data = job.input["payload"]
        if job.role == "planner":
            value = {"queries": [{"gap_id": "g1", "kind": "missing_authority",
                "query": "Scotland written notice statutory requirements current commencement",
                "jurisdiction": "Scotland", "as_of_date": "2026-09-05"}], "clarifications": [], "holds": []}
        elif job.role == "selector":
            self.assert_no_private(data)
            value = {"urls": list(self.search_urls), "holds": []}
        elif job.role == "mapper":
            self.assert_no_private(data)
            src = data["sources"][0]
            prop = {"proposition_id": "prop-1", "jurisdiction": "Scotland", "as_of_date": "2026-09-05",
                "point": span(src, "s1", "Synthetic source statement."),
                "conditions": [span(src, "s1", "Condition A applies.")], "context": [span(src, "s1")],
                "currentness": {"status": "VERIFIED", "checks": [span(src, "s2")],
                                "valid_from": "2026-01-01", "valid_to": "2026-12-31"}}
            value = {"propositions": [prop], "holds": []}
        elif job.role == "reviewer":
            self.assert_no_private(data)
            value = {"sources": [{"source_sha256": s["source_sha256"], "decision": "ELIGIBLE",
                                   "checks": {k: True for k in p.SOURCE_CHECKS}, "holds": []} for s in data["sources"]],
                     "propositions": [{"proposition_id": prop["proposition_id"], "proposition_sha256": p.digest(prop),
                         "decision": "ELIGIBLE", "checks": {k: True for k in p.PROPOSITION_CHECKS}, "holds": []}
                         for prop in data["mapping"]["propositions"]]}
        else:
            ids = [e["proposition"]["proposition_id"] for e in data["EvidencePack"]["evidence"]]
            value = {"status": "ANSWER" if ids else "CLARIFICATION", "answer": "Synthetic dependency answer only.",
                     "cited_proposition_ids": ids}
        if job.role in self.role_mutations:
            self.role_mutations[job.role](value, data)
        return {"context_id": job.context_id, "input_sha256": job.input_sha256,
                "receipt_sha256": H, "output": value}

    def search(self, envelope, reservation):
        self.events.append("search")
        self.query_count += 1
        self.assert_no_private(envelope)
        self.assert_reserved("search", envelope, reservation)
        self.maybe_fail("search")
        hits = [{"url": url, "title": "Synthetic official source", "snippet": "Synthetic discovery snippet"}
                for url in self.search_urls]
        return {"tool": "functions.web", "tool_receipt_sha256": H, "raw_utf8": p.canonical(hits).decode(), "hits": hits}

    def capture(self, envelope, reservation):
        self.events.append("capture")
        self.capture_count += 1
        self.assert_no_private(envelope)
        self.assert_reserved("capture", envelope, reservation)
        self.maybe_fail("capture")
        return source(envelope["data"]["url"])

    def assert_reserved(self, kind, envelope, reservation):
        allocation = reservation["budget"]
        assert allocation is not None
        assert p.decode(self.store.read(f"budget/{kind}-{allocation['ordinal']:02d}.json")) == allocation
        assert allocation["input_sha256"] == p.digest(envelope)
        assert allocation["ordinal"] <= (4 if kind == "search" else 8)

    def official(self, url):
        return url.startswith("https://www.legislation.gov.uk/")

    def index(self, envelope, reservation):
        self.events.append("index")
        self.assert_no_private(envelope)
        self.maybe_fail("index")
        self.last_index = copy.deepcopy(envelope["data"])
        assert "question" not in self.last_index
        assert "history" not in self.last_index
        assert "due_uploads" not in self.last_index
        return {"build_sha256": H, "generation_sha256": H, "receipt_sha256": H,
                "baseline_sha256": self.policy.baseline_sha256, "legal_input_sha256": p.digest(self.last_index),
                "case_id": self.last_index["case_id"], "non_live": True, "active_mutated": False}

    def retrieve(self, envelope, reservation):
        self.events.append("retrieve")
        self.assert_no_private(envelope)
        self.maybe_fail("retrieve")
        return {"baseline_sha256": self.policy.baseline_sha256, "generation_sha256": H,
                "receipt_sha256": H, "evidence": [{"origin": "CASE_LOCAL", "proposition": prop,
                    "eligibility_receipt_sha256": self.last_index["review_sha256"]}
                    for prop in self.last_index["propositions"]]}

    def run(self, req=None, **overrides):
        req = req or request()
        callbacks = {"uploads": {"u1": b"PRIVATE synthetic upload contents"}, "establish_one_pass": self.marker,
                     "invoke_role": self.invoke, "search": self.search, "capture": self.capture,
                     "official_url": self.official, "index": self.index, "retrieve": self.retrieve}
        callbacks.update(overrides)
        return self.protocol().run_case(req, **callbacks)


class CaseProtocolTests(unittest.TestCase):
    def test_actual_callback_order_disclosure_boundaries_and_receipts(self):
        host = FakeHost()
        result = host.run()
        self.assertEqual(host.events, ["marker", "planner", "search", "selector", "capture", "mapper", "reviewer", "index", "retrieve", "final"])
        self.assertEqual(result["dispatch"], "EXECUTED_CALLBACKS")
        self.assertEqual(result["state"], "FINAL_RECORDED_AWAITING_BLIND_SCORING")
        self.assertEqual(result["actual_parent_validation"], "NOT_ESTABLISHED_BY_PROTOCOL")
        self.assertFalse(result["context_ids_are_custody_proof"])
        contexts = [job.context_id for job in host.jobs]
        self.assertEqual(len(contexts), len(set(contexts)))
        for job in host.jobs:
            self.assertEqual(job.schema, p.SCHEMAS[job.role])
            self.assertIn("No browsing", job.prompt)
            prefix = job.root.relative_to(host.store.root).as_posix()
            self.assertEqual(p.digest(host.store.read(prefix + "/input.json")), job.input_sha256)
            if job.role in ("planner", "final"):
                self.assertEqual(host.store.read(prefix + "/upload-01.bytes"), b"PRIVATE synthetic upload contents")
            if job.role in ("mapper", "reviewer"):
                self.assertEqual(host.store.read(prefix + "/source-01.bytes"), source()["raw"])
        final = host.jobs[-1].input["payload"]
        self.assertEqual(set(final), {"facts", "EvidencePack", "holds", "clarifications"})
        self.assertEqual(final["EvidencePack"]["evidence"][0]["proposition"]["conditions"][0]["text"], "Condition A applies.")
        references = final["EvidencePack"]["source_references"]
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0]["sources"][0]["canonical_url"], URL)
        self.assertEqual({r["part_id"] for r in references[0]["sources"][0]["locators"]}, {"s1", "s2"})
        self.assertNotIn("text", references[0]["sources"][0])
        self.assertEqual(set(references[0]["sources"][0]), {"source_sha256", "canonical_url", "final_url", "locators"})
        self.assertTrue(all(not name.startswith((".private", "data/evaluations")) for _, name in host.store.accesses))

    def test_global_marker_denial_prevents_question_storage_and_all_roles(self):
        host = FakeHost()
        host.deny_action = "global_one_pass_receipt"
        with self.assertRaisesRegex(p.ProtocolError, "CAPABILITY_DENIED"):
            host.run()
        self.assertEqual(host.events, ["marker"])
        self.assertFalse(any(b"PRIVATE" in raw for raw in host.store.files.values()))
        self.assertNotIn("turn-0001/request.json", host.store.files)
        host = FakeHost()
        with self.assertRaises(p.ProtocolError):
            host.run(establish_one_pass=lambda binding: {"global_pre_answer_one_pass": False})
        self.assertEqual(host.jobs, [])

    def test_capability_wrong_root_baseline_and_crosscase_denied(self):
        host = FakeHost()
        host.deny_action = "case_protocol_start"
        with self.assertRaisesRegex(p.ProtocolError, "CAPABILITY_DENIED"):
            host.run()
        self.assertEqual(host.store.accesses, [])
        self.assertEqual(host.events, [])
        host = FakeHost()
        host.run()
        before = dict(host.store.files)
        with self.assertRaisesRegex(p.ProtocolError, "CASE_OR_BASELINE_CHANGED"):
            host.run(request("opaque-B"))
        self.assertEqual(before, host.store.files)
        host.policy = p.FrozenPolicy("synthetic-run", H, H, "SHARED_FROZEN", p.digest(b"different baseline"))
        with self.assertRaisesRegex(p.ProtocolError, "CASE_OR_BASELINE_CHANGED"):
            host.run()
        with self.assertRaisesRegex(p.ProtocolError, "STORE_ROOT_MISMATCH"):
            p.CaseProtocol(case_root="/synthetic/case-B", policy=host.policy, capability=host.capability,
                           guard=host.guard, store=host.store)

    def test_duplicate_complete_request_is_noop_and_sealed_question_cannot_change(self):
        host = FakeHost()
        first = host.run()
        events, files = list(host.events), dict(host.store.files)
        second = host.run()
        self.assertEqual(second["dispatch"], "NO_OP_COMPLETE")
        self.assertEqual(first["terminal_sha256"], second["terminal_sha256"])
        self.assertEqual(host.events, events)
        self.assertEqual(host.store.files, files)
        changed = request()
        changed["question"] += " Easier replacement question."
        with self.assertRaisesRegex(p.ProtocolError, "SEALED_REQUEST_CHANGED"):
            host.run(changed)
        self.assertEqual(host.final_count, 1)

    def test_missing_facts_are_clarifications_without_research(self):
        host = FakeHost()
        host.role_mutations["planner"] = lambda value, _: value.update(queries=[],
            clarifications=[{"gap_id": "where", "question": "Which jurisdiction applies?"}], holds=["UNKNOWN_JURISDICTION"])
        req = request()
        req.update(jurisdictions=[], as_of_date=None)
        result = host.run(req)
        self.assertEqual(host.events, ["marker", "planner", "final"])
        self.assertEqual(result["answer"]["status"], "CLARIFICATION")
        self.assertEqual(host.query_count, 0)
        host = FakeHost()
        host.role_mutations["planner"] = lambda value, _: value["clarifications"].append({"gap_id": "g1", "question": "A missing private fact?"})
        result = host.run()
        self.assertIn("MISSING_FACT_CANNOT_BE_RESEARCHED", result["holds"])
        self.assertEqual(host.query_count, 0)

    def test_private_queries_unknown_scope_and_oversized_plans_never_search(self):
        changes = [lambda v: v["queries"][0].update(query="PRIVATE PERSON ALPHA account details"),
                   lambda v: v["queries"][0].update(jurisdiction="California"),
                   lambda v: v["queries"][0].update(as_of_date="2025-01-01"),
                   lambda v: v["queries"].extend(copy.deepcopy(v["queries"]) * 4),
                   lambda v: v["queries"][0].update(kind="missing_fact")]
        for change in changes:
            host = FakeHost()
            host.role_mutations["planner"] = lambda value, _, fn=change: fn(value)
            result = host.run()
            self.assertEqual(host.query_count, 0)
            self.assertEqual(result["answer"]["status"], "CLARIFICATION")

    def test_only_own_search_result_official_urls_can_be_captured(self):
        for url in ("https://www.legislation.gov.uk/not-returned", "https://evil.example/source", "../other-case"):
            host = FakeHost()
            host.role_mutations["selector"] = lambda value, _, url=url: value.update(urls=[url])
            result = host.run()
            self.assertEqual(host.capture_count, 0)
            self.assertNotIn("index", host.events)
            self.assertTrue(result["holds"])
        host = FakeHost()
        host.search_urls = ["https://evil.example/source"]
        result = host.run()
        self.assertIn("URL_NOT_IN_SELECTABLE_OFFICIAL_RESULTS", result["holds"])
        self.assertEqual(host.capture_count, 0)

    def test_selector_sees_only_search_results_accepted_by_the_host_source_policy(self):
        host = FakeHost()
        rejected = "https://law.gov.wales/status"
        host.search_urls = [URL, rejected]

        def inspect(value, payload):
            self.assertEqual(payload["selectable_exact_urls"], [URL])
            self.assertEqual(
                {hit["url"] for result in payload["own_search_results"] for hit in result["hits"]},
                {URL, rejected},
            )
            value["urls"] = [URL]

        host.role_mutations["selector"] = inspect
        result = host.run()
        self.assertEqual(result["answer"]["status"], "ANSWER")
        self.assertEqual(host.capture_count, 1)

    def test_duplicate_queries_and_urls_do_not_spend_extra_budget(self):
        host = FakeHost()
        host.role_mutations["planner"] = lambda value, _: value["queries"].append(copy.deepcopy(value["queries"][0]))
        host.role_mutations["selector"] = lambda value, _: value["urls"].append(value["urls"][0])
        host.run()
        self.assertEqual((host.query_count, host.capture_count), (1, 1))
        self.assertEqual(len([k for k in host.store.files if k.startswith("budget/")]), 2)

    def test_four_query_eight_capture_hard_ceiling_reserved_before_callbacks(self):
        host = FakeHost()
        host.search_urls = [URL + f"-{i}" for i in range(8)]
        def plan(value, _):
            original = value["queries"][0]
            value["queries"] = [{**original, "gap_id": f"g{i}", "query": original["query"] + f" subissue {i}"} for i in range(4)]
        host.role_mutations["planner"] = plan
        first = host.run()
        self.assertEqual((host.query_count, host.capture_count), (4, 8))
        second_request = request(turn=2, history=[{"turn": 1, "request_sha256": first["request_sha256"], "terminal_sha256": first["terminal_sha256"]}])
        host.role_mutations["planner"] = lambda value, _: value["queries"][0].update(query="Scotland a different legal research question")
        result = host.run(second_request)
        self.assertIn("BUDGET_EXHAUSTED", result["holds"])
        self.assertEqual((host.query_count, host.capture_count), (4, 8))

    def test_one_changed_retry_two_failures_stop_and_error_prose_is_not_logged(self):
        host = FakeHost(retry_profiles=(RETRY,))
        host.failures["search"] = 2
        profiles = []
        def choose(kind, failure):
            profiles.append((kind, failure))
            return RETRY if kind == "search" else None
        result = host.run(choose_retry=choose)
        self.assertEqual(host.query_count, 2)
        self.assertIn("TWO_FAILURES_STOP", result["holds"])
        self.assertEqual(len(profiles), 1)
        attempts = [p.decode(raw) for name, raw in host.store.files.items()
                    if name.startswith("operations/search-") and name.endswith("/input.json")]
        self.assertEqual([a["retry_profile_sha256"] for a in attempts], [None, RETRY])
        failures = [raw for name, raw in host.store.files.items() if name.endswith("/failure.json")]
        self.assertTrue(failures)
        self.assertTrue(all(b"PRIVATE exception" not in raw for raw in failures))
        before = host.query_count
        host.run(choose_retry=choose)
        self.assertEqual(host.query_count, before)

    def test_unfrozen_retry_denied_and_retry_consumes_remaining_query_budget(self):
        host = FakeHost()
        host.failures["search"] = 1
        with self.assertRaisesRegex(p.ProtocolError, "UNFROZEN_RETRY_PROFILE"):
            host.run(choose_retry=lambda *_: RETRY)
        self.assertEqual(host.query_count, 1)
        host = FakeHost(retry_profiles=(RETRY,))
        host.role_mutations["planner"] = lambda v, _: v.update(queries=[{**v["queries"][0], "query": f"Scotland public legal issue {i}"} for i in range(4)])
        host.failures["search"] = 1
        result = host.run(choose_retry=lambda kind, failure: RETRY if kind == "search" else None)
        self.assertEqual(host.query_count, 4)
        self.assertIn("BUDGET_EXHAUSTED", result["holds"])

    def test_capture_redirect_parse_hierarchy_and_source_quote_fail_closed(self):
        for mutation, expected in (
            (lambda v: v.update(final_url="https://evil.example/redirect", redirect_chain=[URL, "https://evil.example/redirect"]), "UNVERIFIED_OFFICIAL_URL"),
            (lambda v: v["parts"][0].update(parent_id="s2"), "BROKEN_STRUCTURAL_HIERARCHY"),
            (lambda v: v.update(raw=b""), "SCHEMA_MISMATCH"),
        ):
            host = FakeHost()
            def capture(envelope, reservation, fn=mutation):
                result = host.capture(envelope, reservation)
                fn(result)
                return result
            result = host.run(capture=capture)
            self.assertIn(expected, result["holds"])
            self.assertNotIn("index", host.events)
        host = FakeHost()
        host.role_mutations["mapper"] = lambda v, _: v["propositions"][0]["point"].update(text="Invented statutory rule")
        result = host.run()
        self.assertIn("SOURCE_QUOTE_MISMATCH", result["holds"])
        self.assertNotIn("reviewer", host.events)

    def test_capture_incompatible_host_is_disclosed_and_refused(self):
        self.assertIn("uscode.house.gov", p.CAPTURE_UNAVAILABLE_HOSTS)
        self.assertFalse(p.capture_host_supported(
            "https://uscode.house.gov/view.xhtml?edition=prelim"))
        self.assertTrue(p.capture_host_supported(
            "https://www.govinfo.gov/content/pkg/USCODE-2024-title15/pdf/source.pdf"))
        self.assertIn("capture_unavailable_hosts", p.PROMPTS["selector"])
        self.assertIn("selectable_exact_urls", p.PROMPTS["selector"])
        self.assertIn("differs by even one character", p.PROMPTS["selector"])
        self.assertIn("official consolidated/version-status source", p.PROMPTS["selector"])
        self.assertIn("Do not leave a\ncurrentness HOLD merely to keep the set minimal", p.PROMPTS["selector"])

    def test_legislation_identity_can_yield_only_exact_point_in_time_xml(self):
        expected = "https://www.legislation.gov.uk/anaw/2019/2/2026-09-05/data.xml"
        for source in (
            "https://www.legislation.gov.uk/anaw/2019/2/pdfs/anaw_20190002_en.pdf",
            "https://legislation.gov.uk/anaw/2019/2/section/3?view=extent",
        ):
            self.assertEqual(p.legislation_point_in_time_url(source, "2026-09-05"), expected)
        for refused in (
            "https://evil.example/anaw/2019/2/data.xml",
            "https://www.legislation.gov.uk:443/anaw/2019/2/data.xml",
            "https://www.legislation.gov.uk/help/page",
            "http://www.legislation.gov.uk/anaw/2019/2/data.xml",
        ):
            self.assertIsNone(p.legislation_point_in_time_url(refused, "2026-09-05"))
        self.assertIsNone(p.legislation_point_in_time_url(
            "https://www.legislation.gov.uk/anaw/2019/2/data.xml", "2026-09-31"))

    def test_mapper_prompt_requires_exact_unicode_character_offsets(self):
        prompt = p.PROMPTS["mapper"]
        self.assertIn("host copies part.text[start:end] exactly", prompt)
        self.assertIn(r"\u00a0", prompt)

    def test_mapper_span_canonicalizer_repairs_only_unique_exact_evidence(self):
        source_sha = "a" * 64
        part_text = "Rule requires notice under §\u00a01006.34 before collection."
        span = {"source_sha256": source_sha, "part_id": "block-000001", "start": 0,
                "end": len(part_text) + 2,
                "text": part_text.replace("\u00a0", "\x11a0")}
        currentness = {"status": "UNRESOLVED", "valid_from": None, "valid_to": None,
                       "checks": []}
        context = {"source_sha256": source_sha, "part_id": "block-000001", "start": 0,
                   "end": len(part_text), "text": part_text}
        value = {"propositions": [{"proposition_id": "synthetic_rule", "jurisdiction": "US federal",
            "as_of_date": "2026-09-04", "point": span, "conditions": [], "context": [context],
            "currentness": currentness}], "holds": ["CURRENTNESS_UNRESOLVED"]}
        payload = {"sources": [{"source_sha256": source_sha,
            "parts": [{"part_id": "block-000001", "text": part_text}]}]}
        normalized, receipt = p.canonicalize_mapper_spans(value, payload)
        fixed = normalized["propositions"][0]["point"]
        self.assertEqual(fixed, {**span, "end": len(part_text), "text": part_text})
        self.assertEqual(receipt["repair_count"], 1)
        self.assertFalse(receipt["fuzzy_matching"])
        duplicate = copy.deepcopy(payload)
        duplicate["sources"][0]["parts"][0]["text"] = part_text + " " + part_text
        with self.assertRaisesRegex(p.ProtocolError, "SOURCE_QUOTE_MISMATCH"):
            p.canonicalize_mapper_spans(value, duplicate)

        # Observed whole-part serialization defect: SOH in place of NBSP.
        # The repair must still prove the entire quote against the named part.
        value["propositions"][0]["point"].update(
            text=part_text.replace("\u00a0", "\x01"), end=len(part_text))
        normalized, receipt = p.canonicalize_mapper_spans(value, payload)
        self.assertEqual(normalized["propositions"][0]["point"]["text"], part_text)
        self.assertEqual(receipt["repair_count"], 1)
        self.assertIn("\x01", value["propositions"][0]["point"]["text"])
        for bad_text in (part_text.replace("notice", "consent").replace("\u00a0", "\x01"),
                         part_text.replace("\u00a0", " "),
                         part_text.replace("\u00a0", "\x02")):
            value["propositions"][0]["point"]["text"] = bad_text
            with self.assertRaisesRegex(p.ProtocolError, "SOURCE_QUOTE_MISMATCH"):
                p.canonicalize_mapper_spans(value, payload)

    def test_mapper_reference_transport_preserves_exact_unicode_and_rejects_bad_references(self):
        text = "A\u00a0rule 👩🏽‍⚖️\nrequires notice; an exception follows."
        span = {"source_sha256": "a" * 64, "part_id": "p1", "start": 0, "end": len(text)}
        value = {"propositions": [{"proposition_id": "p1", "jurisdiction": "Wales",
            "as_of_date": "2026-09-05", "point": span, "conditions": [], "context": [span],
            "currentness": {"status": "UNRESOLVED", "checks": [span],
                            "valid_from": None, "valid_to": None}}], "holds": ["CURRENTNESS_UNRESOLVED"]}
        payload = {"sources": [{"source_sha256": "a" * 64, "parts": [{"part_id": "p1", "text": text}]}]}
        resolved, receipt = p.materialize_mapper_spans(value, payload)
        self.assertEqual(resolved["propositions"][0]["point"]["text"], text)
        self.assertNotIn("text", value["propositions"][0]["point"])
        self.assertEqual(resolved["holds"], value["holds"])
        self.assertEqual(receipt["span_count"], 3)
        self.assertFalse(receipt["legal_eligibility_assessed"])
        for field, bad in [("source_sha256", "b" * 64), ("part_id", "missing"),
                           ("end", len(text) + 1), ("end", 0), ("start", len(text)),
                           ("start", True), ("text", "model invented quote")]:
            changed = copy.deepcopy(value)
            changed["propositions"][0]["point"][field] = bad
            with self.assertRaises(p.ProtocolError):
                p.materialize_mapper_spans(changed, payload)
        duplicate = copy.deepcopy(payload)
        duplicate["sources"].append(copy.deepcopy(duplicate["sources"][0]))
        with self.assertRaisesRegex(p.ProtocolError, "DUPLICATE_MAPPER_SOURCE"):
            p.materialize_mapper_spans(value, duplicate)
        duplicate = copy.deepcopy(payload)
        duplicate["sources"][0]["parts"].append({"part_id": "p1", "text": "different"})
        with self.assertRaisesRegex(p.ProtocolError, "DUPLICATE_MAPPER_PART"):
            p.materialize_mapper_spans(value, duplicate)

    def test_source_review_exact_coverage_hashes_conditions_and_unknown_currentness(self):
        changes = [lambda v: v["sources"][0]["checks"].update(official_identity=False),
                   lambda v: v["propositions"][0].update(proposition_sha256="0" * 64),
                   lambda v: v["propositions"][0]["checks"].update(complete_conditions=False),
                   lambda v: v.update(sources=[])]
        for change in changes:
            host = FakeHost()
            host.role_mutations["reviewer"] = lambda value, _, fn=change: fn(value)
            result = host.run()
            self.assertNotIn("index", host.events)
            self.assertTrue(result["holds"])
        host = FakeHost()
        host.role_mutations["mapper"] = lambda v, _: v["propositions"][0]["currentness"].update(status="UNRESOLVED", checks=[], valid_from=None, valid_to=None)
        result = host.run()
        self.assertNotIn("index", host.events)
        self.assertEqual(result["answer"]["status"], "CLARIFICATION")

    def test_reviewer_hold_is_terminal_eligibility_not_automatic_admission(self):
        host = FakeHost()
        def hold(value, _):
            value["propositions"][0].update(decision="HOLD", holds=["CURRENTNESS_UNRESOLVED"])
        host.role_mutations["reviewer"] = hold
        result = host.run()
        self.assertIn("CURRENTNESS_UNRESOLVED", result["holds"])
        self.assertNotIn("index", host.events)
        self.assertEqual(host.final_count, 1)

    def test_unretrieved_or_tampered_evidence_never_reaches_final(self):
        for change in (
            lambda value: value.update(generation_sha256="0" * 64),
            lambda value: value["evidence"][0]["proposition"]["conditions"].clear(),
            lambda value: value["evidence"][0].update(origin="SHARED_BASELINE"),
            lambda value: value["evidence"][0]["proposition"].update(jurisdiction="California"),
        ):
            host = FakeHost()
            def retrieve(envelope, reservation, change=change):
                value = copy.deepcopy(host.retrieve(envelope, reservation))
                change(value)
                return value
            result = host.run(retrieve=retrieve)
            self.assertEqual(host.jobs[-1].input["payload"]["EvidencePack"]["evidence"], [])
            self.assertEqual(result["answer"]["status"], "CLARIFICATION")

    def test_final_attempt_is_consumed_on_failure_invalid_citation_or_uncertainty(self):
        for fail in (True, False):
            host = FakeHost(retry_profiles=(RETRY,))
            if fail:
                host.failures["final"] = 1
            else:
                host.role_mutations["final"] = lambda value, _: value.update(cited_proposition_ids=["unretrieved-id"])
            result = host.run(choose_retry=lambda *_: RETRY)
            self.assertIsNone(result["answer"])
            self.assertEqual(result["state"], "HOLD_FINAL_ATTEMPT_CONSUMED")
            self.assertEqual(host.final_count, 1)
            host.run(choose_retry=lambda *_: RETRY)
            self.assertEqual(host.final_count, 1)
            self.assertFalse(any("jobs/final-a2" in name for name in host.store.files))

    def test_followup_corrections_reuse_only_own_cache_and_keep_earlier_turn_sealed(self):
        host = FakeHost()
        first = host.run()
        old = dict(host.store.files)
        req = request(turn=2, history=[{"turn": 1, "request_sha256": first["request_sha256"], "terminal_sha256": first["terminal_sha256"]}])
        req["question"] = "PRIVATE correction: the notice date was 2 September, not 1 September."
        second = host.run(req)
        self.assertEqual((host.query_count, host.capture_count), (1, 1))
        self.assertEqual(host.final_count, 2)
        self.assertTrue(all(host.store.files[name] == raw for name, raw in old.items()))
        facts = host.jobs[-1].input["payload"]["facts"]
        self.assertEqual(facts["question"], req["question"])
        self.assertEqual(facts["history"][0]["question"], request()["question"])
        self.assertEqual(facts["history"][0]["answer"], first["answer"])
        self.assertEqual(len({j.context_id for j in host.jobs}), len(host.jobs))
        self.assertIn(first["generation_sha256"], host.last_index["own_prior_generations"])
        host.protocol().mark_scored(case_id="opaque-A", receipt_sha256=H)
        third = request(turn=3, history=[*req["history"], {"turn": 2, "request_sha256": second["request_sha256"], "terminal_sha256": second["terminal_sha256"]}])
        with self.assertRaisesRegex(p.ProtocolError, "POST_SCORE_ACTION_DENIED"):
            host.run(third)
        self.assertEqual(host.final_count, 2)

    def test_foreign_history_due_uploads_and_oracle_fields_are_denied(self):
        host = FakeHost()
        first = host.run()
        req = request(turn=2, history=[{"turn": 1, "request_sha256": first["request_sha256"], "terminal_sha256": "0" * 64}])
        with self.assertRaisesRegex(p.ProtocolError, "TERMINAL_HASH_MISMATCH"):
            host.run(req)
        for field in ("oracle", "private_reference", "expected_answer", "future_turn", "case_root"):
            host = FakeHost()
            with self.assertRaisesRegex(p.ProtocolError, "SCHEMA_MISMATCH"):
                host.run(request() | {field: "secret"})
            self.assertEqual(host.store.accesses, [])
        host = FakeHost()
        with self.assertRaisesRegex(p.ProtocolError, "DUE_UPLOAD_HASH_MISMATCH"):
            host.run(uploads={"u1": b"other case upload"})
        self.assertEqual(host.jobs, [])

    def test_terminal_detects_tampered_role_input_source_output_and_policy(self):
        host = FakeHost()
        result = host.run()
        paths = ["turn-0001/request.json", "turn-0001/jobs/selector-a1/input.json",
                 "turn-0001/jobs/mapper-a1/source-01.bytes", "turn-0001/jobs/final-a1/role-receipt.json",
                 "turn-0001/EvidencePack.json", "budget/search-01.json"]
        paths += [name for name in result["artifacts"] if name.startswith("operations/retrieve-") and name.endswith("/output.json")]
        for path in paths:
            original = host.store.files[path]
            host.store.files[path] += b"tampered in synthetic memory only"
            with self.subTest(path=path), self.assertRaisesRegex(p.ProtocolError, "SEALED_ARTIFACT_TAMPERED"):
                host.run()
            host.store.files[path] = original

    def test_concurrent_caller_cannot_double_reserve(self):
        host = FakeHost()
        with host.store.lock():
            with self.assertRaises(BlockingIOError):
                host.run()
        self.assertEqual(host.events, [])

    def test_interrupted_terminal_seal_recovers_without_second_final_attempt(self):
        host = FakeHost()
        original_write = host.store.write_new
        def interrupt(name, raw):
            if name == "turn-0001/terminal.json":
                raise KeyboardInterrupt("synthetic interruption before seal")
            original_write(name, raw)
        with patch.object(host.store, "write_new", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                host.run()
        self.assertEqual(host.final_count, 1)
        preserved = dict(host.store.files)
        roles = [e for e in host.events if e in p.SCHEMAS]
        recovered = host.run()
        self.assertEqual(recovered["state"], "FINAL_RECORDED_AWAITING_BLIND_SCORING")
        self.assertEqual(host.final_count, 1)
        self.assertEqual(roles, [e for e in host.events if e in p.SCHEMAS])
        self.assertTrue(all(host.store.files[name] == raw for name, raw in preserved.items()))
        self.assertIn("turn-0001/jobs/final-a1/input.json", recovered["artifacts"])

    def test_uncertain_final_disclosure_consumed_and_failed_job_bytes_bound(self):
        host = FakeHost()
        original_invoke = host.invoke
        def uncertain(job):
            if job.role == "final":
                host.final_count += 1
                raise KeyboardInterrupt("unknown provider outcome")
            return original_invoke(job)
        with self.assertRaises(KeyboardInterrupt):
            host.run(invoke_role=uncertain)
        self.assertEqual(host.final_count, 1)
        recovered = host.run()
        self.assertIsNone(recovered["answer"])
        self.assertEqual(recovered["state"], "HOLD_FINAL_ATTEMPT_CONSUMED")
        self.assertEqual(host.final_count, 1)
        self.assertIn("turn-0001/jobs/final-a1/input.json", recovered["artifacts"])
        self.assertFalse(any("jobs/final-a2" in path for path in host.store.files))

    def test_second_attempt_crash_recovery_does_not_rechoose_profile_or_recall_provider(self):
        host = FakeHost(retry_profiles=(RETRY,))
        host.failures["search"] = 1
        choose = Mock(return_value=RETRY)
        original_write = host.store.write_new
        def interrupt(name, raw):
            if name == "turn-0001/terminal.json":
                raise KeyboardInterrupt("synthetic seal interruption")
            original_write(name, raw)
        with patch.object(host.store, "write_new", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                host.run(choose_retry=choose)
        self.assertEqual(host.query_count, 2)
        recovered = host.run(choose_retry=lambda *_: self.fail("must reuse saved profile"))
        self.assertIsNotNone(recovered["answer"])
        self.assertEqual(host.query_count, 2)
        self.assertEqual(host.final_count, 1)
        choose.assert_called_once()

    def test_store_traversal_no_follow_hardlinks_and_exclusive_writes(self):
        store = p.CaseStore("/synthetic/case-A")
        for path in ("../bank", "/private", "a/../b", "a//b", "a\\b", "./x", ""):
            with patch.object(os, "open") as opened:
                for operation in (store.read, store.exists, store.mkdir_new, lambda x: store.write_new(x, b"data")):
                    with self.assertRaises(p.ProtocolError):
                        operation(path)
                opened.assert_not_called()
        calls = []
        def opened(name, flags, *args, **kwargs):
            calls.append((name, flags, args))
            if name == "existing.json":
                raise FileExistsError()
            return 100 + len(calls)
        with patch.object(os, "open", side_effect=opened), patch.object(os, "close"):
            with self.assertRaises(FileExistsError):
                store.write_new("jobs/existing.json", b"never overwrite")
        self.assertTrue(all(flags & os.O_NOFOLLOW and not flags & os.O_TRUNC for _, flags, _ in calls))
        self.assertTrue(calls[-1][1] & os.O_EXCL)
        for component in ("synthetic", "case-A", "jobs", "leaf"):
            visited = []
            def symlink(name, flags, *args, **kwargs):
                visited.append(name)
                if name == component:
                    raise OSError(errno.ELOOP, "synthetic symlink")
                return 100 + len(visited)
            with patch.object(os, "open", side_effect=symlink), patch.object(os, "close"):
                with self.assertRaises(OSError):
                    store.read("jobs/leaf")
            self.assertEqual(visited[-1], component)


if __name__ == "__main__":
    unittest.main()
