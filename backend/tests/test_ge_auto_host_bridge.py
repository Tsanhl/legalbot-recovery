"""Own synthetic cases, memory-only storage, no network/model/bank/evaluation IO.

The real intake parser handles locally defined HTML. Network/tool outputs are
explicit synthetic test doubles, never actual web or runtime admission evidence.
No temporary directories, cache artifacts, file deletion or production mutation.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import marshal
import re
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import CodeType, FunctionType

import pytest
from scripts import ge_auto_case_protocol as p
from scripts import ge_auto_host_bridge as b
from scripts import ge_auto_research_intake as intake

URL = "https://www.legislation.gov.uk/synthetic-test-only"
NOW = "2026-09-05T00:00:00+00:00"
HTML = b"<html><body><h1>Synthetic title</h1><h2>Synthetic conditions</h2><p>Only test condition A applies.</p></body></html>"
RAW_WEB = '{"synthetic_test_only":true,"content":[{"url":"' + URL + '","title":"Synthetic title","text":"Full synthetic response; not an actual tool execution."}]}'
HITS = [{"url": URL, "title": "Synthetic title", "snippet": "Synthetic discovery only."}]
H = p.digest(b"SYNTHETIC RECEIPT ONLY; no actual tool execution")


def test_verified_tls_context_uses_fixed_existing_ca_bundle(monkeypatch, tmp_path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text("synthetic CA bundle path test; context creation is stubbed")
    monkeypatch.setattr(b.ssl, "get_default_verify_paths",
                        lambda: type("Paths", (), {"cafile": str(bundle)})())
    seen = []
    marker = object()
    monkeypatch.setattr(b.ssl, "create_default_context",
                        lambda *, cafile: seen.append(cafile) or marker)
    assert b.verified_tls_context() is marker
    assert seen == [str(bundle)]


class MemoryStore:
    def __init__(self, root="/synthetic/case-A"):
        self.root, self.files, self.dirs, self.accesses = Path(root), {}, {"", "budget", "operations"}, []
    def exists(self, name):
        p.parts(name)
        self.accesses.append(("exists", name))
        return name in self.files or name in self.dirs
    def mkdir_new(self, name):
        p.parts(name)
        assert name.rpartition("/")[0] in self.dirs
        if name in self.files or name in self.dirs:
            raise FileExistsError(name)
        self.dirs.add(name)
    def write_new(self, name, raw):
        p.parts(name)
        assert isinstance(raw, bytes) and len(raw) <= p.MAX_BYTES
        assert name.rpartition("/")[0] in self.dirs
        self.accesses.append(("write", name))
        if name in self.files or name in self.dirs:
            raise FileExistsError(name)
        self.files[name] = raw
    def read(self, name):
        p.parts(name)
        self.accesses.append(("read", name))
        if name not in self.files:
            raise FileNotFoundError(name)
        return self.files[name]


class Host:
    """Deliberate protected-parent test double with exact output/file pins."""
    def __init__(self):
        self.store, self.capability, self.pins = MemoryStore(), object(), {}
        self.events, self.sleeps, self.elapsed = [], [], 0
        self.on_sleep = None
        self.deny, self.parser_pin = None, intake.parser_binding(include_legal_tables=True)
        self.expected_raw = HTML
        self.context = b.BridgeContext("own-synthetic-case", H, p.digest(b"policy"), p.digest(b"runtime"),
            p.digest(b"capability"), b.callback_sha256(self.verify), ("Scotland",), "2026-09-05")

    def verify(self, capability, binding):
        self.events.append(copy.deepcopy(binding))
        if (capability is not self.capability or binding["case_root"] != str(self.store.root)
                or any(binding[k] != getattr(self.context, k) for k in ("case_id", "request_sha256", "policy_sha256"))
                or binding["lane"] != "candidate_case_local" or binding["action"] == self.deny):
            return False
        if "public_input" in binding and "PRIVATE PERSON" in p.canonical(binding["public_input"]).decode():
            return False
        if binding["action"] == "web_response":
            pin = self.pins.get(binding["request_file_sha256"])
            return pin is not None and all(binding[k] == value for k, value in pin.items())
        if binding["action"] == "capture_parse":
            if binding["source_sha256"] != p.digest(self.expected_raw) or binding["parser_sha256"] != self.parser_pin:
                return False
            relative = Path(binding["broker_root"]).relative_to(self.store.root).as_posix()
            return all(p.digest(self.store.files[relative + "/" + name]) == sha for name, sha in binding["files"].items())
        return True

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.elapsed += seconds
        if self.on_sleep:
            callback, self.on_sleep = self.on_sleep, None
            callback()

    def kwargs(self):
        return {"case_root": self.store.root, "context": self.context, "capability": self.capability,
                "verify": self.verify, "store": self.store, "now": lambda:NOW}

    def search(self, **kwargs):
        return b.make_search_callback(**self.kwargs(), timeout_seconds=5, poll_seconds=2,
                                     monotonic=lambda:self.elapsed, sleep=self.sleep, **kwargs)

    def capture(self, **kwargs):
        return b.make_capture_callback(**self.kwargs(), parser_sha256=self.parser_pin, **kwargs)

    def reserve(self, kind="search", *, data=None, attempt=1, ordinal=1, profile=None):
        data = data or ({"query":"Scotland public notice requirements", "jurisdiction":"Scotland", "as_of_date":"2026-09-05"}
                        if kind == "search" else {"url": URL, "as_of_date":"2026-09-05"})
        envelope = {"data": data, "retry_profile_sha256": profile}
        operation = "operations/" + kind + "-" + p.digest(data)
        root = operation + "/attempt-" + str(attempt)
        budget = {"case_id":self.context.case_id, "policy_sha256":self.context.policy_sha256,
            "request_sha256":self.context.request_sha256, "operation":operation,
            "input_sha256":p.digest(envelope), "kind":kind, "ordinal":ordinal, "maximum":4 if kind=="search" else 8}
        reservation = {k:budget[k] for k in ("case_id", "policy_sha256", "request_sha256", "input_sha256", "kind")}
        reservation.update(attempt=attempt, budget=budget, attempt_root=root)
        for directory in (operation, root):
            if directory not in self.store.dirs:
                self.store.mkdir_new(directory)
        self.store.write_new(root + "/reservation.json", p.canonical(reservation))
        self.store.write_new(root + "/input.json", p.canonical(envelope))
        self.store.write_new(f"budget/{kind}-{ordinal:02d}.json", p.canonical(budget))
        return envelope, reservation

    @staticmethod
    def broker(reservation):
        return "broker/" + reservation["kind"] + "-" + p.digest(reservation)

    def publish(self, reservation, *, pin=True, mutate=None, ready=True):
        root = self.broker(reservation)
        request = self.store.read(root + "/request.json")
        raw = b.web_response(request, raw_utf8=RAW_WEB, hits=copy.deepcopy(HITS), tool_receipt_sha256=H)
        value = p.decode(raw)
        if pin:
            result = value["result"]
            self.pins[p.digest(request)] = {"response_sha256":p.digest(raw),
                "raw_sha256":p.digest(result["raw_utf8"].encode()), "hits_sha256":p.digest(result["hits"]),
                "tool_receipt_sha256":H, "tool":"functions.web"}
        if mutate:
            raw = mutate(raw)
        self.store.write_new(root + "/response.json", raw)
        if ready:
            self.store.write_new(root + "/response-ready.json", p.canonical({"response_sha256":p.digest(raw)}))
        return raw


@pytest.fixture
def host():
    return Host()


def test_callback_hash_survives_held_constants_on_actual_runtime_and_bridge_code():
    from scripts.ge_auto_role_runtime import CodexRoleRuntime
    callbacks = (CodexRoleRuntime.__call__, b._Bridge.verify, b.HostCapture.__call__,
                 b.fetch_official, b.parse_official_capture)
    for callback in callbacks:
        expected = b.callback_sha256(callback)
        # Only inspect the actual current code: never invoke a role or transport.
        held = list(callback.__code__.co_consts)
        held += [item.co_consts for item in held if isinstance(item, CodeType)]
        assert b.callback_sha256(callback) == expected
        assert expected == hashlib.sha256(marshal.dumps(callback.__code__, 2)).hexdigest()


@pytest.mark.parametrize("mutation", ["constant", "code", "nested"])
def test_callback_hash_detects_actual_code_and_nested_constant_changes(mutation):
    def original():
        def nested():
            return "synthetic original nested constant"
        return "synthetic original outer constant", nested
    code = original.__code__
    if mutation == "constant":
        code = code.replace(co_consts=tuple("synthetic altered outer constant" if type(c) is str else c for c in code.co_consts))
    elif mutation == "nested":
        code = code.replace(co_consts=tuple(c.replace(co_consts=(None, "synthetic altered nested constant"))
                                            if isinstance(c, CodeType) else c for c in code.co_consts))
    else:
        def different():
            raise RuntimeError("synthetic altered code; never executed")
        code = code.replace(co_code=different.__code__.co_code)
    changed = FunctionType(code, original.__globals__)
    assert b.callback_sha256(changed) != b.callback_sha256(original)
    with pytest.raises(b.BridgeError, match="PYTHON_VERIFIER_OR_CALLBACK_ADAPTER_REQUIRED"):
        b.callback_sha256(object())


def test_callback_hash_is_stable_across_process_seeds_and_exhibits_legacy_bug():
    script = r'''
import hashlib, json, marshal
from scripts.ge_auto_role_runtime import CodexRoleRuntime
from scripts import ge_auto_host_bridge as b
def synthetic():
    def nested():
        return "distinct nested text", b"distinct bytes", 4.25, 3+2j
    return "needle" in {"alpha", "bravo", "charlie", "delta"}, nested
callback = CodexRoleRuntime.__call__
legacy_before = hashlib.sha256(marshal.dumps(callback.__code__, 4)).hexdigest()
before = b.callback_sha256(callback)
held = list(callback.__code__.co_consts)
legacy_after = hashlib.sha256(marshal.dumps(callback.__code__, 4)).hexdigest()
assert legacy_before != legacy_after
assert before == b.callback_sha256(callback)
print(json.dumps([b.callback_sha256(f) for f in (
    callback, b._Bridge.verify, b.HostCapture.__call__, b.fetch_official,
    b.parse_official_capture, synthetic)]))
'''
    outputs = [subprocess.check_output([sys.executable, "-B", "-c", script],
        cwd=Path(__file__).resolve().parents[2],
        env={"PYTHONHASHSEED": str(seed), "PYTHONDONTWRITEBYTECODE": "1"}, timeout=15)
        for seed in (0, 1, 31, 991)]
    assert len(set(outputs)) == 1


@pytest.mark.parametrize("jurisdiction,expected", [
    ("England", set()), ("Wales", {"gov.wales"}),
    ("England and Wales", {"gov.wales"}),
    ("Scotland", {"gov.scot", "judiciary.scot"}),
    ("Northern Ireland", {"judiciaryni.uk"}),
    ("UK", {"gov.wales", "gov.scot", "judiciary.scot", "judiciaryni.uk"}),
])
def test_official_discovery_selects_verified_uk_nation_hosts(jurisdiction, expected):
    public = {"query": "Public notice conditions", "jurisdiction": jurisdiction, "as_of_date": "2026-09-05"}
    args = b.search_arguments(public)
    sites = set(re.findall(r"site:([a-z0-9.-]+)", args["search_query"][0]["q"]))
    nation_hosts = {"gov.wales", "gov.scot", "judiciary.scot", "judiciaryni.uk"}
    assert sites & nation_hosts == expected
    assert {"gov.uk", "supremecourt.uk", "judiciary.uk", "www.catribunal.org.uk"} <= sites
    assert {"legislation.gov.uk", "caselaw.nationalarchives.gov.uk"} <= sites
    assert ".gov" not in sites and not sites & b.source_policy._EU_CROSS_BORDER_HOSTS
    assert all(b.is_allowed_source_url("https://" + host + "/") for host in sites)


@pytest.mark.parametrize("jurisdiction,exceptions", [
    ("US federal", set()), ("California", set()), ("District of Columbia", set()),
    ("Florida", {"leg.state.fl.us"}),
    ("Pennsylvania", {"legis.state.pa.us", "palegis.us", "pacourts.us"}),
    ("Alabama", {"legislature.state.al.us", "alison.legislature.state.al.us"}),
    ("New Jersey", {"njleg.state.nj.us", "pub.njleg.state.nj.us"}),
    ("New Hampshire", {"gencourt.state.nh.us"}),
    ("Nevada", {"leg.state.nv.us"}), ("Virginia", {"courts.state.va.us"}),
    ("Maryland", {"courts.state.md.us"}), ("South Carolina", {"sccourts.org"}),
])
def test_us_discovery_keeps_gov_suffix_and_only_verified_state_exceptions(jurisdiction, exceptions):
    public = {"query": "Public notice conditions", "jurisdiction": jurisdiction, "as_of_date": "2026-09-05"}
    args = b.search_arguments(public)
    sites = set(re.findall(r"site:([a-z0-9.-]+)", args["search_query"][0]["q"]))
    assert sites == {".gov"} | exceptions
    assert exceptions <= b.source_policy._EXACT_HOSTS
    query = args["search_query"][0]["q"]
    assert '"' not in query
    hint = "United States federal" if jurisdiction == "US federal" else jurisdiction
    assert ") " + hint + " (site:" in query
    assert b._discovery_receipt(public)["added_jurisdiction_term"] == hint


def test_discovery_preserves_exact_original_query_without_inventing_locators():
    public = {"query": "  notice — timing  and conditions?", "jurisdiction": "England", "as_of_date": "2026-09-05"}
    original = copy.deepcopy(public)
    args = b.search_arguments(public)
    assert public == original and args == b.search_arguments(public)
    assert len(args["search_query"]) == 2
    assert args["search_query"][1]["q"].endswith("amendments commencement site:legislation.gov.uk")
    assert set(args) == {"search_query", "response_length"} and args["response_length"] == "long"
    query = args["search_query"][0]["q"]
    assert query.startswith("(" + original["query"] + ") ")
    assert "https://" not in query and "/section/" not in query and original["as_of_date"] not in query


@pytest.mark.parametrize("query", [
    "Version in force on 5 September 2026 of the Renting Homes (Fees etc.) (Wales) Act 2019 agent prohibitions.",
    "Renting Homes (Fees etc.) (Wales) Act 2019: prohibited payments.",
    "Commencement provisions governing the application of the Renting Homes (Fees etc.) (Wales) Act 2019 to contracts.",
])
def test_uk_primary_search_quotes_exact_cited_act_title(query):
    public = {"query": query, "jurisdiction": "Wales", "as_of_date": "2026-09-05"}
    args = b.search_arguments(public)
    assert args["search_query"][1]["q"] == (
        '"Renting Homes (Fees etc.) (Wales) Act 2019" amendments commencement site:legislation.gov.uk'
    )
    receipt = b._discovery_receipt(public)
    assert receipt["dedicated_primary_terms"] == '"Renting Homes (Fees etc.) (Wales) Act 2019"'


def test_uk_primary_search_falls_back_to_exact_original_query_without_act_title():
    public = {"query": "Public notice conditions", "jurisdiction": "England", "as_of_date": "2026-09-05"}
    args = b.search_arguments(public)
    assert args["search_query"][1]["q"] == (
        "(Public notice conditions) amendments commencement site:legislation.gov.uk"
    )
    assert b._discovery_receipt(public)["dedicated_primary_terms"] == "(Public notice conditions)"


@pytest.mark.parametrize("change", [{"jurisdiction": "England guessed"}, {"as_of_date": "2026-02-30"}, {"extra": "hidden data"}])
def test_discovery_rejects_invalid_public_scope(change):
    public = {"query": "Public notice conditions", "jurisdiction": "England", "as_of_date": "2026-09-05"} | change
    with pytest.raises(p.ProtocolError):
        b.search_arguments(public)


def test_native_search_callback_roundtrip_requires_protected_pin_and_keeps_full_raw(host):
    envelope, reservation = host.reserve()
    host.on_sleep = lambda:host.publish(reservation)
    result = host.search()(envelope, reservation)
    assert p.schema_ok(result, p.SEARCH_SCHEMA) and result["raw_utf8"] == RAW_WEB and result["hits"] == HITS
    root = host.broker(reservation)
    request = p.decode(host.store.files[root + "/request.json"])
    assert request["public_input"] == envelope["data"]
    assert request["tool_arguments"] == b.search_arguments(envelope["data"])
    discovery = request["discovery_policy"]
    assert discovery["original_query"] == envelope["data"]["query"]
    assert discovery["added_jurisdiction_term"] == "Scotland"
    assert discovery["source_policy_path"] == "scripts/ge_unseen_sources.py"
    assert discovery["source_policy_sha256"] == p.digest(Path(b.source_policy.__file__).read_bytes())
    assert set(discovery["site_terms"]) == set(re.findall(r"site:([a-z0-9.-]+)", request["tool_arguments"]["search_query"][0]["q"]))
    assert request["input_sha256"] == p.digest(envelope)
    assert request["reservation_sha256"] == p.digest(reservation)
    response = p.decode(host.store.files[root + "/response.json"])
    assert response["request_sha256"] == p.digest(host.store.files[root + "/request.json"])
    assert "question" not in request and "capability" not in request
    assert all(0 < seconds <= 60 for seconds in host.sleeps)
    saved = dict(host.store.files)
    with pytest.raises(FileExistsError):
        host.search()(envelope, reservation)
    assert host.store.files == saved


@pytest.mark.parametrize("change", ["remove_filter", "change_query", "change_jurisdiction"])
def test_response_helper_refuses_tool_arguments_not_matching_original_public_query(host, change):
    envelope, reservation = host.reserve()
    def publish_changed_request():
        request = p.decode(host.store.files[host.broker(reservation) + "/request.json"])
        if change == "remove_filter":
            request["tool_arguments"] = {"search_query": [{"q": envelope["data"]["query"]}], "response_length": "long"}
        else:
            field = "query" if change == "change_query" else "jurisdiction"
            request["public_input"][field] = "Other issue" if field == "query" else "England"
        b.web_response(p.canonical(request), raw_utf8=RAW_WEB, hits=HITS, tool_receipt_sha256=H)
    host.on_sleep = publish_changed_request
    with pytest.raises(b.BridgeError, match="WEB_TOOL_ARGUMENTS_MISMATCH"):
        host.search()(envelope, reservation)
    root = host.broker(reservation)
    assert root + "/failure.json" in host.store.files and root + "/response.json" not in host.store.files


def test_official_discovery_keeps_four_reserved_queries_and_refuses_fifth(host):
    for ordinal in range(1, 5):
        data = {"query": "Synthetic issue " + str(ordinal), "jurisdiction": "Scotland", "as_of_date": "2026-09-05"}
        envelope, reservation = host.reserve(data=data, ordinal=ordinal)
        host.on_sleep = lambda reservation=reservation:host.publish(reservation)
        host.search()(envelope, reservation)
        request = p.decode(host.store.files[host.broker(reservation) + "/request.json"])
        assert len(request["tool_arguments"]["search_query"]) == 2
        assert request["budget"]["ordinal"] == ordinal and request["budget"]["maximum"] == 4
    envelope, reservation = host.reserve(ordinal=5)
    retained = dict(host.store.files)
    with pytest.raises(b.BridgeError, match="BUDGET_BINDING_MISMATCH"):
        host.search()(envelope, reservation)
    assert retained == host.store.files
    assert sum(name.startswith("broker/search-budget-") for name in retained) == 4


@pytest.mark.parametrize("mutation,pinned", [
    (None, False),
    (lambda raw:raw.replace(b"Synthetic discovery only.", b"Invented finding."), True),
    (lambda raw:raw.replace(b'"request_sha256":"', b'"request_sha256":"wrong-'), True),
    (lambda raw:b'{"schema":', True),
])
def test_unpinned_tampered_foreign_and_partial_ready_responses_are_preserved_and_refused(host, mutation, pinned):
    envelope, reservation = host.reserve()
    host.on_sleep = lambda:host.publish(reservation, pin=pinned, mutate=mutation)
    with pytest.raises((b.BridgeError, p.ProtocolError, PermissionError)):
        host.search()(envelope, reservation)
    root = host.broker(reservation)
    assert host.store.files[root + "/response.json"] == host.store.files[root + "/response-observed.bytes"]
    assert root + "/failure.json" in host.store.files and root + "/success.json" not in host.store.files


@pytest.mark.parametrize("interrupted", [False, True])
def test_timeout_or_interrupt_retains_request_and_partial_response_and_never_reissues(host, interrupted):
    envelope, reservation = host.reserve()
    root = host.broker(reservation)
    def parent():
        host.store.write_new(root + "/response.json", b'{"partial_actual_test_bytes":')
        if interrupted:
            raise KeyboardInterrupt()
    host.on_sleep = parent
    with pytest.raises(KeyboardInterrupt if interrupted else TimeoutError):
        host.search()(envelope, reservation)
    failure = p.decode(host.store.files[root + "/failure.json"])
    assert failure["status"] == ("INTERRUPTED" if interrupted else "FAILED")
    assert failure["retry_decision"] == "PROTOCOL_ONLY"
    assert host.store.files[root + "/response.json"].endswith(b":")
    assert failure["unverified_parent_files"]["response.json"]["sha256"] == p.digest(host.store.files[root + "/response.json"])
    assert sum(host.sleeps) <= 5
    retained = dict(host.store.files)
    with pytest.raises(FileExistsError):
        host.search()(envelope, reservation)
    assert host.store.files == retained


@pytest.mark.parametrize("change", [
    {"case_id":"foreign-case"}, {"policy_sha256":p.digest(b"foreign policy")},
    {"attempt_root":"../foreign/attempt-1"}, {"input_sha256":p.digest(b"foreign input")},
    {"attempt":True},
])
def test_reservation_scope_or_hash_changes_refused_before_any_new_write(host, change):
    envelope, reservation = host.reserve()
    reservation.update(change)
    original = dict(host.store.files)
    with pytest.raises(b.BridgeError):
        host.search()(envelope, reservation)
    assert host.store.files == original


def test_capability_and_query_privacy_gate_precede_broker_disclosure(host):
    host.deny = "bind_case_root"
    with pytest.raises(PermissionError):
        host.search()
    assert not host.store.accesses
    host.deny = None
    envelope, reservation = host.reserve(data={"query":"PRIVATE PERSON ALPHA", "jurisdiction":"Scotland", "as_of_date":"2026-09-05"})
    retained = dict(host.store.files)
    with pytest.raises(PermissionError):
        host.search()(envelope, reservation)
    assert host.store.files == retained and "broker" not in host.store.dirs


def test_verifier_code_pin_and_explicit_root_are_mandatory(host):
    kwargs = host.kwargs()
    kwargs["context"] = replace(host.context, verifier_sha256=p.digest(b"other code"))
    with pytest.raises(b.BridgeError, match="VERIFIER_CODE_PIN"):
        b.make_search_callback(**kwargs)
    for root in ("relative", "/", "/synthetic/../other"):
        kwargs = host.kwargs() | {"case_root":root}
        with pytest.raises(b.BridgeError):
            b.make_search_callback(**kwargs)
    with pytest.raises(b.BridgeError, match="STORE_ROOT"):
        b.make_search_callback(**(host.kwargs() | {"case_root":"/synthetic/foreign"}))


def test_tampered_durable_budget_and_unbounded_wait_refused(host):
    envelope, reservation = host.reserve()
    host.store.files["budget/search-01.json"] = b"{}"  # Explicit corruption of synthetic memory bytes.
    with pytest.raises(b.BridgeError, match="DURABLE_RESERVATION"):
        host.search()(envelope, reservation)
    for options in ({"poll_seconds":61}, {"timeout_seconds":float("inf")}, {"timeout_seconds":0}):
        with pytest.raises(b.BridgeError, match="BOUNDED_WAIT"):
            b.make_search_callback(**host.kwargs(), **options)


def test_changed_profile_retry_requires_separate_reserved_attempt_and_consumes_budget(host):
    envelope, first = host.reserve()
    with pytest.raises(TimeoutError):
        host.search()(envelope, first)
    retained = dict(host.store.files)
    changed, second = host.reserve(attempt=2, ordinal=2, profile=p.digest(b"frozen changed host profile"))
    host.on_sleep = lambda:host.publish(second)
    assert host.search()(changed, second)["hits"] == HITS
    assert all(host.store.files[name] == raw for name, raw in retained.items())
    assert sum(name.startswith("broker/search-budget-") for name in host.store.files) == 2
    assert len([e for e in host.events if e["action"] == "authorize_search"]) == 2


def transport_for(host, *, mutate=None, error=None):
    def transport(url, *, max_bytes, timeout_seconds, emit):
        assert url == URL and 0 < max_bytes <= b.MAX_RAW_BYTES and 0 < timeout_seconds <= 60
        raw = host.expected_raw
        value = {"canonical_url":url, "final_url":url, "redirect_chain":[], "fetched_at":NOW,
                 "raw_sha256":p.digest(raw), "byte_count":len(raw), "http_status":200}
        if mutate:
            mutate(value)
        emit("raw.bytes", raw)
        emit("transport.json", value)
        if error:
            raise error
        return value
    return transport


def test_capture_factory_runs_real_intake_on_synthetic_bytes_and_returns_exact_schema(host):
    envelope, reservation = host.reserve("capture")
    result = host.capture(transport=transport_for(host))(envelope, reservation)
    assert p.schema_ok(result, p.CAPTURE_SCHEMA)
    assert base64.b64decode(result["raw_b64"]) == HTML
    assert [part["text"] for part in result["parts"]] == ["Synthetic title", "Synthetic conditions", "Only test condition A applies."]
    assert result["parts"][2]["parent_id"] == result["parts"][1]["part_id"]
    assert all("capture-sha256:" in part["locator"] for part in result["parts"])
    root = host.broker(reservation)
    receipt = p.decode(host.store.files[root + "/parser-receipt.json"])
    assert p.digest(host.store.files[root + "/parser-receipt.json"]) == result["parser_receipt_sha256"]
    assert receipt["source_review"] == "NOT_PERFORMED" and receipt["admitted"] is False
    assert receipt["parsed_sha256"] == p.digest(result["parts"])
    assert all(p.digest(host.store.files[root + "/" + name]) == sha for name,sha in receipt["files"].items())
    original = dict(host.store.files)
    with pytest.raises(FileExistsError):
        host.capture(transport=transport_for(host))(envelope, reservation)
    assert host.store.files == original


@pytest.mark.parametrize("mutation", [
    lambda value:value.update(raw_sha256=p.digest(b"different raw")),
    lambda value:value.update(byte_count=1),
    lambda value:value.update(fetched_at="2026-09-06T00:00:00+00:00"),
    lambda value:value.update(final_url="https://untrusted.invalid/source"),
    lambda value:value.update(redirect_chain=[URL,"https://www.gov.uk/other-host"],final_url="https://www.gov.uk/other-host"),
])
def test_capture_refuses_invalid_raw_time_and_redirect_provenance_and_preserves_bytes(host, mutation):
    envelope, reservation = host.reserve("capture")
    with pytest.raises(b.BridgeError):
        host.capture(transport=transport_for(host,mutate=mutation))(envelope,reservation)
    root = host.broker(reservation)
    assert host.store.files[root + "/raw.bytes"] == HTML
    assert root + "/failure.json" in host.store.files and root + "/success.json" not in host.store.files


def test_parser_dependency_or_parse_failure_is_preserved_not_replaced(host):
    envelope, reservation = host.reserve("capture")
    def parser(raw, **kwargs):
        raise ImportError("synthetic missing parser dependency")
    with pytest.raises(ImportError):
        host.capture(transport=transport_for(host),parser=parser)(envelope,reservation)
    root = host.broker(reservation)
    failure = p.decode(host.store.files[root+"/failure.json"])
    assert failure["exception_type"] == "ImportError" and host.store.files[root+"/raw.bytes"] == HTML
    assert root+"/parse-manifest.json" not in host.store.files


@pytest.mark.parametrize("base_mode", [False, True])
def test_base_or_changed_parser_pin_refused_before_transport(host, base_mode):
    envelope, reservation = host.reserve("capture")
    host.parser_pin = intake.parser_binding(include_legal_tables=False) if base_mode else p.digest(b"incorrect expected pin")
    with pytest.raises(b.BridgeError, match="PARSER_BINDING"):
        host.capture(transport=transport_for(host))(envelope,reservation)
    root=host.broker(reservation)
    assert root+"/raw.bytes" not in host.store.files and root+"/success.json" not in host.store.files


class HTTPResponse:
    def __init__(self, raw=HTML, status=200, headers=None, failure=None):
        self.raw, self.status, self.headers, self.failure = raw, status, headers or {}, failure
        self.offset = 0
    def getheaders(self):
        return list(self.headers.items())
    def getheader(self, key, default=None):
        return self.headers.get(key, default)
    def read(self, n):
        if self.failure and self.offset:
            raise self.failure
        chunk = self.raw[self.offset:self.offset+n]
        self.offset += len(chunk)
        return chunk


def network_double(monkeypatch, responses):
    connections = []
    class Connection:
        def __init__(self, host, **kwargs):
            self.host, self.sock, self.closed = host, None, False
            self.response = responses[len(connections)]
            connections.append(self)
        def request(self, method, path, headers):
            assert method == "GET" and headers["Accept-Encoding"] == "identity"
            self.path = path
        def getresponse(self):
            return self.response
        def close(self):
            self.closed = True
    monkeypatch.setattr(b,"_PublicHTTPSConnection",Connection)
    return connections


@pytest.mark.parametrize("problem", ["404", "oversize", "read_failure", "truncated", "forbidden_redirect"])
def test_real_transport_preserves_failed_body_and_refuses_redirect_before_next_get(host, monkeypatch, problem):
    response = {"404":HTTPResponse(b"synthetic unavailable page",404),
        "oversize":HTTPResponse(b"123456789"),
        "read_failure":HTTPResponse(b"synthetic partial",failure=TimeoutError("synthetic socket timeout")),
        "truncated":HTTPResponse(b"synthetic partial",headers={"Content-Length":"1000"}),
        "forbidden_redirect":HTTPResponse(status=302,headers={"Location":"https://untrusted.invalid/private"})}[problem]
    connections=network_double(monkeypatch,[response])
    envelope,reservation=host.reserve("capture")
    with pytest.raises((b.BridgeError,TimeoutError)):
        host.capture(max_bytes=8 if problem=="oversize" else b.MAX_RAW_BYTES)(envelope,reservation)
    root=host.broker(reservation)
    assert len(connections)==1 and connections[0].closed
    assert root+"/hop-00-request.json" in host.store.files and root+"/failure.json" in host.store.files
    if problem != "forbidden_redirect":
        assert host.store.files[root+"/raw.bytes"] == response.raw
    else:
        assert root+"/hop-01-request.json" not in host.store.files


def test_real_transport_and_real_parser_keep_allowed_redirect_hop_chain(host,monkeypatch):
    next_url=URL+"/current"
    connections=network_double(monkeypatch,[HTTPResponse(status=302,headers={"Location":next_url}),HTTPResponse()])
    # Bind both bridge and transport clocks to the same synthetic wall time.
    monkeypatch.setattr(b,"_stamp",lambda:NOW)
    envelope,reservation=host.reserve("capture")
    result=host.capture()(envelope,reservation)
    assert result["redirect_chain"]==[URL,next_url] and result["final_url"]==next_url
    assert len(connections)==2 and all(connection.closed for connection in connections)
    root=host.broker(reservation)
    assert root+"/hop-01-response.json" in host.store.files


def test_actual_connection_rejects_private_dns_before_creating_socket(monkeypatch):
    monkeypatch.setattr(b.socket,"getaddrinfo",lambda *a,**k:[(b.socket.AF_INET,b.socket.SOCK_STREAM,6,"",("127.0.0.1",443))])
    def socket_forbidden(*args,**kwargs):
        pytest.fail("private address must never receive a connection")
    monkeypatch.setattr(b.socket,"socket",socket_forbidden)
    connection=b._PublicHTTPSConnection("www.legislation.gov.uk",timeout=1)
    with pytest.raises(b.BridgeError,match="NON_PUBLIC_DNS"):
        connection.connect()


def test_protocol_operation_accepts_native_bridge_and_persists_result_without_replay(host):
    policy=p.FrozenPolicy("synthetic-run",H,H,"EMPTY",p.digest([]))
    host.context=replace(host.context,policy_sha256=p.digest(policy.manifest()))
    protocol=p.CaseProtocol(case_root=host.store.root,policy=policy,capability=host.capability,
                            guard=host.verify,store=host.store)
    protocol.case_id,protocol.request_sha256=host.context.case_id,host.context.request_sha256
    protocol.touched,protocol.choose_retry={},None
    data={"query":"Scotland public notice requirements","jurisdiction":"Scotland","as_of_date":"2026-09-05"}
    def parent():
        # Exact operation path from own synthetic input, not directory discovery.
        path="operations/search-"+p.digest(data)+"/attempt-1/reservation.json"
        host.publish(p.decode(host.store.files[path]))
    host.on_sleep=parent
    search=host.search()
    result=protocol._operation("search",p.digest(data),data,search,protocol._search_result,budget=True)
    retained=dict(host.store.files)
    assert protocol._operation("search",p.digest(data),data,search,protocol._search_result,budget=True)==result
    assert host.store.files==retained and result["raw_utf8"]==RAW_WEB


def test_factory_callbacks_are_directly_bindable_by_system_fault_harness(host):
    from scripts import ge_auto_system_harness as harness
    assert harness.callback_identity(host.search()) == b.callback_sha256(host.search())
    assert harness.callback_identity(host.capture()) == b.callback_sha256(host.capture())


@pytest.mark.parametrize("corruption", ["parsed_digest", "retained_raw", "parent_pin_denied"])
def test_capture_artifact_corruption_or_missing_protected_parent_pin_refuses_return(host, corruption):
    envelope, reservation = host.reserve("capture")
    root = host.broker(reservation)
    def parser(raw, **kwargs):
        manifest = b.parse_official_capture(raw, **kwargs)
        if corruption == "parsed_digest":
            manifest["parsed_sha256"] = p.digest(b"forged parser manifest")
        if corruption == "retained_raw":
            host.store.files[root + "/raw.bytes"] = b"tampered synthetic body"
        return manifest
    if corruption == "parent_pin_denied":
        host.deny = "capture_parse"
    with pytest.raises((b.BridgeError, PermissionError)):
        host.capture(transport=transport_for(host), parser=parser)(envelope, reservation)
    assert root + "/failure.json" in host.store.files
    assert root + "/success.json" not in host.store.files


def test_checked_table_mode_delivers_real_synthetic_table_parse_without_approving_law(host):
    doc = "https://www.legislation.gov.uk/uksi/2099/99999"
    url = doc + "/data.xml"
    raw = (f'<Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation" '
        f'xmlns:h="http://www.w3.org/1999/xhtml" xmlns:dc="http://purl.org/dc/elements/1.1/" DocumentURI="{doc}">'
        '<Metadata><dc:title>Synthetic test only</dc:title></Metadata><Secondary><Schedules>'
        f'<Schedule DocumentURI="{doc}/schedule"><Number>SYNTHETIC SCHEDULE</Number><ScheduleBody><P><Tabular>'
        '<h:table><h:thead><h:tr><h:th>Item</h:th><h:th>Condition</h:th></h:tr></h:thead>'
        '<h:tbody><h:tr><h:td>Test row</h:td><h:td>Only synthetic condition</h:td></h:tr></h:tbody>'
        '</h:table></Tabular></P></ScheduleBody></Schedule></Schedules></Secondary></Legislation>').encode()
    host.expected_raw = raw
    envelope, reservation = host.reserve("capture", data={"url":url, "as_of_date":"2026-09-05"})
    def transport(selected, *, max_bytes, timeout_seconds, emit):
        assert selected == url
        value={"canonical_url":url,"final_url":url,"redirect_chain":[],"fetched_at":NOW,
               "raw_sha256":p.digest(raw),"byte_count":len(raw),"http_status":200}
        emit("raw.bytes",raw)
        emit("transport.json",value)
        return value
    callback=host.capture(transport=transport)
    assert callback.__self__.parser_mode == b.PARSER_MODE
    with pytest.raises(AttributeError):
        callback.__self__.parser_mode = "BASE"
    result=callback(envelope,reservation)
    root=host.broker(reservation)
    manifest=p.decode(host.store.files[root+"/parse-manifest.json"])
    table_rows=[block for block in manifest["parsed"]["body_blocks"] if "row_id" in block["metadata"]]
    assert table_rows and all(any(part["text"] == block["text"] for part in result["parts"]) for block in table_rows)
    assert any("Only synthetic condition" in part["text"] for part in result["parts"])
    receipt=p.decode(host.store.files[root+"/parser-receipt.json"])
    assert receipt["include_legal_tables"] is True and receipt["parser_mode"] == b.PARSER_MODE
    assert receipt["source_review"] == "NOT_PERFORMED" and receipt["admitted"] is False
    assert result["parser_sha256"] == intake.parser_binding(include_legal_tables=True)
    assert result["parser_sha256"] != intake.parser_binding(include_legal_tables=False)
