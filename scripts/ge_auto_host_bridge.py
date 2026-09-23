"""Synchronous, case-local HOST adapters for ge_auto_case_protocol.

No default root, worker browsing, model invocation, global patch, or admission.
The search adapter NEVER performs network IO. It publishes a create-only request
and waits for the parent to call functions.web. Parent publication order:

1. Read broker/search-<reservation digest>/request.json; verify its exact scope.
2. Execute request['tool_arguments'] with the actual host functions.web tool.
3. Exclusively write response.json using web_response(request_bytes,
   raw_utf8=FULL_ACTUAL_TOOL_OUTPUT, hits=ACTUAL_NORMALIZED_HITS,
   tool_receipt_sha256=ACTUAL_HOST_RECEIPT_HASH). No invented results/receipts.
4. Pin its EXACT BYTE hash, raw hash, hits hash and actual tool receipt in the
   protected parent verifier, outside worker control. Then exclusively write
   response-ready.json containing {"response_sha256": <exact response byte hash>}.

The ready file is a completion marker, NOT authority. verify(capability, binding)
must return exactly True, including for web_response, after checking the protected
parent pin and tool provenance. Never implement it as an in-directory self-hash
check or unconditional True. Its Python code hash is pinned in BridgeContext;
the parent must also pin its closure/state/runtime and prevent worker access.
Request authorization must verify generalized-query privacy and actual durable
protocol reservation. This module neither issues capabilities nor approves law.

make_search_callback / make_capture_callback return native (envelope,reservation)
callables. A bridge attempt cannot replay, even after a crash; retry decisions
belong exclusively to the protocol's changed, frozen profile and remaining budget.
All evidence remains under the explicit case root, including failed/partial bytes.
CaseStore provides no-follow, single-link, exclusive file IO. No cleanup/deletion.

Capture uses existing official URL/redirect policy, bounded HTTPS transport and
the actual ge_auto_research_intake parser. No mainrunner import or reference store.
HostCapture.parser_mode is STRUCTURAL_CAPTURE_WITH_LEGAL_TABLES. Caller supplies
the explicit parser_binding(include_legal_tables=True) hash; a base-mode or changed
pin is refused before network IO. The mode also appears in capability bindings
and parser-receipt.json; CAPTURE_SCHEMA itself remains unchanged.
The parent verifier must pin actual capture/parser/file hashes before admitting
the CAPTURE_SCHEMA result; local digest receipts alone are not independent proof.
Capturing/parsing is NOT source/currentness review or production admission.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import http.client
import ipaddress
import marshal
import re
import socket
import ssl
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from scripts import ge_auto_case_protocol as p
from scripts import ge_unseen_sources as source_policy
from scripts.ge_unseen_sources import is_allowed_source_url, redirect_allowed

VERSION = "legalbot.ge-host-bridge.v1"
WEB_RESPONSE_VERSION = "legalbot.ge-host-web-response.v1"
MAX_RAW_BYTES = 8_000_000
MAX_ATTEMPT_BYTES = 32_000_000
MAX_METADATA_BYTES = 2_000_000
PARSER_MODE = "STRUCTURAL_CAPTURE_WITH_LEGAL_TABLES"
_SEARCH_INPUT = p.obj({k: p.QUERY["properties"][k] for k in ("query", "jurisdiction", "as_of_date")})
_CAPTURE_INPUT = p.obj({"url": p.string(3000), "as_of_date": p.DAY})
DISCOVERY_VERSION = "legalbot.ge-official-discovery.v1"
# Jurisdiction labels select only exceptions already verified in source_policy.
# Government suffixes remain broad: never guess a state's authority/provision URL.
_UK_NATION_HOSTS = {
    "Wales": frozenset({"gov.wales"}),
    "Scotland": frozenset({"gov.scot", "judiciary.scot"}),
    "Northern Ireland": frozenset({"judiciaryni.uk"}),
}
_US_STATE_HOSTS = {
    "Alabama": ("legislature.state.al.us", "alison.legislature.state.al.us"),
    "Florida": ("leg.state.fl.us",),
    "Maryland": ("courts.state.md.us",),
    "Nevada": ("leg.state.nv.us",),
    "New Hampshire": ("gencourt.state.nh.us",),
    "New Jersey": ("njleg.state.nj.us", "pub.njleg.state.nj.us"),
    "Pennsylvania": ("legis.state.pa.us", "palegis.us", "pacourts.us"),
    "South Carolina": ("sccourts.org",),
    "Virginia": ("courts.state.va.us",),
}

# These authoritative UK services are already eligible under the gov.uk suffix,
# but a broad ``site:gov.uk`` query did not reliably surface them.  Include the
# exact discovery hosts so primary legislation and judgments are searched rather
# than only general government guidance.
_UK_PRIMARY_DISCOVERY_HOSTS = frozenset({
    "legislation.gov.uk",
    "caselaw.nationalarchives.gov.uk",
})
_UK_ACT_TITLE_AFTER_THE = re.compile(r"\bthe\s+([A-Z][^?;:]{3,180}? Act \d{4})\b")
_UK_ACT_TITLE_AT_START = re.compile(r"^([A-Z][^?;:]{3,180}? Act \d{4})\b")


class BridgeError(ValueError):
    """A bounded attempt stopped; the protocol owns any retry decision."""


def require(condition, code):
    if not condition:
        raise BridgeError(code)


def _search_sites(public_query):
    p.checked(public_query, _SEARCH_INPUT)
    p.day(public_query["as_of_date"])
    jurisdiction = public_query["jurisdiction"]
    if jurisdiction in p.UK:
        nation_hosts = frozenset().union(*_UK_NATION_HOSTS.values())
        hosts = source_policy._UK_EXACT_BASE_HOSTS - nation_hosts
        hosts |= {"www.catribunal.org.uk"}
        if jurisdiction == "UK":
            hosts |= nation_hosts
        else:
            hosts |= _UK_NATION_HOSTS.get(jurisdiction, frozenset())
            if jurisdiction == "England and Wales":
                hosts |= _UK_NATION_HOSTS["Wales"]
        hosts |= _UK_PRIMARY_DISCOVERY_HOSTS
        suffix = "gov.uk"
    else:
        require(jurisdiction in p.US, "EXPLICIT_JURISDICTION_REQUIRED")
        hosts = frozenset(_US_STATE_HOSTS.get(jurisdiction, ()))
        suffix = ".gov"
    require(all(source_policy.is_allowed_source_url("https://" + host + "/") for host in hosts),
            "DISCOVERY_HOST_OUTSIDE_VERIFIED_POLICY")
    return (suffix, *sorted(hosts))


def search_arguments(public_query):
    """One deterministic official-discovery query; no I/O or legal approval.

    Preserve the caller's exact query inside the search expression and keep it
    separately, unchanged, in request.public_input. The jurisdiction term and
    site clause are discovery hints from the frozen source policy, not invented
    authority URLs. Search engines can return off-filter hits; every capture
    still requires the original exact HTTPS host/redirect checks and review.
    EU cross-border exceptions are not selected from a domestic jurisdiction
    alone. A date is retained for review, not asserted as source currentness.
    """
    sites = _search_sites(public_query)
    clause = "(" + " OR ".join("site:" + host for host in sites) + ")"
    query = f'({public_query["query"]}) {_search_jurisdiction_hint(public_query)} {clause}'
    searches = [{"q": query}]
    if public_query["jurisdiction"] in p.UK:
        primary_terms = _uk_primary_search_terms(public_query["query"])
        searches.append({"q": f'{primary_terms} amendments commencement site:legislation.gov.uk'})
    return {"search_query": searches, "response_length": "long"}


def _uk_primary_search_terms(query):
    """Prefer an exact cited Act title; retain the original query otherwise.

    This changes only public search terms.  It neither derives nor mutates a URL,
    and every returned URL remains subject to the original capture allowlist.
    """
    titles = _UK_ACT_TITLE_AFTER_THE.findall(query)
    if not titles:
        titles = _UK_ACT_TITLE_AT_START.findall(query)
    if not titles:
        return f"({query})"
    # Prefer the last citation because phrases such as ``application of the``
    # precede the named authority.  Deduplicate to make ambiguity fail closed.
    title = titles[-1].strip()
    if titles.count(titles[-1]) != 1 or '"' in title:
        return f"({query})"
    return f'"{title}"'


def _search_jurisdiction_hint(public_query):
    # No mandatory exact phrase, particularly the internal label "US federal".
    jurisdiction = public_query["jurisdiction"]
    return "United States federal" if jurisdiction == "US federal" else jurisdiction


def _discovery_receipt(public_query):
    return {"schema": DISCOVERY_VERSION,
        "source_policy_path": "scripts/ge_unseen_sources.py",
        "source_policy_sha256": p.digest(Path(source_policy.__file__).read_bytes()),
        "original_query": public_query["query"],
        "added_jurisdiction_term": _search_jurisdiction_hint(public_query),
        "site_terms": list(_search_sites(public_query)), "method": "EXPLICIT_SITE_QUERY",
        "dedicated_primary_terms": (_uk_primary_search_terms(public_query["query"])
            if public_query["jurisdiction"] in p.UK else None)}


def callback_sha256(callback):
    """Hash exact Python code with reference-count-independent marshal v2.

    Marshal v3+ encodes shared references using incidental live reference
    counts; merely retaining a constant can otherwise change an unchanged code
    pin. V2 retains code/constants (including nested code) without that encoding.
    This remains interpreter-specific; frozen runtime, source and callback-owner
    bindings are still required. All new runtime pins must use this helper.
    """
    target = getattr(callback, "__func__", callback)
    code = getattr(target, "__code__", None)
    require(code is not None, "PYTHON_VERIFIER_OR_CALLBACK_ADAPTER_REQUIRED")
    return hashlib.sha256(marshal.dumps(code, 2)).hexdigest()


def _stamp():
    return datetime.now(UTC).isoformat()


def _time(value):
    try:
        parsed = datetime.fromisoformat(value)
        require(parsed.tzinfo is not None, "TIMEZONE_REQUIRED")
        return parsed
    except (TypeError, ValueError):
        raise BridgeError("INVALID_TIME") from None


@dataclass(frozen=True)
class BridgeContext:
    case_id: str
    request_sha256: str
    policy_sha256: str
    runtime_sha256: str
    capability_sha256: str
    verifier_sha256: str
    jurisdictions: tuple[str, ...]
    as_of_date: str

    def __post_init__(self):
        p.checked(self.case_id, p.ID)
        for name, value in asdict(self).items():
            if name.endswith("sha256"):
                p.checked(value, p.HASH)
        require(isinstance(self.jurisdictions, tuple) and 1 <= len(self.jurisdictions) <= 8
                and len(set(self.jurisdictions)) == len(self.jurisdictions)
                and all(j in p.UK + p.US for j in self.jurisdictions), "EXPLICIT_JURISDICTIONS_REQUIRED")
        p.day(self.as_of_date)


def web_response(request_bytes, *, raw_utf8, hits, tool_receipt_sha256):
    """Parent serialization helper, NOT a tool call, attestation or hit generator.

    Caller supplies exact actual output and its protected host receipt. Return
    bytes for exclusive response.json publication, then pin before ready marker.
    """
    request = p.decode(request_bytes)
    require(request["schema"] == VERSION and request["kind"] == "search", "NOT_A_WEB_REQUEST")
    require(request["tool_arguments"] == search_arguments(request["public_input"]),
            "WEB_TOOL_ARGUMENTS_MISMATCH")
    value = {"tool": "functions.web", "tool_receipt_sha256": tool_receipt_sha256,
             "raw_utf8": raw_utf8, "hits": hits}
    p.checked(value, p.SEARCH_SCHEMA)
    return p.canonical({"schema": WEB_RESPONSE_VERSION,
        "request_sha256": p.digest(request_bytes), "reservation_sha256": request["reservation_sha256"],
        "result": value})


class _Attempt:
    def __init__(self, bridge, kind, envelope, reservation):
        self.bridge, self.kind = bridge, kind
        self.envelope, self.reservation = copy.deepcopy(envelope), copy.deepcopy(reservation)
        self.root = "broker/" + kind + "-" + p.digest(reservation)
        self.files, self.total_bytes = {}, 0
        self.request_hash = None
        self.owned = False
        self.started_at = bridge.now()

    def binding(self, action, **details):
        return {"schema": VERSION, "action": action, "case_root": str(self.bridge.root),
            "broker_root": str(self.bridge.root / self.root), "lane": "candidate_case_local",
            **asdict(self.bridge.context), "kind": self.kind,
            "input_sha256": p.digest(self.envelope), "reservation_sha256": p.digest(self.reservation),
            "attempt": self.reservation["attempt"], "budget": self.reservation["budget"],
            "retry_profile_sha256": self.envelope["retry_profile_sha256"], **details}

    def verify(self, action, **details):
        self.bridge.verify(self.binding(action, **details))

    def put(self, name, raw):
        require(len(p.parts(name)) == 1, "ATTEMPT_FILE_SCOPE")
        raw = raw if isinstance(raw, bytes) else p.canonical(raw)
        require(len(raw) <= p.MAX_BYTES and self.total_bytes + len(raw) <= MAX_ATTEMPT_BYTES,
                "ATTEMPT_BYTES_EXHAUSTED")
        path = self.root + "/" + name
        self.bridge.store.write_new(path, raw)
        require(self.bridge.store.read(path) == raw, "WRITE_READBACK_MISMATCH")
        self.total_bytes += len(raw)
        self.files[name] = p.digest(raw)
        return self.files[name]

    def read_parent(self, name):
        require(name in ("response.json", "response-ready.json"), "PARENT_FILE_SCOPE")
        return self.bridge.store.read(self.root + "/" + name)

    def start(self):
        self.verify("authorize_" + self.kind, public_input=self.envelope["data"],
                    started_at=self.started_at)
        store = self.bridge.store
        if not store.exists("broker"):
            try:
                store.mkdir_new("broker")
            except FileExistsError:
                pass
        # Directory creation is the exclusive attempt claim. A prior incomplete
        # attempt is consumed; never attach to it or overwrite its failure.
        store.mkdir_new(self.root)
        self.owned = True
        ordinal = self.reservation["budget"]["ordinal"]
        store.write_new(f"broker/{self.kind}-budget-{ordinal:02d}.json",
                        p.canonical({"reservation_sha256": p.digest(self.reservation)}))
        request = {"schema": VERSION, "kind": self.kind,
            "context": asdict(self.bridge.context), "public_input": self.envelope["data"],
            "input_sha256": p.digest(self.envelope), "reservation_sha256": p.digest(self.reservation),
            "retry_profile_sha256": self.envelope["retry_profile_sha256"],
            "attempt": self.reservation["attempt"], "budget": self.reservation["budget"],
            "requested_at": self.started_at}
        if self.kind == "search":
            request["tool_arguments"] = search_arguments(self.envelope["data"])
            request["discovery_policy"] = _discovery_receipt(self.envelope["data"])
            request["response_file"] = self.root + "/response.json"
            request["ready_file"] = self.root + "/response-ready.json"
        self.request_hash = self.put("request.json", request)

    def failed(self, exc):
        # Keep actual error prose case-local. Large errors are explicitly bounded,
        # while their complete byte digest still binds the original exception.
        raw = str(exc).encode("utf-8", errors="backslashreplace")
        failure = {"schema": VERSION, "kind": self.kind, "request_sha256": self.request_hash,
            "reservation_sha256": p.digest(self.reservation), "at": self.bridge.now(),
            "status": "INTERRUPTED" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "FAILED",
            "exception_type": type(exc).__name__, "exception_sha256": p.digest(raw),
            "exception_text": raw[:65536].decode("utf-8", errors="replace"),
            "exception_text_truncated": len(raw) > 65536, "files": dict(self.files),
            "retry_decision": "PROTOCOL_ONLY", "admitted": False}
        if self.kind == "search":
            parent_files, unreadable = {}, {}
            for name in ("response.json", "response-ready.json"):
                try:
                    if self.bridge.store.exists(self.root + "/" + name):
                        observed = self.read_parent(name)
                        parent_files[name] = {"sha256": p.digest(observed), "byte_count": len(observed)}
                except Exception as error:
                    unreadable[name] = type(error).__name__
            failure.update(unverified_parent_files=parent_files, unreadable_parent_files=unreadable)
        # Reserve failure space separately: an oversized response must still have
        # a durable failure record. CaseStore enforces its per-file bound.
        self.bridge.store.write_new(self.root + "/failure.json", p.canonical(failure))

    def finish(self, result, **details):
        result_hash = self.put("result.json", result)
        self.verify(self.kind + "_complete", request_file_sha256=self.request_hash,
                    output_sha256=result_hash, files=dict(self.files), **details)
        self.put("success.json", {"schema": VERSION, "request_sha256": self.request_hash,
            "reservation_sha256": p.digest(self.reservation), "output_sha256": result_hash,
            "files": dict(self.files), "source_review": "NOT_PERFORMED", "admitted": False})
        return result


class _Bridge:
    def __init__(self, *, case_root, context, capability, verify, store=None, now=_stamp):
        self.root = Path(case_root)
        require(self.root.is_absolute() and self.root != Path("/") and ".." not in self.root.parts,
                "EXPLICIT_EXACT_CASE_ROOT_REQUIRED")
        require(isinstance(context, BridgeContext) and capability is not None, "EXPLICIT_CONTEXT_AND_CAPABILITY_REQUIRED")
        self.context, self.capability, self.verifier, self.now = context, capability, verify, now
        require(callback_sha256(verify) == context.verifier_sha256, "VERIFIER_CODE_PIN_MISMATCH")
        self.store = store if store is not None else p.CaseStore(self.root)
        require(Path(self.store.root) == self.root, "STORE_ROOT_MISMATCH")
        self.verify({"schema": VERSION, "action": "bind_case_root", "case_root": str(self.root),
                     "lane": "candidate_case_local", **asdict(context)})

    def verify(self, binding):
        require(callback_sha256(self.verifier) == self.context.verifier_sha256, "VERIFIER_CODE_PIN_CHANGED")
        if self.verifier(self.capability, p.decode(p.canonical(binding))) is not True:
            raise PermissionError("PARENT_CAPABILITY_OR_PROTECTED_PIN_DENIED")

    def attempt(self, kind, envelope, reservation):
        require(isinstance(envelope, dict) and set(envelope) == {"data", "retry_profile_sha256"}, "ENVELOPE_SCOPE")
        p.checked(envelope["data"], _SEARCH_INPUT if kind == "search" else _CAPTURE_INPUT)
        profile = envelope["retry_profile_sha256"]
        if profile is not None:
            p.checked(profile, p.HASH)
        data = envelope["data"]
        require(data["as_of_date"] == self.context.as_of_date, "AS_OF_BINDING_MISMATCH")
        if kind == "search":
            scopes = set(self.context.jurisdictions)
            if scopes.intersection(p.US):
                scopes.add("US federal")
            require(data["jurisdiction"] in scopes, "JURISDICTION_BINDING_MISMATCH")
        else:
            require(is_allowed_source_url(data["url"]), "OFFICIAL_URL_REQUIRED")
        require(isinstance(reservation, dict) and set(reservation) == {
            "case_id", "request_sha256", "policy_sha256", "kind", "attempt", "input_sha256", "budget", "attempt_root"},
            "RESERVATION_SHAPE")
        require(all(reservation[k] == getattr(self.context, k) for k in ("case_id", "request_sha256", "policy_sha256"))
                and reservation["kind"] == kind and reservation["input_sha256"] == p.digest(envelope)
                and type(reservation["attempt"]) is int and reservation["attempt"] in (1, 2)
                and (profile is None) == (reservation["attempt"] == 1), "RESERVATION_BINDING_MISMATCH")
        operation = "operations/" + kind + "-" + p.digest(data)
        require(reservation["attempt_root"] == operation + "/attempt-" + str(reservation["attempt"]), "ATTEMPT_ROOT_MISMATCH")
        allocation = reservation["budget"]
        maximum = {"search": 4, "capture": 8}[kind]
        require(isinstance(allocation, dict) and set(allocation) == {"case_id", "policy_sha256", "request_sha256",
            "operation", "input_sha256", "kind", "ordinal", "maximum"}, "BUDGET_SHAPE")
        require(type(allocation["ordinal"]) is int and 1 <= allocation["ordinal"] <= maximum
                and type(allocation["maximum"]) is int and allocation["maximum"] == maximum
                and allocation["operation"] == operation
                and all(allocation[k] == reservation[k] for k in ("case_id", "policy_sha256", "request_sha256", "input_sha256", "kind")),
                "BUDGET_BINDING_MISMATCH")
        attempt = _Attempt(self, kind, envelope, reservation)
        attempt.verify("use_reservation", public_input=data)
        # Read only the exact already-reserved protocol paths, never enumerate.
        for path, value in ((reservation["attempt_root"] + "/reservation.json", reservation),
                            (reservation["attempt_root"] + "/input.json", envelope),
                            (f"budget/{kind}-{allocation['ordinal']:02d}.json", allocation)):
            require(self.store.read(path) == p.canonical(value), "DURABLE_RESERVATION_MISMATCH")
        return attempt


class HostWebSearch(_Bridge):
    def __init__(self, *, timeout_seconds=300, poll_seconds=2, monotonic=time.monotonic,
                 sleep=time.sleep, **kwargs):
        super().__init__(**kwargs)
        require(type(timeout_seconds) in (int, float) and 0 < timeout_seconds <= 1800
                and type(poll_seconds) in (int, float) and 0 < poll_seconds <= 60, "BOUNDED_WAIT_REQUIRED")
        self.timeout, self.poll, self.monotonic, self.sleep = timeout_seconds, poll_seconds, monotonic, sleep

    def __call__(self, envelope, reservation):
        attempt = self.attempt("search", envelope, reservation)
        try:
            attempt.start()
            deadline = self.monotonic() + self.timeout
            # A sleeping callback never retries the web operation. The parent
            # publishes once; the protocol owns another changed-profile attempt.
            while not self.store.exists(attempt.root + "/response-ready.json"):
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    raise TimeoutError("HOST_WEB_RESPONSE_DEADLINE")
                self.sleep(min(self.poll, remaining))
            require(self.monotonic() <= deadline, "HOST_WEB_RESPONSE_DEADLINE")
            raw = attempt.read_parent("response.json")
            attempt.put("response-observed.bytes", raw)  # Retain even invalid JSON.
            marker_raw = attempt.read_parent("response-ready.json")
            attempt.put("response-ready-observed.bytes", marker_raw)
            marker = p.decode(marker_raw)
            require(marker == {"response_sha256": p.digest(raw)}, "RESPONSE_COMPLETION_HASH_MISMATCH")
            response = p.decode(raw)
            require(isinstance(response, dict) and set(response) == {
                "schema", "request_sha256", "reservation_sha256", "result"}
                and response["schema"] == WEB_RESPONSE_VERSION
                and response["request_sha256"] == attempt.request_hash
                and response["reservation_sha256"] == p.digest(reservation), "WEB_RESPONSE_BINDING_MISMATCH")
            result = p.checked(response["result"], p.SEARCH_SCHEMA)
            for hit in result["hits"]:
                parsed = urlsplit(hit["url"])
                require(parsed.scheme in ("https", "http") and parsed.hostname and not parsed.username
                        and not parsed.password and not any(c.isspace() or ord(c) < 32 for c in hit["url"]),
                        "INVALID_DISCOVERY_URL")
            attempt.verify("web_response", request_file_sha256=attempt.request_hash,
                response_sha256=p.digest(raw), raw_sha256=p.digest(result["raw_utf8"].encode()),
                hits_sha256=p.digest(result["hits"]), tool_receipt_sha256=result["tool_receipt_sha256"],
                tool="functions.web", ready_file_sha256=p.digest(marker_raw))
            return attempt.finish(result, response_sha256=p.digest(raw))
        except BaseException as exc:
            if attempt.owned:
                attempt.failed(exc)
            raise


def make_search_callback(**kwargs):
    """Return a bound Python callback, also compatible with the fault harness."""
    return HostWebSearch(**kwargs).__call__


class _PublicHTTPSConnection(http.client.HTTPSConnection):
    """Connect to the checked DNS answer; TLS still verifies the original host.

    No proxy/environment credentials or second DNS lookup after validation.
    Socket operations have an explicit timeout; OS DNS resolution has its own
    resolver timeout and is not represented as a guaranteed wall-clock sandbox.
    """
    def connect(self):
        infos = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        require(bool(infos) and all(ipaddress.ip_address(info[4][0]).is_global for info in infos),
                "NON_PUBLIC_DNS_ADDRESS")
        family, kind, proto, _, address = infos[0]
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(self.timeout)
            sock.connect(address)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def verified_tls_context():
    """Return a verifying TLS context using the host's fixed CA locations.

    Some framework Python builds report an OpenSSL default CA path that does
    not exist even though the operating system exposes its trust bundle at
    /etc/ssl/cert.pem.  Keep certificate and hostname verification enabled and
    use only fixed local trust-bundle paths; never consume proxy credentials or
    an unverified context.
    """
    defaults = ssl.get_default_verify_paths()
    candidates = [defaults.cafile, "/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"]
    for value in candidates:
        if value and Path(value).is_file():
            return ssl.create_default_context(cafile=value)
    raise BridgeError("TLS_CA_BUNDLE_UNAVAILABLE")


def fetch_official(url, *, max_bytes, timeout_seconds, emit):
    """Actual HTTPS GET, no automatic redirects; preserve each hop/partial body.

    emit receives only bounded files within this attempt. No process execution,
    file discovery, environment proxy, credentials, retries or network fallback.
    """
    require(is_allowed_source_url(url) and type(max_bytes) is int and 0 < max_bytes <= MAX_RAW_BYTES,
            "OFFICIAL_URL_AND_BYTE_QUOTA_REQUIRED")
    require(type(timeout_seconds) in (int, float) and 0 < timeout_seconds <= 60, "BOUNDED_CAPTURE_TIMEOUT_REQUIRED")
    deadline, current, chain = time.monotonic() + timeout_seconds, url, [url]
    for hop in range(12):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("CAPTURE_DEADLINE")
        require(is_allowed_source_url(current), "OFFICIAL_URL_REQUIRED")
        emit(f"hop-{hop:02d}-request.json", {"url": current, "requested_at": _stamp()})
        parsed = urlsplit(current)
        connection = _PublicHTTPSConnection(parsed.hostname, timeout=remaining, context=verified_tls_context())
        raw, has_body = bytearray(), False
        try:
            connection.request("GET", (parsed.path or "/") + ("?" + parsed.query if parsed.query else ""),
                headers={"User-Agent": "LegalBot-Case-Local-Research/1.0", "Accept-Encoding": "identity"})
            response = connection.getresponse()
            headers = response.getheaders()
            require(len(p.canonical(headers)) <= 65536, "HTTP_HEADERS_TOO_LARGE")
            emit(f"hop-{hop:02d}-response.json", {"url": current, "status": response.status,
                 "headers": headers, "received_at": _stamp()})
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                require(isinstance(location, str) and bool(location), "REDIRECT_LOCATION_MISSING")
                new = urljoin(current, location)
                require(redirect_allowed(current, new) and new not in chain and len(chain) < 12,
                        "REDIRECT_REFUSED")
                chain.append(new)
                current = new
                continue
            has_body = True
            length = response.getheader("Content-Length")
            if length is not None:
                require(re.fullmatch(r"[0-9]{1,12}", length) is not None, "INVALID_CONTENT_LENGTH")
            try:
                while len(raw) <= max_bytes:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("CAPTURE_DEADLINE")
                    if connection.sock is not None:
                        connection.sock.settimeout(remaining)
                    block = response.read(min(65536, max_bytes + 1 - len(raw)))
                    if not block:
                        break
                    raw.extend(block)
            except http.client.IncompleteRead as exc:
                raw.extend(exc.partial[:max_bytes + 1 - len(raw)])
                raise
            require(len(raw) <= max_bytes, "CAPTURE_BYTE_QUOTA_EXCEEDED")
            require(length is None or len(raw) == int(length), "TRUNCATED_HTTP_BODY")
            require(response.status == 200, "CAPTURE_NOT_HTTP_200")
            require(response.getheader("Content-Encoding", "identity").lower() in ("", "identity"),
                    "COMPRESSED_TRANSPORT_NOT_ENABLED")
            require(bool(raw), "EMPTY_CAPTURE")
            result = {"canonical_url": url, "final_url": current,
                "redirect_chain": chain if len(chain) > 1 else [], "fetched_at": _stamp(),
                "raw_sha256": p.digest(bytes(raw)), "byte_count": len(raw), "http_status": response.status}
            emit("transport.json", result)
            return result
        finally:
            connection.close()
            if has_body:
                emit("raw.bytes", bytes(raw))  # Oversize sentinel/failed body stays preserved.
    raise BridgeError("REDIRECT_LIMIT")


def parse_official_capture(raw, *, source_url, expected_raw_sha256):
    """Lazy production intake import: failure stays HOLD, no substitute parser."""
    from scripts import ge_auto_research_intake as intake
    from backend.app.contracts.schema_registry import canonical_json_bytes
    before = intake.parser_binding(include_legal_tables=True)
    manifest = intake.parsed_manifest(raw, source_url=source_url, expected_raw_sha256=expected_raw_sha256,
                                     include_legal_tables=True)
    require(manifest["parser_sha256"] == before == intake.parser_binding(include_legal_tables=True), "PARSER_CODE_CHANGED")
    require(manifest["parsed_sha256"] == p.digest(canonical_json_bytes(manifest["parsed"])), "PARSED_MANIFEST_HASH_MISMATCH")
    return manifest


def structural_parts(manifest):
    """Exact parser block text/anchors; heading parents only where parser supplies them."""
    parsed = manifest["parsed"]
    require(parsed.get("status") == "ready" and 1 <= len(parsed.get("body_blocks", [])) <= 512,
            "STRUCTURAL_PARSE_NOT_READY")
    parts, seen, headings = [], set(), {}
    for block in parsed["body_blocks"]:
        ordinal = block["ordinal"]
        require(type(ordinal) is int and ordinal >= 0 and ordinal not in seen, "BLOCK_ORDINAL_MISMATCH")
        seen.add(ordinal)
        part_id = f"block-{ordinal:06d}"
        path = tuple(block["heading_path"])
        require(all(isinstance(v, str) and v for v in path), "INVALID_HEADING_PATH")
        heading = block["kind"] in ("heading", "title")
        parent_path = path[:-1] if heading else path
        parent = None
        for depth in range(len(parent_path), 0, -1):
            if parent_path[:depth] in headings:
                parent = headings[parent_path[:depth]]
                break
        part = {"part_id": part_id, "parent_id": parent, "locator": block["source_anchor"], "text": block["text"]}
        p.checked(part, p.PART)
        parts.append(part)
        if heading and path:
            headings[path] = part_id
    return parts


class HostCapture(_Bridge):
    def __init__(self, *, parser_sha256, max_bytes=MAX_RAW_BYTES, timeout_seconds=45,
                 transport=fetch_official, parser=parse_official_capture, **kwargs):
        super().__init__(**kwargs)
        p.checked(parser_sha256, p.HASH)
        require(type(max_bytes) is int and 0 < max_bytes <= MAX_RAW_BYTES, "CAPTURE_BYTE_QUOTA_REQUIRED")
        require(type(timeout_seconds) in (int, float) and 0 < timeout_seconds <= 60, "BOUNDED_CAPTURE_TIMEOUT_REQUIRED")
        self.parser_pin, self.max_bytes, self.timeout = parser_sha256, max_bytes, timeout_seconds
        self.transport, self.parser = transport, parser
        self.transport_code, self.parser_code = callback_sha256(transport), callback_sha256(parser)

    @property
    def parser_mode(self):
        """Checked new mode; base parse/current-review bindings never interchange."""
        return PARSER_MODE

    def __call__(self, envelope, reservation):
        attempt = self.attempt("capture", envelope, reservation)
        try:
            attempt.start()
            url = envelope["data"]["url"]
            from scripts import ge_auto_research_intake as intake
            require(self.parser_pin == intake.parser_binding(include_legal_tables=True), "PARSER_BINDING_MISMATCH")
            attempt.verify("capture_execute", url=url, max_bytes=self.max_bytes, timeout_seconds=self.timeout,
                transport_code_sha256=self.transport_code, parser_adapter_sha256=self.parser_code,
                parser_sha256=self.parser_pin, parser_mode=self.parser_mode, include_legal_tables=True)
            require(callback_sha256(self.transport) == self.transport_code
                    and callback_sha256(self.parser) == self.parser_code, "CAPTURE_CALLBACK_CHANGED")
            def emit(name, value):
                require(name in ("raw.bytes", "transport.json") or re.fullmatch(r"hop-\d{2}-(request|response)\.json", name),
                        "TRANSPORT_FILE_SCOPE")
                raw = value if isinstance(value, bytes) else p.canonical(value)
                require(len(raw) <= (self.max_bytes + 1 if name == "raw.bytes" else MAX_METADATA_BYTES), "TRANSPORT_FILE_QUOTA")
                attempt.verify("capture_file_write", name=name, sha256=p.digest(raw), byte_count=len(raw))
                attempt.put(name, raw)
            transport = self.transport(url, max_bytes=self.max_bytes, timeout_seconds=self.timeout, emit=emit)
            require(self.store.read(attempt.root + "/transport.json") == p.canonical(transport), "TRANSPORT_RECEIPT_FILE_MISMATCH")
            raw = self.store.read(attempt.root + "/raw.bytes")
            require(0 < len(raw) <= self.max_bytes and transport["canonical_url"] == url
                    and transport["http_status"] == 200 and transport["byte_count"] == len(raw)
                    and transport["raw_sha256"] == p.digest(raw), "RAW_CAPTURE_BINDING_MISMATCH")
            chain = transport["redirect_chain"]
            require(isinstance(chain, list) and len(chain) <= 12 and (
                (not chain and transport["final_url"] == url) or
                (len(chain) >= 2 and chain[0] == url and chain[-1] == transport["final_url"]
                 and len(set(chain)) == len(chain) and all(redirect_allowed(a, b) for a, b in zip(chain, chain[1:])))),
                "REDIRECT_RECEIPT_MISMATCH")
            require(is_allowed_source_url(transport["final_url"]), "OFFICIAL_FINAL_URL_REQUIRED")
            require(_time(attempt.started_at) <= _time(transport["fetched_at"]) <= _time(self.now()), "CAPTURE_TIME_MISMATCH")
            manifest = self.parser(raw, source_url=transport["final_url"], expected_raw_sha256=p.digest(raw))
            attempt.put("parse-manifest.json", manifest)
            from backend.app.contracts.schema_registry import canonical_json_bytes
            require(manifest["source_url"] == transport["final_url"] and manifest["raw_sha256"] == p.digest(raw)
                    and manifest["parser_sha256"] == self.parser_pin
                    and manifest["parsed_sha256"] == p.digest(canonical_json_bytes(manifest["parsed"])),
                    "PARSER_BINDING_MISMATCH")
            require(manifest["source_review"] == "NOT_PERFORMED" and manifest["production_admission"] is False
                    and manifest["legal_gold"] is False, "CAPTURE_CANNOT_ASSERT_LEGAL_ADMISSION")
            parts = structural_parts(manifest)
            attempt.put("parts.json", parts)
            # Re-read retained bytes before producing the final adapter result.
            for name, expected in tuple(attempt.files.items()):
                require(p.digest(self.store.read(attempt.root + "/" + name)) == expected, "CAPTURE_ARTIFACT_CHANGED")
            parser_receipt = {"schema": VERSION, "request_sha256": attempt.request_hash,
                "reservation_sha256": p.digest(reservation), "source_sha256": p.digest(raw),
                "parsed_sha256": p.digest(parts), "intake_parsed_sha256": manifest["parsed_sha256"],
                "parser_sha256": self.parser_pin, "parser_mode": self.parser_mode, "include_legal_tables": True,
                "transport_code_sha256": self.transport_code,
                "parser_adapter_sha256": self.parser_code, "fetched_at": transport["fetched_at"],
                "canonical_url": url, "final_url": transport["final_url"], "redirect_chain": chain,
                "files": dict(attempt.files), "source_review": "NOT_PERFORMED", "admitted": False}
            receipt_sha = attempt.put("parser-receipt.json", parser_receipt)
            attempt.verify("capture_parse", source_sha256=p.digest(raw), parsed_sha256=p.digest(parts),
                parser_sha256=self.parser_pin, parser_receipt_sha256=receipt_sha, files=dict(attempt.files),
                fetched_at=transport["fetched_at"], redirect_chain=chain,
                parser_mode=self.parser_mode, include_legal_tables=True)
            result = {k: transport[k] for k in ("canonical_url", "final_url", "redirect_chain", "fetched_at")}
            result.update(raw_b64=base64.b64encode(raw).decode("ascii"), parts=parts,
                          parser_sha256=self.parser_pin, parser_receipt_sha256=receipt_sha)
            p.checked(result, p.CAPTURE_SCHEMA)
            return attempt.finish(result, parser_receipt_sha256=receipt_sha)
        except BaseException as exc:
            if attempt.owned:
                attempt.failed(exc)
            raise


def make_capture_callback(**kwargs):
    """Return a bound Python callback, also compatible with the fault harness."""
    return HostCapture(**kwargs).__call__
