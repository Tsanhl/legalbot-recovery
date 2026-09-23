"""Synthetic transport repair tests: memory-only files, stubbed network, no cleanup.

Run with ``python3 -B -m unittest backend.tests.test_ge_unseen_source_repair -v``.
Only runner source code is read to load its capture/path/digest APIs through AST;
the runner, application, bank artifacts and evaluation state are never imported.
"""
from __future__ import annotations

import ast
import fnmatch
import hashlib
import io
import json
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from urllib.parse import urlparse
from urllib.request import Request

from scripts import ge_unseen_source_repair as repair
from scripts import ge_unseen_sources as sources


def code_functions(relative_path, names):
    path = Path(__file__).resolve().parents[2] / relative_path
    tree = ast.parse(path.read_text())
    nodes = [node for node in tree.body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in nodes} != names:
        raise AssertionError("runner API changed; update synthetic harness explicitly")
    return compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec",
                   flags=__import__("__future__").annotations.compiler_flag)


RUNNER_API = code_functions("scripts/run_ge_codex_unseen.py",
                            {"safe_path", "read", "write", "sha", "capture"})
DIGEST_API = code_functions("backend/app/evaluation/ge_everyday_unseen.py", {"digest"})


class MemoryPath(PurePosixPath):
    """Filesystem methods cannot fall through to a real pathlib implementation."""

    fs = None

    def absolute(self):
        return self if self.is_absolute() else self.fs.root / self

    def is_symlink(self):
        return self in self.fs.symlinks

    def guard(self, operation):
        if self not in self.fs.checked:
            raise AssertionError(f"access without runner safe_path: {operation} {self}")
        if any(p in self.fs.symlinks for p in (self, *self.parents)):
            raise AssertionError("symlink traversal reached filesystem")
        self.fs.accesses.append((operation, self))

    def exists(self):
        self.guard("exists")
        return self in self.fs.files or self in self.fs.dirs

    def glob(self, pattern):
        self.guard("glob")
        return iter(sorted(p for p in self.fs.files.keys() | self.fs.dirs | self.fs.symlinks
                           if p.parent == self and fnmatch.fnmatchcase(p.name, pattern)))

    def mkdir(self, mode=0o777, parents=False, exist_ok=False):
        self.guard("mkdir")
        if self in self.fs.files or (self in self.fs.dirs and not exist_ok):
            raise FileExistsError(str(self))
        if self.parent not in self.fs.dirs and not parents:
            raise FileNotFoundError(str(self.parent))
        self.fs.dirs.add(self)
        if parents:
            self.fs.dirs.update(self.parents)

    def open(self, mode, encoding=None):
        self.guard("open:" + mode)
        if mode == "rb":
            if self not in self.fs.files:
                raise FileNotFoundError(str(self))
            return io.BytesIO(self.fs.files[self])
        if mode not in ("x", "xb"):
            raise AssertionError("overwrite/truncation mode forbidden")
        if self in self.fs.files or self in self.fs.dirs:
            raise FileExistsError(str(self))
        if self.parent not in self.fs.dirs:
            raise FileNotFoundError(str(self.parent))
        # Reserve immediately, just like O_EXCL, including interrupted writes.
        self.fs.files[self] = b""
        self.fs.creates.append(self)
        path = self

        class ByteWriter(io.BytesIO):
            def close(self):
                if not self.closed:
                    data = self.getvalue()
                    path.fs.files[path] = path.fs.write_hook(path, data)
                super().close()

        class TextWriter(io.StringIO):
            def close(self):
                if not self.closed:
                    data = self.getvalue().encode(encoding or "utf-8")
                    path.fs.files[path] = path.fs.write_hook(path, data)
                super().close()

        return ByteWriter() if mode == "xb" else TextWriter()

    def read_bytes(self):
        with self.open("rb") as stream:
            return stream.read()

    def read_text(self):
        return self.read_bytes().decode()

    def chmod(self, mode):
        self.guard("chmod")
        if mode != 0o600:
            raise AssertionError("unexpected file permissions")


class Response:
    def __init__(self, url, raw, status=200):
        self.url, self.raw, self.status = url, raw, status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size):
        return self.raw[:size]


class SyntheticHTTPError(OSError):
    # urllib.HTTPError owns a tempfile-wrapper cleanup callback even with an
    # in-memory stream. This plain exception needs no automatic cleanup at all.
    pass


class RepairTests(unittest.TestCase):
    def setUp(self):
        root = MemoryPath("/synthetic/workspace")
        fs = SimpleNamespace(root=root, files={}, dirs={root, *root.parents},
                             symlinks=set(), checked=set(), accesses=[], creates=[],
                             write_hook=lambda path, data: data)
        MemoryPath.fs = fs
        namespace = dict(Path=MemoryPath, ROOT=root, hashlib=hashlib, json=json,
                         datetime=datetime, UTC=UTC, urlparse=urlparse, Request=Request,
                         source_text=sources.source_text,
                         is_allowed_source_url=sources.is_allowed_source_url,
                         redirect_allowed=sources.redirect_allowed,
                         subprocess=SimpleNamespace(run=Mock(side_effect=AssertionError("no subprocess"))),
                         BUNDLED_PYTHON=MemoryPath("/never-executed"))
        exec(DIGEST_API, namespace)
        exec(RUNNER_API, namespace)
        original_safe_path = namespace["safe_path"]

        def safe_path(path):
            self.assertIsInstance(path, MemoryPath, "real path access forbidden")
            original_safe_path(path)
            fs.checked.update((path, *path.parents))

        namespace["safe_path"] = safe_path
        namespace["urlopen"] = Mock(side_effect=AssertionError("unstubbed network request"))
        self.r = SimpleNamespace(**{name: namespace[name] for name in
                                   ("ROOT", "safe_path", "read", "write", "sha", "digest",
                                    "source_text", "is_allowed_source_url", "redirect_allowed")})
        self.r.source_text = Mock(wraps=sources.source_text)
        self.capture_calls = []

        def capture(url, directory):
            self.capture_calls.append((url, directory))
            for name in ("source_text", "is_allowed_source_url", "redirect_allowed"):
                namespace[name] = getattr(self.r, name)
            return namespace["capture"](url, directory)

        self.r.capture = capture
        self.fs, self.namespace = fs, namespace
        self.directory = root / "sources"
        self.r.safe_path(self.directory)
        self.directory.mkdir()

    def seed(self, suffix="sample", *, status="CAPTURE_HOLD", error="XML_DTD_FORBIDDEN",
             raw=b"<Text>Synthetic transport sample.</Text>", url=None, **fields):
        url = url or "https://www.gov.uk/" + suffix
        key = hashlib.sha256(url.encode()).hexdigest()
        original = {"url": url, "source_id": key, "status": status,
                    "captured_at": "synthetic-original-time", "text": "", **fields}
        if status == "CAPTURE_HOLD":
            original.update(error_type="SourceTextError", error_message=error)
        self.r.write(self.directory / f"{key}.json", original)
        if raw is not None:
            path = self.directory / f"{key}.bytes"
            self.r.safe_path(path)
            with path.open("xb") as stream:
                stream.write(raw)
        return key, original

    def path(self, key, suffix):
        return self.directory / f"{key}.{suffix}"

    def read(self, key, suffix="repair.json"):
        return self.r.read(self.path(key, suffix))

    def assert_preserved(self, snapshot):
        for path, raw in snapshot.items():
            self.assertEqual(self.fs.files[path], raw, f"original modified: {path}")

    def fake_response(self, url, raw=b"<p>Newly eligible transport sample.</p>", status=200):
        network = self.namespace["urlopen"]
        network.side_effect = None
        network.return_value = Response(url, raw, status)
        return network

    def test_parser_repair_immutable_exact_hashes_and_no_network(self):
        key, original = self.seed(qualified_legal_review=False, legal_gold=False,
                                  full_current_law_eligible=False, admitted=False,
                                  currentness_status="UNRESOLVED", custom_metadata={"ok": False})
        snapshot = self.fs.files.copy()
        result = repair.repair_captures(self.r, self.directory)
        self.assertEqual(result, dict(scanned=1, attempted=1, repaired=1, failed=0, skipped=0))
        corrected = repair.read_capture(self.r, self.directory, key)
        self.assertEqual(corrected["status"], "CAPTURED_NOT_LEGAL_VERIFIED")
        self.assertEqual(corrected["text"], "Synthetic transport sample.")
        self.assertEqual(corrected["source_id"], key)
        self.assertEqual(corrected["text_sha256"], self.r.digest(corrected["text"]))
        self.assertNotEqual(corrected["text_sha256"], hashlib.sha256(corrected["text"].encode()).hexdigest())
        binding = corrected["transport_repair"]
        self.assertEqual(binding["prior_receipt_sha256"], hashlib.sha256(snapshot[self.path(key, "json")]).hexdigest())
        self.assertEqual(binding["original_raw_sha256"], hashlib.sha256(snapshot[self.path(key, "bytes")]).hexdigest())
        for field in ("qualified_legal_review", "legal_gold", "admitted", "full_current_law_eligible",
                      "currentness_status", "custom_metadata", "captured_at"):
            self.assertEqual(corrected[field], original[field])
        self.assert_preserved(snapshot)
        self.assertEqual(self.capture_calls, [])
        self.namespace["urlopen"].assert_not_called()
        after = self.fs.files.copy()
        self.assertEqual(repair.repair_captures(self.r, self.directory)["attempted"], 0)
        self.assertEqual(self.fs.files, after)
        self.r.source_text.assert_called_once()

    def test_patched_xhtml_parser_is_supplied_by_runner(self):
        raw = (b'<?xml version="1.0"?><!DOCTYPE html PUBLIC "synthetic" "https://example.invalid/dtd">'
               b'<html xmlns="http://www.w3.org/1999/xhtml"><body>Sample.</body></html>')
        key, _ = self.seed(raw=raw)
        self.r.source_text = Mock(return_value="Sample.")
        self.assertEqual(repair.repair_captures(self.r, self.directory)["repaired"], 1)
        self.r.source_text.assert_called_once_with(raw)
        self.assertEqual(repair.read_capture(self.r, self.directory, key)["text"], "Sample.")

    def test_newly_allowed_host_uses_real_capture_in_separate_directory(self):
        key, original = self.seed(status="REJECTED_SOURCE_HOST", raw=None,
                                  qualified_legal_review=False, currentness_status="UNRESOLVED")
        raw = b"<p>Newly eligible transport sample.</p>"
        network = self.fake_response(original["url"], raw)
        snapshot = self.fs.files.copy()
        self.assertEqual(repair.repair_captures(self.r, self.directory)["repaired"], 1)
        attempts = self.directory / "transport-repair-attempts"
        self.assertEqual(self.capture_calls, [(original["url"], attempts)])
        network.assert_called_once()
        self.assertEqual(network.call_args.kwargs, {"timeout": 45})
        self.assertEqual(self.fs.files[self.path(key, "bytes")], raw)
        self.assertEqual(self.fs.files[attempts / f"{key}.bytes"], raw)
        corrected = repair.read_capture(self.r, self.directory, key)
        self.assertEqual(corrected["status"], "CAPTURED_NOT_LEGAL_VERIFIED")
        self.assertIsNone(corrected["transport_repair"]["original_raw_sha256"])
        self.assertEqual(corrected["transport_repair"]["attempt_receipt_sha256"],
                         self.r.sha(attempts / f"{key}.json"))
        self.assertFalse(corrected["qualified_legal_review"])
        self.assertEqual(corrected["currentness_status"], "UNRESOLVED")
        self.assert_preserved(snapshot)
        after = self.fs.files.copy()
        self.assertEqual(repair.repair_captures(self.r, self.directory)["attempted"], 0)
        self.assertEqual(self.fs.files, after)

    def test_failed_parser_is_terminal_and_other_sources_continue(self):
        bad_key, bad = self.seed("bad", raw=b'<!DOCTYPE Text [<!ENTITY x "bad">]><Text>&x;</Text>')
        good_key, _ = self.seed("good")
        snapshot = self.fs.files.copy()
        result = repair.repair_captures(self.r, self.directory)
        self.assertEqual((result["attempted"], result["repaired"], result["failed"]), (2, 1, 1))
        self.assertEqual(self.read(bad_key, "repair-failure.json")["status"], "TRANSPORT_REPAIR_FAILED_TERMINAL")
        self.assertEqual(repair.read_capture(self.r, self.directory, bad_key), bad)
        self.assertEqual(repair.read_capture(self.r, self.directory, good_key)["status"], "CAPTURED_NOT_LEGAL_VERIFIED")
        self.assert_preserved(snapshot)
        after = self.fs.files.copy()
        self.r.source_text = Mock(side_effect=AssertionError("failed parser cannot retry"))
        self.assertEqual(repair.repair_captures(self.r, self.directory)["attempted"], 0)
        self.assertEqual(self.fs.files, after)

    def test_new_capture_fields_cannot_upgrade_original_review_status(self):
        key, original = self.seed(status="REJECTED_SOURCE_HOST", raw=None,
                                  qualified_legal_review=False, currentness_status="UNRESOLVED")
        self.fake_response(original["url"])
        real_capture = self.r.capture

        def future_capture(url, directory):
            captured = real_capture(url, directory)
            captured.update(qualified_legal_review=True, currentness_status="CURRENT",
                            legal_gold=True, admitted=True)
            # Synthetic future-runner output, including these fields on disk.
            self.fs.files[directory / f"{key}.json"] = json.dumps(captured).encode()
            return captured

        self.r.capture = future_capture
        self.assertEqual(repair.repair_captures(self.r, self.directory)["repaired"], 1)
        corrected = repair.read_capture(self.r, self.directory, key)
        self.assertEqual(corrected["status"], "CAPTURED_NOT_LEGAL_VERIFIED")
        self.assertFalse(corrected["qualified_legal_review"])
        self.assertEqual(corrected["currentness_status"], "UNRESOLVED")
        self.assertNotIn("legal_gold", corrected)
        self.assertNotIn("admitted", corrected)

    def test_capture_return_alone_cannot_substitute_for_actual_attempt_bytes(self):
        key, original = self.seed(status="REJECTED_SOURCE_HOST", raw=None)
        self.r.capture = Mock(return_value={
            **original, "status": "CAPTURED_NOT_LEGAL_VERIFIED", "text": "Invented capture.",
            "text_sha256": self.r.digest("Invented capture."), "raw_sha256": "0" * 64,
            "final_url": original["url"],
        })
        self.assertEqual(repair.repair_captures(self.r, self.directory)["failed"], 1)
        self.assertNotIn(self.path(key, "bytes"), self.fs.files)
        self.assertNotIn(self.path(key, "repair.json"), self.fs.files)
        self.assertEqual(repair.read_capture(self.r, self.directory, key), original)
        self.assertEqual(repair.repair_captures(self.r, self.directory)["attempted"], 0)
        self.r.capture.assert_called_once()

    def test_transport_holds_and_ineligible_originals_are_never_retried(self):
        for i, error in enumerate(("HTTP Error 404: Not Found", "HTTP Error 403: Forbidden",
                                   "cross-host redirect requires source review", "source exceeds bounded capture size",
                                   "empty extracted source", "XML_PARSE_FAILED", "XML_DTD_FORBIDDEN extra")):
            self.seed(str(i), error=error)
        self.seed("missing-raw", raw=None)
        self.seed("already-captured", status="CAPTURED_NOT_LEGAL_VERIFIED")
        self.seed("rejected-with-raw", status="REJECTED_SOURCE_HOST")
        self.seed("still-rejected", status="REJECTED_SOURCE_HOST", raw=None, url="https://untrusted.example/sample")
        snapshot = self.fs.files.copy()
        result = repair.repair_captures(self.r, self.directory)
        self.assertEqual(result["attempted"], 0)
        self.assertEqual(result["scanned"], 11)
        self.assertEqual(self.fs.files, snapshot)
        self.assertEqual(self.capture_calls, [])
        self.r.source_text.assert_not_called()

    def test_any_existing_marker_or_partial_attempt_blocks_retry(self):
        locations = ("repair.json", "repair-attempt.json", "repair-failure.json", "attempt-json", "attempt-bytes")
        for index, suffix in enumerate(locations):
            key, _ = self.seed(str(index), status="REJECTED_SOURCE_HOST", raw=None)
            if suffix.startswith("attempt-"):
                attempts = self.directory / "transport-repair-attempts"
                path = attempts / (key + (".json" if suffix == "attempt-json" else ".bytes"))
                self.r.safe_path(path)
                attempts.mkdir(parents=True, exist_ok=True)
            else:
                path = self.path(key, suffix)
                self.r.safe_path(path)
            with path.open("xb") as stream:
                stream.write(b"partial-or-malformed")
        snapshot = self.fs.files.copy()
        self.assertEqual(repair.repair_captures(self.r, self.directory)["attempted"], 0)
        self.assertEqual(self.fs.files, snapshot)
        self.assertEqual(self.capture_calls, [])

    def test_tampered_canonical_bytes_original_receipt_and_text_fall_back(self):
        for suffix in ("bytes", "json", "repair.json"):
            with self.subTest(suffix=suffix):
                key, original = self.seed(suffix)
                repair.repair_captures(self.r, self.directory)
                path = self.path(key, suffix)
                if suffix == "bytes":
                    self.fs.files[path] += b"changed"
                elif suffix == "json":
                    # Same parsed object, different exact original receipt bytes.
                    self.fs.files[path] += b" \n"
                else:
                    corrected = self.read(key)
                    corrected["text"] = "Tampered text."
                    self.fs.files[path] = json.dumps(corrected).encode()
                self.assertEqual(repair.read_capture(self.r, self.directory, key), original)

    def test_correction_cannot_change_identity_bindings_or_upgrade_flags(self):
        mutations = {
            "status": "LEGAL_VERIFIED", "source_id": "0" * 64, "url": "https://another.gov/",
            "final_url": "https://another.gov/", "raw_sha256": "0" * 64,
            "text_sha256": "0" * 64, "qualified_legal_review": True,
            "full_current_law_eligible": True, "currentness_status": "CURRENT",
            "admitted": True, "legal_gold": True, "new_legal_flag": True,
            "transport_repair": {"prior_receipt_sha256": "0" * 64},
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                key, original = self.seed(field, qualified_legal_review=False, admitted=False,
                                          legal_gold=False, full_current_law_eligible=False,
                                          currentness_status="UNRESOLVED")
                repair.repair_captures(self.r, self.directory)
                corrected = self.read(key)
                corrected[field] = value
                self.fs.files[self.path(key, "repair.json")] = json.dumps(corrected).encode()
                self.assertEqual(repair.read_capture(self.r, self.directory, key), original)

    def test_new_host_attempt_tampering_fails_effective_getter(self):
        for suffix in ("json", "bytes"):
            with self.subTest(suffix=suffix):
                key, original = self.seed(suffix, status="REJECTED_SOURCE_HOST", raw=None)
                self.fake_response(original["url"])
                repair.repair_captures(self.r, self.directory)
                path = self.directory / "transport-repair-attempts" / f"{key}.{suffix}"
                self.fs.files[path] += b" "
                self.assertEqual(repair.read_capture(self.r, self.directory, key), original)

    def test_cross_host_rejected_by_actual_capture_without_copy(self):
        key, original = self.seed(status="REJECTED_SOURCE_HOST", raw=None)
        self.fake_response("https://another.gov/sample")
        self.assertEqual(repair.repair_captures(self.r, self.directory)["failed"], 1)
        attempt = self.directory / "transport-repair-attempts" / f"{key}.json"
        self.assertEqual(self.r.read(attempt)["status"], "CAPTURE_HOLD")
        self.assertNotIn(self.path(key, "bytes"), self.fs.files)
        self.assertNotIn(self.path(key, "repair.json"), self.fs.files)
        self.assertEqual(repair.read_capture(self.r, self.directory, key), original)
        self.assertEqual(repair.repair_captures(self.r, self.directory)["attempted"], 0)
        self.assertEqual(len(self.capture_calls), 1)

    def test_exact_nh_origins_retry_original_url_and_allow_real_redirect_path(self):
        for host in ("gencourt.state.nh.us", "www.gencourt.state.nh.us"):
            with self.subTest(host=host):
                url = f"https://{host}/rsa/html/NHTOC.htm?chapter=1%2F2&v=synthetic#section"
                key, original = self.seed(url=url, raw=None,
                                          error="cross-host redirect requires source review")
                snapshot = self.fs.files.copy()
                # Server-selected path differs from the eligibility probe. No
                # literal substitution of the URL is permitted for the fetch.
                final_url = "https://gc.nh.gov/updated/synthetic?chapter=1"
                network = self.fake_response(final_url)
                self.r.redirect_allowed = Mock(wraps=sources.redirect_allowed)
                self.assertEqual(repair.repair_captures(self.r, self.directory)["repaired"], 1)
                self.r.redirect_allowed.assert_any_call(
                    url, "https://gc.nh.gov/rsa/html/NHTOC.htm?chapter=1%2F2&v=synthetic")
                self.assertEqual(network.call_args.args[0].full_url, url)
                self.assertEqual(self.capture_calls[-1], (url, self.directory / "transport-repair-attempts"))
                corrected = repair.read_capture(self.r, self.directory, key)
                self.assertEqual(corrected["status"], "CAPTURED_NOT_LEGAL_VERIFIED")
                self.assertEqual(corrected["source_id"], hashlib.sha256(url.encode()).hexdigest())
                self.assertEqual(corrected["url"], url)
                self.assertEqual(corrected["final_url"], final_url)
                self.assertEqual(corrected["transport_repair"]["kind"], "RETRY_VERIFIED_NH_REDIRECT")
                self.assertIsNone(corrected["transport_repair"]["original_raw_sha256"])
                self.assert_preserved(snapshot)
                calls = len(self.capture_calls)
                self.assertEqual(repair.repair_captures(self.r, self.directory)["attempted"], 0)
                self.assertEqual(len(self.capture_calls), calls)

    def test_nh_redirect_requires_current_runner_permission(self):
        url = "https://gencourt.state.nh.us/sample?synthetic=1"
        self.seed(url=url, raw=None, error="cross-host redirect requires source review")
        self.r.redirect_allowed = Mock(return_value=False)
        snapshot = self.fs.files.copy()
        self.assertEqual(repair.repair_captures(self.r, self.directory)["attempted"], 0)
        self.r.redirect_allowed.assert_called_once_with(url, "https://gc.nh.gov/sample?synthetic=1")
        self.assertEqual(self.capture_calls, [])
        self.assertEqual(self.fs.files, snapshot)

    def test_other_redirect_holds_remain_ineligible_even_if_helper_allows(self):
        urls = ("https://www.gov.uk/synthetic", "https://gc.nh.gov/synthetic",
                "https://www.gc.nh.gov/synthetic", "https://other.gencourt.state.nh.us/synthetic",
                "https://www.www.gencourt.state.nh.us/synthetic", "https://gencourt.state.nh.us.evil.gov/synthetic",
                "https://www.legis.state.pa.us/synthetic", "https://www.legislature.state.al.us/synthetic")
        for url in urls:
            self.seed(url=url, raw=None, error="cross-host redirect requires source review")
        for index, error in enumerate(("HTTP Error 404: Not Found", "HTTP Error 403: Forbidden",
                                       "cross-host redirect requires source review extra", "source exceeds bounded capture size")):
            self.seed(url=f"https://gencourt.state.nh.us/other-{index}", raw=None, error=error)
        self.seed(url="https://gencourt.state.nh.us/existing-raw", error="cross-host redirect requires source review")
        self.r.redirect_allowed = Mock(return_value=True)
        snapshot = self.fs.files.copy()
        self.assertEqual(repair.repair_captures(self.r, self.directory)["attempted"], 0)
        self.assertEqual(self.capture_calls, [])
        self.assertEqual(self.fs.files, snapshot)

    def test_nh_retry_failure_and_unverified_destination_are_terminal(self):
        for kind in ("http", "redirect"):
            with self.subTest(kind=kind):
                key, original = self.seed(url=f"https://gencourt.state.nh.us/{kind}", raw=None,
                                          error="cross-host redirect requires source review")
                final_url = "https://gc.nh.gov/synthetic" if kind == "http" else "https://another.gov/synthetic"
                self.fake_response(final_url, status=404 if kind == "http" else 200)
                self.assertEqual(repair.repair_captures(self.r, self.directory)["failed"], 1)
                self.assertNotIn(self.path(key, "bytes"), self.fs.files)
                self.assertEqual(repair.read_capture(self.r, self.directory, key), original)
                calls = len(self.capture_calls)
                self.assertEqual(repair.repair_captures(self.r, self.directory)["attempted"], 0)
                self.assertEqual(len(self.capture_calls), calls)

    def test_capture_failures_get_one_attempt_each_and_preserve_attempt_bytes(self):
        for failure in ("404", "403", "size", "status", "parser", "exception"):
            with self.subTest(failure=failure):
                key, original = self.seed(failure, status="REJECTED_SOURCE_HOST", raw=None)
                network = self.fake_response(original["url"])
                if failure in ("404", "403"):
                    network.side_effect = SyntheticHTTPError(f"HTTP Error {failure}: synthetic")
                elif failure == "size":
                    network.return_value = Response(original["url"], b"x" * 8_000_001)
                elif failure == "status":
                    network.return_value.status = 503
                elif failure == "parser":
                    network.return_value.raw = b'<!DOCTYPE Text [<!ENTITY x "bad">]><Text>&x;</Text>'
                else:
                    network.side_effect = RuntimeError("synthetic transport exception")
                self.assertEqual(repair.repair_captures(self.r, self.directory)["failed"], 1)
                self.assertEqual(repair.read_capture(self.r, self.directory, key), original)
                self.assertNotIn(self.path(key, "bytes"), self.fs.files)
                if failure == "parser":
                    self.assertIn(self.directory / "transport-repair-attempts" / f"{key}.bytes", self.fs.files)
                self.assertEqual(repair.repair_captures(self.r, self.directory)["attempted"], 0)

    def test_existing_raw_created_during_capture_is_never_overwritten(self):
        key, original = self.seed(status="REJECTED_SOURCE_HOST", raw=None)
        self.fake_response(original["url"])
        real_capture = self.r.capture

        def race(url, directory):
            captured = real_capture(url, directory)
            # Simulate another authorized writer winning canonical O_EXCL.
            self.fs.files[self.path(key, "bytes")] = b"concurrent original bytes"
            return captured

        self.r.capture = race
        self.assertEqual(repair.repair_captures(self.r, self.directory)["failed"], 1)
        self.assertEqual(self.fs.files[self.path(key, "bytes")], b"concurrent original bytes")
        self.assertEqual(repair.read_capture(self.r, self.directory, key), original)

    def test_copy_is_verified_before_correction(self):
        key, original = self.seed(status="REJECTED_SOURCE_HOST", raw=None)
        self.fake_response(original["url"])
        self.fs.write_hook = lambda path, data: b"damaged copy" if path == self.path(key, "bytes") else data
        self.assertEqual(repair.repair_captures(self.r, self.directory)["failed"], 1)
        self.assertNotIn(self.path(key, "repair.json"), self.fs.files)
        self.assertEqual(repair.read_capture(self.r, self.directory, key), original)

    def test_original_receipt_change_during_parser_prevents_correction(self):
        key, _ = self.seed()

        def parse(raw):
            self.fs.files[self.path(key, "json")] += b"\n"
            return "Synthetic transport sample."

        self.r.source_text = Mock(side_effect=parse)
        self.assertEqual(repair.repair_captures(self.r, self.directory)["failed"], 1)
        self.assertNotIn(self.path(key, "repair.json"), self.fs.files)

    def test_empty_or_invalid_extraction_is_terminal(self):
        for index, text in enumerate(("", " \n", None, b"binary")):
            with self.subTest(text=text):
                self.seed(str(index))
                self.r.source_text = Mock(return_value=text)
                self.assertEqual(repair.repair_captures(self.r, self.directory)["failed"], 1)
                self.assertEqual(repair.repair_captures(self.r, self.directory)["attempted"], 0)
                self.r.source_text.assert_called_once()

    def test_invalid_key_rejected_before_any_access(self):
        for key in (None, 42, "", "a" * 63, "a" * 65, "G" * 64, "A" * 64,
                    "../" + "a" * 64, "/" + "a" * 64, "a" * 64 + "\n"):
            with self.subTest(key=key):
                before = list(self.fs.accesses)
                with self.assertRaises(ValueError):
                    repair.read_capture(self.r, self.directory, key)
                self.assertEqual(self.fs.accesses, before)

    def test_directory_escape_rejected_before_any_access(self):
        for directory in (MemoryPath("/outside/sources"), self.r.ROOT / ".." / "sources"):
            with self.subTest(directory=directory):
                before = list(self.fs.accesses)
                with self.assertRaisesRegex(RuntimeError, "outside authorized workspace"):
                    repair.repair_captures(self.r, directory)
                with self.assertRaisesRegex(RuntimeError, "outside authorized workspace"):
                    repair.read_capture(self.r, directory, "a" * 64)
                self.assertEqual(self.fs.accesses, before)

    def test_symlink_paths_are_refused_before_access(self):
        key, _ = self.seed()
        paths = [self.directory, self.r.ROOT,
                 *(self.path(key, suffix) for suffix in
                   ("json", "bytes", "repair.json", "repair-attempt.json", "repair-failure.json")),
                 self.directory / "transport-repair-attempts",
                 self.directory / "transport-repair-attempts" / f"{key}.bytes",
                 self.directory / "transport-repair-attempts" / f"{key}.json"]
        snapshot = self.fs.files.copy()
        for path in paths:
            with self.subTest(path=path):
                self.fs.symlinks = {path}
                before = len(self.fs.accesses)
                with self.assertRaisesRegex(RuntimeError, "symlink refused"):
                    repair.read_capture(self.r, self.directory, key)
                self.assertEqual(len(self.fs.accesses), before)
                with self.assertRaisesRegex(RuntimeError, "symlink refused"):
                    repair.repair_captures(self.r, self.directory)
                self.assertEqual(self.fs.files, snapshot)
        self.fs.symlinks = set()

    def test_invalid_original_identity_and_malformed_receipts_are_skipped(self):
        key, original = self.seed()
        original["source_id"] = "0" * 64
        self.fs.files[self.path(key, "json")] = json.dumps(original).encode()
        second, _ = self.seed("malformed")
        self.fs.files[self.path(second, "json")] = b"{partial"
        snapshot = self.fs.files.copy()
        self.assertEqual(repair.repair_captures(self.r, self.directory)["attempted"], 0)
        self.assertEqual(self.fs.files, snapshot)

    def test_missing_malformed_or_failed_correction_returns_original_without_writes(self):
        key, original = self.seed()
        self.assertEqual(repair.read_capture(self.r, self.directory, key), original)
        repair.repair_captures(self.r, self.directory)
        self.fs.files[self.path(key, "repair.json")] = b"{partial"
        snapshot = self.fs.files.copy()
        self.assertEqual(repair.read_capture(self.r, self.directory, key), original)
        self.assertEqual(self.fs.files, snapshot)


if __name__ == "__main__":
    unittest.main()
