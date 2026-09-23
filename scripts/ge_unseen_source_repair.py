"""One transport-only repair per saved URL; all writes are create-exclusive.

``directory`` is the runner's sources directory. The caller supplies the existing
runner as ``r`` and serializes this maintenance operation with normal captures.
No runner import, discovery of banks, model calls, sealing, or CLI occurs here.
Newly allowed hosts and the exact verified NH redirect route call ``r.capture``
in an isolated directory, always using the original URL.

An attempt marker is permanent, including after interruption. Failed attempts
also receive a terminal failure marker; neither kind is automatically retried.
The effective getter checks raw receipt bytes, raw source bytes and the runner's
JSON-based text digest. These integrity checks are not legal verification.
"""
from __future__ import annotations

import hashlib
import json
import re
from contextlib import suppress
from urllib.parse import urlsplit, urlunsplit

__all__ = ["read_capture", "repair_captures"]

_KEY = re.compile(r"[0-9a-f]{64}\Z")
_SCHEMA = "legalbot.ge-unseen-source-repair.v1"
_CAPTURED = "CAPTURED_NOT_LEGAL_VERIFIED"
_PARSER = "REEXTRACT_SAVED_RAW"
_HOST = "RETRY_NEWLY_ALLOWED_HOST"
_NH = "RETRY_VERIFIED_NH_REDIRECT"
_NH_ORIGINS = frozenset({"gencourt.state.nh.us", "www.gencourt.state.nh.us"})
_MAX_RAW = 8_000_000  # Existing runner capture envelope.


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _paths(r, directory, key):
    if not isinstance(key, str) or not _KEY.fullmatch(key):
        raise ValueError("invalid lowercase URL SHA-256 key")
    attempts = directory / "transport-repair-attempts"
    paths = {
        "receipt": directory / f"{key}.json",
        "raw": directory / f"{key}.bytes",
        "repair": directory / f"{key}.repair.json",
        "attempt": directory / f"{key}.repair-attempt.json",
        "failure": directory / f"{key}.repair-failure.json",
        "attempts": attempts,
        "attempt_receipt": attempts / f"{key}.json",
        "attempt_raw": attempts / f"{key}.bytes",
    }
    # Validate lexical paths and symlinks before even probing existence. Do not
    # resolve caller paths, which would hide symlink/parent traversal evidence.
    for path in (directory, *paths.values()):
        r.safe_path(path)
    return paths


def _exists(r, path):
    r.safe_path(path)
    return path.exists()


def _bytes(r, path, *, bounded=False):
    r.safe_path(path)
    with path.open("rb") as stream:
        raw = stream.read(_MAX_RAW + 1) if bounded else stream.read()
    if bounded and (not raw or len(raw) > _MAX_RAW):
        raise ValueError("source outside bounded capture size")
    return raw


def _receipt(r, path):
    raw = _bytes(r, path)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("capture receipt must be an object")
    return value, _hash(raw)


def _write(r, path, value):
    r.safe_path(path)
    r.write(path, value)  # The runner's writer uses mode x, never replacement.


def _kind(r, original, key):
    url = original.get("url")
    if (not isinstance(url, str) or _hash(url.encode()) != key
            or original.get("source_id") != key
            or not r.is_allowed_source_url(url)):
        return None
    if (original.get("status") == "CAPTURE_HOLD"
            and original.get("error_message") == "XML_DTD_FORBIDDEN"):
        return _PARSER
    if original.get("status") == "REJECTED_SOURCE_HOST":
        return _HOST
    if (original.get("status") == "CAPTURE_HOLD"
            and original.get("error_message") == "cross-host redirect requires source review"):
        parsed = urlsplit(url)
        # This constructed URL is ONLY a capability check, never a fetch URL.
        # Capture must follow the verified redirect from the original URL itself.
        target = urlunsplit(("https", "gc.nh.gov", parsed.path, parsed.query, ""))
        if parsed.hostname in _NH_ORIGINS and r.redirect_allowed(url, target):
            return _NH
    return None


def _binding(key, kind, prior_sha, original_raw_sha):
    return {"schema": _SCHEMA, "source_id": key, "kind": kind,
            "prior_receipt_sha256": prior_sha,
            "original_raw_sha256": original_raw_sha}


def _text(r, value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("empty or invalid extracted text")
    return r.digest(value)


def _correction(r, original, key, text, raw_sha, final_url, binding):
    if not r.redirect_allowed(original["url"], final_url):
        raise ValueError("cross-host redirect requires source review")
    # Copy all original non-transport fields verbatim. Never propagate new legal
    # or currentness fields from the retry receipt, even if a future runner adds
    # them. The getter reconstructs this exact projection to detect upgrades.
    return {**original, "source_id": key, "status": _CAPTURED,
            "raw_sha256": raw_sha, "text_sha256": _text(r, text),
            "text": text, "final_url": final_url, "transport_repair": binding}


def _validate_attempt(r, paths, original, key):
    captured, receipt_sha = _receipt(r, paths["attempt_receipt"])
    if (captured.get("status") != _CAPTURED or captured.get("source_id") != key
            or captured.get("url") != original["url"]
            or not r.redirect_allowed(original["url"], captured.get("final_url"))):
        raise ValueError("repair capture held or source identity/redirect changed")
    raw = _bytes(r, paths["attempt_raw"], bounded=True)
    if captured.get("raw_sha256") != _hash(raw):
        raise ValueError("repair capture raw digest mismatch")
    if captured.get("text_sha256") != _text(r, captured.get("text")):
        raise ValueError("repair capture text digest mismatch")
    return captured, receipt_sha, raw


def read_capture(r, directory, key):
    """Return a validated correction, otherwise the original receipt.

    Invalid keys/unsafe paths raise before access. A missing/unreadable original
    also raises: there is no original receipt to return in that situation.
    Missing, malformed, interrupted or tampered corrections fall back unchanged.
    No extraction, transport or filesystem writes occur in this getter.
    """
    paths = _paths(r, directory, key)
    original, prior_sha = _receipt(r, paths["receipt"])
    if not _exists(r, paths["repair"]) or _exists(r, paths["failure"]):
        return original
    try:
        kind = _kind(r, original, key)
        if kind is None:
            return original
        corrected, _ = _receipt(r, paths["repair"])
        marker, _ = _receipt(r, paths["attempt"])
        raw_sha = _hash(_bytes(r, paths["raw"], bounded=True))
        binding = _binding(key, kind, prior_sha, raw_sha if kind == _PARSER else None)
        if marker != binding:
            return original
        if kind == _PARSER:
            if ("raw_sha256" in original and original["raw_sha256"] != raw_sha):
                return original
            final_url = original.get("final_url", original["url"])
        else:
            captured, attempt_sha, attempt_raw = _validate_attempt(r, paths, original, key)
            if raw_sha != _hash(attempt_raw) or corrected.get("text") != captured["text"]:
                return original
            binding = {**binding, "attempt_receipt_sha256": attempt_sha}
            final_url = captured["final_url"]
        expected = _correction(r, original, key, corrected.get("text"),
                               raw_sha, final_url, binding)
        return corrected if corrected == expected else original
    except (OSError, ValueError, TypeError, KeyError):
        return original


def repair_captures(r, directory):
    """Inspect original receipts once; return scanned/attempted/repaired/failed/skipped counts.

    Candidates are XML_DTD_FORBIDDEN with saved bytes, newly allowed rejected
    hosts, and exact legacy NH redirect holds now allowed to gc.nh.gov. Every
    other hold (HTTP, other redirects, size, etc.) is left untouched.
    A saved attempt receipt OR raw file also blocks retries, including partial
    captures without a receipt. No original receipt or byte file is overwritten.
    """
    r.safe_path(directory)
    originals = sorted(directory.glob("*.json"))  # Flat, one bounded snapshot.
    counts = dict(scanned=0, attempted=0, repaired=0, failed=0, skipped=0)
    for path in originals:
        key = path.name[:-5]
        if not _KEY.fullmatch(key):
            continue  # Sidecars are never input receipts.
        paths = _paths(r, directory, key)
        counts["scanned"] += 1
        if any(_exists(r, paths[name]) for name in
               ("repair", "attempt", "failure", "attempt_receipt", "attempt_raw")):
            counts["skipped"] += 1
            continue
        try:
            original, prior_sha = _receipt(r, paths["receipt"])
            kind = _kind(r, original, key)
        except (OSError, ValueError, TypeError):
            kind = None
        raw_exists = _exists(r, paths["raw"])
        if kind is None or (kind == _PARSER) != raw_exists:
            counts["skipped"] += 1
            continue
        # Hash the preserved raw before creating the attempt. Reading bytes does
        # not run extraction. Even a subsequent parser failure is terminal.
        original_raw_sha = None
        if kind == _PARSER:
            r.safe_path(paths["raw"])
            original_raw_sha = r.sha(paths["raw"])
        binding = _binding(key, kind, prior_sha, original_raw_sha)
        try:
            _write(r, paths["attempt"], binding)
        except FileExistsError:
            counts["skipped"] += 1
            continue
        counts["attempted"] += 1
        try:
            if kind == _PARSER:
                raw = _bytes(r, paths["raw"], bounded=True)
                if (_hash(raw) != original_raw_sha or
                        ("raw_sha256" in original and original["raw_sha256"] != original_raw_sha)):
                    raise ValueError("original raw digest mismatch")
                text = r.source_text(raw)
                raw_sha = original_raw_sha
                final_url = original.get("final_url", original["url"])
            else:
                # The existing capture implementation probes and creates these
                # paths itself; preflight every one before giving it control.
                _paths(r, directory, key)
                if _exists(r, paths["raw"]):
                    raise FileExistsError("original raw must not exist before retry")
                returned = r.capture(original["url"], paths["attempts"])
                captured, attempt_sha, raw = _validate_attempt(r, paths, original, key)
                if returned != captured:
                    raise ValueError("capture return differs from saved attempt receipt")
                text, raw_sha, final_url = captured["text"], _hash(raw), captured["final_url"]
                binding = {**binding, "attempt_receipt_sha256": attempt_sha}
                r.safe_path(paths["raw"])
                with paths["raw"].open("xb") as stream:
                    stream.write(raw)
                r.safe_path(paths["raw"])
                paths["raw"].chmod(0o600)
            # Detect changes during work before publishing any correction.
            r.safe_path(paths["receipt"])
            r.safe_path(paths["raw"])
            if r.sha(paths["receipt"]) != prior_sha or r.sha(paths["raw"]) != raw_sha:
                raise ValueError("prior receipt or canonical raw changed during repair")
            corrected = _correction(r, original, key, text, raw_sha, final_url, binding)
            _write(r, paths["repair"], corrected)
            counts["repaired"] += 1
        except Exception as exc:
            # An exclusive-write race or a partial failure marker is still
            # terminal because the permanent attempt already exists.
            with suppress(FileExistsError):
                _write(r, paths["failure"], {
                    **binding, "status": "TRANSPORT_REPAIR_FAILED_TERMINAL",
                    "error_type": type(exc).__name__, "error_message": str(exc)[:240],
                })
            counts["failed"] += 1
    return counts
