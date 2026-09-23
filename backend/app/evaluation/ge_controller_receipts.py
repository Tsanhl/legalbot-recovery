"""Durable, fenced receipts for the single GE controller.

The store is deliberately small and filesystem backed.  It gives GE orchestration
one lease generation, one semantic identity for each unit of work, append-only
attempt evidence, and a global defect ledger.  Files are create-only; no cleanup
or overwrite path exists here.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

HASH = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
TERMINAL_STATUSES = frozenset({"COMPLETE", "HOLD", "FAIL_CLOSED", "SYSTEM_ERROR"})


class ControllerReceiptError(RuntimeError):
    """A controller durability or identity invariant was refused."""


class StaleLeaseError(ControllerReceiptError):
    """A controller tried to commit after a successor lease was issued."""


class RepeatedDefectHold(ControllerReceiptError):
    """A third observation of an unchanged defect was refused."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"


def _digest(value: Any) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ControllerReceiptError(f"invalid {field}")
    return value


def _hash(value: str, field: str) -> str:
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        raise ControllerReceiptError(f"invalid {field}")
    return value


def semantic_work_key(
    *,
    stage: str,
    candidate_id: str,
    set_id: str,
    policy_sha256: str,
    source_set_sha256: str,
    evaluator_sha256: str,
    authority_sha256: str,
) -> str:
    """Return an identity that stays stable across process and run IDs."""

    body = {
        "schema": "legalbot.ge-semantic-work-key.v1",
        "stage": _identifier(stage, "stage"),
        "candidate_id": _identifier(candidate_id, "candidate_id"),
        "set_id": _identifier(set_id, "set_id"),
        "policy_sha256": _hash(policy_sha256, "policy_sha256"),
        "source_set_sha256": _hash(source_set_sha256, "source_set_sha256"),
        "evaluator_sha256": _hash(evaluator_sha256, "evaluator_sha256"),
        "authority_sha256": _hash(authority_sha256, "authority_sha256"),
    }
    return _digest(body)


def stable_defect_fingerprint(
    *,
    stage: str,
    defect_code: str,
    input_sha256: str,
    repair_sha256: str | None,
) -> str:
    """Identify an unchanged defect without including a replaceable job ID."""

    body = {
        "schema": "legalbot.ge-defect-fingerprint.v1",
        "stage": _identifier(stage, "stage"),
        "defect_code": _identifier(defect_code, "defect_code"),
        "input_sha256": _hash(input_sha256, "input_sha256"),
        "repair_sha256": None
        if repair_sha256 is None
        else _hash(repair_sha256, "repair_sha256"),
    }
    return _digest(body)


@dataclass(frozen=True)
class LeaseToken:
    controller_id: str
    owner_ref: str
    authority_sha256: str
    generation: int
    receipt_sha256: str


class DurableControllerReceiptStore:
    """Create-only GE controller receipts guarded by a generation fence."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink():
            raise ControllerReceiptError("controller receipt root cannot be a symlink")
        self._lock_path = self.root / "controller.lock"

    def _path(self, relative: str) -> Path:
        candidate = self.root / relative
        if candidate.is_absolute() and candidate.resolve(strict=False).is_relative_to(self.root):
            for parent in (candidate, *candidate.parents):
                if parent == self.root.parent:
                    break
                if parent.exists() and parent.is_symlink():
                    raise ControllerReceiptError("symlink inside controller receipt store")
            return candidate
        raise ControllerReceiptError("controller receipt path escaped its root")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        descriptor = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _sync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _create(self, relative: str, value: Mapping[str, Any]) -> str:
        raw = _canonical(value)
        digest = _digest(raw)
        object_path = self._path(f"objects/{digest}.json")
        object_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            descriptor = os.open(object_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if object_path.read_bytes() != raw:
                raise ControllerReceiptError("content-addressed object mismatch") from None
        else:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            self._sync_directory(object_path.parent)

        target = self._path(relative)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.link(object_path, target)
        except FileExistsError:
            if target.read_bytes() != raw:
                raise ControllerReceiptError(f"immutable receipt already exists: {relative}") from None
        self._sync_directory(target.parent)
        return digest

    def _latest_generation(self) -> int:
        lease_root = self._path("leases")
        if not lease_root.exists():
            return 0
        generations = []
        for path in lease_root.glob("lease-*.json"):
            match = re.fullmatch(r"lease-(\d{10})\.json", path.name)
            if match:
                generations.append(int(match.group(1)))
        return max(generations, default=0)

    def _require_current(self, lease: LeaseToken) -> None:
        if lease.generation != self._latest_generation():
            raise StaleLeaseError("controller lease generation is stale")
        path = self._path(f"leases/lease-{lease.generation:010d}.json")
        if not path.exists() or _digest(path.read_bytes()) != lease.receipt_sha256:
            raise StaleLeaseError("controller lease receipt changed or is missing")

    def acquire_lease(
        self,
        *,
        controller_id: str,
        owner_ref: str,
        authority_sha256: str,
        authority_mechanism: str,
        authority_authenticated: bool,
        scope: str,
    ) -> LeaseToken:
        controller_id = _identifier(controller_id, "controller_id")
        owner_ref = _identifier(owner_ref, "owner_ref")
        authority_sha256 = _hash(authority_sha256, "authority_sha256")
        authority_mechanism = _identifier(authority_mechanism, "authority_mechanism")
        scope = _identifier(scope, "scope")
        with self._locked():
            generation = self._latest_generation() + 1
            receipt = {
                "schema": "legalbot.ge-controller-lease.v1",
                "controller_id": controller_id,
                "owner_ref": owner_ref,
                "authority_sha256": authority_sha256,
                "authority_mechanism": authority_mechanism,
                "authority_authenticated": bool(authority_authenticated),
                "scope": scope,
                "generation": generation,
                "predecessor_generation": generation - 1 or None,
                "hash_scheme": "LEGALBOT_CANONICAL_JSON_V1_SORTED_KEYS_TRAILING_NEWLINE",
            }
            receipt_sha256 = self._create(
                f"leases/lease-{generation:010d}.json", receipt
            )
        return LeaseToken(
            controller_id=controller_id,
            owner_ref=owner_ref,
            authority_sha256=authority_sha256,
            generation=generation,
            receipt_sha256=receipt_sha256,
        )

    def commit_work(
        self,
        *,
        lease: LeaseToken,
        work: Mapping[str, str],
        status: str,
        outcome: Mapping[str, Any],
    ) -> dict[str, Any]:
        if status not in TERMINAL_STATUSES:
            raise ControllerReceiptError("work status is not terminal")
        key = semantic_work_key(**work)
        with self._locked():
            self._require_current(lease)
            target = self._path(f"completed/{key}.json")
            if target.exists():
                existing = json.loads(target.read_bytes())
                return {"duplicate": True, "work_key_sha256": key, "receipt": existing}
            body = {
                "schema": "legalbot.ge-controller-work-completion.v1",
                "controller_id": lease.controller_id,
                "lease_generation": lease.generation,
                "lease_receipt_sha256": lease.receipt_sha256,
                "authority_sha256": lease.authority_sha256,
                "work_key_sha256": key,
                "work": dict(work),
                "status": status,
                "outcome": dict(outcome),
                "hash_scheme": "LEGALBOT_CANONICAL_JSON_V1_SORTED_KEYS_TRAILING_NEWLINE",
            }
            receipt_sha256 = self._create(f"completed/{key}.json", body)
        return {
            "duplicate": False,
            "work_key_sha256": key,
            "receipt_sha256": receipt_sha256,
            "receipt": body,
        }

    def record_failure(
        self,
        *,
        lease: LeaseToken,
        work: Mapping[str, str],
        defect_code: str,
        input_sha256: str,
        repair_sha256: str | None,
        detail: Mapping[str, Any],
    ) -> dict[str, Any]:
        key = semantic_work_key(**work)
        fingerprint = stable_defect_fingerprint(
            stage=work["stage"],
            defect_code=defect_code,
            input_sha256=input_sha256,
            repair_sha256=repair_sha256,
        )
        with self._locked():
            self._require_current(lease)
            defect_root = self._path(f"defects/{fingerprint}")
            prior = sorted(defect_root.glob("observation-*.json")) if defect_root.exists() else []
            if len(prior) >= 2:
                raise RepeatedDefectHold("unchanged defect already appeared twice")
            ordinal = len(prior) + 1
            body = {
                "schema": "legalbot.ge-controller-defect-observation.v1",
                "controller_id": lease.controller_id,
                "lease_generation": lease.generation,
                "work_key_sha256": key,
                "defect_fingerprint": fingerprint,
                "defect_code": _identifier(defect_code, "defect_code"),
                "input_sha256": _hash(input_sha256, "input_sha256"),
                "repair_sha256": None
                if repair_sha256 is None
                else _hash(repair_sha256, "repair_sha256"),
                "observation": ordinal,
                "detail": dict(detail),
                "stop_required": ordinal >= 2,
            }
            receipt_sha256 = self._create(
                f"defects/{fingerprint}/observation-{ordinal:02d}.json", body
            )
        return {**body, "receipt_sha256": receipt_sha256}


def lease_asdict(lease: LeaseToken) -> dict[str, Any]:
    return asdict(lease)
