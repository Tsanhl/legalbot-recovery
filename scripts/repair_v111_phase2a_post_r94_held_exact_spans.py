#!/usr/bin/env python3
"""Repair only the r99b rows held before a third unchanged attempt.

The repair is advisory and append-only.  It verifies the exact r99b artifact,
its held checkpoints and both prior diagnostics for every held row.  Each row
then receives one attempt under a materially changed plan: a stricter atomic
prompt, a 512-token output cap, explicit MLX cleanup, and a fresh pinned model
process after at most twelve rows.  No owner decision, source admission,
candidate mutation, qualification or later gate can be assigned here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
for root in (PROJECT_ROOT, BACKEND_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from app.model_runtime.config import PINNED_RUNTIME_REVISION  # noqa: E402
from scripts import verify_v111_phase2a_exact_semantic_spans_advisory as base  # noqa: E402
from scripts import verify_v111_phase2a_post_r94_exact_spans as post_r94  # noqa: E402

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R99B_ROOT = REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r99b-exact-span-advisory"
R99B_ARTIFACT = R99B_ROOT / "EXACT-SPAN-ADVISORY-361.json"
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r100-debugged-held-exact-span-repair"
)
EXPECTED_R99B_ARTIFACT_CONTENT_SHA256 = (
    "13d43822888f94cd4750d8404f52c46ec340ba19f32f9aab76c70629416f8ca6"
)
EXPECTED_HELD_ROW_COUNT = 95
REPAIR_MAX_OUTPUT_TOKENS = 512
STRICT_PROPOSITION_CHARACTERS = 180
DEFAULT_ROWS_PER_EPOCH = 12
MAX_ROWS_PER_EPOCH = 12
DEFAULT_PORT = 8780
DEFAULT_TIMEOUT_SECONDS = 900.0
DEFAULT_STARTUP_TIMEOUT_SECONDS = 300.0
INFRASTRUCTURE_FAILURE_CODES = frozenset(
    {
        "connect_error",
        "read_error",
        "read_timeout",
        "remote_protocol_error",
        "model_http_generation_failed",
        "model_http_model_unavailable",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CODE = re.compile(r"^[a-z0-9_]{1,96}$")

SYSTEM_PROMPT = """/no_think
Advisory exact-span repair only. This is one attempt under a changed execution plan for one row previously held after two rejected attempts. Inspect only the supplied sealed-candidate chunks and their precomputed exact span IDs. Return GAP unless one supplied span directly supports one short atomic rule for the named issue. A DIRECT or PARTIAL proposition must contain one independent clause, one sentence, and no more than 180 characters. Do not join separate rules with and/or. Every date, amount, percentage, duration and provision identifier in the proposition must occur in the selected exact span or its locator. Do not add a year merely because it appears in source metadata. Never invent an authority, chunk ID or span ID. Do not answer or apply the scenario. Do not decide owner approval, legal materiality, source admission, qualification or any gate. Output compact JSON only with exactly: {"schema":"p2a-exact-span-id-v2","case_id":"<supplied case id>","rows":[{"row_id":"<supplied row id>","assessment":"DIRECT|PARTIAL|GAP","proposition":"<one atomic proposition of at most 180 characters or empty>","support":{"chunk_id":"<supplied chunk id>","span_id":"<supplied span id>"}|null}]}. Include the supplied row exactly once."""

Invoke = Callable[[dict[str, Any]], dict[str, Any]]


class RuntimeStartupFatalError(RuntimeError):
    """A bound model service reported a terminal load/profile failure."""


@dataclass(frozen=True, slots=True)
class RepairSource:
    r99b: dict[str, Any]
    r99b_digest: str
    recovery_digest: str
    held_row_ids: tuple[str, ...]
    projected_rows: Mapping[str, dict[str, Any]]
    cases: Mapping[str, dict[str, Any]]
    held_checkpoints: Mapping[str, dict[str, Any]]
    diagnostic_history: Mapping[str, tuple[dict[str, Any], dict[str, Any]]]
    source_file_sha256s: tuple[str, ...]


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_r100_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r100_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _verify_r99b_top_level_files() -> tuple[str, ...]:
    expected: dict[str, str] = {}
    sums_path = R99B_ROOT / "SHA256SUMS.txt"
    if sums_path.is_symlink() or not sums_path.is_file():
        raise ValueError("phase2a_r100_r99b_checksums_missing")
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        if (
            not separator
            or not _SHA256.fullmatch(digest)
            or not name
            or "/" in name
            or name in expected
        ):
            raise ValueError("phase2a_r100_r99b_checksums_invalid")
        expected[name] = digest
    required = {"EXACT-SPAN-ADVISORY-361.json", "INTENT.json", "OUTCOME.txt"}
    if set(expected) != required:
        raise ValueError("phase2a_r100_r99b_checksum_scope_invalid")
    for name, digest in expected.items():
        if _sha256_file(R99B_ROOT / name) != digest:
            raise ValueError("phase2a_r100_r99b_checksum_mismatch")
    return tuple(expected[name] for name in sorted(expected))


def _load_source() -> RepairSource:
    top_level_file_sha256s = _verify_r99b_top_level_files()
    r99b = _load_object(R99B_ARTIFACT)
    r99b_digest = _verify_seal(
        r99b,
        "artifact_content_sha256",
        "phase2a_r100_r99b_artifact_seal_invalid",
    )
    findings = r99b.get("findings")
    if (
        r99b_digest != EXPECTED_R99B_ARTIFACT_CONTENT_SHA256
        or r99b.get("schema") != "legalbot.v111.phase2a.post-r94-exact-span-advisory-361.v1"
        or r99b.get("row_count") != post_r94.EXPECTED_ROW_COUNT
        or r99b.get("held_batch_count") != EXPECTED_HELD_ROW_COUNT
        or r99b.get("owner_decisions_applied") is not False
        or r99b.get("technical_qualification_assigned") is not False
        or r99b.get("source_admission_authorized") is not False
        or r99b.get("candidate_mutated") is not False
        or r99b.get("phase2b_authorized") is not False
        or r99b.get("development30_authorized") is not False
        or not isinstance(findings, list)
        or len(findings) != post_r94.EXPECTED_ROW_COUNT
    ):
        raise ValueError("phase2a_r100_r99b_artifact_boundary_invalid")
    held_findings = [
        item
        for item in findings
        if isinstance(item, dict)
        and item.get("assessment") == "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT"
    ]
    held_row_ids = tuple(str(item.get("row_id") or "") for item in held_findings)
    if (
        len(held_row_ids) != EXPECTED_HELD_ROW_COUNT
        or len(set(held_row_ids)) != EXPECTED_HELD_ROW_COUNT
        or any(not row_id for row_id in held_row_ids)
    ):
        raise ValueError("phase2a_r100_held_finding_scope_invalid")
    held_finding_by_id = {str(item["row_id"]): item for item in held_findings}

    held_checkpoints: dict[str, dict[str, Any]] = {}
    checkpoint_file_sha256s: list[str] = []
    for path in sorted((R99B_ROOT / "checkpoints").glob("*.json")):
        value = _load_object(path)
        if value.get("schema") != "legalbot.v111.phase2a.exact-span-held-batch.v1":
            continue
        digest = _verify_seal(
            value,
            "held_content_sha256",
            "phase2a_r100_prior_held_checkpoint_invalid",
        )
        row_ids = value.get("row_ids")
        if not isinstance(row_ids, list) or len(row_ids) != 1:
            raise ValueError("phase2a_r100_prior_held_checkpoint_scope_invalid")
        row_id = str(row_ids[0])
        finding = held_finding_by_id.get(row_id)
        fingerprints = value.get("failure_fingerprints")
        if (
            finding is None
            or finding.get("held_content_sha256") != digest
            or row_id in held_checkpoints
            or value.get("attempt_count") != 2
            or value.get("debug_required_before_third_attempt") is not True
            or not isinstance(fingerprints, list)
            or len(fingerprints) != 2
            or any(not _SHA256.fullmatch(str(item)) for item in fingerprints)
            or value.get("same_failure_fingerprint_twice")
            is not (str(fingerprints[0]) == str(fingerprints[1]))
        ):
            raise ValueError("phase2a_r100_prior_held_checkpoint_boundary_invalid")
        held_checkpoints[row_id] = value
        checkpoint_file_sha256s.append(_sha256_file(path))
    if set(held_checkpoints) != set(held_row_ids):
        raise ValueError("phase2a_r100_prior_held_checkpoint_set_invalid")

    histories: dict[str, list[dict[str, Any]]] = defaultdict(list)
    diagnostic_file_sha256s: list[str] = []
    for path in sorted((R99B_ROOT / "diagnostics").glob("*.json")):
        value = _load_object(path)
        _verify_seal(
            value,
            "diagnostic_content_sha256",
            "phase2a_r100_prior_diagnostic_invalid",
        )
        row_ids = value.get("row_ids")
        if isinstance(row_ids, list) and len(row_ids) == 1:
            row_id = str(row_ids[0])
            if row_id in held_checkpoints:
                histories[row_id].append(value)
                diagnostic_file_sha256s.append(_sha256_file(path))
    normalized_histories: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for row_id in held_row_ids:
        records = sorted(histories[row_id], key=lambda item: int(item.get("attempt", 0)))
        checkpoint = held_checkpoints[row_id]
        fingerprints = [str(item.get("failure_fingerprint") or "") for item in records]
        if (
            len(records) != 2
            or [item.get("attempt") for item in records] != [1, 2]
            or fingerprints != checkpoint["failure_fingerprints"]
            or any(not _SAFE_CODE.fullmatch(str(item.get("error_code") or "")) for item in records)
            or any(item.get("technical_qualification_assigned") is not False for item in records)
            or any(item.get("source_admission_authorized") is not False for item in records)
            or any(item.get("candidate_mutated") is not False for item in records)
            or any(item.get("phase2b_authorized") is not False for item in records)
            or any(item.get("development30_authorized") is not False for item in records)
        ):
            raise ValueError("phase2a_r100_prior_diagnostic_history_invalid")
        normalized_histories[row_id] = (dict(records[0]), dict(records[1]))

    recovery_rows, recovery_digest = post_r94._load_recovery(post_r94.DEFAULT_RECOVERY)
    cases = post_r94._load_cases(post_r94.DEFAULT_CASES)
    recovery_by_id = {str(row["row_id"]): row for row in recovery_rows}
    projected_rows: dict[str, dict[str, Any]] = {}
    for row_id in held_row_ids:
        row = recovery_by_id.get(row_id)
        if row is None or post_r94._static_finding(row) is not None:
            raise ValueError("phase2a_r100_held_row_not_reviewable")
        projected_rows[row_id] = post_r94._project_review_row(row)

    return RepairSource(
        r99b=dict(r99b),
        r99b_digest=r99b_digest,
        recovery_digest=recovery_digest,
        held_row_ids=held_row_ids,
        projected_rows=projected_rows,
        cases=cases,
        held_checkpoints=held_checkpoints,
        diagnostic_history={row_id: normalized_histories[row_id] for row_id in held_row_ids},
        source_file_sha256s=tuple(
            [
                *top_level_file_sha256s,
                *checkpoint_file_sha256s,
                *diagnostic_file_sha256s,
                _sha256_file(post_r94.DEFAULT_RECOVERY),
                _sha256_file(post_r94.DEFAULT_CASES),
            ]
        ),
    )


def _repair_input(*, source: RepairSource, row_id: str, repair_ordinal: int) -> dict[str, Any]:
    row = source.projected_rows[row_id]
    case_id = row_id.split(":", 1)[0]
    history = source.diagnostic_history[row_id]
    prior_checkpoint = source.held_checkpoints[row_id]
    value = base._build_input(
        batch_ordinal=repair_ordinal,
        rows=[row],
        case=source.cases[case_id],
        repair_error_code=None,
    )
    value.update(
        {
            "schema": "legalbot.v111.phase2a.post-r94-debugged-held-repair-input.v1",
            "debugged_third_attempt_under_new_execution_plan": True,
            "prior_attempt_count": 2,
            "prior_batch_ordinal": prior_checkpoint["batch_ordinal"],
            "prior_held_content_sha256": prior_checkpoint["held_content_sha256"],
            "prior_error_codes": [str(item["error_code"]) for item in history],
            "prior_failure_fingerprints": [str(item["failure_fingerprint"]) for item in history],
            "strict_proposition_character_limit": STRICT_PROPOSITION_CHARACTERS,
            "return_gap_when_direct_atomic_support_is_unavailable": True,
            "no_additional_attempt_under_this_plan": True,
        }
    )
    return value


def _envelope(row_input: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    request_id = str(uuid4())
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": json.dumps(row_input, ensure_ascii=False, separators=(",", ":")),
        },
    ]
    return (
        {
            "request_id": request_id,
            "mode": "semantic_verify",
            "payload": {**dict(row_input), "messages": messages},
            "messages": messages,
            "max_tokens": REPAIR_MAX_OUTPUT_TOKENS,
            "temperature": 0.0,
            "top_p": 1.0,
            "seed": 0,
            "stop": [],
        },
        request_id,
    )


def _runtime_identity(
    *, health: Mapping[str, Any], port: int, timeout_seconds: float
) -> dict[str, Any]:
    memory = health.get("memory_profile")
    if (
        health.get("backend") != base.MODEL_BACKEND
        or health.get("model_id") != base.EXPECTED_MODEL_ID
        or health.get("model_loaded") is not True
        or health.get("stub_mode") is not False
        or not isinstance(memory, dict)
        or memory.get("context_window_tokens") != 8192
        or memory.get("max_output_tokens") != REPAIR_MAX_OUTPUT_TOKENS
        or memory.get("prefill_step_size") != 256
        or memory.get("kv_cache_bits") != 4
        or memory.get("kv_group_size") != 64
        or memory.get("clear_cache_after_request") is not True
        or memory.get("single_flight_generation") is not True
    ):
        raise RuntimeError("phase2a_r100_managed_runtime_profile_invalid")
    model_root = PROJECT_ROOT / "models/runtime/Qwen3.5-9B-4bit"
    material = {
        "schema": "legalbot.v111.phase2a.post-r94-debugged-runtime-identity.v1",
        "transport": "literal_loopback_http_phase2a_only",
        "host": "127.0.0.1",
        "port": port,
        "backend": health["backend"],
        "model_id": health["model_id"],
        "expected_model_version": base.EXPECTED_MODEL_VERSION,
        "memory_profile": dict(memory),
        "request_configuration": {
            "mode": "semantic_verify",
            "max_tokens": REPAIR_MAX_OUTPUT_TOKENS,
            "temperature": 0.0,
            "top_p": 1.0,
            "seed": 0,
            "stop": [],
        },
        "timeout_seconds": timeout_seconds,
        "managed_fresh_process_epoch": True,
        "maximum_rows_per_process_epoch": MAX_ROWS_PER_EPOCH,
        "runtime_adapter_file_sha256": _sha256_file(
            PROJECT_ROOT / "backend/app/model_runtime/adapters.py"
        ),
        "runtime_service_file_sha256": _sha256_file(
            PROJECT_ROOT / "backend/app/model_runtime/service.py"
        ),
        "runtime_config_file_sha256": _sha256_file(
            PROJECT_ROOT / "backend/app/model_runtime/config.py"
        ),
        "runtime_lock_file_sha256": _sha256_file(PROJECT_ROOT / "model-runtime/uv.lock"),
        "runtime_pyproject_file_sha256": _sha256_file(
            PROJECT_ROOT / "model-runtime/pyproject.toml"
        ),
        "model_config_file_sha256": _sha256_file(model_root / "config.json"),
        "model_provenance_file_sha256": _sha256_file(model_root / "runtime-model.json"),
        "stateless_advisory_review": True,
        "model_independent_reviewer": False,
    }
    return {**material, "runtime_identity_sha256": _sealed(material)}


def _http_invoker(*, port: int, timeout_seconds: float) -> tuple[Invoke, dict[str, Any]]:
    base_url = f"http://127.0.0.1:{port}"
    parsed = urlparse(base_url)
    if parsed.hostname != "127.0.0.1" or parsed.scheme != "http":
        raise ValueError("phase2a_r100_model_url_invalid")
    with httpx.Client(
        timeout=httpx.Timeout(connect=5, read=30, write=30, pool=5),
        trust_env=False,
        follow_redirects=False,
    ) as client:
        response = client.get(f"{base_url}/api/v1/health")
        health = response.json()
    if not isinstance(health, dict):
        raise RuntimeError("phase2a_r100_managed_runtime_unavailable")
    if response.status_code == 503 and health.get("status") == "unavailable":
        detail = str(health.get("detail") or "")
        code = (
            "phase2a_r100_runtime_dependency_unavailable"
            if "ModuleNotFoundError" in detail
            else "phase2a_r100_runtime_load_unavailable"
        )
        raise RuntimeStartupFatalError(code)
    if response.status_code != 200:
        raise RuntimeError("phase2a_r100_managed_runtime_unavailable")
    identity = _runtime_identity(
        health=health,
        port=port,
        timeout_seconds=timeout_seconds,
    )

    def invoke(envelope: dict[str, Any]) -> dict[str, Any]:
        with httpx.Client(
            timeout=httpx.Timeout(
                connect=5,
                read=timeout_seconds,
                write=30,
                pool=5,
            ),
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = client.post(f"{base_url}/api/v1/generate", json=envelope)
            if response.status_code != 200:
                service_code = "unknown"
                response_request_id = ""
                try:
                    error_body = response.json()
                except (json.JSONDecodeError, ValueError):
                    error_body = None
                if isinstance(error_body, dict):
                    response_request_id = str(error_body.get("request_id") or "")
                    error = error_body.get("error")
                    if isinstance(error, dict):
                        candidate = str(error.get("code") or "").casefold()
                        if _SAFE_CODE.fullmatch(candidate):
                            service_code = candidate
                raise base.SemanticValidationError(
                    f"model_http_{service_code}",
                    diagnostics={
                        "http_status": int(response.status_code),
                        "service_error_code": service_code,
                        "request_id_matches": response_request_id
                        == str(envelope.get("request_id") or ""),
                        "response_body_sha256": _sha256(response.content),
                    },
                )
            value = response.json()
        if not isinstance(value, dict):
            raise base.SemanticValidationError("model_response_not_object")
        return value

    return invoke, identity


def _prepare_output_root(output_root: Path, *, resume: bool) -> None:
    if output_root.exists() or output_root.is_symlink():
        if not resume or output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("phase2a_r100_output_already_exists")
    else:
        output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_r100_output_mode_invalid")
    for name in ("checkpoints", "diagnostics", "runtime-epochs"):
        path = output_root / name
        path.mkdir(mode=0o700, exist_ok=True)
        if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise ValueError("phase2a_r100_output_subdirectory_invalid")


def _intent_material(
    *, source: RepairSource, runtime_identity: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "schema": "legalbot.v111.phase2a.post-r94-debugged-held-repair-intent.v1",
        "status": "ONE_CHANGED_PLAN_ATTEMPT_PER_R99B_HELD_ROW",
        "source_r99b_artifact_content_sha256": source.r99b_digest,
        "source_r99b_artifact_file_sha256": _sha256_file(R99B_ARTIFACT),
        "source_r99b_input_file_sha256s": list(source.source_file_sha256s),
        "source_recovery_content_sha256": source.recovery_digest,
        "source_recovery_file_sha256": _sha256_file(post_r94.DEFAULT_RECOVERY),
        "source_cases_file_sha256": _sha256_file(post_r94.DEFAULT_CASES),
        "held_row_count": len(source.held_row_ids),
        "held_row_ids": list(source.held_row_ids),
        "prior_error_history": {
            row_id: [str(item["error_code"]) for item in source.diagnostic_history[row_id]]
            for row_id in source.held_row_ids
        },
        "prior_held_content_sha256s": [
            str(source.held_checkpoints[row_id]["held_content_sha256"])
            for row_id in source.held_row_ids
        ],
        "root_cause": {
            "confirmed_service_failure": "METAL_GPU_OUT_OF_MEMORY",
            "post_crash_rows_failed_closed_as_connect_errors": True,
            "historical_r99b_artifact_preserved": True,
        },
        "new_execution_plan": {
            "fresh_model_process_per_epoch": True,
            "maximum_rows_per_epoch": MAX_ROWS_PER_EPOCH,
            "maximum_output_tokens": REPAIR_MAX_OUTPUT_TOKENS,
            "prefill_step_size": 256,
            "kv_cache_bits": 4,
            "explicit_stream_close_device_sync_gc_and_cache_clear": True,
            "maximum_proposition_characters": STRICT_PROPOSITION_CHARACTERS,
            "one_independent_clause": True,
            "gap_required_if_direct_atomic_support_unavailable": True,
            "attempts_per_row_under_new_plan": 1,
            "abort_epoch_after_infrastructure_failure": True,
        },
        "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode("utf-8")),
        "repair_code_file_sha256": _sha256_file(Path(__file__).resolve()),
        "shared_verifier_code_file_sha256": _sha256_file(Path(base.__file__).resolve()),
        "post_r94_wrapper_code_file_sha256": _sha256_file(Path(post_r94.__file__).resolve()),
        "evidence_validator_code_file_sha256": _sha256_file(base.EVIDENCE_VALIDATOR_CODE_PATH),
        "runtime_identity": dict(runtime_identity),
        "runtime_identity_sha256": runtime_identity["runtime_identity_sha256"],
        "model_independent_reviewer": False,
        "raw_model_output_persisted": False,
        "hidden_reasoning_persisted": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _initialize_or_verify_intent(
    *,
    output_root: Path,
    source: RepairSource,
    runtime_identity: Mapping[str, Any],
) -> dict[str, Any]:
    path = output_root / "INTENT.json"
    expected_material = _intent_material(
        source=source,
        runtime_identity=runtime_identity,
    )
    if path.exists():
        value = _load_object(path)
        _verify_seal(value, "intent_content_sha256", "phase2a_r100_intent_invalid")
        material = dict(value)
        material.pop("intent_content_sha256", None)
        material.pop("started_at", None)
        comparison = dict(expected_material)
        if material != comparison:
            raise ValueError("phase2a_r100_resume_identity_mismatch")
        return value
    material = {
        **expected_material,
        "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    value = {**material, "intent_content_sha256": _sealed(material)}
    _write_exclusive(path, _pretty_json(value))
    return value


def _checkpoint_name(ordinal: int, row_id: str) -> str:
    return f"{ordinal:03d}-{_sha256((row_id + chr(10)).encode())[:24]}.json"


def _load_repair_checkpoints(
    *, output_root: Path, source: RepairSource
) -> dict[str, dict[str, Any]]:
    completed: dict[str, dict[str, Any]] = {}
    for path in sorted((output_root / "checkpoints").glob("*.json")):
        value = _load_object(path)
        _verify_seal(
            value,
            "checkpoint_content_sha256",
            "phase2a_r100_checkpoint_invalid",
        )
        row_id = str(value.get("row_id") or "")
        if (
            value.get("schema")
            != "legalbot.v111.phase2a.post-r94-debugged-held-repair-checkpoint.v1"
            or row_id not in source.held_row_ids
            or row_id in completed
            or value.get("attempt_under_new_plan") != 1
            or value.get("total_attempt_ordinal_for_row") != 3
        ):
            raise ValueError("phase2a_r100_checkpoint_boundary_invalid")
        completed[row_id] = value
    expected_prefix = source.held_row_ids[: len(completed)]
    if tuple(completed) != expected_prefix:
        raise ValueError("phase2a_r100_checkpoint_order_invalid")
    return completed


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, base.SemanticValidationError):
        return exc.code
    return base._error_code(exc)


def _process_epoch(
    *,
    output_root: Path,
    source: RepairSource,
    invoke: Invoke,
    runtime_identity: Mapping[str, Any],
    epoch_id: str,
    row_limit: int,
) -> tuple[list[str], bool]:
    completed = _load_repair_checkpoints(output_root=output_root, source=source)
    pending = [row_id for row_id in source.held_row_ids if row_id not in completed]
    selected = pending[:row_limit]
    processed: list[str] = []
    abort_epoch = False
    for row_id in selected:
        ordinal = source.held_row_ids.index(row_id) + 1
        row_input = _repair_input(
            source=source,
            row_id=row_id,
            repair_ordinal=ordinal,
        )
        input_sha256 = _sealed(row_input)
        envelope, request_id = _envelope(row_input)
        body: dict[str, Any] | None = None
        started = time.perf_counter()
        diagnostic_sha256: str | None = None
        try:
            body = invoke(envelope)
            normalized, metrics = base._validate_model_response(
                body=body,
                row_input=row_input,
                request_id=request_id,
            )
            if len(normalized) != 1:
                raise base.SemanticValidationError("phase2a_r100_finding_count_invalid")
            proposition = normalized[0].get("atomic_proposition")
            if isinstance(proposition, str) and len(proposition) > STRICT_PROPOSITION_CHARACTERS:
                raise base.SemanticValidationError(
                    "phase2a_r100_proposition_over_180",
                    diagnostics={
                        "proposition_character_count": len(proposition),
                        "maximum_proposition_characters": STRICT_PROPOSITION_CHARACTERS,
                    },
                )
            finding = normalized[0]
            status = "RESOLVED_UNDER_CHANGED_PLAN"
        except Exception as exc:
            error = _error_code(exc)
            failure_material = {
                "schema": "legalbot.v111.phase2a.post-r94-debugged-held-repair-failure.v1",
                "repair_ordinal": ordinal,
                "row_id": row_id,
                "runtime_epoch_id": epoch_id,
                "attempt_under_new_plan": 1,
                "total_attempt_ordinal_for_row": 3,
                "input_content_sha256": input_sha256,
                "request_id": request_id,
                "error_code": error,
                "validation_diagnostics": (
                    dict(exc.diagnostics) if isinstance(exc, base.SemanticValidationError) else {}
                ),
                "failure_fingerprint": _sealed(
                    {
                        "schema": "legalbot.v111.phase2a.post-r94-debugged-held-repair-failure-fingerprint.v1",
                        "row_id": row_id,
                        "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode("utf-8")),
                        "runtime_identity_sha256": runtime_identity["runtime_identity_sha256"],
                        "error_code": error,
                    }
                ),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "response_received": body is not None,
                "raw_output_sha256": (
                    _sha256(str(body.get("raw_text") or "").encode("utf-8")) if body else None
                ),
                "raw_output_persisted": False,
                "hidden_reasoning_persisted": False,
                "no_further_attempt_authorized_under_this_plan": True,
                "owner_decision_assigned": False,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            failure = {
                **failure_material,
                "diagnostic_content_sha256": _sealed(failure_material),
            }
            diagnostic_sha256 = str(failure["diagnostic_content_sha256"])
            _write_exclusive(
                output_root / "diagnostics" / _checkpoint_name(ordinal, row_id),
                _pretty_json(failure),
            )
            finding = {
                "row_id": row_id,
                "assessment": "HELD_AFTER_DEBUGGED_NEW_PLAN_ATTEMPT",
                "atomic_proposition": None,
                "exact_span_binding": None,
                "gap_reason": error.upper(),
                "owner_outcome": None,
                "owner_decision_required": True,
                "technical_qualification_assigned": False,
            }
            metrics = None
            status = "HELD_AFTER_CHANGED_PLAN_ATTEMPT"
            abort_epoch = error in INFRASTRUCTURE_FAILURE_CODES

        history = source.diagnostic_history[row_id]
        checkpoint_material = {
            "schema": "legalbot.v111.phase2a.post-r94-debugged-held-repair-checkpoint.v1",
            "repair_ordinal": ordinal,
            "row_id": row_id,
            "runtime_epoch_id": epoch_id,
            "status": status,
            "attempt_under_new_plan": 1,
            "total_attempt_ordinal_for_row": 3,
            "prior_error_codes": [str(item["error_code"]) for item in history],
            "prior_failure_fingerprints": [str(item["failure_fingerprint"]) for item in history],
            "prior_held_content_sha256": source.held_checkpoints[row_id]["held_content_sha256"],
            "input_content_sha256": input_sha256,
            "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode("utf-8")),
            "runtime_identity_sha256": runtime_identity["runtime_identity_sha256"],
            "finding": finding,
            "model_metrics": metrics,
            "failure_diagnostic_content_sha256": diagnostic_sha256,
            "raw_model_output_persisted": False,
            "hidden_reasoning_persisted": False,
            "owner_decision_assigned": False,
            "technical_qualification_assigned": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        checkpoint = {
            **checkpoint_material,
            "checkpoint_content_sha256": _sealed(checkpoint_material),
        }
        _write_exclusive(
            output_root / "checkpoints" / _checkpoint_name(ordinal, row_id),
            _pretty_json(checkpoint),
        )
        processed.append(row_id)
        print(
            json.dumps(
                {
                    "event": "repair_row_complete",
                    "repair_ordinal": ordinal,
                    "row_id": row_id,
                    "status": status,
                    "completed_count": len(completed) + len(processed),
                    "held_row_count": len(source.held_row_ids),
                    "runtime_epoch_id": epoch_id,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        if abort_epoch:
            break
    return processed, abort_epoch


def _runtime_environment(*, port: int) -> dict[str, str]:
    allowed = ("HOME", "LANG", "LC_ALL", "PATH", "TMPDIR")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update(
        {
            "PYTHONPATH": str(BACKEND_ROOT),
            "PYTHONUNBUFFERED": "1",
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "TOKENIZERS_PARALLELISM": "false",
            "NO_PROXY": "127.0.0.1",
            "LEGALBOT_MODEL_MODE": "mlx",
            "LEGALBOT_MODEL_HOST": "127.0.0.1",
            "LEGALBOT_MODEL_PORT": str(port),
            "LEGALBOT_MODEL_ID": base.EXPECTED_MODEL_ID,
            "LEGALBOT_MODEL_REVISION": PINNED_RUNTIME_REVISION,
            "LEGALBOT_MODEL_PATH": str(PROJECT_ROOT / "models/runtime/Qwen3.5-9B-4bit"),
            "LEGALBOT_MODEL_EAGER_LOAD": "true",
            "LEGALBOT_MODEL_CONTEXT_TOKENS": "8192",
            "LEGALBOT_MODEL_MAX_OUTPUT_TOKENS": str(REPAIR_MAX_OUTPUT_TOKENS),
            "LEGALBOT_MODEL_PREFILL_STEP_SIZE": "256",
            "LEGALBOT_MODEL_KV_BITS": "4",
            "LEGALBOT_MODEL_KV_GROUP_SIZE": "64",
            "LEGALBOT_MODEL_CLEAR_CACHE": "true",
        }
    )
    return environment


def _model_runtime_python() -> Path:
    path = PROJECT_ROOT / "model-runtime/.venv/bin/python"
    if not path.is_file():
        raise ValueError("phase2a_r100_model_runtime_python_missing")
    # Invoking the venv symlink makes Python discover its adjacent pyvenv.cfg.
    # Resolving the symlink first would silently select the system interpreter.
    return path


def _wait_for_runtime(
    *,
    process: subprocess.Popen[bytes],
    port: int,
    timeout_seconds: float,
    startup_timeout_seconds: float,
) -> tuple[Invoke, dict[str, Any]]:
    deadline = time.monotonic() + startup_timeout_seconds
    last_error = "runtime_not_yet_listening"
    while time.monotonic() < deadline:
        return_code = process.poll()
        if return_code is not None:
            raise RuntimeError(f"phase2a_r100_runtime_exited_before_ready_{return_code}")
        try:
            return _http_invoker(port=port, timeout_seconds=timeout_seconds)
        except RuntimeStartupFatalError:
            raise
        except (httpx.HTTPError, RuntimeError, ValueError) as exc:
            last_error = _error_code(exc)
            time.sleep(1.0)
    raise RuntimeError(f"phase2a_r100_runtime_startup_timeout_{last_error}")


def _stop_runtime(process: subprocess.Popen[bytes]) -> tuple[str, int]:
    if process.poll() is not None:
        return "already_exited", int(process.returncode)
    process.terminate()
    try:
        return "terminated", int(process.wait(timeout=30))
    except subprocess.TimeoutExpired:
        process.kill()
        return "killed_after_termination_timeout", int(process.wait(timeout=30))


def _write_epoch_receipt(
    *,
    output_root: Path,
    epoch_number: int,
    epoch_id: str,
    started_at: str,
    processed: Sequence[str],
    abort_epoch: bool,
    runtime_identity: Mapping[str, Any] | None,
    log_path: Path,
    stop_mode: str,
    exit_code: int,
    epoch_error_code: str | None,
) -> dict[str, Any]:
    if (
        epoch_number < 1
        or len(processed) > MAX_ROWS_PER_EPOCH
        or len(set(processed)) != len(processed)
    ):
        raise ValueError("phase2a_r100_runtime_epoch_receipt_scope_invalid")
    material = {
        "schema": "legalbot.v111.phase2a.post-r94-debugged-runtime-epoch.v1",
        "epoch_number": epoch_number,
        "runtime_epoch_id": epoch_id,
        "started_at": started_at,
        "completed_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "processed_row_ids": list(processed),
        "processed_row_count": len(processed),
        "maximum_rows_per_epoch": MAX_ROWS_PER_EPOCH,
        "aborted_after_infrastructure_failure": abort_epoch,
        "runtime_identity_sha256": (
            runtime_identity.get("runtime_identity_sha256")
            if runtime_identity is not None
            else None
        ),
        "service_log_file": log_path.name,
        "service_log_file_sha256": _sha256_file(log_path),
        "service_log_contains_model_output": False,
        "termination_mode": stop_mode,
        "process_exit_code": exit_code,
        "epoch_error_code": epoch_error_code,
        "fresh_process_for_epoch": True,
    }
    receipt = {**material, "epoch_content_sha256": _sealed(material)}
    path = output_root / "runtime-epochs" / f"{epoch_number:03d}.json"
    _write_exclusive(path, _pretty_json(receipt))
    return receipt


def _epoch_count(output_root: Path) -> int:
    receipts = sorted((output_root / "runtime-epochs").glob("[0-9][0-9][0-9].json"))
    for expected, path in enumerate(receipts, start=1):
        if path.name != f"{expected:03d}.json":
            raise ValueError("phase2a_r100_runtime_epoch_sequence_invalid")
        value = _load_object(path)
        _verify_seal(
            value,
            "epoch_content_sha256",
            "phase2a_r100_runtime_epoch_receipt_invalid",
        )
    return len(receipts)


def _finalize(*, output_root: Path, source: RepairSource) -> dict[str, Any]:
    final_path = output_root / "DEBUGGED-HELD-REPAIRS-95.json"
    merged_path = output_root / "REPAIRED-EXACT-SPAN-ADVISORY-361.json"
    if final_path.exists() or merged_path.exists():
        raise ValueError("phase2a_r100_already_finalized")
    checkpoints = _load_repair_checkpoints(output_root=output_root, source=source)
    if tuple(checkpoints) != source.held_row_ids:
        raise ValueError("phase2a_r100_final_checkpoint_coverage_invalid")
    findings = [dict(checkpoints[row_id]["finding"]) for row_id in source.held_row_ids]
    counts = Counter(str(item["assessment"]) for item in findings)
    failures = [
        checkpoint
        for checkpoint in checkpoints.values()
        if checkpoint["status"] == "HELD_AFTER_CHANGED_PLAN_ATTEMPT"
    ]
    epoch_receipts: list[dict[str, Any]] = []
    for path in sorted((output_root / "runtime-epochs").glob("*.json")):
        receipt = _load_object(path)
        _verify_seal(
            receipt,
            "epoch_content_sha256",
            "phase2a_r100_runtime_epoch_receipt_invalid",
        )
        epoch_receipts.append(receipt)
    if not epoch_receipts:
        raise ValueError("phase2a_r100_runtime_epoch_evidence_missing")
    repair_material = {
        "schema": "legalbot.v111.phase2a.post-r94-debugged-held-repairs-95.v1",
        "status": (
            "ALL_R99B_HELD_ROWS_RESOLVED_UNDER_CHANGED_PLAN"
            if not failures
            else "DEBUGGED_REPAIR_COMPLETE_WITH_REMAINING_HELD_ROWS"
        ),
        "source_intent_content_sha256": _load_object(output_root / "INTENT.json")[
            "intent_content_sha256"
        ],
        "source_r99b_artifact_content_sha256": source.r99b_digest,
        "source_recovery_content_sha256": source.recovery_digest,
        "row_count": len(findings),
        "assessment_counts": dict(sorted(counts.items())),
        "failure_count": len(failures),
        "findings": findings,
        "supersedes_only_r99b_held_rows": list(source.held_row_ids),
        "runtime_epoch_count": len(epoch_receipts),
        "runtime_epoch_content_sha256s": [
            str(item["epoch_content_sha256"]) for item in epoch_receipts
        ],
        "raw_model_output_persisted": False,
        "hidden_reasoning_persisted": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    repair = {
        **repair_material,
        "artifact_content_sha256": _sealed(repair_material),
    }
    _write_exclusive(final_path, _pretty_json(repair))

    repair_by_id = {str(item["row_id"]): item for item in findings}
    merged_findings = [
        dict(repair_by_id.get(str(item["row_id"]), item)) for item in source.r99b["findings"]
    ]
    merged_counts = Counter(str(item["assessment"]) for item in merged_findings)
    merged_held = sum(1 for item in merged_findings if str(item["assessment"]).startswith("HELD_"))
    positive = [
        item
        for item in merged_findings
        if str(item["assessment"]).startswith(("DIRECT_", "PARTIAL_"))
    ]
    currentness_pending = sum(
        1
        for item in positive
        if (item.get("source_currentness") or {}).get(
            "separate_currentness_or_later_treatment_review_still_required"
        )
        is True
    )
    merged_material = {
        "schema": "legalbot.v111.phase2a.post-r94-exact-span-advisory-361-with-debugged-repairs.v1",
        "status": (
            "ADVISORY_EXACT_SPANS_COMPLETE_OWNER_DECISIONS_REQUIRED"
            if merged_held == 0
            else "ADVISORY_EXACT_SPANS_HAVE_REMAINING_HELD_ROWS_DEBUG_REQUIRED"
        ),
        "source_r99b_artifact_content_sha256": source.r99b_digest,
        "source_repair_artifact_content_sha256": repair["artifact_content_sha256"],
        "source_recovery_content_sha256": source.recovery_digest,
        "reviewer_execution_mode": base.REVIEWER_EXECUTION_MODE,
        "model_independent_reviewer": False,
        "same_model_adapter_family_as_drafting": True,
        "row_count": len(merged_findings),
        "assessment_counts": dict(sorted(merged_counts.items())),
        "positive_binding_count": len(positive),
        "positive_binding_currentness_or_later_treatment_pending_count": currentness_pending,
        "remaining_held_row_count": merged_held,
        "findings": merged_findings,
        "material_fact_validation_enabled": True,
        "atomicity_validation_enabled": True,
        "unrelated_evidence_validation_enabled": True,
        "exact_span_id_binding_enabled": True,
        "silent_truncation": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    merged = {
        **merged_material,
        "artifact_content_sha256": _sealed(merged_material),
    }
    _write_exclusive(merged_path, _pretty_json(merged))
    outcome = (
        f"{repair['status']}. OWNER DECISIONS REMAIN REQUIRED. "
        "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED.\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode("utf-8"))
    files = sorted(
        path for path in output_root.rglob("*") if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    sums = "".join(f"{_sha256_file(path)}  {path.relative_to(output_root)}\n" for path in files)
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return merged


def run_managed_repair(
    *,
    output_root: Path,
    port: int,
    timeout_seconds: float,
    startup_timeout_seconds: float,
    rows_per_epoch: int,
    resume: bool,
) -> dict[str, Any]:
    if not 1 <= rows_per_epoch <= MAX_ROWS_PER_EPOCH:
        raise ValueError("phase2a_r100_rows_per_epoch_invalid")
    if not 1024 <= port <= 65535:
        raise ValueError("phase2a_r100_port_invalid")
    source = _load_source()
    _prepare_output_root(output_root, resume=resume)
    python = _model_runtime_python()
    epoch_number = _epoch_count(output_root)
    while len(_load_repair_checkpoints(output_root=output_root, source=source)) < len(
        source.held_row_ids
    ):
        epoch_number += 1
        epoch_id = f"r100-epoch-{epoch_number:03d}-{uuid4()}"
        started_at = datetime.now(UTC).isoformat(timespec="seconds")
        log_path = output_root / "runtime-epochs" / f"{epoch_number:03d}.log"
        log_descriptor = os.open(
            log_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        processed: list[str] = []
        abort_epoch = False
        runtime_identity: dict[str, Any] | None = None
        process: subprocess.Popen[bytes] | None = None
        stop_mode = "not_started"
        exit_code = -1
        epoch_error: BaseException | None = None
        with os.fdopen(log_descriptor, "wb") as log_handle:
            process = subprocess.Popen(
                [str(python), "-m", "app.model_runtime"],
                cwd=PROJECT_ROOT,
                env=_runtime_environment(port=port),
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                invoke, runtime_identity = _wait_for_runtime(
                    process=process,
                    port=port,
                    timeout_seconds=timeout_seconds,
                    startup_timeout_seconds=startup_timeout_seconds,
                )
                _initialize_or_verify_intent(
                    output_root=output_root,
                    source=source,
                    runtime_identity=runtime_identity,
                )
                print(
                    json.dumps(
                        {
                            "event": "runtime_epoch_ready",
                            "runtime_epoch_id": epoch_id,
                            "epoch_number": epoch_number,
                            "rows_per_epoch": rows_per_epoch,
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
                processed, abort_epoch = _process_epoch(
                    output_root=output_root,
                    source=source,
                    invoke=invoke,
                    runtime_identity=runtime_identity,
                    epoch_id=epoch_id,
                    row_limit=rows_per_epoch,
                )
            except BaseException as exc:
                epoch_error = exc
            finally:
                stop_mode, exit_code = _stop_runtime(process)
        _write_epoch_receipt(
            output_root=output_root,
            epoch_number=epoch_number,
            epoch_id=epoch_id,
            started_at=started_at,
            processed=processed,
            abort_epoch=abort_epoch,
            runtime_identity=runtime_identity,
            log_path=log_path,
            stop_mode=stop_mode,
            exit_code=exit_code,
            epoch_error_code=(_error_code(epoch_error) if epoch_error is not None else None),
        )
        if epoch_error is not None:
            raise epoch_error
        if not processed:
            raise RuntimeError("phase2a_r100_epoch_completed_without_row")
    return _finalize(output_root=output_root, source=source)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--startup-timeout-seconds",
        type=float,
        default=DEFAULT_STARTUP_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--rows-per-epoch",
        type=int,
        default=DEFAULT_ROWS_PER_EPOCH,
    )
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    result = run_managed_repair(
        output_root=args.output_root.resolve(),
        port=args.port,
        timeout_seconds=args.timeout_seconds,
        startup_timeout_seconds=args.startup_timeout_seconds,
        rows_per_epoch=args.rows_per_epoch,
        resume=bool(args.resume),
    )
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "artifact_content_sha256": result["artifact_content_sha256"],
                "row_count": result["row_count"],
                "assessment_counts": result["assessment_counts"],
                "remaining_held_row_count": result["remaining_held_row_count"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
