"""Capability-gated persistence and replay for v1.11 technical evidence.

The technical run JSON is not authority by itself.  This module admits it only
in the same process that holds the opaque strict-loader capability, records one
create-only receipt in the private run directory and one exact catalogue
ledger row, and later replays both plus every source artifact.  A caller cannot
upgrade legacy favorable summaries or a copied JSON receipt into authority.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Final, Literal

from ..config import Settings
from ..db import Database, utc_iso
from ..retrieval.retrieval_reattest import _clean_integration_sha
from . import v111_technical_attestation as technical
from .live_suite import sealed_sha256
from .live_suite_stage_a_v2_runner import STAGE_A_SCORER_IDENTITY_SHA256
from .nonrelease_artifacts import (
    CreateOnlyRunDirectory,
    safe_json_bytes,
    sealed_safe_payload,
    verify_sealed_artifact,
)
from .sealed_candidate import SealedCandidateIdentity, load_sealed_candidate_identity

V111_TECHNICAL_ADMISSION_SCHEMA = "legalbot.v111-technical-attestation-admission.v1"
V111_TECHNICAL_ADMISSION_LEDGER_SCHEMA = "legalbot.v111-technical-attestation-admission-ledger.v1"
V111_TECHNICAL_ADMISSION_FILENAME = "verified-admission.json"
V111_TECHNICAL_ADMISSION_NAMESPACE = "owner-quality-v111-technical-attestation"

_ADMISSION_TOKEN = object()
_SAFE_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_SAFE_RELATIVE = re.compile(
    r"^data/evaluations/v111-technical-attestations/"
    r"[a-z0-9][a-z0-9._-]{2,127}/verified-admission\.json$"
)


class AdmittedV111TechnicalAttestation:
    """Opaque capability returned only after exact admission or persisted replay."""

    __slots__ = ("_receipt", "_receipt_path", "_token", "_transition")

    def __init__(
        self,
        *,
        receipt_path: Path,
        receipt: Mapping[str, Any],
        transition: Mapping[str, Any],
        _token: object,
    ) -> None:
        if _token is not _ADMISSION_TOKEN:
            raise TypeError("v1.11 technical admission requires strict persisted replay")
        self._receipt_path = receipt_path
        self._receipt = MappingProxyType(dict(receipt))
        self._transition = MappingProxyType(dict(transition))
        self._token = _token

    @property
    def receipt(self) -> Mapping[str, Any]:
        return self._receipt

    @property
    def receipt_path(self) -> Path:
        return self._receipt_path

    @property
    def admission_id(self) -> str:
        return str(self._receipt["admission_id"])

    @property
    def seal_sha256(self) -> str:
        return str(self._receipt["seal_sha256"])

    @property
    def run_id(self) -> str:
        return str(self._receipt["run_id"])

    @property
    def candidate_build_id(self) -> str:
        return str(self._receipt["candidate_build_id"])

    @property
    def integration_sha(self) -> str:
        return str(self._receipt["integration_sha"])

    @property
    def transition(self) -> Mapping[str, Any]:
        return self._transition


def require_admitted_v111_technical_attestation(
    value: object,
) -> AdmittedV111TechnicalAttestation:
    if type(value) is not AdmittedV111TechnicalAttestation or value._token is not _ADMISSION_TOKEN:
        raise TypeError("v1.11 technical admission capability was not strictly replayed")
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _source_member_schemas() -> dict[str, str]:
    members = {
        "run-manifest.json": technical.TECHNICAL_RUN_SCHEMA,
        "stage-a-scorer-reattestation.json": technical.TECHNICAL_STAGE_A_SCHEMA,
        "rollback-plan-readiness.json": technical.TECHNICAL_ROLLBACK_SCHEMA,
        "final-attestation.json": technical.TECHNICAL_FINAL_SCHEMA,
    }
    for spec in technical.FIXED_CHECK_MATRIX:
        members[technical._artifact_name("intents", spec)] = technical.TECHNICAL_INTENT_SCHEMA
        members[technical._artifact_name("outcomes", spec)] = technical.TECHNICAL_OUTCOME_SCHEMA
    return members


_SOURCE_MEMBER_SCHEMAS: Final = _source_member_schemas()
_SOURCE_MEMBER_COUNT: Final = len(_SOURCE_MEMBER_SCHEMAS)


def _safe_receipt_relative_path(settings: Settings, run_id: str) -> str:
    run_root = technical._expected_run_root(settings, run_id)
    receipt = run_root / V111_TECHNICAL_ADMISSION_FILENAME
    relative = receipt.relative_to(settings.project_root.resolve()).as_posix()
    if not _SAFE_RELATIVE.fullmatch(relative):
        raise RuntimeError("technical admission receipt path is not fixed evaluation storage")
    return relative


def _private_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("technical admission artifact is missing or unsafe")
    metadata = path.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError("technical admission artifact is not private")
    return path.read_bytes()


def _private_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir() or stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError("technical admission directory is not private")


def _load_source_artifacts(run_root: Path, *, admitted: bool) -> dict[str, dict[str, Any]]:
    _private_directory(run_root)
    expected_files = set(_SOURCE_MEMBER_SCHEMAS)
    if admitted:
        expected_files.add(V111_TECHNICAL_ADMISSION_FILENAME)
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    for member in run_root.rglob("*"):
        if member.is_symlink():
            raise ValueError("technical admission run inventory contains a symlink")
        relative = member.relative_to(run_root).as_posix()
        if member.is_dir():
            _private_directory(member)
            observed_directories.add(relative)
        elif member.is_file():
            _private_file(member)
            observed_files.add(relative)
        else:
            raise ValueError("technical admission run inventory contains a special file")
    if observed_files != expected_files or observed_directories != {"intents", "outcomes"}:
        raise ValueError("technical admission run inventory is not exact")
    loaded: dict[str, dict[str, Any]] = {}
    for member_name, schema in _SOURCE_MEMBER_SCHEMAS.items():
        raw = _private_file(run_root.joinpath(*PurePosixPath(member_name).parts))
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("technical admission source artifact is invalid JSON") from exc
        if not isinstance(parsed, Mapping):
            raise ValueError("technical admission source artifact is not an object")
        loaded[member_name] = verify_sealed_artifact(parsed, schema=schema)
    return loaded


def _artifact_references(
    run_root: Path, artifacts: Mapping[str, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    return [
        {
            "member": member_name,
            "file_sha256": _file_sha256(run_root.joinpath(*PurePosixPath(member_name).parts)),
            "artifact_seal_sha256": str(artifacts[member_name]["seal_sha256"]),
        }
        for member_name in sorted(artifacts)
    ]


def _validate_source_run(
    *,
    artifacts: Mapping[str, Mapping[str, Any]],
    references: list[dict[str, Any]],
    run_id: str,
    candidate_binding: Mapping[str, Any],
    integration_sha: str,
    context_details: Mapping[str, Any],
) -> None:
    context_binding = context_details.get("context_binding")
    if not isinstance(context_binding, Mapping):
        raise ValueError("technical admission context binding is missing")
    manifest = artifacts["run-manifest.json"]
    expected_manifest = sealed_safe_payload(
        {
            "schema": technical.TECHNICAL_RUN_SCHEMA,
            "run_id": run_id,
            "integration_sha": integration_sha,
            "candidate_build_id": candidate_binding["candidate_build_id"],
            "candidate_manifest_sha256": candidate_binding["candidate_manifest_sha256"],
            "matrix_sha256": technical.FIXED_CHECK_MATRIX_SHA256,
            "checks": [item.safe_dict() for item in technical.FIXED_CHECK_MATRIX],
            "context": dict(context_binding),
            "stage_a_attestation_seal_sha256": context_details["stage_a"]["seal_sha256"],
            "rollback_plan_seal_sha256": context_details["rollback"]["seal_sha256"],
            "execution_policy": "serial_once_no_retry_no_shell_network_denied",
            "raw_output_persisted": False,
            "writes_active": False,
            "writes_o04": False,
            "starts_model": False,
        }
    )
    if manifest != expected_manifest:
        raise ValueError("technical admission run manifest differs from current contract")
    if artifacts["stage-a-scorer-reattestation.json"] != context_details["stage_a"]:
        raise ValueError("technical admission Stage A artifact differs")
    if artifacts["rollback-plan-readiness.json"] != context_details["rollback"]:
        raise ValueError("technical admission rollback artifact differs")
    outcome_seals: list[str] = []
    for spec in technical.FIXED_CHECK_MATRIX:
        intent = artifacts[technical._artifact_name("intents", spec)]
        expected_intent = technical._intent(
            run_id=run_id,
            spec=spec,
            manifest_seal_sha256=str(manifest["seal_sha256"]),
        )
        if intent != expected_intent:
            raise ValueError("technical admission contains a nonfixed check intent")
        outcome = artifacts[technical._artifact_name("outcomes", spec)]
        if (
            outcome.get("run_id") != run_id
            or outcome.get("ordinal") != spec.ordinal
            or outcome.get("check_id") != spec.check_id
            or outcome.get("intent_seal_sha256") != intent["seal_sha256"]
            or outcome.get("attempt_number") != 1
            or outcome.get("retry_count") != 0
            or outcome.get("exit_code") != 0
        ):
            raise ValueError("technical admission check did not pass exactly once")
        for digest_key in ("stdout_sha256", "stderr_sha256"):
            if not _SHA256.fullmatch(str(outcome.get(digest_key) or "")):
                raise ValueError("technical admission output digest is invalid")
        for count_key in (
            "stdout_byte_count",
            "stderr_byte_count",
            "stdout_line_count",
            "stderr_line_count",
        ):
            count = outcome.get(count_key)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError("technical admission output count is invalid")
        semantic_counts = outcome.get("semantic_counts")
        if not isinstance(semantic_counts, Mapping):
            raise ValueError("technical admission semantic result is missing")
        technical._require_semantic_pass(
            check_id=spec.check_id,
            counts=semantic_counts,
            outcome=outcome,
        )
        if spec.check_id == "live60_verify":
            suite_seal = str(context_details["stage_a"].get("suite_manifest_seal_sha256") or "")
            if (
                not _SHA256.fullmatch(suite_seal)
                or outcome.get("stdout_sha256")
                != hashlib.sha256(f"{suite_seal}\n".encode("ascii")).hexdigest()
                or outcome.get("stderr_byte_count") != 0
            ):
                raise ValueError("technical admission Live60 output differs from suite seal")
        outcome_seals.append(str(outcome["seal_sha256"]))
    final = artifacts["final-attestation.json"]
    expected_final = sealed_safe_payload(
        {
            "schema": technical.TECHNICAL_FINAL_SCHEMA,
            "run_id": run_id,
            "integration_sha": integration_sha,
            "candidate_build_id": candidate_binding["candidate_build_id"],
            "candidate_manifest_sha256": candidate_binding["candidate_manifest_sha256"],
            "run_manifest_seal_sha256": manifest["seal_sha256"],
            "matrix_sha256": technical.FIXED_CHECK_MATRIX_SHA256,
            "outcome_seal_sha256s": outcome_seals,
            "outcome_count": len(outcome_seals),
            "context_seal_sha256": context_binding["seal_sha256"],
            "stage_a_attestation_seal_sha256": context_details["stage_a"]["seal_sha256"],
            "rollback_plan_seal_sha256": context_details["rollback"]["seal_sha256"],
            "terminal_state": "matrix_completed",
            "post_promotion_drill_status": "not_part_of_pre_promotion_attestation",
        }
    )
    if final != expected_final:
        raise ValueError("technical admission final attestation differs")
    reference_names = [str(item.get("member") or "") for item in references]
    if (
        len(references) != _SOURCE_MEMBER_COUNT
        or reference_names != sorted(_SOURCE_MEMBER_SCHEMAS)
        or len(set(reference_names)) != len(reference_names)
    ):
        raise ValueError("technical admission artifact reference set is not exact")
    for reference in references:
        member = str(reference["member"])
        artifact = artifacts.get(member)
        if (
            artifact is None
            or reference.get("artifact_seal_sha256") != artifact["seal_sha256"]
            or not _SHA256.fullmatch(str(reference.get("file_sha256") or ""))
        ):
            raise ValueError("technical admission artifact reference differs")


def _context_details(context: technical._Context) -> dict[str, Any]:
    return sealed_safe_payload(
        {
            "schema": "legalbot.v111-technical-admission-context.v1",
            "candidate": dict(context.candidate_binding),
            "stage_a": dict(context.stage_a_binding),
            "toolchain": dict(context.toolchain.binding),
            "lock_set": dict(context.lock_binding),
            "prepromotion_state": dict(context.state_binding),
            "rollback": dict(context.rollback_binding),
            "context_binding": technical._context_binding(context),
        }
    )


def _capture_current_context(
    *,
    settings: Settings,
    database: Database,
    candidate: SealedCandidateIdentity,
    stage_a: technical.StageAReplayInputs,
    expected_integration_sha: str,
) -> technical._Context:
    scratch_parent = settings.evaluation_dir
    scratch_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    scratch_parent.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix=".technical-admission-", dir=scratch_parent) as raw:
        return technical._capture_context(
            settings=settings,
            database=database,
            candidate=candidate,
            stage_a=stage_a,
            expected_integration_sha=expected_integration_sha,
            scratch_root=Path(raw),
        )


def _rollback_policy_binding(context_details: Mapping[str, Any]) -> dict[str, Any]:
    state = context_details["prepromotion_state"]
    active = state.get("active_pointer") if isinstance(state, Mapping) else None
    if not isinstance(active, Mapping) or active.get("state") != "present":
        raise RuntimeError("OWNER_DECISION_REQUIRED:first_live_rollback_target_policy_unresolved")
    return sealed_safe_payload(
        {
            "schema": "legalbot.v111-technical-rollback-policy-binding.v1",
            "policy_sha256": technical._first_live_rollback_policy_sha256(),
            "decision_state": "not_required_prior_active_is_exact_rollback_target",
            "decision_id": "none-existing-active",
            "request_seal_sha256": "0" * 64,
            "resolution_seal_sha256": "0" * 64,
            "prepromotion_state_seal_sha256": state["seal_sha256"],
            "rollback_plan_seal_sha256": context_details["rollback"]["seal_sha256"],
        }
    )


def _ledger_metadata(
    receipt: Mapping[str, Any], *, state: Literal["pending", "active"] = "active"
) -> dict[str, Any]:
    return {
        "schema": V111_TECHNICAL_ADMISSION_LEDGER_SCHEMA,
        "admission_state": state,
        "admission_id": receipt["admission_id"],
        "admission_seal_sha256": receipt["seal_sha256"],
        "run_id": receipt["run_id"],
        "candidate_build_id": receipt["candidate_build_id"],
        "candidate_manifest_sha256": receipt["candidate_manifest_sha256"],
        "integration_sha": receipt["integration_sha"],
        "matrix_sha256": receipt["matrix_sha256"],
        "final_attestation_seal_sha256": receipt["final_attestation_seal_sha256"],
        "artifact_set_sha256": receipt["artifact_set_sha256"],
    }


def admit_verified_v111_technical_attestation(
    verified: object,
    *,
    settings: Settings,
    database: Database,
    candidate: SealedCandidateIdentity,
    stage_a: technical.StageAReplayInputs,
    expected_integration_sha: str,
) -> AdmittedV111TechnicalAttestation:
    """Persist exactly one admission from the process-local strict capability."""

    capability = technical.require_verified_v111_technical_attestation(verified)
    if (
        capability.candidate_build_id != candidate.build_id
        or capability.integration_sha != expected_integration_sha
        or candidate.status != "candidate"
    ):
        raise ValueError("technical capability differs from admission inputs")
    existing_receipt = technical._expected_run_root(settings, capability.run_id) / (
        V111_TECHNICAL_ADMISSION_FILENAME
    )
    if existing_receipt.exists():
        raise FileExistsError("technical admission is create-only and already exists")
    context = _capture_current_context(
        settings=settings,
        database=database,
        candidate=candidate,
        stage_a=stage_a,
        expected_integration_sha=expected_integration_sha,
    )
    details = _context_details(context)
    run_root = technical._expected_run_root(settings, capability.run_id)
    artifacts = _load_source_artifacts(run_root, admitted=False)
    references = _artifact_references(run_root, artifacts)
    _validate_source_run(
        artifacts=artifacts,
        references=references,
        run_id=capability.run_id,
        candidate_binding=candidate.safe_dict(),
        integration_sha=expected_integration_sha,
        context_details=details,
    )
    if artifacts["final-attestation.json"] != dict(capability.attestation):
        raise ValueError("technical capability differs from final run artifact")
    artifact_set_sha256 = sealed_sha256(
        {
            "schema": "legalbot.v111-technical-admission-artifact-set.v1",
            "members": references,
        }
    )
    rollback_policy = _rollback_policy_binding(details)
    identity = sealed_sha256(
        {
            "schema": "legalbot.v111-technical-admission-identity.v1",
            "run_id": capability.run_id,
            "candidate_build_id": candidate.build_id,
            "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
            "integration_sha": expected_integration_sha,
            "matrix_sha256": technical.FIXED_CHECK_MATRIX_SHA256,
            "final_attestation_seal_sha256": capability.seal_sha256,
            "artifact_set_sha256": artifact_set_sha256,
            "context_details_seal_sha256": details["seal_sha256"],
            "rollback_policy_binding_seal_sha256": rollback_policy["seal_sha256"],
        }
    )
    admission_id = f"v111-technical-admission:{identity}"
    relative_path = _safe_receipt_relative_path(settings, capability.run_id)
    object_key = f"v111-technical-admission:{identity}"
    receipt = sealed_safe_payload(
        {
            "schema": V111_TECHNICAL_ADMISSION_SCHEMA,
            "admission_id": admission_id,
            "runtime_object_key": object_key,
            "run_id": capability.run_id,
            "receipt_relative_path": relative_path,
            "candidate_build_id": candidate.build_id,
            "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
            "integration_sha": expected_integration_sha,
            "matrix_sha256": technical.FIXED_CHECK_MATRIX_SHA256,
            "final_attestation_seal_sha256": capability.seal_sha256,
            "run_manifest_seal_sha256": artifacts["run-manifest.json"]["seal_sha256"],
            "stage_a_attestation_seal_sha256": details["stage_a"]["seal_sha256"],
            "scorer_identity_sha256": details["stage_a"]["scorer_identity_sha256"],
            "stage_a_result_seal_sha256": details["stage_a"]["result_seal_sha256"],
            "completion_preflight_verified_result_sha256": details["stage_a"][
                "completion_preflight_verified_result_sha256"
            ],
            "rollback_plan_seal_sha256": details["rollback"]["seal_sha256"],
            "rollback_policy_binding": rollback_policy,
            "context_details": details,
            "artifact_members": references,
            "artifact_member_count": len(references),
            "artifact_set_sha256": artifact_set_sha256,
            "admission_source": "same_process_strict_loader_capability",
            "legacy_favorable_summaries_accepted": False,
            "writes_active": False,
            "writes_o04": False,
        }
    )
    receipt_bytes = safe_json_bytes(receipt)
    pending_metadata_json = json.dumps(_ledger_metadata(receipt, state="pending"), sort_keys=True)
    with database.transaction() as connection:
        conflicts = connection.execute(
            """
            SELECT * FROM runtime_objects
            WHERE namespace=? OR object_key=? OR relative_path=?
            """,
            (V111_TECHNICAL_ADMISSION_NAMESPACE, object_key, relative_path),
        ).fetchall()
        for row in conflicts:
            try:
                existing = json.loads(str(row["metadata_json"]))
            except json.JSONDecodeError as exc:
                raise RuntimeError("technical admission ledger metadata is invalid") from exc
            if (
                row["object_key"] == object_key
                or row["relative_path"] == relative_path
                or (
                    isinstance(existing, Mapping)
                    and existing.get("candidate_build_id") == candidate.build_id
                    and existing.get("integration_sha") == expected_integration_sha
                )
            ):
                raise FileExistsError("technical admission is create-only and already exists")
        connection.execute(
            """
            INSERT INTO runtime_objects(
              object_key,namespace,content_sha256,relative_path,byte_size,
              metadata_json,expires_at,created_at
            ) VALUES (?,?,?,?,?,?,NULL,?)
            """,
            (
                object_key,
                V111_TECHNICAL_ADMISSION_NAMESPACE,
                hashlib.sha256(receipt_bytes).hexdigest(),
                relative_path,
                len(receipt_bytes),
                pending_metadata_json,
                utc_iso(),
            ),
        )
    writer = CreateOnlyRunDirectory(
        root=settings.evaluation_dir / "v111-technical-attestations",
        run_id=capability.run_id,
        resume=True,
    )
    receipt_path = writer.write_json(V111_TECHNICAL_ADMISSION_FILENAME, receipt)
    if _private_file(receipt_path) != receipt_bytes:
        raise RuntimeError("technical admission receipt differs after create-only write")
    with database.transaction() as connection:
        pending = connection.execute(
            "SELECT * FROM runtime_objects WHERE object_key=?",
            (object_key,),
        ).fetchone()
        if pending is None or json.loads(str(pending["metadata_json"])) != _ledger_metadata(
            receipt, state="pending"
        ):
            raise RuntimeError("technical admission pending ledger row changed")
        connection.execute(
            "UPDATE runtime_objects SET metadata_json=? WHERE object_key=?",
            (json.dumps(_ledger_metadata(receipt), sort_keys=True), object_key),
        )
    return _replay_admission(
        receipt_path=receipt_path,
        settings=settings,
        database=database,
        candidate=candidate,
        stage_a=stage_a,
        expected_integration_sha=expected_integration_sha,
        phase="prepromotion",
    )


def _load_receipt(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _private_file(path)
    try:
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("technical admission receipt is invalid JSON") from exc
    if not isinstance(parsed, Mapping):
        raise ValueError("technical admission receipt is not an object")
    receipt = verify_sealed_artifact(parsed, schema=V111_TECHNICAL_ADMISSION_SCHEMA)
    expected_keys = {
        "schema",
        "admission_id",
        "runtime_object_key",
        "run_id",
        "receipt_relative_path",
        "candidate_build_id",
        "candidate_manifest_sha256",
        "integration_sha",
        "matrix_sha256",
        "final_attestation_seal_sha256",
        "run_manifest_seal_sha256",
        "stage_a_attestation_seal_sha256",
        "scorer_identity_sha256",
        "stage_a_result_seal_sha256",
        "completion_preflight_verified_result_sha256",
        "rollback_plan_seal_sha256",
        "rollback_policy_binding",
        "context_details",
        "artifact_members",
        "artifact_member_count",
        "artifact_set_sha256",
        "admission_source",
        "legacy_favorable_summaries_accepted",
        "writes_active",
        "writes_o04",
        "seal_sha256",
    }
    if set(receipt) != expected_keys:
        raise ValueError("technical admission receipt schema fields differ")
    return receipt, raw


def _verify_ledger(*, database: Database, receipt: Mapping[str, Any], receipt_bytes: bytes) -> None:
    row = database.fetchone(
        "SELECT * FROM runtime_objects WHERE object_key=?",
        (str(receipt["runtime_object_key"]),),
    )
    if row is None:
        raise ValueError("technical admission is not present in the trusted ledger")
    try:
        metadata = json.loads(str(row["metadata_json"]))
    except json.JSONDecodeError as exc:
        raise ValueError("technical admission ledger metadata is invalid") from exc
    if (
        row["namespace"] != V111_TECHNICAL_ADMISSION_NAMESPACE
        or row["content_sha256"] != hashlib.sha256(receipt_bytes).hexdigest()
        or row["relative_path"] != receipt["receipt_relative_path"]
        or row["byte_size"] != len(receipt_bytes)
        or row["expires_at"] is not None
        or metadata != _ledger_metadata(receipt)
    ):
        raise ValueError("technical admission ledger binding differs or is revoked")


def _immutable_candidate_binding(candidate: SealedCandidateIdentity) -> dict[str, Any]:
    value = candidate.safe_dict()
    value["candidate_status"] = "candidate"
    return value


def _postpromotion_transition(
    *,
    settings: Settings,
    database: Database,
    candidate: SealedCandidateIdentity,
    context_details: Mapping[str, Any],
) -> dict[str, Any]:
    if candidate.status != "active":
        raise ValueError(
            "technical admission post-promotion replay requires exact ACTIVE candidate"
        )
    active = technical._pointer_binding(settings, "active")
    previous = technical._pointer_binding(settings, "previous")
    pre_state = context_details["prepromotion_state"]
    pre_active = pre_state.get("active_pointer") if isinstance(pre_state, Mapping) else None
    rollback = context_details["rollback"]
    active_rows = database.fetchall("SELECT id FROM index_builds WHERE status='active' ORDER BY id")
    if (
        len(active_rows) != 1
        or str(active_rows[0]["id"]) != candidate.build_id
        or active.get("state") != "present"
        or active.get("build_id") != candidate.build_id
        or active.get("manifest_sha256") != candidate.candidate_manifest_sha256
    ):
        raise ValueError("technical admission ACTIVE transition is not reconciled")
    if not isinstance(pre_active, Mapping) or pre_active.get("state") != "present":
        raise RuntimeError(
            "OWNER_DECISION_REQUIRED:first_live_rollback_transition_contract_missing"
        )
    if (
        previous.get("state") != "present"
        or previous.get("build_id") != pre_active.get("build_id")
        or previous.get("manifest_sha256") != pre_active.get("manifest_sha256")
        or rollback.get("expected_previous_after_promotion_build_id") != previous.get("build_id")
        or rollback.get("expected_previous_after_promotion_manifest_sha256")
        != previous.get("manifest_sha256")
        or rollback.get("implementation") != technical._rollback_implementation_binding()
    ):
        raise ValueError("technical admission pre-to-post rollback transition differs")
    prior_row = database.fetchone(
        "SELECT status FROM index_builds WHERE id=?",
        (str(previous["build_id"]),),
    )
    if prior_row is None or str(prior_row["status"]) != "superseded":
        raise ValueError("technical admission prior rollback catalogue status differs")
    prior_candidate = load_sealed_candidate_identity(
        settings=settings,
        database=database,
        candidate_build_id=str(previous["build_id"]),
    )
    if (
        prior_candidate.status != "superseded"
        or prior_candidate.candidate_manifest_sha256 != previous["manifest_sha256"]
    ):
        raise ValueError("technical admission prior rollback candidate identity differs")
    return sealed_safe_payload(
        {
            "schema": "legalbot.v111-technical-admission-postpromotion-transition.v1",
            "admission_prepromotion_state_seal_sha256": pre_state["seal_sha256"],
            "active_build_id": candidate.build_id,
            "active_manifest_sha256": candidate.candidate_manifest_sha256,
            "active_pointer_sha256": active["pointer_sha256"],
            "previous_build_id": previous["build_id"],
            "previous_manifest_sha256": previous["manifest_sha256"],
            "previous_pointer_sha256": previous["pointer_sha256"],
            "rollback_plan_seal_sha256": rollback["seal_sha256"],
        }
    )


def _replay_admission(
    *,
    receipt_path: Path,
    settings: Settings,
    database: Database,
    candidate: SealedCandidateIdentity,
    stage_a: technical.StageAReplayInputs,
    expected_integration_sha: str,
    phase: Literal["prepromotion", "postpromotion"],
) -> AdmittedV111TechnicalAttestation:
    project_root = settings.project_root.resolve()
    resolved_receipt = receipt_path.resolve(strict=True)
    if (
        receipt_path.is_symlink()
        or not resolved_receipt.is_relative_to(project_root)
        or resolved_receipt.name != V111_TECHNICAL_ADMISSION_FILENAME
    ):
        raise ValueError("technical admission receipt path is unsafe")
    receipt, receipt_bytes = _load_receipt(resolved_receipt)
    run_id = str(receipt.get("run_id") or "")
    expected_receipt = technical._expected_run_root(settings, run_id) / (
        V111_TECHNICAL_ADMISSION_FILENAME
    )
    relative = resolved_receipt.relative_to(project_root).as_posix()
    if (
        resolved_receipt != expected_receipt
        or relative != receipt.get("receipt_relative_path")
        or not _SAFE_RUN_ID.fullmatch(run_id)
        or not _SAFE_RELATIVE.fullmatch(relative)
    ):
        raise ValueError("technical admission receipt location differs")
    _verify_ledger(database=database, receipt=receipt, receipt_bytes=receipt_bytes)
    if (
        receipt.get("candidate_build_id") != candidate.build_id
        or receipt.get("candidate_manifest_sha256") != candidate.candidate_manifest_sha256
        or receipt.get("integration_sha") != expected_integration_sha
        or receipt.get("matrix_sha256") != technical.FIXED_CHECK_MATRIX_SHA256
        or receipt.get("admission_source") != "same_process_strict_loader_capability"
        or receipt.get("legacy_favorable_summaries_accepted") is not False
        or receipt.get("writes_active") is not False
        or receipt.get("writes_o04") is not False
        or not _GIT_SHA.fullmatch(expected_integration_sha)
        or _clean_integration_sha(settings.project_root) != expected_integration_sha
    ):
        raise ValueError("technical admission current identity differs")
    context_details = receipt.get("context_details")
    rollback_policy = receipt.get("rollback_policy_binding")
    references = receipt.get("artifact_members")
    if (
        not isinstance(context_details, Mapping)
        or context_details.get("seal_sha256") != sealed_sha256(context_details)
        or not isinstance(rollback_policy, Mapping)
        or rollback_policy.get("seal_sha256") != sealed_sha256(rollback_policy)
        or rollback_policy.get("policy_sha256") != technical._first_live_rollback_policy_sha256()
        or not isinstance(references, list)
        or receipt.get("artifact_member_count") != _SOURCE_MEMBER_COUNT
        or receipt.get("artifact_set_sha256")
        != sealed_sha256(
            {
                "schema": "legalbot.v111-technical-admission-artifact-set.v1",
                "members": references,
            }
        )
    ):
        raise ValueError("technical admission context or artifact set differs")
    artifacts = _load_source_artifacts(resolved_receipt.parent, admitted=True)
    current_references = _artifact_references(resolved_receipt.parent, artifacts)
    if current_references != references:
        raise ValueError("technical admission source artifact bytes changed")
    pre_candidate = context_details.get("candidate")
    if not isinstance(pre_candidate, Mapping) or dict(
        pre_candidate
    ) != _immutable_candidate_binding(candidate):
        raise ValueError("technical admission immutable candidate binding differs")
    _validate_source_run(
        artifacts=artifacts,
        references=current_references,
        run_id=run_id,
        candidate_binding=pre_candidate,
        integration_sha=expected_integration_sha,
        context_details=context_details,
    )
    if (
        receipt.get("final_attestation_seal_sha256")
        != artifacts["final-attestation.json"]["seal_sha256"]
        or receipt.get("run_manifest_seal_sha256") != artifacts["run-manifest.json"]["seal_sha256"]
        or receipt.get("stage_a_attestation_seal_sha256")
        != artifacts["stage-a-scorer-reattestation.json"]["seal_sha256"]
        or receipt.get("rollback_plan_seal_sha256")
        != artifacts["rollback-plan-readiness.json"]["seal_sha256"]
        or receipt.get("scorer_identity_sha256") != STAGE_A_SCORER_IDENTITY_SHA256
        or receipt.get("scorer_identity_sha256")
        != artifacts["stage-a-scorer-reattestation.json"]["scorer_identity_sha256"]
        or receipt.get("stage_a_result_seal_sha256")
        != artifacts["stage-a-scorer-reattestation.json"]["result_seal_sha256"]
        or receipt.get("completion_preflight_verified_result_sha256")
        != stage_a.completion_preflight_verified_result_sha256
    ):
        raise ValueError("technical admission final, scorer, or Stage A binding differs")
    if phase == "prepromotion":
        if candidate.status != "candidate":
            raise ValueError("technical admission pre-promotion candidate status differs")
        current_context = _capture_current_context(
            settings=settings,
            database=database,
            candidate=candidate,
            stage_a=stage_a,
            expected_integration_sha=expected_integration_sha,
        )
        if _context_details(current_context) != context_details:
            raise ValueError("technical admission pre-promotion context changed")
        transition = sealed_safe_payload(
            {
                "schema": "legalbot.v111-technical-admission-promotion-ready.v1",
                "prepromotion_state_seal_sha256": context_details["prepromotion_state"][
                    "seal_sha256"
                ],
                "rollback_plan_seal_sha256": context_details["rollback"]["seal_sha256"],
            }
        )
    else:
        projected = replace(candidate, status="candidate")
        current_stage_a = technical._stage_a_binding(
            candidate=projected,
            stage_a=stage_a,
            integration_sha=expected_integration_sha,
        )
        scratch_parent = settings.evaluation_dir
        with tempfile.TemporaryDirectory(prefix=".technical-replay-", dir=scratch_parent) as raw:
            current_toolchain = technical._resolve_toolchain(
                settings.project_root, scratch_root=Path(raw)
            ).binding
        if (
            current_stage_a != context_details["stage_a"]
            or dict(current_toolchain) != context_details["toolchain"]
            or technical._lock_binding(settings.project_root) != context_details["lock_set"]
        ):
            raise ValueError("technical admission post-promotion immutable context changed")
        transition = _postpromotion_transition(
            settings=settings,
            database=database,
            candidate=candidate,
            context_details=context_details,
        )
    return AdmittedV111TechnicalAttestation(
        receipt_path=resolved_receipt,
        receipt=receipt,
        transition=transition,
        _token=_ADMISSION_TOKEN,
    )


def load_admitted_v111_technical_attestation(
    receipt_path: Path,
    *,
    settings: Settings,
    database: Database,
    candidate: SealedCandidateIdentity,
    stage_a: technical.StageAReplayInputs,
    expected_integration_sha: str,
    phase: Literal["prepromotion", "postpromotion"],
) -> AdmittedV111TechnicalAttestation:
    """Replay one persisted capability admission against current exact state."""

    reloaded = load_sealed_candidate_identity(
        settings=settings,
        database=database,
        candidate_build_id=candidate.build_id,
    )
    if reloaded != candidate:
        raise ValueError("technical admission candidate changed before persisted replay")
    return _replay_admission(
        receipt_path=receipt_path,
        settings=settings,
        database=database,
        candidate=candidate,
        stage_a=stage_a,
        expected_integration_sha=expected_integration_sha,
        phase=phase,
    )


__all__ = [
    "V111_TECHNICAL_ADMISSION_FILENAME",
    "V111_TECHNICAL_ADMISSION_SCHEMA",
    "AdmittedV111TechnicalAttestation",
    "admit_verified_v111_technical_attestation",
    "load_admitted_v111_technical_attestation",
    "require_admitted_v111_technical_attestation",
]
