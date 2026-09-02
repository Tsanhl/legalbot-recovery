"""Fail-closed admission of proved GE source gaps to official research.

The adapter deliberately stops at the existing :class:`ResearchControlPlane`.
It never performs network work and has no source-intake, catalogue, embedding,
training, index-pointer, unseen-test, or deletion capability.

``ResearchTaskRequest.staging_only`` is intentionally left ``False``.  In the
control plane that flag describes a legacy, non-dispatchable ``staging_sync``
record and skips the exact open-gap pin.  A real GE gap must instead be pinned
to its sealed candidate and queued for the research worker.  Staging safety is
provided by the registered source's ``staged_only`` disposition and by the
downstream quarantine/review boundary; it is reported explicitly in the
result below.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path
from typing import Any, Literal, NoReturn

from ..contracts import canonical_json_bytes, load_json_strict, seal_contract
from ..research.control_plane import ResearchControlPlane
from ..research.models import (
    GapMateriality,
    ResearchGapBindingRequest,
    ResearchPriority,
    ResearchTaskRequest,
    ResearchTaskType,
    ResearchTrigger,
)
from ..research.retrieval_attempt import (
    RetrievalAttemptBinding,
    load_verified_candidate_retrieval_attempt,
    opaque_gap_reference,
)
from ..research.source_intake_bridge import StagedSourceIntake
from ..research.source_registry import ContentMode, OnlineDisposition
from .ge_improvement_loop import build_official_research_intent
from .secure_artifact_io import open_directory_at, read_file_at

SUPPORTED_GE_DISCOVERY_SOURCE = "legislation_gov_uk"
ADAPTER_REQUIRED_HOLD = "OFFICIAL_DISCOVERY_ADAPTER_REQUIRED"
GE_SOURCE_PROVENANCE_SCHEMA = "legalbot.ge-source-provenance-chain.v1"
GE_SOURCE_PROVENANCE_COMPONENT_SCHEMA = (
    "legalbot.ge-source-provenance-component-receipt.v1"
)

_COMPONENT_ARTIFACT_PARTS = ("research", "ge-source-provenance-components")
_MAX_COMPONENT_ARTIFACT_BYTES = 2 * 1024 * 1024
_NOFOLLOW = int(getattr(os, "O_NOFOLLOW", 0))
_CLOEXEC = int(getattr(os, "O_CLOEXEC", 0))

_INTAKE_SUFFIXES: Mapping[str, str] = {
    "application/akn+xml": ".xml",
    "application/json": ".json",
    "application/ld+json": ".json",
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/xhtml+xml": ".html",
    "application/xml": ".xml",
    "text/html": ".html",
    "text/plain": ".txt",
    "text/xml": ".xml",
}


class GEOfficialResearchControlError(ValueError):
    """A proved GE gap cannot safely enter official research."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


@dataclass(frozen=True, slots=True)
class GEOfficialResearchHold:
    """Stable, write-free hold for a registered source without a dispatcher."""

    source_id: str
    candidate_build_id: str
    intent_sha256: str
    status: Literal["HOLD"] = "HOLD"
    hold_code: Literal["OFFICIAL_DISCOVERY_ADAPTER_REQUIRED"] = (
        "OFFICIAL_DISCOVERY_ADAPTER_REQUIRED"
    )
    research_gap_created: Literal[False] = False
    research_task_created: Literal[False] = False
    network_action_performed: Literal[False] = False
    source_admission_authorized: Literal[False] = False
    promotion_authorized: Literal[False] = False


@dataclass(frozen=True, slots=True)
class GEOfficialResearchAdmission:
    """Safe identity of an idempotently logged and admitted research task."""

    gap_id: str
    task_id: str
    task_status: str
    source_id: Literal["legislation_gov_uk"]
    candidate_build_id: str
    source_manifest_sha256: str
    query_sha256: str
    retrieval_attempt_artifact_sha256: str
    intent_sha256: str
    status: Literal["ADMITTED"] = "ADMITTED"
    staging_only: Literal[True] = True
    feeds_current_answer: Literal[False] = False
    network_action_performed: Literal[False] = False
    owner_source_intake_review_required: Literal[True] = True
    rights_review_required: Literal[True] = True
    currentness_review_required: Literal[True] = True
    source_admission_authorized: Literal[False] = False
    successor_candidate_state: Literal["NON_ACTIVE"] = "NON_ACTIVE"
    promotion_authorized: Literal[False] = False


def _fail(code: str, detail: str) -> NoReturn:
    raise GEOfficialResearchControlError(code, detail)


def _exact_replayed_intent(
    *,
    diagnosis: Mapping[str, Any],
    diagnosed_result: Mapping[str, Any],
    sealed_intent: Mapping[str, Any],
    candidate_build_id: str,
) -> dict[str, Any]:
    try:
        expected = build_official_research_intent(
            diagnosis=diagnosis,
            diagnosed_result=diagnosed_result,
            candidate_build_id=candidate_build_id,
        )
    except (KeyError, TypeError, ValueError) as exc:
        _fail("GE_RESEARCH_EVIDENCE_INVALID", str(exc))
    if canonical_json_bytes(expected) != canonical_json_bytes(sealed_intent):
        _fail(
            "GE_RESEARCH_INTENT_REPLAY_MISMATCH",
            "sealed intent differs from the deterministic diagnosis/result replay",
        )
    if diagnosis.get("materiality") != GapMateriality.MATERIAL.value:
        _fail(
            "GE_RESEARCH_GAP_NOT_MATERIAL",
            "only an evidence-backed material gap may enter connected research",
        )
    # These are execution gates, not claims of later source approval.  Replaying
    # the builder already checks them indirectly; spelling them out makes this
    # boundary robust if a future builder accidentally weakens its envelope.
    required_gates = {
        "task_type": ResearchTaskType.GAP_RESEARCH.value,
        "source_scope": "OFFICIAL_SOURCES_ONLY",
        "effect": "RESEARCH_CONTROL_PLANE_INTAKE_ONLY",
        "network_action_performed": False,
        "source_admission_authorized": False,
        "successor_candidate_state": "NON_ACTIVE",
        "promotion_authorized": False,
    }
    if any(expected.get(key) != value for key, value in required_gates.items()):
        _fail("GE_RESEARCH_GATE_MISSING", "research intent safety gates are incomplete")
    return expected


def _registered_discovery_policy(
    *, control_plane: ResearchControlPlane, source_id: str, intent: Mapping[str, Any]
) -> GEOfficialResearchHold | None:
    try:
        policy = control_plane.registry.get(source_id)
    except KeyError:
        _fail("GE_RESEARCH_SOURCE_NOT_REGISTERED", "official discovery source is unregistered")

    if policy.authority_tier != "primary_law":
        _fail(
            "GE_RESEARCH_PRIMARY_AUTHORITY_REQUIRED",
            "scholarship, teaching, guidance, and procedure are not independent authority",
        )
    if policy.online_disposition is not OnlineDisposition.STAGED_ONLY:
        _fail("GE_RESEARCH_STAGING_GATE_MISSING", "source is not registered staging-only")
    if (
        policy.additional_permission_required
        or not policy.licence.name.strip()
        or not (policy.licence.url or "").startswith("https://")
    ):
        _fail(
            "GE_RESEARCH_RIGHTS_OWNER_DECISION_REQUIRED",
            "registered discovery rights remain ambiguous or need added permission",
        )
    if not policy.currentness.strip():
        _fail(
            "GE_RESEARCH_CURRENTNESS_OWNER_DECISION_REQUIRED",
            "registered source has no explicit currentness verification rule",
        )
    if source_id != SUPPORTED_GE_DISCOVERY_SOURCE:
        return GEOfficialResearchHold(
            source_id=source_id,
            candidate_build_id=str(intent["candidate_build_id"]),
            intent_sha256=str(intent["content_sha256"]),
        )
    if policy.content_mode is not ContentMode.FULL_TEXT:
        _fail(
            "GE_RESEARCH_RIGHTS_OWNER_DECISION_REQUIRED",
            "connected legislation discovery is not registered for staged full text",
        )
    return None


def _encrypted_gap_detail(
    *, diagnosis: Mapping[str, Any], intent: Mapping[str, Any]
) -> str:
    """Return deterministic digest-only detail; never a raw user question."""

    payload = {
        "schema": "legalbot.ge-research-gap-detail.v1",
        "diagnosis_id": diagnosis["diagnosis_id"],
        "failure_class": diagnosis["failure_class"],
        "failure_code": diagnosis["failure_code"],
        "failure_fingerprint_sha256": diagnosis["failure_fingerprint_sha256"],
        "finding_sha256": diagnosis["finding_sha256"],
        "result_sha256": diagnosis["result_sha256"],
        "intent_sha256": intent["content_sha256"],
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def admit_ge_official_research(
    *,
    control_plane: ResearchControlPlane,
    diagnosis: Mapping[str, Any],
    diagnosed_result: Mapping[str, Any],
    sealed_intent: Mapping[str, Any],
    candidate_build_id: str,
    source_id: str,
) -> GEOfficialResearchAdmission | GEOfficialResearchHold:
    """Log and enqueue one exact material GE gap, or return a write-free hold.

    All durable writes are delegated to ``ResearchControlPlane``.  Its sealed
    candidate loader and retrieval-attempt verifier bind the query, proposition,
    case, issue, jurisdiction, date, source manifest, and candidate bytes.
    """

    if control_plane.cipher is None:
        _fail(
            "GE_RESEARCH_ENCRYPTED_GAP_GATE_MISSING",
            "ResearchControlPlane has no encrypted gap-storage capability",
        )
    intent = _exact_replayed_intent(
        diagnosis=diagnosis,
        diagnosed_result=diagnosed_result,
        sealed_intent=sealed_intent,
        candidate_build_id=candidate_build_id,
    )
    hold = _registered_discovery_policy(
        control_plane=control_plane, source_id=source_id, intent=intent
    )
    if hold is not None:
        return hold

    try:
        as_of_date = date.fromisoformat(str(intent["as_of_date"]))
        gap = control_plane.log_knowledge_gap(
            ResearchGapBindingRequest(
                candidate_build_id=candidate_build_id,
                case_id=str(intent["case_id"]),
                issue_id=str(intent["issue_id"]),
                subject=str(intent["subject"]),
                jurisdiction=str(intent["jurisdiction"]),
                as_of_date=as_of_date,
                retrieval_query_sha256=str(intent["retrieval_query_sha256"]),
                proposition_sha256=str(intent["proposition_sha256"]),
                retrieval_attempt_artifact_sha256=str(
                    intent["retrieval_attempt_artifact_sha256"]
                ),
                materiality=GapMateriality.MATERIAL,
                detail=_encrypted_gap_detail(diagnosis=diagnosis, intent=intent),
            )
        )
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        _fail("GE_RESEARCH_GAP_ADMISSION_FAILED", str(exc))

    gap_id = str(gap["id"])
    try:
        task = control_plane.admit(
            ResearchTaskRequest(
                task_type=ResearchTaskType.GAP_RESEARCH,
                trigger=ResearchTrigger.ENQUIRY,
                priority=ResearchPriority.HIGH,
                subject=str(intent["subject"]),
                jurisdiction=str(intent["jurisdiction"]),
                as_of_date=as_of_date,
                source_id=SUPPORTED_GE_DISCOVERY_SOURCE,
                knowledge_gap_id=gap_id,
                public_query=None,
                query_sha256=str(intent["retrieval_query_sha256"]),
                staging_only=False,
            )
        )
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        _fail("GE_RESEARCH_TASK_ADMISSION_FAILED", str(exc))

    expected_gap = {
        "candidate_build_id": candidate_build_id,
        "case_id": opaque_gap_reference("case", str(intent["case_id"])),
        "issue_id": opaque_gap_reference("issue", str(intent["issue_id"])),
        "subject": " ".join(str(intent["subject"]).split()).casefold(),
        "jurisdiction": " ".join(str(intent["jurisdiction"]).split()),
        "as_of_date": as_of_date.isoformat(),
        "attempted_retrieval_sha256": str(intent["retrieval_attempt_artifact_sha256"]),
        "materiality": GapMateriality.MATERIAL.value,
    }
    if any(str(gap[key]) != value for key, value in expected_gap.items()):
        _fail("GE_RESEARCH_GAP_BINDING_DIFFERED", "persisted gap identity differs")
    source_manifest_sha256 = str(gap["source_manifest_sha256"])
    expected_task: dict[str, Any] = {
        "task_type": ResearchTaskType.GAP_RESEARCH.value,
        "trigger_kind": ResearchTrigger.ENQUIRY.value,
        "priority_band": ResearchPriority.HIGH.value,
        "subject": expected_gap["subject"],
        "jurisdiction": expected_gap["jurisdiction"],
        "as_of_date": expected_gap["as_of_date"],
        "source_id": SUPPORTED_GE_DISCOVERY_SOURCE,
        "knowledge_gap_id": gap_id,
        "query_sha256": str(intent["retrieval_query_sha256"]),
        "pinned_index_build_id": candidate_build_id,
        "source_manifest_sha256": source_manifest_sha256,
        "encrypted_query": None,
        "authority_identity_id": None,
        "source_locator": None,
        "answer_id": None,
        "answer_job_id": None,
        "refinement_id": None,
    }
    if any(task[key] != value for key, value in expected_task.items()):
        _fail("GE_RESEARCH_TASK_BINDING_DIFFERED", "persisted task identity differs")
    task_status = str(task["status"])
    if task_status not in {"queued", "deferred_capacity"}:
        _fail("GE_RESEARCH_TASK_NOT_QUEUED", "admitted task is not dispatchable")

    return GEOfficialResearchAdmission(
        gap_id=gap_id,
        task_id=str(task["id"]),
        task_status=task_status,
        source_id="legislation_gov_uk",
        candidate_build_id=candidate_build_id,
        source_manifest_sha256=source_manifest_sha256,
        query_sha256=str(intent["retrieval_query_sha256"]),
        retrieval_attempt_artifact_sha256=str(
            intent["retrieval_attempt_artifact_sha256"]
        ),
        intent_sha256=str(intent["content_sha256"]),
    )


def _verified_contract_sha256(value: Mapping[str, Any], *, label: str) -> str:
    claimed = str(value.get("content_sha256") or "")
    material = dict(value)
    material.pop("content_sha256", None)
    actual = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    if claimed != actual:
        _fail("GE_SOURCE_CHAIN_OBJECT_REPLAY_FAILED", f"{label} digest differs")
    return actual


def _stored_value(value: Any) -> Any:
    if isinstance(value, bytes | bytearray | memoryview):
        content = bytes(value)
        return {
            "type": "bytes",
            "length": len(content),
            "base64": base64.b64encode(content).decode("ascii"),
        }
    if value is None or isinstance(value, bool | str | int | float):
        return value
    _fail(
        "GE_SOURCE_CHAIN_RECORD_TYPE_INVALID",
        f"stored record contains unsupported {type(value).__name__} value",
    )


def _stored_record_snapshot(row: Any, *, table: str) -> dict[str, Any]:
    """Capture every stored column and exact BLOB byte for immutable replay."""

    return {
        "schema": "legalbot.exact-stored-record.v1",
        "table": table,
        # sqlite3.Row iteration yields values; ``keys()`` is required here.
        "fields": {
            str(key): _stored_value(row[key]) for key in row.keys()  # noqa: SIM118
        },
    }


def _stored_record_sha256(row: Any, *, table: str) -> str:
    """Digest the complete exact stored record snapshot."""

    return hashlib.sha256(
        canonical_json_bytes(_stored_record_snapshot(row, table=table))
    ).hexdigest()


def _component_artifact_root(*, control_plane: ResearchControlPlane, create: bool) -> Path:
    root = control_plane.settings.evaluation_dir
    if create:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root.chmod(0o700)
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise GEOfficialResearchControlError(
            "GE_SOURCE_CHAIN_COMPONENT_STORE_MISSING",
            "component receipt root is missing",
        ) from exc
    if not stat.S_ISDIR(root_stat.st_mode) or root.is_symlink():
        _fail(
            "GE_SOURCE_CHAIN_COMPONENT_STORE_INVALID",
            "component receipt root is unsafe",
        )
    return root


def _write_component_artifact(
    *, control_plane: ResearchControlPlane, component_receipt: Mapping[str, Any]
) -> str:
    payload = canonical_json_bytes(component_receipt)
    if not payload or len(payload) > _MAX_COMPONENT_ARTIFACT_BYTES:
        _fail(
            "GE_SOURCE_CHAIN_COMPONENT_ARTIFACT_INVALID",
            "component receipt size is invalid",
        )
    artifact_sha256 = hashlib.sha256(payload).hexdigest()
    name = f"{artifact_sha256}.json"
    root = _component_artifact_root(control_plane=control_plane, create=True)
    try:
        with open_directory_at(
            root, _COMPONENT_ARTIFACT_PARTS, create=True, private_mode=0o700
        ) as directory_fd:
            try:
                descriptor = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
                    0o600,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                stored = read_file_at(directory_fd, name, required_mode=0o600)
                if stored != payload:
                    _fail(
                        "GE_SOURCE_CHAIN_COMPONENT_ARTIFACT_COLLISION",
                        "existing component receipt bytes differ",
                    )
                return artifact_sha256
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short component receipt write")
                    view = view[written:]
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
            finally:
                # A partial create-only artifact is deliberately retained for
                # diagnosis; this path never unlinks evidence.
                os.close(descriptor)
            os.fsync(directory_fd)
    except GEOfficialResearchControlError:
        raise
    except (OSError, ValueError) as exc:
        raise GEOfficialResearchControlError(
            "GE_SOURCE_CHAIN_COMPONENT_ARTIFACT_WRITE_FAILED",
            "component receipt could not be stored create-only",
        ) from exc
    return artifact_sha256


def load_ge_source_provenance_components(
    *, control_plane: ResearchControlPlane, artifact_sha256: str
) -> dict[str, Any]:
    """Load and self-verify the exact private component receipt artifact."""

    if len(artifact_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in artifact_sha256
    ):
        _fail(
            "GE_SOURCE_CHAIN_COMPONENT_ARTIFACT_INVALID",
            "component receipt digest is invalid",
        )
    root = _component_artifact_root(control_plane=control_plane, create=False)
    try:
        with open_directory_at(root, _COMPONENT_ARTIFACT_PARTS) as directory_fd:
            raw = read_file_at(
                directory_fd,
                f"{artifact_sha256}.json",
                required_mode=0o600,
            )
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise GEOfficialResearchControlError(
            "GE_SOURCE_CHAIN_COMPONENT_ARTIFACT_MISSING",
            "component receipt artifact is missing or unsafe",
        ) from exc
    if (
        not raw
        or len(raw) > _MAX_COMPONENT_ARTIFACT_BYTES
        or hashlib.sha256(raw).hexdigest() != artifact_sha256
    ):
        _fail(
            "GE_SOURCE_CHAIN_COMPONENT_ARTIFACT_DIGEST_DIFFERED",
            "component receipt artifact bytes differ",
        )
    try:
        decoded = load_json_strict(raw)
    except (TypeError, ValueError) as exc:
        raise GEOfficialResearchControlError(
            "GE_SOURCE_CHAIN_COMPONENT_ARTIFACT_INVALID",
            "component receipt JSON is invalid",
        ) from exc
    if not isinstance(decoded, dict):
        _fail(
            "GE_SOURCE_CHAIN_COMPONENT_ARTIFACT_INVALID",
            "component receipt is not an object",
        )
    receipt = dict(decoded)
    _verified_contract_sha256(receipt, label="component receipt")
    if receipt.get("schema") != GE_SOURCE_PROVENANCE_COMPONENT_SCHEMA:
        _fail(
            "GE_SOURCE_CHAIN_COMPONENT_ARTIFACT_INVALID",
            "component receipt schema differs",
        )
    return receipt


def _compact_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def _json_mapping(value: Any, *, code: str) -> dict[str, Any]:
    try:
        result = json.loads(str(value))
    except (TypeError, json.JSONDecodeError) as exc:
        raise GEOfficialResearchControlError(code, "stored JSON is invalid") from exc
    if not isinstance(result, dict) or not all(isinstance(key, str) for key in result):
        _fail(code, "stored JSON is not an object")
    return dict(result)


def _require_review(
    row: Any,
    *,
    review_type: str,
    target_id: str,
    status: str,
    decided: bool,
    label: str,
) -> str:
    if (
        row is None
        or str(row["review_type"]) != review_type
        or str(row["target_id"]) != target_id
        or str(row["status"]) != status
        or (row["decided_at"] is not None) is not decided
    ):
        _fail("GE_SOURCE_CHAIN_REVIEW_REPLAY_FAILED", f"{label} review differs")
    return _stored_record_sha256(row, table="reviews")


def _verify_exact_vault_object(
    *, control_plane: ResearchControlPlane, relative_path: Any, content_sha256: str
) -> int:
    relative = Path(str(relative_path or ""))
    if not relative.parts or relative.is_absolute() or ".." in relative.parts:
        _fail("GE_SOURCE_CHAIN_SOURCE_OBJECT_INVALID", "vault object path is unsafe")
    try:
        project_root = control_plane.settings.project_root.resolve(strict=True)
        vault_root = control_plane.settings.vault_dir.resolve(strict=True)
        target = (project_root / relative).resolve(strict=True)
    except OSError as exc:
        raise GEOfficialResearchControlError(
            "GE_SOURCE_CHAIN_SOURCE_OBJECT_MISSING", "vault object is missing"
        ) from exc
    if (
        not target.is_relative_to(vault_root)
        or target.is_symlink()
        or not target.is_file()
    ):
        _fail("GE_SOURCE_CHAIN_SOURCE_OBJECT_INVALID", "vault object is outside custody")
    digest = hashlib.sha256()
    try:
        with target.open("rb") as handle:
            while block := handle.read(1024 * 1024):
                digest.update(block)
    except OSError as exc:
        raise GEOfficialResearchControlError(
            "GE_SOURCE_CHAIN_SOURCE_OBJECT_MISSING", "vault object cannot be read"
        ) from exc
    if digest.hexdigest() != content_sha256:
        _fail("GE_SOURCE_CHAIN_SOURCE_OBJECT_DIGEST_DIFFERED", "vault bytes differ")
    return target.stat().st_size


def _verified_source_end(
    *,
    control_plane: ResearchControlPlane,
    admission: GEOfficialResearchAdmission,
    receipt: StagedSourceIntake,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    database = control_plane.database
    receipt_payload = asdict(receipt)
    receipt_sha256 = hashlib.sha256(canonical_json_bytes(receipt_payload)).hexdigest()
    if (
        receipt.schema != "legalbot.research-source-intake-bridge.v1"
        or receipt.task_id != admission.task_id
        or receipt.source_id != admission.source_id
        or receipt.source_review_status != "pending"
        or receipt.source_version_review_status != "staged"
        or receipt.currentness_status != "unknown"
        or receipt.materialization_state not in {"created", "existing_verified"}
        or not receipt.ingestion_status
        or receipt.writes_index
        or receipt.writes_active
        or receipt.approves_source
        or receipt.enqueues_embedding
        or receipt.trains_model
    ):
        _fail("GE_SOURCE_CHAIN_RECEIPT_REPLAY_FAILED", "source-intake receipt is invalid")

    candidate = database.fetchone(
        "SELECT * FROM research_candidates WHERE id=?", (receipt.candidate_id,)
    )
    if candidate is None:
        _fail("GE_SOURCE_CHAIN_CANDIDATE_MISSING", "research candidate is missing")
    if (
        str(candidate["task_id"]) != admission.task_id
        or str(candidate["source_id"]) != admission.source_id
        or str(candidate["content_sha256"] or "") != receipt.content_sha256
        or str(candidate["status"]) != "source_intake_pending"
        or str(candidate["system_verification_sha256"] or "")
        != receipt.system_verification_sha256
        or str(candidate["review_id"] or "") != receipt.owner_review_id
        or str(candidate["review_manifest_sha256"] or "")
        != receipt.owner_review_manifest_sha256
        or str(candidate["rights_state"]) != receipt.rights_state
        or str(candidate["intake_review_id"] or "") != receipt.pending_intake_review_id
        or str(candidate["identity_review_state"]) != "candidate_matched"
        or str(candidate["currentness_review_state"])
        not in {"verified", "not_applicable"}
    ):
        _fail("GE_SOURCE_CHAIN_CANDIDATE_REPLAY_FAILED", "candidate record differs")
    safe_metadata = _json_mapping(
        candidate["safe_metadata_json"], code="GE_SOURCE_CHAIN_CANDIDATE_REPLAY_FAILED"
    )
    content_type = str(safe_metadata.get("content_type") or "").casefold()
    suffix = _INTAKE_SUFFIXES.get(content_type)
    if (
        suffix is None
        or safe_metadata.get("disposition") != "staged_only"
        or safe_metadata.get("owner_decision_required") is not True
        or safe_metadata.get("response_sha256") != receipt.content_sha256
    ):
        _fail("GE_SOURCE_CHAIN_CANDIDATE_REPLAY_FAILED", "candidate metadata differs")

    binding = {
        "schema": receipt.schema,
        "candidate_id": receipt.candidate_id,
        "task_id": receipt.task_id,
        "source_id": receipt.source_id,
        "source_identity": str(candidate["source_identity"]),
        "content_sha256": receipt.content_sha256,
        "metadata_sha256": str(candidate["metadata_sha256"]),
        "content_object_key": str(candidate["content_object_key"]),
        "system_verification_sha256": receipt.system_verification_sha256,
        "owner_review_id": receipt.owner_review_id,
        "owner_review_manifest_sha256": receipt.owner_review_manifest_sha256,
        "rights_state": receipt.rights_state,
        "pending_intake_review_id": receipt.pending_intake_review_id,
    }
    if _compact_sha256(binding) != receipt.binding_sha256:
        _fail("GE_SOURCE_CHAIN_RECEIPT_REPLAY_FAILED", "intake binding digest differs")
    if (
        receipt.intake_id != f"source-intake-{receipt.binding_sha256[:40]}"
        or receipt.scan_id != f"research-intake-{receipt.binding_sha256[:40]}"
        or receipt.opaque_relative_path
        != (
            "official-research-intake/legislation/"
            f"official-{receipt.binding_sha256[:32]}-{receipt.content_sha256[:16]}{suffix}"
        )
    ):
        _fail("GE_SOURCE_CHAIN_RECEIPT_REPLAY_FAILED", "intake identity differs")

    expected_marker = {
        "schema": receipt.schema,
        "intake_id": receipt.intake_id,
        "binding_sha256": receipt.binding_sha256,
        "candidate_id": receipt.candidate_id,
        "task_id": receipt.task_id,
        "source_id": receipt.source_id,
        "content_sha256": receipt.content_sha256,
        "system_verification_sha256": receipt.system_verification_sha256,
        "owner_review_id": receipt.owner_review_id,
        "owner_review_manifest_sha256": receipt.owner_review_manifest_sha256,
        "rights_state": receipt.rights_state,
        "pending_intake_review_id": receipt.pending_intake_review_id,
    }
    source_version = database.fetchone(
        "SELECT * FROM source_versions WHERE id=?", (receipt.source_version_id,)
    )
    if source_version is None:
        _fail("GE_SOURCE_CHAIN_SOURCE_VERSION_MISSING", "source version is missing")
    metadata = _json_mapping(
        source_version["metadata_json"], code="GE_SOURCE_CHAIN_SOURCE_VERSION_REPLAY_FAILED"
    )
    marker = metadata.get("research_source_intake")
    if (
        not isinstance(marker, dict)
        or marker != expected_marker
        or receipt.provenance_marker_schema != marker.get("schema")
        or str(source_version["version_sha256"]) != receipt.content_sha256
        or str(source_version["review_status"]) != "staged"
        or str(source_version["currentness_status"]) != "unknown"
        or source_version["superseded_by"] is not None
        or metadata.get("scan_id") != receipt.scan_id
        or metadata.get("raw_object_sha256") != receipt.content_sha256
        or metadata.get("identity_verified") is not False
        or metadata.get("currentness_verified") is not False
        or metadata.get("authority_eligible") is not False
        or metadata.get("citation_rendering_enabled") is not False
        or metadata.get("official_source_identity_sha256")
        != hashlib.sha256(str(candidate["source_identity"]).encode()).hexdigest()
        or metadata.get("official_canonical_url_sha256")
        != hashlib.sha256(str(candidate["canonical_url"]).encode()).hexdigest()
    ):
        _fail("GE_SOURCE_CHAIN_SOURCE_VERSION_REPLAY_FAILED", "source marker differs")
    vault_byte_size = _verify_exact_vault_object(
        control_plane=control_plane,
        relative_path=metadata.get("raw_vault_path"),
        content_sha256=receipt.content_sha256,
    )

    document = database.fetchone(
        "SELECT * FROM documents WHERE id=?", (str(source_version["document_id"]),)
    )
    if (
        document is None
        or str(document["content_sha256"]) != receipt.content_sha256
        or str(document["lane"]) not in {"primary_authority", "official_secondary"}
    ):
        _fail("GE_SOURCE_CHAIN_DOCUMENT_REPLAY_FAILED", "source document differs")
    chunks = database.fetchall(
        "SELECT * FROM chunks WHERE source_version_id=? ORDER BY ordinal, id",
        (receipt.source_version_id,),
    )
    if not chunks:
        _fail("GE_SOURCE_CHAIN_CHUNKS_MISSING", "source version has no chunks")
    chunk_set_sha256 = hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "legalbot.ge-source-chunk-set.v1",
                "source_version_id": receipt.source_version_id,
                "chunk_record_sha256s": [
                    _stored_record_sha256(row, table="chunks") for row in chunks
                ],
            }
        )
    ).hexdigest()

    system_review_id = f"review-research-system-{receipt.candidate_id}"
    system_review = database.fetchone("SELECT * FROM reviews WHERE id=?", (system_review_id,))
    if (
        system_review is None
        or str(system_review["reason"] or "")
        != f"Deterministic candidate envelope {receipt.system_verification_sha256}"
    ):
        _fail("GE_SOURCE_CHAIN_REVIEW_REPLAY_FAILED", "system review reason differs")
    system_review_sha256 = _require_review(
        system_review,
        review_type="research_candidate_system_verification",
        target_id=receipt.candidate_id,
        status="approved",
        decided=True,
        label="candidate system",
    )
    owner_review = database.fetchone(
        "SELECT * FROM reviews WHERE id=?", (receipt.owner_review_id,)
    )
    if (
        owner_review is None
        or str(owner_review["reason"] or "")
        != f"Explicit reviewed manifest {receipt.owner_review_manifest_sha256}"
    ):
        _fail("GE_SOURCE_CHAIN_REVIEW_REPLAY_FAILED", "owner review reason differs")
    owner_review_sha256 = _require_review(
        owner_review,
        review_type="official_research_candidate",
        target_id=receipt.candidate_id,
        status="approved",
        decided=True,
        label="candidate owner",
    )
    intake_review = database.fetchone(
        "SELECT * FROM reviews WHERE id=?", (receipt.pending_intake_review_id,)
    )
    intake_review_sha256 = _require_review(
        intake_review,
        review_type="research_source_intake",
        target_id=receipt.candidate_id,
        status="pending",
        decided=False,
        label="source intake",
    )
    source_review = database.fetchone(
        "SELECT * FROM reviews WHERE id=?", (receipt.source_review_id,)
    )
    source_review_sha256 = _require_review(
        source_review,
        review_type="source_version",
        target_id=receipt.source_version_id,
        status="pending",
        decided=False,
        label="source version",
    )
    source_end = {
        "source_intake_receipt_sha256": receipt_sha256,
        "research_candidate_record_sha256": _stored_record_sha256(
            candidate, table="research_candidates"
        ),
        "candidate_system_review_record_sha256": system_review_sha256,
        "candidate_owner_review_record_sha256": owner_review_sha256,
        "pending_intake_review_record_sha256": intake_review_sha256,
        "source_version_record_sha256": _stored_record_sha256(
            source_version, table="source_versions"
        ),
        "source_document_record_sha256": _stored_record_sha256(
            document, table="documents"
        ),
        "source_review_record_sha256": source_review_sha256,
        "source_provenance_marker_sha256": hashlib.sha256(
            canonical_json_bytes(marker)
        ).hexdigest(),
        "source_object_sha256": receipt.content_sha256,
        "source_chunk_set_sha256": chunk_set_sha256,
        "source_chunk_count": len(chunks),
    }
    record_snapshots = {
        "research_candidate": _stored_record_snapshot(
            candidate, table="research_candidates"
        ),
        "candidate_system_review": _stored_record_snapshot(
            system_review, table="reviews"
        ),
        "candidate_owner_review": _stored_record_snapshot(
            owner_review, table="reviews"
        ),
        "pending_intake_review": _stored_record_snapshot(
            intake_review, table="reviews"
        ),
        "staged_source_version": _stored_record_snapshot(
            source_version, table="source_versions"
        ),
        "staged_source_document": _stored_record_snapshot(
            document, table="documents"
        ),
        "pending_source_review": _stored_record_snapshot(
            source_review, table="reviews"
        ),
        "staged_source_chunks": [
            _stored_record_snapshot(row, table="chunks") for row in chunks
        ],
    }
    vault_binding = {
        "relative_path": str(metadata.get("raw_vault_path") or ""),
        "content_sha256": receipt.content_sha256,
        "byte_size": vault_byte_size,
    }
    return source_end, record_snapshots, vault_binding


def build_verified_ge_source_provenance(
    *,
    control_plane: ResearchControlPlane,
    diagnosis: Mapping[str, Any],
    diagnosed_result: Mapping[str, Any],
    sealed_intent: Mapping[str, Any],
    research_admission: GEOfficialResearchAdmission,
    source_intake_receipt: StagedSourceIntake,
) -> dict[str, Any]:
    """Bind both replayed GE evidence and the exact staged source end.

    The returned receipt remains pending source admission/currentness review.
    A digest-shaped input is never treated as evidence: this function reloads
    all control-plane rows, the sealed retrieval-attempt object, all intake
    reviews, the source-version marker, chunks, and the exact vault bytes.
    """

    intent = _exact_replayed_intent(
        diagnosis=diagnosis,
        diagnosed_result=diagnosed_result,
        sealed_intent=sealed_intent,
        candidate_build_id=research_admission.candidate_build_id,
    )
    diagnosis_sha256 = _verified_contract_sha256(diagnosis, label="diagnosis")
    result_sha256 = _verified_contract_sha256(diagnosed_result, label="diagnosed result")
    intent_sha256 = _verified_contract_sha256(intent, label="research intent")
    if (
        diagnosis.get("materiality") != "material"
        or research_admission.intent_sha256 != intent_sha256
        or research_admission.query_sha256 != intent.get("retrieval_query_sha256")
        or research_admission.retrieval_attempt_artifact_sha256
        != intent.get("retrieval_attempt_artifact_sha256")
        or research_admission.source_id != SUPPORTED_GE_DISCOVERY_SOURCE
        or research_admission.source_admission_authorized
        or research_admission.promotion_authorized
    ):
        _fail("GE_SOURCE_CHAIN_ADMISSION_REPLAY_FAILED", "research admission differs")

    database = control_plane.database
    gap = database.research_gap_binding(research_admission.gap_id)
    task = database.research_task(research_admission.task_id)
    candidate_index_build = database.fetchone(
        "SELECT * FROM index_builds WHERE id=?",
        (research_admission.candidate_build_id,),
    )
    if gap is None or task is None or candidate_index_build is None:
        _fail(
            "GE_SOURCE_CHAIN_CONTROL_RECORD_MISSING",
            "gap, task, or candidate index build is missing",
        )
    if (
        str(gap["candidate_build_id"]) != research_admission.candidate_build_id
        or str(gap["source_manifest_sha256"])
        != research_admission.source_manifest_sha256
        or str(gap["case_id"]) != opaque_gap_reference("case", str(intent["case_id"]))
        or str(gap["issue_id"]) != opaque_gap_reference("issue", str(intent["issue_id"]))
        or str(gap["attempted_retrieval_sha256"])
        != research_admission.retrieval_attempt_artifact_sha256
        or str(gap["materiality"]) != "material"
        or str(gap["status"]) not in {"open", "triaged", "source_needed"}
        or str(task["knowledge_gap_id"] or "") != research_admission.gap_id
        or str(task["task_type"]) != "gap_research"
        or str(task["trigger_kind"]) != "enquiry"
        or str(task["source_id"] or "") != research_admission.source_id
        or str(task["query_sha256"]) != research_admission.query_sha256
        or str(task["pinned_index_build_id"] or "")
        != research_admission.candidate_build_id
        or str(task["source_manifest_sha256"] or "")
        != research_admission.source_manifest_sha256
        or task["encrypted_query"] is not None
        or str(task["status"]) != "review_required"
        or str(candidate_index_build["id"]) != research_admission.candidate_build_id
        or str(candidate_index_build["status"]) == "active"
        or str(candidate_index_build["source_manifest_hash"] or "")
        != research_admission.source_manifest_sha256
    ):
        _fail("GE_SOURCE_CHAIN_CONTROL_RECORD_REPLAY_FAILED", "gap/task binding differs")
    try:
        control_plane.assert_task_gap_open(dict(task))
        candidate_binding = control_plane.candidate_binding_loader(
            control_plane.settings,
            database,
            research_admission.candidate_build_id,
        )
        if (
            candidate_binding.candidate_build_id != research_admission.candidate_build_id
            or candidate_binding.source_manifest_sha256
            != research_admission.source_manifest_sha256
        ):
            _fail("GE_SOURCE_CHAIN_CANDIDATE_REPLAY_FAILED", "candidate seal differs")
        retrieval_attempt = load_verified_candidate_retrieval_attempt(
            settings=control_plane.settings,
            artifact_sha256=research_admission.retrieval_attempt_artifact_sha256,
            expected=RetrievalAttemptBinding(
                candidate_build_id=candidate_binding.candidate_build_id,
                candidate_seal_sha256=candidate_binding.candidate_seal_sha256,
                source_manifest_sha256=candidate_binding.source_manifest_sha256,
                case_ref=str(gap["case_id"]),
                issue_ref=str(gap["issue_id"]),
                subject=str(gap["subject"]),
                jurisdiction=str(gap["jurisdiction"]),
                as_of_date=date.fromisoformat(str(gap["as_of_date"])),
                proposition_sha256=str(intent["proposition_sha256"]),
                query_sha256=research_admission.query_sha256,
            ),
        )
    except GEOfficialResearchControlError:
        raise
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        raise GEOfficialResearchControlError(
            "GE_SOURCE_CHAIN_RETRIEVAL_OBJECT_REPLAY_FAILED", str(exc)
        ) from exc

    source_end, source_record_snapshots, vault_binding = _verified_source_end(
        control_plane=control_plane,
        admission=research_admission,
        receipt=source_intake_receipt,
    )
    admission_sha256 = hashlib.sha256(
        canonical_json_bytes(asdict(research_admission))
    ).hexdigest()
    gap_sha256 = _stored_record_sha256(gap, table="research_gap_bindings")
    task_sha256 = _stored_record_sha256(task, table="research_tasks")
    candidate_index_build_sha256 = _stored_record_sha256(
        candidate_index_build, table="index_builds"
    )
    component_receipt = seal_contract(
        {
            "schema": GE_SOURCE_PROVENANCE_COMPONENT_SCHEMA,
            "diagnosis": dict(diagnosis),
            "diagnosed_result": dict(diagnosed_result),
            "research_intent": dict(intent),
            "research_admission": asdict(research_admission),
            "candidate_build_binding": asdict(candidate_binding),
            "retrieval_attempt_artifact": retrieval_attempt.model_dump(
                mode="json", by_alias=True
            ),
            "source_intake_receipt": asdict(source_intake_receipt),
            "stored_records": {
                "research_gap_binding": _stored_record_snapshot(
                    gap, table="research_gap_bindings"
                ),
                "research_task": _stored_record_snapshot(
                    task, table="research_tasks"
                ),
                "candidate_index_build": _stored_record_snapshot(
                    candidate_index_build, table="index_builds"
                ),
                **source_record_snapshots,
            },
            "vault_object": vault_binding,
            "source_state": "STAGED_PENDING_SOURCE_ADMISSION",
            "authorizes_source_admission": False,
            "authorizes_indexing": False,
            "authorizes_promotion": False,
        }
    )
    component_artifact_sha256 = _write_component_artifact(
        control_plane=control_plane,
        component_receipt=component_receipt,
    )
    identity = {
        "diagnosis_sha256": diagnosis_sha256,
        "diagnosed_result_sha256": result_sha256,
        "research_intent_sha256": intent_sha256,
        "research_admission_sha256": admission_sha256,
        "research_gap_record_sha256": gap_sha256,
        "research_task_record_sha256": task_sha256,
        "candidate_index_build_record_sha256": candidate_index_build_sha256,
        "component_receipt_artifact_sha256": component_artifact_sha256,
        **source_end,
    }
    chain_id = "ge-source-chain-" + hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "legalbot.ge-source-provenance-chain-identity.v1",
                **identity,
            }
        )
    ).hexdigest()[:40]
    return seal_contract(
        {
            "schema": GE_SOURCE_PROVENANCE_SCHEMA,
            "chain_id": chain_id,
            "diagnosis_id": str(diagnosis["diagnosis_id"]),
            "diagnosis_sha256": diagnosis_sha256,
            "failure_fingerprint_sha256": str(
                diagnosis["failure_fingerprint_sha256"]
            ),
            "diagnosed_result_sha256": result_sha256,
            "research_intent_id": str(intent["intent_id"]),
            "research_intent_sha256": intent_sha256,
            "candidate_build_id": research_admission.candidate_build_id,
            "candidate_source_manifest_sha256": (
                research_admission.source_manifest_sha256
            ),
            "retrieval_query_sha256": research_admission.query_sha256,
            "proposition_sha256": str(intent["proposition_sha256"]),
            "retrieval_attempt_artifact_sha256": (
                research_admission.retrieval_attempt_artifact_sha256
            ),
            "research_admission_sha256": admission_sha256,
            "research_gap_id": research_admission.gap_id,
            "research_gap_record_sha256": gap_sha256,
            "research_task_id": research_admission.task_id,
            "research_task_record_sha256": task_sha256,
            "candidate_index_build_record_sha256": candidate_index_build_sha256,
            "component_receipt_artifact_sha256": component_artifact_sha256,
            "research_candidate_id": source_intake_receipt.candidate_id,
            "source_intake_id": source_intake_receipt.intake_id,
            "source_version_id": source_intake_receipt.source_version_id,
            **source_end,
            "source_state": "STAGED_PENDING_SOURCE_ADMISSION",
            "source_identity_verified_for_index": False,
            "source_currentness_verified_for_index": False,
            "source_authority_eligible_for_index": False,
            "feeds_current_answer": False,
            "writes_active": False,
            "enqueues_embedding": False,
            "trains_model": False,
            "opens_unseen": False,
            "promotion_authorized": False,
        }
    )


def validate_verified_ge_source_provenance(
    provenance: Mapping[str, Any],
    *,
    control_plane: ResearchControlPlane,
    diagnosis: Mapping[str, Any],
    diagnosed_result: Mapping[str, Any],
    sealed_intent: Mapping[str, Any],
    research_admission: GEOfficialResearchAdmission,
    source_intake_receipt: StagedSourceIntake,
) -> None:
    """Replay every object/record and require the exact provenance receipt."""

    _verified_contract_sha256(provenance, label="GE source provenance")
    if provenance.get("schema") != GE_SOURCE_PROVENANCE_SCHEMA:
        _fail("GE_SOURCE_CHAIN_SCHEMA_DIFFERED", "provenance schema differs")
    expected = build_verified_ge_source_provenance(
        control_plane=control_plane,
        diagnosis=diagnosis,
        diagnosed_result=diagnosed_result,
        sealed_intent=sealed_intent,
        research_admission=research_admission,
        source_intake_receipt=source_intake_receipt,
    )
    if canonical_json_bytes(expected) != canonical_json_bytes(provenance):
        _fail("GE_SOURCE_CHAIN_REPLAY_DIFFERED", "provenance receipt differs")
