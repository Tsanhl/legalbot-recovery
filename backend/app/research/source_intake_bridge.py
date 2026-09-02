"""Owner-gated research-quarantine to staged-catalogue intake.

The bridge has one narrow responsibility: reopen bytes already held in the
encrypted official-research quarantine and pass one exact, owner-accepted
object to the dedicated create-only ingestion service.  It cannot approve a
source version, enqueue an index build, embed content, promote a candidate,
write ACTIVE/PREVIOUS, train a model, or alter an earlier artifact.

Materialised filenames and returned records are opaque and path-free.  The
configured root and encrypted local alias remain inside the existing ingestion
boundary.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..config import Settings
from ..crypto import LocalCipher
from ..db import Database
from ..orchestration.object_store import EncryptedObjectStore
from ..privacy import path_fingerprint
from .source_intake_create_only import (
    CreateOnlyResearchSourceIngestor,
    CreateOnlySourceIntakeError,
    CreateOnlySourceIntakeRequest,
)
from .source_registry import ContentMode, OfficialSourceRegistry, OnlineDisposition

SOURCE_INTAKE_BRIDGE_SCHEMA = "legalbot.research-source-intake-bridge.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")

_CONTENT_TYPE_EXTENSIONS: Mapping[str, str] = {
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

_AUTHORITY_FOLDERS: Mapping[str, str] = {
    "primary_law": "legislation",
    "official_procedure": "official-guidance",
    "official_guidance": "official-guidance",
    "reform_material": "law-commission",
    "legislative_history": "official-guidance",
    "regulator_rule": "regulator",
}

_PERMITTED_AUTHORITY_TIERS = frozenset(_AUTHORITY_FOLDERS)


class SourceIntakeBridgeError(RuntimeError):
    """A stable, path-free failure from the staged source-intake boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class SourceIntakePlan:
    """A path-free, non-authorising identity for one exact intake attempt."""

    schema: str
    intake_id: str
    binding_sha256: str
    candidate_id: str
    task_id: str
    source_id: str
    content_sha256: str
    system_verification_sha256: str
    owner_review_id: str
    owner_review_manifest_sha256: str
    rights_state: str
    pending_intake_review_id: str
    opaque_relative_path: str
    scan_id: str
    writes_index: bool = False
    writes_active: bool = False
    approves_source: bool = False
    enqueues_embedding: bool = False
    trains_model: bool = False


@dataclass(frozen=True, slots=True)
class StagedSourceIntake:
    """Verified result of ordinary ingestion; still pending source approval."""

    schema: str
    intake_id: str
    binding_sha256: str
    candidate_id: str
    task_id: str
    source_id: str
    content_sha256: str
    system_verification_sha256: str
    owner_review_id: str
    owner_review_manifest_sha256: str
    rights_state: str
    pending_intake_review_id: str
    opaque_relative_path: str
    scan_id: str
    materialization_state: str
    ingestion_status: str
    source_version_id: str
    source_review_id: str
    source_review_status: str
    source_version_review_status: str
    currentness_status: str
    provenance_marker_schema: str
    writes_index: bool = False
    writes_active: bool = False
    approves_source: bool = False
    enqueues_embedding: bool = False
    trains_model: bool = False


@dataclass(frozen=True, slots=True)
class _VerifiedCandidate:
    plan: SourceIntakePlan
    content: bytes
    root: Path
    target: Path
    content_type: str
    source_identity: str
    canonical_url_sha256: str
    observed_at: str
    subject: str
    jurisdiction: str


class ResearchSourceIntakeBridge:
    """Move one fully reviewed quarantine object into staged source intake."""

    def __init__(
        self,
        settings: Settings,
        database: Database,
        cipher: LocalCipher,
        *,
        objects: EncryptedObjectStore | None = None,
        registry: OfficialSourceRegistry | None = None,
        ingestor: CreateOnlyResearchSourceIngestor | None = None,
    ) -> None:
        self.settings = settings
        self.database = database
        self.cipher = cipher
        self.objects = objects or EncryptedObjectStore(
            settings.runtime_object_dir, database, cipher
        )
        self.registry = registry or OfficialSourceRegistry.load(
            settings.project_root / "config" / "official_sources.json"
        )
        self.ingestor = ingestor or CreateOnlyResearchSourceIngestor(
            settings, database, cipher
        )

    def plan(self, candidate_id: str, *, source_root: Path) -> SourceIntakePlan:
        """Validate all gates and return only an opaque relative destination."""

        return self._verified_candidate(candidate_id, source_root=source_root).plan

    def intake(self, candidate_id: str, *, source_root: Path) -> StagedSourceIntake:
        """Materialise and ingest one candidate without granting authority."""

        verified = self._verified_candidate(candidate_id, source_root=source_root)
        plan = verified.plan
        fingerprint = path_fingerprint(verified.target)
        materialization_state = _materialize_create_only(
            verified.root, verified.target, verified.content, plan.content_sha256
        )

        # Re-read the complete candidate/review/object chain immediately before
        # the ingestion mutation.  A concurrent drift becomes a permanent hold;
        # the immutable materialised bytes remain available for diagnosis.
        refreshed = self._verified_candidate(candidate_id, source_root=source_root)
        if refreshed.plan != plan or refreshed.content != verified.content:
            raise SourceIntakeBridgeError("source_intake_candidate_changed_before_ingestion")

        try:
            result = self.ingestor.ingest(
                CreateOnlySourceIntakeRequest(
                    scan_id=plan.scan_id,
                    path=verified.target,
                    content_sha256=plan.content_sha256,
                    content_type=verified.content_type,
                    source_identity=verified.source_identity,
                    canonical_url_sha256=verified.canonical_url_sha256,
                    observed_at=verified.observed_at,
                    subject=verified.subject,
                    jurisdiction=verified.jurisdiction,
                    intake_marker=_source_version_marker(plan),
                )
            )
        except CreateOnlySourceIntakeError as exc:
            raise SourceIntakeBridgeError(exc.code) from exc
        ingestion_status = _verify_ingestion_result(result, plan)
        return self._verified_result(
            plan,
            fingerprint=fingerprint,
            materialization_state=materialization_state,
            ingestion_status=ingestion_status,
        )

    def _verified_candidate(self, candidate_id: str, *, source_root: Path) -> _VerifiedCandidate:
        if not _SAFE_ID.fullmatch(candidate_id):
            raise SourceIntakeBridgeError("source_intake_candidate_id_invalid")
        row = self.database.fetchone(
            """
            SELECT rc.*, rt.status AS task_status, rt.source_id AS task_source_id,
                   rt.subject AS task_subject, rt.jurisdiction AS task_jurisdiction
            FROM research_candidates rc
            JOIN research_tasks rt ON rt.id=rc.task_id
            WHERE rc.id=?
            """,
            (candidate_id,),
        )
        if row is None:
            raise SourceIntakeBridgeError("source_intake_candidate_missing")

        candidate_digests = (
            row["content_sha256"],
            row["metadata_sha256"],
            row["system_verification_sha256"],
        )
        if any(not _SHA256.fullmatch(str(value or "")) for value in candidate_digests):
            raise SourceIntakeBridgeError("source_intake_candidate_digest_invalid")
        if (
            str(row["status"]) != "source_intake_pending"
            or str(row["task_status"]) != "review_required"
            or str(row["task_source_id"] or "") != str(row["source_id"])
        ):
            raise SourceIntakeBridgeError("source_intake_candidate_state_invalid")
        if not _SHA256.fullmatch(str(row["review_manifest_sha256"] or "")):
            raise SourceIntakeBridgeError("source_intake_candidate_digest_invalid")
        if (
            str(row["rights_state"]) not in {"verified", "licensed"}
            or str(row["identity_review_state"]) != "candidate_matched"
            or str(row["currentness_review_state"]) not in {"verified", "not_applicable"}
        ):
            raise SourceIntakeBridgeError("source_intake_owner_gate_incomplete")
        if not _SAFE_ID.fullmatch(str(row["task_id"])):
            raise SourceIntakeBridgeError("source_intake_task_binding_invalid")

        policy = self.registry.get(str(row["source_id"]))
        if (
            policy.content_mode is not ContentMode.FULL_TEXT
            or policy.online_disposition is not OnlineDisposition.STAGED_ONLY
            or (policy.additional_permission_required and str(row["rights_state"]) != "licensed")
        ):
            raise SourceIntakeBridgeError("source_intake_full_text_rights_not_permitted")
        if policy.authority_tier not in _PERMITTED_AUTHORITY_TIERS:
            raise SourceIntakeBridgeError("source_intake_non_authority_source_forbidden")
        _verify_candidate_url(str(row["canonical_url"]), policy.base_url)

        safe_metadata = _json_object(row["safe_metadata_json"], "source_intake_metadata_invalid")
        metadata_sha256 = hashlib.sha256(
            json.dumps(safe_metadata, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if metadata_sha256 != str(row["metadata_sha256"]):
            raise SourceIntakeBridgeError("source_intake_metadata_hash_mismatch")
        if (
            safe_metadata.get("disposition") != "staged_only"
            or safe_metadata.get("owner_decision_required") is not True
            or safe_metadata.get("response_sha256") != str(row["content_sha256"])
        ):
            raise SourceIntakeBridgeError("source_intake_metadata_binding_invalid")
        content_type = str(safe_metadata.get("content_type") or "").casefold()
        suffix = _CONTENT_TYPE_EXTENSIONS.get(content_type)
        if suffix is None:
            raise SourceIntakeBridgeError("source_intake_content_type_unsupported")

        self._verify_review_chain(row, safe_metadata)
        content = self._open_quarantine_object(row)
        root = _permitted_root(self.settings, source_root)

        binding = {
            "schema": SOURCE_INTAKE_BRIDGE_SCHEMA,
            "candidate_id": str(row["id"]),
            "task_id": str(row["task_id"]),
            "source_id": str(row["source_id"]),
            "source_identity": str(row["source_identity"]),
            "content_sha256": str(row["content_sha256"]),
            "metadata_sha256": str(row["metadata_sha256"]),
            "content_object_key": str(row["content_object_key"]),
            "system_verification_sha256": str(row["system_verification_sha256"]),
            "owner_review_id": str(row["review_id"]),
            "owner_review_manifest_sha256": str(row["review_manifest_sha256"]),
            "rights_state": str(row["rights_state"]),
            "pending_intake_review_id": str(row["intake_review_id"]),
        }
        binding_sha256 = _canonical_sha256(binding)
        intake_id = f"source-intake-{binding_sha256[:40]}"
        folder = _AUTHORITY_FOLDERS.get(policy.authority_tier, "official-materials")
        opaque_filename = (
            f"official-{binding_sha256[:32]}-{str(row['content_sha256'])[:16]}{suffix}"
        )
        relative = Path("official-research-intake") / folder / opaque_filename
        target = root / relative
        _assert_target_within_root(root, target)
        plan = SourceIntakePlan(
            schema=SOURCE_INTAKE_BRIDGE_SCHEMA,
            intake_id=intake_id,
            binding_sha256=binding_sha256,
            candidate_id=str(row["id"]),
            task_id=str(row["task_id"]),
            source_id=str(row["source_id"]),
            content_sha256=str(row["content_sha256"]),
            system_verification_sha256=str(row["system_verification_sha256"]),
            owner_review_id=str(row["review_id"]),
            owner_review_manifest_sha256=str(row["review_manifest_sha256"]),
            rights_state=str(row["rights_state"]),
            pending_intake_review_id=str(row["intake_review_id"]),
            opaque_relative_path=relative.as_posix(),
            scan_id=f"research-intake-{binding_sha256[:40]}",
        )
        return _VerifiedCandidate(
            plan=plan,
            content=content,
            root=root,
            target=target,
            content_type=content_type,
            source_identity=str(row["source_identity"]),
            canonical_url_sha256=hashlib.sha256(str(row["canonical_url"]).encode()).hexdigest(),
            observed_at=str(row["created_at"]),
            subject=str(row["task_subject"]),
            jurisdiction=str(row["task_jurisdiction"]),
        )

    def _verify_review_chain(self, row: Any, safe_metadata: Mapping[str, Any]) -> None:
        candidate_id = str(row["id"])
        system_digest = str(row["system_verification_sha256"])
        system_review = self.database.fetchone(
            "SELECT * FROM reviews WHERE id=?", (f"review-research-system-{candidate_id}",)
        )
        if (
            system_review is None
            or str(system_review["review_type"]) != "research_candidate_system_verification"
            or str(system_review["target_id"]) != candidate_id
            or str(system_review["status"]) != "approved"
            or str(system_review["reason"] or "")
            != f"Deterministic candidate envelope {system_digest}"
            or system_review["decided_at"] is None
        ):
            raise SourceIntakeBridgeError("source_intake_system_verification_missing")

        reconstructed_system_envelope = {
            "schema": "legalbot.research-candidate-system-verification.v1",
            "candidate_id": candidate_id,
            "task_id": str(row["task_id"]),
            "source_id": str(row["source_id"]),
            "source_identity": str(row["source_identity"]),
            "content_sha256": str(row["content_sha256"]),
            "metadata_sha256": str(row["metadata_sha256"]),
            "status": "quarantined",
            "comparison_state": row["comparison_state"],
            "rights_state": "unreviewed",
            "content_type": safe_metadata.get("content_type"),
            "disposition": safe_metadata.get("disposition"),
            "network_fetch_state": safe_metadata.get("network_fetch"),
            "additional_permission_required": safe_metadata.get(
                "additional_permission_required"
            ),
            "owner_decision_required": bool(safe_metadata.get("owner_decision_required", False)),
            "has_quarantined_content": True,
        }
        if _canonical_sha256(reconstructed_system_envelope) != system_digest:
            raise SourceIntakeBridgeError("source_intake_system_verification_mismatch")

        review_id = str(row["review_id"] or "")
        owner_review = self.database.fetchone("SELECT * FROM reviews WHERE id=?", (review_id,))
        if (
            not review_id
            or owner_review is None
            or str(owner_review["review_type"]) != "official_research_candidate"
            or str(owner_review["target_id"]) != candidate_id
            or str(owner_review["status"]) != "approved"
            or str(owner_review["reason"] or "")
            != f"Explicit reviewed manifest {row['review_manifest_sha256']}"
            or owner_review["decided_at"] is None
            or not re.fullmatch(r"reviewer:[0-9a-f]{64}", str(row["reviewer_ref"] or ""))
        ):
            raise SourceIntakeBridgeError("source_intake_owner_review_missing")

        expected_intake_review_id = f"review-research-intake-{candidate_id}"
        intake_review = self.database.fetchone(
            "SELECT * FROM reviews WHERE id=?", (expected_intake_review_id,)
        )
        if (
            str(row["intake_review_id"] or "") != expected_intake_review_id
            or intake_review is None
            or str(intake_review["review_type"]) != "research_source_intake"
            or str(intake_review["target_id"]) != candidate_id
            or str(intake_review["status"]) != "pending"
            or intake_review["decided_at"] is not None
        ):
            raise SourceIntakeBridgeError("source_intake_pending_review_missing")

    def _open_quarantine_object(self, row: Any) -> bytes:
        object_key = str(row["content_object_key"] or "")
        if not object_key.startswith("research_candidates:"):
            raise SourceIntakeBridgeError("source_intake_quarantine_object_missing")
        object_row = self.database.fetchone(
            "SELECT * FROM runtime_objects WHERE object_key=?", (object_key,)
        )
        if object_row is None or str(object_row["namespace"]) != "research_candidates":
            raise SourceIntakeBridgeError("source_intake_quarantine_object_missing")
        object_metadata = _json_object(
            object_row["metadata_json"], "source_intake_quarantine_metadata_invalid"
        )
        expected_metadata = {
            "source_id": str(row["source_id"]),
            "content_sha256": str(row["content_sha256"]),
        }
        if object_metadata != expected_metadata:
            raise SourceIntakeBridgeError("source_intake_quarantine_metadata_mismatch")

        envelope = self.objects.get_json(object_key)
        if set(envelope) != {
            "source_id",
            "source_identity",
            "content_sha256",
            "content_base64",
        }:
            raise SourceIntakeBridgeError("source_intake_quarantine_envelope_invalid")
        if (
            envelope.get("source_id") != str(row["source_id"])
            or envelope.get("source_identity") != str(row["source_identity"])
            or envelope.get("content_sha256") != str(row["content_sha256"])
        ):
            raise SourceIntakeBridgeError("source_intake_quarantine_binding_mismatch")
        encoded = envelope.get("content_base64")
        if not isinstance(encoded, str):
            raise SourceIntakeBridgeError("source_intake_quarantine_base64_invalid")
        try:
            content = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
            raise SourceIntakeBridgeError("source_intake_quarantine_base64_invalid") from exc
        if not content or hashlib.sha256(content).hexdigest() != str(row["content_sha256"]):
            raise SourceIntakeBridgeError("source_intake_quarantine_content_mismatch")
        return content

    def _verified_result(
        self,
        plan: SourceIntakePlan,
        *,
        fingerprint: str,
        materialization_state: str,
        ingestion_status: str,
    ) -> StagedSourceIntake:
        rows = self.database.fetchall(
            """
            SELECT sv.id, sv.version_sha256, sv.review_status, sv.currentness_status,
                   sv.superseded_by, sv.metadata_json, r.id AS source_review_id,
                   r.status AS source_review_status
            FROM source_aliases sa
            JOIN source_versions sv ON sv.document_id=sa.document_id
            LEFT JOIN reviews r
              ON r.review_type='source_version' AND r.target_id=sv.id
            WHERE sa.path_fingerprint=? AND sv.superseded_by IS NULL
            """,
            (fingerprint,),
        )
        if len(rows) != 1:
            raise SourceIntakeBridgeError("source_intake_staged_version_missing")
        row = rows[0]
        metadata = _json_object(row["metadata_json"], "source_intake_catalogue_metadata_invalid")
        if (
            str(row["version_sha256"]) != plan.content_sha256
            or str(row["review_status"]) != "staged"
            or str(row["currentness_status"]) != "unknown"
            or row["superseded_by"] is not None
            or not str(row["source_review_id"] or "")
            or str(row["source_review_status"] or "") != "pending"
            or metadata.get("research_source_intake") != _source_version_marker(plan)
        ):
            raise SourceIntakeBridgeError("source_intake_staged_version_not_pending")
        return StagedSourceIntake(
            schema=plan.schema,
            intake_id=plan.intake_id,
            binding_sha256=plan.binding_sha256,
            candidate_id=plan.candidate_id,
            task_id=plan.task_id,
            source_id=plan.source_id,
            content_sha256=plan.content_sha256,
            system_verification_sha256=plan.system_verification_sha256,
            owner_review_id=plan.owner_review_id,
            owner_review_manifest_sha256=plan.owner_review_manifest_sha256,
            rights_state=plan.rights_state,
            pending_intake_review_id=plan.pending_intake_review_id,
            opaque_relative_path=plan.opaque_relative_path,
            scan_id=plan.scan_id,
            materialization_state=materialization_state,
            ingestion_status=ingestion_status,
            source_version_id=str(row["id"]),
            source_review_id=str(row["source_review_id"]),
            source_review_status="pending",
            source_version_review_status="staged",
            currentness_status="unknown",
            provenance_marker_schema=SOURCE_INTAKE_BRIDGE_SCHEMA,
        )


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _source_version_marker(plan: SourceIntakePlan) -> dict[str, str]:
    return {
        "schema": plan.schema,
        "intake_id": plan.intake_id,
        "binding_sha256": plan.binding_sha256,
        "candidate_id": plan.candidate_id,
        "task_id": plan.task_id,
        "source_id": plan.source_id,
        "content_sha256": plan.content_sha256,
        "system_verification_sha256": plan.system_verification_sha256,
        "owner_review_id": plan.owner_review_id,
        "owner_review_manifest_sha256": plan.owner_review_manifest_sha256,
        "rights_state": plan.rights_state,
        "pending_intake_review_id": plan.pending_intake_review_id,
    }


def _json_object(value: Any, code: str) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value))
    except (TypeError, json.JSONDecodeError) as exc:
        raise SourceIntakeBridgeError(code) from exc
    if not isinstance(parsed, dict) or not all(isinstance(key, str) for key in parsed):
        raise SourceIntakeBridgeError(code)
    return parsed


def _verify_candidate_url(candidate_url: str, base_url: str) -> None:
    candidate = urlsplit(candidate_url)
    registered = urlsplit(base_url)
    base_path = registered.path.rstrip("/")
    if (
        candidate.scheme != "https"
        or candidate.username is not None
        or candidate.password is not None
        or candidate.query
        or candidate.fragment
        or (candidate.hostname or "").casefold() != (registered.hostname or "").casefold()
        or not (
            candidate.path == base_path
            or candidate.path.startswith(f"{base_path}/" if base_path else "/")
        )
    ):
        raise SourceIntakeBridgeError("source_intake_registered_source_mismatch")


def _permitted_root(settings: Settings, requested_root: Path) -> Path:
    requested = requested_root.expanduser().absolute()
    configured = tuple(root.expanduser().absolute() for root in settings.source_roots)
    if requested not in configured:
        raise SourceIntakeBridgeError("source_intake_root_not_configured")
    if requested.is_symlink() or not requested.is_dir():
        raise SourceIntakeBridgeError("source_intake_root_unavailable")
    try:
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise SourceIntakeBridgeError("source_intake_root_unavailable") from exc
    if not any(
        not root.is_symlink() and root.is_dir() and root.resolve(strict=True) == resolved
        for root in configured
    ):
        raise SourceIntakeBridgeError("source_intake_root_not_configured")
    return resolved


def _assert_target_within_root(root: Path, target: Path) -> None:
    relative = target.relative_to(root)
    if relative.is_absolute() or ".." in relative.parts:
        raise SourceIntakeBridgeError("source_intake_target_invalid")


def _ensure_target_parent(root: Path, target: Path) -> None:
    _assert_target_within_root(root, target)
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    cursor = parent
    while cursor != root:
        if cursor.is_symlink() or not cursor.is_dir():
            raise SourceIntakeBridgeError("source_intake_target_parent_invalid")
        cursor = cursor.parent
    if parent.resolve(strict=True).is_relative_to(root) is False:
        raise SourceIntakeBridgeError("source_intake_target_parent_invalid")


def _materialize_create_only(
    root: Path, target: Path, content: bytes, content_sha256: str
) -> str:
    _ensure_target_parent(root, target)
    if target.exists() or target.is_symlink():
        return _verify_existing_file(target, content, content_sha256)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags, 0o400)
    except FileExistsError:
        return _verify_existing_file(target, content, content_sha256)
    except OSError as exc:
        raise SourceIntakeBridgeError("source_intake_materialization_failed") from exc
    try:
        view = memoryview(content)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
    except OSError as exc:
        # Create-only custody keeps a partial artifact for diagnosis.  Nothing
        # is silently rewritten after a failed write.
        raise SourceIntakeBridgeError("source_intake_materialization_failed") from exc
    finally:
        os.close(descriptor)
    try:
        directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        raise SourceIntakeBridgeError("source_intake_materialization_failed") from exc
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return "created"


def _verify_existing_file(target: Path, content: bytes, content_sha256: str) -> str:
    try:
        details = target.lstat()
    except OSError as exc:
        raise SourceIntakeBridgeError("source_intake_materialization_conflict") from exc
    if not stat.S_ISREG(details.st_mode) or target.is_symlink() or details.st_size != len(content):
        raise SourceIntakeBridgeError("source_intake_materialization_conflict")
    digest = hashlib.sha256()
    try:
        with target.open("rb") as handle:
            while block := handle.read(1024 * 1024):
                digest.update(block)
    except OSError as exc:
        raise SourceIntakeBridgeError("source_intake_materialization_conflict") from exc
    if digest.hexdigest() != content_sha256:
        raise SourceIntakeBridgeError("source_intake_materialization_conflict")
    return "existing_verified"


def _verify_ingestion_result(result: Mapping[str, Any], plan: SourceIntakePlan) -> str:
    items = result.get("items")
    if (
        result.get("scan_id") != plan.scan_id
        or result.get("file_count") != 1
        or result.get("wrote_active") is not False
        or result.get("seals_expert_gold") is not False
        or not isinstance(items, list)
        or len(items) != 1
        or not isinstance(items[0], dict)
        or items[0].get("content_sha256") != plan.content_sha256
    ):
        raise SourceIntakeBridgeError("source_intake_ingestion_result_invalid")
    status = str(items[0].get("status") or "")
    if status in {"", "missing", "rejected", "skipped", "quarantined", "unsupported"}:
        raise SourceIntakeBridgeError("source_intake_ingestion_not_staged")
    return status
