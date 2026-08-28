"""Fail-closed recorder for the owner-observed real-browser recovery drill.

This module does not drive a browser and cannot infer visual behaviour.  It
records the gate only after the owner explicitly confirms every browser-side
observation and the durable runtime identities reconcile with SQLite, the
immutable Live60 contract and the ACTIVE index pointer.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from ..config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from ..db import PUBLIC_RELEASE_STATES, Database
from ..orchestration.classifier import CLASSIFIER_VERSION
from ..orchestration.routing import ROUTER_VERSION
from ..quality.policy import POLICY_SHA256
from ..retrieval.lancedb import ImmutableLanceRepository
from ..runtime_adapters import PROMPT_VERSION
from .live30 import assert_safe_evaluation_payload
from .live_suite import admission_as_of_date, load_live_evaluation_bundle
from .live_suite_store import LiveSuiteRunManifest

BROWSER_RECOVERY_SCHEMA = "legalbot.browser-recovery-drill-result.v3"
BROWSER_RECOVERY_RELATIVE_PATH = Path("data/evaluations/e2e/gates/browser-recovery-drill.json")

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SAFE_TRACE_ID = re.compile(r"^trace-[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_REQUEST_FIELDS = frozenset(
    {
        "task_type",
        "jurisdiction",
        "as_of_date",
        "word_target",
        "online_mode",
        "upload_ids",
    }
)


def _canonical_self_seal(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("seal_sha256", None)
    encoded = (
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ordinary_drill_request_fingerprint(
    *,
    encrypted_question: bytes,
    request: Mapping[str, Any],
    route: str,
    word_target: int,
    active_build_id: str,
) -> str:
    """Digest an ordinary drill request without exposing its question.

    The encrypted-question byte digest detects later SQLite mutation while the
    canonical request fields bind the routing inputs.  Only the known API
    request contract is accepted, so hidden prose or upload-scoped context
    cannot be smuggled into a browser-readiness drill.
    """

    if set(request) != _REQUEST_FIELDS:
        raise RuntimeError("the drill request does not match the ordinary API contract")
    if (
        request.get("jurisdiction") != "England and Wales"
        or request.get("online_mode") != "local_only"
        or request.get("upload_ids") != []
        or request.get("word_target") != word_target
        or not isinstance(request.get("task_type"), str)
        or request.get("task_type") not in {"auto", "essay", "problem", "general"}
        or route not in {"direct", "sectioned", "full_enquiry"}
        or not isinstance(word_target, int)
        or not 100 <= word_target <= 10_000
    ):
        raise RuntimeError("the drill request is not an ordinary local E&W answer")
    material = {
        "schema": "legalbot.ordinary-browser-drill-request.v1",
        "encrypted_question_sha256": hashlib.sha256(encrypted_question).hexdigest(),
        "task_type": request["task_type"],
        "jurisdiction": request["jurisdiction"],
        "as_of_date": request["as_of_date"],
        "word_target": word_target,
        "online_mode": request["online_mode"],
        "upload_ids": [],
        "route": route,
        "active_build_id": active_build_id,
    }
    return hashlib.sha256(
        (
            json.dumps(
                material,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    ).hexdigest()


def sealed_build_source_manifest(
    repository: ImmutableLanceRepository,
    *,
    active_build_id: str,
    active_manifest_sha256: str,
) -> str:
    manifest_path = repository.builds / active_build_id / "manifest.json"
    try:
        raw = manifest_path.read_bytes()
        value = json.loads(raw)
    except (OSError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("the ACTIVE build manifest is missing or invalid") from exc
    if not isinstance(value, dict):
        raise RuntimeError("the ACTIVE build manifest is not an object")
    source_sha = value.get("source_manifest_sha256")
    if (
        hashlib.sha256(raw).hexdigest() != active_manifest_sha256
        or value.get("schema") != "legalbot.lance-build.v1"
        or value.get("build_id") != active_build_id
        or value.get("sealed") is not True
        or not isinstance(source_sha, str)
        or _SHA256.fullmatch(source_sha) is None
    ):
        raise RuntimeError("the ACTIVE build manifest identity is inconsistent")
    return source_sha


@dataclass(frozen=True, slots=True)
class BrowserRecoveryConfirmations:
    """Visual/operational observations that only the drill owner can attest."""

    real_browser: bool
    page_reloaded_while_running: bool
    same_job_recovered_after_reload: bool
    progress_resumed: bool
    terminal_state_visible: bool
    no_indefinite_spinner: bool
    exactly_one_release: bool
    privacy_passed: bool
    loopback_only: bool
    zero_online_calls: bool

    def require_all(self) -> None:
        if not all(
            (
                self.real_browser,
                self.page_reloaded_while_running,
                self.same_job_recovered_after_reload,
                self.progress_resumed,
                self.terminal_state_visible,
                self.no_indefinite_spinner,
                self.exactly_one_release,
                self.privacy_passed,
                self.loopback_only,
                self.zero_online_calls,
            )
        ):
            raise ValueError("every browser-recovery owner confirmation is required")


class BrowserRecoveryDrillRecord(BaseModel):
    """Privacy-safe, self-sealed readiness evidence for one completed drill."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.browser-recovery-drill-result.v3"] = Field(
        default="legalbot.browser-recovery-drill-result.v3", alias="schema"
    )
    purpose: Literal["evaluation_only"] = "evaluation_only"
    eligible_for_training: Literal[False] = False
    training_export_allowed: Literal[False] = False
    passed: Literal[True] = True
    recorded_at: str = Field(
        pattern=(
            r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
        )
    )
    as_of_date: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    suite_id: Literal["live-evaluation-60-v1"] = "live-evaluation-60-v1"
    suite_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_plan_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    run_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    job_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    trace_id: str = Field(pattern=r"^trace-[0-9a-f]{40}$")
    drill_job_kind: Literal["ordinary_local_answer"] = "ordinary_local_answer"
    counts_as_live60_selected_outcome: Literal[False] = False
    live60_evaluation_binding_absent: Literal[True] = True
    live60_case_run_link_count: Literal[0] = 0
    request_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    route: Literal["direct", "sectioned", "full_enquiry"]
    word_target: int = Field(ge=100, le=10_000)
    model_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,255}$")
    active_build_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    active_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,255}$")
    router_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,255}$")
    classifier_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,255}$")
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assessment_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    terminal_job_status: Literal["complete"] = "complete"
    terminal_release_state: Literal["verified_full", "verified_concise", "verified_limited"]
    release_outbox_count: Literal[1] = 1
    online_adapter_call_count: Literal[0] = 0
    runtime_profile_local_only: Literal[True] = True
    job_request_local_only: Literal[True] = True
    active_pointer_catalogue_reconciled: Literal[True] = True
    real_browser: Literal[True] = True
    loopback_only: Literal[True] = True
    page_reloaded_while_running: Literal[True] = True
    same_job_recovered_after_reload: Literal[True] = True
    progress_resumed: Literal[True] = True
    terminal_state_visible: Literal[True] = True
    no_indefinite_spinner: Literal[True] = True
    exactly_one_release: Literal[True] = True
    privacy_passed: Literal[True] = True
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def seal_is_valid(self) -> Self:
        if self.seal_sha256 != _canonical_self_seal(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("browser-recovery drill seal is invalid")
        return self


def _require_safe_inputs(
    *,
    job_id: str,
    trace_id: str,
    run_id: str,
    suite_canonical_sha256: str,
    active_build_id: str,
) -> None:
    if _SAFE_ID.fullmatch(job_id) is None or _SAFE_ID.fullmatch(run_id) is None:
        raise ValueError("job_id and run_id must be safe opaque identifiers")
    if _SAFE_TRACE_ID.fullmatch(trace_id) is None:
        raise ValueError("trace_id is not a LegalBot trace identity")
    if _SHA256.fullmatch(suite_canonical_sha256) is None:
        raise ValueError("suite canonical SHA-256 is invalid")
    if re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", active_build_id) is None:
        raise ValueError("ACTIVE build identity is invalid")


def _load_run_manifest(
    settings: Settings, *, run_id: str, bundle_root: Path
) -> tuple[LiveSuiteRunManifest, Path]:
    run_root = (settings.evaluation_dir / "e2e" / "runs" / run_id).resolve()
    allowed_root = (settings.evaluation_dir / "e2e" / "runs").resolve()
    if not run_root.is_relative_to(allowed_root):
        raise ValueError("run identity escaped the evaluation root")
    manifest_path = run_root / "manifest.json"
    suite_snapshot = run_root / "suite-manifest.json"
    plan_snapshot = run_root / "generation-run-plan.json"
    try:
        manifest = LiveSuiteRunManifest.model_validate_json(manifest_path.read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        raise RuntimeError("the immutable Live60 run manifest is missing or invalid") from exc
    bundle_manifest = bundle_root / "manifest.json"
    bundle_plan = bundle_root / "generation-run-plan.json"
    try:
        if suite_snapshot.read_bytes() != bundle_manifest.read_bytes():
            raise RuntimeError("the run suite snapshot differs from the current sealed suite")
        if plan_snapshot.read_bytes() != bundle_plan.read_bytes():
            raise RuntimeError("the run plan snapshot differs from the current sealed plan")
    except OSError as exc:
        raise RuntimeError("the immutable Live60 run snapshots are incomplete") from exc
    return manifest, manifest_path


def first_live_recorder_settings(project_root: Path) -> Settings:
    """Build recorder settings from the first-live environment, not import defaults."""

    profile = os.getenv("LEGALBOT_LIVE_PROFILE")
    if profile != FIRST_LIVE_LOCAL_ONLY_PROFILE:
        raise RuntimeError(
            "LEGALBOT_LIVE_PROFILE=first_live_local_only is required to record "
            "the browser recovery drill"
        )
    return Settings(
        project_root=project_root,
        live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE,
        online_default="local_only",
        official_research_enabled=False,
    )


def _require_local_only_runtime(settings: Settings) -> None:
    model_host = (urlsplit(settings.model_url).hostname or "").casefold()
    if (
        settings.live_profile != FIRST_LIVE_LOCAL_ONLY_PROFILE
        or settings.host.casefold() not in _LOOPBACK_HOSTS
        or model_host not in _LOOPBACK_HOSTS
        or settings.online_default != "local_only"
        or settings.official_research_enabled
        or not settings.evaluation_forbids_online_research
    ):
        raise RuntimeError("the first-live loopback-only runtime profile is not active")


def _atomic_create_owner_only(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    if path.exists():
        raise FileExistsError("browser-recovery drill is immutable and already exists")
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # link(2) is an atomic create-if-absent operation.  Unlike replace(),
        # it cannot silently overwrite evidence from an earlier drill.
        os.link(temporary, path)
        path.chmod(0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def record_browser_recovery_drill(
    settings: Settings,
    *,
    job_id: str,
    trace_id: str,
    run_id: str,
    suite_canonical_sha256: str,
    as_of_date: date,
    active_build_id: str,
    confirmations: BrowserRecoveryConfirmations,
) -> Path:
    """Cross-check and atomically record one owner-observed browser drill.

    The function performs no browser, model, network, promotion or evaluation
    action.  Any absent confirmation or identity mismatch leaves no artifact.
    """

    confirmations.require_all()
    _require_safe_inputs(
        job_id=job_id,
        trace_id=trace_id,
        run_id=run_id,
        suite_canonical_sha256=suite_canonical_sha256,
        active_build_id=active_build_id,
    )
    if as_of_date != admission_as_of_date():
        raise RuntimeError("the supplied legal date is not today's Europe/London date")
    _require_local_only_runtime(settings)

    bundle_root = settings.project_root / "benchmarks/evaluation/live-evaluation-60-v1"
    bundle = load_live_evaluation_bundle(bundle_root)
    if suite_canonical_sha256 != bundle.registry.canonical_sha256:
        raise RuntimeError("the supplied suite digest is not the current Live60 seal")
    manifest, manifest_path = _load_run_manifest(settings, run_id=run_id, bundle_root=bundle_root)
    if (
        manifest.run_id != run_id
        or manifest.as_of_date != as_of_date.isoformat()
        or manifest.suite_manifest_seal_sha256 != bundle.manifest.seal_sha256
        or manifest.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256
        or manifest.run_plan_seal_sha256 != bundle.run_plan.seal_sha256
        or manifest.provenance.index_build_id != active_build_id
        or manifest.provenance.git_dirty
        or not manifest.local_only
        or manifest.online_research_allowed
    ):
        raise RuntimeError("the run manifest is not bound to this sealed local-only drill")

    repository = ImmutableLanceRepository(settings.index_dir)
    destination = settings.project_root / BROWSER_RECOVERY_RELATIVE_PATH
    if destination.exists():
        raise FileExistsError("browser-recovery drill is immutable and already exists")
    if not settings.database_path.is_file():
        raise RuntimeError("the runtime catalogue is missing")

    database = Database(settings.database_path)
    try:
        with database.transaction() as connection:
            pointer = repository.read_active()
            active_rows = connection.execute(
                """
                SELECT id, status, promoted_at FROM index_builds
                WHERE status='active' ORDER BY promoted_at DESC
                """
            ).fetchall()
            job = connection.execute(
                """
                SELECT id, status, stage, progress, request_json, answer_id,
                       release_state, pinned_index_build_id, job_type,
                       evaluation_run_id, evaluation_case_id, trace_id,
                       evaluation_request_sha256, trace_full_retention,
                       encrypted_question, route, word_target,
                       worker_prompt_version, worker_router_version,
                       worker_classifier_version, worker_policy_sha256,
                       assessment_bundle_sha256
                FROM jobs WHERE id=?
                """,
                (job_id,),
            ).fetchone()
            outbox = connection.execute(
                """
                SELECT answer_id, release_state, status, published_at
                FROM release_outbox WHERE job_id=?
                """,
                (job_id,),
            ).fetchall()
            case_run_links = connection.execute(
                "SELECT id FROM evaluation_case_runs WHERE job_id=?",
                (job_id,),
            ).fetchall()
            if job is None:
                raise RuntimeError("the browser drill job is absent from SQLite")
            answer_id = str(job["answer_id"] or "")
            answer = connection.execute(
                """
                SELECT id, release_state, index_build_id, model_version,
                       policy_sha256, word_count
                FROM answer_versions WHERE id=?
                """,
                (answer_id,),
            ).fetchone()
            try:
                request = json.loads(str(job["request_json"] or "{}"))
            except (TypeError, json.JSONDecodeError) as exc:
                raise RuntimeError("the drill job request binding is invalid") from exc
            if not isinstance(request, dict):
                raise RuntimeError("the drill job request binding is invalid")
            release_state = str(job["release_state"] or "")
            if pointer is None:
                raise RuntimeError("ACTIVE pointer is missing")
            source_manifest_sha256 = sealed_build_source_manifest(
                repository,
                active_build_id=active_build_id,
                active_manifest_sha256=pointer.manifest_sha256,
            )
            route = str(job["route"] or "")
            word_target = int(job["word_target"] or 0)
            request_fingerprint_sha256 = ordinary_drill_request_fingerprint(
                encrypted_question=bytes(job["encrypted_question"]),
                request=request,
                route=route,
                word_target=word_target,
                active_build_id=active_build_id,
            )
            provenance = manifest.provenance
            checks = (
                pointer is not None and pointer.build_id == active_build_id,
                len(active_rows) == 1 and str(active_rows[0]["id"]) == active_build_id,
                len(active_rows) == 1 and bool(active_rows[0]["promoted_at"]),
                str(job["status"]) == "complete",
                float(job["progress"]) >= 1.0,
                str(job["trace_id"]) == trace_id,
                not job["evaluation_run_id"],
                not job["evaluation_case_id"],
                not job["evaluation_request_sha256"],
                len(case_run_links) == 0,
                str(job["pinned_index_build_id"] or "") == active_build_id,
                str(job["job_type"] or "") == "answer",
                int(job["trace_full_retention"] or 0) == 0,
                request.get("online_mode") == "local_only",
                request.get("as_of_date") == as_of_date.isoformat(),
                request.get("word_target") == word_target,
                str(job["worker_prompt_version"] or "") == PROMPT_VERSION,
                str(job["worker_router_version"] or "") == ROUTER_VERSION,
                str(job["worker_classifier_version"] or "") == CLASSIFIER_VERSION,
                str(job["worker_policy_sha256"] or "") == POLICY_SHA256,
                str(job["assessment_bundle_sha256"] or "") == OWNER_ASSESSMENT_BUNDLE.sha256,
                provenance.model_version == settings.model_id,
                provenance.prompt_version == PROMPT_VERSION,
                provenance.router_version == ROUTER_VERSION,
                provenance.classifier_version == CLASSIFIER_VERSION,
                provenance.policy_sha256 == POLICY_SHA256,
                provenance.assessment_rules_sha256 == OWNER_ASSESSMENT_BUNDLE.sha256,
                bool(answer_id),
                release_state in PUBLIC_RELEASE_STATES,
                len(outbox) == 1,
                str(outbox[0]["status"]) == "published" if len(outbox) == 1 else False,
                bool(outbox[0]["published_at"]) if len(outbox) == 1 else False,
                str(outbox[0]["answer_id"]) == answer_id if len(outbox) == 1 else False,
                str(outbox[0]["release_state"]) == release_state if len(outbox) == 1 else False,
                answer is not None,
                str(answer["release_state"] or "") == release_state
                if answer is not None
                else False,
                str(answer["index_build_id"] or "") == active_build_id
                if answer is not None
                else False,
                str(answer["model_version"] or "") == settings.model_id
                if answer is not None
                else False,
                str(answer["policy_sha256"] or "") == POLICY_SHA256
                if answer is not None
                else False,
                int(answer["word_count"] or 0) > 0 if answer is not None else False,
            )
            if not all(checks):
                raise RuntimeError("SQLite, release outbox, run and ACTIVE bindings disagree")
            value: dict[str, Any] = {
                "schema": BROWSER_RECOVERY_SCHEMA,
                "purpose": "evaluation_only",
                "eligible_for_training": False,
                "training_export_allowed": False,
                "passed": True,
                "recorded_at": datetime.now(UTC).isoformat(),
                "as_of_date": as_of_date.isoformat(),
                "suite_id": bundle.manifest.suite_id,
                "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
                "suite_canonical_sha256": bundle.registry.canonical_sha256,
                "run_plan_seal_sha256": bundle.run_plan.seal_sha256,
                "run_id": run_id,
                "run_manifest_sha256": _file_sha256(manifest_path),
                "job_id": job_id,
                "trace_id": trace_id,
                "drill_job_kind": "ordinary_local_answer",
                "counts_as_live60_selected_outcome": False,
                "live60_evaluation_binding_absent": True,
                "live60_case_run_link_count": 0,
                "request_fingerprint_sha256": request_fingerprint_sha256,
                "route": route,
                "word_target": word_target,
                "model_version": settings.model_id,
                "active_build_id": active_build_id,
                "active_manifest_sha256": pointer.manifest_sha256,
                "source_manifest_sha256": source_manifest_sha256,
                "prompt_version": PROMPT_VERSION,
                "router_version": ROUTER_VERSION,
                "classifier_version": CLASSIFIER_VERSION,
                "policy_sha256": POLICY_SHA256,
                "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
                "terminal_job_status": "complete",
                "terminal_release_state": release_state,
                "release_outbox_count": 1,
                "online_adapter_call_count": 0,
                "runtime_profile_local_only": True,
                "job_request_local_only": True,
                "active_pointer_catalogue_reconciled": True,
                "real_browser": True,
                "loopback_only": True,
                "page_reloaded_while_running": True,
                "same_job_recovered_after_reload": True,
                "progress_resumed": True,
                "terminal_state_visible": True,
                "no_indefinite_spinner": True,
                "exactly_one_release": True,
                "privacy_passed": True,
            }
            value["seal_sha256"] = _canonical_self_seal(value)
            record = BrowserRecoveryDrillRecord.model_validate(value)
            serializable = record.model_dump(mode="json", by_alias=True)
            assert_safe_evaluation_payload(serializable)
            encoded = (
                json.dumps(
                    serializable,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
            _atomic_create_owner_only(destination, encoded)
    finally:
        database.close()
    return destination


def verify_browser_recovery_drill(path: Path) -> BrowserRecoveryDrillRecord:
    """Verify a recorded drill's privacy shape and self-seal without mutation."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        assert_safe_evaluation_payload(value)
        return BrowserRecoveryDrillRecord.model_validate(value)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise RuntimeError("browser-recovery drill artifact is missing or invalid") from exc
