"""Admission, staging and ACTIVE-aware comparison for official research work."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..config import Settings
from ..crypto import LocalCipher
from ..db import Database
from ..orchestration.classifier import SUBJECT_MARKERS
from ..privacy import assert_review_payload_safe, scrub_pii
from ..retrieval.lancedb import ImmutableLanceRepository
from ..retrieval.source_manifest import approved_source_manifest_sha256
from .models import (
    GapMateriality,
    ResearchCandidateDraft,
    ResearchGapBindingRequest,
    ResearchTaskRequest,
    ResearchTaskType,
    ResearchTrigger,
    SourceUpdateDraft,
    SourceUpdateState,
)
from .retrieval_attempt import (
    CandidateBuildBinding,
    CandidateBuildBindingLoader,
    RetrievalAttemptBinding,
    load_sealed_candidate_build_binding,
    load_verified_candidate_retrieval_attempt,
    opaque_gap_reference,
)
from .source_registry import OfficialSourceRegistry

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_PUBLIC_AUTHORITY_ID = re.compile(
    r"^(?:"
    r"neutral[-_]citation:\[(?:18|19|20)\d{2}\]\s+[A-Za-z0-9 .()/-]{2,100}"
    r"|(?:ukpga|uksi|wsi|asp|ssi|nia|nisr|anaw|asc):[A-Za-z0-9@._-]+"
    r"(?::[A-Za-z0-9@._-]+){1,6}"
    r"|(?:ecli|celex|doi|authority|case):[A-Za-z0-9./_()@:-]{2,180}"
    r")$",
    re.IGNORECASE,
)

# Network discovery accepts a registered taxonomy value, never arbitrary owner
# prose or a raw user question. Composite families come from the same bounded
# classifier that routes answer work; the base values cover source update and
# gap workflows that are not derived from a full question.
RESEARCH_SUBJECT_TAXONOMY = frozenset(
    {
        *SUBJECT_MARKERS,
        "general",
        "known_sources",
        "case law",
        "contract",
        "consumer",
        "tort",
        "criminal",
        "evidence",
        "employment",
        "land",
        "land_law",
        "trusts",
        "public law",
        "constitutional law",
        "human rights",
        "company law",
        "family law",
        "civil litigation",
        "intellectual property",
        "banking",
        "competition",
        "medical law",
        "procurement",
        "environmental law",
        "data protection",
        "privacy",
        "legal ethics",
        "insolvency",
        "construction",
        "commercial law",
    }
)
RESEARCH_PUBLIC_QUERIES = frozenset(
    {
        "general legislation",
        "competition",
        "contract",
        "criminal",
        "employment",
        "evidence",
        "land registration",
        "medical treatment",
        "pensions",
        "data protection",
        "negligence",
        "trustees",
    }
)


@dataclass(frozen=True, slots=True)
class ActiveResearchSnapshot:
    build_id: str | None
    source_manifest_sha256: str | None


@dataclass(frozen=True, slots=True)
class _OpenGapBinding:
    gap_id: str
    subject: str
    jurisdiction: str | None
    as_of_date: str | None
    candidate_build_id: str | None
    candidate_seal_sha256: str | None
    source_manifest_sha256: str | None
    retrieval_attempt_artifact_sha256: str | None
    retrieval_query_sha256: str | None
    proposition_sha256: str | None
    materiality: str


def _canonical_json_sha256(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _stable_id(prefix: str, *parts: str) -> str:
    payload = "\0".join((f"legalbot-{prefix}-v1", *parts)).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(payload).hexdigest()[:40]}"


def scrub_candidate_url(value: str) -> str:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("official candidate URL has an invalid port") from exc
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or not parsed.hostname
    ):
        raise ValueError("official candidate URL is not safe HTTPS")
    clean = urlunsplit(("https", parsed.netloc, parsed.path or "/", "", ""))
    if clean != scrub_pii(clean):
        raise ValueError("official candidate URL contains private data")
    return clean


def _path_is_within(candidate_path: str, registered_path: str) -> bool:
    """Match one registered URL path without accepting sibling prefixes."""

    boundary = registered_path.rstrip("/")
    if not boundary:
        return candidate_path.startswith("/")
    return candidate_path == boundary or candidate_path.startswith(f"{boundary}/")


class ResearchControlPlane:
    """Durable research admission. It has no approval, indexing or promotion method."""

    def __init__(
        self,
        settings: Settings,
        database: Database,
        *,
        cipher: LocalCipher | None = None,
        registry: OfficialSourceRegistry | None = None,
        candidate_binding_loader: CandidateBuildBindingLoader = (
            load_sealed_candidate_build_binding
        ),
    ) -> None:
        self.settings = settings
        self.database = database
        self.cipher = cipher
        self.registry = registry or OfficialSourceRegistry.load(
            settings.project_root / "config" / "official_sources.json"
        )
        self.candidate_binding_loader = candidate_binding_loader

    def _candidate_binding(self, candidate_build_id: str) -> CandidateBuildBinding:
        try:
            binding = self.candidate_binding_loader(
                self.settings, self.database, candidate_build_id
            )
        except (RuntimeError, ValueError) as exc:
            raise ValueError("research gap must bind to a sealed candidate build") from exc
        if (
            binding.candidate_build_id != candidate_build_id
            or not _SAFE_REFERENCE.fullmatch(binding.candidate_build_id)
            or not _SHA256.fullmatch(binding.candidate_seal_sha256)
            or not _SHA256.fullmatch(binding.source_manifest_sha256)
        ):
            raise ValueError("sealed candidate research binding is invalid")
        return binding

    def active_snapshot(self) -> ActiveResearchSnapshot:
        repository = ImmutableLanceRepository(self.settings.index_dir)
        pointer = repository.read_active()
        database_id = self.database.active_index_id()
        pointer_id = pointer.build_id if pointer else None
        if pointer_id != database_id:
            raise RuntimeError("ACTIVE pointer and catalogue disagree for research admission")
        if database_id is None:
            return ActiveResearchSnapshot(None, None)
        row = self.database.fetchone(
            "SELECT source_manifest_hash FROM index_builds WHERE id=? AND status='active'",
            (database_id,),
        )
        if row is None:
            raise RuntimeError("ACTIVE research snapshot disappeared")
        digest = str(row["source_manifest_hash"] or "")
        if not _SHA256.fullmatch(digest):
            raise RuntimeError("ACTIVE build has no valid source-manifest identity")
        return ActiveResearchSnapshot(database_id, digest)

    def known_active_authorities(self) -> tuple[dict[str, str], ...]:
        """Return safe registered identities from the pinned ACTIVE source manifest."""

        snapshot = self.active_snapshot()
        if snapshot.build_id is None or snapshot.source_manifest_sha256 is None:
            return ()
        path = (
            self.settings.index_dir / "builds" / snapshot.build_id / "approved-source-manifest.json"
        )
        payload = json.loads(path.read_text(encoding="utf-8"))
        if (
            payload.get("manifest_sha256") != snapshot.source_manifest_sha256
            or approved_source_manifest_sha256(payload) != snapshot.source_manifest_sha256
        ):
            raise RuntimeError("ACTIVE approved-source manifest digest changed")
        hosts = {
            (urlsplit(policy.base_url).hostname or "").casefold(): policy.source_id
            for policy in self.registry.all()
        }
        output: list[dict[str, str]] = []
        for source in payload.get("sources", []):
            canonical_url = str(source.get("canonical_url") or "")
            parsed = urlsplit(canonical_url)
            source_id = hosts.get((parsed.hostname or "").casefold())
            authority_id = str(source.get("authority_identity_id") or "")
            if source_id is None or not authority_id:
                continue
            identity = parsed.path.strip("/")
            if not identity:
                continue
            output.append(
                {
                    "source_id": source_id,
                    "authority_identity_id": authority_id,
                    "adapter_identity": identity,
                }
            )
        return tuple(
            sorted(
                output,
                key=lambda item: (
                    item["source_id"],
                    item["authority_identity_id"],
                ),
            )
        )

    def log_knowledge_gap(self, request: ResearchGapBindingRequest) -> Any:
        """Log one encrypted, semantically deduplicated gap before research."""

        if self.cipher is None:
            raise RuntimeError("encrypted research-gap storage is unavailable")
        subject = " ".join(request.subject.split()).casefold()
        jurisdiction = " ".join(request.jurisdiction.split())
        detail = request.detail.strip()
        safe_references = (request.candidate_build_id, request.case_id, request.issue_id)
        if (
            subject not in RESEARCH_SUBJECT_TAXONOMY
            or not jurisdiction
            or len(jurisdiction) > 80
            or scrub_pii(jurisdiction) != jurisdiction
            or not detail
            or len(detail) > 20_000
            or any(not _SAFE_REFERENCE.fullmatch(value) for value in safe_references)
            or not _SHA256.fullmatch(request.retrieval_query_sha256)
            or not _SHA256.fullmatch(request.proposition_sha256)
            or not _SHA256.fullmatch(request.retrieval_attempt_artifact_sha256)
        ):
            raise ValueError("research-gap binding is invalid")
        # Even caller-safe local references are persisted only as stable
        # one-way bindings.  Detailed gap content remains encrypted separately.
        case_ref = opaque_gap_reference("case", request.case_id)
        issue_ref = opaque_gap_reference("issue", request.issue_id)
        candidate = self._candidate_binding(request.candidate_build_id)
        load_verified_candidate_retrieval_attempt(
            settings=self.settings,
            artifact_sha256=request.retrieval_attempt_artifact_sha256,
            expected=RetrievalAttemptBinding(
                candidate_build_id=candidate.candidate_build_id,
                candidate_seal_sha256=candidate.candidate_seal_sha256,
                source_manifest_sha256=candidate.source_manifest_sha256,
                case_ref=case_ref,
                issue_ref=issue_ref,
                subject=subject,
                jurisdiction=jurisdiction,
                as_of_date=request.as_of_date,
                proposition_sha256=request.proposition_sha256,
                query_sha256=request.retrieval_query_sha256,
            ),
        )
        detail_sha256 = hashlib.sha256(detail.encode("utf-8")).hexdigest()
        identity = {
            "candidate_build_id": request.candidate_build_id,
            "candidate_seal_sha256": candidate.candidate_seal_sha256,
            "source_manifest_sha256": candidate.source_manifest_sha256,
            "case_id": case_ref,
            "issue_id": issue_ref,
            "subject": subject,
            "jurisdiction": jurisdiction,
            "as_of_date": request.as_of_date.isoformat(),
            "retrieval_query_sha256": request.retrieval_query_sha256,
            "proposition_sha256": request.proposition_sha256,
            "retrieval_attempt_artifact_sha256": (request.retrieval_attempt_artifact_sha256),
            "materiality": request.materiality.value,
        }
        fingerprint = _canonical_json_sha256(identity)
        return self.database.store_research_gap_binding(
            gap_id=f"research-gap-{fingerprint[:40]}",
            fingerprint_sha256=fingerprint,
            candidate_build_id=request.candidate_build_id,
            source_manifest_sha256=candidate.source_manifest_sha256,
            case_id=case_ref,
            issue_id=issue_ref,
            subject=subject,
            jurisdiction=jurisdiction,
            as_of_date=request.as_of_date.isoformat(),
            attempted_retrieval_sha256=request.retrieval_attempt_artifact_sha256,
            materiality=request.materiality.value,
            detail_sha256=detail_sha256,
            encrypted_detail=self.cipher.encrypt_text(detail),
        )

    def admit(self, request: ResearchTaskRequest) -> Any:
        policy = self.registry.get(request.source_id) if request.source_id else None
        origin_host = None
        if policy is not None:
            origin_host = urlsplit(policy.base_url).hostname
        subject = " ".join(request.subject.split()).casefold()
        jurisdiction = " ".join(request.jurisdiction.split())
        if (
            not subject
            or len(subject) > 80
            or scrub_pii(subject) != subject
            or subject not in RESEARCH_SUBJECT_TAXONOMY
            or not jurisdiction
            or len(jurisdiction) > 80
            or scrub_pii(jurisdiction) != jurisdiction
        ):
            raise ValueError("research taxonomy or jurisdiction is unsafe")
        public_query = " ".join((request.public_query or "").split())
        authority_identity = " ".join((request.authority_identity_id or "").split())
        if authority_identity and (
            len(authority_identity) > 255
            or scrub_pii(authority_identity) != authority_identity
            or not _PUBLIC_AUTHORITY_ID.fullmatch(authority_identity)
        ):
            raise ValueError("research authority identity is not a public stable identifier")
        if request.knowledge_gap_id and not _SAFE_REFERENCE.fullmatch(request.knowledge_gap_id):
            raise ValueError("research knowledge-gap reference is unsafe")
        gap_snapshot: ActiveResearchSnapshot | None = None
        gap_binding: _OpenGapBinding | None = None
        # Legacy/local staging records never enter the crawler queue.  If one
        # were ever made dispatchable, dispatch-time revalidation below still
        # refuses it without a live material gap.
        if self._requires_gap(request.task_type, request.trigger) and not request.staging_only:
            if not request.knowledge_gap_id:
                raise ValueError("research crawl requires an existing knowledge-gap identity")
            gap_binding = self._open_gap_binding(
                request.knowledge_gap_id,
                subject=subject,
                jurisdiction=jurisdiction,
                as_of_date=request.as_of_date.isoformat(),
            )
            gap_snapshot = ActiveResearchSnapshot(
                gap_binding.candidate_build_id, gap_binding.source_manifest_sha256
            )
        if request.idempotency_key and not _SAFE_REFERENCE.fullmatch(request.idempotency_key):
            raise ValueError("research idempotency key is unsafe")
        source_locator = (request.source_locator or "").strip().strip("/")
        if source_locator and (
            len(source_locator) > 255
            or ".." in source_locator
            or "?" in source_locator
            or "#" in source_locator
            or scrub_pii(source_locator) != source_locator
        ):
            raise ValueError("official source locator is unsafe")
        if public_query:
            if (
                len(public_query) > 160
                or scrub_pii(public_query) != public_query
                or public_query.casefold() not in RESEARCH_PUBLIC_QUERIES
            ):
                raise ValueError("research query must come from the registered public taxonomy")
            query_digest = hashlib.sha256(public_query.encode("utf-8")).hexdigest()
        elif request.query_sha256 and _SHA256.fullmatch(request.query_sha256):
            query_digest = request.query_sha256
        else:
            material = "\0".join(
                (
                    subject,
                    request.source_id or "",
                    authority_identity,
                )
            )
            query_digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
        if gap_binding is not None and gap_binding.retrieval_query_sha256 != query_digest:
            raise ValueError("research crawl query changed from the sealed candidate attempt")
        encrypted_query = (
            self.cipher.encrypt_text(public_query) if public_query and self.cipher else None
        )
        snapshot = gap_snapshot or self.active_snapshot()
        identity_material = {
            "task_type": request.task_type.value,
            "trigger": request.trigger.value,
            "priority": request.priority.value,
            "subject": subject,
            "jurisdiction": jurisdiction,
            "as_of_date": request.as_of_date.isoformat(),
            "source_id": request.source_id,
            "authority_identity_id": authority_identity or None,
            "source_locator": source_locator or None,
            "knowledge_gap_id": request.knowledge_gap_id,
            "answer_id": request.answer_id,
            "answer_job_id": request.answer_job_id,
            "query_sha256": query_digest,
            "pinned_index_build_id": snapshot.build_id,
            "source_manifest_sha256": snapshot.source_manifest_sha256,
            "staging_only": request.staging_only,
        }
        # Client retry keys are not task identities. The server derives one
        # canonical key from the pinned legal/update request so repeated owner
        # clicks with different UUIDs cannot fill the 20-slot queue.
        idempotency_key = _canonical_json_sha256(identity_material)
        task_id = f"research-{uuid.uuid4().hex}"
        return self.database.enqueue_research_task(
            task_id=task_id,
            idempotency_key=idempotency_key,
            task_type=request.task_type.value,
            trigger_kind=request.trigger.value,
            priority_band=request.priority.value,
            subject=subject,
            jurisdiction=jurisdiction,
            as_of_date=request.as_of_date.isoformat(),
            query_sha256=query_digest,
            encrypted_query=encrypted_query,
            source_id=request.source_id,
            origin_host=origin_host,
            authority_identity_id=authority_identity or None,
            source_locator=source_locator or None,
            knowledge_gap_id=request.knowledge_gap_id,
            answer_id=request.answer_id,
            answer_job_id=request.answer_job_id,
            refinement_id=request.refinement_id,
            pinned_index_build_id=snapshot.build_id,
            source_manifest_sha256=snapshot.source_manifest_sha256,
            initial_status="staging_sync" if request.staging_only else None,
        )

    def assert_task_gap_open(self, task: Mapping[str, Any]) -> None:
        """Revalidate a queued gap immediately before any network dispatch."""

        task_data = dict(task)
        task_type = ResearchTaskType(str(task_data["task_type"]))
        trigger = ResearchTrigger(str(task_data["trigger_kind"]))
        gap_id = str(task_data.get("knowledge_gap_id") or "")
        if not self._requires_gap(task_type, trigger) and not gap_id:
            return
        if not gap_id:
            raise ValueError("research crawl has no knowledge-gap binding")
        gap = self._open_gap_binding(
            gap_id,
            subject=" ".join(str(task_data["subject"]).casefold().split()),
            jurisdiction=" ".join(str(task_data["jurisdiction"]).split()),
            as_of_date=str(task_data["as_of_date"]),
        )
        pinned_build = str(task_data.get("pinned_index_build_id") or "") or None
        pinned_manifest = str(task_data.get("source_manifest_sha256") or "") or None
        if gap.candidate_build_id is not None and gap.candidate_build_id != pinned_build:
            raise ValueError("research crawl candidate binding changed while queued")
        if gap.source_manifest_sha256 is not None and gap.source_manifest_sha256 != pinned_manifest:
            raise ValueError("research crawl source manifest changed while queued")
        queued_query = str(task_data.get("query_sha256") or "")
        if gap.retrieval_query_sha256 != queued_query:
            raise ValueError("research crawl query changed from the sealed candidate attempt")

    @staticmethod
    def _requires_gap(task_type: ResearchTaskType, trigger: ResearchTrigger) -> bool:
        return task_type is ResearchTaskType.GAP_RESEARCH or (
            task_type is ResearchTaskType.BROAD_DISCOVERY
            and trigger in {ResearchTrigger.MANUAL, ResearchTrigger.ENQUIRY}
        )

    def _open_gap_binding(
        self,
        gap_id: str,
        *,
        subject: str,
        jurisdiction: str,
        as_of_date: str,
    ) -> _OpenGapBinding:
        bound = self.database.research_gap_binding(gap_id)
        if bound is not None:
            if (
                str(bound["status"]) not in {"open", "triaged", "source_needed"}
                or str(bound["subject"]) != subject
                or str(bound["jurisdiction"]) != jurisdiction
                or str(bound["as_of_date"]) != as_of_date
                or str(bound["materiality"]) == GapMateriality.NON_MATERIAL.value
            ):
                raise ValueError("research crawl is not bound to this open material gap")
            candidate_build_id = str(bound["candidate_build_id"])
            candidate = self._candidate_binding(candidate_build_id)
            source_manifest_sha256 = str(bound["source_manifest_sha256"])
            if source_manifest_sha256 != candidate.source_manifest_sha256:
                raise ValueError("research gap candidate source manifest changed")
            artifact_sha256 = str(bound["attempted_retrieval_sha256"])
            artifact = load_verified_candidate_retrieval_attempt(
                settings=self.settings,
                artifact_sha256=artifact_sha256,
                expected=RetrievalAttemptBinding(
                    candidate_build_id=candidate_build_id,
                    candidate_seal_sha256=candidate.candidate_seal_sha256,
                    source_manifest_sha256=source_manifest_sha256,
                    case_ref=str(bound["case_id"]),
                    issue_ref=str(bound["issue_id"]),
                    subject=str(bound["subject"]),
                    jurisdiction=str(bound["jurisdiction"]),
                    as_of_date=date.fromisoformat(str(bound["as_of_date"])),
                ),
            )
            return _OpenGapBinding(
                gap_id=gap_id,
                subject=str(bound["subject"]),
                jurisdiction=str(bound["jurisdiction"]),
                as_of_date=str(bound["as_of_date"]),
                candidate_build_id=candidate_build_id,
                candidate_seal_sha256=candidate.candidate_seal_sha256,
                source_manifest_sha256=source_manifest_sha256,
                retrieval_attempt_artifact_sha256=artifact_sha256,
                retrieval_query_sha256=artifact.query_sha256,
                proposition_sha256=artifact.proposition_sha256,
                materiality=str(bound["materiality"]),
            )
        raise ValueError("research crawl requires a verified candidate retrieval-attempt gap")

    def stage_candidate(self, task_id: str, draft: ResearchCandidateDraft) -> Any:
        policy = self.registry.get(draft.source_id)
        source_identity = " ".join(draft.source_identity.split())
        if (
            not source_identity
            or len(source_identity) > 255
            or scrub_pii(source_identity) != source_identity
        ):
            raise ValueError("research candidate identity is unsafe")
        canonical_url = scrub_candidate_url(draft.canonical_url)
        registered = urlsplit(policy.base_url)
        candidate = urlsplit(canonical_url)
        if (candidate.hostname or "").casefold() != (
            registered.hostname or ""
        ).casefold() or not _path_is_within(candidate.path, registered.path):
            raise ValueError("research candidate escaped its registered source")
        safe_metadata_json = json.dumps(dict(draft.safe_metadata), sort_keys=True)
        assert_review_payload_safe(safe_metadata_json)
        candidate_id = _stable_id("candidate", task_id, draft.source_id, source_identity)
        return self.database.add_research_candidate(
            candidate_id=candidate_id,
            task_id=task_id,
            source_id=draft.source_id,
            source_identity=source_identity,
            canonical_url=canonical_url,
            metadata_sha256=draft.metadata_sha256,
            content_sha256=draft.content_sha256,
            content_object_key=draft.content_object_key,
            status=draft.status.value,
            rights_state=draft.rights_state,
            safe_metadata=draft.safe_metadata,
        )

    def compare_remote(
        self,
        task: Mapping[str, Any],
        *,
        source_id: str,
        authority_identity_id: str,
        remote_content_sha256: str | None,
        withdrawn: bool = False,
        legal_locator: str | None = None,
        proposition_sha256: str | None = None,
    ) -> SourceUpdateDraft:
        task_data = dict(task)
        pinned_build = str(task_data.get("pinned_index_build_id") or "") or None
        pinned_manifest = str(task_data.get("source_manifest_sha256") or "") or None
        current = self.active_snapshot()
        stale = (
            pinned_build != current.build_id or pinned_manifest != current.source_manifest_sha256
        )
        baseline = self._baseline_version(
            pinned_build,
            pinned_manifest,
            authority_identity_id,
        )
        if withdrawn:
            state = SourceUpdateState.WITHDRAWN
        elif remote_content_sha256 is None or not _SHA256.fullmatch(remote_content_sha256):
            state = SourceUpdateState.UNKNOWN
        elif baseline is None:
            state = SourceUpdateState.NEW
        elif baseline == remote_content_sha256:
            state = SourceUpdateState.UNCHANGED
        else:
            state = SourceUpdateState.CHANGED
        return SourceUpdateDraft(
            source_id=source_id,
            authority_identity_id=authority_identity_id,
            comparison_state=state,
            baseline_version_sha256=baseline,
            remote_content_sha256=remote_content_sha256,
            observed_active_build_id=current.build_id,
            stale_active=stale,
            scope_kind=("proposition" if proposition_sha256 is not None else "authority"),
            legal_locator=legal_locator,
            proposition_sha256=proposition_sha256,
            safe_detail={
                "recompare_required": stale,
                "scope_kind": ("proposition" if proposition_sha256 is not None else "authority"),
            },
        )

    def persist_update(
        self,
        task: Mapping[str, Any],
        draft: SourceUpdateDraft,
        *,
        candidate_id: str | None = None,
    ) -> str:
        task_data = dict(task)
        assert_review_payload_safe(json.dumps(dict(draft.safe_detail), sort_keys=True))
        observation_id = _stable_id(
            "source-update",
            str(task_data["id"]),
            draft.source_id,
            draft.authority_identity_id,
            draft.remote_content_sha256 or "unknown",
        )
        review_not_required = (
            draft.comparison_state is SourceUpdateState.UNCHANGED and not draft.stale_active
        )
        self.database.add_source_update_observation(
            observation_id=observation_id,
            task_id=str(task_data["id"]),
            candidate_id=candidate_id,
            source_id=draft.source_id,
            authority_identity_id=draft.authority_identity_id,
            pinned_index_build_id=(str(task_data.get("pinned_index_build_id") or "") or None),
            pinned_source_manifest_sha256=(
                str(task_data.get("source_manifest_sha256") or "") or None
            ),
            observed_active_build_id=draft.observed_active_build_id,
            baseline_version_sha256=draft.baseline_version_sha256,
            remote_content_sha256=draft.remote_content_sha256,
            comparison_state=draft.comparison_state.value,
            stale_active=draft.stale_active,
            scope_kind=draft.scope_kind,
            legal_locator=draft.legal_locator,
            proposition_sha256=draft.proposition_sha256,
            materiality_status=("non_material" if review_not_required else "unassessed"),
            review_status=("not_required" if review_not_required else "pending"),
            safe_detail=draft.safe_detail,
        )
        if candidate_id is not None:
            self.database.execute(
                "UPDATE research_candidates SET comparison_state=?, updated_at=? WHERE id=?",
                (draft.comparison_state.value, self._now_iso(), candidate_id),
            )
        return observation_id

    def _baseline_version(
        self,
        build_id: str | None,
        expected_manifest_sha256: str | None,
        authority_identity_id: str,
    ) -> str | None:
        if build_id is None or expected_manifest_sha256 is None:
            return None
        path = self.settings.index_dir / "builds" / build_id / "approved-source-manifest.json"
        if not path.is_file() or not path.resolve().is_relative_to(
            (self.settings.index_dir / "builds").resolve()
        ):
            raise RuntimeError("pinned approved-source manifest is unavailable")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if (
            payload.get("manifest_sha256") != expected_manifest_sha256
            or approved_source_manifest_sha256(payload) != expected_manifest_sha256
        ):
            raise RuntimeError("pinned approved-source manifest digest changed")
        for source in payload.get("sources", []):
            if source.get("authority_identity_id") != authority_identity_id:
                continue
            digest = str(source.get("version_sha256") or source.get("content_sha256") or "")
            if not _SHA256.fullmatch(digest):
                raise RuntimeError("pinned source version has no valid digest")
            return digest
        return None

    @staticmethod
    def _now_iso() -> str:
        from datetime import UTC, datetime

        return datetime.now(UTC).isoformat()
