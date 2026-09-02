"""Authoritative evidence/reviewer gates for exact all-60 qualification.

This module deliberately does not use retrieval rankings. It freezes exact
candidate-resident spans selected by the independent gold overlay, verifies
their sealed candidate/source/currentness/rights identities, and then requires
one real v3 AI evidence-review checkpoint for each of the 585 issue claims.
Stage A may subsequently measure retrieval of those spans, but it cannot
create or qualify them.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from types import MappingProxyType
from typing import Any

from ..legal_roles import MATERIAL_CASE_ROLES
from ..quality.ai_evidence_reviewer import (
    FrozenClaimReviewInput,
    ai_evidence_reviewer_prompt_sha256,
    ai_evidence_reviewer_toolchain_sha256,
    freeze_material_claims,
    frozen_claim_bundle_sha256,
)
from ..quality.draft_identity import source_draft_sha256
from ..quality.evidence import is_substantively_related, substantive_tokens
from ..quality.policy import POLICY_SHA256
from ..retrieval.ge_generic_read_guard import require_generic_index_read_allowed
from ..retrieval.source_manifest import (
    MANIFEST_SCHEMA,
    OFFICIAL_JUDGMENT_LICENCE_PREFIXES,
    OGL_LICENCE_PREFIX,
    approved_source_manifest_sha256,
)
from ..types import EvidenceSpan, MaterialLane, StructuredClaimDraft, StructuredDraft, TaskType
from ..types import StructuredSectionDraft as DraftSection
from .live_suite import LiveEvaluationBundle, sealed_sha256
from .live_suite_gold import LiveGoldSpan, LiveSuiteExpertQualification
from .sealed_candidate import SealedCandidateIdentity

OWNER_DECISION_REQUIRED = "OWNER_DECISION_REQUIRED"
REQUIRED_AI_REASON_CODES = frozenset(
    {
        "issue_relevance_supported",
        "contrary_authority_checked",
        "currentness_inputs_checked",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_CITABLE_LANES = frozenset(
    {
        MaterialLane.PRIMARY_AUTHORITY.value,
        MaterialLane.OFFICIAL_SECONDARY.value,
        MaterialLane.SCHOLARSHIP.value,
    }
)


class All60OwnerDecisionRequired(ValueError):
    """A legal currentness/rights judgment cannot be inferred technically."""

    def __init__(self, reason_code: str, *, row_id: str, decision_id: str | None = None) -> None:
        self.reason_code = reason_code
        self.row_id = row_id
        self.decision_id = decision_id
        super().__init__(f"{OWNER_DECISION_REQUIRED}:{reason_code}:{row_id}")


@dataclass(frozen=True, slots=True)
class VerifiedAll60IssueReview:
    row_id: str
    claim_sha256: str
    evidence_bundle_sha256: str
    checkpoint_seal_sha256: str
    model_id: str
    model_version: str
    prompt_sha256: str
    policy_sha256: str
    toolchain_sha256: str
    cited_evidence_ids: tuple[str, ...]
    invocation_id: str
    deterministic_gate_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedAll60EvidenceReviews:
    issues: Mapping[str, VerifiedAll60IssueReview]
    candidate_source_manifest_file_sha256: str
    candidate_lance_tree_sha256: str
    provision_verification_sha256: str
    deterministic_gate_set_sha256: str
    ai_review_set_sha256: str
    ai_review_batch_attestation_seal_sha256: str
    ai_review_batch_manifest_seal_sha256: str
    ai_review_batch_checkpoint_set_sha256: str
    ai_review_batch_intent_ledger_sha256: str
    ai_review_batch_outcome_ledger_sha256: str
    ai_review_batch_launcher_start_sha256: str
    ai_review_batch_launcher_end_sha256: str


@dataclass(frozen=True, slots=True)
class All60ReviewerBatchInput:
    """One exact candidate-gated input for the owned 585-review producer."""

    ordinal: int
    row_id: str
    case_id: str
    issue_id: str
    issue_identity_sha256: str
    deterministic_gate_sha256: str
    draft: StructuredDraft
    frozen_claim: FrozenClaimReviewInput
    evidence_by_id: Mapping[str, EvidenceSpan]


@dataclass(frozen=True, slots=True)
class _CandidateContext:
    candidate_build_id: str
    rows: Mapping[str, Mapping[str, Any]]
    sources: Mapping[str, Mapping[str, Any]]
    provisions: Mapping[tuple[str, str], Mapping[str, Any]]
    source_manifest_file_sha256: str
    lance_tree_sha256: str
    provision_sha256: str
    current_law_as_of_date: str


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tree_sha256(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("all-60 candidate Lance tree is missing")
    members = sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: item.as_posix(),
    )
    if not members or any(item.is_symlink() for item in root.rglob("*")):
        raise ValueError("all-60 candidate Lance tree is unsafe")
    digest = hashlib.sha256()
    for member in members:
        relative = member.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(_file_sha256(member)))
    return digest.hexdigest()


def _json_object(path: Path, *, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"all-60 candidate {label} is missing")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"all-60 candidate {label} is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError(f"all-60 candidate {label} is invalid")
    return value


def _load_candidate_rows(root: Path, chunk_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    require_generic_index_read_allowed(root, expected_build_id=root.name)
    authority = root / "lance" / "authority"
    if not authority.is_dir() or authority.is_symlink():
        raise ValueError("all-60 candidate authority lane is missing")
    try:
        import lancedb  # type: ignore[import-untyped]

        table = lancedb.connect(str(authority)).open_table("chunks")
    except Exception as exc:
        raise ValueError("all-60 candidate authority table is unavailable") from exc
    columns = [
        "chunk_id",
        "source_version_id",
        "source_identity",
        "text",
        "content_sha256",
        "locator",
        "catalog_lane",
        "catalog_jurisdiction",
        "currentness_status",
        "identity_verified",
        "currentness_verified",
        "legal_role",
        "case_currentness_reviews_json",
        "case_currentness_manifest_seals_json",
    ]
    # These release-facing fields were added to the sealed Lance row before
    # v1.11.  Older synthetic qualification fixtures can omit them because
    # LiveGoldSpan qualification does not render a citation; authoritative
    # runtime EvidenceSpan replay below fails closed when any is absent.
    available_columns = set(table.schema.names)
    columns.extend(
        column
        for column in (
            "citation_json",
            "canonical_citation",
            "canonical_url",
            "subject",
        )
        if column in available_columns
    )
    output: dict[str, dict[str, Any]] = {}
    unique_ids = tuple(dict.fromkeys(chunk_ids))
    for offset in range(0, len(unique_ids), 100):
        batch = unique_ids[offset : offset + 100]
        if any(not _SAFE_ID.fullmatch(value) for value in batch):
            raise ValueError("all-60 gold contains an unsafe chunk identity")
        sql = ",".join(f"'{value.replace(chr(39), chr(39) * 2)}'" for value in batch)
        try:
            rows = (
                table.search()
                .where(f"chunk_id IN ({sql})")
                .select(columns)
                .limit(len(batch) + 1)
                .to_list()
            )
        except Exception as exc:
            raise ValueError("all-60 candidate membership lookup failed") from exc
        for raw in rows:
            row = dict(raw)
            chunk_id = str(row.get("chunk_id") or "")
            if chunk_id in output:
                raise ValueError("all-60 candidate contains duplicate chunk identities")
            output[chunk_id] = row
    if set(output) != set(unique_ids):
        raise ValueError("all-60 gold span is absent from the exact sealed candidate")
    return output


def _candidate_context(
    *,
    candidate: SealedCandidateIdentity,
    candidate_build_root: Path,
    spans: Sequence[LiveGoldSpan | EvidenceSpan],
) -> _CandidateContext:
    if (
        candidate_build_root.is_symlink()
        or not candidate_build_root.is_dir()
        or candidate_build_root.name != candidate.build_id
    ):
        raise ValueError("all-60 candidate build root is not exact")
    manifest_path = candidate_build_root / "manifest.json"
    seal_path = candidate_build_root / "seal.json"
    source_path = candidate_build_root / "approved-source-manifest.json"
    provision_path = candidate_build_root / "provision-verification.v1.json"
    manifest = _json_object(manifest_path, label="manifest")
    seal = _json_object(seal_path, label="seal")
    source_manifest = _json_object(source_path, label="source manifest")
    provisions = _json_object(provision_path, label="provision registry")
    manifest_sha256 = _file_sha256(manifest_path)
    seal_sha256 = _file_sha256(seal_path)
    source_file_sha256 = _file_sha256(source_path)
    provision_sha256 = _file_sha256(provision_path)
    lance_sha256 = _tree_sha256(candidate_build_root / "lance")
    if (
        manifest_sha256 != candidate.candidate_manifest_sha256
        or seal_sha256 != candidate.candidate_seal_sha256
        or manifest.get("build_id") != candidate.build_id
        or manifest.get("source_manifest_sha256") != candidate.source_manifest_sha256
        or int(manifest.get("chunk_count") or 0) != candidate.chunk_count
        or seal.get("build_id") != candidate.build_id
        or seal.get("manifest_sha256") != manifest_sha256
        or seal.get("source_manifest_file_sha256") != source_file_sha256
        or seal.get("provision_verification_sha256") != provision_sha256
        or seal.get("lance_tree_sha256") != lance_sha256
        or source_manifest.get("schema") != MANIFEST_SCHEMA
        or source_manifest.get("manifest_sha256")
        != approved_source_manifest_sha256(source_manifest)
        or source_manifest.get("manifest_sha256") != candidate.source_manifest_sha256
        or source_manifest.get("authority_lane_only") is not True
        or source_manifest.get("benchmark_answers_used_for_selection") is not False
    ):
        raise ValueError("all-60 candidate durable identities do not reconcile")
    raw_sources = source_manifest.get("sources")
    if not isinstance(raw_sources, list):
        raise ValueError("all-60 candidate source inventory is invalid")
    sources: dict[str, Mapping[str, Any]] = {}
    for raw in raw_sources:
        if not isinstance(raw, Mapping):
            raise ValueError("all-60 candidate source inventory is invalid")
        source_version_id = str(raw.get("source_version_id") or "")
        if not source_version_id or source_version_id in sources:
            raise ValueError("all-60 candidate source identities are duplicated")
        sources[source_version_id] = raw
    raw_records = provisions.get("records")
    provision_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
    if not isinstance(raw_records, list):
        raise ValueError("all-60 candidate provision registry is invalid")
    for raw in raw_records:
        if not isinstance(raw, Mapping):
            continue
        key = (str(raw.get("stable_source_id") or ""), str(raw.get("legal_locator") or ""))
        if all(key):
            if key in provision_by_key:
                raise ValueError("all-60 provision registry contains duplicate locators")
            provision_by_key[key] = raw
    rows = _load_candidate_rows(
        candidate_build_root,
        tuple(span.chunk_id for span in spans),
    )
    return _CandidateContext(
        candidate_build_id=candidate.build_id,
        rows=rows,
        sources=sources,
        provisions=provision_by_key,
        source_manifest_file_sha256=source_file_sha256,
        lance_tree_sha256=lance_sha256,
        provision_sha256=provision_sha256,
        current_law_as_of_date=str(source_manifest.get("current_law_as_of_date") or ""),
    )


def verify_runtime_candidate_evidence_spans(
    *,
    candidate: SealedCandidateIdentity,
    candidate_build_root: Path,
    evidence: Sequence[EvidenceSpan],
    required_as_of_date: date,
) -> None:
    """Prove runtime EvidenceSpans are exact members of the sealed Lance build."""

    if not evidence or len({item.id for item in evidence}) != len(evidence):
        raise ValueError("runtime candidate evidence inventory is empty or duplicated")
    context = _candidate_context(
        candidate=candidate,
        candidate_build_root=candidate_build_root,
        spans=evidence,
    )
    if context.current_law_as_of_date != required_as_of_date.isoformat():
        raise ValueError("runtime candidate current-law date differs")
    for span in evidence:
        if span.index_build_id != candidate.build_id:
            raise ValueError("runtime evidence names another candidate")
        row = context.rows.get(span.chunk_id)
        source = context.sources.get(span.source_version_id)
        if row is None or source is None:
            raise ValueError("runtime evidence is outside the sealed candidate")
        text = str(row.get("text") or "")
        lane = str(row.get("catalog_lane") or "")
        try:
            citation_data = json.loads(str(row.get("citation_json") or ""))
        except json.JSONDecodeError as exc:
            raise ValueError("runtime candidate citation metadata is invalid") from exc
        if not isinstance(citation_data, dict):
            raise ValueError("runtime candidate citation metadata is not an object")
        reviews = json.loads(str(row.get("case_currentness_reviews_json") or "[]"))
        seals = json.loads(str(row.get("case_currentness_manifest_seals_json") or "[]"))
        expected_reviews = [
            item.model_dump(mode="json", by_alias=True) for item in span.case_currentness_reviews
        ]
        stable_identifier = str(source.get("stable_identifier") or "")
        provision = context.provisions.get((stable_identifier, span.locator))
        expected_unapplied_effect_count = (
            int(provision.get("section_unapplied_effect_count") or 0)
            if provision is not None
            else (
                int(source["unapplied_effect_count"])
                if source.get("unapplied_effect_count") is not None
                else None
            )
        )
        expected_provision_extent_status = (
            "england_and_wales_verified"
            if provision is not None
            else str(source.get("provision_extent_status") or "unverified")
        )
        if (
            str(row.get("source_version_id") or "") != span.source_version_id
            or str(row.get("chunk_id") or "") != span.chunk_id
            or text != span.text
            or hashlib.sha256(text.encode("utf-8")).hexdigest() != span.content_sha256
            or str(row.get("content_sha256") or "") != span.content_sha256
            or str(row.get("locator") or "").strip() != span.locator.strip()
            or citation_data != span.citation_data
            or (str(row.get("canonical_citation") or "") or None) != span.canonical_citation
            or (str(row.get("canonical_url") or "") or None) != span.canonical_url
            or lane != str(span.lane)
            or lane not in _CITABLE_LANES
            or str(row.get("catalog_jurisdiction") or "") != span.jurisdiction
            or str(row.get("subject") or "") != span.subject
            or str(row.get("legal_role") or "") != span.legal_role
            or str(row.get("currentness_status") or "") != span.currentness_status
            or expected_unapplied_effect_count != span.unapplied_effect_count
            or expected_provision_extent_status != span.provision_extent_status
            or not span.identity_verified
            or not span.currentness_verified
            or str(source.get("jurisdiction") or "") != span.jurisdiction
            or row.get("identity_verified") is not True
            or row.get("currentness_verified") is not True
            or source.get("identity_verified") is not True
            or source.get("currentness_verified") is not True
            or source.get("currentness_reviewed_as_of_date") != required_as_of_date.isoformat()
            or source.get("document_status") != "citable"
            or source.get("lane") != lane
            or reviews != expected_reviews
            or seals != list(span.case_currentness_manifest_seals)
        ):
            raise ValueError("runtime evidence differs from its exact Lance/source identity")
        licence = str(source.get("licence_name") or "")
        source_type = str(span.citation_data.get("source_type") or "")
        official_rights = (
            (
                source_type == "legislation"
                and stable_identifier.startswith(("ukpga:", "uksi:"))
                and licence.startswith(OGL_LICENCE_PREFIX)
            )
            or (
                source_type == "case"
                and stable_identifier.startswith("neutral-citation:")
                and licence.startswith(OFFICIAL_JUDGMENT_LICENCE_PREFIXES)
            )
            or (
                source_type not in {"legislation", "case"}
                and licence.startswith((OGL_LICENCE_PREFIX, *OFFICIAL_JUDGMENT_LICENCE_PREFIXES))
            )
        )
        if not official_rights:
            raise All60OwnerDecisionRequired("SOURCE_RIGHTS_NOT_DETERMINISTIC", row_id=span.id)


def _rights_are_verified(span: LiveGoldSpan, source: Mapping[str, Any]) -> bool:
    licence = str(source.get("licence_name") or "")
    stable_identifier = str(source.get("stable_identifier") or "")
    if span.source_type == "legislation":
        return (
            stable_identifier.startswith("ukpga:") or stable_identifier.startswith("uksi:")
        ) and licence.startswith(OGL_LICENCE_PREFIX)
    if span.source_type == "case":
        return stable_identifier.startswith("neutral-citation:") and licence.startswith(
            OFFICIAL_JUDGMENT_LICENCE_PREFIXES
        )
    return licence.startswith((OGL_LICENCE_PREFIX, *OFFICIAL_JUDGMENT_LICENCE_PREFIXES))


def _case_review_is_in_candidate(span: LiveGoldSpan, row: Mapping[str, Any]) -> bool:
    review = span.case_currentness_review
    if review is None:
        return False
    try:
        raw = json.loads(str(row.get("case_currentness_reviews_json") or "[]"))
    except json.JSONDecodeError:
        return False
    if not isinstance(raw, list):
        return False
    expected = review.model_dump(mode="json", by_alias=True)
    return any(isinstance(item, Mapping) and dict(item) == expected for item in raw)


def _verified_provision(
    *, span: LiveGoldSpan, source: Mapping[str, Any], context: _CandidateContext
) -> bool:
    key = (str(source.get("stable_identifier") or ""), span.legal_locator)
    record = context.provisions.get(key)
    if record is None:
        return False
    extent = str(record.get("verified_extent") or "")
    return (
        "E+W" in extent
        and int(record.get("section_unapplied_effect_count") or 0) == 0
        and record.get("unapplied_effect_materiality") == "none_recorded"
        and record.get("source_content_sha256") == source.get("content_sha256")
        and record.get("source_version_sha256") == source.get("version_sha256")
    )


def _gate_span(
    *,
    span: LiveGoldSpan,
    row_id: str,
    required_as_of_date: date,
    context: _CandidateContext,
) -> tuple[EvidenceSpan, str]:
    row = context.rows[span.chunk_id]
    source = context.sources.get(span.source_version_id)
    if source is None:
        raise ValueError("all-60 span source version is outside candidate source manifest")
    text = str(row.get("text") or "")
    lane = str(row.get("catalog_lane") or "")
    source_jurisdiction = str(source.get("jurisdiction") or "")
    row_jurisdiction = str(row.get("catalog_jurisdiction") or "")
    if (
        str(row.get("source_version_id") or "") != span.source_version_id
        or str(row.get("content_sha256") or "") != span.content_sha256
        or hashlib.sha256(text.encode("utf-8")).hexdigest() != span.content_sha256
        or str(row.get("locator") or "").strip() != span.legal_locator
        or str(row.get("legal_role") or "") != span.legal_role
        or row.get("identity_verified") is not True
        or source.get("identity_verified") is not True
        or source.get("document_status") != "citable"
        or source.get("lane") != lane
        or lane not in _CITABLE_LANES
        or row_jurisdiction != source_jurisdiction
    ):
        raise ValueError("all-60 span failed candidate identity/lane/locator gates")
    if not _rights_are_verified(span, source):
        raise All60OwnerDecisionRequired("SOURCE_RIGHTS_NOT_DETERMINISTIC", row_id=row_id)
    currentness_gate: str
    if span.source_type == "legislation":
        if (
            context.current_law_as_of_date != required_as_of_date.isoformat()
            or source.get("currentness_verified") is not True
            or source.get("currentness_reviewed_as_of_date") != required_as_of_date.isoformat()
            or row.get("currentness_verified") is not True
            or int(source.get("unapplied_effect_count") or 0) != 0
            or not _verified_provision(span=span, source=source, context=context)
        ):
            raise All60OwnerDecisionRequired("LEGAL_CURRENTNESS_NOT_DETERMINISTIC", row_id=row_id)
        currentness_gate = "legislation-currentness-and-extent-v1"
    elif span.source_type == "case" and span.legal_role in MATERIAL_CASE_ROLES:
        review = span.case_currentness_review
        if (
            review is None
            or review.later_treatment_reviewed_as_of_date != required_as_of_date
            or review.later_treatment_status not in {"confirmed_current", "qualified_current"}
            or not review.qualifies_for_present_law
            or not _case_review_is_in_candidate(span, row)
        ):
            raise All60OwnerDecisionRequired("CASE_CURRENTNESS_NOT_DETERMINISTIC", row_id=row_id)
        currentness_gate = "candidate-bound-case-proposition-review-v1"
    elif (
        source.get("currentness_verified") is not True
        or source.get("currentness_reviewed_as_of_date") != required_as_of_date.isoformat()
        or row.get("currentness_verified") is not True
    ):
        raise All60OwnerDecisionRequired("LEGAL_CURRENTNESS_NOT_DETERMINISTIC", row_id=row_id)
    else:
        currentness_gate = "source-currentness-v1"
    evidence = EvidenceSpan(
        id=span.gold_span_id,
        source_version_id=span.source_version_id,
        chunk_id=span.chunk_id,
        text=text,
        locator=span.legal_locator,
        lane=MaterialLane(lane),
        jurisdiction="England and Wales",
        subject="evaluation",
        currentness_status=str(row.get("currentness_status") or "verified"),
        content_sha256=span.content_sha256,
        index_build_id=context.candidate_build_id,
        legal_role=span.legal_role,
        provision_extent_status="verified_ew"
        if span.source_type == "legislation"
        else "not_applicable",
        identity_verified=True,
        currentness_verified=True,
        case_currentness_reviews=(
            (span.case_currentness_review,) if span.case_currentness_review is not None else ()
        ),
    )
    gate_sha = sealed_sha256(
        {
            "schema": "legalbot.live60-deterministic-span-gate.v1",
            "row_id": row_id,
            "gold_span_id": span.gold_span_id,
            "candidate_chunk_id": span.chunk_id,
            "candidate_content_sha256": span.content_sha256,
            "candidate_source_version_id": span.source_version_id,
            "locator_sha256": hashlib.sha256(span.legal_locator.encode("utf-8")).hexdigest(),
            "lane": lane,
            "source_rights": "verified_official_licence",
            "jurisdiction": "England and Wales",
            "currentness_gate": currentness_gate,
            "contrary_or_limiting": span.contrary_or_limiting,
        }
    )
    return evidence, gate_sha


def _issue_span_is_related(topic: str, span: EvidenceSpan) -> bool:
    if is_substantively_related(topic, span):
        return True
    topic_tokens = set(substantive_tokens(topic))
    span_tokens = set(substantive_tokens(f"{span.text}\n{span.locator}"))
    return bool(topic_tokens) and topic_tokens.issubset(span_tokens)


def all60_issue_identity_sha256(
    *, case_id: str, issue_id: str, question_sha256: str, record_sha256: str, topic: str
) -> str:
    """Return the single issue identity shared by review production and qualification."""

    return sealed_sha256(
        {
            "schema": "legalbot.live60-all-issue-identity.v1",
            "case_id": case_id,
            "issue_id": issue_id,
            "question_sha256": question_sha256,
            "record_sha256": record_sha256,
            "topic_sha256": sealed_sha256(
                {"schema": "legalbot.live60-topic-binding.v1", "topic": topic}
            ),
        }
    )


def build_all60_issue_review_input(
    *,
    row_id: str,
    topic: str,
    task_type: str,
    as_of_date: date,
    evidence: Sequence[EvidenceSpan],
) -> tuple[StructuredDraft, FrozenClaimReviewInput]:
    """Build the one-claim review input used both for invocation and admission."""

    draft = StructuredDraft(
        title=row_id,
        task_type=TaskType(task_type),
        jurisdiction="England and Wales",
        as_of_date=as_of_date,
        sections=[
            DraftSection(
                id=f"section-{hashlib.sha256(row_id.encode()).hexdigest()[:16]}",
                heading="Frozen issue evidence review",
                claims=[
                    StructuredClaimDraft(
                        id=row_id,
                        text=topic,
                        evidence_ids=[span.id for span in evidence],
                        material=True,
                        kind="legal_proposition",
                    )
                ],
            )
        ],
        limitations=[],
    )
    frozen = freeze_material_claims(
        draft=draft,
        evidence_by_id={span.id: span for span in evidence},
    )
    if len(frozen) != 1:
        raise AssertionError("all-60 issue review input is not exactly one material claim")
    return draft, frozen[0]


def load_all60_reviewer_batch_inputs(
    *,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    expert: LiveSuiteExpertQualification,
    required_as_of_date: date,
    candidate_build_root: Path,
) -> tuple[All60ReviewerBatchInput, ...]:
    """Derive the ordered 585 producer inputs from exact sealed evidence.

    This loader accepts no caller-authored checkpoint or favorable review
    fields.  Each result is built only after the source, candidate membership,
    rights, jurisdiction, locator and currentness gates pass.  The producer and
    later batch verifier therefore share one immutable pre-review inventory.
    """

    registry_ids = tuple(case.case_id for case in bundle.registry.cases)
    if (
        bundle.registry.case_count != 60
        or len(registry_ids) != 60
        or candidate.status != "candidate"
        or candidate.chunk_count < 1
        or candidate.vector_count != candidate.chunk_count
        or expert.suite_id != bundle.manifest.suite_id
        or expert.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256
        or expert.run_plan_sha256 != bundle.manifest.run_plan_sha256
        or expert.index_build_id != candidate.build_id
        or expert.as_of_date != required_as_of_date
        or expert.case_count != 60
        or tuple(case.case_id for case in expert.cases) != registry_ids
    ):
        raise ValueError("all-60 reviewer inputs have mismatched sealed identities")
    spans = tuple(span for case in expert.cases for span in case.exact_gold_spans)
    context = _candidate_context(
        candidate=candidate,
        candidate_build_root=candidate_build_root,
        spans=spans,
    )
    output: list[All60ReviewerBatchInput] = []
    ordinal = 0
    for source_case, expert_case in zip(bundle.registry.cases, expert.cases, strict=True):
        expected_issue_ids = tuple(
            f"issue-{number:02d}" for number in range(1, len(source_case.must_cover_issues) + 1)
        )
        if (
            expert_case.case_id != source_case.case_id
            or expert_case.question_sha256 != source_case.question_sha256
            or expert_case.record_sha256 != source_case.record_sha256
            or expert_case.status != "qualified"
            or tuple(issue.issue_id for issue in expert_case.issues) != expected_issue_ids
            or expert_case.contrary_authority_status not in {"reviewed_none", "reviewed_and_bound"}
        ):
            raise ValueError("all-60 reviewer input case is incomplete or unqualified")
        for topic, issue in zip(source_case.must_cover_issues, expert_case.issues, strict=True):
            ordinal += 1
            row_id = f"{source_case.case_id}:{issue.issue_id}"
            if issue.status != "qualified" or issue.reason_code is not None:
                raise ValueError("all-60 reviewer input issue is limited or unqualified")
            evidence_rows = tuple(
                _gate_span(
                    span=span,
                    row_id=row_id,
                    required_as_of_date=required_as_of_date,
                    context=context,
                )
                for span in issue.exact_gold_spans
            )
            evidence = tuple(item[0] for item in evidence_rows)
            positive = tuple(
                evidence_span
                for evidence_span, gold_span in zip(evidence, issue.exact_gold_spans, strict=True)
                if not gold_span.contrary_or_limiting
            )
            if not positive or not any(_issue_span_is_related(topic, span) for span in positive):
                raise ValueError(
                    "all-60 reviewer input lacks independently relevant positive evidence"
                )
            deterministic_gate_sha256 = sealed_sha256(
                {
                    "schema": "legalbot.live60-issue-deterministic-gates.v1",
                    "row_id": row_id,
                    "gate_sha256s": [item[1] for item in evidence_rows],
                }
            )
            draft, frozen = build_all60_issue_review_input(
                row_id=row_id,
                topic=topic,
                task_type=source_case.task_type,
                as_of_date=required_as_of_date,
                evidence=evidence,
            )
            evidence_by_id = MappingProxyType({span.id: span for span in evidence})
            if len(evidence_by_id) != len(evidence):
                raise ValueError("all-60 reviewer input evidence identities are duplicated")
            output.append(
                All60ReviewerBatchInput(
                    ordinal=ordinal,
                    row_id=row_id,
                    case_id=source_case.case_id,
                    issue_id=issue.issue_id,
                    issue_identity_sha256=all60_issue_identity_sha256(
                        case_id=source_case.case_id,
                        issue_id=issue.issue_id,
                        question_sha256=source_case.question_sha256,
                        record_sha256=source_case.record_sha256,
                        topic=topic,
                    ),
                    deterministic_gate_sha256=deterministic_gate_sha256,
                    draft=draft,
                    frozen_claim=frozen,
                    evidence_by_id=evidence_by_id,
                )
            )
    if ordinal != 585 or len(output) != 585:
        raise ValueError("all-60 reviewer input inventory must contain exactly 585 issues")
    if len({item.row_id for item in output}) != 585 or tuple(
        item.ordinal for item in output
    ) != tuple(range(1, 586)):
        raise ValueError("all-60 reviewer input inventory is duplicated or out of order")
    return tuple(output)


def verify_all60_candidate_evidence_reviews(
    *,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    expert: LiveSuiteExpertQualification,
    required_as_of_date: date,
    candidate_build_root: Path,
    ai_review_batch: object,
) -> VerifiedAll60EvidenceReviews:
    """Verify all 585 independent issue reviews and deterministic span gates."""

    from .all60_ai_review_batch import require_verified_all60_ai_review_batch

    verified_batch = require_verified_all60_ai_review_batch(ai_review_batch)
    attestation = verified_batch.attestation
    if (
        attestation.candidate_build_id != candidate.build_id
        or attestation.candidate_manifest_sha256 != candidate.candidate_manifest_sha256
        or attestation.candidate_seal_sha256 != candidate.candidate_seal_sha256
        or attestation.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256
        or attestation.run_plan_sha256 != bundle.manifest.run_plan_sha256
        or attestation.expert_qualification_seal_sha256 != expert.seal_sha256
        or attestation.required_as_of_date != required_as_of_date
        or attestation.authoritative is not True
        or attestation.qualification_eligible is not True
        or attestation.completed is not True
        or attestation.all_reviews_passed is not True
    ):
        raise ValueError("all-60 reviewer batch differs from qualification inputs")

    spans = tuple(span for case in expert.cases for span in case.exact_gold_spans)
    context = _candidate_context(
        candidate=candidate,
        candidate_build_root=candidate_build_root,
        spans=spans,
    )
    checkpoints = {
        checkpoint.claim_identity.claim_id: checkpoint for checkpoint in verified_batch.checkpoints
    }
    if len(checkpoints) != 585:
        raise ValueError("all-60 verified reviewer batch contains duplicate claims")
    issue_reviews: dict[str, VerifiedAll60IssueReview] = {}
    deterministic_gates: list[str] = []
    review_seals: list[str] = []
    invocation_ids: set[str] = set()
    model_identity: tuple[str, str] | None = None
    for source_case, expert_case in zip(bundle.registry.cases, expert.cases, strict=True):
        for topic, issue in zip(source_case.must_cover_issues, expert_case.issues, strict=True):
            row_id = f"{source_case.case_id}:{issue.issue_id}"
            if issue.status != "qualified" or not issue.exact_gold_spans:
                raise ValueError("all-60 issue review requires positive exact gold")
            evidence_rows = tuple(
                _gate_span(
                    span=span,
                    row_id=row_id,
                    required_as_of_date=required_as_of_date,
                    context=context,
                )
                for span in issue.exact_gold_spans
            )
            evidence = tuple(item[0] for item in evidence_rows)
            positive_evidence = tuple(
                evidence_span
                for evidence_span, gold_span in zip(evidence, issue.exact_gold_spans, strict=True)
                if not gold_span.contrary_or_limiting
            )
            if not any(_issue_span_is_related(topic, span) for span in positive_evidence):
                raise ValueError("all-60 issue has no independently relevant exact candidate span")
            issue_gate_sha256s = tuple(item[1] for item in evidence_rows)
            issue_gate_aggregate = sealed_sha256(
                {
                    "schema": "legalbot.live60-issue-deterministic-gates.v1",
                    "row_id": row_id,
                    "gate_sha256s": issue_gate_sha256s,
                }
            )
            deterministic_gates.append(issue_gate_aggregate)
            draft, frozen = build_all60_issue_review_input(
                row_id=row_id,
                topic=topic,
                task_type=source_case.task_type,
                as_of_date=required_as_of_date,
                evidence=evidence,
            )
            checkpoint = checkpoints.get(row_id)
            if checkpoint is None:
                raise ValueError("all-60 issue is missing its independent AI evidence review")
            identity = frozen.identity
            cited = checkpoint.decision.cited_evidence_ids
            positive_ids = {
                span.gold_span_id
                for span in issue.exact_gold_spans
                if not span.contrary_or_limiting
            }
            if (
                checkpoint.source_draft_sha256 != source_draft_sha256(draft)
                or checkpoint.frozen_claim_bundle_sha256 != frozen_claim_bundle_sha256((frozen,))
                or checkpoint.claim_identity != identity
                or checkpoint.decision.verdict != "supported"
                or not REQUIRED_AI_REASON_CODES.issubset(checkpoint.decision.reason_codes)
                or not (positive_ids & set(cited))
                or checkpoint.prompt_sha256 != ai_evidence_reviewer_prompt_sha256()
                or checkpoint.policy_sha256 != POLICY_SHA256
                or checkpoint.toolchain_sha256 != ai_evidence_reviewer_toolchain_sha256()
                or checkpoint.invocation_trace.timing_source == "deterministic_zero"
                or checkpoint.invocation_trace.invocation_id in invocation_ids
            ):
                raise ValueError("all-60 issue AI evidence review is not independently bound")
            current_model = (checkpoint.model_id, checkpoint.model_version)
            if model_identity is None:
                model_identity = current_model
            elif model_identity != current_model:
                raise ValueError("all-60 AI evidence reviews use inconsistent model identities")
            invocation_ids.add(checkpoint.invocation_trace.invocation_id)
            review_seals.append(checkpoint.seal_sha256)
            issue_reviews[row_id] = VerifiedAll60IssueReview(
                row_id=row_id,
                claim_sha256=identity.claim_sha256,
                evidence_bundle_sha256=identity.evidence_bundle_sha256,
                checkpoint_seal_sha256=checkpoint.seal_sha256,
                model_id=checkpoint.model_id,
                model_version=checkpoint.model_version,
                prompt_sha256=checkpoint.prompt_sha256,
                policy_sha256=checkpoint.policy_sha256,
                toolchain_sha256=checkpoint.toolchain_sha256,
                cited_evidence_ids=cited,
                invocation_id=checkpoint.invocation_trace.invocation_id,
                deterministic_gate_sha256=issue_gate_aggregate,
            )
    if set(issue_reviews) != set(checkpoints) or len(issue_reviews) != 585:
        raise ValueError("all-60 AI evidence reviews do not cover the exact 585 issues")
    deterministic_gate_set = sealed_sha256(
        {
            "schema": "legalbot.live60-deterministic-gate-set.v1",
            "gate_sha256s": deterministic_gates,
        }
    )
    ai_review_set = sealed_sha256(
        {
            "schema": "legalbot.live60-ai-evidence-review-set.v1",
            "checkpoint_seal_sha256s": review_seals,
        }
    )
    return VerifiedAll60EvidenceReviews(
        issues=issue_reviews,
        candidate_source_manifest_file_sha256=context.source_manifest_file_sha256,
        candidate_lance_tree_sha256=context.lance_tree_sha256,
        provision_verification_sha256=context.provision_sha256,
        deterministic_gate_set_sha256=deterministic_gate_set,
        ai_review_set_sha256=ai_review_set,
        ai_review_batch_attestation_seal_sha256=attestation.seal_sha256,
        ai_review_batch_manifest_seal_sha256=verified_batch.manifest_seal_sha256,
        ai_review_batch_checkpoint_set_sha256=verified_batch.checkpoint_set_sha256,
        ai_review_batch_intent_ledger_sha256=(verified_batch.invocation_intent_ledger_sha256),
        ai_review_batch_outcome_ledger_sha256=(verified_batch.invocation_outcome_ledger_sha256),
        ai_review_batch_launcher_start_sha256=(verified_batch.launcher_start_attestation_sha256),
        ai_review_batch_launcher_end_sha256=(verified_batch.launcher_end_attestation_sha256),
    )
