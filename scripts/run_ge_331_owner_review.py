#!/usr/bin/env python3
"""Run the 331 visible GE questions as a non-release owner-review draft.

This runner is deliberately separate from Development, sealed Validation,
promotion, and live execution.  It performs a full sealed-tree verification of
the pinned ``built_unscored`` retrieval generation, but it never changes the
catalogue status or an index pointer.  Case artifacts are create-only and the
run is resumable without deleting or replacing earlier evidence.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import runtime_adapters as runtime_adapters_module  # noqa: E402
from app.assessment.guidance_bundle import (  # noqa: E402
    OWNER_ASSESSMENT_BUNDLE,
    applicable_guidance_rules,
)
from app.citations.oscola import CitationMetadataError, render_answer  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import Database  # noqa: E402
from app.evaluation.ge_visible_harness import (  # noqa: E402
    FACTUAL_CHECKS,
    QUALITY_DIMENSION_MAX,
    VisibleGECase,
    VisibleGEPack,
    policy_documents,
    quality_outcome,
)
from app.model_runtime.config import PINNED_RUNTIME_MODEL_VERSION  # noqa: E402
from app.privacy import prompt_injection_hits, scrub_pii  # noqa: E402
from app.quality.evaluator import QualityEvaluator  # noqa: E402
from app.retrieval.ge_generic_read_guard import (  # noqa: E402
    require_generic_index_read_allowed,
)
from app.retrieval.service import (  # noqa: E402
    HybridRetrievalService,
    _runtime_catalogue_binding_sha256,
    _tree_metadata_sha256,
    _VerifiedBuildCapability,
    _verify_durable_candidate_tree,
)
from app.runtime_adapters import LoopbackModelGateway, ModelDraft  # noqa: E402
from app.types import (  # noqa: E402
    EvidenceSpan,
    QualityFinding,
    Severity,
    StructuredDraft,
    TaskType,
)

VISIBLE_PACK = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-review-r3"
)
READINESS_PACK = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-execution-readiness-r1"
)
RUN_ID = "LegalBot-GE-2026-09-01-owner-draft-r4"
RUN_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / RUN_ID
BUILD_ID = "current-law-ew-full-fp16-v111-20260829-recovery-b"
AS_OF_DATE = date(2026, 8, 28)
WORD_TARGET = 260
OWNER_REVIEW_MAX_OUTPUT_TOKENS = 768

TOPIC_TO_CATALOGUE_SUBJECT: Mapping[str, str] = {
    "administrative-law": "public and constitutional",
    "ai-and-data-protection": "ai and data protection",
    "business-and-company-law": "company and insolvency",
    "commercial-law": "commercial",
    "competition-law": "competition",
    "contemporary-biolaw-and-regulation": "biolaw",
    "contract-law": "contract",
    "criminal-law": "criminal",
    "eu-internal-market-law": "eu and internal market",
    "international-commercial-mediation": "mediation and ADR",
    "land-law": "land",
    "law-and-medicine": "medical law",
    "pensions-law": "pensions",
    "private-international-law": "private international law",
    "tort-law": "tort",
    "trusts-law": "trusts",
    "wills-and-estates": "wills and succession",
}

_SAFE_CASE = re.compile(r"[^a-z0-9]+")
_NUMBER = re.compile(
    r"(?<![A-Za-z])(?:£|\$)?\d[\d,]*(?:\.\d+)?(?:%|\s+(?:days?|weeks?|months?|years?))?",
    re.IGNORECASE,
)
_ABSOLUTE_PATH = re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\\\Users\\\\)", re.IGNORECASE)
_URGENT = re.compile(
    r"\b(?:999|emergency|immediate(?:ly)?|urgent(?:ly)?|today|same day|police|"
    r"shelter|hospital|injunction|deadline)\b",
    re.IGNORECASE,
)
_EXACT_AUTHORITY_REFERENCE = re.compile(
    r"(?:\b(?:Act|Regulations|Order)\s+(?:18|19|20)\d{2}\b|"
    r"\bsection\s+\d+[A-Za-z]?(?:\([^)]*\))?|"
    r"\[(?:18|19|20)\d{2}\]\s+(?:UKSC|UKHL|EWCA|EWHC|UKPC)\s+\d+|"
    r"\b(?:UKSC|UKHL|EWCA|EWHC|UKPC)\s+\d{4}\s+\d+\b)",
    re.IGNORECASE,
)


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def create_json(path: Path, value: Any) -> None:
    """Create one JSON artifact without replacing an existing path."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(value)
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def safe_case_name(case: VisibleGECase) -> str:
    slug = _SAFE_CASE.sub("-", case.case_id.casefold()).strip("-")
    return f"{case.ordinal:03d}-{slug}.json"


class OwnerReviewRetrievalService(HybridRetrievalService):
    """Read a fully sealed unscored build without creating candidate authority."""

    def _selected_build_row(self) -> dict[str, Any] | None:
        if self._pinned_build_id != BUILD_ID:
            raise RuntimeError("owner-review retrieval is bound to one exact build")
        row = self.database.fetchone(
            "SELECT * FROM index_builds WHERE id=?", (self._pinned_build_id,)
        )
        if row is None or str(row["status"]) != "built_unscored":
            raise RuntimeError("owner-review build status changed from built_unscored")
        return dict(row)

    def _ensure_verified_build(
        self, row: Mapping[str, Any]
    ) -> _VerifiedBuildCapability:
        build_id = str(row["id"])
        build_path = self.settings.index_dir / "builds" / build_id
        require_generic_index_read_allowed(build_path, expected_build_id=build_id)
        catalogue_binding = _runtime_catalogue_binding_sha256(row)
        with self._runtime_lock:
            existing = self._verified_build
            if existing is not None:
                if existing.catalogue_binding_sha256 != catalogue_binding:
                    raise RuntimeError("owner-review catalogue binding changed")
                if _tree_metadata_sha256(build_path) != existing.tree_metadata_sha256:
                    raise RuntimeError("owner-review build changed after verification")
                return existing
            before = _tree_metadata_sha256(build_path)
            source_manifest = _verify_durable_candidate_tree(self.settings, row)
            after = _tree_metadata_sha256(build_path)
            if before != after:
                raise RuntimeError("owner-review build changed during verification")
            capability = _VerifiedBuildCapability(
                build_id=build_id,
                source_manifest_sha256=source_manifest,
                catalogue_binding_sha256=catalogue_binding,
                tree_metadata_sha256=after,
                durable_v1_1=False,
            )
            self._verified_build = capability
            self._pinned_verified = True
            return capability


def _case_rules(case: VisibleGECase) -> tuple[str, ...]:
    rules = applicable_guidance_rules(
        OWNER_ASSESSMENT_BUNDLE,
        task_type="general",
        subject=str(case.raw.get("topic_id") or "general"),
    )
    instructions = [rule.positive_target for rule in rules]
    instructions.extend(
        (
            "Open with a direct, qualified short answer to the user's exact question.",
            "Use separate sections headed Short answer, What the law requires, "
            "What to do now, and Uncertainty and next questions.",
            "Give practical and time-sensitive steps only where supplied evidence supports them.",
            "State missing outcome-changing facts and do not imply a lawyer-client relationship.",
            "Use plain English while preserving legal precision and evidence traceability.",
        )
    )
    return tuple(dict.fromkeys(instructions))


def _plain_answer(draft: StructuredDraft, evidence: Mapping[str, EvidenceSpan]) -> str:
    lines: list[str] = []
    for section in draft.sections:
        lines.append(section.heading)
        for claim in section.claims:
            sources = [
                evidence[evidence_id].canonical_citation
                or evidence[evidence_id].citation_data.get("title")
                or evidence[evidence_id].source_version_id
                for evidence_id in claim.evidence_ids
                if evidence_id in evidence
            ]
            suffix = f" [Sources: {'; '.join(str(item) for item in sources)}]" if sources else ""
            lines.append(f"{claim.text.rstrip('.')}.{suffix}")
        lines.append("")
    if draft.limitations:
        lines.append("Evidence limitations")
        lines.extend(f"- {item}" for item in draft.limitations)
    return "\n".join(lines).strip()


def _fallback_answer(case: VisibleGECase, reason: str) -> str:
    clarification = case.raw.get("proposed_clarification_criteria") or {}
    indispensable = clarification.get("indispensable_facts") or []
    documents = case.raw.get("required_document_categories") or []
    lines = [
        "Evidence hold",
        (
            "I cannot give a reliable legal answer to this question from the verified material "
            "available in this run. This is an evidence gap, not a conclusion that you have no "
            "legal rights or remedy."
        ),
        "What to do now",
        str(clarification.get("safe_first_response") or "Preserve the relevant documents and dates."),
    ]
    if documents:
        lines.append("Documents to gather: " + ", ".join(str(item).replace("_", " ").title() for item in documents) + ".")
    if indispensable:
        lines.append("Questions that must be answered")
        lines.extend(f"- {item}" for item in indispensable)
    lines.extend(("Review reason", reason))
    return "\n\n".join(lines)


def _finding_codes(findings: Sequence[QualityFinding], *, hard_only: bool = False) -> set[str]:
    return {
        item.code
        for item in findings
        if not hard_only or item.severity == Severity.HARD_BLOCKER
    }


def _number_support_passes(draft: StructuredDraft, evidence: Mapping[str, EvidenceSpan]) -> bool:
    for section in draft.sections:
        for claim in section.claims:
            numbers = set(_NUMBER.findall(claim.text))
            if not numbers:
                continue
            bound = " ".join(
                evidence[item].text for item in claim.evidence_ids if item in evidence
            )
            if any(number not in bound for number in numbers):
                return False
    return True


def factual_review(
    *,
    case: VisibleGECase,
    draft: StructuredDraft | None,
    evidence: Mapping[str, EvidenceSpan],
    findings: Sequence[QualityFinding],
    rendered_text: str,
    model_version: str | None,
    integrity_ok: bool,
    render_ok: bool,
) -> tuple[dict[str, str], dict[str, str]]:
    hard = _finding_codes(findings, hard_only=True)
    all_codes = _finding_codes(findings)
    cited = {
        evidence_id
        for section in (draft.sections if draft else [])
        for claim in section.claims
        for evidence_id in claim.evidence_ids
    }
    checks: dict[str, str] = {}
    reasons: dict[str, str] = {}

    checks["integrity_chain"] = (
        "PASS"
        if integrity_ok and (draft is None or model_version == PINNED_RUNTIME_MODEL_VERSION)
        else "FAIL"
    )
    reasons["integrity_chain"] = (
        "Visible-pack, sealed-index and pinned-model identities verified."
        if checks["integrity_chain"] == "PASS"
        else "One or more exact input, index, or model identities were unavailable."
    )

    support_codes = {
        "unsupported_material_law",
        "wrong_authority_identity",
        "non_atomic_material_claim",
        "no_threshold_qualified_evidence",
        "non_authority_lane",
        "incomplete_proposition_span",
        "quality_evaluator_error",
    }
    checks["claim_evidence_support"] = (
        "PASS" if draft is not None and cited and not (hard & support_codes) else "FAIL"
    )
    reasons["claim_evidence_support"] = (
        "Every material claim retained for review is bound to qualifying retrieved evidence."
        if checks["claim_evidence_support"] == "PASS"
        else "The answer is absent, uncited, or contains a material support defect."
    )

    fact_codes = {"unsupported_material_fact", "material_fact_not_in_evidence"}
    checks["user_fact_provenance"] = "FAIL" if hard & fact_codes else "PASS"
    reasons["user_fact_provenance"] = (
        "The hypothetical user facts were not expanded beyond the question."
        if checks["user_fact_provenance"] == "PASS"
        else "A material fact was not traceable to the supplied question or evidence."
    )

    checks["jurisdiction_scope"] = (
        "PASS"
        if draft is not None
        and draft.jurisdiction == "England and Wales"
        and "wrong_jurisdiction" not in hard
        else "FAIL"
    )
    reasons["jurisdiction_scope"] = (
        "The answer discloses and uses the England-and-Wales scope."
        if checks["jurisdiction_scope"] == "PASS"
        else "The answer or supporting authority does not establish the required jurisdiction."
    )

    current_codes = {
        "wrong_currentness_status",
        "unverified_currentness",
        "reviewed_material_update_unresolved",
        "case_currentness_unverified",
        "historical_above_current",
    }
    current_spans_ok = bool(cited) and all(
        item in evidence and evidence[item].currentness_verified for item in cited
    )
    checks["requested_date_and_currentness"] = (
        "PASS" if current_spans_ok and not (hard & current_codes) else "FAIL"
    )
    reasons["requested_date_and_currentness"] = (
        f"All cited spans carry verified currentness at the {AS_OF_DATE.isoformat()} cutoff."
        if checks["requested_date_and_currentness"] == "PASS"
        else "At least one material proposition lacks verified currentness for the cutoff."
    )

    numbers_ok = draft is not None and _number_support_passes(draft, evidence)
    checks["dates_amounts_and_deadlines"] = "PASS" if numbers_ok else "FAIL"
    reasons["dates_amounts_and_deadlines"] = (
        "Every number, date, duration, or amount in a claim appears in its bound span."
        if numbers_ok
        else "A number, date, duration, or amount was not found in the bound evidence."
    )

    citation_codes = {"wrong_authority_identity", "citation_metadata_error", "false_quotation"}
    checks["citation_and_quotation_identity"] = (
        "PASS" if render_ok and cited and not (all_codes & citation_codes) else "FAIL"
    )
    reasons["citation_and_quotation_identity"] = (
        "Deterministic OSCOLA rendering succeeded from verified source metadata."
        if checks["citation_and_quotation_identity"] == "PASS"
        else "Citation identity, quotation, or deterministic rendering did not pass."
    )

    contradiction_codes = {"material_contradiction", "contrary_authority_unresolved"}
    checks["contradiction_and_counterauthority"] = (
        "FAIL" if all_codes & contradiction_codes else "PASS"
    )
    reasons["contradiction_and_counterauthority"] = (
        "No deterministic material contradiction or unresolved contrary-authority flag was found."
        if checks["contradiction_and_counterauthority"] == "PASS"
        else "The answer contains a contradiction or does not resolve material contrary authority."
    )

    urgent = bool(case.raw.get("urgent_handoff_required"))
    urgent_ok = not urgent or bool(_URGENT.search(rendered_text))
    checks["safety_and_urgent_action"] = "PASS" if urgent_ok else "FAIL"
    reasons["safety_and_urgent_action"] = (
        "No urgent handoff was required, or the answer includes an observable urgent action."
        if urgent_ok
        else "The case requires an urgent handoff but the answer does not state one."
    )

    privacy_ok = (
        not _ABSOLUTE_PATH.search(rendered_text)
        and rendered_text == scrub_pii(rendered_text)
        and not prompt_injection_hits(rendered_text)
        and "personal_data_leakage" not in hard
        and "prompt_injection" not in hard
    )
    checks["privacy_and_instruction_isolation"] = "PASS" if privacy_ok else "FAIL"
    reasons["privacy_and_instruction_isolation"] = (
        "No absolute path, owner identifier, personal-data leak, or document instruction was found."
        if privacy_ok
        else "Privacy or instruction-isolation checks failed."
    )
    if set(checks) != set(FACTUAL_CHECKS):
        raise AssertionError("factual check implementation is incomplete")
    return checks, reasons


def quality_dimensions(report: Mapping[str, Any]) -> dict[str, float]:
    rubric = {str(key): float(value) for key, value in report.get("rubric_scores", {}).items()}
    def ratio(key: str, maximum: float) -> float:
        return max(0.0, min(1.0, rubric.get(key, 0.0) / maximum))

    authority = ratio("authority_accuracy", 25.0)
    analysis = ratio("analysis", 20.0)
    direct = ratio("direct_answer", 12.0)
    next_steps = ratio("next_steps", 8.0)
    limitations = ratio("limitations", 8.0)
    organisation = ratio("organisation", 10.0)
    precision = ratio("precision", 10.0)
    synthesis = ratio("synthesis", 7.0)
    values = {
        "legal_and_factual_accuracy": 25.0,
        "issue_coverage_and_reasoning": round(15.0 * (0.55 * analysis + 0.30 * direct + 0.15 * synthesis), 2),
        "authority_and_currentness": round(15.0 * authority, 2),
        "practical_steps_and_urgency": round(15.0 * next_steps, 2),
        "uncertainty_limits_and_clarification": round(10.0 * limitations, 2),
        "organisation_and_plain_language": round(10.0 * (0.60 * organisation + 0.40 * precision), 2),
        "traceability_and_citations": 10.0,
    }
    if set(values) != set(QUALITY_DIMENSION_MAX):
        raise AssertionError("quality dimension implementation is incomplete")
    return values


def _root_causes(checks: Mapping[str, str], quality: Mapping[str, Any] | None) -> list[str]:
    causes = [f"factual:{name}" for name in FACTUAL_CHECKS if checks[name] == "FAIL"]
    if quality is not None:
        for finding in quality.get("findings", []):
            if finding.get("severity") in {"hard_blocker", "repairable"}:
                causes.append(f"quality:{finding.get('code')}")
        if quality.get("quality_outcome") in {
            "BELOW_70_STANDARD",
            "MATERIAL_IMPROVEMENT_REQUIRED",
        }:
            causes.append(f"quality:{quality['quality_outcome'].casefold()}")
    return list(dict.fromkeys(causes))


async def run_case(
    *,
    case: VisibleGECase,
    retrieval: OwnerReviewRetrievalService,
    gateway: LoopbackModelGateway,
    evaluator: QualityEvaluator,
    integrity: Mapping[str, Any],
) -> dict[str, Any]:
    started = datetime.now(UTC)
    evidence_rows: Sequence[EvidenceSpan] = ()
    draft_result: ModelDraft | None = None
    draft: StructuredDraft | None = None
    rendered_text = ""
    rendered_markdown: str | None = None
    model_error: str | None = None
    retrieval_error: str | None = None
    retrieval_code: str | None = None
    render_error: str | None = None
    quality_report: dict[str, Any] | None = None

    topic_id = str(case.raw.get("topic_id") or "")
    catalogue_subject = TOPIC_TO_CATALOGUE_SUBJECT.get(topic_id)

    if _EXACT_AUTHORITY_REFERENCE.search(case.prompt) is None:
        retrieval_code = "relevance_threshold_policy_not_frozen"
    else:
        try:
            evidence_rows = await retrieval.retrieve(
                query=case.prompt,
                jurisdiction="England and Wales",
                subject=catalogue_subject,
                as_of_date=AS_OF_DATE,
                limit=5,
                cacheable=False,
            )
            retrieval_code = retrieval.last_retrieval_code
        except Exception as exc:
            retrieval_error = f"{type(exc).__name__}: {exc}"

    evidence = {item.id: item for item in evidence_rows}
    if evidence and retrieval_error is None:
        try:
            draft_result = await gateway.draft(
                question=case.prompt,
                task_type=TaskType.GENERAL,
                jurisdiction="England and Wales",
                as_of_date=AS_OF_DATE,
                word_target=WORD_TARGET,
                evidence=evidence_rows,
                assessment_rules=_case_rules(case),
            )
            draft = draft_result.structured
        except Exception as exc:
            model_error = f"{type(exc).__name__}: {exc}"

    render_ok = False
    findings: list[QualityFinding] = []
    if draft is not None:
        try:
            rendered = render_answer(draft, evidence)
            rendered_markdown = rendered.markdown
            rendered_text = _plain_answer(draft, evidence)
            render_ok = True
            report = evaluator.evaluate(
                answer_version_id=f"owner-draft-{case.ordinal:03d}",
                draft=draft,
                rendered_text=rendered.markdown,
                evidence_by_id=evidence,
                word_count=rendered.word_count,
                word_target=WORD_TARGET,
                question=case.prompt,
                subject=topic_id or None,
            )
            findings = list(report.findings)
            quality_report = report.model_dump(mode="json")
        except CitationMetadataError as exc:
            render_error = f"{type(exc).__name__}: {exc}"
            rendered_text = _plain_answer(draft, evidence)
            findings.append(
                QualityFinding(
                    gate="citation_identity",
                    code="citation_metadata_error",
                    message="Deterministic citation rendering failed.",
                    severity=Severity.HARD_BLOCKER,
                    corrective_action="Repair the source metadata and re-evaluate the case.",
                )
            )
        except Exception as exc:
            render_error = f"{type(exc).__name__}: {exc}"
            rendered_text = _plain_answer(draft, evidence)
            render_ok = False
            findings.append(
                QualityFinding(
                    gate="quality_runtime",
                    code="quality_evaluator_error",
                    message="The deterministic quality evaluator did not complete.",
                    severity=Severity.HARD_BLOCKER,
                    corrective_action="Diagnose the evaluator error before re-evaluating the case.",
                )
            )
    else:
        reason = (
            retrieval_error
            or model_error
            or retrieval_code
            or "No threshold-qualified evidence was retrieved."
        )
        rendered_text = _fallback_answer(case, reason)

    checks, factual_reasons = factual_review(
        case=case,
        draft=draft,
        evidence=evidence,
        findings=findings,
        rendered_text=rendered_text,
        model_version=draft_result.model_version if draft_result else None,
        integrity_ok=bool(integrity.get("sealed_tree_verified")),
        render_ok=render_ok,
    )
    factual_pass = all(value in {"PASS", "NOT_APPLICABLE"} for value in checks.values())

    quality: dict[str, Any] | None = None
    if factual_pass and quality_report is not None:
        dimensions = quality_dimensions(quality_report)
        score, outcome = quality_outcome(dimensions)
        standards = quality_report.get("assessment_standards") or {}
        if not bool(standards.get("quality_target_met")) and outcome in {
            "MEETS_70_STANDARD",
            "EXCEEDS_70_STANDARD",
        }:
            outcome = "MATERIAL_IMPROVEMENT_REQUIRED"
        quality = {
            **quality_report,
            "quality_dimensions": dimensions,
            "quality_score": score,
            "quality_outcome": outcome,
            "law_folder_70_plus_advisory_only": True,
        }

    evidence_payload = [item.model_dump(mode="json") for item in evidence_rows]
    answer_payload = {
        "schema": "legalbot.ge-owner-review-case.v1",
        "run_id": RUN_ID,
        "case_id": case.case_id,
        "case_version_id": case.version_id,
        "case_record_sha256": case.record_sha256,
        "ordinal": case.ordinal,
        "scenario_family_id": case.scenario_family_id,
        "topic_id": case.raw.get("topic_id"),
        "catalogue_subject": catalogue_subject,
        "lane": case.lane,
        "question": case.prompt,
        "answer": rendered_text,
        "answer_markdown": rendered_markdown,
        "answer_kind": "model_evidence_draft" if draft is not None else "deterministic_evidence_hold",
        "structured_draft": draft.model_dump(mode="json") if draft else None,
        "model": {
            "version": draft_result.model_version if draft_result else None,
            "metrics": draft_result.metrics if draft_result else None,
            "error": model_error,
        },
        "retrieval": {
            "build_id": BUILD_ID,
            "status": "built_unscored",
            "owner_review_only": True,
            "source_manifest_sha256": integrity.get("source_manifest_sha256"),
            "evidence_count": len(evidence_payload),
            "error": retrieval_error,
            "result_code": retrieval_code,
            "evidence": evidence_payload,
        },
        "factual_gate": {
            "outcome": "FACTUAL_PASS" if factual_pass else "FACTUAL_HOLD",
            "checks": checks,
            "reasons": factual_reasons,
            "quality_scoring_permitted": factual_pass,
        },
        "quality_review": quality,
        "quality_not_scored_reason": (
            None
            if factual_pass and quality is not None
            else (
                "The quality evaluator did not complete."
                if factual_pass
                else "At least one material factual check failed."
            )
        ),
        "root_causes": _root_causes(checks, quality),
        "errors": {
            "retrieval": retrieval_error,
            "model": model_error,
            "render_or_quality": render_error,
        },
        "owner_decision": "UNREVIEWED",
        "owner_options": ["APPROVE", "RE_EVALUATE", "TUNE_OR_TRAIN", "HOLD"],
        "non_authorizing": {
            "legal_gold": False,
            "qualified_legal_review": False,
            "training_export": False,
            "unseen": False,
            "promotion": False,
            "live": False,
        },
        "started_at": started.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
    }
    material = dict(answer_payload)
    answer_payload["content_sha256"] = sha256_bytes(canonical_json_bytes(material))
    return answer_payload


def _verify_existing_case(path: Path, case: VisibleGECase) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    material = dict(value)
    claimed = str(material.pop("content_sha256", ""))
    if (
        value.get("schema") != "legalbot.ge-owner-review-case.v1"
        or value.get("case_id") != case.case_id
        or value.get("ordinal") != case.ordinal
        or sha256_bytes(canonical_json_bytes(material)) != claimed
    ):
        raise RuntimeError(f"existing owner-review case artifact is invalid: {path.name}")
    return value


def _write_readme(path: Path, pack: VisibleGEPack) -> None:
    text = f"""# {RUN_ID}

This is a create-only, owner-review draft of the 331 visible General Enquiries.
It is not legal gold, a qualified legal review, training data, unseen testing,
promotion evidence, or live output.

The visible input is `{pack.content_version}` and contains exactly 331 cases.
The retrieval generation is `{BUILD_ID}`. Its sealed tree and passing benchmark
are verified for this read-only review, but its catalogue status remains
`built_unscored` because release attestation stopped at the clean-Git-tree gate.
No ACTIVE or PREVIOUS pointer is written.

Each case applies the factual gate first. A factual hold receives no 70+ score.
Every failure and hold remains visible for the owner to choose APPROVE,
RE_EVALUATE, TUNE_OR_TRAIN, or HOLD.
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


async def main_async(args: argparse.Namespace) -> int:
    pack = VisibleGEPack.load(VISIBLE_PACK)
    settings = Settings()
    database = Database(settings.database_path)
    retrieval = OwnerReviewRetrievalService(
        settings,
        database,
        pinned_build_id=BUILD_ID,
    )
    # Full content verification occurs here before a question or model call.
    source_manifest = retrieval._ensure_verified_build(retrieval._selected_build_row() or {})
    integrity = {
        "sealed_tree_verified": True,
        "build_id": BUILD_ID,
        "catalogue_status": "built_unscored",
        "source_manifest_sha256": source_manifest.source_manifest_sha256,
        "tree_metadata_sha256": source_manifest.tree_metadata_sha256,
        "catalogue_binding_sha256": source_manifest.catalogue_binding_sha256,
        "release_attestation": "STOPPED_DIRTY_GIT_TREE",
        "candidate_status_written": False,
        "active_pointer_written": False,
        "owner_review_max_output_tokens": OWNER_REVIEW_MAX_OUTPUT_TOKENS,
    }

    RUN_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(RUN_ROOT, 0o700)
    if not (RUN_ROOT / "README.md").exists():
        _write_readme(RUN_ROOT / "README.md", pack)
    if not (RUN_ROOT / "RUN-INTEGRITY.json").exists():
        create_json(RUN_ROOT / "RUN-INTEGRITY.json", integrity)
    if not (RUN_ROOT / "FACTUAL-GATE-POLICY.json").exists():
        factual, quality = policy_documents()
        create_json(RUN_ROOT / "FACTUAL-GATE-POLICY.json", factual)
        create_json(RUN_ROOT / "QUALITY-GATE-POLICY.json", quality)

    runtime_adapters_module.GENERATION_CONFIG = {
        **runtime_adapters_module.GENERATION_CONFIG,
        "max_tokens": OWNER_REVIEW_MAX_OUTPUT_TOKENS,
    }
    runtime_adapters_module.GENERATION_CONFIG_SHA256 = sha256_bytes(
        canonical_json_bytes(runtime_adapters_module.GENERATION_CONFIG)
    )
    gateway = LoopbackModelGateway(settings)
    if not args.retrieval_only and not await gateway.health():
        raise RuntimeError("pinned local model runtime is not healthy")
    evaluator = QualityEvaluator(database, enforce_retrieval_threshold=True)
    selected = pack.cases[args.start - 1 : args.stop]
    for offset, case in enumerate(selected, 1):
        path = RUN_ROOT / "cases" / safe_case_name(case)
        if path.exists():
            value = _verify_existing_case(path, case)
            print(
                json.dumps(
                    {
                        "ordinal": case.ordinal,
                        "status": "verified_existing",
                        "factual": value["factual_gate"]["outcome"],
                        "quality": (value.get("quality_review") or {}).get("quality_outcome"),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            continue
        if args.retrieval_only:
            topic_id = str(case.raw.get("topic_id") or "")
            catalogue_subject = TOPIC_TO_CATALOGUE_SUBJECT.get(topic_id)
            evidence = (
                await retrieval.retrieve(
                    query=case.prompt,
                    jurisdiction="England and Wales",
                    subject=catalogue_subject,
                    as_of_date=AS_OF_DATE,
                    limit=5,
                    cacheable=False,
                )
                if _EXACT_AUTHORITY_REFERENCE.search(case.prompt)
                else ()
            )
            value = {
                "schema": "legalbot.ge-owner-review-retrieval-preview.v1",
                "case_id": case.case_id,
                "ordinal": case.ordinal,
                "evidence": [item.model_dump(mode="json") for item in evidence],
            }
            value["content_sha256"] = sha256_bytes(canonical_json_bytes(value))
            create_json(RUN_ROOT / "retrieval-preview" / safe_case_name(case), value)
            print(json.dumps({"ordinal": case.ordinal, "evidence": len(evidence)}), flush=True)
            continue
        result = await run_case(
            case=case,
            retrieval=retrieval,
            gateway=gateway,
            evaluator=evaluator,
            integrity=integrity,
        )
        create_json(path, result)
        print(
            json.dumps(
                {
                    "ordinal": case.ordinal,
                    "status": "created",
                    "factual": result["factual_gate"]["outcome"],
                    "quality": (result.get("quality_review") or {}).get("quality_outcome"),
                    "evidence": result["retrieval"]["evidence_count"],
                    "model_error": result["errors"]["model"],
                },
                sort_keys=True,
            ),
            flush=True,
        )
        if offset % 10 == 0:
            print(json.dumps({"progress": f"{case.ordinal}/331"}), flush=True)

    if args.start == 1 and args.stop == 331 and not args.retrieval_only:
        rows = [
            _verify_existing_case(RUN_ROOT / "cases" / safe_case_name(case), case)
            for case in pack.cases
        ]
        factual = Counter(row["factual_gate"]["outcome"] for row in rows)
        quality = Counter(
            (row.get("quality_review") or {}).get("quality_outcome", "NOT_SCORED")
            for row in rows
        )
        manifest = {
            "schema": "legalbot.ge-owner-review-run.v1",
            "run_id": RUN_ID,
            "visible_pack_content_sha256": pack.pack_manifest_sha256,
            "visible_case_manifest_sha256": pack.case_manifest_sha256,
            "visible_case_order_sha256": pack.case_order_sha256,
            "case_count": len(rows),
            "build_id": BUILD_ID,
            "build_status": "built_unscored",
            "source_manifest_sha256": source_manifest.source_manifest_sha256,
            "model_version": PINNED_RUNTIME_MODEL_VERSION,
            "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
            "factual_counts": dict(sorted(factual.items())),
            "quality_counts": dict(sorted(quality.items())),
            "cases": [
                {
                    "ordinal": row["ordinal"],
                    "case_id": row["case_id"],
                    "path": f"cases/{safe_case_name(pack.cases[row['ordinal'] - 1])}",
                    "sha256": sha256_file(
                        RUN_ROOT / "cases" / safe_case_name(pack.cases[row["ordinal"] - 1])
                    ),
                    "content_sha256": row["content_sha256"],
                    "factual_outcome": row["factual_gate"]["outcome"],
                    "quality_outcome": (
                        row.get("quality_review") or {}
                    ).get("quality_outcome", "NOT_SCORED"),
                }
                for row in rows
            ],
            "non_authorizing": True,
            "completed_at": datetime.now(UTC).isoformat(),
        }
        manifest["content_sha256"] = sha256_bytes(canonical_json_bytes(manifest))
        manifest_path = RUN_ROOT / "RUN-MANIFEST.json"
        if not manifest_path.exists():
            create_json(manifest_path, manifest)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--stop", type=int, default=331)
    parser.add_argument("--retrieval-only", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.start <= args.stop <= 331:
        parser.error("start and stop must satisfy 1 <= start <= stop <= 331")
    return args


def main() -> int:
    return asyncio.run(main_async(parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
