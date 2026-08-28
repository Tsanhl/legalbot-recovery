"""Create-only, resumable Stage-A-v2 runner for the sealed Live60 suite.

The runner is deliberately outside promotion and answer-generation paths.  It
requires both the sealed 60-case disposition and the issue-level expert gold
overlay, then validates all 60 case and 585 issue identities before retrieval.
"""

from __future__ import annotations

import fcntl
import hashlib
import inspect
import json
import os
import re
import time
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO

from ..db import Database
from ..jurisdictions import compatible
from ..orchestration.classifier import classify_subject
from ..orchestration.retry_policy import MAX_ATTEMPTS, decide_retry, failure_fingerprint
from ..quality.evidence import evidence_span_eligible_for_drafting
from ..retrieval.budget import RetrievalBudgetExhausted, bind_retrieval_budget
from ..types import EvidenceSpan
from .live30 import _private_directory
from .live30_coverage import _candidate_matches_gold, _safe_candidate
from .live30_gold import Live30GoldSpan
from .live_suite import LiveEvaluationBundle, sealed_sha256
from .live_suite_gold import LiveSuiteExpertQualification
from .live_suite_stage_a_v2 import (
    POSITIVE_GOLD_STATUSES,
    STAGE_A_V2_SCHEMA,
    score_stage_a_v2,
)
from .nonrelease_artifacts import (
    CreateOnlyRunDirectory,
    sealed_safe_payload,
    verify_sealed_artifact,
)
from .owner_quality_canary import All60CaseQualification
from .sealed_candidate import SealedCandidateIdentity

STAGE_A_RUN_SCHEMA = "legalbot.live60-stage-a-v2-run.v1"
STAGE_A_ATTEMPT_SCHEMA = "legalbot.live60-stage-a-v2-attempt.v1"
STAGE_A_CHECKPOINT_SCHEMA = "legalbot.live60-stage-a-v2-checkpoint.v1"
STAGE_A_STOP_SCHEMA = "legalbot.live60-stage-a-v2-stop.v1"
STAGE_A_GATE_FAILURE_SCHEMA = "legalbot.live60-stage-a-v2-gate-failure.v1"
STAGE_A_ISSUE_DEADLINE_SECONDS = 300
STAGE_A_RUNNER_POLICY = {
    "schema": "legalbot.live60-stage-a-v2-runner-policy.v1",
    "required_case_count": 60,
    "required_issue_count": 585,
    "positive_statuses": sorted(POSITIVE_GOLD_STATUSES),
    "gold_span_policy": "positive_non_contrary_exact_span_identity",
    "ranking_limit": 10,
    "issue_deadline_seconds": STAGE_A_ISSUE_DEADLINE_SECONDS,
    "attempts": MAX_ATTEMPTS,
    "serial": True,
    "checkpoint": "create_only_one_per_sealed_issue",
    "resume": "exact_identity_only",
    "hard_stop": "filter_or_technical_deterministic_or_repeat",
    "metric_miss": "complete_immutable_gate_failure",
    "writes_active": False,
    "writes_o04": False,
}
STAGE_A_RUNNER_POLICY_SHA256 = sealed_sha256(STAGE_A_RUNNER_POLICY)
STAGE_A_SCORER_IDENTITY_SHA256 = sealed_sha256(
    {
        "schema": "legalbot.live60-stage-a-v2-scorer-identity.v1",
        "result_schema": STAGE_A_V2_SCHEMA,
        "implementation_sha256": hashlib.sha256(
            inspect.getsource(score_stage_a_v2).encode("utf-8")
        ).hexdigest(),
        "runner_policy_sha256": STAGE_A_RUNNER_POLICY_SHA256,
    }
)

_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
UNBOUND_COMPLETION_PREFLIGHT_SHA256 = "0" * 64
_DETERMINISTIC_FAILURES = frozenset(
    {
        "candidate_identity_mismatch",
        "evidence_filter_violation",
        "retrieval_budget_exceeded",
        "retrieval_deadline_exceeded",
        "retrieval_result_invalid",
        "stage_a_identity_mismatch",
    }
)


@dataclass(frozen=True, slots=True)
class StageAIssue:
    global_ordinal: int
    positive_ordinal: int | None
    case_id: str
    issue_id: str
    issue_identity_sha256: str
    question_sha256: str
    status: str
    query: str
    jurisdiction: str
    subject: str | None
    gold_spans: tuple[Live30GoldSpan, ...]

    @property
    def gold_span_ids(self) -> tuple[str, ...]:
        return tuple(span.gold_span_id for span in self.gold_spans)

    @property
    def ranking_issue_id(self) -> str:
        return f"{self.case_id}:{self.issue_id}"


@dataclass(frozen=True, slots=True)
class ValidatedStageAInputs:
    all_issues: tuple[StageAIssue, ...]
    positive_issues: tuple[StageAIssue, ...]
    issue_identity_set_sha256: str
    status_counts: dict[str, int]


def _expected_stage_a_run_manifest(
    *,
    run_id: str,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    all60_qualification: All60CaseQualification,
    expert_qualification: LiveSuiteExpertQualification,
    as_of_date: date,
    code_revision: str,
    code_dirty: bool,
    validated: ValidatedStageAInputs,
    completion_preflight_verified_result_sha256: str,
) -> dict[str, Any]:
    return sealed_safe_payload(
        {
            "schema": STAGE_A_RUN_SCHEMA,
            "run_id": run_id,
            "suite_id": bundle.manifest.suite_id,
            "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
            "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
            "run_plan_sha256": bundle.manifest.run_plan_sha256,
            **candidate.safe_dict(),
            "all60_qualification_seal_sha256": all60_qualification.seal_sha256,
            "expert_qualification_seal_sha256": expert_qualification.seal_sha256,
            "completion_preflight_verified_result_sha256": (
                completion_preflight_verified_result_sha256
            ),
            "completion_preflight_authoritative": (
                completion_preflight_verified_result_sha256 != UNBOUND_COMPLETION_PREFLIGHT_SHA256
            ),
            "as_of_date": as_of_date.isoformat(),
            "case_count": 60,
            "case_ids": [case.case_id for case in bundle.registry.cases],
            "issue_count": 585,
            "positive_issue_count": len(validated.positive_issues),
            "issue_status_counts": validated.status_counts,
            "issue_identity_set_sha256": validated.issue_identity_set_sha256,
            "runner_policy_sha256": STAGE_A_RUNNER_POLICY_SHA256,
            "scorer_identity_sha256": STAGE_A_SCORER_IDENTITY_SHA256,
            "retrieval_limit": 10,
            "code_revision": code_revision,
            "code_dirty": code_dirty,
            "purpose": "stage_a_retrieval_evaluation_only",
            "local_only": True,
            "online_research_allowed": False,
            "eligible_for_training": False,
            "training_export_allowed": False,
            "requires_active": False,
            "writes_active": False,
            "writes_o04": False,
            "answer_generation_allowed": False,
        }
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_reason_code(exc: BaseException) -> str:
    if isinstance(exc, RetrievalBudgetExhausted):
        candidate = exc.reason_code
    elif isinstance(exc, TimeoutError):
        candidate = "timeout_error"
    else:
        candidate = (
            re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__)
            .casefold()
            .removesuffix("_exception")
        )
    candidate = (candidate or "runtime_error").strip().casefold().replace("-", "_")
    return candidate if _SAFE_CODE.fullmatch(candidate) else "runtime_error"


def _issue_identity(
    *,
    case_id: str,
    issue_id: str,
    question_sha256: str,
    record_sha256: str,
    topic: str,
) -> str:
    return str(
        sealed_sha256(
            {
                "schema": "legalbot.live60-stage-a-issue-identity.v1",
                "case_id": case_id,
                "issue_id": issue_id,
                "question_sha256": question_sha256,
                "record_sha256": record_sha256,
                "topic_sha256": _sha256_text(topic),
            }
        )
    )


def validate_stage_a_inputs(
    *,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    all60_qualification: All60CaseQualification,
    expert_qualification: LiveSuiteExpertQualification,
    as_of_date: date,
) -> ValidatedStageAInputs:
    """Bind both qualification layers to exactly 60 cases and 585 issues."""

    registry_ids = tuple(case.case_id for case in bundle.registry.cases)
    if bundle.registry.case_count != 60 or len(registry_ids) != 60:
        raise ValueError("Stage A v2 requires exactly 60 sealed cases")
    if (
        all60_qualification.suite_id != bundle.manifest.suite_id
        or all60_qualification.suite_manifest_seal_sha256 != bundle.manifest.seal_sha256
        or all60_qualification.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256
        or all60_qualification.candidate_build_id != candidate.build_id
        or all60_qualification.case_ids != registry_ids
        or all60_qualification.review_complete is not True
        or all60_qualification.unreviewed_issue_count != 0
    ):
        raise ValueError("sealed all-60 qualification identity mismatch")
    if (
        expert_qualification.suite_id != bundle.manifest.suite_id
        or expert_qualification.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256
        or expert_qualification.run_plan_sha256 != bundle.manifest.run_plan_sha256
        or expert_qualification.index_build_id != candidate.build_id
        or expert_qualification.as_of_date != as_of_date
        or expert_qualification.case_count != 60
        or len(expert_qualification.cases) != 60
        or expert_qualification.seal_sha256
        != sealed_sha256(expert_qualification.model_dump(mode="json", by_alias=True))
    ):
        raise ValueError("sealed expert qualification identity mismatch")

    expert_qualified = {
        case.case_id for case in expert_qualification.cases if case.status == "qualified"
    }
    expert_limited = {
        case.case_id for case in expert_qualification.cases if case.status != "qualified"
    }
    if (
        set(all60_qualification.qualified_case_ids) != expert_qualified
        or set(all60_qualification.limited_case_ids) != expert_limited
    ):
        raise ValueError("all-60 case dispositions disagree with issue-level qualification")

    all_issues: list[StageAIssue] = []
    positive_count = 0
    for case, qualified_case in zip(bundle.registry.cases, expert_qualification.cases, strict=True):
        if (
            qualified_case.case_id != case.case_id
            or qualified_case.question_sha256 != case.question_sha256
            or qualified_case.record_sha256 != case.record_sha256
            or len(qualified_case.issues) != len(case.must_cover_issues)
        ):
            raise ValueError("Stage A case or issue identity mismatch")
        for issue_number, (topic, qualified_issue) in enumerate(
            zip(case.must_cover_issues, qualified_case.issues, strict=True), start=1
        ):
            issue_id = f"issue-{issue_number:02d}"
            if qualified_issue.issue_id != issue_id:
                raise ValueError("Stage A issue order mismatch")
            positive_ordinal: int | None = None
            gold_spans: tuple[Live30GoldSpan, ...] = ()
            if qualified_issue.status in POSITIVE_GOLD_STATUSES:
                positive_count += 1
                positive_ordinal = positive_count
                gold_spans = tuple(
                    span
                    for span in qualified_issue.exact_gold_spans
                    if not span.contrary_or_limiting
                )
                if not gold_spans:
                    raise ValueError("positive Stage A issue has no supporting exact gold")
            all_issues.append(
                StageAIssue(
                    global_ordinal=len(all_issues) + 1,
                    positive_ordinal=positive_ordinal,
                    case_id=case.case_id,
                    issue_id=issue_id,
                    issue_identity_sha256=_issue_identity(
                        case_id=case.case_id,
                        issue_id=issue_id,
                        question_sha256=case.question_sha256,
                        record_sha256=case.record_sha256,
                        topic=topic,
                    ),
                    question_sha256=case.question_sha256,
                    status=qualified_issue.status,
                    query=topic,
                    jurisdiction=case.jurisdiction,
                    subject=classify_subject(topic),
                    gold_spans=gold_spans,
                )
            )
    if len(all_issues) != 585:
        raise ValueError("Stage A v2 requires exactly 585 sealed issue identities")
    identities = tuple(issue.issue_identity_sha256 for issue in all_issues)
    if len(set(identities)) != 585:
        raise ValueError("Stage A issue identities are duplicated")
    positive_issues = tuple(issue for issue in all_issues if issue.positive_ordinal is not None)
    status_counts = dict(sorted(Counter(issue.status for issue in all_issues).items()))
    identity_set_sha256 = sealed_sha256(
        {
            "schema": "legalbot.live60-stage-a-issue-identity-set.v1",
            "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
            "case_count": 60,
            "issue_count": 585,
            "issue_identity_sha256s": list(identities),
        }
    )
    return ValidatedStageAInputs(
        all_issues=tuple(all_issues),
        positive_issues=positive_issues,
        issue_identity_set_sha256=identity_set_sha256,
        status_counts=status_counts,
    )


def _span_field(span: Any, name: str) -> Any:
    if isinstance(span, Mapping):
        return span.get(name)
    return getattr(span, name, None)


def _span_is_qualified(
    span: Any,
    *,
    candidate_build_id: str,
    issue: StageAIssue,
    as_of_date: date,
    database: Database | None,
) -> bool:
    if str(_span_field(span, "index_build_id") or "") != candidate_build_id:
        return False
    lane = str(_span_field(span, "lane") or "")
    if lane not in {"primary_authority", "official_secondary", "scholarship"}:
        return False
    citation_data = _span_field(span, "citation_data")
    if not compatible(
        issue.jurisdiction,
        str(_span_field(span, "jurisdiction") or ""),
        citation_data if isinstance(citation_data, Mapping) else None,
    ):
        return False
    if isinstance(span, EvidenceSpan):
        return bool(
            span.locator.strip()
            and span.text.strip()
            and evidence_span_eligible_for_drafting(span, as_of_date=as_of_date, database=database)
        )
    return bool(
        str(_span_field(span, "locator") or "").strip()
        and str(_span_field(span, "text") or "").strip()
        and _span_field(span, "identity_verified")
        and _span_field(span, "currentness_verified")
    )


def _chunk_id(span: Any) -> str:
    value = str(_span_field(span, "chunk_id") or "")
    if not _SAFE_CODE.fullmatch(value):
        raise RuntimeError("retrieval_result_invalid")
    return value


def _ranking_identity_tokens(
    evidence: Sequence[Any],
    *,
    issue: StageAIssue,
    as_of_date: date,
    database: Database | None,
    candidate_build_id: str,
) -> tuple[str, ...]:
    """Keep rank positions while crediting only exact positive-gold matches."""

    tokens: list[str] = []
    for rank, span in enumerate(evidence, start=1):
        if not isinstance(span, EvidenceSpan):
            raise RuntimeError("retrieval_result_invalid")
        candidate = _safe_candidate(
            span,
            rank,
            requested_jurisdiction=issue.jurisdiction,
            as_of_date=as_of_date,
        )
        candidate["runtime_qualification_passed"] = _span_is_qualified(
            span,
            candidate_build_id=candidate_build_id,
            issue=issue,
            as_of_date=as_of_date,
            database=database,
        )
        matches = [
            gold.gold_span_id
            for gold in issue.gold_spans
            if _candidate_matches_gold(candidate, gold)
        ]
        if len(matches) > 1:
            raise RuntimeError("retrieval_result_invalid")
        if matches:
            tokens.append(matches[0])
            continue
        miss_identity = sealed_sha256(
            {
                "schema": "legalbot.live60-stage-a-ranking-miss.v1",
                "candidate_build_id": candidate_build_id,
                "issue_identity_sha256": issue.issue_identity_sha256,
                "rank": rank,
                "source_version_id": span.source_version_id,
                "chunk_id": span.chunk_id,
                "content_sha256": span.content_sha256,
            }
        )
        tokens.append(f"miss:{miss_identity}")
    return tuple(tokens)


def _attempt_name(issue: StageAIssue, attempt_number: int) -> str:
    return (
        f"attempts/{issue.global_ordinal:04d}-{issue.case_id}-{issue.issue_id}/"
        f"attempt-{attempt_number:02d}.json"
    )


def _checkpoint_name(issue: StageAIssue) -> str:
    return f"checkpoints/{issue.global_ordinal:04d}-{issue.case_id}-{issue.issue_id}.json"


def _validate_issue_binding(value: Mapping[str, Any], issue: StageAIssue) -> None:
    if (
        value.get("case_id") != issue.case_id
        or value.get("issue_id") != issue.issue_id
        or value.get("global_ordinal") != issue.global_ordinal
        or value.get("positive_ordinal") != issue.positive_ordinal
        or value.get("issue_identity_sha256") != issue.issue_identity_sha256
        or tuple(value.get("gold_span_ids") or ()) != issue.gold_span_ids
    ):
        raise ValueError("Stage A resume issue identity mismatch")


def _load_attempts(
    store: CreateOnlyRunDirectory,
    *,
    issue: StageAIssue,
    run_id: str,
    candidate_build_id: str,
) -> list[dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    missing_seen = False
    for attempt_number in range(1, MAX_ATTEMPTS + 1):
        name = _attempt_name(issue, attempt_number)
        if not store.exists(name):
            missing_seen = True
            continue
        if missing_seen:
            raise ValueError("Stage A attempt sequence is not contiguous")
        value = verify_sealed_artifact(store.read_json(name), schema=STAGE_A_ATTEMPT_SCHEMA)
        _validate_issue_binding(value, issue)
        if (
            value.get("run_id") != run_id
            or value.get("candidate_build_id") != candidate_build_id
            or value.get("attempt_number") != attempt_number
        ):
            raise ValueError("Stage A attempt binding mismatch")
        attempts.append(value)
    return attempts


def _load_checkpoint(
    store: CreateOnlyRunDirectory,
    *,
    issue: StageAIssue,
    run_id: str,
    candidate_build_id: str,
) -> dict[str, Any] | None:
    name = _checkpoint_name(issue)
    if not store.exists(name):
        return None
    value = verify_sealed_artifact(store.read_json(name), schema=STAGE_A_CHECKPOINT_SCHEMA)
    _validate_issue_binding(value, issue)
    if (
        value.get("run_id") != run_id
        or value.get("candidate_build_id") != candidate_build_id
        or value.get("filter_violation_count") != 0
        or value.get("status") != "succeeded"
    ):
        raise ValueError("Stage A checkpoint binding mismatch")
    expected_state = "scored" if issue.positive_ordinal is not None else "knowledge_gap_not_scored"
    if value.get("checkpoint_state") != expected_state:
        raise ValueError("Stage A checkpoint state mismatch")
    return value


def _checkpoint_from_attempt(value: Mapping[str, Any]) -> dict[str, Any]:
    return sealed_safe_payload(
        {
            "schema": STAGE_A_CHECKPOINT_SCHEMA,
            "run_id": value["run_id"],
            "candidate_build_id": value["candidate_build_id"],
            "case_id": value["case_id"],
            "issue_id": value["issue_id"],
            "global_ordinal": value["global_ordinal"],
            "positive_ordinal": value["positive_ordinal"],
            "issue_identity_sha256": value["issue_identity_sha256"],
            "question_sha256": value["question_sha256"],
            "status_disposition": value["status_disposition"],
            "gold_span_ids": value["gold_span_ids"],
            "ranked_identity_tokens": value["ranked_identity_tokens"],
            "retrieval_attempt_number": value["attempt_number"],
            "duration_seconds": value["duration_seconds"],
            "filter_violation_count": 0,
            "checkpoint_state": "scored",
            "status": "succeeded",
        }
    )


def _knowledge_gap_checkpoint(
    *,
    run_id: str,
    candidate_build_id: str,
    issue: StageAIssue,
) -> dict[str, Any]:
    return sealed_safe_payload(
        {
            "schema": STAGE_A_CHECKPOINT_SCHEMA,
            "run_id": run_id,
            "candidate_build_id": candidate_build_id,
            "case_id": issue.case_id,
            "issue_id": issue.issue_id,
            "global_ordinal": issue.global_ordinal,
            "positive_ordinal": None,
            "issue_identity_sha256": issue.issue_identity_sha256,
            "question_sha256": issue.question_sha256,
            "status_disposition": issue.status,
            "gold_span_ids": [],
            "ranked_identity_tokens": [],
            "retrieval_attempt_number": 0,
            "duration_seconds": 0.0,
            "filter_violation_count": 0,
            "checkpoint_state": "knowledge_gap_not_scored",
            "status": "succeeded",
        }
    )


def _ranking_from_checkpoint(value: Mapping[str, Any], issue: StageAIssue) -> dict[str, Any]:
    return {
        "issue_id": issue.ranking_issue_id,
        "gold_span_ids": list(value["gold_span_ids"]),
        "ranked_chunk_ids": list(value["ranked_identity_tokens"]),
        "filter_violation_count": 0,
    }


def _validate_checkpoint_prefix(store: CreateOnlyRunDirectory) -> None:
    checkpoint_root = store.path / "checkpoints"
    if not checkpoint_root.exists():
        return
    if not checkpoint_root.is_dir() or checkpoint_root.is_symlink():
        raise ValueError("Stage A checkpoint root is invalid")
    ordinals: list[int] = []
    pattern = re.compile(
        r"^(?P<ordinal>[0-9]{4})-(?:live30|live60)-q[0-9]{2}-issue-[0-9]{2}\.json$"
    )
    for path in sorted(checkpoint_root.iterdir()):
        match = pattern.fullmatch(path.name)
        if match is None or not path.is_file() or path.is_symlink():
            raise ValueError("Stage A checkpoint set contains an invalid member")
        ordinals.append(int(match.group("ordinal")))
    if ordinals != list(range(1, len(ordinals) + 1)):
        raise ValueError("Stage A checkpoints are not a contiguous prefix")


def _safe_existing_stage_a_run(*, output_root: Path, run_id: str) -> Path:
    """Resolve one private existing run without creating or chmodding anything."""

    if not re.fullmatch(r"^[a-z0-9][a-z0-9._:-]{2,127}$", run_id):
        raise ValueError("Stage A run ID is invalid")
    if not output_root.is_dir() or output_root.is_symlink():
        raise ValueError("Stage A output root is missing or unsafe")
    root_stat = output_root.stat()
    if root_stat.st_uid != os.getuid() or root_stat.st_mode & 0o077:
        raise ValueError("Stage A output root is not private to the local owner")
    resolved_root = output_root.resolve()
    raw_run = output_root / run_id
    if not raw_run.is_dir() or raw_run.is_symlink():
        raise ValueError("Stage A run directory is missing or unsafe")
    run_stat = raw_run.stat()
    if run_stat.st_uid != os.getuid() or run_stat.st_mode & 0o077:
        raise ValueError("Stage A run directory is not private to the local owner")
    run_dir = raw_run.resolve()
    if run_dir.parent != resolved_root:
        raise ValueError("Stage A run directory escapes its safe local root")
    return run_dir


def _read_existing_stage_a_artifact(
    run_dir: Path,
    relative_name: str,
    *,
    schema: str | None = None,
) -> dict[str, Any]:
    path = run_dir / relative_name
    if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(run_dir):
        raise ValueError("Stage A artifact is missing or unsafe")
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
        raise ValueError("Stage A artifact is not a private create-only file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Stage A artifact is unreadable") from exc
    if not isinstance(value, dict):
        raise ValueError("Stage A artifact must be an object")
    return verify_sealed_artifact(value, schema=schema)


def load_verified_stage_a_v2_artifact_set(
    *,
    output_root: Path,
    run_id: str,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    all60_qualification: All60CaseQualification,
    expert_qualification: LiveSuiteExpertQualification,
    as_of_date: date,
    code_revision: str,
    completion_preflight_verified_result_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify and rescore one complete on-disk 585-checkpoint Stage A run.

    A result mapping or self-seal supplied by a caller is never sufficient.  The
    loader reads the private create-only run, validates the exact manifest and
    checkpoint filenames/identities, recomputes the checkpoint-set digest, and
    derives Stage A metrics again from the checkpoint rankings.
    """

    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", code_revision):
        raise ValueError("Stage A code revision is invalid")
    validated = validate_stage_a_inputs(
        bundle=bundle,
        candidate=candidate,
        all60_qualification=all60_qualification,
        expert_qualification=expert_qualification,
        as_of_date=as_of_date,
    )
    run_dir = _safe_existing_stage_a_run(output_root=output_root, run_id=run_id)
    completion_preflight_seal = (
        completion_preflight_verified_result_sha256 or UNBOUND_COMPLETION_PREFLIGHT_SHA256
    )
    if not _SHA256.fullmatch(completion_preflight_seal):
        raise ValueError("Stage A completion-preflight identity is invalid")
    expected_manifest = _expected_stage_a_run_manifest(
        run_id=run_id,
        bundle=bundle,
        candidate=candidate,
        all60_qualification=all60_qualification,
        expert_qualification=expert_qualification,
        as_of_date=as_of_date,
        code_revision=code_revision,
        code_dirty=False,
        validated=validated,
        completion_preflight_verified_result_sha256=completion_preflight_seal,
    )
    observed_manifest = _read_existing_stage_a_artifact(
        run_dir, "run-manifest.json", schema=STAGE_A_RUN_SCHEMA
    )
    if observed_manifest != expected_manifest:
        raise ValueError("Stage A artifact manifest identity mismatch")
    if (run_dir / "STOPPED.json").exists() or (run_dir / "GATE-FAILED.json").exists():
        raise ValueError("Stage A artifact set contains a terminal failure marker")

    checkpoint_root = run_dir / "checkpoints"
    if not checkpoint_root.is_dir() or checkpoint_root.is_symlink():
        raise ValueError("Stage A checkpoint root is missing or unsafe")
    checkpoint_root_stat = checkpoint_root.stat()
    if checkpoint_root_stat.st_uid != os.getuid() or checkpoint_root_stat.st_mode & 0o077:
        raise ValueError("Stage A checkpoint root is not private to the local owner")
    expected_names = tuple(
        _checkpoint_name(issue).removeprefix("checkpoints/") for issue in validated.all_issues
    )
    observed_paths = tuple(sorted(checkpoint_root.iterdir(), key=lambda path: path.name))
    if (
        len(observed_paths) != 585
        or tuple(path.name for path in observed_paths) != expected_names
        or any(not path.is_file() or path.is_symlink() for path in observed_paths)
    ):
        raise ValueError("Stage A checkpoint set is not the exact 585-member identity set")

    checkpoint_seals: list[str] = []
    rankings: list[dict[str, Any]] = []
    for issue, expected_name in zip(validated.all_issues, expected_names, strict=True):
        checkpoint = _read_existing_stage_a_artifact(
            run_dir,
            f"checkpoints/{expected_name}",
            schema=STAGE_A_CHECKPOINT_SCHEMA,
        )
        _validate_issue_binding(checkpoint, issue)
        expected_state = (
            "scored" if issue.positive_ordinal is not None else "knowledge_gap_not_scored"
        )
        ranked_tokens = checkpoint.get("ranked_identity_tokens")
        if (
            checkpoint.get("run_id") != run_id
            or checkpoint.get("candidate_build_id") != candidate.build_id
            or checkpoint.get("question_sha256") != issue.question_sha256
            or checkpoint.get("status_disposition") != issue.status
            or checkpoint.get("filter_violation_count") != 0
            or checkpoint.get("checkpoint_state") != expected_state
            or checkpoint.get("status") != "succeeded"
            or not isinstance(ranked_tokens, list)
            or len(ranked_tokens) > 10
            or len(ranked_tokens) != len(set(ranked_tokens))
            or any(not isinstance(token, str) or not token for token in ranked_tokens)
        ):
            raise ValueError("Stage A checkpoint binding or ranking is invalid")
        attempt_number = checkpoint.get("retrieval_attempt_number")
        duration = checkpoint.get("duration_seconds")
        if issue.positive_ordinal is None:
            if attempt_number != 0 or ranked_tokens or duration != 0.0:
                raise ValueError("Stage A knowledge-gap checkpoint is invalid")
        elif (
            isinstance(attempt_number, bool)
            or not isinstance(attempt_number, int)
            or not 1 <= attempt_number <= MAX_ATTEMPTS
            or isinstance(duration, bool)
            or not isinstance(duration, int | float)
            or float(duration) < 0
        ):
            raise ValueError("Stage A scored checkpoint attempt identity is invalid")
        checkpoint_seals.append(str(checkpoint["seal_sha256"]))
        if issue.positive_ordinal is not None:
            rankings.append(_ranking_from_checkpoint(checkpoint, issue))

    checkpoint_set_sha256 = sealed_sha256(
        {
            "schema": "legalbot.live60-stage-a-checkpoint-set.v1",
            "checkpoint_seal_sha256s": checkpoint_seals,
        }
    )
    issues_for_scorer = [
        {"issue_id": issue.ranking_issue_id, "status": issue.status}
        for issue in validated.all_issues
    ]
    recomputed = score_stage_a_v2(
        issues=issues_for_scorer,
        unreviewed_issue_count=0,
        candidate_build_id=candidate.build_id,
        rankings=rankings,
    )
    recomputed.pop("seal_sha256", None)
    result = _read_existing_stage_a_artifact(
        run_dir, "stage-a-result.json", schema=STAGE_A_V2_SCHEMA
    )
    expected_result_fields: dict[str, Any] = {
        **recomputed,
        "run_id": run_id,
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
        "all60_qualification_seal_sha256": all60_qualification.seal_sha256,
        "expert_qualification_seal_sha256": expert_qualification.seal_sha256,
        "completion_preflight_verified_result_sha256": completion_preflight_seal,
        "completion_preflight_authoritative": (
            completion_preflight_seal != UNBOUND_COMPLETION_PREFLIGHT_SHA256
        ),
        "as_of_date": as_of_date.isoformat(),
        "case_count": 60,
        "issue_count": 585,
        "issue_status_counts": validated.status_counts,
        "issue_identity_set_sha256": validated.issue_identity_set_sha256,
        "completed_checkpoint_count": 585,
        "completed_issue_count": 585,
        "checkpoint_set_sha256": checkpoint_set_sha256,
        "runner_policy_sha256": STAGE_A_RUNNER_POLICY_SHA256,
        "scorer_identity_sha256": STAGE_A_SCORER_IDENTITY_SHA256,
        "code_revision": code_revision,
        "code_dirty": False,
        "timeout_count": 0,
        "worker_failure_count": 0,
        "hard_failure_count": 0,
        "writes_active": False,
        "writes_o04": False,
        "answer_generation_invoked": False,
        "run_status": "passed",
    }
    if any(result.get(key) != value for key, value in expected_result_fields.items()):
        raise ValueError("Stage A result differs from the verified checkpoint recomputation")
    if set(result) != {*expected_result_fields, "seal_sha256"}:
        raise ValueError("Stage A result contains unverified fields")
    if result.get("stage_a_passed") is not True or result.get("authorization_eligible") is not True:
        raise ValueError("Stage A verified checkpoint set did not pass")
    return result


def _failure_attempt(
    *,
    run_id: str,
    candidate: SealedCandidateIdentity,
    issue: StageAIssue,
    attempt_number: int,
    duration_seconds: float,
    reason_code: str,
    prior_fingerprints: Sequence[str],
) -> dict[str, Any]:
    fingerprint = failure_fingerprint(
        stage="stage_a_v2",
        reason_code=reason_code,
        scope_id=issue.ranking_issue_id,
        identity_digests=tuple(
            dict.fromkeys((candidate.candidate_manifest_sha256, issue.issue_identity_sha256))
        ),
    )
    decision = decide_retry(
        attempt_number=attempt_number,
        failure_reason_code=reason_code,
        failure_fingerprint_sha256=fingerprint,
        prior_failure_fingerprints=prior_fingerprints,
        deterministic_safety=reason_code in _DETERMINISTIC_FAILURES,
        retryable=reason_code not in _DETERMINISTIC_FAILURES,
        # Stage A has no durable proof that the candidate, query, worker or
        # retrieval condition changed between calls.  An attempt ordinal alone
        # is never a changed condition, so this lane stops and debugs instead
        # of spending a second retrieval on the same opaque failure.
        input_or_condition_changed=False,
    )
    return sealed_safe_payload(
        {
            "schema": STAGE_A_ATTEMPT_SCHEMA,
            "run_id": run_id,
            "candidate_build_id": candidate.build_id,
            "case_id": issue.case_id,
            "issue_id": issue.issue_id,
            "global_ordinal": issue.global_ordinal,
            "positive_ordinal": issue.positive_ordinal,
            "issue_identity_sha256": issue.issue_identity_sha256,
            "question_sha256": issue.question_sha256,
            "status_disposition": issue.status,
            "gold_span_ids": list(issue.gold_span_ids),
            "attempt_number": attempt_number,
            "duration_seconds": round(duration_seconds, 6),
            "failure_reason_code": reason_code,
            "failure_fingerprint_sha256": fingerprint,
            "decision_action": decision.action,
            "decision_reason": decision.reason,
            "retries_remaining": decision.retries_remaining,
            "status": "failed",
        }
    )


def _stop_payload(
    *,
    run_id: str,
    candidate_build_id: str,
    issue: StageAIssue,
    failure: Mapping[str, Any],
    completed_checkpoint_count: int,
) -> dict[str, Any]:
    return sealed_safe_payload(
        {
            "schema": STAGE_A_STOP_SCHEMA,
            "run_id": run_id,
            "candidate_build_id": candidate_build_id,
            "case_id": issue.case_id,
            "issue_id": issue.issue_id,
            "global_ordinal": issue.global_ordinal,
            "positive_ordinal": issue.positive_ordinal,
            "issue_identity_sha256": issue.issue_identity_sha256,
            "attempt_number": failure["attempt_number"],
            "failure_reason_code": failure["failure_reason_code"],
            "failure_fingerprint_sha256": failure["failure_fingerprint_sha256"],
            "stop_reason": failure["decision_reason"],
            "completed_checkpoint_count": completed_checkpoint_count,
            "writes_active": False,
            "writes_o04": False,
            "status": "stopped",
        }
    )


@contextmanager
def _stage_a_run_lock(*, output_root: Path, run_id: str) -> Iterator[BinaryIO]:
    if not re.fullmatch(r"^[a-z0-9][a-z0-9._:-]{2,127}$", run_id):
        raise ValueError("Stage A run ID is invalid")
    _private_directory(output_root)
    lock_digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:24]
    lock_path = output_root / f".stage-a-{lock_digest}.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    handle = os.fdopen(descriptor, "a+b")
    lock_path.chmod(0o600)
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("stage_a_run_already_locked") from exc
        yield handle
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


async def _run_stage_a_v2_create_only_unlocked(
    *,
    run_id: str,
    output_root: Path,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    all60_qualification: All60CaseQualification,
    expert_qualification: LiveSuiteExpertQualification,
    retriever: Any,
    as_of_date: date,
    code_revision: str,
    code_dirty: bool,
    database: Database | None = None,
    completion_preflight_verified_result_sha256: str | None = None,
) -> dict[str, Any]:
    """Run or safely resume a serial Stage A; never promote or authorize live."""

    if candidate.build_id != str(retriever.active_build_id() or ""):
        raise RuntimeError("candidate_identity_mismatch")
    validated = validate_stage_a_inputs(
        bundle=bundle,
        candidate=candidate,
        all60_qualification=all60_qualification,
        expert_qualification=expert_qualification,
        as_of_date=as_of_date,
    )
    completion_preflight_seal = (
        completion_preflight_verified_result_sha256 or UNBOUND_COMPLETION_PREFLIGHT_SHA256
    )
    if not _SHA256.fullmatch(completion_preflight_seal):
        raise ValueError("Stage A completion-preflight identity is invalid")
    expected_manifest = _expected_stage_a_run_manifest(
        run_id=run_id,
        bundle=bundle,
        candidate=candidate,
        all60_qualification=all60_qualification,
        expert_qualification=expert_qualification,
        as_of_date=as_of_date,
        code_revision=code_revision,
        code_dirty=code_dirty,
        validated=validated,
        completion_preflight_verified_result_sha256=completion_preflight_seal,
    )
    resume = (output_root / run_id).exists()
    store = CreateOnlyRunDirectory(root=output_root, run_id=run_id, resume=resume)
    if resume:
        observed_manifest = verify_sealed_artifact(
            store.read_json("run-manifest.json"), schema=STAGE_A_RUN_SCHEMA
        )
        if observed_manifest != expected_manifest:
            raise ValueError("Stage A resume manifest identity mismatch")
    else:
        store.write_json("run-manifest.json", expected_manifest)

    if store.exists("stage-a-result.json"):
        result = verify_sealed_artifact(store.read_json("stage-a-result.json"))
        if (
            result.get("candidate_build_id") != candidate.build_id
            or result.get("run_id") != run_id
            or result.get("issue_identity_set_sha256") != validated.issue_identity_set_sha256
        ):
            raise ValueError("completed Stage A result identity mismatch")
        return result
    if store.exists("STOPPED.json"):
        stopped = verify_sealed_artifact(
            store.read_json("STOPPED.json"), schema=STAGE_A_STOP_SCHEMA
        )
        if (
            stopped.get("run_id") != run_id
            or stopped.get("candidate_build_id") != candidate.build_id
        ):
            raise ValueError("stopped Stage A result identity mismatch")
        return stopped

    _validate_checkpoint_prefix(store)
    rankings: list[dict[str, Any]] = []
    checkpoint_seals: list[str] = []
    completed_checkpoint_count = 0
    try:
        for issue in validated.all_issues:
            checkpoint = _load_checkpoint(
                store,
                issue=issue,
                run_id=run_id,
                candidate_build_id=candidate.build_id,
            )
            if checkpoint is not None:
                completed_checkpoint_count += 1
                checkpoint_seals.append(str(checkpoint["seal_sha256"]))
                if issue.positive_ordinal is not None:
                    rankings.append(_ranking_from_checkpoint(checkpoint, issue))
                continue

            if issue.positive_ordinal is None:
                checkpoint = _knowledge_gap_checkpoint(
                    run_id=run_id,
                    candidate_build_id=candidate.build_id,
                    issue=issue,
                )
                store.write_json(_checkpoint_name(issue), checkpoint)
                completed_checkpoint_count += 1
                checkpoint_seals.append(str(checkpoint["seal_sha256"]))
                continue

            attempts = _load_attempts(
                store,
                issue=issue,
                run_id=run_id,
                candidate_build_id=candidate.build_id,
            )
            if attempts and attempts[-1]["status"] == "succeeded":
                checkpoint = _checkpoint_from_attempt(attempts[-1])
                store.write_json(_checkpoint_name(issue), checkpoint)
                rankings.append(_ranking_from_checkpoint(checkpoint, issue))
                completed_checkpoint_count += 1
                checkpoint_seals.append(str(checkpoint["seal_sha256"]))
                continue
            if attempts and attempts[-1]["decision_action"] == "stop":
                stopped = _stop_payload(
                    run_id=run_id,
                    candidate_build_id=candidate.build_id,
                    issue=issue,
                    failure=attempts[-1],
                    completed_checkpoint_count=completed_checkpoint_count,
                )
                store.write_json("STOPPED.json", stopped)
                return stopped

            prior_fingerprints = [
                str(value["failure_fingerprint_sha256"])
                for value in attempts
                if value["status"] == "failed"
            ]
            first_attempt = len(attempts) + 1
            for attempt_number in range(first_attempt, MAX_ATTEMPTS + 1):
                bind_retrieval_budget(
                    deadline_at=datetime.now(UTC)
                    + timedelta(seconds=STAGE_A_ISSUE_DEADLINE_SECONDS)
                )
                started = time.perf_counter()
                try:
                    evidence = tuple(
                        await retriever.retrieve(
                            query=issue.query,
                            jurisdiction=issue.jurisdiction,
                            subject=issue.subject,
                            as_of_date=as_of_date,
                            limit=10,
                            cacheable=True,
                        )
                    )
                    if any(
                        not _span_is_qualified(
                            span,
                            candidate_build_id=candidate.build_id,
                            issue=issue,
                            as_of_date=as_of_date,
                            database=database,
                        )
                        for span in evidence
                    ):
                        raise RuntimeError("evidence_filter_violation")
                    chunk_ids = tuple(_chunk_id(span) for span in evidence)
                    if len(chunk_ids) != len(set(chunk_ids)):
                        raise RuntimeError("retrieval_result_invalid")
                    ranked_tokens = _ranking_identity_tokens(
                        evidence,
                        issue=issue,
                        as_of_date=as_of_date,
                        database=database,
                        candidate_build_id=candidate.build_id,
                    )
                    attempt = sealed_safe_payload(
                        {
                            "schema": STAGE_A_ATTEMPT_SCHEMA,
                            "run_id": run_id,
                            "candidate_build_id": candidate.build_id,
                            "case_id": issue.case_id,
                            "issue_id": issue.issue_id,
                            "global_ordinal": issue.global_ordinal,
                            "positive_ordinal": issue.positive_ordinal,
                            "issue_identity_sha256": issue.issue_identity_sha256,
                            "question_sha256": issue.question_sha256,
                            "status_disposition": issue.status,
                            "gold_span_ids": list(issue.gold_span_ids),
                            "ranked_identity_tokens": list(ranked_tokens),
                            "attempt_number": attempt_number,
                            "duration_seconds": round(time.perf_counter() - started, 6),
                            "filter_violation_count": 0,
                            "status": "succeeded",
                        }
                    )
                except Exception as exc:
                    reason_code = _safe_reason_code(exc)
                    if isinstance(exc, RuntimeError) and exc.args:
                        explicit = str(exc.args[0]).strip().casefold().replace("-", "_")
                        if _SAFE_CODE.fullmatch(explicit):
                            reason_code = explicit
                    failure = _failure_attempt(
                        run_id=run_id,
                        candidate=candidate,
                        issue=issue,
                        attempt_number=attempt_number,
                        duration_seconds=time.perf_counter() - started,
                        reason_code=reason_code,
                        prior_fingerprints=prior_fingerprints,
                    )
                    store.write_json(_attempt_name(issue, attempt_number), failure)
                    prior_fingerprints.append(str(failure["failure_fingerprint_sha256"]))
                    if failure["decision_action"] == "retry":
                        continue
                    stopped = _stop_payload(
                        run_id=run_id,
                        candidate_build_id=candidate.build_id,
                        issue=issue,
                        failure=failure,
                        completed_checkpoint_count=completed_checkpoint_count,
                    )
                    store.write_json("STOPPED.json", stopped)
                    return stopped
                else:
                    bind_retrieval_budget(deadline_at=None)
                    store.write_json(_attempt_name(issue, attempt_number), attempt)
                    checkpoint = _checkpoint_from_attempt(attempt)
                    store.write_json(_checkpoint_name(issue), checkpoint)
                    rankings.append(_ranking_from_checkpoint(checkpoint, issue))
                    completed_checkpoint_count += 1
                    checkpoint_seals.append(str(checkpoint["seal_sha256"]))
                    break

        expected_ranking_ids = {issue.ranking_issue_id for issue in validated.positive_issues}
        observed_ranking_ids = {str(item["issue_id"]) for item in rankings}
        if (
            len(rankings) != len(validated.positive_issues)
            or len(observed_ranking_ids) != len(rankings)
            or observed_ranking_ids != expected_ranking_ids
        ):
            raise RuntimeError("stage_a_identity_mismatch")
        if completed_checkpoint_count != 585 or len(checkpoint_seals) != 585:
            raise RuntimeError("stage_a_identity_mismatch")
        issues_for_scorer = [
            {"issue_id": issue.ranking_issue_id, "status": issue.status}
            for issue in validated.all_issues
        ]
        scored = score_stage_a_v2(
            issues=issues_for_scorer,
            unreviewed_issue_count=0,
            candidate_build_id=candidate.build_id,
            rankings=rankings,
        )
        scored.update(
            {
                "run_id": run_id,
                "suite_id": bundle.manifest.suite_id,
                "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
                "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
                "run_plan_sha256": bundle.manifest.run_plan_sha256,
                "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
                "all60_qualification_seal_sha256": all60_qualification.seal_sha256,
                "expert_qualification_seal_sha256": expert_qualification.seal_sha256,
                "completion_preflight_verified_result_sha256": completion_preflight_seal,
                "completion_preflight_authoritative": (
                    completion_preflight_seal != UNBOUND_COMPLETION_PREFLIGHT_SHA256
                ),
                "as_of_date": as_of_date.isoformat(),
                "case_count": 60,
                "issue_count": 585,
                "issue_status_counts": validated.status_counts,
                "issue_identity_set_sha256": validated.issue_identity_set_sha256,
                "completed_checkpoint_count": completed_checkpoint_count,
                "completed_issue_count": completed_checkpoint_count,
                "checkpoint_set_sha256": sealed_sha256(
                    {
                        "schema": "legalbot.live60-stage-a-checkpoint-set.v1",
                        "checkpoint_seal_sha256s": checkpoint_seals,
                    }
                ),
                "runner_policy_sha256": STAGE_A_RUNNER_POLICY_SHA256,
                "scorer_identity_sha256": STAGE_A_SCORER_IDENTITY_SHA256,
                "code_revision": code_revision,
                "code_dirty": code_dirty,
                "timeout_count": 0,
                "worker_failure_count": 0,
                "hard_failure_count": 0,
                "writes_active": False,
                "writes_o04": False,
                "answer_generation_invoked": False,
                "run_status": ("passed" if scored["stage_a_passed"] is True else "gate_failed"),
            }
        )
        result = sealed_safe_payload(scored)
        store.write_json("stage-a-result.json", result)
        if result["stage_a_passed"] is not True:
            gate_failure = sealed_safe_payload(
                {
                    "schema": STAGE_A_GATE_FAILURE_SCHEMA,
                    "run_id": run_id,
                    "candidate_build_id": candidate.build_id,
                    "stage_a_result_seal_sha256": result["seal_sha256"],
                    "recall_at_5": result["recall_at_5"],
                    "recall_at_10": result["recall_at_10"],
                    "mrr": result["mrr"],
                    "filter_violation_count": result["filter_violation_count"],
                    "writes_active": False,
                    "writes_o04": False,
                    "status": "gate_failed",
                }
            )
            store.write_json("GATE-FAILED.json", gate_failure)
        return result
    finally:
        bind_retrieval_budget(deadline_at=None)


async def run_stage_a_v2_create_only(
    *,
    run_id: str,
    output_root: Path,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    all60_qualification: All60CaseQualification,
    expert_qualification: LiveSuiteExpertQualification,
    retriever: Any,
    as_of_date: date,
    code_revision: str,
    code_dirty: bool,
    database: Database | None = None,
    completion_preflight_verified_result_sha256: str | None = None,
) -> dict[str, Any]:
    """Run under a non-blocking advisory lease so only one writer can resume."""

    with _stage_a_run_lock(output_root=output_root, run_id=run_id):
        return await _run_stage_a_v2_create_only_unlocked(
            run_id=run_id,
            output_root=output_root,
            bundle=bundle,
            candidate=candidate,
            all60_qualification=all60_qualification,
            expert_qualification=expert_qualification,
            retriever=retriever,
            as_of_date=as_of_date,
            code_revision=code_revision,
            code_dirty=code_dirty,
            database=database,
            completion_preflight_verified_result_sha256=(
                completion_preflight_verified_result_sha256
            ),
        )
