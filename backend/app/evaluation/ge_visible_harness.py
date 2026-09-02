"""Visible General Enquiry factual-first evaluation preparation and scoring."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..contracts import ContractSchemaRegistry, canonical_json_bytes, seal_contract

VISIBLE_CASE_COUNT = 331
VISIBLE_CORE_COUNT = 306
VISIBLE_STRESS_COUNT = 25
SYSTEM_SCENARIO_COUNT = 32

FACTUAL_CHECKS: tuple[str, ...] = (
    "integrity_chain",
    "claim_evidence_support",
    "user_fact_provenance",
    "jurisdiction_scope",
    "requested_date_and_currentness",
    "dates_amounts_and_deadlines",
    "citation_and_quotation_identity",
    "contradiction_and_counterauthority",
    "safety_and_urgent_action",
    "privacy_and_instruction_isolation",
)

QUALITY_DIMENSION_MAX: Mapping[str, float] = {
    "legal_and_factual_accuracy": 25.0,
    "issue_coverage_and_reasoning": 15.0,
    "authority_and_currentness": 15.0,
    "practical_steps_and_urgency": 15.0,
    "uncertainty_limits_and_clarification": 10.0,
    "organisation_and_plain_language": 10.0,
    "traceability_and_citations": 10.0,
}

QUALITY_CRITICAL_FLOORS: Mapping[str, float] = {
    "legal_and_factual_accuracy": 17.5,
    "authority_and_currentness": 10.5,
    "practical_steps_and_urgency": 9.0,
}


class VisibleGEHarnessError(ValueError):
    """The visible pack, denominator or factual-first policy was violated."""


@dataclass(frozen=True, slots=True)
class VisibleGERunBindings:
    authorization_sha256: str
    candidate_sha256: str
    runtime_config_sha256: str
    gold_currentness_decision_sha256: str
    private_root_capability_sha256: str
    exposure_ledger_sha256: str
    model_sha256: str
    prompt_sha256: str
    renderer_sha256: str
    validator_bundle_sha256: str
    resource_policy_sha256: str


def _legacy_canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class VisibleGECase:
    case_id: str
    version_id: str
    record_sha256: str
    ordinal: int
    scenario_family_id: str
    lane: str
    prompt: str
    raw: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class VisibleGESystemScenario:
    case_id: str
    ordinal: int
    category: str
    record_sha256: str
    raw: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class VisibleGEPack:
    run_id: str
    content_version: str
    pack_manifest_sha256: str
    source_file_sha256: str
    case_manifest_sha256: str
    case_order_sha256: str
    input_projection_sha256: str
    system_manifest_sha256: str
    system_order_sha256: str
    cases: tuple[VisibleGECase, ...]
    system_scenarios: tuple[VisibleGESystemScenario, ...]

    @classmethod
    def load(cls, directory: Path) -> VisibleGEPack:
        directory = directory.resolve(strict=True)
        manifest_path = directory / "PACK-MANIFEST.json"
        cases_path = directory / "GE-VISIBLE-REVIEW.jsonl"
        system_path = directory / "SYSTEM-SCENARIOS.json"
        for path in (manifest_path, cases_path, system_path):
            if not path.is_file() or path.is_symlink():
                raise VisibleGEHarnessError(f"visible GE pack member is missing: {path.name}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise VisibleGEHarnessError("visible GE manifest is not an object")
        claimed_manifest_digest = str(manifest.get("content_sha256") or "")
        manifest_material = dict(manifest)
        manifest_material.pop("content_sha256", None)
        if (
            hashlib.sha256(_legacy_canonical(manifest_material)).hexdigest()
            != claimed_manifest_digest
        ):
            raise VisibleGEHarnessError("visible GE pack manifest digest changed")
        artifact_map = {
            str(item["path"]): str(item["sha256"])
            for item in manifest.get("artifacts", [])
            if isinstance(item, dict) and "path" in item and "sha256" in item
        }
        if artifact_map.get(cases_path.name) != _file_sha256(cases_path):
            raise VisibleGEHarnessError("visible GE case file digest changed")
        if artifact_map.get(system_path.name) != _file_sha256(system_path):
            raise VisibleGEHarnessError("system-scenario file digest changed")
        rows: list[dict[str, Any]] = []
        for line_number, line in enumerate(cases_path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise VisibleGEHarnessError(f"case row {line_number} is not an object")
            material = dict(value)
            claimed = str(material.pop("record_content_sha256", ""))
            if hashlib.sha256(_legacy_canonical(material)).hexdigest() != claimed:
                raise VisibleGEHarnessError(f"case row {line_number} digest changed")
            rows.append(value)
        if len(rows) != VISIBLE_CASE_COUNT:
            raise VisibleGEHarnessError("visible GE denominator is not exactly 331")
        case_ids = [str(row.get("question_id") or "") for row in rows]
        version_ids = [str(row.get("question_version_id") or "") for row in rows]
        if len(set(case_ids)) != len(case_ids) or len(set(version_ids)) != len(version_ids):
            raise VisibleGEHarnessError("visible GE case identity is duplicated")
        ordinals = [int(row.get("source_review_ordinal") or 0) for row in rows]
        if ordinals != list(range(1, VISIBLE_CASE_COUNT + 1)):
            raise VisibleGEHarnessError("visible GE order is incomplete or changed")
        lane_counts = Counter("stress" if "STRESS" in str(row["lane"]) else "core" for row in rows)
        if lane_counts != {"core": VISIBLE_CORE_COUNT, "stress": VISIBLE_STRESS_COUNT}:
            raise VisibleGEHarnessError("visible GE core/stress denominator changed")
        for row in rows:
            if (
                row.get("question_type") != "GENERAL_ENQUIRY"
                or row.get("content_version") != "GE-visible-r3"
                or row.get("usage_role") != "VISIBLE_DEVELOPMENT_EVALUATION_REVIEW_ONLY"
                or row.get("permanently_ineligible_for_unseen_validation") is not True
                or row.get("unseen_eligible") is not False
                or row.get("training_export_eligible") is not False
                or not str(row.get("prompt") or "").strip()
            ):
                raise VisibleGEHarnessError(f"visible GE custody rule failed: {row['question_id']}")
        system_value = json.loads(system_path.read_text(encoding="utf-8"))
        system_records = system_value.get("records") if isinstance(system_value, dict) else None
        if not isinstance(system_records, list) or len(system_records) != SYSTEM_SCENARIO_COUNT:
            raise VisibleGEHarnessError("system scenarios are not exactly 32 separate records")
        system_ids: list[str] = []
        system_scenarios: list[VisibleGESystemScenario] = []
        for ordinal, record in enumerate(system_records, start=1):
            if not isinstance(record, dict):
                raise VisibleGEHarnessError("system scenario is not an object")
            case_id = str(record.get("system_case_id") or "")
            turns = record.get("user_turns")
            if (
                not case_id
                or record.get("usage_role") != "SYSTEM_BEHAVIOUR_REVIEW_ONLY"
                or record.get("execution_authorized") is not False
                or not isinstance(turns, list)
                or not turns
                or any(
                    not isinstance(turn, dict)
                    or turn.get("role") not in {"user", "assistant"}
                    or not str(turn.get("content") or "").strip()
                    for turn in turns
                )
                or not any(isinstance(turn, dict) and turn.get("role") == "user" for turn in turns)
                or not isinstance(record.get("expected_behaviour"), list)
                or not record["expected_behaviour"]
                or not isinstance(record.get("prohibited_behaviour"), list)
                or not record["prohibited_behaviour"]
            ):
                raise VisibleGEHarnessError(f"system scenario custody rule failed: {case_id}")
            system_ids.append(case_id)
            system_scenarios.append(
                VisibleGESystemScenario(
                    case_id=case_id,
                    ordinal=ordinal,
                    category=str(record.get("category") or "unknown"),
                    record_sha256=hashlib.sha256(canonical_json_bytes(record)).hexdigest(),
                    raw=record,
                )
            )
        if len(set(system_ids)) != SYSTEM_SCENARIO_COUNT:
            raise VisibleGEHarnessError("system scenario identity is duplicated")
        if (
            manifest.get("visible_total") != VISIBLE_CASE_COUNT
            or manifest.get("visible_core") != VISIBLE_CORE_COUNT
            or manifest.get("visible_stress") != VISIBLE_STRESS_COUNT
            or manifest.get("system_cases_separate") != SYSTEM_SCENARIO_COUNT
            or manifest.get("approved_training_examples") != 0
            or manifest.get("approved_gold_answers") != 0
        ):
            raise VisibleGEHarnessError("visible GE manifest execution boundary changed")

        case_manifest = [
            {
                "case_id": row["question_id"],
                "case_version_id": row["question_version_id"],
                "case_version_sha256": row["record_content_sha256"],
                "ordinal": row["source_review_ordinal"],
                "scenario_family_id": row["scenario_family_id"],
            }
            for row in rows
        ]
        input_projection = [
            {
                "case_id": row["question_id"],
                "prompt": row["prompt"],
                "primary_jurisdiction": row["primary_jurisdiction"],
                "legal_currentness_cutoff": row["legal_currentness_cutoff"],
                "material_dates": row["material_dates"],
                "clarification_criteria": row["proposed_clarification_criteria"],
                "immediate_actions": row["immediate_actions"],
                "prohibited_overstatement": row["prohibited_overstatement"],
            }
            for row in rows
        ]
        cases = tuple(
            VisibleGECase(
                case_id=str(row["question_id"]),
                version_id=str(row["question_version_id"]),
                record_sha256=str(row["record_content_sha256"]),
                ordinal=int(row["source_review_ordinal"]),
                scenario_family_id=str(row["scenario_family_id"]),
                lane=str(row["lane"]),
                prompt=str(row["prompt"]),
                raw=row,
            )
            for row in rows
        )
        return cls(
            run_id=str(manifest["run_id"]),
            content_version=str(manifest["content_version"]),
            pack_manifest_sha256=claimed_manifest_digest,
            source_file_sha256=_file_sha256(cases_path),
            case_manifest_sha256=hashlib.sha256(canonical_json_bytes(case_manifest)).hexdigest(),
            case_order_sha256=hashlib.sha256(canonical_json_bytes(case_ids)).hexdigest(),
            input_projection_sha256=hashlib.sha256(
                canonical_json_bytes(input_projection)
            ).hexdigest(),
            system_manifest_sha256=hashlib.sha256(
                canonical_json_bytes(
                    [
                        {
                            "case_id": scenario.case_id,
                            "ordinal": scenario.ordinal,
                            "category": scenario.category,
                            "record_sha256": scenario.record_sha256,
                        }
                        for scenario in system_scenarios
                    ]
                )
            ).hexdigest(),
            system_order_sha256=hashlib.sha256(canonical_json_bytes(system_ids)).hexdigest(),
            cases=cases,
            system_scenarios=tuple(system_scenarios),
        )

    def review_worksheet(self) -> list[dict[str, Any]]:
        return [
            {
                "schema": "legalbot.ge-visible-review-worksheet.v1",
                "case_id": case.case_id,
                "case_version_id": case.version_id,
                "case_version_sha256": case.record_sha256,
                "ordinal": case.ordinal,
                "scenario_family_id": case.scenario_family_id,
                "factual_checks": {name: "UNREVIEWED" for name in FACTUAL_CHECKS},
                "factual_report_sha256": None,
                "quality_dimensions": {name: None for name in QUALITY_DIMENSION_MAX},
                "quality_report_sha256": None,
                "root_cause_layers": [],
                "owner_notes": "",
            }
            for case in self.cases
        ]

    def system_review_worksheet(self) -> list[dict[str, Any]]:
        """Return a separate, unscored system-behaviour review worksheet."""

        return [
            {
                "schema": "legalbot.ge-system-review-worksheet.v1",
                "system_case_id": scenario.case_id,
                "ordinal": scenario.ordinal,
                "category": scenario.category,
                "record_sha256": scenario.record_sha256,
                "expected_behaviour_checks": [
                    {"criterion": criterion, "result": "UNREVIEWED"}
                    for criterion in scenario.raw["expected_behaviour"]
                ],
                "prohibited_behaviour_checks": [
                    {"criterion": criterion, "observed": "UNREVIEWED"}
                    for criterion in scenario.raw["prohibited_behaviour"]
                ],
                "terminal_state": "NOT_RUN",
                "system_report_sha256": None,
                "owner_notes": "",
            }
            for scenario in self.system_scenarios
        ]


def factual_gate_passes(checks: Mapping[str, str]) -> bool:
    if set(checks) != set(FACTUAL_CHECKS):
        raise VisibleGEHarnessError("factual gate check set is incomplete")
    allowed = {"PASS", "FAIL", "NOT_APPLICABLE"}
    if any(value not in allowed for value in checks.values()):
        raise VisibleGEHarnessError("factual gate has an invalid result")
    return all(value in {"PASS", "NOT_APPLICABLE"} for value in checks.values())


def quality_outcome(scores: Mapping[str, float]) -> tuple[float, str]:
    if set(scores) != set(QUALITY_DIMENSION_MAX):
        raise VisibleGEHarnessError("GE quality dimension set is incomplete")
    for name, maximum in QUALITY_DIMENSION_MAX.items():
        value = float(scores[name])
        if not 0 <= value <= maximum:
            raise VisibleGEHarnessError(f"GE quality score is out of range: {name}")
    total = round(sum(float(value) for value in scores.values()), 2)
    if any(float(scores[name]) < floor for name, floor in QUALITY_CRITICAL_FLOORS.items()):
        return total, "MATERIAL_IMPROVEMENT_REQUIRED"
    if total >= 80:
        return total, "EXCEEDS_70_STANDARD"
    if total >= 70:
        return total, "MEETS_70_STANDARD"
    if total >= 60:
        return total, "BELOW_70_STANDARD"
    return total, "MATERIAL_IMPROVEMENT_REQUIRED"


def build_case_result(
    *,
    registry: ContractSchemaRegistry,
    run_id: str,
    case: VisibleGECase,
    job_id: str | None,
    release_id: str | None,
    factual_checks: Mapping[str, str],
    factual_report_sha256: str,
    quality_scores: Mapping[str, float] | None,
    quality_report_sha256: str | None,
    root_cause_layers: Sequence[str],
    review_decision_sha256: str | None,
    started_at: datetime,
    completed_at: datetime,
) -> dict[str, Any]:
    factual_pass = factual_gate_passes(factual_checks)
    if factual_pass:
        if quality_scores is None or quality_report_sha256 is None:
            raise VisibleGEHarnessError("quality review is required after factual pass")
        score, outcome = quality_outcome(quality_scores)
        factual_outcome = "FACTUAL_PASS"
        terminal_state = "completed"
    else:
        if quality_scores is not None or quality_report_sha256 is not None:
            raise VisibleGEHarnessError("quality scoring cannot run after factual hold")
        score = None
        outcome = "NOT_ELIGIBLE"
        factual_outcome = "FACTUAL_HOLD"
        terminal_state = "held"
    value = seal_contract(
        {
            "schema": "legalbot.evaluation-case-result.v2",
            "result_id": f"result-{run_id}-{case.ordinal:03d}",
            "run_id": run_id,
            "case_id": case.case_id,
            "case_version_sha256": case.record_sha256,
            "scenario_family_id": case.scenario_family_id,
            "ordinal": case.ordinal,
            "job_id": job_id,
            "release_id": release_id,
            "terminal_state": terminal_state,
            "factual_outcome": factual_outcome,
            "factual_report_sha256": factual_report_sha256,
            "factual_checks": [
                {"check_id": name, "outcome": factual_checks[name]}
                for name in FACTUAL_CHECKS
            ],
            "quality_outcome": outcome,
            "quality_score": score,
            "quality_report_sha256": quality_report_sha256,
            "quality_dimensions": (
                [
                    {"dimension_id": name, "score": float(quality_scores[name])}
                    for name in QUALITY_DIMENSION_MAX
                ]
                if quality_scores is not None
                else None
            ),
            "root_cause_layers": list(root_cause_layers),
            "review_decision_sha256": review_decision_sha256,
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
        }
    )
    registry.validate_new(value)
    return value


def validate_case_result(
    *,
    registry: ContractSchemaRegistry,
    result: Mapping[str, Any],
    case: VisibleGECase,
    run_id: str,
) -> None:
    """Replay one selected v2 result from its exact ordered review evidence."""

    if result.get("schema") != "legalbot.evaluation-case-result.v2":
        raise VisibleGEHarnessError(
            "visible GE diagnosis/run requires selected evaluation-case-result v2"
        )
    registry.validate_new(result)
    factual_rows = result.get("factual_checks")
    quality_rows = result.get("quality_dimensions")
    causes_raw = result.get("root_cause_layers")
    if not isinstance(factual_rows, list) or not isinstance(causes_raw, list):
        raise VisibleGEHarnessError("visible GE result review evidence is invalid")
    try:
        factual_checks = {
            str(row["check_id"]): str(row["outcome"])
            for row in factual_rows
            if isinstance(row, Mapping)
        }
        if len(factual_checks) != len(factual_rows):
            raise ValueError
        if quality_rows is None:
            quality_scores: Mapping[str, float] | None = None
        elif isinstance(quality_rows, list):
            quality_scores = {
                str(row["dimension_id"]): float(row["score"])
                for row in quality_rows
                if isinstance(row, Mapping)
            }
            if len(quality_scores) != len(quality_rows):
                raise ValueError
        else:
            raise ValueError
        started_at = datetime.fromisoformat(str(result["started_at"]))
        completed_at = datetime.fromisoformat(str(result["completed_at"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise VisibleGEHarnessError(
            "visible GE result review evidence cannot be replayed"
        ) from exc
    expected = build_case_result(
        registry=registry,
        run_id=run_id,
        case=case,
        job_id=str(result["job_id"]) if result.get("job_id") is not None else None,
        release_id=(
            str(result["release_id"]) if result.get("release_id") is not None else None
        ),
        factual_checks=factual_checks,
        factual_report_sha256=str(result.get("factual_report_sha256") or ""),
        quality_scores=quality_scores,
        quality_report_sha256=(
            str(result["quality_report_sha256"])
            if result.get("quality_report_sha256") is not None
            else None
        ),
        root_cause_layers=tuple(str(value) for value in causes_raw),
        review_decision_sha256=(
            str(result["review_decision_sha256"])
            if result.get("review_decision_sha256") is not None
            else None
        ),
        started_at=started_at,
        completed_at=completed_at,
    )
    if canonical_json_bytes(expected) != canonical_json_bytes(result):
        raise VisibleGEHarnessError(
            "visible GE result aggregate differs from its exact review evidence"
        )


def build_completed_visible_ge_run(
    *,
    registry: ContractSchemaRegistry,
    pack: VisibleGEPack,
    run_id: str,
    case_results: Sequence[Mapping[str, Any]],
    bindings: VisibleGERunBindings,
    started_at: datetime,
    completed_at: datetime,
) -> dict[str, Any]:
    """Reconcile a closed 331-case result set into one selected EvaluationRun."""

    if started_at.tzinfo is None or completed_at.tzinfo is None:
        raise VisibleGEHarnessError("evaluation run timestamps must be timezone-aware")
    if completed_at < started_at:
        raise VisibleGEHarnessError("evaluation run completed before it started")
    if len(case_results) != VISIBLE_CASE_COUNT:
        raise VisibleGEHarnessError("completed visible GE run must contain exactly 331 results")

    ordered: list[Mapping[str, Any]] = []
    result_ids: set[str] = set()
    for case, result in zip(pack.cases, case_results, strict=True):
        validate_case_result(registry=registry, result=result, case=case, run_id=run_id)
        if (
            result["run_id"] != run_id
            or result["case_id"] != case.case_id
            or result["case_version_sha256"] != case.record_sha256
            or result["scenario_family_id"] != case.scenario_family_id
            or result["ordinal"] != case.ordinal
        ):
            raise VisibleGEHarnessError(f"visible GE result identity/order differs: {case.case_id}")
        result_id = str(result["result_id"])
        if result_id in result_ids:
            raise VisibleGEHarnessError("visible GE result identity is duplicated")
        result_ids.add(result_id)
        terminal = str(result["terminal_state"])
        factual = str(result["factual_outcome"])
        quality = str(result["quality_outcome"])
        if terminal == "completed" and factual != "FACTUAL_PASS":
            raise VisibleGEHarnessError("completed GE case did not pass the factual gate")
        if terminal == "held" and factual != "FACTUAL_HOLD":
            raise VisibleGEHarnessError("held GE case lacks a factual hold")
        if terminal == "system_error" and factual != "SYSTEM_ERROR":
            raise VisibleGEHarnessError("system-error GE case has the wrong factual outcome")
        if terminal in {"cancelled", "ineligible"} and factual != "NOT_RUN":
            raise VisibleGEHarnessError("unrun GE case has the wrong factual outcome")
        if terminal != "completed" and quality not in {"NOT_ELIGIBLE", "NOT_RUN"}:
            raise VisibleGEHarnessError("non-completed GE case cannot have a quality outcome")
        ordered.append(result)

    counts = Counter(str(result["terminal_state"]) for result in ordered)
    count_object = {
        name: counts.get(name, 0)
        for name in ("completed", "held", "system_error", "cancelled", "ineligible")
    }
    if sum(count_object.values()) != VISIBLE_CASE_COUNT:
        raise VisibleGEHarnessError("visible GE terminal counts do not reconcile")
    result_manifest = [
        {
            "ordinal": result["ordinal"],
            "case_id": result["case_id"],
            "result_id": result["result_id"],
            "content_sha256": result["content_sha256"],
            "terminal_state": result["terminal_state"],
        }
        for result in ordered
    ]
    factual_policy, quality_policy = policy_documents()
    factual_policy_sha256 = str(factual_policy["content_sha256"])
    quality_policy_sha256 = str(quality_policy["content_sha256"])
    scoring_policy_sha256 = hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "legalbot.ge-visible-scoring-policy-binding.v1",
                "factual_gate_policy_sha256": factual_policy_sha256,
                "quality_gate_policy_sha256": quality_policy_sha256,
                "factual_first": True,
                "visible_case_count": VISIBLE_CASE_COUNT,
                "system_scenario_count": SYSTEM_SCENARIO_COUNT,
            }
        )
    ).hexdigest()
    contract_pack_sha256 = hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "legalbot.ge-visible-contract-pack-binding.v1",
                "pack_manifest_sha256": pack.pack_manifest_sha256,
                "schema_selection_sha256": registry.manifest_sha256,
                "scoring_policy_sha256": scoring_policy_sha256,
            }
        )
    ).hexdigest()
    run_valid = not any(count_object[name] for name in ("system_error", "cancelled", "ineligible"))
    value = {
        "schema": "legalbot.evaluation-run.v1",
        "run_id": run_id,
        "lane": "visible_development",
        "authorization_sha256": bindings.authorization_sha256,
        "case_manifest_sha256": pack.case_manifest_sha256,
        "case_order_sha256": pack.case_order_sha256,
        "case_count": VISIBLE_CASE_COUNT,
        "candidate_sha256": bindings.candidate_sha256,
        "runtime_config_sha256": bindings.runtime_config_sha256,
        "gold_currentness_decision_sha256": bindings.gold_currentness_decision_sha256,
        "private_root_capability_sha256": bindings.private_root_capability_sha256,
        "exposure_ledger_sha256": bindings.exposure_ledger_sha256,
        "result_counts": count_object,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "contract_pack_sha256": contract_pack_sha256,
        "schema_selection_sha256": registry.manifest_sha256,
        "input_projection_sha256": pack.input_projection_sha256,
        "scoring_policy_sha256": scoring_policy_sha256,
        "factual_gate_policy_sha256": factual_policy_sha256,
        "quality_gate_policy_sha256": quality_policy_sha256,
        "model_sha256": bindings.model_sha256,
        "prompt_sha256": bindings.prompt_sha256,
        "renderer_sha256": bindings.renderer_sha256,
        "validator_bundle_sha256": bindings.validator_bundle_sha256,
        "case_result_manifest_sha256": hashlib.sha256(
            canonical_json_bytes(result_manifest)
        ).hexdigest(),
        "case_result_count": len(ordered),
        "question_mode": "general_enquiry",
        "run_status": "completed",
        "run_validity": "PASS" if run_valid else "FAIL",
        "resource_policy_sha256": bindings.resource_policy_sha256,
    }
    registry.validate_new(value)
    return value


def policy_documents() -> tuple[dict[str, Any], dict[str, Any]]:
    factual = {
        "schema": "legalbot.ge-factual-gate-policy.v1",
        "gate_order": 1,
        "all_material_checks_must_pass": True,
        "checks": list(FACTUAL_CHECKS),
        "failure_effect": "FACTUAL_HOLD_AND_NO_QUALITY_SCORE",
        "advisory_model_may_override": False,
    }
    factual["content_sha256"] = hashlib.sha256(canonical_json_bytes(factual)).hexdigest()
    quality = {
        "schema": "legalbot.ge-quality-gate-policy.v1",
        "gate_order": 2,
        "requires_factual_pass": True,
        "dimension_max": dict(QUALITY_DIMENSION_MAX),
        "critical_floors": dict(QUALITY_CRITICAL_FLOORS),
        "meets_70_threshold": 70,
        "exceeds_70_threshold": 80,
        "standards_basis": [
            "accurate_detailed_comprehensive_legal_knowledge",
            "problem_solving_and_defensible_application",
            "relevant_primary_and_secondary_authority",
            "synthesis_critical_evaluation_and_independence",
            "clear_economical_confident_communication",
            "current_authority_uncertainty_counterarguments_and_correct_oscola",
            "plain_language_practical_general_enquiry_overlay",
        ],
    }
    quality["content_sha256"] = hashlib.sha256(canonical_json_bytes(quality)).hexdigest()
    return factual, quality


__all__ = [
    "FACTUAL_CHECKS",
    "QUALITY_CRITICAL_FLOORS",
    "QUALITY_DIMENSION_MAX",
    "VisibleGECase",
    "VisibleGEHarnessError",
    "VisibleGEPack",
    "VisibleGERunBindings",
    "VisibleGESystemScenario",
    "build_case_result",
    "build_completed_visible_ge_run",
    "factual_gate_passes",
    "policy_documents",
    "quality_outcome",
    "validate_case_result",
]
