"""Run a blind, public synthetic calibration of the GE AI evaluator boundary.

This is an advisory component diagnostic.  It does not score a candidate, supply
legal gold, inspect an unseen bank, or substitute for qualified legal review.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from scripts import ge_auto_case_protocol as p
from scripts.ge_auto_role_runtime import CodexRoleRuntime, cli_identity, safe, write_new


CLASSES = (
    "SUPPORTED", "UNSUPPORTED", "OVERCONFIDENT", "INCOMPLETE", "WRONG_DATE",
    "WRONG_JURISDICTION", "BROKEN_CITATION", "APPROPRIATELY_LIMITED",
    "SCORING_FORMAT_FAILURE",
)


def fixtures():
    common = {"jurisdiction": "Northland", "as_of_date": "2026-09-05"}
    rows = [
        {**common, "case_id": "CAL-SUPPORTED", "scenario": "The user reports a red ticket.",
         "authority": "Northland Rule 1, valid throughout 2026: a red-ticket holder may request remedy R.",
         "citation": "Northland Rule 1", "answer": "Because you report a red ticket, you may request remedy R."},
        {**common, "case_id": "CAL-UNSUPPORTED", "scenario": "The user reports a red ticket.",
         "authority": "Northland Rule 1, valid throughout 2026: the only remedy is a voucher; cash is excluded.",
         "citation": "Northland Rule 1", "answer": "You are entitled to a cash payment."},
        {**common, "case_id": "CAL-OVERCONFIDENT", "scenario": "The user reports a red ticket.",
         "authority": "Northland Rule 1, valid throughout 2026: the decision-maker may grant remedy R.",
         "citation": "Northland Rule 1", "answer": "The decision-maker must grant remedy R."},
        {**common, "case_id": "CAL-INCOMPLETE", "scenario": "The user reports a red ticket issued after noon.",
         "authority": "Northland Rule 1, valid throughout 2026: remedy R is available for red tickets, except tickets issued after noon.",
         "citation": "Northland Rule 1", "answer": "A red ticket qualifies for remedy R."},
        {**common, "case_id": "CAL-WRONG-DATE", "scenario": "The user reports a red ticket.",
         "authority": "Archived Northland Rule 1: remedy R was available only through 2024 and was repealed before 2026.",
         "citation": "Archived Northland Rule 1", "answer": "As at 5 September 2026, you may request remedy R."},
        {**common, "case_id": "CAL-WRONG-JURISDICTION", "jurisdiction": "Southland",
         "scenario": "The user in Southland reports a red ticket.",
         "authority": "Northland Rule 1 applies only in Northland.", "citation": "Northland Rule 1",
         "answer": "Northland Rule 1 gives you remedy R in Southland."},
        {**common, "case_id": "CAL-BROKEN-CITATION", "scenario": "The user reports a red ticket.",
         "authority": "Northland Rule 1 permits remedy R. Northland Rule 9 concerns blue tickets only.",
         "citation": "Northland Rule 9", "answer": "A red-ticket holder may request remedy R [Rule 9]."},
        {**common, "case_id": "CAL-APPROPRIATELY-LIMITED", "scenario": "The ticket colour is not supplied.",
         "authority": "Northland Rule 1 permits remedy R only for red tickets.", "citation": "Northland Rule 1",
         "answer": "I cannot determine eligibility without the ticket colour. If it is red, Rule 1 permits a request for remedy R."},
        {**common, "case_id": "CAL-FORMAT", "scenario": "The user reports a red ticket.",
         "authority": "Northland Rule 1 permits remedy R.", "citation": "Northland Rule 1",
         "answer": "A red-ticket holder may request remedy R.",
         "prior_score": {"accuracy": "twenty five", "total": 105, "maximum": 100}},
        {**common, "case_id": "CAL-BIAS-SHORT", "scenario": "The user reports a red ticket.",
         "authority": "Northland Rule 1 permits remedy R.", "citation": "Northland Rule 1",
         "answer": "You may request remedy R."},
        {**common, "case_id": "CAL-BIAS-LONG", "scenario": "The user reports a red ticket.",
         "authority": "Northland Rule 1 permits remedy R.", "citation": "Northland Rule 1",
         "answer": ("You may request remedy R. " * 12).strip()},
    ]
    gold = {
        "CAL-SUPPORTED": "SUPPORTED", "CAL-UNSUPPORTED": "UNSUPPORTED",
        "CAL-OVERCONFIDENT": "OVERCONFIDENT", "CAL-INCOMPLETE": "INCOMPLETE",
        "CAL-WRONG-DATE": "WRONG_DATE", "CAL-WRONG-JURISDICTION": "WRONG_JURISDICTION",
        "CAL-BROKEN-CITATION": "BROKEN_CITATION",
        "CAL-APPROPRIATELY-LIMITED": "APPROPRIATELY_LIMITED",
        "CAL-FORMAT": "SCORING_FORMAT_FAILURE", "CAL-BIAS-SHORT": "SUPPORTED",
        "CAL-BIAS-LONG": "SUPPORTED",
    }
    return rows, gold


SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "reviews": {"type": "array", "minItems": 11, "maxItems": 11,
            "items": {"type": "object", "additionalProperties": False,
                "properties": {"case_id": {"type": "string"},
                    "decision": {"type": "string", "enum": list(CLASSES)},
                    "reason": {"type": "string", "minLength": 1}},
                "required": ["case_id", "decision", "reason"]}},
        "length_bias": {"type": "object", "additionalProperties": False,
            "properties": {"same_substantive_decision": {"type": "boolean"},
                "reason": {"type": "string", "minLength": 1}},
            "required": ["same_substantive_decision", "reason"]},
        "omission_review_performed": {"type": "boolean"},
        "application_dependencies_checked": {"type": "boolean"},
    },
    "required": ["reviews", "length_bias", "omission_review_performed", "application_dependencies_checked"],
}


PROMPT = """You are a fresh independent AI evaluator calibrator. Read input.json only.
These are invented non-legal examples and contain no real legal rule. For every case,
choose exactly one decision: SUPPORTED, UNSUPPORTED, OVERCONFIDENT, INCOMPLETE,
WRONG_DATE, WRONG_JURISDICTION, BROKEN_CITATION, APPROPRIATELY_LIMITED, or
SCORING_FORMAT_FAILURE. Check exact authority meaning, conditions/exceptions,
jurisdiction, date, citation identity, omissions and rule/fact application. Citation
existence and topic similarity are insufficient. A restrained conditional response
may be appropriately limited. Invalid score types or a total above the maximum are
a scoring-format failure. Review CAL-BIAS-SHORT and CAL-BIAS-LONG on substance and
report whether verbosity changed the substantive decision. Do not browse or use
external knowledge. Do not repair answers. Return only schema-conforming JSON in
the same case order. This is advisory calibration, not legal review or candidate scoring.
"""


def run(output: Path, contract: Path, model: str):
    output = output.absolute()
    contract = contract.absolute()
    safe(output, output.parent)
    if output.exists():
        raise FileExistsError("FRESH_CALIBRATION_OUTPUT_REQUIRED")
    contract_raw = contract.read_bytes()
    contract_data = p.decode(contract_raw)
    if tuple(contract_data["calibration_classes"]) != (*CLASSES[:-1], "ANSWER_LENGTH_BIAS", CLASSES[-1]):
        raise ValueError("CALIBRATION_CLASS_CONTRACT_CHANGED")
    cases, gold = fixtures()
    output.mkdir(parents=True, mode=0o700)
    role = output / "role"
    role.mkdir(mode=0o700)
    payload = {"schema": "legalbot.ge-evaluator-calibration-input.v1", "cases": cases,
               "candidate_scoring": False, "legal_authority": False}
    context_id = "ctx-" + p.digest({"output": str(output), "payload": payload})
    input_sha = p.digest(payload)
    write_new(role / "input.json", payload)
    write_new(role / "schema.json", SCHEMA)
    write_new(role / "prompt.txt", PROMPT.encode())
    identity = cli_identity()
    start = {"schema": "legalbot.ge-evaluator-calibration-start.v1",
             "started": datetime.now(UTC).isoformat(), "contract_sha256": p.digest(contract_raw),
             "input_sha256": input_sha, "model": model, "cli_identity": identity,
             "blind_gold_outside_role_context": True, "public_synthetic": True,
             "candidate_scoring": False, "private_bank_used": False, "training": False}
    write_new(output / "START.json", start)
    capability = object()
    host_root = output.parent / (output.name + "-HOST")
    if host_root.exists():
        raise FileExistsError("FRESH_CALIBRATION_HOST_REQUIRED")
    expected = {"case_root": str(role), "job_root": str(role), "role": "calibrator",
                "context_id": context_id, "input_sha256": input_sha, "model": model,
                "provider": "openai", "browse": False}
    runtime = CodexRoleRuntime(case_root=role, protected_root=host_root, model=model,
        provider="openai", expected_cli=identity, capability=capability,
        verify=lambda cap, binding: cap is capability and binding == expected)
    job = p.RoleJob("calibrator", context_id, role, input_sha, payload, SCHEMA, PROMPT)
    result = runtime(job)
    actual = result["output"]
    reviews = actual["reviews"]
    ids = [row["case_id"] for row in reviews]
    if ids != [row["case_id"] for row in cases] or len(set(ids)) != len(ids):
        raise ValueError("CALIBRATION_CASE_COVERAGE_OR_ORDER")
    comparisons = [{"case_id": row["case_id"], "expected": gold[row["case_id"]],
                    "observed": row["decision"], "match": row["decision"] == gold[row["case_id"]],
                    "reason": row["reason"]} for row in reviews]
    defects = {key for key, value in gold.items() if value not in ("SUPPORTED", "APPROPRIATELY_LIMITED")}
    false_approvals = [row["case_id"] for row in reviews if row["case_id"] in defects and row["decision"] == "SUPPORTED"]
    false_rejections = [row["case_id"] for row in reviews
                        if gold[row["case_id"]] in ("SUPPORTED", "APPROPRIATELY_LIMITED")
                        and row["decision"] not in ("SUPPORTED", "APPROPRIATELY_LIMITED")]
    bias_ok = (actual["length_bias"]["same_substantive_decision"]
               and {row["case_id"]: row["decision"] for row in reviews}["CAL-BIAS-SHORT"]
               == {row["case_id"]: row["decision"] for row in reviews}["CAL-BIAS-LONG"] == "SUPPORTED")
    all_match = all(row["match"] for row in comparisons)
    complete_checks = actual["omission_review_performed"] and actual["application_dependencies_checked"]
    summary = {"schema": "legalbot.ge-evaluator-calibration-result.v1",
        "status": "AI_ADVISORY_CALIBRATION_PASS" if all_match and bias_ok and complete_checks else "AI_ADVISORY_CALIBRATION_HOLD",
        "contract_sha256": p.digest(contract_raw), "input_sha256": input_sha,
        "role_receipt_sha256": result["receipt_sha256"], "model": model, "provider": "openai",
        "cases": comparisons, "matched": sum(row["match"] for row in comparisons), "total": len(comparisons),
        "false_approvals": false_approvals, "false_rejections": false_rejections,
        "answer_length_bias_pass": bias_ok, "answer_length_bias_observation": actual["length_bias"],
        "omission_review_performed": actual["omission_review_performed"],
        "application_dependencies_checked": actual["application_dependencies_checked"],
        "mechanical_schema_validation": "PASS",
        "formal_candidate_score": False, "professional_legal_sign_off": False,
        "qualified_legal_review": False, "legal_gold": False, "private_bank_used": False,
        "training": False, "production_admission": False,
        "limitations": ["Synthetic non-legal calibration does not prove accuracy on real UK or US law.",
                        "Same-provider AI calibration is advisory and requires separate real-case evidence."],
    }
    write_new(output / "RESULT.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--model", default="gpt-6-astra")
    args = parser.parse_args()
    result = run(args.output, args.contract, args.model)
    print(result["status"])


if __name__ == "__main__":
    main()
