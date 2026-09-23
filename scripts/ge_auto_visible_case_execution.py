"""Execute independently authored visible cases through the actual isolated host.

Preparation discloses no reference proposals to candidate roles. Each case gets
only its due prompt, actual upload extraction and its own completed history.
The active parent must service the protected functions.web mailbox. This is
visible implementation validation, never an unseen result or a training job.
"""
from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from scripts import ge_auto_case_protocol as p
from scripts.ge_auto_case_host import CaseHost, runtime_manifest
from scripts.ge_auto_role_runtime import CodexRoleRuntime, safe, write_new

ROOT = Path(__file__).resolve().parents[1]
VISIBLE = ROOT / "data/evaluations/general-enquiries/ge-auto-research-visible-20260905"
PUBLIC = ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-05-codex-unseen-r1"
CASES = VISIBLE / "author-research/CASES.json"
OWNER = PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json"
JURISDICTIONS = {"GB-ENG": "England", "GB-WLS": "Wales", "GB-SCT": "Scotland",
                 "GB-NIR": "Northern Ireland", "US-FED": "US federal",
                 "US-CA": "California", "US-NY": "New York", "US-TX": "Texas"}
VERSION = "legalbot.ge-visible-case-execution.v1"


def sha(path):
    safe(path, ROOT)
    return p.digest(path.read_bytes())


def read(path):
    safe(path, ROOT)
    return p.decode(path.read_bytes())


def completion_summary(turns, error, *, unresolved_operations=()):
    """Separate process completion, runtime health and answer disposition.

    A recorded final HOLD after a broken callback is not a successful route.
    This summary never substitutes for independent answer review.
    """
    answers = [t.get("answer", {}).get("status", "MISSING") for t in turns]
    holds = sorted({h for turn in turns for h in turn.get("holds", [])})
    technical = sorted(h for h in holds if h not in p.HOLDS)
    if error is not None or unresolved_operations or technical or not turns:
        status = "EXECUTION_HOLD"
    elif all(answer == "ANSWER" for answer in answers):
        status = "EXECUTED_PENDING_BLIND_REVIEW"
    else:
        status = "HELD_OR_LIMITED_PENDING_BLIND_REVIEW"
    return {"status": status, "answer_dispositions": answers, "terminal_holds": holds,
            "runtime_hold_codes": technical, "unresolved_operations": list(unresolved_operations),
            "supported_answer_proven": False}


def unresolved_operation_failures(case_root):
    failures = []
    for operation in sorted((case_root / "operations").glob("*")):
        # A successfully completed successor attempt retains its failed history.
        if any(operation.glob("attempt-*/success.json")):
            continue
        for path in sorted(operation.glob("attempt-*/failure.json")):
            failure = read(path)
            failures.append({"path": path.relative_to(case_root).as_posix(),
                             "sha256": sha(path), "code": failure.get("code", "UNSPECIFIED")})
    return failures


def projection(case):
    """Allowlist due user content only; expected facts never enter this object."""
    question = case["prompt"]
    if p.digest(question.encode()) != case["prompt_sha256"]:
        raise ValueError("VISIBLE_QUESTION_CHANGED")
    return {"case_id": case["case_id"], "question": question,
            "question_sha256": case["prompt_sha256"], "as_of_date": case["relevant_date"],
            "jurisdictions": [JURISDICTIONS[case["jurisdiction"]]]}


def review_scenario_projection(due, *, request_sha256, turn):
    """Exact metadata visible to answer review, excluding author expectations."""
    return {"schema": "legalbot.ge-visible-review-scenario.v1",
        "visibility": "VISIBLE", "case_id": due["case_id"], "turn": turn,
        "question": due["question"], "question_sha256": due["question_sha256"],
        "request_sha256": request_sha256, "as_of_date": due["as_of_date"],
        "jurisdictions": list(due["jurisdictions"]),
        "author_expectations_included": False}


def execute_answer_review(*, folder, host, due, turn, runtime):
    """Run one fresh, fenced answer reviewer and selected-contract release check."""
    from scripts import ge_auto_visible_answer_review as review
    from scripts.ge_auto_visible_release_bridge import build_selected_release_contracts

    material = host.read_answer_review_material()
    scenario = review_scenario_projection(due, request_sha256=host.driver.request_sha, turn=turn)
    values = {"scenario": scenario,
        **{key: material[key] for key in review.ARTIFACTS if key not in {"scenario"}}}
    artifacts = {key: p.canonical(value) for key, value in values.items()}
    expected_hashes = {key: review.sha256(raw) for key, raw in artifacts.items()}
    lineage = {"case_id": due["case_id"], "turn": turn,
        "runtime_sha256": p.digest(runtime),
        "terminal_sha256": p.digest(artifacts["terminal"]),
        "candidate_context_id": material["candidate_receipt"]["context_id"],
        "excluded_reviewer_context_ids": sorted({row["context_id"] for row in host.driver.roles.values()})}

    def verify_inputs(action, binding):
        return (action == "answer_review_inputs" and binding["artifacts"] == artifacts
                and binding["hashes"] == expected_hashes and binding["lineage"] == lineage
                and material["fact_projection"]["fact_snapshot_sha256"]
                    == material["selected_contracts"]["fact_snapshot"]["content_sha256"]
                and {row["selected_evidence_id"] for row in material["evidence"]["sources"]}
                    == {row["evidence_id"] for row in material["selected_contracts"]["evidence_pack"]["selected"]})

    packet = review.prepare_review(artifacts=artifacts, expected_hashes=expected_hashes,
        lineage=lineage, host_verify=verify_inputs)
    review_root = folder / f"answer-review-turn-{turn:04d}"
    host_root = folder / f"answer-review-host-turn-{turn:04d}"
    review_root.mkdir(mode=0o700)
    schema = review.review_schema(packet)
    write_new(review_root / "input.json", packet)
    write_new(review_root / "schema.json", schema)
    write_new(review_root / "prompt.txt", review.REVIEW_PROMPT.encode())
    input_sha = p.digest(packet)
    context_id = "answer-review-" + p.digest({"case": due["case_id"], "turn": turn,
                                               "packet": packet["packet_sha256"]})[:40]
    capability = object()
    expected = {"case_root": str(review_root), "job_root": str(review_root),
        "role": "answer-reviewer", "context_id": context_id,
        "input_sha256": input_sha, "model": runtime["model"],
        "provider": runtime["provider"], "browse": False}
    role_runtime = CodexRoleRuntime(case_root=review_root, protected_root=host_root,
        model=runtime["model"], provider=runtime["provider"],
        expected_cli=runtime["cli_identity"], capability=capability,
        verify=lambda cap, binding: cap is capability and binding == expected)
    role_result = role_runtime(p.RoleJob("answer-reviewer", context_id, review_root,
        input_sha, packet, schema, review.REVIEW_PROMPT))
    output_bytes = (review_root / "output.json").read_bytes()
    receipt_path = host_root / context_id / "COMPLETE.json"
    receipt_bytes = receipt_path.read_bytes()
    identity = {"reviewer_id": context_id, "context_id": context_id,
        "model": runtime["model"], "provider": runtime["provider"],
        "receipt_sha256": review.sha256(receipt_bytes)}

    def verify_receipt(action, binding):
        if action != "answer_review_receipt" or binding["identity"] != identity:
            return False
        receipt = p.decode(receipt_bytes)
        return (binding["packet_sha256"] == packet["packet_sha256"]
            and binding["output_bytes"] == output_bytes
            and binding["receipt_bytes"] == receipt_bytes
            and receipt["role"] == "answer-reviewer" and receipt["context_id"] == context_id
            and receipt["input_sha256"] == input_sha
            and receipt["model_output_sha256"] == review.sha256(output_bytes)
            and receipt["returncode"] == 0 and receipt["error"] is None
            and receipt["fresh_context"] is True and receipt["training"] is False
            and receipt["browse"] is False and receipt["fence"]["input_write_open_denied"] is True
            and role_result["receipt_sha256"] == review.sha256(receipt_bytes))

    finalized = review.finalize_review(packet=packet, output_bytes=output_bytes,
        expected_output_sha256=review.sha256(output_bytes),
        reviewer_receipt_bytes=receipt_bytes, identity=identity,
        host_verify=verify_receipt)
    packet_path = folder / f"ANSWER-REVIEW-PACKET-TURN-{turn}.json"
    result_path = folder / f"ANSWER-REVIEW-RESULT-TURN-{turn}.json"
    write_new(packet_path, p.canonical(packet))
    write_new(result_path, p.canonical(finalized))
    release_sha = None
    if finalized["full_answer_pass"]:
        release_calls = []
        def verify_release(action, binding):
            release_calls.append((action, binding))
            return (len(release_calls) == 1 and action == "visible_selected_release"
                and binding["request_sha256"] == material["selected_contracts"]["query_plan"]["request_sha256"]
                and binding["review_output_sha256"] == finalized["review_output_sha256"])
        chain = build_selected_release_contracts(review_output=p.decode(output_bytes),
            finalized_review=finalized, review_material=material,
            created_at=datetime.now(UTC),
            model_sha256=host.driver.pins.contract.model_sha256,
            prompt_sha256=p.digest(p.PROMPTS["final"].encode()),
            renderer_sha256=review.citation_renderer_sha256(),
            policy_bundle_sha256=p.digest(host.driver.policy.manifest()),
            registry=host.driver.registry, encrypt_store=host.driver.vault,
            host_verify=verify_release)
        chain_path = folder / f"SELECTED-RELEASE-CONTRACTS-TURN-{turn}.json"
        write_new(chain_path, p.canonical(chain))
        release_sha = sha(chain_path)
    return {"turn": turn, "status": "PASS" if finalized["full_answer_pass"] else "HOLD",
        "factual_pass": finalized["factual_pass"], "quality_pass": finalized["quality_pass"],
        "quality_score": finalized["quality_score"],
        "material_claim_count": finalized["material_claim_count"],
        "review_packet_sha256": sha(packet_path), "review_result_sha256": sha(result_path),
        "selected_release_contracts_sha256": release_sha,
        "professional_legal_sign_off": False, "publication_performed": False}


def prepare(output):
    safe(output, VISIBLE)
    if output.exists():
        raise ValueError("VISIBLE_ATTEMPT_EXISTS_NO_OVERWRITE")
    rows = read(CASES)["cases"]
    prepared = [projection(c) for c in rows]
    if len(rows) != 8 or len({r["case_id"] for r in rows}) != 8:
        raise ValueError("EXACT_EIGHT_VISIBLE_CASES_REQUIRED")
    output.mkdir(mode=0o700)
    observed = datetime.now(UTC).isoformat()
    runtime = runtime_manifest(model="gpt-6-astra", provider="openai")
    # Bind this executable as well as the host/runtime, before any candidate role.
    runtime["code_sha256s"][str(Path(__file__).resolve().relative_to(ROOT))] = sha(Path(__file__).resolve())
    review_path = ROOT / "scripts/ge_auto_visible_answer_review.py"
    runtime["code_sha256s"][str(review_path.relative_to(ROOT))] = sha(review_path)
    release_path = ROOT / "scripts/ge_auto_visible_release_bridge.py"
    runtime["code_sha256s"][str(release_path.relative_to(ROOT))] = sha(release_path)
    write_new(output / "RUNTIME.json", p.canonical(runtime))
    owner_sha = sha(OWNER)
    from scripts.ge_auto_visible_answer_review import QUALITY_FLOORS, QUALITY_MAX
    scope = {"kind": "OWNER_AUTHORIZED_VISIBLE_IMPLEMENTATION_VALIDATION", "owner_sha256": owner_sha,
             "cases_sha256": sha(CASES), "legal_cases": 8, "due_turns": 9,
             "quality_maxima": QUALITY_MAX, "critical_floors": QUALITY_FLOORS,
             "quality_threshold": 70, "material_factual_gate_first": True,
             "private_bank_used": False, "training": False, "production": False}
    write_new(output / "SCOPE.json", p.canonical(scope))
    run_id = "ge-visible-" + output.name
    p.checked(run_id, p.ID)
    marker = {"schema": VERSION, "run_id": run_id, "runtime_sha256": p.digest(runtime),
              "baseline_sha256": p.digest([]), "owner_instruction_sha256": owner_sha,
              "scope_sha256": p.digest(scope), "created_at": observed, "training": False,
              "kind": "VISIBLE_START_NOT_UNSEEN_DISCLOSURE", "private_bank_used": False}
    write_new(output / "VISIBLE-START.json", p.canonical(marker))
    # The host alone reads the complete author file. Candidate role fences cannot.
    write_new(output / "CASE-ASSIGNMENTS.json", p.canonical(prepared))
    receipt = {"schema": VERSION, "run_id": run_id, "created_at": observed,
               "runtime_sha256": sha(output / "RUNTIME.json"), "scope_sha256": sha(output / "SCOPE.json"),
               "marker_sha256": sha(output / "VISIBLE-START.json"), "author_file_sha256": sha(CASES),
               "owner_instruction_sha256": owner_sha, "case_assignments_sha256": sha(output / "CASE-ASSIGNMENTS.json"),
               "private_bank_used": False, "training": False, "candidate_runs": 0}
    write_new(output / "PREPARATION.json", p.canonical(receipt))
    return receipt


def run_case(output, case_id):
    safe(output, VISIBLE)
    prepared = read(output / "PREPARATION.json")
    for name, key in (("RUNTIME.json", "runtime_sha256"), ("SCOPE.json", "scope_sha256"),
                      ("VISIBLE-START.json", "marker_sha256"), ("CASE-ASSIGNMENTS.json", "case_assignments_sha256")):
        if sha(output / name) != prepared[key]:
            raise ValueError("VISIBLE_PREPARATION_CHANGED")
    if sha(CASES) != prepared["author_file_sha256"] or sha(OWNER) != prepared["owner_instruction_sha256"]:
        raise ValueError("VISIBLE_SOURCE_OR_AUTHORITY_CHANGED")
    selected = [c for c in read(CASES)["cases"] if c["case_id"] == case_id]
    if len(selected) != 1:
        raise ValueError("EXACT_VISIBLE_CASE_REQUIRED")
    case = selected[0]
    due = projection(case)
    folder = output / "cases" / case_id
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    write_new(folder / "START.json", {"case_id": case_id, "preparation_sha256": sha(output / "PREPARATION.json"),
                                    "started_at": datetime.now(UTC).isoformat(), "due_question_sha256": due["question_sha256"]})
    case_root = folder / "candidate"
    case_root.mkdir(mode=0o700)
    host = None
    turns = []
    selected_contract_hashes = []
    review_material_hashes = []
    answer_reviews = []
    error = None
    try:
        host = CaseHost(run_id=prepared["run_id"], case_id=case_id, case_root=case_root,
            protected_root=folder / "host", mailbox_root=folder / "mailbox",
            owner_instruction_path=OWNER, expected_owner_sha256=prepared["owner_instruction_sha256"],
            owner_scope_sha256=prepared["scope_sha256"], global_marker_path=output / "VISIBLE-START.json",
            global_marker_sha256=prepared["marker_sha256"], runtime_manifest=read(output / "RUNTIME.json"),
            baseline_created_at=datetime.fromisoformat(prepared["created_at"]))
        uploads = []
        if case["uploads"]:
            if case_id != "VIS-RESEARCH-ENG-01" or len(case["uploads"]) != 1:
                raise ValueError("UNEXPECTED_VISIBLE_UPLOAD")
            uploads.append(host.extract_upload(path=VISIBLE / "upload-validation/receipt.pdf",
                upload_id=case["uploads"][0]["fixture_id"], turn=1, media_type="application/pdf"))
        result = host.run_turn(question=due["question"], jurisdictions=due["jurisdictions"],
                               as_of_date=due["as_of_date"], uploads=uploads)
        turns.append(result)
        write_new(folder / "TURN-1-RESULT.json", p.canonical(result))
        scenario_path = folder / "REVIEW-SCENARIO-TURN-1.json"
        write_new(scenario_path, p.canonical(review_scenario_projection(
            due, request_sha256=host.driver.request_sha, turn=1)))
        fact_path = folder / "FACT-PROJECTION-TURN-1.json"
        write_new(fact_path, p.canonical(host.read_fact_projection()))
        if host.driver.read_evidence_pack()["evidence"]:
            path = folder / "SELECTED-RETRIEVAL-CONTRACTS-TURN-1.json"
            write_new(path, p.canonical(host.read_selected_retrieval_contracts()))
            selected_contract_hashes.append(sha(path))
            path = folder / "ANSWER-REVIEW-MATERIAL-TURN-1.json"
            write_new(path, p.canonical(host.read_answer_review_material()))
            review_material_hashes.append(sha(path))
            answer_reviews.append(execute_answer_review(folder=folder, host=host,
                due=due, turn=1, runtime=read(output / "RUNTIME.json")))
        # Access the follow-up only after the first result has actually terminated.
        follow = case["follow_up"]
        if follow is not None:
            if p.digest(follow["prompt"].encode()) != follow["prompt_sha256"]:
                raise ValueError("DUE_FOLLOWUP_CHANGED")
            if not host.driver.terminal_bytes:
                raise ValueError("PRIOR_TERMINAL_REQUIRED_BEFORE_FOLLOWUP")
            result = host.run_turn(question=follow["prompt"], jurisdictions=due["jurisdictions"],
                                   as_of_date=due["as_of_date"])
            turns.append(result)
            write_new(folder / "TURN-2-RESULT.json", p.canonical(result))
            follow_due = {**due, "question": follow["prompt"],
                          "question_sha256": follow["prompt_sha256"]}
            scenario_path = folder / "REVIEW-SCENARIO-TURN-2.json"
            write_new(scenario_path, p.canonical(review_scenario_projection(
                follow_due, request_sha256=host.driver.request_sha, turn=2)))
            fact_path = folder / "FACT-PROJECTION-TURN-2.json"
            write_new(fact_path, p.canonical(host.read_fact_projection()))
            if host.driver.read_evidence_pack()["evidence"]:
                path = folder / "SELECTED-RETRIEVAL-CONTRACTS-TURN-2.json"
                write_new(path, p.canonical(host.read_selected_retrieval_contracts()))
                selected_contract_hashes.append(sha(path))
                path = folder / "ANSWER-REVIEW-MATERIAL-TURN-2.json"
                write_new(path, p.canonical(host.read_answer_review_material()))
                review_material_hashes.append(sha(path))
                answer_reviews.append(execute_answer_review(folder=folder, host=host,
                    due=follow_due, turn=2, runtime=read(output / "RUNTIME.json")))
    except Exception as exc:
        # Preserve all failed work. This runner has no repair/retry switch.
        error = type(exc).__name__ + ":" + str(exc)[:240]
    summary = completion_summary(turns, error, unresolved_operations=unresolved_operation_failures(case_root))
    case_pass = (error is None and len(turns) == (2 if case_id.endswith("TX-01") else 1)
                 and len(answer_reviews) == len(turns)
                 and all(row["status"] == "PASS" for row in answer_reviews))
    if case_pass:
        summary.update(status="EXECUTED_REVIEWED_RELEASE_CHECKS_PASS", supported_answer_proven=True)
    receipt = {"schema": VERSION, "case_id": case_id, "completed_at": datetime.now(UTC).isoformat(),
               **summary,
               "error": error, "turns_completed": len(turns), "expected_turns": 2 if case_id.endswith("TX-01") else 1,
               "material_claim_review": ("PASS" if case_pass else "HOLD" if answer_reviews else "NOT_STARTED"),
               "answer_reviews": answer_reviews, "case_pass": case_pass, "private_bank_used": False,
               "selected_retrieval_contract_sha256s": selected_contract_hashes,
               "answer_review_material_sha256s": review_material_hashes,
               "training": False, "automatic_retry": False,
               "start_sha256": sha(folder / "START.json"), "preparation_sha256": sha(output / "PREPARATION.json")}
    write_new(folder / "COMPLETE.json", p.canonical(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--case")
    args = parser.parse_args()
    result = prepare(args.output.absolute()) if args.prepare else run_case(args.output.absolute(), args.case)
    print(json.dumps(result, sort_keys=True), flush=True)
    if result.get("status") == "EXECUTION_HOLD":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
