"""Read-only visible-case triage before spending another model attempt.

Writes a separate create-only diagnostic. Never changes a case, launches a role,
accepts legal evidence, searches a bank, or turns a replay into an execution pass.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts import ge_auto_case_protocol as p
from scripts.ge_auto_role_runtime import safe, write_new
from scripts.ge_auto_visible_case_execution import VISIBLE


def read_bytes(path):
    safe(path, VISIBLE)
    return p.CaseStore(path.parent).read(path.name)


def assess_mapper(value, payload, *, references=False):
    if references:
        normalized, conversion = p.materialize_mapper_spans(value, payload)
    else:
        normalized, conversion = p.canonicalize_mapper_spans(value, payload)
    validator = object.__new__(p.CaseProtocol)
    validator._mapping(normalized, {s["source_sha256"]: s for s in payload["sources"]}, payload["queries"])
    refs = p.decode(p.canonical(normalized))
    for prop in refs["propositions"]:
        for span in p.CaseProtocol._spans(prop):
            span.pop("text")
    materialized, receipt = p.materialize_mapper_spans(refs, payload)
    p.require(materialized == normalized, "REFERENCE_TRANSPORT_REPLAY_CHANGED")
    unresolved = [x["proposition_id"] for x in normalized["propositions"]
                  if x["currentness"]["status"] != "VERIFIED"]
    return {"mechanical_mapping": "PASS", "conversion": conversion,
        "reference_transport": receipt, "canonical_mapping_bytes": len(p.canonical(normalized)),
        "reference_output_bytes": len(p.canonical(refs)), "unresolved_proposition_ids": unresolved,
        "mapper_holds": normalized["holds"], "all_propositions_currentness_unresolved":
            bool(normalized["propositions"]) and len(unresolved) == len(normalized["propositions"]),
        "source_review": "NOT_PERFORMED_BY_DIAGNOSTIC",
        "next_action": "RESOLVE_SOURCE_CURRENTNESS_BEFORE_ANOTHER_FULL_RUN" if unresolved
            else "CHECK_INDEPENDENT_SOURCE_REVIEW_BEFORE_ANOTHER_FULL_RUN"}


def inspect_case(case_root):
    case_root = case_root.absolute()
    safe(case_root, VISIBLE)
    p.require(case_root.is_relative_to(VISIBLE), "VISIBLE_CASE_REQUIRED")
    complete_path = case_root / "COMPLETE.json"
    p.require(complete_path.is_file(), "TERMINAL_CASE_REQUIRED_NO_ACTIVE_REPLAY")
    complete_raw = read_bytes(complete_path)
    complete = p.decode(complete_raw)
    p.require(complete.get("private_bank_used") is False, "VISIBLE_CASE_REQUIRED")
    records = []
    for job in sorted((case_root / "candidate").glob("turn-*/jobs/mapper-a*")):
        input_raw = read_bytes(job / "input.json")
        data = p.decode(input_raw)
        references = (job / "span-references.json").is_file()
        raw_path = job / ("span-references.json" if references else "output.json")
        if not raw_path.is_file():
            records.append({"job": job.relative_to(case_root).as_posix(), "mechanical_mapping": "NO_MODEL_OUTPUT"})
            continue
        raw = read_bytes(raw_path)
        matching = []
        for path in (case_root / "host").glob("ctx-*/COMPLETE.json"):
            host = p.decode(read_bytes(path))
            if host.get("job_root") == str(job):
                matching.append((path, host))
        p.require(len(matching) == 1, "EXACT_MAPPER_HOST_RECEIPT_REQUIRED")
        host_path, host = matching[0]
        p.require(host["input_sha256"] == p.digest(data)
                  and host.get("model_output_sha256") == p.digest(raw), "MAPPER_DIAGNOSTIC_BINDING_CHANGED")
        for source in data["payload"]["sources"]:
            raw_file = source["raw_file"]
            p.require(len(p.parts(raw_file)) == 1, "SOURCE_FILE_SCOPE")
            source_path = job / raw_file
            safe(source_path, VISIBLE)
            p.require(p.digest(read_bytes(source_path)) == source["source_sha256"], "SOURCE_BYTES_CHANGED")
        row = {"job": job.relative_to(case_root).as_posix(), "input_sha256": p.digest(input_raw),
            "model_output_sha256": p.digest(raw), "host_receipt_sha256": p.digest(read_bytes(host_path)),
            "original_host_error": host.get("error"), "source_count": len(data["payload"]["sources"]),
            "source_text_characters": sum(len(part["text"]) for s in data["payload"]["sources"] for part in s["parts"])}
        try:
            row.update(assess_mapper(p.decode(raw), data["payload"], references=references))
        except p.ProtocolError as exc:
            row.update(mechanical_mapping="HOLD", failure_code=str(exc),
                       next_action="FIX_EXACT_MECHANICAL_FAILURE_WITHOUT_MODEL_RETRY")
        records.append(row)
    broker_failures = []
    for path in sorted((case_root / "candidate/broker").glob("*/failure.json")):
        broker_failures.append({"path": path.relative_to(case_root).as_posix(),
                                "sha256": p.digest(read_bytes(path)), "failure": p.decode(read_bytes(path))})
    return {"schema": "legalbot.ge-visible-offline-diagnostic.v1", "case_id": complete["case_id"],
        "case_root": case_root.relative_to(VISIBLE).as_posix(), "completion_sha256": p.digest(complete_raw),
        "kind": "OFFLINE_COMPONENT_REPLAY_NOT_END_TO_END_EXECUTION", "mapper": records,
        "broker_failures": broker_failures, "new_model_calls": 0, "case_artifacts_modified": False,
        "legal_eligibility_assessed": False, "browser_gate_pass": False, "automatic_retry": False,
        "diagnostic_code_sha256": p.digest(Path(__file__).read_bytes()),
        "protocol_code_sha256": p.digest(Path(p.__file__).read_bytes())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    safe(output, VISIBLE)
    p.require(output.is_relative_to(VISIBLE), "VISIBLE_DIAGNOSTIC_OUTPUT_REQUIRED")
    p.require(not output.is_relative_to(args.case_root.absolute())
              and not any(part.startswith("case-execution-") for part in output.relative_to(VISIBLE).parts),
              "DIAGNOSTIC_MUST_NOT_WRITE_CASE_ARTIFACTS")
    result = inspect_case(args.case_root)
    write_new(output, p.canonical(result))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
