"""One bounded visible source-mapper/reviewer diagnostic, separate from case scores.

Uses explicit already-captured sources and public queries. No answer generation,
search, indexing, active pointer, retry, private-bank access or browser gate claim.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from backend.app.contracts.schema_registry import canonical_json_bytes

from scripts import ge_auto_case_protocol as p
from scripts.ge_auto_role_runtime import CodexRoleRuntime, cli_identity, safe, write_new
from scripts.ge_auto_visible_case_execution import VISIBLE


def read(path):
    safe(path, VISIBLE)
    return p.CaseStore(path.parent).read(path.name)


def run(*, query_input, source_dirs, output, model):
    safe(output, VISIBLE)
    p.require(output.is_relative_to(VISIBLE) and not output.exists(), "FRESH_VISIBLE_DIAGNOSTIC_REQUIRED")
    p.require(not any(part.startswith("case-execution-") for part in output.relative_to(VISIBLE).parts),
              "DIAGNOSTIC_MUST_NOT_WRITE_CASE_ARTIFACTS")
    query_raw = read(query_input)
    queries = p.decode(query_raw)["payload"]["queries"]
    for query in queries:
        p.checked(query, p.QUERY)
    sources, files, lineage = [], {}, []
    p.require(1 <= len(source_dirs) <= 8, "BOUNDED_SOURCE_SET_REQUIRED")
    for n, folder in enumerate(source_dirs, 1):
        raw = read(folder / "raw.bytes")
        transport = p.decode(read(folder / "transport.json"))
        parsed = p.decode(read(folder / "parsed.json"))
        parts = p.decode(read(folder / "parts.json"))
        p.require(p.digest(raw) == transport["raw_sha256"] == parsed["raw_sha256"], "SOURCE_BYTES_CHANGED")
        p.require(parsed["parsed_sha256"] == p.digest(canonical_json_bytes(parsed["parsed"])), "PARSED_SOURCE_CHANGED")
        from scripts.ge_auto_host_bridge import structural_parts
        p.require(parts == structural_parts(parsed), "SOURCE_PARTS_CHANGED")
        filename = f"source-{n:02d}.bytes"
        files[filename] = raw
        sources.append({"source_sha256": p.digest(raw), "raw_file": filename, "parts": parts,
            **{k: transport[k] for k in ("canonical_url", "final_url", "redirect_chain", "fetched_at")},
            "parser_sha256": parsed["parser_sha256"], "parser_receipt_sha256": p.digest(read(folder / "parsed.json"))})
        lineage.append({"source_sha256": p.digest(raw), "transport_sha256": p.digest(read(folder / "transport.json")),
                        "parse_manifest_sha256": p.digest(read(folder / "parsed.json"))})
    output.mkdir(parents=True, mode=0o700)
    payload = {"sources": sources, "queries": queries}
    identity = cli_identity()
    write_new(output / "START.json", {"kind": "VISIBLE_SOURCE_COMPONENT_DIAGNOSTIC",
        "query_input_sha256": p.digest(query_raw), "source_lineage": lineage, "model": model,
        "script_sha256": p.digest(Path(__file__).read_bytes()), "cli_identity": identity,
        "private_bank_used": False, "formal_case_execution": False, "automatic_retry": False})
    mapping = None
    for role in ("mapper", "reviewer"):
        work = output / "roles" / role
        work.mkdir(parents=True, mode=0o700)
        data = {"schema": p.VERSION, "case_id": "VISIBLE-SOURCE-COMPONENT", "role": role,
                "payload": payload if role == "mapper" else {**payload, "mapping": mapping},
                "retry_profile_sha256": None}
        context = "ctx-" + p.digest({"root": str(output), "role": role, "input": p.digest(data)})
        for name, value in (("input.json", data), ("schema.json", p.SCHEMAS[role]),
                            ("prompt.txt", p.PROMPTS[role].encode())):
            write_new(work / name, value)
        for name, raw in files.items():
            write_new(work / name, raw)
        if role == "mapper":
            write_new(work / "transport-schema.json", p.MAPPER_REFERENCE_SCHEMA)
            write_new(work / "source-inventory.json", [{"source_sha256": s["source_sha256"],
                "raw_file": s["raw_file"], "canonical_url": s["canonical_url"],
                "part_count": len(s["parts"]), "text_characters": sum(len(x["text"]) for x in s["parts"])} for s in sources])
        job = p.RoleJob(role, context, work, p.digest(data), data, p.SCHEMAS[role], p.PROMPTS[role])
        capability = object()
        expected = {"case_root": str(output / "roles"), "job_root": str(work), "role": role,
            "context_id": context, "input_sha256": p.digest(data), "model": model, "provider": "openai", "browse": False}
        def verify(cap, binding, capability=capability, expected=expected, work=work):
            return (cap is capability and binding == expected
                    and p.digest(p.decode(read(work / "input.json"))) == expected["input_sha256"])
        host_root = output.parent / (output.name + "-host")
        if role == "mapper" and host_root.exists():
            raise FileExistsError("FRESH_DISJOINT_COMPONENT_HOST_REQUIRED")
        runtime = CodexRoleRuntime(case_root=output / "roles", protected_root=host_root,
            model=model, provider="openai", expected_cli=identity, capability=capability, verify=verify)
        print(f"{role}: STARTED", flush=True)
        try:
            result = runtime(job)
            value = result["output"]
            validator = object.__new__(p.CaseProtocol)
            source_map = {s["source_sha256"]: s for s in sources}
            if role == "mapper":
                validator._mapping(value, source_map, queries)
                mapping = value
            else:
                validator._review(value, source_map, mapping)
            write_new(output / (role.upper() + "-RESULT.json"), result)
            print(f"{role}: COMPLETED_VALIDATED_COMPONENT_ONLY", flush=True)
        except Exception as exc:
            write_new(output / "COMPLETE.json", {"status": "COMPONENT_HOLD", "stage": role,
                "error": type(exc).__name__ + ":" + str(exc)[:150], "automatic_retry": False,
                "formal_case_execution": False, "browser_gate_pass": False})
            raise
    write_new(output / "COMPLETE.json", {"status": "COMPONENT_REVIEW_COMPLETE",
        "propositions": [{"proposition_id": x["proposition_id"], "decision": x["decision"], "holds": x["holds"]}
                         for x in value["propositions"]], "formal_case_execution": False,
        "browser_gate_pass": False, "private_bank_used": False, "training": False,
        "production_admission": False, "automatic_retry": False})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query-input", type=Path, required=True)
    parser.add_argument("--source-dir", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", required=True)
    args = parser.parse_args()
    run(query_input=args.query_input.absolute(), source_dirs=[x.absolute() for x in args.source_dir],
        output=args.output.absolute(), model=args.model)


if __name__ == "__main__":
    main()
