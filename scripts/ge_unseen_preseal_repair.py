"""One bounded, evidence-bound construction repair per unchanged scenario.

Original proposals and reviews remain in place. Successors are private overlays;
no candidate has run, and only a new independent review can accept an overlay.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil

STAGES = {"oracle-repair": "oracles", "bank-review-repair": "reviews"}
REPAIR_PROMPT = """You are the assigned private CONSTRUCTION REPAIR RESEARCHER.
The original scenario and both ordered turns are immutable. Read input.json and
the supplied raw sources in your own directory only. This is a single targeted
repair of precise research/reviewer defects, not candidate scoring or training.
Preserve difficulty and all known facts. Repair controlling authority, exact
locators/quotes, dates/extent/currentness, missing conditions, contradictory
guidance and reasonable conditional branches. Do not hide or relabel a hold.
The previous oracle is untrusted, not authority. Use its captured official bytes
where appropriate; no repeated fetch of an unchanged existing source. Browse
official UK/US primary sources only for the named gaps, at most four focused
queries and eight new source URLs for this case. Stop with a precise construction
gap if unsupported, inaccessible or budget-exhausted. Never invent an exact quote
or say currentness is verified because the host is official. Do not use future
user facts to excuse a first-turn overclaim. Return the full revised oracle with
every required material point and each exact source; include unresolved limits.
Return every assigned ID once. No question changes, candidate answer, weight
training, professional identity or sign-off. JSON only.
"""


def _preseal(r):
    from scripts.ge_unseen_research_gate import require_plan_execution
    require_plan_execution(r)
    if any((r.PUBLIC / name).exists() for name in (
            "BANK-SEAL.json", "RUN-FREEZE.json", "ONE-PASS-START.json")):
        raise RuntimeError("construction repair requires an unsealed, unexecuted bank")


def _complete(r, work):
    return ((work / "COMPLETION.json").exists()
            and r.completion_recheckable(work.parent.name, r.read(work / "COMPLETION.json")))


def _valid_repair(r, work):
    """Malformed model proposals stay held without stalling unrelated cases.

The outcome inspector independently records failed job validation. No invalid
successor can replace the original held row or supply a fresh approval.
"""
    if not _complete(r, work):
        return None
    try:
        return r.validate_job(work)
    except Exception:
        return None


def _copy_sources(r, oracle, dest):
    evidence = []
    urls = sorted({s["url"] for s in oracle["sources"]}
                  | {u for s in oracle["sources"] for u in s["currentness_check_urls"]})
    for url in urls:
        key = hashlib.sha256(url.encode()).hexdigest()
        path = r.PRIVATE / "sources" / (key + ".json")
        if not path.exists():
            r.capture(url, r.PRIVATE / "sources")
        captured = r.read_source_capture(r.PRIVATE / "sources", key)
        raw = r.PRIVATE / "sources" / (key + ".bytes")
        relative = "sources/" + key + ".bytes"
        target = dest / relative
        if raw.exists() and not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(raw, target)
        evidence.append({**captured, "raw_relative_path": relative})
    return evidence


def original_records(r, shard):
    author = r.PRIVATE / "author" / shard
    oracle = r.PRIVATE / "oracle" / shard
    review = r.PRIVATE / "bank-review" / shard
    if not all(_complete(r, work) for work in (author, oracle, review)):
        return None
    r.validate_job(author)
    o = {x["case_id"]: x for x in r.validate_job(oracle)["oracles"]}
    v = {x["case_id"]: x for x in r.validate_job(review)["reviews"]}
    cases = r.read(oracle / "input.json")["cases"]
    return cases, o, v


def prepare_repairs(r):
    _preseal(r)
    count = 0
    for review in sorted((r.PRIVATE / "bank-review").glob("shard-*")):
        records = original_records(r, review.name)
        if records is None:
            continue
        cases, oracles, reviews = records
        for number, case in enumerate(cases, 1):
            oracle, checked = oracles[case["case_id"]], reviews[case["case_id"]]
            # A fixture-only issue receives formatting repair, not generic law
            # research. Legal gaps and explicit unsupported expectations do.
            legal_defect = (not oracle["source_sufficient"]
                or oracle["currentness_status"] != "VERIFIED" or bool(oracle["construction_gaps"])
                or any(checked[k] is not True for k in (
                    "scenario_fair", "oracle_complete", "source_support_verified", "currentness_verified"))
                or any(c["supported"] is not True for c in checked["required_point_checks"]))
            if not legal_defect:
                continue
            dest = r.PRIVATE / "oracle-repair" / f"{review.name}-case-{number:02d}"
            if dest.exists():
                continue
            evidence = _copy_sources(r, oracle, dest)
            r.write(dest / "input.json", {
                "as_of": r.TODAY, "cases": [case], "original_oracle": oracle,
                "construction_review": checked, "evidence": evidence,
                "parent_shard": review.name, "case_number": number,
                "author_output_sha256": r.sha(r.PRIVATE / "author" / review.name / "output.json"),
                "oracle_output_sha256": r.sha(r.PRIVATE / "oracle" / review.name / "output.json"),
                "review_output_sha256": r.sha(review / "output.json"),
                "repair_attempt": 1, "change": "TARGETED_CASE_AND_VERIFIED_CAPTURE_CONTEXT",
                "no_second_repair": True, "question_sha256": r.digest(case["question"]),
                "query_budget": 4, "new_source_capture_budget": 8})
            r.write(dest / "schema.json", r.ORACLE_SCHEMA)
            count += 1
    return {"targeted_oracle_repairs_prepared": count}


def validate_lineage(r, work):
    payload = r.read(work / "input.json")
    parent = payload["parent_shard"]
    # Resolve parent name against exact assigned canonical author names before IO.
    if parent not in {f"shard-{i:02d}" for i in range(1, 37)}:
        raise RuntimeError("unassigned construction repair parent")
    records = original_records(r, parent)
    if records is None:
        raise RuntimeError("construction repair requires completed original roles")
    cases, oracles, reviews = records
    number = payload["case_number"]
    if type(number) is not int or not 1 <= number <= len(cases):
        raise RuntimeError("unassigned repair case number")
    case = cases[number - 1]
    if (work.name != f"{parent}-case-{number:02d}"
            or payload["author_output_sha256"] != r.sha(r.PRIVATE / "author" / parent / "output.json")
            or payload["oracle_output_sha256"] != r.sha(r.PRIVATE / "oracle" / parent / "output.json")
            or payload["review_output_sha256"] != r.sha(r.PRIVATE / "bank-review" / parent / "output.json")):
        raise RuntimeError("construction repair original lineage changed")
    if work.parent.name == "oracle-repair":
        if (payload["cases"] != [case] or payload["original_oracle"] != oracles[case["case_id"]]
                or payload["construction_review"] != reviews[case["case_id"]]
                or payload["repair_attempt"] != 1 or payload["no_second_repair"] is not True
                or payload["question_sha256"] != r.digest(case["question"])):
            raise RuntimeError("construction research repair changed facts or original findings")
        proposed = r.read(work / "output.json")["oracles"][0]
        original_urls = {row["url"] for row in payload["evidence"]}
        proposed_urls = ({s["url"] for s in proposed["sources"]}
                         | {u for s in proposed["sources"] for u in s["currentness_check_urls"]})
        if (payload.get("new_source_capture_budget") != 8 or payload.get("query_budget") != 4
                or len(proposed_urls - original_urls) > 8):
            raise RuntimeError("targeted repair source budget exceeded")
    elif work.parent.name == "bank-review-repair":
        row = payload["cases"][0]
        if len(payload["cases"]) != 1 or row["case"] != case:
            raise RuntimeError("construction rereview changed scenario")
        research = r.PRIVATE / "oracle-repair" / work.name
        if payload.get("repaired_oracle_output_sha256") is not None:
            if (not _complete(r, research)
                    or payload["repaired_oracle_output_sha256"] != r.sha(research / "output.json")
                    or row["oracle"] != r.validate_job(research)["oracles"][0]):
                raise RuntimeError("fresh reviewer oracle binding changed")
        elif row["oracle"] != oracles[case["case_id"]]:
            raise RuntimeError("fresh reviewer changed the original oracle")
        fixture = fixture_directory(r, parent, number)
        if payload["fixture_manifest_sha256"] != r.sha(fixture / "UPLOAD-MANIFEST.json"):
            raise RuntimeError("fresh reviewer fixture binding changed")


def fixture_directory(r, shard, number):
    # A formatter's proposed output is never used without actual rendered bytes.
    repaired = r.PRIVATE / "fixture-repaired" / f"{shard}-case-{number:02d}"
    if (repaired / "UPLOAD-MANIFEST.json").exists():
        from scripts.ge_unseen_fixture_repair import validate_rendered_successor
        validate_rendered_successor(r, repaired)
        return repaired
    return r.PRIVATE / "fixtures" / shard / f"case-{number:02d}"


def _fixture_original(r, name):
    match = re.fullmatch(r"(shard-\d{2})-case-(\d{2})", name)
    if not match or match[1] not in {f"shard-{i:02d}" for i in range(1, 37)}:
        raise RuntimeError("unassigned fixture inventory")
    records = original_records(r, match[1])
    number = int(match[2])
    if records is None or not 1 <= number <= len(records[0]):
        raise RuntimeError("fixture inventory original roles incomplete")
    return records[0][number - 1], r.PRIVATE / "fixtures" / match[1] / f"case-{number:02d}"


def _inventory_input(r, name, *, schema_repair=False):
    from scripts.ge_unseen_fixture_repair import prepare_requirement_input
    case, fixture = _fixture_original(r, name)
    r.safe_path(fixture / "UPLOAD-MANIFEST.json")
    return prepare_requirement_input(json.dumps(case, ensure_ascii=False).encode(),
        (fixture / "UPLOAD-MANIFEST.json").read_bytes(),
        inventory_context_id="inventory-" + name + ("-schema-r2" if schema_repair else ""),
        formatter_context_id="formatter-" + name,
        review_issues=["MISSING_STRUCTURE"])


def validate_fixture_inventory(r, work):
    repaired = work.parent == r.PRIVATE / "fixture-inventory-repair"
    if repaired:
        validate_fixture_schema_repair(r, work)
    if (work.parent not in (r.PRIVATE / "fixture-inventory", r.PRIVATE / "fixture-inventory-repair")
            or r.read(work / "input.json") != _inventory_input(r, work.name, schema_repair=repaired)):
        raise RuntimeError("fixture inventory changed original fact or manifest binding")
    output = r.read(work / "output.json")
    payload = r.read(work / "input.json")
    if (output["case_id"] != payload["case"]["case_id"]
            or output["original_binding_sha256"] != payload["original_binding_sha256"]):
        raise RuntimeError("fixture inventory output binding mismatch")
    return output


def _schema_failure(r, original):
    """Only the observed pre-model transport failure qualifies for this retry."""
    names = ("input.json", "schema.json", "INVOCATION.json", "COMPLETION.json", "stderr.log")
    if not all((original / name).exists() for name in names) or (original / "output.json").exists():
        return None
    completion = r.read(original / "COMPLETION.json")
    r.safe_path(original / "stderr.log")
    with (original / "stderr.log").open("rb") as stream:
        log = stream.read().decode("utf-8", errors="replace")
    if (completion.get("returncode") != 1 or completion.get("validated_rows") != 0
            or '"code": "invalid_json_schema"' not in log
            or "schema must have a 'type' key" not in log
            or "('properties', 'schema')" not in log):
        return None
    return {name: r.sha(original / name) for name in names}


def validate_fixture_schema_repair(r, work):
    if work.parent != r.PRIVATE / "fixture-inventory-repair":
        raise RuntimeError("wrong fixture schema repair root")
    original = r.PRIVATE / "fixture-inventory" / work.name
    hashes = _schema_failure(r, original)
    receipt = r.read(work / "SCHEMA-REPAIR-LINEAGE.json")
    if (hashes is None or receipt != r.seal(receipt)
            or receipt.get("original_hashes") != hashes or receipt.get("attempt") != 2
            or receipt.get("change") != "ADD_EXPLICIT_RESPONSE_SCHEMA_TYPES"
            or receipt.get("no_third_attempt") is not True
            or receipt.get("input_sha256") != r.sha(work / "input.json")
            or receipt.get("schema_sha256") != r.sha(work / "schema.json")):
        raise RuntimeError("fixture schema retry lineage changed")
    if r.read(original / "input.json") != _inventory_input(r, work.name):
        raise RuntimeError("original inventory scenario changed")


def prepare_fixture_schema_repairs(r):
    _preseal(r)
    from scripts.ge_unseen_fixture_repair import REQUIREMENT_SCHEMA
    prepared = 0
    for original in sorted((r.PRIVATE / "fixture-inventory").glob("shard-*")):
        hashes = _schema_failure(r, original)
        if hashes is None:
            continue
        work = r.PRIVATE / "fixture-inventory-repair" / original.name
        if work.exists():
            validate_fixture_schema_repair(r, work)
            continue
        old_schema = r.read(original / "schema.json")
        if old_schema == REQUIREMENT_SCHEMA:
            raise RuntimeError("unchanged fixture schema retry refused")
        # Removing only the newly explicit types must recover the exact failed
        # schema; this transport correction cannot alter facts or requirements.
        def same_meaning(old, new):
            if isinstance(old, dict) and isinstance(new, dict):
                extra = set(new) - set(old)
                if "type" in extra:
                    values = [old["const"]] if "const" in old else old.get("enum", [])
                    types = {type(v) for v in values}
                    expected = {str: "string", bool: "boolean", int: "integer", type(None): "null"}
                    if len(types) != 1 or new["type"] != expected.get(next(iter(types))):
                        return False
                return (extra <= {"type"} and set(old) <= set(new)
                        and all(same_meaning(v, new[k]) for k, v in old.items()))
            if isinstance(old, list) and isinstance(new, list):
                return len(old) == len(new) and all(same_meaning(a, b) for a, b in zip(old, new, strict=True))
            return type(old) is type(new) and old == new
        if not same_meaning(old_schema, REQUIREMENT_SCHEMA):
            raise RuntimeError("fixture repair exceeds transport type correction")
        r.write(work / "input.json", _inventory_input(r, original.name, schema_repair=True))
        r.write(work / "schema.json", REQUIREMENT_SCHEMA)
        r.write(work / "SCHEMA-REPAIR-LINEAGE.json", r.seal({
            "attempt": 2, "change": "ADD_EXPLICIT_RESPONSE_SCHEMA_TYPES", "no_third_attempt": True,
            "original_hashes": hashes, "input_sha256": r.sha(work / "input.json"),
            "schema_sha256": r.sha(work / "schema.json")}))
        prepared += 1
    return {"fixture_schema_repairs_prepared": prepared}


def prepare_fixture_repairs(r):
    _preseal(r)
    from scripts.ge_unseen_fixture_repair import (
        REQUIREMENT_SCHEMA,
        prepare_formatter_job,
        validate_requirement_output,
    )
    prepare_fixture_schema_repairs(r)
    inventories, formatters = 0, 0
    for parent in sorted((r.PRIVATE / "bank-review").glob("shard-*")):
        records = original_records(r, parent.name)
        if records is None:
            continue
        cases, _, reviews = records
        for number, case in enumerate(cases, 1):
            if not case["uploads"] or reviews[case["case_id"]]["fixtures_valid"] is True:
                continue
            name = f"{parent.name}-case-{number:02d}"
            inventory = r.PRIVATE / "fixture-inventory" / name
            successor = r.PRIVATE / "fixture-inventory-repair" / name
            formatter = r.PRIVATE / "fixture-format" / name
            held = r.PRIVATE / "receipts/fixture-inventory" / (name + "-prepare-hold.json")
            if not inventory.exists():
                r.write(inventory / "input.json", _inventory_input(r, name))
                r.write(inventory / "schema.json", REQUIREMENT_SCHEMA)
                inventories += 1
            if successor.exists():
                validate_fixture_schema_repair(r, successor)
                inventory = successor
            if formatter.exists() or held.exists() or not _complete(r, inventory):
                continue
            try:
                r.validate_job(inventory)
                raw_output = (inventory / "output.json").read_bytes()
                payload = r.read(inventory / "input.json")
                checked = validate_requirement_output(payload, raw_output)
                if checked["state"] != "INVENTORY_DRAFT_BOUND":
                    continue  # Explicit formatting hold is a completed outcome.
                original = r.PRIVATE / "fixtures" / parent.name / f"case-{number:02d}"
                prepare_formatter_job(r, formatter, case, original,
                    formatter_context_id="formatter-" + name,
                    inventory_input=payload, inventory_output_json=raw_output,
                    review_issues=["MISSING_STRUCTURE"])
                formatters += 1
            except Exception as exc:
                if not held.exists():
                    r.write(held, r.seal({"error_type": type(exc).__name__,
                        "error_fingerprint": r.digest(str(exc)),
                        "inventory_output_sha256": r.sha(inventory / "output.json"),
                        "automatic_retry": False}))
    return {"fixture_inventories_prepared": inventories, "fixture_formatters_prepared": formatters}


def prepare_rereviews(r):
    _preseal(r)
    count = 0
    for parent in sorted((r.PRIVATE / "bank-review").glob("shard-*")):
        records = original_records(r, parent.name)
        if records is None:
            continue
        cases, oracles, reviews = records
        for number, case in enumerate(cases, 1):
            name = f"{parent.name}-case-{number:02d}"
            dest = r.PRIVATE / "bank-review-repair" / name
            if dest.exists():
                continue
            research = r.PRIVATE / "oracle-repair" / name
            fixture = fixture_directory(r, parent.name, number)
            if research.exists() and not _complete(r, research):
                continue
            revised = _valid_repair(r, research)
            if research.exists() and revised is None:
                continue
            changed_fixture = fixture.parent.name == "fixture-repaired"
            if case["uploads"] and reviews[case["case_id"]]["fixtures_valid"] is not True and not changed_fixture:
                # Do not spend the only fresh rereview on a known broken upload.
                continue
            if not _complete(r, research) and not changed_fixture:
                continue
            oracle = revised["oracles"][0] if revised else oracles[case["case_id"]]
            evidence = _copy_sources(r, oracle, dest)
            shutil.copytree(fixture, dest / "fixtures" / "case-01")
            row = {"case": case, "oracle": oracle, "evidence": evidence,
                   "fixture_manifest": r.read(fixture / "UPLOAD-MANIFEST.json"),
                   "fixture_directory": "fixtures/case-01"}
            r.write(dest / "input.json", {
                "as_of": r.TODAY, "cases": [row], "parent_shard": parent.name, "case_number": number,
                "author_output_sha256": r.sha(r.PRIVATE / "author" / parent.name / "output.json"),
                "oracle_output_sha256": r.sha(r.PRIVATE / "oracle" / parent.name / "output.json"),
                "review_output_sha256": r.sha(parent / "output.json"),
                "repaired_oracle_output_sha256": r.sha(research / "output.json") if _complete(r, research) else None,
                "fixture_manifest_sha256": r.sha(fixture / "UPLOAD-MANIFEST.json"),
                "fresh_reviewer_no_prior_recommendations": True})
            r.write(dest / "schema.json", r.BANK_REVIEW_SCHEMA)
            count += 1
    return {"fresh_construction_rereviews_prepared": count}


def effective_rows(r, stage, rows):
    """Return only bound current proposals/reviews; never manufacture an approval."""
    if stage not in ("oracle", "bank-review"):
        return rows
    by_id = {row["case_id"]: row for row in rows}
    repaired = set()
    for work in sorted((r.PRIVATE / "oracle-repair").glob("shard-*")):
        validated = _valid_repair(r, work)
        if validated:
            row = validated["oracles"][0]
            repaired.add(row["case_id"])
            if stage == "oracle":
                by_id[row["case_id"]] = row
    if stage == "bank-review":
        for work in sorted((r.PRIVATE / "fixture-repaired").glob("shard-*")):
            if (work / "UPLOAD-MANIFEST.json").exists():
                from scripts.ge_unseen_fixture_repair import validate_rendered_successor
                validate_rendered_successor(r, work)
                repaired.add(r.read(work / "UPLOAD-MANIFEST.json")["case_id"])
        for cid in repaired:
            by_id.pop(cid, None)
        for work in sorted((r.PRIVATE / "bank-review-repair").glob("shard-*")):
            validated = _valid_repair(r, work)
            if validated:
                row = validated["reviews"][0]
                by_id[row["case_id"]] = row
    return list(by_id.values())
