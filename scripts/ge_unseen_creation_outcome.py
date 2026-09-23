"""Read-only construction inspection and create-only, redacted outcome publication.

Call ``inspect_outcome(r)`` after the supervisor's preparation/assembly pass. Call
``publish_outcome(r)`` only while the coordinator owns scheduling and all its
futures have drained. Files cannot prove a process is dead: an INVOCATION without
COMPLETION remains active, including interrupted mechanical assemblies. The
caller must handle pipeline exceptions and must serialize publication with all
writers; the two inventory observations detect changes, not replace that lock.

Only the injected runner's read-only validators/IO and question-free assignments
are used. No runner import, models, network, retry, assembly, seal, scoring,
execution or training. A terminal HOLD is an end to construction polling, not a
discarded case or permission for a later stage. READY still requires the runner's
separate bank, authority and runtime checks before any optional execution.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter

RUN_ID = "LegalBot-GE-2026-09-05-codex-unseen-r1"
RECEIPT_NAME = "CONSTRUCTION-OUTCOME.json"
RESUME_RECEIPT_NAME = "CONSTRUCTION-PLAN-RESUME-OUTCOME.json"
STAGES = {"author": "cases", "author-parts": "cases", "oracle": "oracles",
          "oracle-parts": "oracles", "bank-review": "reviews",
          "oracle-repair": "oracles", "bank-review-repair": "reviews",
          "fixture-inventory": None, "fixture-inventory-repair": None,
          "fixture-format": None, "novelty-review": "reviews"}
REVIEW_CHECKS = ("scenario_fair", "variant_materially_distinct", "oracle_complete",
                 "source_support_verified", "currentness_verified", "fixtures_valid", "ready")
_CONTROLS = {"input.json", "schema.json", "output.json", "INVOCATION.json",
             "COMPLETION.json", "PARTS-PLAN.json", "ASSEMBLY-LINEAGE.json", "SCHEMA-REPAIR-LINEAGE.json"}


class OutcomeError(RuntimeError):
    """Stable public error codes only; never propagate private validator text."""


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _exists(r, path):
    r.safe_path(path)
    return path.exists()


def _preseal(r):
    if r.RUN_ID != RUN_ID:
        raise OutcomeError("OUTCOME_RUN_ID_MISMATCH")
    for name in ("BANK-SEAL.json", "ONE-PASS-START.json", "RUN-FREEZE.json"):
        if _exists(r, r.PUBLIC / name):
            raise OutcomeError("OUTCOME_REQUIRES_PRESEAL_CONSTRUCTION")


def _inventory(r):
    """Only current construction roots; no historical, candidate or log traversal."""
    result = {}
    for category in (*STAGES, "sources", "fixtures", "fixture-repaired", "fixture-repair-jobs", "novelty-review-control",
                     "author-batch-failure-preserved", "oracle-batch-failure-preserved", "receipts"):
        root = r.PRIVATE / category
        roots = [root / stage for stage in STAGES] if category == "receipts" else [root]
        entries = []
        for directory in roots:
            r.safe_path(directory)
            # Do not recurse into worker logs or unspecified preserved trees.
            if category in STAGES:
                files = []
                for work in sorted(directory.glob("shard-*")):
                    r.safe_path(work)
                    files.extend(work / name for name in sorted(_CONTROLS)
                                 if _exists(r, work / name))
                    if category in ("bank-review", "oracle-repair", "bank-review-repair"):
                        for name in ("sources", "fixtures"):
                            files.extend(r.safe_files(work / name))
            else:
                files = r.safe_files(directory)
            for path in files:
                entries.append({"path_sha256": _digest(path.relative_to(r.PRIVATE).as_posix()),
                                "raw_sha256": r.sha(path)})
        entries.sort(key=lambda entry: entry["path_sha256"])
        # Bind every path/raw-byte pair while keeping polling/public output small.
        result[category] = {"files": len(entries), "inventory_sha256": _digest(entries)}
    entries = []
    for name in ("OWNER-AUTHORIZATION.json", "UK-USA-SCOPE-AMENDMENT.json", "CREATION-START.json",
                 "PLAN-EXECUTION-AUTHORIZATION.json", "CONTINUOUS-PLAN-RESUME-START.json"):
        path = r.PUBLIC / name
        if _exists(r, path):
            entries.append({"path_sha256": _digest(name), "raw_sha256": r.sha(path)})
    result["public_controls"] = {"files": len(entries), "inventory_sha256": _digest(entries)}
    return result


def _assignments(r):
    legal, system = r.coverage_slots(), r.system_slots()
    domains = list(r.DOMAIN_FAMILIES)
    if len(legal) != 420 or len(system) != 23 or len(domains) != 35:
        raise OutcomeError("OUTCOME_ASSIGNMENT_DENOMINATOR_MISMATCH")
    slots = {slot["slot_id"]: slot for slot in legal + system}
    if len(slots) != 443 or {slot["slot_id"] for slot in system} != {
            f"system:{i:02d}" for i in range(1, 24)}:
        raise OutcomeError("OUTCOME_ASSIGNMENT_IDENTITY_MISMATCH")
    groups = {f"shard-{i:02d}": [s["slot_id"] for s in legal if s["domain"] == domain]
              for i, domain in enumerate(domains, 1)}
    if any(len(ids) != 12 for ids in groups.values()):
        raise OutcomeError("OUTCOME_ASSIGNMENT_SHARD_MISMATCH")
    groups["shard-36"] = [s["slot_id"] for s in system]
    return groups


def _job(r, work, key, expected=None):
    invocation = _exists(r, work / "INVOCATION.json")
    completed = _exists(r, work / "COMPLETION.json")
    job = {"state": "ACTIVE" if invocation and not completed else "PENDING",
           "attempted": invocation, "completed": completed, "rows": {}, "returned": 0}
    if not completed:
        return job
    job["state"] = "FAILED"
    try:
        raw = r.read(work / "output.json")
        if isinstance(raw, dict):
            if key is None:
                job["returned"] = 1
            elif isinstance(raw.get(key), list):
                job["returned"] = len(raw[key])
        completion = r.read(work / "COMPLETION.json")
        if (not invocation or type(completion.get("returncode")) is not int
                or not r.completion_recheckable(work.parent.name, completion)):
            return job
        validated = r.validate_job(work)
        if validated != raw:
            return job
        rows = [validated] if key is None else validated[key]
        ids = [row["case_id"] for row in rows]
        if not ids or any(not isinstance(cid, str) for cid in ids) or len(set(ids)) != len(ids):
            return job
        if expected is not None and set(ids) != set(expected):
            return job
        job.update(state="VALIDATED", rows=dict(zip(ids, rows, strict=True)))
    except Exception:
        # Schema validators can include complete private questions in exceptions.
        pass
    return job


def _source_checks(r, oracle):
    """Capture hashes are mechanical evidence only, never legal verification."""
    try:
        sources, points = oracle["sources"], oracle["required_points"]
        urls = {source["url"] for source in sources}
        # Several exact locators/quotes may legitimately share one official page.
        # Check each quote below, while capturing the page once by URL.
        if any(not p["source_urls"] or not set(p["source_urls"]) <= urls for p in points):
            return False, True
        all_urls = urls | {url for source in sources for url in source["currentness_check_urls"]}
        captured = {}
        missing, failed = False, False
        for url in sorted(all_urls):
            key = hashlib.sha256(url.encode()).hexdigest()
            path = r.PRIVATE / "sources" / (key + ".json")
            if not _exists(r, path):
                missing = True
                continue
            getter = getattr(r, "read_source_capture", None)
            record = getter(r.PRIVATE / "sources", key) if callable(getter) else r.read(path)
            if (record.get("url") != url or record.get("status") != "CAPTURED_NOT_LEGAL_VERIFIED"
                    or r.sha(path.with_suffix(".bytes")) != record.get("raw_sha256")
                    or r.digest(record["text"]) != record.get("text_sha256")):
                failed = True
            else:
                captured[url] = " ".join(record["text"].split()).casefold()
        if failed or missing:
            return False, failed
        for source in sources:
            quote = " ".join(source["quote"].split()).casefold()
            if (not quote or quote not in captured[source["url"]]
                    or not source["currentness_check_urls"]):
                return False, True
        return True, False
    except Exception:
        return False, True


def _fixture_checks(r, shard, number, case):
    try:
        from scripts.ge_unseen_preseal_repair import fixture_directory
        directory = fixture_directory(r, shard, number)
        r.safe_path(directory)
    except Exception:
        return False, True
    if _exists(r, directory / "FIXTURE-FAILURE.json"):
        return False, True
    path = directory / "UPLOAD-MANIFEST.json"
    if not _exists(r, path):
        return False, False
    try:
        manifest = r.read(path)
        files, extraction = manifest["files"], manifest["extraction"]
        if (manifest["case_id"] != case["case_id"]
                or manifest["raw_case_sha256"] != r.digest(case)
                or bool(files) != bool(case["uploads"]) or len(files) != len(extraction)):
            return False, True
        names = []
        for file, extracted in zip(files, extraction, strict=True):
            name = file.get("relative_path", file.get("path"))
            if not isinstance(name, str) or not name:
                return False, True
            target = directory / name
            if ".." in target.parts or not target.is_relative_to(directory):
                return False, True
            names.append(name)
            raw_hash = r.sha(target)
            if (file["sha256"] != raw_hash or extracted["file_sha256"] != raw_hash
                    or extracted["path"] != name or extracted.get("error", True) is not None
                    or not extracted["pages"] or extracted["page_count"] != len(extracted["pages"])
                    or file["page_count"] != extracted["page_count"]):
                return False, True
            for number, page in enumerate(extracted["pages"], 1):
                if (page.get("error", True) is not None or page["file_sha256"] != raw_hash
                        or page["page_number"] != number or not page["text"].strip()
                        or hashlib.sha256(page["text"].encode()).hexdigest() != page["text_sha256"]):
                    return False, True
        return len(set(names)) == len(names), len(set(names)) != len(names)
    except Exception:
        return False, True


def _oracle_ready(oracle, system):
    try:
        points = [point["point"] for point in oracle["required_points"]]
        return (oracle["source_sufficient"] is True and oracle["currentness_status"] == "VERIFIED"
                and oracle["construction_gaps"] == [] and (bool(points) or system)
                and all(isinstance(point, str) and point.strip() for point in points)
                and len(set(points)) == len(points)
                and (not system or bool(oracle["system_assertions"])))
    except Exception:
        return False


def _review_ready(review, oracle):
    try:
        checks = review["required_point_checks"]
        return (all(review.get(key) is True for key in REVIEW_CHECKS) and review["issues"] == []
                and Counter(c["point"] for c in checks) == Counter(p["point"] for p in oracle["required_points"])
                and all(c.get("supported") is True for c in checks))
    except Exception:
        return False


def _part_state(r, stage, shard, jobs, counts, planned, *, upstream_held=False):
    """Read the exact author/oracle subset plan; active jobs remain visible even on bad lineage."""
    part_stage = stage + "-parts"
    work = r.PRIVATE / stage / shard
    present = {name for name in jobs[part_stage] if name.startswith(shard + "-part-")}
    has_plan = _exists(r, work / "PARTS-PLAN.json")
    state = {"present": has_plan or bool(present), "failed": False, "pending": 0,
             "active": False, "drained": False}
    if not state["present"]:
        return state
    try:
        if stage == "author":
            from scripts.ge_unseen_author_parts import checked_plan
            plan = checked_plan(r, work)
        else:
            from scripts.ge_unseen_oracle_parts import _checked_plan
            _, plan = _checked_plan(r, work)
        names = {entry["part_shard"] for entry in plan["parts"]}
        if len(names) != len(plan["parts"]) or not names:
            raise ValueError
        planned[part_stage].update(names)
        state["drained"] = True
        for name in names:
            part = jobs[part_stage].get(name, {"state": "PENDING", "completed": False})
            state["failed"] |= part["state"] == "FAILED"
            state["active"] |= part["state"] == "ACTIVE"
            state["drained"] &= part["completed"]
            if part["state"] == "PENDING":
                if upstream_held:
                    counts[part_stage]["upstream_held"] += 1
                else:
                    counts[part_stage]["pending"] += 1
                    state["pending"] += 1
    except Exception:
        state["failed"] = True
        planned[part_stage].update(present)
        counts[part_stage]["upstream_held"] += sum(
            jobs[part_stage][name]["state"] == "PENDING" for name in present)
    return state


def _effective(r, jobs, stage):
    """Match collect's current rows to independently validated original/repair jobs."""
    expected = {cid: row for job in jobs[stage].values() for cid, row in job["rows"].items()}
    repair_stage = "oracle-repair" if stage == "oracle" else "bank-review-repair"
    if stage == "bank-review":
        for job in jobs["oracle-repair"].values():
            for cid in job["rows"]:
                expected.pop(cid, None)  # Old review cannot accept changed oracle bytes.
        for name in jobs["fixture-format"]:
            # A proposed/repaired fixture needs its own fresh review too.
            for cid in jobs["fixture-format"][name]["rows"]:
                expected.pop(cid, None)
        for work in (r.PRIVATE / "fixture-repaired").glob("shard-*"):
            try:
                from scripts.ge_unseen_fixture_repair import validate_rendered_successor
                manifest = validate_rendered_successor(r, work)
                expected.pop(manifest["case_id"], None)
            except Exception:
                pass  # The fixture gate reports invalid bytes on their own case.
    for job in jobs[repair_stage].values():
        for cid, row in job["rows"].items():
            expected[cid] = row
    try:
        rows = r.collect(stage, STAGES[stage])
        actual = {row["case_id"]: row for row in rows}
        occurrences = Counter(row["case_id"] for row in rows)
        matched = {cid: row for cid, row in actual.items()
                   if occurrences[cid] == 1 and cid in expected and row == expected[cid]}
        return matched, len(matched) == len(rows) and matched == expected
    except Exception:
        # Retain independently verified case-local rows when one malformed
        # aggregate member prevents collect completing. The aggregate gate fails.
        return expected, False


def _repair_plan(r, work):
    """Verify an input-only oracle plan without inventing/reading a future output."""
    from scripts.ge_unseen_preseal_repair import original_records, validate_lineage
    if work.parent.name != "oracle-repair":
        validate_lineage(r, work)
        return
    payload = r.read(work / "input.json")
    parent, number = payload["parent_shard"], payload["case_number"]
    if (parent not in {f"shard-{i:02d}" for i in range(1, 37)} or type(number) is not int
            or number < 1 or work.name != f"{parent}-case-{number:02d}"):
        raise ValueError("invalid repair plan assignment")
    records = original_records(r, parent)
    if records is None:
        raise ValueError("repair plan missing original roles")
    cases, oracles, reviews = records
    case = cases[number - 1]
    if (payload["cases"] != [case] or payload["original_oracle"] != oracles[case["case_id"]]
            or payload["construction_review"] != reviews[case["case_id"]]
            or payload["question_sha256"] != r.digest(case["question"])
            or payload["repair_attempt"] != 1 or payload["no_second_repair"] is not True
            or payload.get("query_budget") != 4 or payload.get("new_source_capture_budget") != 8
            or r.read(work / "schema.json") != r.ORACLE_SCHEMA):
        raise ValueError("repair plan changed original roles or bounded scope")
    for field, stage in (("author_output_sha256", "author"), ("oracle_output_sha256", "oracle"),
                         ("review_output_sha256", "bank-review")):
        if payload[field] != r.sha(r.PRIVATE / stage / parent / "output.json"):
            raise ValueError("repair plan original hash changed")


def _repair_state(r, jobs, counts):
    """Prepared repairs and their required single-case fresh reviews share one queue."""
    pending, invalid = 0, 0
    for stage in ("oracle-repair", "bank-review-repair", "fixture-inventory", "fixture-inventory-repair", "fixture-format"):
        for name, job in jobs[stage].items():
            if job["state"] != "PENDING":
                continue
            try:
                work = r.PRIVATE / stage / name
                if stage in ("fixture-inventory", "fixture-inventory-repair"):
                    if stage == "fixture-inventory-repair":
                        from scripts.ge_unseen_preseal_repair import validate_fixture_schema_repair
                        validate_fixture_schema_repair(r, work)
                    payload = r.read(work / "input.json")
                    from scripts.ge_unseen_fixture_repair import REQUIREMENT_SCHEMA
                    # The parent owns selecting the exact original case; the
                    # requirement worker sees only its frozen document contract.
                    parent, number = name.rsplit("-case-", 1)
                    if (parent not in {f"shard-{i:02d}" for i in range(1, 37)}
                            or not number.isdigit() or int(number) < 1):
                        raise ValueError("unassigned fixture inventory")
                    from scripts.ge_unseen_preseal_repair import original_records
                    cases, _, _ = original_records(r, parent)
                    case = cases[int(number)-1]
                    projected, binding = payload["case"], payload["binding"]
                    manifest_path = r.PRIVATE / "fixtures" / parent / f"case-{int(number):02d}/UPLOAD-MANIFEST.json"
                    manifest = r.read(manifest_path)
                    if (name != f"{parent}-case-{int(number):02d}"
                            or r.read(work / "schema.json") != REQUIREMENT_SCHEMA
                            or not {"case_id", "question", "uploads"} <= projected.keys()
                            or any(key not in case or value != case[key] for key,value in projected.items())
                            or binding["case_projection_sha256"] != r.digest(projected)
                            or binding["manifest_sha256"] != r.sha(manifest_path)
                            or binding["raw_case_sha256"] != manifest["raw_case_sha256"]
                            or binding["inventory_context_id"] == binding["formatter_context_id"]
                            or payload["original_binding_sha256"] != r.digest(binding)):
                        raise ValueError("fixture inventory input lineage changed")
                elif stage == "fixture-format":
                    # The formatter's adapter owns its immutable requirement and
                    # original-byte binding; no model result is trusted here.
                    from scripts.ge_unseen_fixture_repair import _adapter_job
                    _adapter_job(r, name)
                else:
                    _repair_plan(r, work)
                counts[stage]["pending"] += 1
                pending += 1
            except Exception:
                counts[stage]["upstream_held"] += 1
                invalid += 1
        counts[stage]["planned"] = len(jobs[stage])
        counts[stage]["absent"] = 0
    effective_inventories = {name: ("fixture-inventory", job) for name, job in jobs["fixture-inventory"].items()}
    effective_inventories.update({name: ("fixture-inventory-repair", job)
                                 for name, job in jobs["fixture-inventory-repair"].items()})
    for name, (inventory_stage, job) in effective_inventories.items():
        if job["state"] != "VALIDATED" or name in jobs["fixture-format"]:
            continue
        if _exists(r, r.PRIVATE / "receipts/fixture-inventory" / (name + "-prepare-hold.json")):
            invalid += 1
            continue
        try:
            from scripts.ge_unseen_fixture_repair import validate_requirement_output
            work = r.PRIVATE / inventory_stage / name
            value = validate_requirement_output(r.read(work / "input.json"),
                json.dumps(r.read(work / "output.json"), ensure_ascii=False).encode())
            if value["state"] == "INVENTORY_DRAFT_BOUND":
                pending += 1
                counts["fixture-format"]["pending"] += 1
                counts["fixture-format"]["planned"] += 1
                counts["fixture-format"]["absent"] += 1
            else:
                invalid += 1  # Honest inventory HOLD is terminal.
        except Exception:
            invalid += 1
    needs_review = {name for name, job in jobs["oracle-repair"].items() if job["state"] == "VALIDATED"}
    for directory in (r.PRIVATE / "fixture-repaired").glob("shard-*"):
        if directory.name in jobs["fixture-format"]:
            continue
        try:
            from scripts.ge_unseen_fixture_repair import validate_rendered_successor
            validate_rendered_successor(r, directory)
            needs_review.add(directory.name)
        except Exception:
            invalid += 1
    for name, job in jobs["fixture-format"].items():
        if job["state"] != "VALIDATED":
            continue
        directory = r.PRIVATE / "fixture-repaired" / name
        if not _exists(r, directory):
            failure = r.PRIVATE / "receipts/fixture-format" / (name + "-render-failure.json")
            if _exists(r, failure):
                invalid += 1
            else:
                pending += 1
                counts["fixture-format"]["pending"] += 1  # Local render still required.
        else:
            try:
                from scripts.ge_unseen_fixture_repair import validate_rendered_successor
                validate_rendered_successor(r, directory)
                needs_review.add(name)
            except Exception:
                invalid += 1
    absent = needs_review - set(jobs["bank-review-repair"])
    blocked = set()
    for name in absent:
        try:
            research = jobs["oracle-repair"].get(name)
            if research is None:
                continue
            if research["state"] != "VALIDATED":
                blocked.add(name)
                continue
            payload = r.read(r.PRIVATE / "oracle-repair" / name / "input.json")
            if payload["cases"][0]["uploads"] and payload["construction_review"]["fixtures_valid"] is not True:
                from scripts.ge_unseen_preseal_repair import fixture_directory
                directory = fixture_directory(r, payload["parent_shard"], payload["case_number"])
                if directory.parent.name != "fixture-repaired":
                    blocked.add(name)
        except Exception:
            blocked.add(name)
            invalid += 1
    counts["bank-review-repair"]["planned"] += len(absent)
    counts["bank-review-repair"]["absent"] += len(absent)
    counts["bank-review-repair"]["upstream_held"] += len(blocked)
    counts["bank-review-repair"]["pending"] += len(absent - blocked)
    return pending + len(absent - blocked), invalid


def _inspect(r):
    _preseal(r)
    groups = _assignments(r)
    inventory = _inventory(r)
    jobs, counts = {}, {}
    for stage, key in STAGES.items():
        root = r.PRIVATE / stage
        r.safe_path(root)
        jobs[stage] = {}
        for work in sorted(root.glob("shard-*")):
            r.safe_path(work)
            jobs[stage][work.name] = _job(r, work, key,
                groups.get(work.name) if stage in ("author", "oracle", "bank-review") else None)
        values = list(jobs[stage].values())
        counts[stage] = {"prepared": len(values), "attempted": sum(j["attempted"] for j in values),
                         "completed": sum(j["completed"] for j in values),
                         "active": sum(j["state"] == "ACTIVE" for j in values),
                         "failed": sum(j["state"] == "FAILED" for j in values),
                         "validated_rows": sum(len(j["rows"]) for j in values),
                         "returned_rows": sum(j["returned"] for j in values),
                         "pending": 0, "upstream_held": 0}
    empty = {"state": "PENDING", "rows": {}, "completed": False}
    pending, invalid_repair_lineage = _repair_state(r, jobs, counts)
    novelty_required = _exists(r, r.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json")
    novelty = {}
    if novelty_required:
        novelty = {cid: row for j in jobs["novelty-review"].values() for cid, row in j["rows"].items()}
        novelty_pending = sum(j["state"] == "PENDING" for j in jobs["novelty-review"].values())
        counts["novelty-review"]["pending"] = novelty_pending
        pending += novelty_pending
    upstream, assembly_missing = 0, 0
    unexpected = sum(name not in groups for stage in ("author", "oracle", "bank-review")
                     for name in jobs[stage])
    planned_parts = {"author-parts": set(), "oracle-parts": set()}
    effective_oracles, oracle_lineage = _effective(r, jobs, "oracle")
    effective_reviews, review_lineage = _effective(r, jobs, "bank-review")
    resolved_authors = 0
    outcomes = {kind: Counter() for kind in ("legal", "system")}
    readiness = Counter()
    for shard, expected in groups.items():
        author = jobs["author"].get(shard, empty)
        oracle = jobs["oracle"].get(shard, empty)
        reviewer = jobs["bank-review"].get(shard, empty)
        author_parts = _part_state(r, "author", shard, jobs, counts, planned_parts)
        pending += author_parts["pending"]
        author_held = author["state"] == "FAILED"
        if author["state"] == "PENDING" and not author_parts["present"]:
            counts["author"]["pending"] += 1
            pending += 1
        if author_parts["failed"]:
            author_held = True
        if author_parts["present"] and author_parts["drained"] and author["state"] == "PENDING":
            author_held = True
            if not author_parts["failed"]:
                assembly_missing += 1
        resolved_authors += author["completed"] or (
            author_parts["present"] and (author_parts["drained"] or author_parts["failed"]))
        work = r.PRIVATE / "oracle" / shard
        oracle_parts = _part_state(r, "oracle", shard, jobs, counts, planned_parts,
                                   upstream_held=author_held)
        pending += oracle_parts["pending"]
        has_plan = oracle_parts["present"]
        oracle_held = author_held or oracle["state"] == "FAILED" or oracle_parts["failed"]
        if oracle["state"] == "PENDING":
            if not oracle_held and has_plan and oracle_parts["drained"]:
                # No model job exists for a canonical assembly placeholder. A
                # drained plan with no assembled output is a construction HOLD.
                oracle_held = True
                assembly_missing += 1
            if oracle_held:
                counts["oracle"]["upstream_held"] += 1
            elif not has_plan:
                counts["oracle"]["pending"] += 1
                pending += 1
        review_upstream_held = oracle_held
        by_case = {}
        if author["state"] == "VALIDATED" and oracle["state"] == "VALIDATED" and not oracle_held:
            # Fixture numbering follows frozen canonical order, not model order.
            try:
                canonical = r.read(work / "input.json")["cases"]
                if len(canonical) != len(expected) or {c["case_id"] for c in canonical} != set(expected):
                    raise ValueError
                for number, case in enumerate(canonical, 1):
                    cid = case["case_id"]
                    value = effective_oracles[cid]
                    source_ok, source_failed = _source_checks(r, value)
                    fixture_ok, fixture_failed = _fixture_checks(r, shard, number, case)
                    oracle_ok = _oracle_ready(value, cid.startswith("system:"))
                    by_case[cid] = (oracle_ok, source_ok, fixture_ok)
                    review_upstream_held |= source_failed or fixture_failed or not oracle_ok
            except Exception:
                review_upstream_held = True
                by_case = {}
        if reviewer["state"] == "PENDING":
            if review_upstream_held:
                counts["bank-review"]["upstream_held"] += 1
            else:
                counts["bank-review"]["pending"] += 1
                pending += 1
        upstream += author_held or oracle_held
        for cid in expected:
            kind = "system" if cid.startswith("system:") else "legal"
            flags = by_case.get(cid, (False, False, False))
            reviewed = (cid in effective_reviews and cid in effective_oracles
                        and _review_ready(effective_reviews[cid], effective_oracles[cid]))
            readiness["authored"] += cid in author["rows"]
            readiness["oracle"] += flags[0]
            readiness["sources"] += flags[1]
            readiness["fixtures"] += flags[2]
            readiness["reviewer"] += reviewed
            novelty_ok = not novelty_required or novelty.get(cid, {}).get("novelty") == "PASS"
            readiness["novelty"] += novelty.get(cid, {}).get("novelty") == "PASS"
            if author["state"] == "VALIDATED" and not oracle_held and all(flags) and reviewed and novelty_ok:
                category = "ready"
            elif cid not in author["rows"]:
                category = "author_unavailable"
            elif cid not in effective_oracles or oracle_held:
                category = "oracle_unavailable"
            elif not flags[0]:
                category = "oracle_hold"
            elif not flags[1]:
                category = "source_hold"
            elif not flags[2]:
                category = "fixture_hold"
            elif cid not in effective_reviews:
                category = "review_unavailable"
            elif reviewed and not novelty_ok:
                category = "novelty_hold"
            else:
                category = "review_hold"
            outcomes[kind][category] += 1
    for stage, planned in planned_parts.items():
        unexpected += len(set(jobs[stage]) - planned)
    for stage in ("author", "author-parts", "oracle", "oracle-parts", "bank-review"):
        assigned = planned_parts[stage] if stage in planned_parts else set(groups)
        expected_jobs = len(assigned)
        counts[stage]["planned"] = expected_jobs
        counts[stage]["absent"] = len(assigned - set(jobs[stage]))
    active = sum(stage["active"] for stage in counts.values())
    authors_completed = sum(jobs["author"].get(shard, empty)["completed"] for shard in groups)
    terminal = resolved_authors == 36 and active == 0 and pending == 0
    ready = sum(row["ready"] for row in outcomes.values())
    repair_failed = sum(counts[stage]["failed"] for stage in
                        ("oracle-repair", "bank-review-repair", "fixture-inventory", "fixture-inventory-repair", "fixture-format"))
    # Keep the failed transport attempts in historical counts. A validated
    # bounded successor resolves only its own pre-model launch failure; actual
    # fixture rendering and fresh construction review still gate every case.
    resolved_fixture_transport_failures = sum(
        job["state"] == "VALIDATED" and jobs["fixture-inventory"].get(name, {}).get("state") == "FAILED"
        for name, job in jobs["fixture-inventory-repair"].items())
    repair_failed -= resolved_fixture_transport_failures
    all_ready = (terminal and ready == 443 and unexpected == 0 and not invalid_repair_lineage
                 and not repair_failed and oracle_lineage and review_lineage)
    result = {"schema": "legalbot.ge-unseen-construction-outcome.v1", "run_id": RUN_ID,
              "overall_state": ("CONSTRUCTION_READY" if all_ready else "CONSTRUCTION_TERMINAL_HOLD")
              if terminal else "CONSTRUCTION_ACTIVE" if active else "CONSTRUCTION_PENDING",
              "terminal": terminal, "construction_ready": all_ready,
              "denominators": {"legal": 420, "system": 23, "total": 443},
              "stages": counts, "author_shards_completed": authors_completed,
              "author_shards_resolved": resolved_authors,
              "active_jobs": active, "pending_jobs": pending,
              "upstream_held_shards": upstream, "unassembled_drained_plans": assembly_missing,
              "unexpected_jobs": unexpected,
              "effective_rows": {"oracles": len(effective_oracles), "reviews": len(effective_reviews)},
              "lineage": {"effective_oracles_validated": oracle_lineage,
                          "effective_reviews_validated": review_lineage,
                          "invalid_repair_plans_or_renders": invalid_repair_lineage},
              "confirmed_checks": {key: readiness[key] for key in
                                   ("authored", "oracle", "sources", "fixtures", "reviewer")},
              "novelty_review": {"required": novelty_required, "passed_cases": readiness["novelty"],
                                  "denominator": 443},
              "resolved_fixture_transport_failures": resolved_fixture_transport_failures,
              "cases": {kind: {"denominator": denominator, "ready": outcomes[kind]["ready"],
                               "not_ready": denominator - outcomes[kind]["ready"],
                               "categories": dict(sorted(outcomes[kind].items()))}
                        for kind, denominator in (("legal", 420), ("system", 23))},
              "authorizing": False, "bank_sealed": False, "candidate_executed": False,
              "training": False, "scoring_performed": False,
              "factual_first": True, "quality_threshold": 70, "critical_floors_required": True,
              "input_inventories": inventory}
    _preseal(r)
    if inventory != _inventory(r):
        raise OutcomeError("OUTCOME_INPUTS_CHANGED_DURING_INSPECTION")
    return {**result, "content_sha256": _digest(result)}


def inspect_outcome(r):
    """Return counts and hashes only; no writes or inferred job death/authority."""
    try:
        return _inspect(r)
    except OutcomeError:
        raise
    except Exception:
        raise OutcomeError("OUTCOME_INSPECTION_FAILED") from None


def publish_outcome(r, *, resume=False, schema_repair_resume=False):
    """Publish once under caller-owned scheduling exclusion; verify exact NO_OP.

    An existing receipt must match both its own digest and the newly inspected
    state, including raw byte inventories. Conflicts are never overwritten. A
    publication race is accepted only if the winning receipt is identical.
    """
    def inspect_current():
        value = inspect_outcome(r)
        if schema_repair_resume:
            if resume:
                raise OutcomeError("OUTCOME_RESUME_MODES_CONFLICT")
            from scripts.ge_unseen_research_gate import require_plan_execution
            require_plan_execution(r)
            path = r.PUBLIC / "CONTINUOUS-SCHEMA-REPAIR-START.json"
            start = r.read(path)
            if (start != r.seal(start) or start.get("run_id") != r.RUN_ID
                    or start.get("schema_repair_resume") is not True
                    or start.get("previous_resume_sha256") != r.sha(r.PUBLIC / "CONTINUOUS-PLAN-RESUME-START.json")
                    or start.get("plan_execution_sha256") != r.sha(r.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json")):
                raise OutcomeError("OUTCOME_SCHEMA_REPAIR_BINDING_INVALID")
            value.update(schema_repair_start_sha256=r.sha(path),
                         previous_resume_sha256=start["previous_resume_sha256"])
            value = r.seal(value)
        if resume:
            from scripts.ge_unseen_research_gate import require_plan_execution
            require_plan_execution(r)
            start_path = r.PUBLIC / "CONTINUOUS-PLAN-RESUME-START.json"
            start = r.read(start_path)
            if (start != r.seal(start) or start.get("run_id") != r.RUN_ID
                    or start.get("resume") is not True
                    or start.get("original_start_sha256") != r.sha(r.PUBLIC / "CONTINUOUS-RUN-START.json")
                    or start.get("plan_execution_sha256") != r.sha(r.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json")):
                raise OutcomeError("OUTCOME_RESUME_BINDING_INVALID")
            original = r.PUBLIC / RECEIPT_NAME
            value.update(resume_start_sha256=r.sha(start_path),
                         original_outcome_sha256=r.sha(original) if _exists(r, original) else None)
            value = r.seal(value)
        return value

    current = inspect_current()
    path = r.PUBLIC / ("CONSTRUCTION-SCHEMA-REPAIR-OUTCOME.json" if schema_repair_resume else
                       RESUME_RECEIPT_NAME if resume else RECEIPT_NAME)

    def verify_existing():
        try:
            saved = r.read(path)
            body = {key: value for key, value in saved.items() if key != "content_sha256"}
            if saved.get("content_sha256") != _digest(body) or saved != current:
                raise OutcomeError("OUTCOME_RECEIPT_IDENTITY_MISMATCH")
        except OutcomeError:
            raise
        except Exception:
            raise OutcomeError("OUTCOME_RECEIPT_INVALID") from None
        return {"status": "NO_OP", "outcome": current}

    try:
        if _exists(r, path):
            return verify_existing()
        if not current["terminal"]:
            return {"status": "NOT_TERMINAL", "outcome": current}
        # Recheck immediately before the exclusive create; the caller still owns
        # the scheduling/writer lock through this operation.
        if inspect_current() != current:
            raise OutcomeError("OUTCOME_INPUTS_CHANGED_BEFORE_PUBLICATION")
        try:
            r.write(path, current)
        except FileExistsError:
            return verify_existing()
        verify_existing()
        return {"status": "CREATED", "outcome": current}
    except OutcomeError:
        raise
    except Exception:
        raise OutcomeError("OUTCOME_PUBLICATION_FAILED") from None
