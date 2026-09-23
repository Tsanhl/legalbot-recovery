"""Question-only exclusion intake from explicitly named exposed public packs.

No retired bank discovery, latest-result lookup, source selection, shared export
or answer-model call. Only the current private novelty reviewers see this corpus.
"""
from __future__ import annotations

import hashlib
import json

EXPOSED_PACKS = (
    "LegalBot-GE-2026-09-03-answer-reconstruction-r1",
    "LegalBot-GE-2026-09-04-ai-auto-quality-review-r1",
    "LegalBot-GE-2026-09-04-fresh-visible-adapter-evaluation-r2",
    "LegalBot-GE-2026-09-04-fresh-visible-codex-evaluation-r1",
    "LegalBot-GE-2026-09-04-post-unseen-clean-visible-r3",
    "LegalBot-GE-2026-09-04-post-unseen-fresh-planned-route-r1",
    "LegalBot-GE-2026-09-04-post-unseen-fresh-audited-route-r1",
)
OWNER_EXAMPLE = ("like my mom - she buy a defect product shop refuse to pay she upload the case - "
                 "now the bot should act like a lawyer and tell her what to do with leg + case law")


def questions(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("question", "question_text", "user_question") and isinstance(item, str) and item.strip():
                yield item
            elif isinstance(item, (dict, list)):
                yield from questions(item)
    elif isinstance(value, list):
        for item in value:
            yield from questions(item)


def _rows(r, path):
    r.safe_path(path)
    if path.stat().st_size > 40_000_000:
        raise RuntimeError("explicit exposure source exceeds bounded size")
    return ([json.loads(line) for line in path.read_text().splitlines() if line.strip()]
            if path.suffix == ".jsonl" else r.read(path))


def prepare(r):
    from scripts import ge_unseen_novelty_review as review
    from scripts.ge_unseen_research_gate import require_plan_execution
    require_plan_execution(r)
    authors = sorted((r.PRIVATE/"author").glob("shard-*"))
    if len(authors) != 36 or any(not (p/"COMPLETION.json").exists() for p in authors):
        return {"novelty_review_waiting_for_author_terminal": True}
    if (r.PRIVATE/"novelty-review-control/PLAN.json").exists():
        review.checked_plan(r)
        return {"novelty_review_existing_plan": True}
    rows = r.collect("author", "cases")
    slots = {s["slot_id"]: s for s in r.coverage_slots()+r.system_slots()}
    cases = [{"case_id": c["case_id"], "question": c["question"],
              "domain": slots[c["case_id"]]["domain"], "family": slots[c["case_id"]]["family"],
              "pair_family": None if c["case_id"].startswith("system:") else
                  slots[c["case_id"]]["domain"]+":"+slots[c["case_id"]]["family"],
              "case_type": "system" if c["case_id"].startswith("system:") else "legal"} for c in rows]
    exposed, files = {}, {}
    root = r.ROOT/"data/evaluations/general-enquiries"
    for pack in EXPOSED_PACKS:
        for path in sorted((root/pack).glob("*.json*")):
            if not path.is_file():
                continue
            try:
                value = _rows(r, path)
            except (ValueError, UnicodeError):
                continue
            found = list(questions(value))
            if found:
                files[path.relative_to(r.ROOT).as_posix()] = r.sha(path)
                for text in found:
                    key = hashlib.sha256(text.encode()).hexdigest()
                    exposed[key] = {"id": "exposed-"+key, "text": text}
    training = root/"LegalBot-GE-2026-09-04-answer-weight-training-r2/TRAINING-RECORDS.jsonl"
    approved = root/"LegalBot-GE-2026-09-04-ai-auto-quality-review-r1/AI-EVALUATION-GOLD-CANDIDATES.jsonl"
    records, accepted = _rows(r, training), _rows(r, approved)
    if len(records) != 13 or len(accepted) != 13:
        raise RuntimeError("thirteen trained exclusions not reconciled")
    expected = {x["case_id"]: x["target_answer_hash"] for x in records}
    trained = []
    for row in accepted:
        sha = hashlib.sha256(row["candidate_answer"].encode()).hexdigest()
        if expected.get(row["case_id"]) != sha or row["candidate_answer_hash"] != sha:
            raise RuntimeError("exact trained answer exclusion hash mismatch")
        trained.append({"id": "trained-"+sha, "text": row["candidate_answer"]})
    for path in (training, approved):
        files[path.relative_to(r.ROOT).as_posix()] = r.sha(path)
    files["scripts/ge_unseen_novelty_intake.py"] = r.sha(r.ROOT/"scripts/ge_unseen_novelty_intake.py")
    # Do not send real paths to model contexts. The protected host copy binds them.
    opaque = {"source-"+str(i): sha for i, sha in enumerate(files.values(), 1)}
    binding = {"files": files, "opaque_labels": {"source-"+str(i): name for i, name in enumerate(files, 1)},
               "canonical_authored_cases": len(cases), "full_bank_denominator": 443,
               "author_unavailable_slots": 443-len(cases), "retired_bank_accessed": False}
    path = r.PRIVATE/"NOVELTY-CORPUS-INPUT-FILES.json"
    if path.exists():
        if r.read(path) != binding:
            raise RuntimeError("novelty exclusion inputs changed")
    else:
        r.write(path, binding)
    return review.prepare_jobs(r, cases, list(exposed.values()), trained,
        [{"id": "owner-consumer-example", "text": OWNER_EXAMPLE}], opaque)
