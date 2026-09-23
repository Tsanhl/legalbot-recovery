"""Summarise a frozen exposed campaign without exporting private transcripts.

Reads only the named isolated development state. Does not open protected banks,
call a model, repair an answer or change a completed execution record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"shared-chat-[a-z0-9-]{3,40}", args.state):
        raise ValueError("Expected isolated shared-chat state")
    from app.crypto import LocalCipher

    cipher = LocalCipher.from_local_key(create=False)
    state = ROOT / "data/development-runtime" / args.state
    campaign_raw = (ROOT / "docs/testing/CHAT_CAMPAIGN_20.json").read_bytes()
    campaign = json.loads(campaign_raw)
    cases = {c["question"]: c for c in campaign["cases"]}
    db = sqlite3.connect(f"file:{state / 'data/catalog.sqlite3'}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    displays = {}
    for path in (state / "data/vault/display-receipts").glob("*.enc"):
        value = json.loads(cipher.decrypt_bytes(path.read_bytes()))
        displays.setdefault(value["conversation_id"], []).append((path.stem, value))
    rows = []
    for conversation in db.execute("SELECT id FROM chat_owned_conversations ORDER BY created_at"):
        cid = conversation["id"]
        messages = list(
            db.execute(
                "SELECT * FROM conversation_messages WHERE conversation_id=? ORDER BY ordinal",
                (cid,),
            )
        )
        if not messages:
            continue
        first = cipher.decrypt_text(messages[0]["encrypted_content"])
        case = cases.get(first)
        if case is None:
            continue
        jobs = list(
            db.execute(
                "SELECT j.*,cc.route_id FROM chat_owned_jobs c JOIN jobs j ON j.id=c.job_id JOIN chat_connections cc ON cc.id=c.connection_id WHERE c.conversation_id=? ORDER BY j.created_at",
                (cid,),
            )
        )
        route = jobs[0]["route_id"]
        if any(j["route_id"] != route for j in jobs):
            raise ValueError("Provider changed inside a comparison conversation")
        research, retrieval, model_stages = [], [], []
        for job in jobs:
            for attempt in db.execute(
                "SELECT * FROM job_stage_attempts WHERE job_id=? ORDER BY rowid", (job["id"],)
            ):
                stage = attempt["stage_key"]
                if stage in {"online-research", "online-source-review", "retrieval"}:
                    value = (
                        json.loads(cipher.decrypt_text(attempt["encrypted_output"]))
                        if attempt["encrypted_output"]
                        else {}
                    )
                    if stage == "online-research":
                        research.append(value)
                    elif stage == "retrieval":
                        retrieval.append(json.loads(attempt["metrics_json"]))
                if stage not in {"retrieval", "online-research"}:
                    model_stages.append(stage)
        final = jobs[-1]
        expected_sequence = [(m["id"], m["role"]) for m in messages]
        matching = [
            (digest, v)
            for digest, v in displays.get(cid, [])
            if [(m["id"], m["role"]) for m in v["messages"]] == expected_sequence
        ]
        user_texts = [
            cipher.decrypt_text(m["encrypted_content"]) for m in messages if m["role"] == "user"
        ]
        expected_texts = [case["question"]] + ([case["follow_up"]] if case["follow_up"] else [])
        answers = [
            cipher.decrypt_text(m["encrypted_content"])
            for m in messages
            if m["role"] == "assistant"
        ]
        final_is_clarification = bool(answers and answers[-1].startswith("I need a few facts"))
        clarification_sequence = None
        if case["follow_up"]:
            clarification_sequence = (
                len(answers) == 2
                and answers[0].startswith("I need a few facts")
                and not final_is_clarification
            )
        row = {
            "case_id": case["id"],
            "task_type": case["task_type"],
            "selected_route": route,
            "selected_model": "gpt-5.5"
            if route == "codex_bridge"
            else "mlx-community/Qwen3.5-9B-4bit",
            "messages_submitted": len(jobs),
            "exact_frozen_user_messages": user_texts == expected_texts,
            "publication_status": final["status"],
            "terminal_reason": final["error_code"],
            "clarification_then_resolved_followup": clarification_sequence,
            "display_receipt_sha256": [d for d, _ in matching],
            "displayed_message_count": len(messages),
            "latency_seconds_per_turn": [
                round(
                    (
                        datetime.fromisoformat(j["updated_at"])
                        - datetime.fromisoformat(j["created_at"])
                    ).total_seconds(),
                    3,
                )
                for j in jobs
            ],
            "model_stage_names": sorted(set(model_stages)),
            "substantive_generation_attempted": any(
                "draft" in s or "repair" in s for s in model_stages
            ),
            "source_review_attempted": "online-source-review" in model_stages,
            "retrieval_candidate_counts": [r.get("candidate_count") for r in retrieval],
            "query_count": sum(r.get("query_count", 0) for r in retrieval),
            "online_searches": [s for r in research for s in r.get("searches", [])],
            "evidence_rejection_reasons": sorted(
                set(code for r in research for code in r.get("rejections", []))
            ),
            "retrieval_generation_sha256": sorted(
                set(r["query_trace"]["generation_sha256"] for r in research if r.get("query_trace"))
            ),
            "query_embedding_performed": any(
                r.get("query_trace", {}).get("embedding_performed", False) for r in research
            ),
            "supplied_evidence_count": sum(
                len(r.get("supplied_evidence_ids", [])) for r in research
            ),
            "substantive_word_count": None,
            "length_result": "NOT_ASSESSABLE_NO_SUBSTANTIVE_ANSWER",
            "factual_accuracy": "NOT_ASSESSABLE_NO_SUBSTANTIVE_ANSWER",
            "material_coverage": "INCOMPLETE",
            "invented_facts": "NO_SUBSTANTIVE_ANSWER_TO_ASSESS",
            "citation_validation": "NOT_ASSESSABLE_NO_SUBSTANTIVE_ANSWER",
        }
        if final["status"] == "complete" or row["substantive_generation_attempted"]:
            raise ValueError(
                "Substantive output requires a separate claim-level review; this hold report cannot score it"
            )
        rows.append(row)
    expected = {(c["id"], r) for c in campaign["cases"] for r in campaign["models"]}
    actual = {(r["case_id"], r["selected_route"]) for r in rows}
    if actual != expected or len(rows) != 40:
        raise ValueError(f"Campaign coverage mismatch: {len(rows)} conversations")
    result = {
        "schema": "legalbot.exposed-ui-campaign-holds.v1",
        "state": args.state,
        "campaign_sha256": hashlib.sha256(campaign_raw).hexdigest(),
        "authority_sha256": hashlib.sha256(
            (state / "GE-DEVELOPMENT-CHAT-AUTHORITY.json").read_bytes()
        ).hexdigest(),
        "completed_legal_answers": 0,
        "conversations": len(rows),
        "submitted_turns": sum(r["messages_submitted"] for r in rows),
        "source_and_intake_failure_is_model_quality_score": False,
        "professional_legal_validation": False,
        "raw_transcripts_location": "isolated state encrypted conversation_messages and vault/display-receipts; excluded from Git",
        "rows": sorted(rows, key=lambda r: (r["selected_route"], r["case_id"])),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise FileExistsError("Preserve the existing report")
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {k: v for k, v in result.items() if k not in {"rows", "raw_transcripts_location"}}
        )
    )


if __name__ == "__main__":
    main()
