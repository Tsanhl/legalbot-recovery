import hashlib
import json
from datetime import date

from app.conversations.clarification import necessary_questions
from app.research.licence_permissions import permits_find_case_law


def test_followup_uses_user_facts_without_assistant_suggestions():
    first = "I rent a flat in the UK. My landlord emailed me on 21 September. Rent is £1,000."
    ask = necessary_questions(first)
    assert len(ask) == 5
    assert not any("rent" in q.lower() and "amount" in q.lower() for q in ask)
    text = f"Saved conversation (facts).\nUSER MESSAGE 1:\n{first}\n\nASSISTANT MESSAGE 2:\nThe flat might be in England. Does your landlord live there?\n\nCURRENT USER MESSAGE:\nI have no further information."
    assert any("nation" in q.lower() or "england" in q.lower() for q in necessary_questions(text))
    text = f"Saved conversation (facts).\nUSER MESSAGE 1:\n{first}\n\nASSISTANT MESSAGE 2:\nWhere is it?\n\nCURRENT USER MESSAGE:\nBirmingham, England. I rent the entire flat as my main home. The landlord does not live there. The agreement term began on 1 September 2025. The email is the only notice."
    assert necessary_questions(text) == ()


def test_fcl_permissions_are_effective_and_purpose_specific(tmp_path):
    assert not permits_find_case_law(tmp_path, "vector_index", today=date(2026, 9, 23))
    doc = tmp_path / "executed.pdf"
    doc.write_bytes(b"test-only synthetic licence bytes")
    record = {
        "schema": "legalbot.executed-fcl-permissions.v1",
        "executed": True,
        "terms_reviewed": True,
        "executed_document": "executed.pdf",
        "executed_document_sha256": hashlib.sha256(doc.read_bytes()).hexdigest(),
        "effective_from": "2026-09-24",
        "effective_to": None,
        "revoked": False,
        "permissions": {
            "capture": True,
            "vector_index": True,
            "external_model": False,
            "training": False,
        },
        "term_locators": {"capture": "synthetic clause 1", "vector_index": "synthetic clause 2"},
    }
    path = tmp_path / "find-case-law-permissions.json"
    path.write_text(json.dumps(record))
    assert not permits_find_case_law(tmp_path, "vector_index", today=date(2026, 9, 23))
    assert permits_find_case_law(tmp_path, "vector_index", today=date(2026, 9, 24))
    assert not permits_find_case_law(tmp_path, "training", today=date(2026, 9, 24))
    assert not permits_find_case_law(tmp_path, "external_model", today=date(2026, 9, 24))
    doc.write_bytes(b"changed")
    assert not permits_find_case_law(tmp_path, "vector_index", today=date(2026, 9, 24))


def test_real_scottish_followup_and_assistant_document_question_do_not_reask():
    import json
    from pathlib import Path

    from app.conversations.clarification import necessary_questions
    from app.orchestration.behavior import looks_like_missing_document
    cases = json.loads((Path(__file__).resolve().parents[2] / 'docs/testing/CHAT_CAMPAIGN_20.json').read_text())['cases']
    for case_id in ('GE02', 'GE04', 'GE09'):
        case = next(c for c in cases if c['id'] == case_id)
        first_questions = necessary_questions(case['question'])
        assert first_questions
        context = f"Saved conversation (facts)\nUSER MESSAGE 1:\n{case['question']}\n\nASSISTANT MESSAGE 2:\n" + '\n'.join(first_questions) + f"\n\nCURRENT USER MESSAGE:\n{case['follow_up']}"
        assert not necessary_questions(context)
        assert not looks_like_missing_document(context, 0)
