from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.deletion_guard import DeletionAuthorization, DeletionGuard, DeletionObjectClass
from app.quality.policy import POLICY_VERSION
from app.types import EvidenceSpan


def _create_job(database, cipher, job_id: str = "job-sensitive") -> None:
    database.create_job(
        job_id=job_id,
        encrypted_question=cipher.encrypt_text("SECRET QUESTION PLAINTEXT"),
        question_summary="safe summary",
        request={"task_type": "general", "jurisdiction": "England and Wales"},
    )


def test_question_claims_and_diffs_are_never_stored_as_plaintext(database, cipher) -> None:
    with pytest.raises(ValueError, match="must not duplicate"):
        database.create_job(
            job_id="bad-job",
            encrypted_question=cipher.encrypt_text("secret"),
            question_summary="safe",
            request={"question": "secret"},
        )

    _create_job(database, cipher)
    database.store_answer_version(
        answer_id="answer-sensitive",
        job_id="job-sensitive",
        version_number=1,
        version_kind="structured",
        encrypted_content=cipher.encrypt_text("released answer"),
        encrypted_diff_from_parent=cipher.encrypt_text("SECRET VERSION DIFF"),
        word_count=2,
        release_state="verified_full",
        policy_version=POLICY_VERSION,
        model_version="test",
        index_build_id=None,
        purge_after_days=None,
    )
    database.store_claims(
        "answer-sensitive",
        [
            {
                "id": "claim-sensitive",
                "section_id": "section-1",
                "encrypted_text": cipher.encrypt_text("SECRET CLAIM TEXT"),
                "proposition_hash": "a" * 64,
                "verification_status": "verified",
            }
        ],
    )

    job = database.job("job-sensitive")
    answer = database.answer("answer-sensitive")
    claim = database.fetchone("SELECT * FROM claims WHERE model_claim_id='claim-sensitive'")
    assert job is not None and "SECRET QUESTION" not in str(job["request_json"])
    assert answer is not None and answer["diff_from_parent"] is None
    assert claim is not None and claim["claim_text"] == ""
    assert claim["id"] != claim["model_claim_id"]
    assert claim["proposition_hash"] == "a" * 64
    assert cipher.decrypt_text(answer["encrypted_diff_from_parent"]) == "SECRET VERSION DIFF"
    assert cipher.decrypt_text(claim["encrypted_claim_text"]) == "SECRET CLAIM TEXT"


def test_unchanged_model_claim_ids_are_scoped_across_repaired_versions(
    database, cipher, evidence: EvidenceSpan
) -> None:
    _create_job(database, cipher, "job-repair-claims")
    database.store_evidence([evidence.model_dump(mode="json")])
    for answer_id, version_number, version_kind in (
        ("answer-structured", 1, "structured"),
        ("answer-repaired", 2, "targeted_repair"),
    ):
        # A later answer commonly freezes the same stable build/chunk evidence
        # identity. Re-persisting it must never delete the first answer's
        # claim_evidence rows via SQLite REPLACE semantics.
        if version_number == 2:
            database.store_evidence([evidence.model_dump(mode="json")])
        database.store_answer_version(
            answer_id=answer_id,
            job_id="job-repair-claims",
            version_number=version_number,
            version_kind=version_kind,
            encrypted_content=cipher.encrypt_text(version_kind),
            word_count=1,
            policy_version=POLICY_VERSION,
            model_version="test",
            index_build_id=evidence.index_build_id,
        )
        database.store_claims(
            answer_id,
            [
                {
                    "id": "model-claim-unchanged",
                    "section_id": "analysis",
                    "encrypted_text": cipher.encrypt_text("The supported proposition."),
                    "verification_status": "verified",
                    "evidence_ids": [evidence.id],
                }
            ],
        )

    rows = database.fetchall(
        "SELECT id, answer_version_id, model_claim_id FROM claims "
        "WHERE model_claim_id='model-claim-unchanged' ORDER BY answer_version_id"
    )
    assert len(rows) == 2
    assert {row["model_claim_id"] for row in rows} == {"model-claim-unchanged"}
    assert len({row["id"] for row in rows}) == 2
    for row in rows:
        _, links, linked_evidence = database.answer_claims_and_evidence(
            str(row["answer_version_id"])
        )
        assert [(link["claim_id"], link["evidence_id"]) for link in links] == [
            (row["id"], evidence.id)
        ]
        assert [item["id"] for item in linked_evidence] == [evidence.id]


def test_evidence_identity_collision_fails_without_mutating_existing_row(
    database, evidence: EvidenceSpan
) -> None:
    database.store_evidence([evidence.model_dump(mode="json")])
    conflicting = evidence.model_copy(update={"locator": "s 999"})
    with pytest.raises(RuntimeError, match="immutable evidence identity collides"):
        database.store_evidence([conflicting.model_dump(mode="json")])
    stored = database.fetchone("SELECT locator FROM evidence_spans WHERE id=?", (evidence.id,))
    assert stored["locator"] == evidence.locator


def test_legacy_sensitive_plaintext_is_migrated_in_place(database, cipher) -> None:
    _create_job(database, cipher, "job-legacy")
    database.execute(
        "UPDATE jobs SET request_json=?, question_summary='LEGACY SUMMARY' WHERE id='job-legacy'",
        ('{"question":"LEGACY QUESTION","task_type":"general"}',),
    )
    database.store_answer_version(
        answer_id="answer-legacy",
        job_id="job-legacy",
        version_number=1,
        version_kind="structured",
        encrypted_content=cipher.encrypt_text("answer"),
        word_count=1,
        policy_version=POLICY_VERSION,
        model_version="test",
        index_build_id=None,
    )
    database.execute(
        "UPDATE answer_versions SET diff_from_parent='LEGACY DIFF' WHERE id='answer-legacy'"
    )
    database.execute(
        """
        INSERT INTO claims(
          id, answer_version_id, section_id, ordinal, claim_text,
          verification_status
        ) VALUES ('legacy-claim', 'answer-legacy', 's', 0, 'LEGACY CLAIM', 'pending')
        """
    )

    assert database.migrate_sensitive_content(cipher) == {
        "jobs": 2,
        "claims": 1,
        "diffs": 1,
        "gaps": 0,
        "review_notes": 0,
    }
    job = database.job("job-legacy")
    answer = database.answer("answer-legacy")
    claim = database.fetchone("SELECT * FROM claims WHERE id='legacy-claim'")
    assert job is not None and "LEGACY QUESTION" not in job["request_json"]
    assert answer is not None and answer["diff_from_parent"] is None
    assert claim is not None and claim["claim_text"] == ""
    assert cipher.decrypt_text(answer["encrypted_diff_from_parent"]) == "LEGACY DIFF"
    assert cipher.decrypt_text(claim["encrypted_claim_text"]) == "LEGACY CLAIM"


def test_expiry_detaches_surviving_children_before_parent_purge(database, cipher) -> None:
    _create_job(database, cipher, "job-purge")
    database.store_answer_version(
        answer_id="expired-parent",
        job_id="job-purge",
        version_number=1,
        version_kind="raw_model",
        encrypted_content=cipher.encrypt_text("parent"),
        word_count=1,
        policy_version=POLICY_VERSION,
        model_version="test",
        index_build_id=None,
    )
    database.store_answer_version(
        answer_id="released-child",
        job_id="job-purge",
        version_number=2,
        version_kind="structured",
        encrypted_content=cipher.encrypt_text("child"),
        encrypted_diff_from_parent=cipher.encrypt_text("diff"),
        word_count=1,
        release_state="verified_limited",
        parent_version_id="expired-parent",
        policy_version=POLICY_VERSION,
        model_version="test",
        index_build_id=None,
        purge_after_days=None,
    )
    expired = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    database.execute(
        "UPDATE answer_versions SET purge_after=? WHERE id='expired-parent'", (expired,)
    )

    assert database.purge_expired_unreleased_versions() == 0
    assert database.answer("expired-parent") is not None
    current = datetime.now(UTC)
    authorization = DeletionAuthorization(
        authorization_id="synthetic-answer-delete",
        owner_decision_sha256="3" * 64,
        object_class=DeletionObjectClass.ANSWER_VERSION,
        object_ids=("expired-parent",),
        issued_at=current - timedelta(minutes=1),
        expires_at=current + timedelta(minutes=1),
    )
    assert (
        database.purge_expired_unreleased_versions(
            guard=DeletionGuard(),
            authorization=authorization,
        )
        == 1
    )
    assert database.answer("expired-parent") is None
    child = database.answer("released-child")
    assert child is not None and child["parent_version_id"] is None
    assert cipher.decrypt_text(child["encrypted_diff_from_parent"]) == "diff"
