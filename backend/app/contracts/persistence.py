"""Durable encrypted persistence for one verified selected answer chain.

This boundary is deliberately publication-free. It records the exact selected
objects after full integrity verification, but it cannot write release_outbox,
change a job to complete, invoke a model, or grant evaluation/live authority.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..db import Database, utc_iso
from ..orchestration.object_store import EncryptedObjectStore
from .integrity_chain import AnswerIntegrityChainVerifier, IntegrityChainReceipt
from .schema_registry import ContractSchemaRegistry, canonical_json_bytes, seal_contract

_OBJECT_ROLES: tuple[str, ...] = (
    "conversation_snapshot",
    "fact_snapshot",
    "query_plan",
    "retrieval_result",
    "evidence_pack",
    "claim_set",
    "validation_report",
    "verified_release",
    "terminal_event",
    "answer_job",
)


@dataclass(frozen=True, slots=True)
class PersistedAnswerChain:
    job_id: str
    chain_sha256: str
    release_id: str
    release_sha256: str
    answer_id: str
    answer_content_sha256: str
    release_state: str
    terminal_event_id: str
    answer_job_sha256: str
    object_keys: Mapping[str, str]
    status: str = "verified_unpublished"


def _contract_sha256(value: Mapping[str, Any]) -> str:
    supplied = value.get("content_sha256")
    if isinstance(supplied, str):
        return supplied
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class SelectedAnswerContractStore:
    """Persist a complete verified chain with immutable encrypted bindings."""

    def __init__(
        self,
        *,
        database: Database,
        objects: EncryptedObjectStore,
        registry: ContractSchemaRegistry,
    ) -> None:
        self.database = database
        self.objects = objects
        self.registry = registry
        self.verifier = AnswerIntegrityChainVerifier(registry)

    def persist_verified_unpublished(
        self,
        *,
        job_id: str,
        request_id: str,
        request_sha256: str,
        conversation_snapshot: Mapping[str, Any],
        fact_snapshot: Mapping[str, Any],
        query_plan: Mapping[str, Any],
        retrieval_result: Mapping[str, Any],
        evidence_pack: Mapping[str, Any],
        claim_set: Mapping[str, Any],
        validation_report: Mapping[str, Any],
        verified_release: Mapping[str, Any],
        terminal_event: Mapping[str, Any],
        answer_job: Mapping[str, Any],
    ) -> PersistedAnswerChain:
        values: dict[str, Mapping[str, Any]] = {
            "conversation_snapshot": conversation_snapshot,
            "fact_snapshot": fact_snapshot,
            "query_plan": query_plan,
            "retrieval_result": retrieval_result,
            "evidence_pack": evidence_pack,
            "claim_set": claim_set,
            "validation_report": validation_report,
            "verified_release": verified_release,
            "terminal_event": terminal_event,
            "answer_job": answer_job,
        }
        receipt = self.verifier.verify_complete(
            job_id=job_id,
            request_id=request_id,
            request_sha256=request_sha256,
            conversation_snapshot=conversation_snapshot,
            fact_snapshot=fact_snapshot,
            query_plan=query_plan,
            retrieval_result=retrieval_result,
            evidence_pack=evidence_pack,
            claim_set=claim_set,
            validation_report=validation_report,
            verified_release=verified_release,
            terminal_event=terminal_event,
            answer_job=answer_job,
        )
        contract_digests = {role: _contract_sha256(values[role]) for role in _OBJECT_ROLES}
        release_id = str(verified_release["release_id"])
        release_sha256 = contract_digests["verified_release"]
        answer_id = str(verified_release["answer_id"])
        answer_content_sha256 = str(verified_release["answer_content_sha256"])
        release_state = str(verified_release["release_state"])
        answer_job_sha256 = contract_digests["answer_job"]

        existing = self.database.fetchone(
            "SELECT job_id FROM selected_answer_contract_chains WHERE job_id=?", (job_id,)
        )
        if existing is not None:
            return self._require_exact_existing(
                receipt=receipt,
                release_id=release_id,
                release_sha256=release_sha256,
                answer_id=answer_id,
                answer_content_sha256=answer_content_sha256,
                release_state=release_state,
                attempt_id=str(terminal_event["attempt_id"]),
                lease_generation=int(terminal_event["lease_generation"]),
                terminal_sequence=int(terminal_event["sequence"]),
                answer_job_sha256=answer_job_sha256,
                contract_digests=contract_digests,
            )

        job = self.database.fetchone("SELECT id,cancel_requested FROM jobs WHERE id=?", (job_id,))
        if job is None:
            raise RuntimeError("selected answer chain job is missing")
        if bool(job["cancel_requested"]):
            raise RuntimeError("cancelled job cannot persist a selected answer chain")

        object_keys: dict[str, str] = {}
        for role in _OBJECT_ROLES:
            value = values[role]
            object_keys[role] = self.objects.put_json(
                namespace=f"selected_contract_{role}",
                value=value,
                metadata={
                    "job_id": job_id,
                    "role": role,
                    "schema": str(value["schema"]),
                    "contract_sha256": contract_digests[role],
                },
                ttl_days=None,
            )

        created_at = utc_iso()
        with self.database.transaction() as conn:
            job = conn.execute(
                "SELECT id,cancel_requested FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if job is None:
                raise RuntimeError("selected answer chain job is missing")
            if bool(job["cancel_requested"]):
                raise RuntimeError("cancelled job cannot persist a selected answer chain")
            raced = conn.execute(
                "SELECT * FROM selected_answer_contract_chains WHERE job_id=?", (job_id,)
            ).fetchone()
            if raced is not None:
                raise RuntimeError("selected answer chain raced with another writer")
            conn.execute(
                """
                INSERT INTO selected_answer_contract_chains(
                  job_id,request_id,terminal_event_id,chain_sha256,
                  schema_selection_sha256,release_sha256,answer_job_sha256,
                  object_count,status,created_at
                ) VALUES (?,?,?,?,?,?,?,?, 'verified_unpublished', ?)
                """,
                (
                    job_id,
                    request_id,
                    receipt.terminal_event_id,
                    receipt.chain_sha256,
                    receipt.schema_selection_sha256,
                    release_sha256,
                    answer_job_sha256,
                    len(_OBJECT_ROLES),
                    created_at,
                ),
            )
            conn.execute(
                """
                INSERT INTO selected_answer_release_bindings(
                  job_id,release_id,release_sha256,answer_id,answer_content_sha256,
                  release_state,attempt_id,lease_generation,terminal_sequence,
                  terminal_event_id,created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    job_id,
                    release_id,
                    release_sha256,
                    answer_id,
                    answer_content_sha256,
                    release_state,
                    str(terminal_event["attempt_id"]),
                    int(terminal_event["lease_generation"]),
                    int(terminal_event["sequence"]),
                    receipt.terminal_event_id,
                    created_at,
                ),
            )
            for ordinal, role in enumerate(_OBJECT_ROLES, start=1):
                conn.execute(
                    """
                    INSERT INTO selected_answer_contract_objects(
                      job_id,ordinal,role,schema_name,contract_sha256,object_key,created_at
                    ) VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        job_id,
                        ordinal,
                        role,
                        str(values[role]["schema"]),
                        contract_digests[role],
                        object_keys[role],
                        created_at,
                    ),
                )
        return PersistedAnswerChain(
            job_id=job_id,
            chain_sha256=receipt.chain_sha256,
            release_id=release_id,
            release_sha256=release_sha256,
            answer_id=answer_id,
            answer_content_sha256=answer_content_sha256,
            release_state=release_state,
            terminal_event_id=receipt.terminal_event_id,
            answer_job_sha256=answer_job_sha256,
            object_keys=object_keys,
        )

    def load_verified_unpublished(self, job_id: str) -> PersistedAnswerChain:
        """Reopen every encrypted object and replay the complete integrity proof."""

        chain = self.database.fetchone(
            """
            SELECT c.*,b.release_id,b.answer_id,b.answer_content_sha256,b.release_state,
                   b.attempt_id,b.lease_generation,b.terminal_sequence,
                   b.terminal_event_id AS bound_terminal_event_id,
                   b.release_sha256 AS bound_release_sha256
            FROM selected_answer_contract_chains c
            JOIN selected_answer_release_bindings b ON b.job_id=c.job_id
            WHERE c.job_id=?
            """,
            (job_id,),
        )
        rows = self.database.fetchall(
            "SELECT * FROM selected_answer_contract_objects WHERE job_id=? ORDER BY ordinal",
            (job_id,),
        )
        if chain is None or len(rows) != len(_OBJECT_ROLES):
            raise RuntimeError("persisted selected answer chain is incomplete")
        values: dict[str, Mapping[str, Any]] = {}
        for ordinal, role in enumerate(_OBJECT_ROLES, start=1):
            row = rows[ordinal - 1]
            if int(row["ordinal"]) != ordinal or str(row["role"]) != role:
                raise RuntimeError("persisted selected answer contract order differs")
            value = self.objects.get_json(str(row["object_key"]))
            self.registry.validate_new(value)
            if str(value["schema"]) != str(row["schema_name"]) or _contract_sha256(value) != str(
                row["contract_sha256"]
            ):
                raise RuntimeError("persisted selected answer contract content differs")
            values[role] = value
        query_plan = values["query_plan"]
        receipt = self.verifier.verify_complete(
            job_id=job_id,
            request_id=str(chain["request_id"]),
            request_sha256=str(query_plan["request_sha256"]),
            conversation_snapshot=values["conversation_snapshot"],
            fact_snapshot=values["fact_snapshot"],
            query_plan=query_plan,
            retrieval_result=values["retrieval_result"],
            evidence_pack=values["evidence_pack"],
            claim_set=values["claim_set"],
            validation_report=values["validation_report"],
            verified_release=values["verified_release"],
            terminal_event=values["terminal_event"],
            answer_job=values["answer_job"],
        )
        return self._require_exact_existing(
            receipt=receipt,
            release_id=str(values["verified_release"]["release_id"]),
            release_sha256=_contract_sha256(values["verified_release"]),
            answer_id=str(values["verified_release"]["answer_id"]),
            answer_content_sha256=str(values["verified_release"]["answer_content_sha256"]),
            release_state=str(values["verified_release"]["release_state"]),
            attempt_id=str(values["terminal_event"]["attempt_id"]),
            lease_generation=int(values["terminal_event"]["lease_generation"]),
            terminal_sequence=int(values["terminal_event"]["sequence"]),
            answer_job_sha256=_contract_sha256(values["answer_job"]),
            contract_digests={role: _contract_sha256(values[role]) for role in _OBJECT_ROLES},
        )

    def load_publication_proof(self, job_id: str) -> dict[str, Any]:
        """Replay the chain and bind it to the actual encrypted answer bytes.

        The returned proof is publication-free.  It can be supplied to the
        database's atomic release boundary, which rechecks the immutable rows
        in the same transaction as the outbox write.  Decryption and complete
        object replay happen here, before SQLite is write-locked.
        """

        persisted = self.load_verified_unpublished(job_id)
        chain = self.database.fetchone(
            """
            SELECT c.request_id,c.chain_sha256,c.schema_selection_sha256,
                   c.answer_job_sha256,c.object_count,c.status,
                   b.release_id,b.release_sha256,b.answer_id,
                   b.answer_content_sha256,b.release_state,b.attempt_id,
                   b.lease_generation,b.terminal_sequence,b.terminal_event_id
            FROM selected_answer_contract_chains c
            JOIN selected_answer_release_bindings b ON b.job_id=c.job_id
            WHERE c.job_id=?
            """,
            (job_id,),
        )
        release_row = self.database.fetchone(
            """
            SELECT object_key FROM selected_answer_contract_objects
            WHERE job_id=? AND role='verified_release'
            """,
            (job_id,),
        )
        answer = self.database.answer(persisted.answer_id)
        if chain is None or release_row is None or answer is None:
            raise RuntimeError("selected answer publication proof is incomplete")
        release = self.objects.get_json(str(release_row["object_key"]))
        self.registry.validate_new(release)
        if (
            release.get("content_sha256") != persisted.release_sha256
            or release.get("job_id") != job_id
            or release.get("answer_id") != persisted.answer_id
            or release.get("release_state") != persisted.release_state
            or release.get("terminal_event_id") != persisted.terminal_event_id
            or str(answer["job_id"]) != job_id
            or answer["release_state"] not in (None, "", persisted.release_state)
        ):
            raise RuntimeError("selected answer publication identity differs")
        answer_text = self.objects.cipher.decrypt_text(bytes(answer["encrypted_content"]))
        actual_answer_sha256 = hashlib.sha256(answer_text.encode("utf-8")).hexdigest()
        if actual_answer_sha256 != persisted.answer_content_sha256:
            raise RuntimeError("selected answer publication content differs")
        proof = seal_contract(
            {
                "schema": "legalbot.selected-answer-publication-proof.v1",
                "job_id": job_id,
                "request_id": str(chain["request_id"]),
                "chain_sha256": persisted.chain_sha256,
                "schema_selection_sha256": str(chain["schema_selection_sha256"]),
                "object_count": int(chain["object_count"]),
                "chain_status": str(chain["status"]),
                "release_id": persisted.release_id,
                "release_sha256": persisted.release_sha256,
                "outbox_id": str(release["outbox_id"]),
                "answer_id": persisted.answer_id,
                "answer_content_sha256": actual_answer_sha256,
                "release_state": persisted.release_state,
                "terminal_event_id": persisted.terminal_event_id,
                "answer_job_sha256": persisted.answer_job_sha256,
                "attempt_id": str(chain["attempt_id"]),
                "lease_generation": int(chain["lease_generation"]),
                "terminal_sequence": int(chain["terminal_sequence"]),
            }
        )
        return proof

    def _require_exact_existing(
        self,
        *,
        receipt: IntegrityChainReceipt,
        release_id: str,
        release_sha256: str,
        answer_id: str,
        answer_content_sha256: str,
        release_state: str,
        attempt_id: str,
        lease_generation: int,
        terminal_sequence: int,
        answer_job_sha256: str,
        contract_digests: Mapping[str, str],
    ) -> PersistedAnswerChain:
        chain = self.database.fetchone(
            """
            SELECT c.*,b.release_id,b.answer_id,b.answer_content_sha256,b.release_state,
                   b.attempt_id,b.lease_generation,b.terminal_sequence,
                   b.terminal_event_id AS bound_terminal_event_id,
                   b.release_sha256 AS bound_release_sha256
            FROM selected_answer_contract_chains c
            JOIN selected_answer_release_bindings b ON b.job_id=c.job_id
            WHERE c.job_id=?
            """,
            (receipt.job_id,),
        )
        rows = self.database.fetchall(
            "SELECT * FROM selected_answer_contract_objects WHERE job_id=? ORDER BY ordinal",
            (receipt.job_id,),
        )
        if (
            chain is None
            or str(chain["chain_sha256"]) != receipt.chain_sha256
            or str(chain["terminal_event_id"]) != receipt.terminal_event_id
            or str(chain["schema_selection_sha256"]) != receipt.schema_selection_sha256
            or str(chain["release_id"]) != release_id
            or str(chain["release_sha256"]) != release_sha256
            or str(chain["bound_release_sha256"]) != release_sha256
            or str(chain["answer_id"]) != answer_id
            or str(chain["answer_content_sha256"]) != answer_content_sha256
            or str(chain["release_state"]) != release_state
            or str(chain["attempt_id"]) != attempt_id
            or int(chain["lease_generation"]) != lease_generation
            or int(chain["terminal_sequence"]) != terminal_sequence
            or str(chain["bound_terminal_event_id"]) != receipt.terminal_event_id
            or str(chain["answer_job_sha256"]) != answer_job_sha256
            or str(chain["status"]) != "verified_unpublished"
            or int(chain["object_count"]) != len(_OBJECT_ROLES)
            or len(rows) != len(_OBJECT_ROLES)
        ):
            raise RuntimeError("persisted selected answer chain differs")
        object_keys: dict[str, str] = {}
        for ordinal, role in enumerate(_OBJECT_ROLES, start=1):
            row = rows[ordinal - 1]
            if (
                int(row["ordinal"]) != ordinal
                or str(row["role"]) != role
                or str(row["contract_sha256"]) != contract_digests[role]
            ):
                raise RuntimeError("persisted selected answer contract binding differs")
            object_key = str(row["object_key"])
            persisted = self.objects.get_json(object_key)
            self.registry.validate_new(persisted)
            if _contract_sha256(persisted) != contract_digests[role]:
                raise RuntimeError("persisted selected answer contract content differs")
            object_keys[role] = object_key
        return PersistedAnswerChain(
            job_id=receipt.job_id,
            chain_sha256=receipt.chain_sha256,
            release_id=release_id,
            release_sha256=release_sha256,
            answer_id=answer_id,
            answer_content_sha256=answer_content_sha256,
            release_state=release_state,
            terminal_event_id=receipt.terminal_event_id,
            answer_job_sha256=answer_job_sha256,
            object_keys=object_keys,
        )


__all__ = ["PersistedAnswerChain", "SelectedAnswerContractStore"]
