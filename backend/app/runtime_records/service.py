"""Owner runtime records: feedback, incidents, regressions and curation.

SQLite is source of truth. Encrypted objects hold sensitive text. Evaluation
artifacts cannot be curated as training data.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..crypto import LocalCipher
from ..db import Database
from .schema import (
    CURATION_STATES,
    FEEDBACK_KINDS,
    LIVE_EVALUATION_SOURCE_KINDS,
)

CURATION_TRANSITIONS = {
    "quarantine": "rights",
    "rights": "privacy",
    "privacy": "legal",
    "legal": "quality",
    "quality": "owner_approved",
    "owner_approved": "sealed_export",
}


def _utc() -> str:
    return datetime.now(UTC).isoformat()


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _write_encrypted_object(
    *,
    object_dir: Path,
    cipher: LocalCipher,
    kind: str,
    text: str,
) -> str:
    object_dir.mkdir(parents=True, exist_ok=True)
    object_id = f"{kind}-{uuid4().hex}"
    path = object_dir / f"{object_id}.enc"
    path.write_bytes(cipher.encrypt_text(text))
    path.chmod(0o600)
    return object_id


class RuntimeRecordService:
    def __init__(
        self,
        database: Database,
        cipher: LocalCipher,
        *,
        object_dir: Path,
    ) -> None:
        self.database = database
        self.cipher = cipher
        self.object_dir = object_dir

    def record_feedback(
        self,
        *,
        kind: str,
        class_code: str,
        note: str | None = None,
        answer_id: str | None = None,
    ) -> dict[str, Any]:
        if kind not in FEEDBACK_KINDS:
            raise ValueError("feedback kind is not recognised")
        object_id = None
        if note:
            object_id = _write_encrypted_object(
                object_dir=self.object_dir,
                cipher=self.cipher,
                kind="feedback",
                text=note,
            )
        feedback_id = f"feedback-{uuid4().hex}"
        fingerprint = _fingerprint(kind, class_code, answer_id or "")
        self.database.execute(
            """
            INSERT INTO runtime_feedback(
              id, kind, answer_id, class_code, fingerprint, encrypted_object_id,
              eligible_for_training, training_export_allowed, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)
            """,
            (
                feedback_id,
                kind,
                answer_id,
                class_code,
                fingerprint,
                object_id,
                _utc(),
            ),
        )
        self.database._connection.commit()
        return {
            "id": feedback_id,
            "kind": kind,
            "class_code": class_code,
            "fingerprint": fingerprint,
            "eligible_for_training": False,
            "training_export_allowed": False,
            "has_encrypted_note": object_id is not None,
        }

    def record_incident(
        self,
        *,
        class_code: str,
        crash_bundle: str | None = None,
    ) -> dict[str, Any]:
        object_id = None
        if crash_bundle:
            object_id = _write_encrypted_object(
                object_dir=self.object_dir,
                cipher=self.cipher,
                kind="incident",
                text=crash_bundle,
            )
        incident_id = f"incident-{uuid4().hex}"
        fingerprint = _fingerprint("incident", class_code)
        self.database.execute(
            """
            INSERT INTO runtime_incidents(
              id, class_code, fingerprint, encrypted_bundle_id, status, created_at
            ) VALUES (?, ?, ?, ?, 'open', ?)
            """,
            (incident_id, class_code, fingerprint, object_id, _utc()),
        )
        self.database._connection.commit()
        return {
            "id": incident_id,
            "class_code": class_code,
            "fingerprint": fingerprint,
            "status": "open",
            "has_encrypted_bundle": object_id is not None,
        }

    def close_incident(
        self,
        incident_id: str,
        *,
        regression_case_id: str | None = None,
        accepted_risk: bool = False,
    ) -> dict[str, Any]:
        row = self.database.fetchone("SELECT * FROM runtime_incidents WHERE id=?", (incident_id,))
        if row is None:
            raise KeyError(incident_id)
        if not accepted_risk and not regression_case_id:
            raise ValueError("closing a fixable incident requires a regression or accepted risk")
        regression_id = None
        if regression_case_id or accepted_risk:
            regression_id = f"regression-{uuid4().hex}"
            self.database.execute(
                """
                INSERT INTO runtime_regressions(
                  id, incident_id, case_id, accepted_risk, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    regression_id,
                    incident_id,
                    regression_case_id,
                    int(accepted_risk),
                    _utc(),
                ),
            )
        self.database.execute(
            "UPDATE runtime_incidents SET status='closed', closed_at=? WHERE id=?",
            (_utc(), incident_id),
        )
        self.database._connection.commit()
        return {
            "incident_id": incident_id,
            "status": "closed",
            "regression_id": regression_id,
            "accepted_risk": accepted_risk,
        }

    def start_curation(self, *, source_kind: str) -> dict[str, Any]:
        if source_kind in LIVE_EVALUATION_SOURCE_KINDS:
            raise ValueError("Live30/Live60 evaluation artifacts cannot enter curation")
        curation_id = f"curation-{uuid4().hex}"
        now = _utc()
        self.database.execute(
            """
            INSERT INTO runtime_curation(
              id, state, source_kind, live_evaluation_contaminated,
              encrypted_object_id, created_at, updated_at
            ) VALUES (?, 'quarantine', ?, 0, NULL, ?, ?)
            """,
            (curation_id, source_kind, now, now),
        )
        self.database._connection.commit()
        return {"id": curation_id, "state": "quarantine", "source_kind": source_kind}

    def advance_curation(self, curation_id: str) -> dict[str, Any]:
        row = self.database.fetchone("SELECT * FROM runtime_curation WHERE id=?", (curation_id,))
        if row is None:
            raise KeyError(curation_id)
        current = str(row["state"])
        nxt = CURATION_TRANSITIONS.get(current)
        if nxt is None:
            raise ValueError("curation record is already sealed")
        self.database.execute(
            "UPDATE runtime_curation SET state=?, updated_at=? WHERE id=?",
            (nxt, _utc(), curation_id),
        )
        self.database._connection.commit()
        return {"id": curation_id, "state": nxt}

    def status_snapshot(self) -> dict[str, Any]:
        def count(sql: str) -> int:
            row = self.database.fetchone(sql)
            return int(row[0]) if row is not None else 0

        curation_counts = {
            state: int(
                (
                    self.database.fetchone(
                        "SELECT COUNT(*) FROM runtime_curation WHERE state=?",
                        (state,),
                    )
                    or [0]
                )[0]
            )
            for state in CURATION_STATES
        }
        return {
            "schema": "legalbot.runtime-records-status.v1",
            "feedback_count": count("SELECT COUNT(*) FROM runtime_feedback"),
            "open_incident_count": count(
                "SELECT COUNT(*) FROM runtime_incidents WHERE status='open'"
            ),
            "regression_count": count("SELECT COUNT(*) FROM runtime_regressions"),
            "curation_counts": curation_counts,
            "eligible_for_training": False,
            "training_export_allowed": False,
        }
