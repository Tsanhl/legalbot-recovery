"""Immutable encrypted persistence for selected visible-GE evaluation contracts."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..contracts import ContractSchemaRegistry, canonical_json_bytes
from ..db import Database, utc_iso
from ..orchestration.object_store import EncryptedObjectStore
from .ge_visible_harness import (
    VISIBLE_CASE_COUNT,
    VisibleGEPack,
    VisibleGERunBindings,
    build_completed_visible_ge_run,
)


@dataclass(frozen=True, slots=True)
class PersistedVisibleGERun:
    run_id: str
    run_sha256: str
    case_result_manifest_sha256: str
    run_object_key: str
    case_object_keys: tuple[str, ...]
    status: str


class SelectedEvaluationRunStore:
    """Persist a fully reconciled visible run without granting run authority."""

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

    def persist_completed_visible_ge(
        self,
        *,
        pack: VisibleGEPack,
        evaluation_run: Mapping[str, Any],
        case_results: Sequence[Mapping[str, Any]],
    ) -> PersistedVisibleGERun:
        self.registry.validate_new(evaluation_run)
        run_id = str(evaluation_run["run_id"])
        bindings = VisibleGERunBindings(
            authorization_sha256=str(evaluation_run["authorization_sha256"]),
            candidate_sha256=str(evaluation_run["candidate_sha256"]),
            runtime_config_sha256=str(evaluation_run["runtime_config_sha256"]),
            gold_currentness_decision_sha256=str(
                evaluation_run["gold_currentness_decision_sha256"]
            ),
            private_root_capability_sha256=str(evaluation_run["private_root_capability_sha256"]),
            exposure_ledger_sha256=str(evaluation_run["exposure_ledger_sha256"]),
            model_sha256=str(evaluation_run["model_sha256"]),
            prompt_sha256=str(evaluation_run["prompt_sha256"]),
            renderer_sha256=str(evaluation_run["renderer_sha256"]),
            validator_bundle_sha256=str(evaluation_run["validator_bundle_sha256"]),
            resource_policy_sha256=str(evaluation_run["resource_policy_sha256"]),
        )
        expected = build_completed_visible_ge_run(
            registry=self.registry,
            pack=pack,
            run_id=run_id,
            case_results=case_results,
            bindings=bindings,
            started_at=datetime.fromisoformat(str(evaluation_run["started_at"])),
            completed_at=datetime.fromisoformat(str(evaluation_run["completed_at"])),
        )
        if canonical_json_bytes(expected) != canonical_json_bytes(evaluation_run):
            raise RuntimeError("selected evaluation run differs from reconciled results")
        run_sha256 = hashlib.sha256(canonical_json_bytes(evaluation_run)).hexdigest()
        existing = self.database.fetchone(
            "SELECT run_id, run_sha256 FROM selected_evaluation_run_contracts WHERE run_id=?",
            (run_id,),
        )
        if existing is not None:
            if str(existing["run_sha256"]) != run_sha256:
                raise RuntimeError("selected evaluation run identity has a different digest")
            persisted = self.load_completed_visible_ge(run_id)
            if persisted.run_sha256 != run_sha256:
                raise RuntimeError("selected evaluation run replay digest differs")
            return persisted

        run_object_key = self.objects.put_json(
            namespace="selected_evaluation_run",
            value=evaluation_run,
            metadata={
                "run_id": run_id,
                "schema": str(evaluation_run["schema"]),
                "run_sha256": run_sha256,
            },
            ttl_days=None,
        )
        case_object_keys: list[str] = []
        for result in case_results:
            result_sha256 = str(result["content_sha256"])
            case_object_keys.append(
                self.objects.put_json(
                    namespace="selected_evaluation_case_result",
                    value=result,
                    metadata={
                        "run_id": run_id,
                        "case_id": str(result["case_id"]),
                        "ordinal": int(result["ordinal"]),
                        "result_sha256": result_sha256,
                    },
                    ttl_days=None,
                )
            )
        created_at = utc_iso()
        status = (
            "completed_valid" if evaluation_run["run_validity"] == "PASS" else "completed_invalid"
        )
        with self.database.transaction() as conn:
            raced = conn.execute(
                "SELECT run_id FROM selected_evaluation_run_contracts WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if raced is not None:
                raise RuntimeError("selected evaluation run raced with another writer")
            conn.execute(
                """
                INSERT INTO selected_evaluation_run_contracts(
                  run_id,run_sha256,lane,case_count,case_result_manifest_sha256,
                  run_validity,run_object_key,status,created_at
                ) VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    run_id,
                    run_sha256,
                    str(evaluation_run["lane"]),
                    int(evaluation_run["case_count"]),
                    str(evaluation_run["case_result_manifest_sha256"]),
                    str(evaluation_run["run_validity"]),
                    run_object_key,
                    status,
                    created_at,
                ),
            )
            for result, object_key in zip(case_results, case_object_keys, strict=True):
                conn.execute(
                    """
                    INSERT INTO selected_evaluation_case_contracts(
                      run_id,ordinal,case_id,case_version_sha256,result_id,
                      result_sha256,terminal_state,object_key,created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        run_id,
                        int(result["ordinal"]),
                        str(result["case_id"]),
                        str(result["case_version_sha256"]),
                        str(result["result_id"]),
                        str(result["content_sha256"]),
                        str(result["terminal_state"]),
                        object_key,
                        created_at,
                    ),
                )
        return PersistedVisibleGERun(
            run_id=run_id,
            run_sha256=run_sha256,
            case_result_manifest_sha256=str(evaluation_run["case_result_manifest_sha256"]),
            run_object_key=run_object_key,
            case_object_keys=tuple(case_object_keys),
            status=status,
        )

    def load_completed_visible_ge(self, run_id: str) -> PersistedVisibleGERun:
        row = self.database.fetchone(
            "SELECT * FROM selected_evaluation_run_contracts WHERE run_id=?", (run_id,)
        )
        cases = self.database.fetchall(
            "SELECT * FROM selected_evaluation_case_contracts WHERE run_id=? ORDER BY ordinal",
            (run_id,),
        )
        if row is None or len(cases) != VISIBLE_CASE_COUNT:
            raise RuntimeError("persisted selected evaluation run is incomplete")
        run = self.objects.get_json(str(row["run_object_key"]))
        self.registry.validate_new(run)
        run_sha256 = hashlib.sha256(canonical_json_bytes(run)).hexdigest()
        if (
            run_sha256 != str(row["run_sha256"])
            or run["run_id"] != run_id
            or run["case_result_manifest_sha256"] != row["case_result_manifest_sha256"]
            or int(run["case_result_count"]) != VISIBLE_CASE_COUNT
            or int(run["case_count"]) != VISIBLE_CASE_COUNT
            or run["run_validity"] != row["run_validity"]
        ):
            raise RuntimeError("persisted selected evaluation run binding differs")
        result_manifest: list[dict[str, Any]] = []
        object_keys: list[str] = []
        for ordinal, case_row in enumerate(cases, start=1):
            if int(case_row["ordinal"]) != ordinal:
                raise RuntimeError("persisted selected evaluation case order differs")
            object_key = str(case_row["object_key"])
            result = self.objects.get_json(object_key)
            self.registry.validate_new(result)
            if (
                result["run_id"] != run_id
                or int(result["ordinal"]) != ordinal
                or result["case_id"] != case_row["case_id"]
                or result["case_version_sha256"] != case_row["case_version_sha256"]
                or result["result_id"] != case_row["result_id"]
                or result["content_sha256"] != case_row["result_sha256"]
                or result["terminal_state"] != case_row["terminal_state"]
            ):
                raise RuntimeError("persisted selected evaluation case binding differs")
            result_manifest.append(
                {
                    "ordinal": ordinal,
                    "case_id": result["case_id"],
                    "result_id": result["result_id"],
                    "content_sha256": result["content_sha256"],
                    "terminal_state": result["terminal_state"],
                }
            )
            object_keys.append(object_key)
        manifest_sha256 = hashlib.sha256(canonical_json_bytes(result_manifest)).hexdigest()
        if manifest_sha256 != row["case_result_manifest_sha256"]:
            raise RuntimeError("persisted selected evaluation result manifest differs")
        return PersistedVisibleGERun(
            run_id=run_id,
            run_sha256=run_sha256,
            case_result_manifest_sha256=manifest_sha256,
            run_object_key=str(row["run_object_key"]),
            case_object_keys=tuple(object_keys),
            status=str(row["status"]),
        )


__all__ = ["PersistedVisibleGERun", "SelectedEvaluationRunStore"]
