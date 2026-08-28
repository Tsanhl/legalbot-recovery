"""Authority/proposition-scoped answer guard for reviewed official updates."""

from __future__ import annotations

from dataclasses import dataclass

from ..db import Database
from ..retrieval.source_manifest import authority_identity_id
from ..types import EvidenceSpan


@dataclass(frozen=True, slots=True)
class MaterialUpdateAssessment:
    blocked_observation_ids: tuple[str, ...] = ()
    pending_alert_ids: tuple[str, ...] = ()
    resolved_observation_ids: tuple[str, ...] = ()

    @property
    def qualified(self) -> bool:
        return not self.blocked_observation_ids


class MaterialUpdateGate:
    """Apply expert materiality decisions without trusting raw byte changes.

    Pending crawler observations are alerts only.  A current, expert-reviewed
    ``material`` or ``unknown`` observation blocks the affected authority or
    proposition until an append-only resolution is bound to the exact build
    serving the evidence.  Rollback to an older build therefore reactivates the
    block automatically.
    """

    def __init__(self, database: Database) -> None:
        self.database = database

    def assess(
        self,
        span: EvidenceSpan,
        *,
        proposition_hash: str | None = None,
        enforce_promoted_resolution: bool = True,
    ) -> MaterialUpdateAssessment:
        if not enforce_promoted_resolution:
            return MaterialUpdateAssessment()
        source = self.database.fetchone(
            """
            SELECT sv.authority_identity_id, sv.stable_identifier
            FROM source_versions sv WHERE sv.id=?
            """,
            (span.source_version_id,),
        )
        if source is None:
            # An EvidenceSpan detached from its reviewed catalogue identity is
            # already rejected by the ordinary evidence identity gate.
            return MaterialUpdateAssessment()
        identities = {
            str(source["authority_identity_id"] or ""),
            str(source["stable_identifier"] or ""),
        }
        stable_identifier = str(source["stable_identifier"] or "")
        if stable_identifier:
            identities.add(authority_identity_id(stable_identifier))
        identities.discard("")
        if not identities:
            return MaterialUpdateAssessment()
        placeholders = ",".join("?" for _ in identities)
        observations = self.database.fetchall(
            f"""
            SELECT id, comparison_state, stale_active, scope_kind, legal_locator,
              proposition_sha256, materiality_status, review_status
            FROM source_update_observations
            WHERE authority_identity_id IN ({placeholders})
              AND comparison_state IN ('changed','withdrawn','unknown')
            ORDER BY created_at DESC, id DESC
            """,
            tuple(sorted(identities)),
        )
        blocked: list[str] = []
        pending: list[str] = []
        resolved: list[str] = []
        for observation in observations:
            observation_id = str(observation["id"])
            if not _scope_matches(
                observation,
                locator=span.locator,
                proposition_hash=proposition_hash,
            ):
                continue
            if bool(observation["stale_active"]) or str(observation["review_status"]) == "pending":
                pending.append(observation_id)
                continue
            if str(observation["review_status"]) != "approved" or str(
                observation["materiality_status"]
            ) not in {"material", "unknown"}:
                continue
            resolution = self.database.fetchone(
                """
                SELECT id FROM source_update_resolution_events
                WHERE observation_id=? AND resolved_by_build_id=?
                """,
                (observation_id, span.index_build_id),
            )
            if resolution is None:
                blocked.append(observation_id)
            else:
                resolved.append(observation_id)
        return MaterialUpdateAssessment(
            blocked_observation_ids=tuple(dict.fromkeys(blocked)),
            pending_alert_ids=tuple(dict.fromkeys(pending)),
            resolved_observation_ids=tuple(dict.fromkeys(resolved)),
        )


def _scope_matches(
    observation: object,
    *,
    locator: str,
    proposition_hash: str | None,
) -> bool:
    row = observation
    scope_kind = str(row["scope_kind"] or "authority")  # type: ignore[index]
    if scope_kind == "authority":
        return True
    if _normalise_locator(locator) != _normalise_locator(
        str(row["legal_locator"] or "")  # type: ignore[index]
    ):
        return False
    expected_hash = str(row["proposition_sha256"] or "")  # type: ignore[index]
    # Retrieval does not yet have a generated claim hash.  In that uncertain
    # phase the exact locator is excluded fail-closed; final claim verification
    # narrows the decision to the exact proposition hash.
    return proposition_hash is None or proposition_hash == expected_hash


def _normalise_locator(value: str) -> str:
    return " ".join(value.casefold().split())
