"""Failure ledger states and catalogue rows.

Ledger rows live in catalog.sqlite3 (jobs already live there) and are also
exported to gitignored logs/failure-ledger.jsonl.
"""

from __future__ import annotations

from enum import StrEnum

LEDGER_SCHEMA = "legalbot.failure-ledger.v1"


class LedgerState(StrEnum):
    OPEN = "open"
    RETRYING = "retrying"
    RECOVERED = "recovered"
    TERMINAL = "terminal"
    WAIVED = "waived"


LEDGER_STATES = tuple(item.value for item in LedgerState)

OPEN_LEDGER_STATES = frozenset({LedgerState.OPEN.value, LedgerState.RETRYING.value})


class LedgerError(ValueError):
    """Invalid ledger transition or missing owner reason."""


CREATE_LEDGER_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS failure_ledger (
  failure_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  state TEXT NOT NULL,
  component TEXT NOT NULL,
  stage TEXT,
  failure_code TEXT,
  source_id TEXT,
  job_id TEXT,
  build_id TEXT,
  retryable INTEGER NOT NULL DEFAULT 0,
  blocking INTEGER NOT NULL DEFAULT 0,
  owner_reason TEXT,
  parent_failure_id TEXT,
  first_event_id TEXT,
  last_event_id TEXT,
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  closed_at TEXT,
  waived_reason TEXT,
  provenance_json TEXT NOT NULL DEFAULT '{}',
  user_or_owner_safe TEXT NOT NULL,
  internal_detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_failure_ledger_fingerprint
  ON failure_ledger(fingerprint, state);
CREATE INDEX IF NOT EXISTS idx_failure_ledger_state
  ON failure_ledger(state, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_failure_ledger_job
  ON failure_ledger(job_id, state);
"""


def assert_waive_reason(owner_reason: str | None) -> str:
    reason = " ".join((owner_reason or "").split())
    if not reason:
        raise LedgerError("waived ledger rows require an owner reason")
    return reason
