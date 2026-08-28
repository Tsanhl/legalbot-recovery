"""SQLite schema for runtime feedback, incidents, regressions and curation.

These tables live in the catalogue. Sensitive text is stored as encrypted
objects, not plaintext columns. Evaluation artifacts are ineligible for training.
"""

from __future__ import annotations

RUNTIME_RECORDS_SCHEMA = """
CREATE TABLE IF NOT EXISTS runtime_feedback (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  answer_id TEXT,
  class_code TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  encrypted_object_id TEXT,
  eligible_for_training INTEGER NOT NULL DEFAULT 0,
  training_export_allowed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runtime_feedback_kind
  ON runtime_feedback(kind, created_at DESC);

CREATE TABLE IF NOT EXISTS runtime_incidents (
  id TEXT PRIMARY KEY,
  class_code TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  encrypted_bundle_id TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  closed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_runtime_incidents_status
  ON runtime_incidents(status, created_at DESC);

CREATE TABLE IF NOT EXISTS runtime_regressions (
  id TEXT PRIMARY KEY,
  incident_id TEXT REFERENCES runtime_incidents(id),
  case_id TEXT,
  accepted_risk INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_curation (
  id TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  live_evaluation_contaminated INTEGER NOT NULL DEFAULT 0,
  encrypted_object_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runtime_curation_state
  ON runtime_curation(state, updated_at DESC);
"""

FEEDBACK_KINDS = frozenset({"wrong_answer", "missing_authority", "citation_error", "other"})
CURATION_STATES = (
    "quarantine",
    "rights",
    "privacy",
    "legal",
    "quality",
    "owner_approved",
    "sealed_export",
)
LIVE_EVALUATION_SOURCE_KINDS = frozenset({"live30", "live60", "evaluation_artifact"})
