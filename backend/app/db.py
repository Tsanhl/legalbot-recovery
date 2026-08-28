from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlparse

from .citations.oscola import CitationMetadataError, render_oscola
from .privacy import PRIVATE_QUESTION_SUMMARY, scrub_pii
from .source_diagnostics import EXCLUSION_STATUSES, validate_exclusion_reason

if TYPE_CHECKING:
    from .crypto import LocalCipher
    from .orchestration.retry_policy import RetryDecision

SCHEMA_VERSION = 25
PUBLIC_RELEASE_STATES = ("verified_full", "verified_concise", "verified_limited")
_SQLITE_CONNECTION_IDENTITY_LOCK = threading.Lock()


class JobQueueCapacityError(RuntimeError):
    """Atomic job admission would exceed a bounded local queue."""


_RELEASE_OUTBOX_TRIGGER_SQL = {
    "trg_release_outbox_binding_no_replace": """
        CREATE TRIGGER trg_release_outbox_binding_no_replace
        BEFORE INSERT ON release_outbox
        WHEN EXISTS (
          SELECT 1 FROM release_outbox existing
          WHERE existing.id=NEW.id
             OR existing.job_id=NEW.job_id
             OR existing.answer_id=NEW.answer_id
             OR existing.idempotency_key=NEW.idempotency_key
        )
        BEGIN
          SELECT RAISE(ABORT, 'bound release outbox identity cannot be replaced');
        END
    """,
    "trg_release_outbox_content_binding_immutable": """
        CREATE TRIGGER trg_release_outbox_content_binding_immutable
        BEFORE UPDATE OF owner_canary_content_graph_sha256,answer_sha256
        ON release_outbox
        WHEN OLD.owner_canary_content_graph_sha256
               IS NOT NEW.owner_canary_content_graph_sha256
          OR OLD.answer_sha256 IS NOT NEW.answer_sha256
        BEGIN
          SELECT RAISE(ABORT, 'release outbox content binding is immutable');
        END
    """,
    "trg_release_outbox_owner_binding_no_update": """
        CREATE TRIGGER trg_release_outbox_owner_binding_no_update
        BEFORE UPDATE ON release_outbox
        WHEN OLD.owner_canary_content_graph_sha256 IS NOT NULL
          OR OLD.answer_sha256 IS NOT NULL
        BEGIN
          SELECT RAISE(ABORT, 'bound owner release outbox is immutable');
        END
    """,
    "trg_release_outbox_owner_binding_no_delete": """
        CREATE TRIGGER trg_release_outbox_owner_binding_no_delete
        BEFORE DELETE ON release_outbox
        WHEN OLD.owner_canary_content_graph_sha256 IS NOT NULL
          OR OLD.answer_sha256 IS NOT NULL
        BEGIN
          SELECT RAISE(ABORT, 'bound owner release outbox is immutable');
        END
    """,
}


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  content_sha256 TEXT NOT NULL,
  source_identity_id TEXT NOT NULL,
  representation_group_id TEXT,
  safe_display_name TEXT NOT NULL,
  media_type TEXT NOT NULL,
  status TEXT NOT NULL,
  lane TEXT,
  subject_primary TEXT,
  subject_secondary_json TEXT NOT NULL DEFAULT '[]',
  jurisdiction TEXT,
  duplicate_of TEXT REFERENCES documents(id),
  retrieval_canonical INTEGER NOT NULL DEFAULT 0,
  has_annotations INTEGER NOT NULL DEFAULT 0,
  searchable_text INTEGER NOT NULL DEFAULT 0,
  dedupe_status TEXT NOT NULL DEFAULT 'new',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_semantic_content_canonical
  ON documents(
    content_sha256,
    COALESCE(lane, ''),
    COALESCE(jurisdiction, ''),
    COALESCE(subject_primary, '')
  ) WHERE duplicate_of IS NULL;
CREATE INDEX IF NOT EXISTS idx_documents_status_subject
  ON documents(status, subject_primary);
CREATE INDEX IF NOT EXISTS idx_documents_lane_jurisdiction
  ON documents(lane, jurisdiction);

CREATE TABLE IF NOT EXISTS source_aliases (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  path_fingerprint TEXT NOT NULL UNIQUE,
  encrypted_path BLOB NOT NULL,
  imported_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_source_aliases_document_id
  ON source_aliases(document_id);

CREATE TABLE IF NOT EXISTS uploads (
  id TEXT PRIMARY KEY,
  content_sha256 TEXT NOT NULL,
  safe_display_name TEXT NOT NULL,
  encrypted_original_name BLOB NOT NULL,
  media_type TEXT NOT NULL,
  byte_size INTEGER NOT NULL,
  vault_path TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'staged',
  encrypted_blob INTEGER NOT NULL DEFAULT 0,
  retention_until TEXT,
  review_pinned INTEGER NOT NULL DEFAULT 0,
  review_completed_at TEXT,
  quarantine_status TEXT NOT NULL DEFAULT 'unreviewed',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_uploads_content_sha256
  ON uploads(content_sha256);

CREATE TABLE IF NOT EXISTS source_versions (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  authority_identity_id TEXT,
  version_sha256 TEXT NOT NULL,
  canonical_markdown_path TEXT NOT NULL,
  title TEXT,
  author_or_body TEXT,
  source_date TEXT,
  as_of_date TEXT,
  canonical_url TEXT,
  stable_identifier TEXT,
  currentness_status TEXT NOT NULL DEFAULT 'unknown',
  licence_name TEXT,
  licence_url TEXT,
  review_status TEXT NOT NULL DEFAULT 'staged',
  processing_fingerprint TEXT NOT NULL DEFAULT 'legacy',
  superseded_by TEXT REFERENCES source_versions(id),
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  UNIQUE(document_id, version_sha256, processing_fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_source_versions_review
  ON source_versions(review_status, currentness_status);
CREATE INDEX IF NOT EXISTS idx_source_versions_stable_identifier
  ON source_versions(stable_identifier);
CREATE TABLE IF NOT EXISTS chunks (
  id TEXT PRIMARY KEY,
  source_version_id TEXT NOT NULL REFERENCES source_versions(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  heading_path TEXT,
  locator TEXT NOT NULL,
  text_sha256 TEXT NOT NULL,
  markdown_text TEXT NOT NULL,
  token_count INTEGER NOT NULL,
  stream TEXT NOT NULL DEFAULT 'body',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE(source_version_id, ordinal)
);
CREATE INDEX IF NOT EXISTS idx_chunks_source_version
  ON chunks(source_version_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_chunks_text_sha256
  ON chunks(text_sha256);

CREATE TABLE IF NOT EXISTS case_proposition_review_imports (
  manifest_sha256 TEXT PRIMARY KEY,
  manifest_id TEXT NOT NULL UNIQUE,
  review_count INTEGER NOT NULL,
  applied_count INTEGER NOT NULL,
  already_present_count INTEGER NOT NULL,
  safe_report_json TEXT NOT NULL,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS index_builds (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  path TEXT NOT NULL,
  document_count INTEGER NOT NULL DEFAULT 0,
  chunk_count INTEGER NOT NULL DEFAULT 0,
  vector_count INTEGER NOT NULL DEFAULT 0,
  embedding_model TEXT NOT NULL,
  reranker_model TEXT NOT NULL,
  manifest_sha256 TEXT,
  metrics_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  promoted_at TEXT,
  corpus_id TEXT,
  scoped_corpus_id TEXT,
  source_manifest_hash TEXT,
  parser_version TEXT,
  chunker_version TEXT,
  index_schema_version TEXT,
  embedding_model_version TEXT,
  rerank_version TEXT,
  stage TEXT NOT NULL DEFAULT 'queued',
  stage_started_at TEXT,
  stage_timings_json TEXT NOT NULL DEFAULT '{}',
  failure_count INTEGER NOT NULL DEFAULT 0,
  failure_reason_code TEXT,
  job_id TEXT,
  idempotency_key TEXT,
  candidate_manifest_hash TEXT,
  benchmark_result_json TEXT NOT NULL DEFAULT '{}',
  counts_json TEXT NOT NULL DEFAULT '{}',
  promotion_decision TEXT NOT NULL DEFAULT 'not_requested'
  ,policy_sha256 TEXT NOT NULL DEFAULT ''
  ,assessment_bundle_sha256 TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_index_builds_status_created
  ON index_builds(status, created_at DESC);

CREATE TABLE IF NOT EXISTS retrieval_attestation_history (
  id TEXT PRIMARY KEY,
  build_id TEXT NOT NULL REFERENCES index_builds(id),
  attestation_path TEXT NOT NULL UNIQUE,
  attestation_sha256 TEXT NOT NULL UNIQUE,
  schema_version TEXT NOT NULL,
  prior_attestation_path TEXT,
  prior_attestation_sha256 TEXT,
  build_seal_sha256 TEXT NOT NULL,
  source_manifest_sha256 TEXT NOT NULL,
  embedding_model TEXT NOT NULL,
  reranker_model TEXT NOT NULL,
  quality_policy_sha256 TEXT NOT NULL,
  assessment_bundle_sha256 TEXT NOT NULL,
  retrieval_policy_sha256 TEXT NOT NULL,
  benchmark_sha256 TEXT NOT NULL,
  freeze_manifest_sha256 TEXT NOT NULL,
  scorer_version TEXT NOT NULL,
  scorer_implementation_sha256 TEXT NOT NULL,
  integration_sha TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(build_id, scorer_implementation_sha256, integration_sha,
         prior_attestation_sha256)
);
CREATE INDEX IF NOT EXISTS idx_retrieval_attestation_history_build
  ON retrieval_attestation_history(build_id, created_at);

CREATE TABLE IF NOT EXISTS retrieval_attestation_selections (
  build_id TEXT PRIMARY KEY REFERENCES index_builds(id),
  attestation_id TEXT NOT NULL REFERENCES retrieval_attestation_history(id),
  selected_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS trg_retrieval_attestation_history_no_update
BEFORE UPDATE ON retrieval_attestation_history
BEGIN
  SELECT RAISE(ABORT, 'retrieval attestation history is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_retrieval_attestation_history_no_delete
BEFORE DELETE ON retrieval_attestation_history
BEGIN
  SELECT RAISE(ABORT, 'retrieval attestation history is immutable');
END;

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  stage TEXT NOT NULL,
  progress REAL NOT NULL DEFAULT 0,
  encrypted_question BLOB NOT NULL,
  question_summary TEXT NOT NULL,
  request_json TEXT NOT NULL,
  answer_id TEXT,
  release_state TEXT,
  checkpoint_json TEXT NOT NULL DEFAULT '{}',
  error_code TEXT,
  user_message TEXT,
  route TEXT NOT NULL DEFAULT 'direct',
  route_reasons_json TEXT NOT NULL DEFAULT '[]',
  lease_owner TEXT,
  lease_expires_at TEXT,
  heartbeat_at TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  idempotency_key TEXT,
  cancel_requested INTEGER NOT NULL DEFAULT 0,
  pinned_index_build_id TEXT,
  job_type TEXT NOT NULL DEFAULT 'answer',
  queue_wait_deadline_at TEXT,
  workflow_deadline_at TEXT,
  stage_started_at TEXT,
  stage_deadline_at TEXT,
  model_call_deadline_at TEXT,
  model_call_token TEXT,
  terminal_reason_code TEXT,
  dlq INTEGER NOT NULL DEFAULT 0,
  evaluation_run_id TEXT,
  evaluation_case_id TEXT,
  evaluation_request_sha256 TEXT,
  evaluation_authority_json TEXT,
  evaluation_authority_sha256 TEXT,
  normal_live_authority_sha256 TEXT,
  worker_prompt_version TEXT NOT NULL DEFAULT '',
  worker_router_version TEXT NOT NULL DEFAULT '',
  worker_classifier_version TEXT NOT NULL DEFAULT '',
  worker_policy_sha256 TEXT NOT NULL DEFAULT '',
  assessment_bundle_sha256 TEXT NOT NULL DEFAULT '',
  issue_plan_proposition_keys_json TEXT NOT NULL DEFAULT '[]',
  trace_id TEXT NOT NULL DEFAULT '',
  trace_root_span_id TEXT NOT NULL DEFAULT '',
  trace_full_retention INTEGER NOT NULL DEFAULT 0,
  last_progress_at TEXT,
  word_target INTEGER NOT NULL DEFAULT 1500,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_status_updated
  ON jobs(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_created
  ON jobs(created_at DESC);

CREATE TABLE IF NOT EXISTS job_upload_bindings (
  job_id TEXT NOT NULL REFERENCES jobs(id),
  ordinal INTEGER NOT NULL,
  upload_id TEXT NOT NULL REFERENCES uploads(id),
  content_sha256 TEXT NOT NULL,
  byte_size INTEGER NOT NULL,
  media_type TEXT NOT NULL,
  PRIMARY KEY(job_id, ordinal),
  UNIQUE(job_id, upload_id)
);

CREATE TRIGGER IF NOT EXISTS trg_job_upload_bindings_no_update
BEFORE UPDATE ON job_upload_bindings
BEGIN
  SELECT RAISE(ABORT, 'job upload binding is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_job_upload_bindings_no_delete
BEFORE DELETE ON job_upload_bindings
BEGIN
  SELECT RAISE(ABORT, 'job upload binding is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_upload_identity_no_update
BEFORE UPDATE OF id, content_sha256, safe_display_name, encrypted_original_name,
  media_type, byte_size, vault_path ON uploads
BEGIN
  SELECT RAISE(ABORT, 'upload content identity is immutable');
END;

CREATE TABLE IF NOT EXISTS job_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  stage TEXT NOT NULL,
  progress REAL NOT NULL,
  message TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_job_events_job_sequence
  ON job_events(job_id, sequence);

CREATE TABLE IF NOT EXISTS retry_decisions (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  lane TEXT NOT NULL,
  work_id TEXT NOT NULL,
  attempt_number INTEGER NOT NULL,
  stage_code TEXT NOT NULL,
  failure_reason_code TEXT NOT NULL,
  failure_fingerprint_sha256 TEXT NOT NULL,
  input_identity_sha256 TEXT NOT NULL,
  condition_identity_sha256 TEXT NOT NULL,
  decision_action TEXT NOT NULL,
  decision_reason TEXT NOT NULL,
  retries_remaining INTEGER NOT NULL,
  retry_operation TEXT NOT NULL,
  condition_changed INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(lane, work_id, attempt_number)
);
CREATE INDEX IF NOT EXISTS idx_retry_decisions_work
  ON retry_decisions(lane, work_id, attempt_number);

CREATE TABLE IF NOT EXISTS job_stage_attempts (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  stage_key TEXT NOT NULL,
  section_key TEXT NOT NULL DEFAULT '',
  attempt_number INTEGER NOT NULL,
  status TEXT NOT NULL,
  input_digest TEXT,
  evidence_pack_digest TEXT,
  encrypted_output BLOB,
  output_object_key TEXT REFERENCES runtime_objects(object_key),
  metrics_json TEXT NOT NULL DEFAULT '{}',
  error_code TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  UNIQUE(job_id, stage_key, section_key, attempt_number)
);
CREATE INDEX IF NOT EXISTS idx_job_stage_resume
  ON job_stage_attempts(job_id, stage_key, section_key, status, attempt_number DESC);

CREATE TABLE IF NOT EXISTS evidence_packs (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  section_key TEXT NOT NULL,
  digest TEXT NOT NULL,
  index_build_id TEXT NOT NULL,
  source_ids_json TEXT NOT NULL DEFAULT '[]',
  encrypted_payload BLOB NOT NULL,
  object_key TEXT REFERENCES runtime_objects(object_key),
  created_at TEXT NOT NULL,
  UNIQUE(job_id, section_key),
  UNIQUE(job_id, digest)
);
CREATE INDEX IF NOT EXISTS idx_evidence_packs_job
  ON evidence_packs(job_id, section_key);

CREATE TABLE IF NOT EXISTS release_outbox (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id) ON DELETE CASCADE,
  answer_id TEXT NOT NULL UNIQUE REFERENCES answer_versions(id) ON DELETE CASCADE,
  release_state TEXT NOT NULL,
  release_audience TEXT NOT NULL DEFAULT 'normal_live',
  evaluation_authority_sha256 TEXT,
  owner_canary_content_graph_sha256 TEXT,
  answer_sha256 TEXT,
  idempotency_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  published_at TEXT
);

CREATE TABLE IF NOT EXISTS normal_live_readiness_state (
  scope TEXT PRIMARY KEY CHECK(scope='owner-only-normal-live'),
  generation_sha256 TEXT NOT NULL,
  authority_sha256 TEXT NOT NULL,
  candidate_build_id TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 0 CHECK(active IN (0,1)),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS owner_canary_runtime_sessions (
  run_id TEXT PRIMARY KEY,
  authorization_sha256 TEXT NOT NULL,
  start_attestation_sha256 TEXT NOT NULL UNIQUE,
  runtime_instance_sha256 TEXT NOT NULL UNIQUE,
  candidate_build_id TEXT NOT NULL,
  memory_policy_sha256 TEXT NOT NULL,
  expected_case_count INTEGER NOT NULL CHECK(expected_case_count=30),
  next_sequence INTEGER NOT NULL DEFAULT 1 CHECK(next_sequence BETWEEN 1 AND 31),
  active_case_id TEXT,
  active_before_checkpoint_sha256 TEXT,
  frontier_generation INTEGER NOT NULL DEFAULT 0,
  controller_pid INTEGER NOT NULL,
  heartbeat_at TEXT NOT NULL,
  lease_expires_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active','revoked','ended')),
  end_attestation_sha256 TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_objects (
  object_key TEXT PRIMARY KEY,
  namespace TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  relative_path TEXT NOT NULL UNIQUE,
  byte_size INTEGER NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  expires_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runtime_objects_namespace
  ON runtime_objects(namespace, created_at DESC);

CREATE TABLE IF NOT EXISTS service_heartbeats (
  service_key TEXT PRIMARY KEY,
  instance_id TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS evaluation_runs (
  id TEXT PRIMARY KEY,
  suite_version TEXT NOT NULL,
  suite_sha256 TEXT NOT NULL,
  corpus_manifest_sha256 TEXT NOT NULL,
  index_build_id TEXT NOT NULL,
  model_version TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  purpose TEXT NOT NULL DEFAULT 'evaluation_only',
  eligible_for_training INTEGER NOT NULL DEFAULT 0,
  training_export_allowed INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  aggregate_metrics_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  completed_at TEXT
  ,policy_sha256 TEXT NOT NULL DEFAULT ''
  ,assessment_bundle_sha256 TEXT NOT NULL DEFAULT ''
  ,as_of_date TEXT
);

CREATE TABLE IF NOT EXISTS evaluation_case_runs (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES evaluation_runs(id) ON DELETE CASCADE,
  case_id TEXT NOT NULL,
  attempt_number INTEGER NOT NULL DEFAULT 1,
  job_id TEXT REFERENCES jobs(id),
  route TEXT,
  status TEXT NOT NULL,
  release_state TEXT,
  coverage_status TEXT NOT NULL DEFAULT 'unqualified',
  artifact_id TEXT,
  metrics_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(run_id, case_id, attempt_number)
);
CREATE INDEX IF NOT EXISTS idx_evaluation_case_runs_run
  ON evaluation_case_runs(run_id, case_id, attempt_number);

CREATE TABLE IF NOT EXISTS evaluation_issues (
  id TEXT PRIMARY KEY,
  run_id TEXT REFERENCES evaluation_runs(id),
  case_id TEXT,
  job_id TEXT REFERENCES jobs(id),
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  affected_layer TEXT NOT NULL,
  safe_expected_ids_json TEXT NOT NULL DEFAULT '[]',
  safe_observed_ids_json TEXT NOT NULL DEFAULT '[]',
  root_cause TEXT,
  corrective_action TEXT,
  regression_case_id TEXT,
  fixed_version TEXT,
  status TEXT NOT NULL,
  encrypted_human_note BLOB,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evaluation_issues_status
  ON evaluation_issues(status, severity, created_at DESC);

CREATE TABLE IF NOT EXISTS evaluation_issue_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  issue_id TEXT NOT NULL REFERENCES evaluation_issues(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL,
  safe_payload_json TEXT NOT NULL DEFAULT '{}',
  encrypted_note BLOB,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evaluation_issue_events
  ON evaluation_issue_events(issue_id, sequence);

CREATE TABLE IF NOT EXISTS answer_versions (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  version_number INTEGER NOT NULL,
  version_kind TEXT NOT NULL,
  encrypted_content BLOB NOT NULL,
  word_count INTEGER NOT NULL,
  release_state TEXT,
  parent_version_id TEXT REFERENCES answer_versions(id),
  diff_from_parent TEXT,
  encrypted_diff_from_parent BLOB,
  policy_version TEXT NOT NULL,
  model_version TEXT NOT NULL,
  index_build_id TEXT REFERENCES index_builds(id),
  purge_after TEXT,
  created_at TEXT NOT NULL,
  policy_sha256 TEXT NOT NULL DEFAULT '',
  UNIQUE(job_id, version_number)
);
CREATE INDEX IF NOT EXISTS idx_answer_versions_job
  ON answer_versions(job_id, version_number);
CREATE INDEX IF NOT EXISTS idx_answer_versions_purge
  ON answer_versions(purge_after) WHERE purge_after IS NOT NULL;

CREATE TABLE IF NOT EXISTS conversation_sessions (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active','expired','closed')),
  message_count INTEGER NOT NULL DEFAULT 0 CHECK(message_count >= 0),
  estimated_tokens INTEGER NOT NULL DEFAULT 0 CHECK(estimated_tokens >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_accessed_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_conversation_sessions_expiry
  ON conversation_sessions(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_conversation_sessions_recent
  ON conversation_sessions(updated_at DESC, id);

CREATE TABLE IF NOT EXISTS conversation_messages (
  id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL REFERENCES conversation_sessions(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 1),
  role TEXT NOT NULL CHECK(role IN ('user','assistant')),
  encrypted_content BLOB NOT NULL,
  content_sha256 TEXT NOT NULL,
  estimated_tokens INTEGER NOT NULL CHECK(estimated_tokens >= 1),
  job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
  answer_id TEXT REFERENCES answer_versions(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  UNIQUE(conversation_id, ordinal),
  UNIQUE(conversation_id, job_id, role)
);
CREATE INDEX IF NOT EXISTS idx_conversation_messages_window
  ON conversation_messages(conversation_id, ordinal DESC);
CREATE INDEX IF NOT EXISTS idx_conversation_messages_expiry
  ON conversation_messages(expires_at);

CREATE TABLE IF NOT EXISTS conversation_job_bindings (
  job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
  conversation_id TEXT NOT NULL REFERENCES conversation_sessions(id) ON DELETE CASCADE,
  user_message_id TEXT NOT NULL REFERENCES conversation_messages(id) ON DELETE CASCADE,
  assistant_message_id TEXT REFERENCES conversation_messages(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_conversation_job_bindings_session
  ON conversation_job_bindings(conversation_id, created_at DESC);

CREATE TRIGGER IF NOT EXISTS trg_conversation_messages_no_update
BEFORE UPDATE ON conversation_messages
WHEN OLD.id IS NOT NEW.id
  OR OLD.conversation_id IS NOT NEW.conversation_id
  OR OLD.ordinal IS NOT NEW.ordinal
  OR OLD.role IS NOT NEW.role
  OR OLD.encrypted_content IS NOT NEW.encrypted_content
  OR OLD.content_sha256 IS NOT NEW.content_sha256
  OR OLD.estimated_tokens IS NOT NEW.estimated_tokens
  OR OLD.created_at IS NOT NEW.created_at
  OR OLD.expires_at IS NOT NEW.expires_at
  OR (OLD.job_id IS NULL AND NEW.job_id IS NOT NULL)
  OR (OLD.job_id IS NOT NULL AND NEW.job_id IS NOT NULL
      AND OLD.job_id IS NOT NEW.job_id)
  OR (OLD.answer_id IS NULL AND NEW.answer_id IS NOT NULL)
  OR (OLD.answer_id IS NOT NULL AND NEW.answer_id IS NOT NULL
      AND OLD.answer_id IS NOT NEW.answer_id)
BEGIN
  SELECT RAISE(ABORT, 'conversation message content and identity are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_conversation_job_binding_identity_no_update
BEFORE UPDATE OF job_id,conversation_id,user_message_id ON conversation_job_bindings
BEGIN
  SELECT RAISE(ABORT, 'conversation job binding identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_conversation_job_binding_assistant_once
BEFORE UPDATE OF assistant_message_id ON conversation_job_bindings
WHEN OLD.assistant_message_id IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'conversation assistant binding is immutable');
END;

CREATE TABLE IF NOT EXISTS claims (
  id TEXT PRIMARY KEY,
  answer_version_id TEXT NOT NULL REFERENCES answer_versions(id) ON DELETE CASCADE,
  model_claim_id TEXT,
  section_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  claim_text TEXT NOT NULL,
  encrypted_claim_text BLOB,
  material INTEGER NOT NULL DEFAULT 1,
  proposition_hash TEXT,
  verification_status TEXT NOT NULL,
  verification_reason TEXT,
  UNIQUE(answer_version_id, model_claim_id),
  UNIQUE(answer_version_id, ordinal)
);
CREATE INDEX IF NOT EXISTS idx_claims_answer
  ON claims(answer_version_id, ordinal);

CREATE TABLE IF NOT EXISTS evidence_spans (
  id TEXT PRIMARY KEY,
  source_version_id TEXT NOT NULL REFERENCES source_versions(id),
  chunk_id TEXT NOT NULL REFERENCES chunks(id),
  span_text TEXT NOT NULL,
  locator TEXT NOT NULL,
  lane TEXT NOT NULL,
  jurisdiction TEXT NOT NULL,
  subject TEXT NOT NULL,
  citation_data_json TEXT NOT NULL,
  canonical_citation TEXT,
  currentness_status TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  index_build_id TEXT NOT NULL REFERENCES index_builds(id),
  canonical_url TEXT,
  entailment_score REAL,
  retrieval_relevance_score REAL,
  retrieval_route TEXT,
  retrieval_threshold REAL,
  retrieval_threshold_policy_sha256 TEXT,
  retrieval_threshold_qualified INTEGER,
  retrieval_qualification_reason TEXT,
  legal_role TEXT NOT NULL DEFAULT 'unclassified',
  unapplied_effect_count INTEGER,
  provision_extent_status TEXT NOT NULL DEFAULT 'unverified',
  identity_verified INTEGER NOT NULL DEFAULT 0,
  currentness_verified INTEGER NOT NULL DEFAULT 0,
  case_currentness_reviews_json TEXT NOT NULL DEFAULT '[]',
  case_currentness_manifest_seals_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_source_chunk
  ON evidence_spans(source_version_id, chunk_id);

CREATE TABLE IF NOT EXISTS claim_evidence (
  claim_id TEXT NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL REFERENCES evidence_spans(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  PRIMARY KEY (claim_id, evidence_id)
);
CREATE INDEX IF NOT EXISTS idx_claim_evidence_evidence
  ON claim_evidence(evidence_id);

CREATE TABLE IF NOT EXISTS quality_reports (
  id TEXT PRIMARY KEY,
  answer_version_id TEXT NOT NULL REFERENCES answer_versions(id) ON DELETE CASCADE,
  evidence_passed INTEGER NOT NULL,
  academic_score REAL NOT NULL,
  rubric_scores_json TEXT NOT NULL,
  findings_json TEXT NOT NULL,
  release_state TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  created_at TEXT NOT NULL
  ,policy_sha256 TEXT NOT NULL DEFAULT ''
  ,ai_evidence_review_json TEXT
  ,ai_evidence_adjudication_json TEXT
  ,assessment_standards_json TEXT
  ,encrypted_source_draft BLOB
);
CREATE INDEX IF NOT EXISTS idx_quality_reports_release_created
  ON quality_reports(release_state, created_at DESC);

CREATE TABLE IF NOT EXISTS knowledge_gaps (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  missing_proposition TEXT NOT NULL,
  encrypted_missing_proposition BLOB,
  proposition_sha256 TEXT,
  jurisdiction TEXT NOT NULL,
  subject TEXT,
  searches_json TEXT NOT NULL DEFAULT '[]',
  rejection_reasons_json TEXT NOT NULL DEFAULT '[]',
  review_file TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_knowledge_gaps_status_jurisdiction
  ON knowledge_gaps(status, jurisdiction, created_at DESC);

CREATE TABLE IF NOT EXISTS research_gap_bindings (
  id TEXT PRIMARY KEY,
  fingerprint_sha256 TEXT NOT NULL UNIQUE,
  candidate_build_id TEXT NOT NULL REFERENCES index_builds(id),
  source_manifest_sha256 TEXT NOT NULL,
  case_id TEXT NOT NULL,
  issue_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  jurisdiction TEXT NOT NULL,
  as_of_date TEXT NOT NULL,
  attempted_retrieval_sha256 TEXT NOT NULL,
  materiality TEXT NOT NULL,
  detail_sha256 TEXT NOT NULL,
  encrypted_detail BLOB NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_research_gap_bindings_status
  ON research_gap_bindings(status, candidate_build_id, as_of_date, created_at DESC);

CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY,
  review_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  reason TEXT,
  decision_note TEXT,
  encrypted_decision_note BLOB,
  created_at TEXT NOT NULL,
  decided_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_reviews_status_type
  ON reviews(status, review_type, created_at);
CREATE INDEX IF NOT EXISTS idx_reviews_status_created_id
  ON reviews(status, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_reviews_created_id
  ON reviews(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_reviews_status_type_created_id
  ON reviews(status, review_type, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_reviews_type_created_id
  ON reviews(review_type, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS rubric_rules (
  id TEXT PRIMARY KEY,
  task_type TEXT,
  subject TEXT,
  criterion TEXT NOT NULL,
  polarity TEXT NOT NULL,
  grade_band TEXT NOT NULL,
  rule_text TEXT NOT NULL,
  remediation_text TEXT,
  source_version_id TEXT REFERENCES source_versions(id),
  review_status TEXT NOT NULL DEFAULT 'staged',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rubric_rules_lookup
  ON rubric_rules(review_status, task_type, subject, criterion);

CREATE TABLE IF NOT EXISTS source_scans (
  id TEXT PRIMARY KEY,
  resumed_from_scan_id TEXT REFERENCES source_scans(id),
  status TEXT NOT NULL,
  required_roots_json TEXT NOT NULL,
  roots_seen_json TEXT NOT NULL DEFAULT '[]',
  expected_file_count INTEGER NOT NULL DEFAULT 0,
  files_accounted INTEGER NOT NULL DEFAULT 0,
  statuses_json TEXT NOT NULL DEFAULT '{}',
  manifest_sha256 TEXT,
  error_code TEXT,
  error_message TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_source_scans_created
  ON source_scans(created_at DESC);

CREATE TABLE IF NOT EXISTS source_scan_files (
  scan_id TEXT NOT NULL REFERENCES source_scans(id) ON DELETE CASCADE,
  path_fingerprint TEXT NOT NULL,
  document_id TEXT REFERENCES documents(id),
  status TEXT NOT NULL,
  content_sha256 TEXT,
  reason TEXT,
  PRIMARY KEY(scan_id, path_fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_source_scan_files_status
  ON source_scan_files(scan_id, status);

CREATE TABLE IF NOT EXISTS operational_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  component TEXT NOT NULL,
  stage TEXT,
  failure_code TEXT,
  source_id TEXT,
  fingerprint TEXT NOT NULL,
  severity TEXT,
  retryable INTEGER NOT NULL DEFAULT 0,
  blocking INTEGER NOT NULL DEFAULT 0,
  job_id TEXT,
  build_id TEXT,
  failure_id TEXT,
  parent_failure_id TEXT,
  user_or_owner_safe TEXT NOT NULL,
  internal_detail TEXT,
  provenance_json TEXT NOT NULL DEFAULT '{}',
  context_json TEXT NOT NULL DEFAULT '{}',
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_operational_events_fingerprint
  ON operational_events(fingerprint);
CREATE INDEX IF NOT EXISTS idx_operational_events_type
  ON operational_events(event_type, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_operational_events_failure
  ON operational_events(failure_id);
CREATE INDEX IF NOT EXISTS idx_operational_events_job
  ON operational_events(job_id, last_seen DESC);

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

CREATE TABLE IF NOT EXISTS research_tasks (
  id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  task_type TEXT NOT NULL,
  trigger_kind TEXT NOT NULL,
  priority_band TEXT NOT NULL,
  base_priority INTEGER NOT NULL,
  subject TEXT NOT NULL,
  jurisdiction TEXT NOT NULL,
  as_of_date TEXT NOT NULL,
  source_id TEXT,
  origin_host TEXT,
  authority_identity_id TEXT,
  source_locator TEXT,
  knowledge_gap_id TEXT,
  answer_id TEXT REFERENCES answer_versions(id),
  answer_job_id TEXT REFERENCES jobs(id),
  refinement_id TEXT,
  pinned_index_build_id TEXT REFERENCES index_builds(id),
  source_manifest_sha256 TEXT,
  query_sha256 TEXT NOT NULL,
  encrypted_query BLOB,
  status TEXT NOT NULL,
  status_reason TEXT,
  lease_owner TEXT,
  lease_expires_at TEXT,
  heartbeat_at TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  retry_after_at TEXT,
  candidate_cap INTEGER NOT NULL DEFAULT 20,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_research_tasks_queue
  ON research_tasks(status, base_priority DESC, created_at, id);
CREATE INDEX IF NOT EXISTS idx_research_tasks_lease
  ON research_tasks(status, lease_expires_at, origin_host);
CREATE INDEX IF NOT EXISTS idx_research_tasks_links
  ON research_tasks(knowledge_gap_id, answer_job_id, refinement_id);

CREATE TABLE IF NOT EXISTS research_candidates (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES research_tasks(id) ON DELETE CASCADE,
  source_id TEXT NOT NULL,
  source_identity TEXT NOT NULL,
  canonical_url TEXT NOT NULL,
  content_sha256 TEXT,
  metadata_sha256 TEXT NOT NULL,
  content_object_key TEXT REFERENCES runtime_objects(object_key),
  status TEXT NOT NULL DEFAULT 'detected',
  comparison_state TEXT,
  rights_state TEXT NOT NULL DEFAULT 'unreviewed',
  review_id TEXT REFERENCES reviews(id),
  system_verification_sha256 TEXT,
  system_verified_at TEXT,
  intake_review_id TEXT REFERENCES reviews(id),
  identity_review_state TEXT NOT NULL DEFAULT 'unreviewed',
  currentness_review_state TEXT NOT NULL DEFAULT 'unreviewed',
  reviewer_ref TEXT,
  review_manifest_sha256 TEXT,
  safe_metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(task_id, source_id, source_identity)
);
CREATE INDEX IF NOT EXISTS idx_research_candidates_review
  ON research_candidates(status, rights_state, created_at DESC);

CREATE TABLE IF NOT EXISTS source_update_observations (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES research_tasks(id) ON DELETE CASCADE,
  candidate_id TEXT REFERENCES research_candidates(id),
  source_id TEXT NOT NULL,
  authority_identity_id TEXT NOT NULL,
  pinned_index_build_id TEXT,
  pinned_source_manifest_sha256 TEXT,
  observed_active_build_id TEXT,
  baseline_version_sha256 TEXT,
  remote_content_sha256 TEXT,
  comparison_state TEXT NOT NULL,
  stale_active INTEGER NOT NULL DEFAULT 0,
  scope_kind TEXT NOT NULL DEFAULT 'authority',
  legal_locator TEXT,
  proposition_sha256 TEXT,
  materiality_status TEXT NOT NULL DEFAULT 'unassessed',
  review_status TEXT NOT NULL DEFAULT 'pending',
  review_id TEXT REFERENCES reviews(id),
  reviewer_ref TEXT,
  review_manifest_sha256 TEXT,
  safe_detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_source_update_observations_identity
  ON source_update_observations(source_id, authority_identity_id, created_at DESC);

CREATE TABLE IF NOT EXISTS knowledge_update_events (
  id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL
    CHECK(event_type IN ('knowledge_gap','source_changed','project_clarification')),
  source_id TEXT,
  authority_identity_id TEXT,
  knowledge_gap_id TEXT,
  subject TEXT NOT NULL,
  jurisdiction TEXT NOT NULL,
  source_date TEXT,
  as_of_date TEXT,
  observed_at TEXT NOT NULL,
  last_updated_at TEXT NOT NULL,
  query_sha256 TEXT,
  safe_payload_json TEXT NOT NULL DEFAULT '{}',
  encrypted_detail BLOB,
  status TEXT NOT NULL,
  dispatch_mode TEXT NOT NULL,
  research_task_id TEXT REFERENCES research_tasks(id),
  owner_admission_required INTEGER NOT NULL DEFAULT 1,
  writes_index INTEGER NOT NULL DEFAULT 0,
  failure_code TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knowledge_update_events_dispatch
  ON knowledge_update_events(status, observed_at, id);
CREATE INDEX IF NOT EXISTS idx_knowledge_update_events_authority
  ON knowledge_update_events(source_id, authority_identity_id, last_updated_at DESC);

CREATE TRIGGER IF NOT EXISTS trg_knowledge_update_events_no_index_write
BEFORE UPDATE OF writes_index ON knowledge_update_events
WHEN NEW.writes_index<>0
BEGIN
  SELECT RAISE(ABORT, 'knowledge update events cannot write an index');
END;

CREATE TRIGGER IF NOT EXISTS trg_knowledge_update_event_identity_no_update
BEFORE UPDATE OF id,idempotency_key,event_type,source_id,authority_identity_id,
  knowledge_gap_id,subject,jurisdiction,source_date,as_of_date,observed_at,query_sha256,
  safe_payload_json,encrypted_detail ON knowledge_update_events
BEGIN
  SELECT RAISE(ABORT, 'knowledge update event identity is immutable');
END;

CREATE TABLE IF NOT EXISTS source_update_resolution_events (
  id TEXT PRIMARY KEY,
  observation_id TEXT NOT NULL REFERENCES source_update_observations(id),
  resolved_by_build_id TEXT NOT NULL REFERENCES index_builds(id),
  source_manifest_sha256 TEXT NOT NULL,
  resolution_kind TEXT NOT NULL,
  authority_identity_id TEXT NOT NULL,
  legal_locator TEXT,
  proposition_sha256 TEXT,
  evidence_sha256 TEXT NOT NULL,
  reviewer_ref TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(observation_id, resolved_by_build_id)
);
CREATE INDEX IF NOT EXISTS idx_source_update_resolution_active
  ON source_update_resolution_events(resolved_by_build_id, observation_id);

CREATE TABLE IF NOT EXISTS research_schedules (
  id TEXT PRIMARY KEY,
  task_type TEXT NOT NULL,
  timezone TEXT NOT NULL,
  local_hour INTEGER NOT NULL,
  local_minute INTEGER NOT NULL,
  weekday INTEGER,
  enabled INTEGER NOT NULL DEFAULT 0,
  last_scheduled_for TEXT,
  next_due_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_research_schedules_due
  ON research_schedules(enabled, next_due_at);

CREATE TABLE IF NOT EXISTS refinements (
  id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL UNIQUE,
  category TEXT NOT NULL,
  scope TEXT NOT NULL,
  priority INTEGER NOT NULL,
  status TEXT NOT NULL,
  origin TEXT NOT NULL,
  answer_id TEXT REFERENCES answer_versions(id),
  job_id TEXT REFERENCES jobs(id),
  knowledge_gap_id TEXT,
  research_task_id TEXT REFERENCES research_tasks(id),
  safe_target_json TEXT NOT NULL DEFAULT '{}',
  encrypted_note BLOB,
  note_sha256 TEXT,
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  root_cause TEXT,
  repair_version TEXT,
  regression_case_id TEXT,
  resolution_evidence_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  closed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_refinements_inbox
  ON refinements(status, priority DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_refinements_links
  ON refinements(category, knowledge_gap_id, research_task_id);

CREATE TABLE IF NOT EXISTS refinement_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  refinement_id TEXT NOT NULL REFERENCES refinements(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  from_status TEXT,
  to_status TEXT NOT NULL,
  safe_payload_json TEXT NOT NULL DEFAULT '{}',
  encrypted_note BLOB,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refinement_events_refinement
  ON refinement_events(refinement_id, sequence);

CREATE TABLE IF NOT EXISTS legacy_research_gap_imports (
  manifest_sha256 TEXT PRIMARY KEY,
  schema_name TEXT NOT NULL,
  imported_count INTEGER NOT NULL,
  skipped_count INTEGER NOT NULL,
  imported_at TEXT NOT NULL
);
"""


def utc_iso() -> str:
    return datetime.now(UTC).isoformat()


def _parse_utc_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _research_effective_priority(row: Mapping[str, Any], now: datetime) -> int:
    created = _parse_utc_iso(str(row["created_at"]))
    age_days = max(0, int((now - created).total_seconds() // 86_400))
    return min(95, int(row["base_priority"]) + age_days * 5)


def _scoped_claim_id(answer_version_id: str, model_claim_id: str) -> str:
    """Create a stable storage key without changing the model-visible claim ID."""

    digest = hashlib.sha256(
        f"legalbot-claim-v1\0{answer_version_id}\0{model_claim_id}".encode()
    ).hexdigest()
    return f"claim-{digest[:40]}"


class SourceScanConflictError(RuntimeError):
    """Raised when a second queued/running source scan is requested."""

    def __init__(self, active_scan_id: str, active_status: str) -> None:
        self.active_scan_id = active_scan_id
        self.active_status = active_status
        super().__init__(
            f"Source scan {active_scan_id} is already {active_status}; "
            "wait for it to finish before starting another scan"
        )


class SourceScanStateError(RuntimeError):
    """Raised when a scan transition would make its history ambiguous."""


@contextmanager
def _catalog_process_lock(path: Path) -> Iterator[None]:
    """Serialise catalogue connection setup and migrations across processes."""

    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.parent / ".catalog-initialize.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "a+b") as handle:
        lock_path.chmod(0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


_SnapshotPathIdentity = tuple[int, int, int, int, int]


def _snapshot_path_identity(value: os.stat_result) -> _SnapshotPathIdentity:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_uid),
        int(value.st_mode),
        int(value.st_nlink),
    )


def _open_pinned_snapshot_path(
    database_path: Path,
    *,
    create_if_missing: bool = False,
) -> tuple[
    tuple[tuple[Path, int, tuple[int, int]], ...],
    tuple[Path, int, _SnapshotPathIdentity],
    tuple[Path, int, _SnapshotPathIdentity],
]:
    """Open every lexical ancestor without following links and pin the leaf.

    SQLite must still open its own descriptor, but holding this descriptor
    chain across connect/replay/close makes every lexical component auditable.
    The exact parent and database metadata form part of the public-read
    authority; higher ancestors are pinned by device/inode and must remain
    non-symlink directories.
    """

    if not database_path.is_absolute() or database_path.name in {"", ".", ".."}:
        raise RuntimeError("database_snapshot_identity_invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags = flags | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    leaf_flags = flags | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[tuple[Path, int, tuple[int, int]]] = []
    current_path = Path(database_path.anchor)
    try:
        current_fd = os.open(database_path.anchor, directory_flags)
        root_stat = os.fstat(current_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise RuntimeError("database_snapshot_identity_invalid")
        descriptors.append(
            (current_path, current_fd, (int(root_stat.st_dev), int(root_stat.st_ino)))
        )
        for component in database_path.parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            current_path /= component
            next_stat = os.fstat(next_fd)
            if not stat.S_ISDIR(next_stat.st_mode):
                os.close(next_fd)
                raise RuntimeError("database_snapshot_identity_invalid")
            descriptors.append(
                (current_path, next_fd, (int(next_stat.st_dev), int(next_stat.st_ino)))
            )
            current_fd = next_fd
        parent_path, parent_fd, _parent_dev_ino = descriptors[-1]
        parent_stat = os.fstat(parent_fd)
        if (
            int(parent_stat.st_uid) != os.getuid()
            or stat.S_IMODE(parent_stat.st_mode) & 0o022
            or int(parent_stat.st_nlink) < 1
        ):
            raise RuntimeError("database_snapshot_parent_permissions_invalid")
        try:
            database_fd = os.open(database_path.name, leaf_flags, dir_fd=parent_fd)
        except FileNotFoundError:
            if not create_if_missing:
                raise
            database_fd = os.open(
                database_path.name,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
        database_stat = os.fstat(database_fd)
        parent_stat = os.fstat(parent_fd)
        parent_identity = _snapshot_path_identity(parent_stat)
        database_identity = _snapshot_path_identity(database_stat)
        if (
            not stat.S_ISREG(database_stat.st_mode)
            or int(database_stat.st_uid) != os.getuid()
            or stat.S_IMODE(database_stat.st_mode) != 0o600
            or int(database_stat.st_nlink) != 1
        ):
            os.close(database_fd)
            raise RuntimeError("database_snapshot_file_permissions_invalid")
        return (
            tuple(descriptors),
            (parent_path, parent_fd, parent_identity),
            (database_path, database_fd, database_identity),
        )
    except OSError:
        for _path, descriptor, _identity in reversed(descriptors):
            os.close(descriptor)
        raise RuntimeError("database_snapshot_identity_invalid") from None
    except RuntimeError:
        for _path, descriptor, _identity in reversed(descriptors):
            os.close(descriptor)
        raise


def _require_pinned_snapshot_path_current(
    *,
    ancestors: tuple[tuple[Path, int, tuple[int, int]], ...],
    parent: tuple[Path, int, _SnapshotPathIdentity],
    database: tuple[Path, int, _SnapshotPathIdentity],
    allowed_parent_nlinks: set[int] | None = None,
) -> None:
    for path, descriptor, expected_dev_ino in ancestors:
        descriptor_stat = os.fstat(descriptor)
        path_stat = os.lstat(path)
        if (
            not stat.S_ISDIR(descriptor_stat.st_mode)
            or stat.S_ISLNK(path_stat.st_mode)
            or not stat.S_ISDIR(path_stat.st_mode)
            or (int(descriptor_stat.st_dev), int(descriptor_stat.st_ino)) != expected_dev_ino
            or (int(path_stat.st_dev), int(path_stat.st_ino)) != expected_dev_ino
        ):
            raise RuntimeError("database_snapshot_ancestor_identity_changed")
    parent_path, parent_descriptor, parent_identity = parent
    parent_descriptor_identity = _snapshot_path_identity(os.fstat(parent_descriptor))
    parent_path_identity = _snapshot_path_identity(os.lstat(parent_path))
    if (
        parent_descriptor_identity != parent_path_identity
        or parent_descriptor_identity[:3] != parent_identity[:3]
        or not stat.S_ISDIR(parent_descriptor_identity[3])
        or stat.S_IMODE(parent_descriptor_identity[3]) & 0o022
        or parent_descriptor_identity[4] < 1
        or (
            allowed_parent_nlinks is not None
            and parent_descriptor_identity[4] not in allowed_parent_nlinks
        )
    ):
        raise RuntimeError("database_snapshot_parent_identity_changed")
    database_path, database_descriptor, database_identity = database
    if (
        _snapshot_path_identity(os.fstat(database_descriptor)) != database_identity
        or _snapshot_path_identity(os.lstat(database_path)) != database_identity
    ):
        raise RuntimeError("database_snapshot_identity_changed")


def _normalized_schema_sql(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())


def require_release_outbox_schema_contract(connection: sqlite3.Connection) -> str:
    """Require the exact immutable anchor relied on by public owner reads."""

    expected_columns = {
        "id": ("TEXT", 0, None, 1),
        "job_id": ("TEXT", 1, None, 0),
        "answer_id": ("TEXT", 1, None, 0),
        "release_state": ("TEXT", 1, None, 0),
        "release_audience": ("TEXT", 1, "'normal_live'", 0),
        "evaluation_authority_sha256": ("TEXT", 0, None, 0),
        "normal_live_authority_sha256": ("TEXT", 0, None, 0),
        "owner_canary_content_graph_sha256": ("TEXT", 0, None, 0),
        "answer_sha256": ("TEXT", 0, None, 0),
        "idempotency_key": ("TEXT", 1, None, 0),
        "status": ("TEXT", 1, "'pending'", 0),
        "created_at": ("TEXT", 1, None, 0),
        "published_at": ("TEXT", 0, None, 0),
    }
    table_rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name='release_outbox'"
    ).fetchall()
    if (
        len(table_rows) != 1
        or str(table_rows[0]["type"]) != "table"
        or str(table_rows[0]["tbl_name"]) != "release_outbox"
        or table_rows[0]["sql"] in (None, "")
    ):
        raise RuntimeError("release_outbox_schema_contract_invalid")
    columns = connection.execute("PRAGMA table_info(release_outbox)").fetchall()
    actual_columns = {
        str(row["name"]): (
            str(row["type"]).upper(),
            int(row["notnull"]),
            row["dflt_value"],
            int(row["pk"]),
        )
        for row in columns
    }
    if actual_columns != expected_columns:
        raise RuntimeError("release_outbox_schema_contract_invalid")

    index_contract: set[tuple[int, str, int, tuple[str, ...]]] = set()
    for index in connection.execute("PRAGMA index_list(release_outbox)").fetchall():
        index_name = str(index["name"])
        index_columns = tuple(
            str(row["name"])
            for row in connection.execute(f"PRAGMA index_info({json.dumps(index_name)})")
        )
        index_contract.add(
            (
                int(index["unique"]),
                str(index["origin"]),
                int(index["partial"]),
                index_columns,
            )
        )
    expected_indexes = {
        (1, "pk", 0, ("id",)),
        (1, "u", 0, ("job_id",)),
        (1, "u", 0, ("answer_id",)),
        (1, "u", 0, ("idempotency_key",)),
    }
    if index_contract != expected_indexes:
        raise RuntimeError("release_outbox_schema_contract_invalid")

    foreign_keys = {
        (
            str(row["table"]),
            str(row["from"]),
            str(row["to"]),
            str(row["on_update"]),
            str(row["on_delete"]),
            str(row["match"]),
        )
        for row in connection.execute("PRAGMA foreign_key_list(release_outbox)").fetchall()
    }
    if foreign_keys != {
        ("jobs", "job_id", "id", "NO ACTION", "CASCADE", "NONE"),
        ("answer_versions", "answer_id", "id", "NO ACTION", "CASCADE", "NONE"),
    }:
        raise RuntimeError("release_outbox_schema_contract_invalid")

    triggers = {
        str(row["name"]): _normalized_schema_sql(str(row["sql"]))
        for row in connection.execute(
            "SELECT name,sql FROM sqlite_master "
            "WHERE type='trigger' AND tbl_name='release_outbox' ORDER BY name"
        ).fetchall()
    }
    expected_triggers = {
        name: _normalized_schema_sql(sql) for name, sql in _RELEASE_OUTBOX_TRIGGER_SQL.items()
    }
    if triggers != expected_triggers:
        raise RuntimeError("release_outbox_schema_contract_invalid")

    material = {
        "schema": "legalbot.release-outbox-schema-contract.v1",
        "columns": sorted((name, *values) for name, values in actual_columns.items()),
        "indexes": sorted(index_contract),
        "foreign_keys": sorted(foreign_keys),
        "triggers": sorted(triggers.items()),
    }
    return hashlib.sha256(
        (
            json.dumps(
                material,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    ).hexdigest()


def _process_file_descriptors() -> dict[int, _SnapshotPathIdentity]:
    try:
        names = os.listdir("/dev/fd")
    except OSError as exc:  # pragma: no cover - macOS first-release invariant
        raise RuntimeError("sqlite_connection_descriptor_inventory_unavailable") from exc
    result: dict[int, _SnapshotPathIdentity] = {}
    for name in names:
        try:
            descriptor = int(name)
            descriptor_stat = os.fstat(descriptor)
        except (ValueError, OSError):
            continue
        if stat.S_ISREG(descriptor_stat.st_mode):
            result[descriptor] = _snapshot_path_identity(descriptor_stat)
    return result


def _descriptor_kernel_path(descriptor: int) -> Path:
    # F_GETPATH is the exact open-file path on macOS.  Keep a /proc fallback
    # for developer Linux hosts, although the first release is macOS-local.
    try:
        value = fcntl.fcntl(descriptor, 50, b"\0" * 1024)
        if isinstance(value, bytes):
            raw_path = value.split(b"\0", 1)[0]
            if raw_path:
                return Path(os.path.abspath(os.fsdecode(raw_path)))
    except OSError:
        pass
    try:
        return Path(os.path.abspath(os.readlink(f"/proc/self/fd/{descriptor}")))
    except OSError:
        raise RuntimeError("sqlite_connection_descriptor_path_unavailable") from None


def _new_regular_descriptors(
    before: Mapping[int, _SnapshotPathIdentity],
) -> dict[int, _SnapshotPathIdentity]:
    after = _process_file_descriptors()
    return {
        descriptor: identity
        for descriptor, identity in after.items()
        if before.get(descriptor) != identity
    }


class Database:
    _snapshot_identity_verifier: Callable[[], None] | None

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(path))
        connection: sqlite3.Connection | None = None
        detached_connection: sqlite3.Connection | None = None
        owned_identity_pins: list[int] = []
        pinned: (
            tuple[
                tuple[tuple[Path, int, tuple[int, int]], ...],
                tuple[Path, int, _SnapshotPathIdentity],
                tuple[Path, int, _SnapshotPathIdentity],
            ]
            | None
        ) = None
        with _catalog_process_lock(self.path):
            previous_umask = os.umask(0o077)
            try:
                pinned = _open_pinned_snapshot_path(
                    self.path,
                    create_if_missing=True,
                )
                ancestors, parent, database = pinned
                os.fchmod(database[1], 0o600)
                database = (
                    database[0],
                    database[1],
                    _snapshot_path_identity(os.fstat(database[1])),
                )
                pinned = (ancestors, parent, database)
                with _SQLITE_CONNECTION_IDENTITY_LOCK:
                    before_connect = _process_file_descriptors()
                    connection = sqlite3.connect(
                        self.path,
                        check_same_thread=False,
                        timeout=30,
                    )
                    opened_main = _new_regular_descriptors(before_connect)
                    if len(opened_main) != 1:
                        raise RuntimeError("sqlite_primary_connection_identity_invalid")
                    main_descriptor, main_identity = next(iter(opened_main.items()))
                    if (
                        main_identity != database[2]
                        or _descriptor_kernel_path(main_descriptor) != self.path
                    ):
                        raise RuntimeError("sqlite_primary_connection_identity_invalid")
                    connection.row_factory = sqlite3.Row
                    main_paths = [
                        Path(os.path.abspath(str(row[2])))
                        for row in connection.execute("PRAGMA database_list").fetchall()
                        if str(row[1]) == "main"
                    ]
                    if len(main_paths) != 1 or main_paths[0] != self.path:
                        raise RuntimeError("sqlite_primary_connection_identity_invalid")
                    before_wal = _process_file_descriptors()
                    connection.execute("PRAGMA foreign_keys = ON")
                    if (
                        str(
                            connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
                        ).casefold()
                        != "wal"
                    ):
                        raise RuntimeError("sqlite_primary_connection_wal_required")
                    connection.execute("PRAGMA synchronous = NORMAL")
                    connection.execute("PRAGMA busy_timeout = 30000")
                    connection.execute("BEGIN IMMEDIATE")
                    connection.rollback()
                    opened_wal = _new_regular_descriptors(before_wal)
                    expected_auxiliary_paths = {
                        Path(f"{self.path}-wal"),
                        Path(f"{self.path}-shm"),
                    }
                    actual_auxiliary_paths = {
                        _descriptor_kernel_path(descriptor) for descriptor in opened_wal
                    }
                    if (
                        len(opened_wal) > 2
                        or not actual_auxiliary_paths <= expected_auxiliary_paths
                    ):
                        raise RuntimeError("sqlite_primary_connection_wal_identity_invalid")
                    sqlite_files: list[tuple[Path, int, _SnapshotPathIdentity]] = [
                        (self.path, main_descriptor, main_identity)
                    ]
                    for descriptor in opened_wal:
                        auxiliary_path = _descriptor_kernel_path(descriptor)
                        os.fchmod(descriptor, 0o600)
                        descriptor_identity = _snapshot_path_identity(os.fstat(descriptor))
                        if (
                            _snapshot_path_identity(os.lstat(auxiliary_path)) != descriptor_identity
                            or not stat.S_ISREG(descriptor_identity[3])
                            or descriptor_identity[2] != os.getuid()
                            or stat.S_IMODE(descriptor_identity[3]) != 0o600
                            or descriptor_identity[4] != 1
                        ):
                            raise RuntimeError("sqlite_primary_connection_wal_identity_invalid")
                        sqlite_files.append((auxiliary_path, descriptor, descriptor_identity))
                    # SQLite shares a process-global SHM descriptor on macOS,
                    # so fd-delta inventory alone cannot assign both sidecars
                    # to a second connection.  Every Database instance owns
                    # independent no-follow pins for the exact WAL and SHM
                    # names; any SQLite-opened descriptors above must agree.
                    for auxiliary_path in sorted(expected_auxiliary_paths):
                        auxiliary_descriptor = os.open(
                            auxiliary_path.name,
                            os.O_RDONLY
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=parent[1],
                        )
                        owned_identity_pins.append(auxiliary_descriptor)
                        descriptor_identity = _snapshot_path_identity(
                            os.fstat(auxiliary_descriptor)
                        )
                        if (
                            _descriptor_kernel_path(auxiliary_descriptor) != auxiliary_path
                            or _snapshot_path_identity(os.lstat(auxiliary_path))
                            != descriptor_identity
                            or not stat.S_ISREG(descriptor_identity[3])
                            or descriptor_identity[2] != os.getuid()
                            or stat.S_IMODE(descriptor_identity[3]) != 0o600
                            or descriptor_identity[4] != 1
                        ):
                            raise RuntimeError("sqlite_primary_connection_wal_identity_invalid")
                        sqlite_files.append(
                            (auxiliary_path, auxiliary_descriptor, descriptor_identity)
                        )
                    before_detached_connect = _process_file_descriptors()
                    detached_connection = sqlite3.connect(
                        f"{self.path.as_uri()}?mode=ro",
                        uri=True,
                        check_same_thread=False,
                        timeout=30,
                    )
                    detached_main = _new_regular_descriptors(before_detached_connect)
                    if len(detached_main) != 1:
                        raise RuntimeError("sqlite_detached_connection_identity_invalid")
                    detached_main_descriptor, detached_main_identity = next(
                        iter(detached_main.items())
                    )
                    if (
                        detached_main_identity != database[2]
                        or _descriptor_kernel_path(detached_main_descriptor) != self.path
                    ):
                        raise RuntimeError("sqlite_detached_connection_identity_invalid")
                    detached_connection.row_factory = sqlite3.Row
                    detached_paths = [
                        Path(os.path.abspath(str(row[2])))
                        for row in detached_connection.execute("PRAGMA database_list").fetchall()
                        if str(row[1]) == "main"
                    ]
                    if len(detached_paths) != 1 or detached_paths[0] != self.path:
                        raise RuntimeError("sqlite_detached_connection_identity_invalid")
                    before_detached_wal = _process_file_descriptors()
                    detached_connection.execute("PRAGMA foreign_keys = ON")
                    detached_connection.execute("PRAGMA query_only = ON")
                    detached_connection.execute("PRAGMA busy_timeout = 30000")
                    detached_connection.execute("BEGIN")
                    detached_connection.execute("SELECT COUNT(*) FROM sqlite_schema").fetchone()
                    if (
                        str(
                            detached_connection.execute("PRAGMA journal_mode").fetchone()[0]
                        ).casefold()
                        != "wal"
                    ):
                        raise RuntimeError("sqlite_detached_connection_wal_required")
                    detached_connection.rollback()
                    detached_wal = _new_regular_descriptors(before_detached_wal)
                    detached_auxiliary_paths = {
                        _descriptor_kernel_path(descriptor) for descriptor in detached_wal
                    }
                    if len(detached_wal) > 2 or not (
                        detached_auxiliary_paths <= expected_auxiliary_paths
                    ):
                        raise RuntimeError("sqlite_detached_connection_wal_identity_invalid")
                    detached_files: list[tuple[Path, int, _SnapshotPathIdentity]] = [
                        (self.path, detached_main_descriptor, detached_main_identity)
                    ]
                    for descriptor in detached_wal:
                        auxiliary_path = _descriptor_kernel_path(descriptor)
                        descriptor_identity = _snapshot_path_identity(os.fstat(descriptor))
                        if (
                            _snapshot_path_identity(os.lstat(auxiliary_path)) != descriptor_identity
                            or descriptor_identity[2] != os.getuid()
                            or stat.S_IMODE(descriptor_identity[3]) != 0o600
                            or descriptor_identity[4] != 1
                        ):
                            raise RuntimeError("sqlite_detached_connection_wal_identity_invalid")
                        detached_files.append((auxiliary_path, descriptor, descriptor_identity))
                parent = (
                    parent[0],
                    parent[1],
                    _snapshot_path_identity(os.fstat(parent[1])),
                )
                pinned = (ancestors, parent, database)
                _require_pinned_snapshot_path_current(
                    ancestors=ancestors,
                    parent=parent,
                    database=database,
                    allowed_parent_nlinks={parent[2][4]},
                )
                self._connection = connection
                self._detached_connection = detached_connection
                self._database_path_ancestors = ancestors
                self._database_path_parent = parent
                self._database_path_identity = database
                self._sqlite_connection_files = tuple(sqlite_files)
                self._detached_connection_files = tuple(detached_files)
                self._owned_sqlite_identity_pins = tuple(owned_identity_pins)
            except BaseException:
                if detached_connection is not None:
                    with suppress(Exception):
                        detached_connection.close()
                if connection is not None:
                    with suppress(Exception):
                        connection.close()
                for descriptor in reversed(owned_identity_pins):
                    with suppress(OSError):
                        os.close(descriptor)
                if pinned is not None:
                    ancestors, _parent, database = pinned
                    with suppress(OSError):
                        os.close(database[1])
                    for _item_path, descriptor, _identity in reversed(ancestors):
                        with suppress(OSError):
                            os.close(descriptor)
                raise
            finally:
                os.umask(previous_umask)
        self._lock = threading.RLock()
        self._detached_lock = threading.RLock()
        self._closed = False
        self._snapshot_identity_verifier = None

    @staticmethod
    def _job_trace_ids(job_id: str) -> tuple[str, str]:
        trace_digest = hashlib.sha256(f"legalbot-job-trace-v1\0{job_id}".encode()).hexdigest()
        root_digest = hashlib.sha256(f"legalbot-job-root-v1\0{job_id}".encode()).hexdigest()
        return f"trace-{trace_digest[:40]}", f"span-{root_digest[:40]}"

    def close(self) -> None:
        failure: BaseException | None = None

        def remember(exc: BaseException) -> None:
            nonlocal failure
            if failure is None:
                failure = exc

        with self._detached_lock, self._lock:
            if self._closed:
                return
            # Integrity failures must not leak SQLite WAL locks or the retained
            # no-follow descriptor chain.  Attest both handles before closing
            # either, then perform best-effort cleanup and re-raise the first
            # failure only after every owned resource has been released.
            for verify in (
                self._require_detached_connection_identity_current,
                self._require_primary_connection_identity_current,
            ):
                try:
                    verify()
                except BaseException as exc:
                    remember(exc)
            for connection in (self._detached_connection, self._connection):
                try:
                    connection.close()
                except BaseException as exc:
                    remember(exc)
            try:
                _require_pinned_snapshot_path_current(
                    ancestors=self._database_path_ancestors,
                    parent=self._database_path_parent,
                    database=self._database_path_identity,
                )
            except BaseException as exc:
                remember(exc)
            descriptors = (
                *self._owned_sqlite_identity_pins,
                self._database_path_identity[1],
                *(
                    descriptor
                    for _path, descriptor, _identity in reversed(self._database_path_ancestors)
                ),
            )
            for descriptor in descriptors:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    remember(exc)
            self._closed = True
        if failure is not None:
            raise failure

    def _require_primary_connection_identity_current(self) -> None:
        _require_pinned_snapshot_path_current(
            ancestors=self._database_path_ancestors,
            parent=self._database_path_parent,
            database=self._database_path_identity,
        )
        main_paths = [
            Path(os.path.abspath(str(row[2])))
            for row in self._connection.execute("PRAGMA database_list").fetchall()
            if str(row[1]) == "main"
        ]
        if len(main_paths) != 1 or main_paths[0] != self.path:
            raise RuntimeError("sqlite_primary_connection_identity_changed")
        self._require_connection_files_current(
            self._sqlite_connection_files,
            error_code="sqlite_primary_connection_identity_changed",
        )

    @staticmethod
    def _require_connection_files_current(
        files: Sequence[tuple[Path, int, _SnapshotPathIdentity]],
        *,
        error_code: str,
    ) -> None:
        for path, descriptor, identity in files:
            if (
                _snapshot_path_identity(os.fstat(descriptor)) != identity
                or _snapshot_path_identity(os.lstat(path)) != identity
                or _descriptor_kernel_path(descriptor) != path
            ):
                raise RuntimeError(error_code)

    def _require_detached_connection_identity_current(self) -> None:
        _require_pinned_snapshot_path_current(
            ancestors=self._database_path_ancestors,
            parent=self._database_path_parent,
            database=self._database_path_identity,
        )
        main_paths = [
            Path(os.path.abspath(str(row[2])))
            for row in self._detached_connection.execute("PRAGMA database_list").fetchall()
            if str(row[1]) == "main"
        ]
        if len(main_paths) != 1 or main_paths[0] != self.path:
            raise RuntimeError("sqlite_detached_connection_identity_changed")
        self._require_connection_files_current(
            self._detached_connection_files,
            error_code="sqlite_detached_connection_identity_changed",
        )
        # A read-only handle may share the writer's SHM mapping without opening
        # a separately observable descriptor.  The retained primary main,
        # WAL, and SHM identities therefore also guard every detached read.
        self._require_connection_files_current(
            self._sqlite_connection_files,
            error_code="sqlite_detached_connection_identity_changed",
        )

    def initialize(self) -> None:
        """Initialise or migrate the catalogue once across API/worker processes."""

        with _catalog_process_lock(self.path):
            self._initialize_locked()

    def _initialize_locked(self) -> None:
        with self._lock:
            self._require_primary_connection_identity_current()
            self._connection.executescript(SCHEMA)
            from .runtime_records.schema import RUNTIME_RECORDS_SCHEMA

            self._connection.executescript(RUNTIME_RECORDS_SCHEMA)
            # Schema v25 permits SQLite foreign-key cleanup to clear stale job and
            # answer links while keeping every durable message byte and identity
            # immutable.  Recreate the trigger because CREATE IF NOT EXISTS cannot
            # replace the over-broad v24 definition in an existing catalogue.
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "DROP TRIGGER IF EXISTS trg_conversation_messages_no_update"
                )
                self._connection.execute(
                    """
                CREATE TRIGGER trg_conversation_messages_no_update
                BEFORE UPDATE ON conversation_messages
                WHEN OLD.id IS NOT NEW.id
                  OR OLD.conversation_id IS NOT NEW.conversation_id
                  OR OLD.ordinal IS NOT NEW.ordinal
                  OR OLD.role IS NOT NEW.role
                  OR OLD.encrypted_content IS NOT NEW.encrypted_content
                  OR OLD.content_sha256 IS NOT NEW.content_sha256
                  OR OLD.estimated_tokens IS NOT NEW.estimated_tokens
                  OR OLD.created_at IS NOT NEW.created_at
                  OR OLD.expires_at IS NOT NEW.expires_at
                  OR (OLD.job_id IS NULL AND NEW.job_id IS NOT NULL)
                  OR (OLD.job_id IS NOT NULL AND NEW.job_id IS NOT NULL
                      AND OLD.job_id IS NOT NEW.job_id)
                  OR (OLD.answer_id IS NULL AND NEW.answer_id IS NOT NULL)
                  OR (OLD.answer_id IS NOT NULL AND NEW.answer_id IS NOT NULL
                      AND OLD.answer_id IS NOT NEW.answer_id)
                BEGIN
                  SELECT RAISE(
                    ABORT,
                    'conversation message content and identity are immutable'
                  );
                END
                    """
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
            self._migrate_source_versions_v6()
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_source_versions_processing "
                "ON source_versions(document_id, version_sha256, "
                "processing_fingerprint, superseded_by)"
            )
            self._ensure_column("documents", "representation_group_id", "TEXT")
            self._ensure_column("documents", "retrieval_canonical", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("documents", "has_annotations", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("documents", "searchable_text", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("documents", "dedupe_status", "TEXT NOT NULL DEFAULT 'new'")
            self._ensure_column("chunks", "stream", "TEXT NOT NULL DEFAULT 'body'")
            self._ensure_column("uploads", "encrypted_blob", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("uploads", "retention_until", "TEXT")
            self._ensure_column("uploads", "review_pinned", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("uploads", "review_completed_at", "TEXT")
            self._ensure_column(
                "uploads", "quarantine_status", "TEXT NOT NULL DEFAULT 'unreviewed'"
            )
            self._ensure_column("refinements", "fingerprint", "TEXT")
            self._ensure_column("research_candidates", "review_id", "TEXT")
            self._ensure_column("research_candidates", "system_verification_sha256", "TEXT")
            self._ensure_column("research_candidates", "system_verified_at", "TEXT")
            self._ensure_column("research_candidates", "intake_review_id", "TEXT")
            self._ensure_column(
                "research_candidates",
                "identity_review_state",
                "TEXT NOT NULL DEFAULT 'unreviewed'",
            )
            self._ensure_column(
                "research_candidates",
                "currentness_review_state",
                "TEXT NOT NULL DEFAULT 'unreviewed'",
            )
            self._ensure_column("research_candidates", "reviewer_ref", "TEXT")
            self._ensure_column("research_candidates", "review_manifest_sha256", "TEXT")
            self._ensure_column("research_tasks", "source_locator", "TEXT")
            self._ensure_column(
                "source_update_observations",
                "materiality_status",
                "TEXT NOT NULL DEFAULT 'unassessed'",
            )
            self._ensure_column(
                "source_update_observations",
                "review_status",
                "TEXT NOT NULL DEFAULT 'pending'",
            )
            self._ensure_column("source_update_observations", "review_id", "TEXT")
            self._ensure_column("source_update_observations", "reviewer_ref", "TEXT")
            self._ensure_column("source_update_observations", "review_manifest_sha256", "TEXT")
            self._ensure_column(
                "source_update_observations",
                "scope_kind",
                "TEXT NOT NULL DEFAULT 'authority'",
            )
            self._ensure_column("source_update_observations", "legal_locator", "TEXT")
            self._ensure_column("source_update_observations", "proposition_sha256", "TEXT")
            self._ensure_column("knowledge_update_events", "as_of_date", "TEXT")
            # Existing v24 catalogues already have this trigger, so the schema's
            # CREATE IF NOT EXISTS cannot add the new immutable as-of coordinate.
            self._connection.execute(
                "DROP TRIGGER IF EXISTS trg_knowledge_update_event_identity_no_update"
            )
            self._connection.execute(
                """
                CREATE TRIGGER trg_knowledge_update_event_identity_no_update
                BEFORE UPDATE OF id,idempotency_key,event_type,source_id,
                  authority_identity_id,knowledge_gap_id,subject,jurisdiction,
                  source_date,as_of_date,observed_at,query_sha256,
                  safe_payload_json,encrypted_detail ON knowledge_update_events
                BEGIN
                  SELECT RAISE(ABORT, 'knowledge update event identity is immutable');
                END
                """
            )
            self._connection.execute(
                "UPDATE refinements SET fingerprint=id WHERE fingerprint IS NULL OR fingerprint=''"
            )
            self._connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_refinements_fingerprint "
                "ON refinements(fingerprint)"
            )
            self._migrate_document_canonicals_v7()
            self._ensure_column("answer_versions", "encrypted_diff_from_parent", "BLOB")
            self._ensure_column("source_versions", "authority_identity_id", "TEXT")
            self._ensure_column("answer_versions", "policy_sha256", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("quality_reports", "policy_sha256", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("quality_reports", "ai_evidence_review_json", "TEXT")
            self._ensure_column("quality_reports", "ai_evidence_adjudication_json", "TEXT")
            self._ensure_column("quality_reports", "assessment_standards_json", "TEXT")
            self._ensure_column("quality_reports", "encrypted_source_draft", "BLOB")
            self._ensure_column("evaluation_runs", "policy_sha256", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(
                "evaluation_runs",
                "assessment_bundle_sha256",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column("evaluation_runs", "as_of_date", "TEXT")
            self._ensure_column("evidence_spans", "retrieval_relevance_score", "REAL")
            self._ensure_column("evidence_spans", "retrieval_route", "TEXT")
            self._ensure_column("evidence_spans", "retrieval_threshold", "REAL")
            self._ensure_column(
                "evidence_spans", "retrieval_threshold_policy_sha256", "TEXT"
            )
            self._ensure_column(
                "evidence_spans", "retrieval_threshold_qualified", "INTEGER"
            )
            self._ensure_column(
                "evidence_spans", "retrieval_qualification_reason", "TEXT"
            )
            self._ensure_column(
                "evidence_spans", "legal_role", "TEXT NOT NULL DEFAULT 'unclassified'"
            )
            self._ensure_column("evidence_spans", "unapplied_effect_count", "INTEGER")
            self._ensure_column(
                "evidence_spans",
                "provision_extent_status",
                "TEXT NOT NULL DEFAULT 'unverified'",
            )
            self._ensure_column("claims", "encrypted_claim_text", "BLOB")
            self._ensure_column("claims", "model_claim_id", "TEXT")
            self._ensure_column("claims", "proposition_hash", "TEXT")
            self._ensure_column(
                "evidence_spans",
                "case_currentness_reviews_json",
                "TEXT NOT NULL DEFAULT '[]'",
            )
            self._ensure_column(
                "evidence_spans",
                "case_currentness_manifest_seals_json",
                "TEXT NOT NULL DEFAULT '[]'",
            )
            self._ensure_column("reviews", "encrypted_decision_note", "BLOB")
            self._ensure_column("jobs", "route", "TEXT NOT NULL DEFAULT 'direct'")
            self._ensure_column("jobs", "route_reasons_json", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column("jobs", "lease_owner", "TEXT")
            self._ensure_column("jobs", "lease_expires_at", "TEXT")
            self._ensure_column("jobs", "heartbeat_at", "TEXT")
            self._ensure_column("jobs", "attempt_count", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("jobs", "idempotency_key", "TEXT")
            self._ensure_column("jobs", "cancel_requested", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("jobs", "pinned_index_build_id", "TEXT")
            self._ensure_column("jobs", "job_type", "TEXT NOT NULL DEFAULT 'answer'")
            self._ensure_column("jobs", "queue_wait_deadline_at", "TEXT")
            self._ensure_column("jobs", "workflow_deadline_at", "TEXT")
            self._ensure_column("jobs", "stage_started_at", "TEXT")
            self._ensure_column("jobs", "stage_deadline_at", "TEXT")
            self._ensure_column("jobs", "model_call_deadline_at", "TEXT")
            self._ensure_column("jobs", "model_call_token", "TEXT")
            self._ensure_column("jobs", "terminal_reason_code", "TEXT")
            self._ensure_column("jobs", "dlq", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("jobs", "evaluation_run_id", "TEXT")
            self._ensure_column("jobs", "evaluation_case_id", "TEXT")
            self._ensure_column("jobs", "evaluation_request_sha256", "TEXT")
            self._ensure_column("jobs", "evaluation_authority_json", "TEXT")
            self._ensure_column("jobs", "evaluation_authority_sha256", "TEXT")
            self._ensure_column("jobs", "worker_prompt_version", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("jobs", "worker_router_version", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("jobs", "worker_classifier_version", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("jobs", "worker_policy_sha256", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("jobs", "assessment_bundle_sha256", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(
                "jobs", "issue_plan_proposition_keys_json", "TEXT NOT NULL DEFAULT '[]'"
            )
            self._ensure_column("jobs", "trace_id", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("jobs", "trace_root_span_id", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("jobs", "trace_full_retention", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("jobs", "last_progress_at", "TEXT")
            self._ensure_column("jobs", "word_target", "INTEGER NOT NULL DEFAULT 1500")
            self._ensure_column("release_outbox", "evaluation_authority_sha256", "TEXT")
            self._ensure_column("release_outbox", "normal_live_authority_sha256", "TEXT")
            self._ensure_column("release_outbox", "owner_canary_content_graph_sha256", "TEXT")
            self._ensure_column("release_outbox", "answer_sha256", "TEXT")
            self._ensure_column(
                "release_outbox", "release_audience", "TEXT NOT NULL DEFAULT 'normal_live'"
            )
            self._connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_release_outbox_binding_no_replace
                BEFORE INSERT ON release_outbox
                WHEN EXISTS (
                  SELECT 1 FROM release_outbox existing
                  WHERE existing.id=NEW.id
                     OR existing.job_id=NEW.job_id
                     OR existing.answer_id=NEW.answer_id
                     OR existing.idempotency_key=NEW.idempotency_key
                )
                BEGIN
                  SELECT RAISE(ABORT, 'bound release outbox identity cannot be replaced');
                END
                """
            )
            self._connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_release_outbox_content_binding_immutable
                BEFORE UPDATE OF owner_canary_content_graph_sha256,answer_sha256
                ON release_outbox
                WHEN OLD.owner_canary_content_graph_sha256
                       IS NOT NEW.owner_canary_content_graph_sha256
                  OR OLD.answer_sha256 IS NOT NEW.answer_sha256
                BEGIN
                  SELECT RAISE(ABORT, 'release outbox content binding is immutable');
                END
                """
            )
            self._connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_release_outbox_owner_binding_no_update
                BEFORE UPDATE ON release_outbox
                WHEN OLD.owner_canary_content_graph_sha256 IS NOT NULL
                  OR OLD.answer_sha256 IS NOT NULL
                BEGIN
                  SELECT RAISE(ABORT, 'bound owner release outbox is immutable');
                END
                """
            )
            self._connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_release_outbox_owner_binding_no_delete
                BEFORE DELETE ON release_outbox
                WHEN OLD.owner_canary_content_graph_sha256 IS NOT NULL
                  OR OLD.answer_sha256 IS NOT NULL
                BEGIN
                  SELECT RAISE(ABORT, 'bound owner release outbox is immutable');
                END
                """
            )
            self._ensure_column(
                "retry_decisions", "input_identity_sha256", "TEXT NOT NULL DEFAULT ''"
            )
            self._ensure_column(
                "retry_decisions", "condition_identity_sha256", "TEXT NOT NULL DEFAULT ''"
            )
            for job in self._connection.execute(
                "SELECT id, trace_id, trace_root_span_id, last_progress_at, "
                "updated_at, request_json, word_target FROM jobs"
            ).fetchall():
                trace_id, root_span_id = self._job_trace_ids(str(job["id"]))
                requested_target = 1_500
                try:
                    request_value = json.loads(str(job["request_json"] or "{}"))
                    requested_target = int(request_value.get("word_target", 1_500))
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
                self._connection.execute(
                    """
                    UPDATE jobs SET
                      trace_id=CASE WHEN trace_id='' THEN ? ELSE trace_id END,
                      trace_root_span_id=CASE WHEN trace_root_span_id='' THEN ?
                        ELSE trace_root_span_id END,
                      last_progress_at=COALESCE(last_progress_at, updated_at),
                      word_target=CASE WHEN word_target=1500 THEN ? ELSE word_target END
                    WHERE id=?
                    """,
                    (trace_id, root_span_id, requested_target, job["id"]),
                )
            self._ensure_column("job_stage_attempts", "output_object_key", "TEXT")
            self._ensure_column("evidence_packs", "object_key", "TEXT")
            self._ensure_column("index_builds", "corpus_id", "TEXT")
            self._ensure_column("index_builds", "scoped_corpus_id", "TEXT")
            self._ensure_column("index_builds", "source_manifest_hash", "TEXT")
            self._ensure_column("index_builds", "parser_version", "TEXT")
            self._ensure_column("index_builds", "chunker_version", "TEXT")
            self._ensure_column("index_builds", "index_schema_version", "TEXT")
            self._ensure_column("index_builds", "embedding_model_version", "TEXT")
            self._ensure_column("index_builds", "rerank_version", "TEXT")
            self._ensure_column("index_builds", "stage", "TEXT NOT NULL DEFAULT 'queued'")
            self._ensure_column("index_builds", "stage_started_at", "TEXT")
            self._ensure_column("index_builds", "stage_timings_json", "TEXT NOT NULL DEFAULT '{}'")
            self._ensure_column("index_builds", "failure_count", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("index_builds", "failure_reason_code", "TEXT")
            self._ensure_column("index_builds", "job_id", "TEXT")
            self._ensure_column("index_builds", "idempotency_key", "TEXT")
            self._ensure_column("index_builds", "candidate_manifest_hash", "TEXT")
            self._ensure_column(
                "index_builds", "benchmark_result_json", "TEXT NOT NULL DEFAULT '{}'"
            )
            self._ensure_column("index_builds", "counts_json", "TEXT NOT NULL DEFAULT '{}'")
            self._ensure_column(
                "index_builds",
                "promotion_decision",
                "TEXT NOT NULL DEFAULT 'not_requested'",
            )
            self._ensure_column("index_builds", "policy_sha256", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(
                "index_builds", "assessment_bundle_sha256", "TEXT NOT NULL DEFAULT ''"
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_source_versions_authority_identity "
                "ON source_versions(authority_identity_id, created_at)"
            )
            self._connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_source_versions_authority_identity
                AFTER INSERT ON source_versions
                WHEN NEW.authority_identity_id IS NULL OR NEW.authority_identity_id=''
                BEGIN
                  UPDATE source_versions SET authority_identity_id=CASE
                    WHEN instr(NEW.stable_identifier, ':latest-available@') > 0
                      THEN substr(NEW.stable_identifier, 1,
                                  instr(NEW.stable_identifier, ':latest-available@') - 1)
                    WHEN NEW.stable_identifier LIKE '%:enacted'
                      THEN substr(NEW.stable_identifier, 1, length(NEW.stable_identifier) - 8)
                    ELSE NEW.stable_identifier END
                  WHERE id=NEW.id;
                END
                """
            )
            self._connection.execute(
                "UPDATE source_versions SET authority_identity_id=CASE "
                "WHEN instr(stable_identifier, ':latest-available@') > 0 "
                "THEN substr(stable_identifier,1,instr(stable_identifier, ':latest-available@')-1) "
                "WHEN stable_identifier LIKE '%:enacted' "
                "THEN substr(stable_identifier,1,length(stable_identifier)-8) "
                "ELSE stable_identifier END "
                "WHERE authority_identity_id IS NULL OR authority_identity_id=''"
            )
            self._connection.execute(
                "UPDATE source_versions SET currentness_status='latest_available_revised_snapshot' "
                "WHERE stable_identifier LIKE '%:latest-available@2026-08-12' "
                "AND currentness_status='point_in_time'"
            )
            self._connection.execute(
                "UPDATE evidence_spans SET retrieval_relevance_score=entailment_score "
                "WHERE retrieval_relevance_score IS NULL AND entailment_score IS NOT NULL"
            )
            self._connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_index_builds_idempotency "
                "ON index_builds(idempotency_key) WHERE idempotency_key IS NOT NULL"
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_jobs_type_status "
                "ON jobs(job_type, status, created_at)"
            )
            self._ensure_column("knowledge_gaps", "encrypted_missing_proposition", "BLOB")
            self._ensure_column("knowledge_gaps", "proposition_sha256", "TEXT")
            self._ensure_column(
                "source_scans",
                "resumed_from_scan_id",
                "TEXT REFERENCES source_scans(id)",
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_source_scans_resumed_from "
                "ON source_scans(resumed_from_scan_id, created_at DESC)"
            )
            self._connection.execute(
                "UPDATE claims SET model_claim_id=id "
                "WHERE model_claim_id IS NULL OR model_claim_id=''"
            )
            self._connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_claims_answer_model_id "
                "ON claims(answer_version_id, model_claim_id)"
            )
            self._connection.execute(
                "UPDATE chunks SET stream=CASE "
                "WHEN json_valid(metadata_json) "
                "THEN COALESCE(json_extract(metadata_json, '$.stream'), 'body') "
                "ELSE 'body' END"
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_documents_representation_group "
                "ON documents(representation_group_id, retrieval_canonical)"
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_chunks_stream ON chunks(stream, source_version_id)"
            )
            self._connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_idempotency "
                "ON jobs(idempotency_key) WHERE idempotency_key IS NOT NULL"
            )
            self._connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_evaluation_request "
                "ON jobs(evaluation_run_id, evaluation_case_id) "
                "WHERE evaluation_request_sha256 IS NOT NULL"
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_jobs_lease "
                "ON jobs(status, lease_expires_at, created_at)"
            )
            for row in self._connection.execute(
                "SELECT id, required_roots_json, roots_seen_json FROM source_scans"
            ).fetchall():
                self._connection.execute(
                    "UPDATE source_scans SET required_roots_json=?, roots_seen_json=? WHERE id=?",
                    (
                        _scrub_root_descriptors(row["required_roots_json"]),
                        _scrub_root_descriptors(row["roots_seen_json"]),
                        row["id"],
                    ),
                )
            self._ensure_single_active_source_scan()
            require_release_outbox_schema_contract(self._connection)
            self._connection.execute(
                "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(SCHEMA_VERSION),),
            )
            self._connection.execute("PRAGMA optimize")
            self._connection.commit()
            self._require_primary_connection_identity_current()

    def _migrate_source_versions_v6(self) -> None:
        """Add immutable processing representations without rewriting their children."""

        columns = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(source_versions)").fetchall()
        }
        if {"processing_fingerprint", "superseded_by"} <= columns:
            return

        self._connection.commit()
        self._connection.execute("PRAGMA foreign_keys = OFF")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                """
                CREATE TABLE source_versions_v6 (
                  id TEXT PRIMARY KEY,
                  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                  version_sha256 TEXT NOT NULL,
                  canonical_markdown_path TEXT NOT NULL,
                  title TEXT,
                  author_or_body TEXT,
                  source_date TEXT,
                  as_of_date TEXT,
                  canonical_url TEXT,
                  stable_identifier TEXT,
                  currentness_status TEXT NOT NULL DEFAULT 'unknown',
                  licence_name TEXT,
                  licence_url TEXT,
                  review_status TEXT NOT NULL DEFAULT 'staged',
                  processing_fingerprint TEXT NOT NULL DEFAULT 'legacy',
                  superseded_by TEXT REFERENCES source_versions_v6(id),
                  metadata_json TEXT NOT NULL DEFAULT '{}',
                  created_at TEXT NOT NULL,
                  UNIQUE(document_id, version_sha256, processing_fingerprint)
                )
                """
            )
            self._connection.execute(
                """
                INSERT INTO source_versions_v6(
                  id, document_id, version_sha256, canonical_markdown_path, title,
                  author_or_body, source_date, as_of_date, canonical_url,
                  stable_identifier, currentness_status, licence_name, licence_url,
                  review_status, processing_fingerprint, superseded_by,
                  metadata_json, created_at
                )
                SELECT id, document_id, version_sha256, canonical_markdown_path, title,
                       author_or_body, source_date, as_of_date, canonical_url,
                       stable_identifier, currentness_status, licence_name, licence_url,
                       review_status, 'legacy', NULL, metadata_json, created_at
                FROM source_versions
                """
            )
            self._connection.execute("DROP TABLE source_versions")
            self._connection.execute("ALTER TABLE source_versions_v6 RENAME TO source_versions")
            self._connection.execute(
                "CREATE INDEX idx_source_versions_review "
                "ON source_versions(review_status, currentness_status)"
            )
            self._connection.execute(
                "CREATE INDEX idx_source_versions_stable_identifier "
                "ON source_versions(stable_identifier)"
            )
            self._connection.execute(
                "CREATE INDEX idx_source_versions_processing "
                "ON source_versions(document_id, version_sha256, "
                "processing_fingerprint, superseded_by)"
            )
            violations = self._connection.execute("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise RuntimeError("source-version v6 migration failed foreign-key validation")
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        finally:
            self._connection.execute("PRAGMA foreign_keys = ON")

    def _migrate_document_canonicals_v7(self) -> None:
        """Separate physical-byte dedupe from logical source eligibility."""

        recorded = self._connection.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        indexes = {
            str(row["name"])
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        if (
            recorded is not None
            and int(recorded["value"]) >= 7
            and "idx_documents_semantic_content_canonical" in indexes
            and "idx_documents_semantic_retrieval_canonical" in indexes
        ):
            return

        def normalized(value: Any) -> str:
            return str(value or "")

        def effective_status(row: Mapping[str, Any]) -> str:
            status = str(row["status"])
            if status != "duplicate":
                return status
            try:
                metadata = json.loads(str(row["current_metadata_json"] or "{}"))
            except (TypeError, ValueError, json.JSONDecodeError):
                return "quarantined"
            parser_status = metadata.get("parser_status") if isinstance(metadata, dict) else None
            if parser_status == "ready":
                return {
                    "assessment_guidance": "assessment_guidance",
                    "private_teaching": "private_teaching",
                }.get(normalized(row["lane"]), "citable")
            return {
                "ocr_required": "ocr_required",
                "encrypted": "encrypted",
                "unsupported": "unsupported",
                "parser_unavailable": "unsupported",
            }.get(str(parser_status), "quarantined")

        def rank(row: Mapping[str, Any], status: str) -> tuple[int, int, int, str, str, str]:
            status_rank = {
                "citable": 0,
                "private_teaching": 1,
                "assessment_guidance": 2,
                "ocr_required": 3,
                "encrypted": 4,
                "unsupported": 5,
                "quarantined": 6,
                "duplicate": 7,
            }.get(status, 8)
            annotated_feedback = (
                normalized(row["lane"]) == "assessment_guidance"
                and normalized(row["media_type"])
                == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                and bool(row["has_annotations"])
            )
            searchable_pdf = normalized(row["media_type"]) == "application/pdf" and bool(
                row["searchable_text"]
            )
            source_preference = 0 if annotated_feedback else 1 if searchable_pdf else 2
            searchable_rank = 0 if bool(row["searchable_text"]) or annotated_feedback else 1
            return (
                status_rank,
                searchable_rank,
                source_preference,
                normalized(row["media_type"]),
                normalized(row["created_at"]),
                normalized(row["id"]),
            )

        self._connection.execute("SAVEPOINT migrate_document_canonicals_v7")
        try:
            self._connection.execute("DROP INDEX IF EXISTS idx_documents_content_sha256_canonical")
            self._connection.execute("DROP INDEX IF EXISTS idx_documents_one_retrieval_canonical")
            rows = self._connection.execute(
                """
                SELECT d.*,
                       (SELECT sv.metadata_json FROM source_versions sv
                        WHERE sv.document_id=d.id AND sv.superseded_by IS NULL
                        ORDER BY sv.created_at DESC, sv.id DESC LIMIT 1)
                         AS current_metadata_json,
                       (SELECT sv.id FROM source_versions sv
                        WHERE sv.document_id=d.id AND sv.superseded_by IS NULL
                        ORDER BY sv.created_at DESC, sv.id DESC LIMIT 1)
                         AS current_source_version_id,
                       (SELECT sv.review_status FROM source_versions sv
                        WHERE sv.document_id=d.id AND sv.superseded_by IS NULL
                        ORDER BY sv.created_at DESC, sv.id DESC LIMIT 1)
                         AS current_source_review_status
                FROM documents d ORDER BY d.created_at, d.id
                """
            ).fetchall()
            partitions: dict[tuple[str, str, str, str], list[Any]] = {}
            for row in rows:
                key = (
                    normalized(row["content_sha256"]),
                    normalized(row["lane"]),
                    normalized(row["jurisdiction"]),
                    normalized(row["subject_primary"]),
                )
                partitions.setdefault(key, []).append(row)

            promoted_document_ids: set[str] = set()
            for partition_rows in partitions.values():
                statuses = {normalized(row["id"]): effective_status(row) for row in partition_rows}
                winner = min(
                    partition_rows,
                    key=lambda row: rank(row, statuses[normalized(row["id"])]),
                )
                winner_id = normalized(winner["id"])
                if winner["duplicate_of"] is not None:
                    promoted_document_ids.add(winner_id)
                for row in partition_rows:
                    row_id = normalized(row["id"])
                    if row_id == winner_id:
                        continue
                    self._connection.execute(
                        """
                        UPDATE documents
                        SET duplicate_of=?, status='duplicate', retrieval_canonical=0
                        WHERE id=?
                        """,
                        (winner_id, row_id),
                    )
                self._connection.execute(
                    """
                    UPDATE documents SET duplicate_of=NULL, status=? WHERE id=?
                    """,
                    (statuses[winner_id], winner_id),
                )

            now = utc_iso()
            if promoted_document_ids:
                placeholders = ",".join("?" for _ in promoted_document_ids)
                self._connection.execute(
                    f"""
                    UPDATE source_versions SET review_status='staged'
                    WHERE superseded_by IS NULL AND document_id IN ({placeholders})
                    """,
                    tuple(sorted(promoted_document_ids)),
                )
            self._connection.execute(
                """
                UPDATE reviews
                SET status='rejected',
                    reason='Logical duplicate within semantic partition; review the canonical source',
                    decision_note='Superseded by the semantic-partition canonical',
                    decided_at=?
                WHERE review_type='source_version' AND status='pending'
                  AND target_id IN (
                    SELECT sv.id FROM source_versions sv
                    JOIN documents d ON d.id=sv.document_id
                    WHERE sv.superseded_by IS NULL AND d.duplicate_of IS NOT NULL
                  )
                """,
                (now,),
            )
            staged_canonicals = self._connection.execute(
                """
                SELECT sv.id, d.lane FROM source_versions sv
                JOIN documents d ON d.id=sv.document_id
                WHERE sv.superseded_by IS NULL AND sv.review_status='staged'
                  AND sv.version_sha256=d.content_sha256
                  AND d.duplicate_of IS NULL
                """
            ).fetchall()
            for row in staged_canonicals:
                source_version_id = normalized(row["id"])
                review_id = (
                    "review-" + hashlib.sha256(source_version_id.encode("utf-8")).hexdigest()[:40]
                )
                reason = (
                    f"Source-admission review required before {normalized(row['lane'])} "
                    "enters a candidate build"
                )
                self._connection.execute(
                    """
                    INSERT OR IGNORE INTO reviews(
                      id, review_type, target_id, status, reason, created_at
                    ) VALUES (?, 'source_version', ?, 'pending', ?, ?)
                    """,
                    (review_id, source_version_id, reason, now),
                )
                self._connection.execute(
                    """
                    UPDATE reviews
                    SET status='pending', reason=?, decision_note=NULL, decided_at=NULL
                    WHERE id=? AND review_type='source_version' AND target_id=?
                    """,
                    (reason, review_id, source_version_id),
                )
                self._connection.execute(
                    """
                    UPDATE reviews
                    SET status='rejected',
                        reason='Duplicate review record retired for the canonical source',
                        decision_note='Canonical source uses one actionable review',
                        decided_at=?
                    WHERE review_type='source_version' AND target_id=?
                      AND status='pending' AND id<>?
                    """,
                    (now, source_version_id, review_id),
                )

            self._connection.execute("UPDATE documents SET retrieval_canonical=0")
            canonical_rows = [
                row
                for row in self._connection.execute(
                    """
                    SELECT d.*,
                           (SELECT sv.metadata_json FROM source_versions sv
                            WHERE sv.document_id=d.id AND sv.superseded_by IS NULL
                            ORDER BY sv.created_at DESC, sv.id DESC LIMIT 1)
                             AS current_metadata_json
                    FROM documents d WHERE d.duplicate_of IS NULL
                    ORDER BY d.created_at, d.id
                    """
                ).fetchall()
                if row["representation_group_id"] is not None
            ]
            representation_partitions: dict[tuple[str, str, str, str], list[Any]] = {}
            for row in canonical_rows:
                key = (
                    normalized(row["representation_group_id"]),
                    normalized(row["lane"]),
                    normalized(row["jurisdiction"]),
                    normalized(row["subject_primary"]),
                )
                representation_partitions.setdefault(key, []).append(row)
            for partition_rows in representation_partitions.values():
                winner = min(
                    partition_rows,
                    key=lambda row: rank(row, effective_status(row)),
                )
                self._connection.execute(
                    "UPDATE documents SET retrieval_canonical=1 WHERE id=?",
                    (winner["id"],),
                )

            self._connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_semantic_content_canonical
                ON documents(
                  content_sha256,
                  COALESCE(lane, ''),
                  COALESCE(jurisdiction, ''),
                  COALESCE(subject_primary, '')
                ) WHERE duplicate_of IS NULL
                """
            )
            self._connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_semantic_retrieval_canonical
                ON documents(
                  representation_group_id,
                  COALESCE(lane, ''),
                  COALESCE(jurisdiction, ''),
                  COALESCE(subject_primary, '')
                )
                WHERE retrieval_canonical=1 AND duplicate_of IS NULL
                  AND representation_group_id IS NOT NULL
                """
            )
            mismatch = self._connection.execute(
                """
                SELECT 1 FROM documents child
                JOIN documents parent ON parent.id=child.duplicate_of
                WHERE child.content_sha256<>parent.content_sha256
                   OR COALESCE(child.lane, '')<>COALESCE(parent.lane, '')
                   OR COALESCE(child.jurisdiction, '')<>COALESCE(parent.jurisdiction, '')
                   OR COALESCE(child.subject_primary, '')<>COALESCE(parent.subject_primary, '')
                LIMIT 1
                """
            ).fetchone()
            if mismatch is not None:
                raise RuntimeError("semantic canonical migration left an invalid duplicate link")
            violations = self._connection.execute("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise RuntimeError("document canonical v7 migration failed foreign-key validation")
            self._connection.execute("RELEASE SAVEPOINT migrate_document_canonicals_v7")
        except Exception:
            self._connection.execute("ROLLBACK TO SAVEPOINT migrate_document_canonicals_v7")
            self._connection.execute("RELEASE SAVEPOINT migrate_document_canonicals_v7")
            raise

    def _ensure_single_active_source_scan(self) -> None:
        """Repair an older ambiguous state, then enforce one active scan in SQLite."""

        active = self._connection.execute(
            """
            SELECT id, status FROM source_scans
            WHERE status IN ('queued', 'running')
            ORDER BY CASE status WHEN 'running' THEN 0 ELSE 1 END,
                     COALESCE(started_at, created_at), created_at, id
            """
        ).fetchall()
        if len(active) > 1:
            now = utc_iso()
            for row in active[1:]:
                self._connection.execute(
                    """
                    UPDATE source_scans
                    SET status='failed', files_accounted=(
                          SELECT COUNT(*) FROM source_scan_files WHERE scan_id=source_scans.id
                        ),
                        error_code='concurrent_scan_reconciled',
                        error_message='Older database state contained more than one active scan',
                        completed_at=COALESCE(completed_at, ?)
                    WHERE id=? AND status IN ('queued', 'running')
                    """,
                    (now, row["id"]),
                )
        self._connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_source_scans_single_active
            ON source_scans((1)) WHERE status IN ('queued', 'running')
            """
        )

    def _ensure_column(self, table: str, column: str, declaration: str) -> None:
        columns = {
            str(row["name"])
            for row in self._connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            self._connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

    def migrate_sensitive_content(self, cipher: LocalCipher) -> dict[str, int]:
        """Encrypt legacy operational prose before the application serves requests."""

        migrated_claims = 0
        migrated_diffs = 0
        migrated_jobs = 0
        migrated_gaps = 0
        migrated_review_notes = 0
        with self.transaction() as conn:
            jobs = conn.execute("SELECT id, request_json, question_summary FROM jobs").fetchall()
            for row in jobs:
                rewrite = False
                try:
                    request = json.loads(row["request_json"])
                except (TypeError, json.JSONDecodeError):
                    request = {}
                    rewrite = True
                if not isinstance(request, dict):
                    request = {}
                    rewrite = True
                if "question" in request:
                    request.pop("question", None)
                    rewrite = True
                if rewrite:
                    conn.execute(
                        "UPDATE jobs SET request_json=? WHERE id=?",
                        (json.dumps(request), row["id"]),
                    )
                    migrated_jobs += 1
                if str(row["question_summary"]) != PRIVATE_QUESTION_SUMMARY:
                    conn.execute(
                        "UPDATE jobs SET question_summary=? WHERE id=?",
                        (PRIVATE_QUESTION_SUMMARY, row["id"]),
                    )
                    migrated_jobs += 1
            claims = conn.execute(
                """
                SELECT id, claim_text FROM claims
                WHERE encrypted_claim_text IS NULL AND claim_text <> ''
                """
            ).fetchall()
            for row in claims:
                conn.execute(
                    "UPDATE claims SET encrypted_claim_text=?, claim_text='' WHERE id=?",
                    (cipher.encrypt_text(str(row["claim_text"])), row["id"]),
                )
                migrated_claims += 1
            diffs = conn.execute(
                """
                SELECT id, diff_from_parent FROM answer_versions
                WHERE encrypted_diff_from_parent IS NULL
                  AND diff_from_parent IS NOT NULL AND diff_from_parent <> ''
                """
            ).fetchall()
            for row in diffs:
                conn.execute(
                    """
                    UPDATE answer_versions
                    SET encrypted_diff_from_parent=?, diff_from_parent=NULL WHERE id=?
                    """,
                    (cipher.encrypt_text(str(row["diff_from_parent"])), row["id"]),
                )
                migrated_diffs += 1
            gaps = conn.execute(
                """
                SELECT id, missing_proposition FROM knowledge_gaps
                WHERE encrypted_missing_proposition IS NULL
                  AND missing_proposition NOT IN ('', '[encrypted]')
                """
            ).fetchall()
            for row in gaps:
                proposition = str(row["missing_proposition"])
                conn.execute(
                    """
                    UPDATE knowledge_gaps
                    SET encrypted_missing_proposition=?, proposition_sha256=?,
                        missing_proposition='[encrypted]'
                    WHERE id=?
                    """,
                    (
                        cipher.encrypt_text(proposition),
                        hashlib.sha256(proposition.encode("utf-8")).hexdigest(),
                        row["id"],
                    ),
                )
                migrated_gaps += 1
            review_notes = conn.execute(
                """
                SELECT id, decision_note FROM reviews
                WHERE encrypted_decision_note IS NULL
                  AND decision_note IS NOT NULL AND decision_note <> ''
                """
            ).fetchall()
            for row in review_notes:
                conn.execute(
                    """
                    UPDATE reviews
                    SET encrypted_decision_note=?, decision_note='[encrypted]'
                    WHERE id=?
                    """,
                    (cipher.encrypt_text(str(row["decision_note"])), row["id"]),
                )
                migrated_review_notes += 1
        return {
            "jobs": migrated_jobs,
            "claims": migrated_claims,
            "diffs": migrated_diffs,
            "gaps": migrated_gaps,
            "review_notes": migrated_review_notes,
        }

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self._require_primary_connection_identity_current()
                self._connection.execute("BEGIN IMMEDIATE")
                yield self._connection
                self._require_primary_connection_identity_current()
                self._connection.commit()
                self._require_primary_connection_identity_current()
            except Exception:
                self._connection.rollback()
                raise

    @contextmanager
    def read_snapshot(self) -> Iterator[sqlite3.Connection]:
        """Hold one SQLite read snapshot while a released DTO is verified and built."""

        with self._lock:
            try:
                self._require_primary_connection_identity_current()
                self._connection.execute("BEGIN")
                yield self._connection
            finally:
                # A read path must never commit incidental state.  ROLLBACK also
                # closes the snapshot after ordinary successful reads.
                self._connection.rollback()
                self._require_primary_connection_identity_current()

    def snapshot_view(self, connection: sqlite3.Connection) -> Database:
        """Return a read-only-use Database facade over an already pinned connection."""

        detached = connection is self._detached_connection
        primary = connection is self._connection
        if not detached and not primary:
            raise RuntimeError("database_snapshot_identity_invalid")
        identity_verifier = (
            self._require_detached_connection_identity_current
            if detached
            else self._require_primary_connection_identity_current
        )
        identity_verifier()
        view = object.__new__(Database)
        view.path = self.path
        view._connection = connection
        view._lock = self._lock if connection is self._connection else threading.RLock()
        view._detached_connection = cast(
            sqlite3.Connection,
            connection if detached else None,
        )
        view._snapshot_identity_verifier = identity_verifier
        return view

    def _require_access_identity_current(self) -> None:
        verifier = getattr(self, "_snapshot_identity_verifier", None)
        if verifier is None:
            self._require_primary_connection_identity_current()
        else:
            verifier()

    @contextmanager
    def detached_read_snapshot(self) -> Iterator[tuple[Database, sqlite3.Connection]]:
        """Hold one exact WAL snapshot without the primary heartbeat lock."""

        with self._detached_lock:
            connection = self._detached_connection
            try:
                self._require_detached_connection_identity_current()
                connection.execute("BEGIN")
                # Force the WAL read mark now; every admission, graph and DTO
                # read below observes this one immutable SQLite snapshot.
                connection.execute("SELECT COUNT(*) FROM sqlite_schema").fetchone()
                yield self.snapshot_view(connection), connection
            finally:
                connection.rollback()
                self._require_detached_connection_identity_current()

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            try:
                self._require_primary_connection_identity_current()
                cursor = self._connection.execute(sql, params)
                self._require_primary_connection_identity_current()
                self._connection.commit()
                self._require_primary_connection_identity_current()
                return cursor
            except Exception:
                self._connection.rollback()
                raise

    def executescript(self, sql: str) -> None:
        with self._lock:
            try:
                self._require_primary_connection_identity_current()
                self._connection.executescript(sql)
                self._require_primary_connection_identity_current()
                self._connection.commit()
                self._require_primary_connection_identity_current()
            except Exception:
                self._connection.rollback()
                raise

    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            self._require_access_identity_current()
            value = cast(sqlite3.Row | None, self._connection.execute(sql, params).fetchone())
            self._require_access_identity_current()
            return value

    def fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            self._require_access_identity_current()
            values = list(self._connection.execute(sql, params).fetchall())
            self._require_access_identity_current()
            return values

    def create_job(
        self,
        *,
        job_id: str,
        encrypted_question: bytes,
        question_summary: str,
        request: dict[str, Any],
        route: str = "direct",
        route_reasons: Sequence[str] = (),
        idempotency_key: str | None = None,
        pinned_index_build_id: str | None = None,
        job_type: str = "answer",
        queue_wait_deadline_at: str | None = None,
        workflow_deadline_at: str | None = None,
        model_call_deadline_at: str | None = None,
        evaluation_run_id: str | None = None,
        evaluation_case_id: str | None = None,
        evaluation_request_sha256: str | None = None,
        evaluation_authority: Mapping[str, Any] | None = None,
        trace_full_retention: bool = False,
        word_target: int | None = None,
        owner_canary_controller_claim: Mapping[str, Any] | None = None,
        exact_controller_claim: Mapping[str, Any] | None = None,
        queue_capacity: int | None = None,
        index_build_admission: Mapping[str, Any] | None = None,
    ) -> str | None:
        from .types import JobType

        resolved_job_type = str(job_type)
        if resolved_job_type not in {JobType.ANSWER, JobType.INDEX_BUILD}:
            raise ValueError("job type is not supported by a bounded worker queue")
        job_type = resolved_job_type
        index_build_values: dict[str, str] | None = None
        if index_build_admission is not None:
            required_fields = {
                "path",
                "embedding_model",
                "reranker_model",
                "corpus_id",
                "scoped_corpus_id",
                "source_manifest_hash",
                "parser_version",
                "chunker_version",
                "index_schema_version",
                "embedding_model_version",
                "rerank_version",
                "policy_sha256",
                "assessment_bundle_sha256",
            }
            if resolved_job_type != JobType.INDEX_BUILD:
                raise ValueError("index-build aggregate admission requires an index-build job")
            if set(index_build_admission) != required_fields:
                raise ValueError("index-build aggregate admission fields are invalid")
            if (
                not pinned_index_build_id
                or request.get("build_id") != pinned_index_build_id
                or idempotency_key is None
            ):
                raise ValueError("index-build aggregate identity is incomplete")
            index_build_values = {}
            for field in required_fields:
                value = index_build_admission[field]
                if not isinstance(value, str) or not value:
                    raise ValueError(f"index-build aggregate {field} is invalid")
                index_build_values[field] = value
            for field in (
                "source_manifest_hash",
                "policy_sha256",
                "assessment_bundle_sha256",
            ):
                if re.fullmatch(r"[0-9a-f]{64}", index_build_values[field]) is None:
                    raise ValueError(f"index-build aggregate {field} is not a lowercase SHA-256")
        if job_type == "answer" and "question" in request:
            raise ValueError("request_json must not duplicate encrypted question plaintext")
        raw_upload_ids = request.get("upload_ids", [])
        if (
            not isinstance(raw_upload_ids, list)
            or any(not isinstance(value, str) or not value for value in raw_upload_ids)
            or len(raw_upload_ids) != len(set(raw_upload_ids))
            or len(raw_upload_ids) > 20
        ):
            raise ValueError("job upload references are invalid")
        upload_ids = tuple(raw_upload_ids)
        evaluation_values = (
            evaluation_run_id,
            evaluation_case_id,
            evaluation_request_sha256,
            evaluation_authority,
        )
        legacy_observability_only = (
            evaluation_run_id is not None
            and evaluation_case_id is not None
            and evaluation_request_sha256 is None
            and evaluation_authority is None
            and pinned_index_build_id is None
        )
        if (
            any(value is not None for value in evaluation_values)
            and not all(value is not None for value in evaluation_values)
            and not legacy_observability_only
        ):
            raise ValueError(
                "evaluation run, case, request and authority identities must be supplied together"
            )
        if evaluation_request_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", evaluation_request_sha256
        ):
            raise ValueError("evaluation request SHA must be a lowercase SHA-256")
        authority_json: str | None = None
        authority_sha256: str | None = None
        authority_value: dict[str, Any] | None = None
        if evaluation_authority is not None:
            authority_value = dict(evaluation_authority)
            observed_seal = str(authority_value.get("seal_sha256") or "")
            material = dict(authority_value)
            material.pop("seal_sha256", None)
            expected_seal = hashlib.sha256(
                (
                    json.dumps(
                        material,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
            ).hexdigest()
            if observed_seal != expected_seal:
                raise ValueError("evaluation authority seal does not match")
            expected_binding = (
                evaluation_run_id,
                evaluation_case_id,
                evaluation_request_sha256,
            )
            observed_binding = (
                authority_value.get("run_id"),
                authority_value.get("case_id"),
                authority_value.get("request_sha256"),
            )
            if observed_binding != expected_binding:
                raise ValueError("evaluation authority differs from the job binding")
            authority_json = json.dumps(
                authority_value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            authority_sha256 = observed_seal
        if trace_full_retention and evaluation_run_id is None:
            raise ValueError("full trace retention requires a validated evaluation binding")
        controller_worker_id: str | None = None
        controller_pid: int | None = None
        controller_lease_seconds: int | None = None
        controller_before_sha256: str | None = None
        controller_frontier_generation: int | None = None
        if owner_canary_controller_claim is not None and exact_controller_claim is not None:
            raise ValueError("a job cannot have two controller claims")
        if owner_canary_controller_claim is not None:
            controller_pid = int(owner_canary_controller_claim.get("controller_pid") or 0)
            controller_lease_seconds = int(owner_canary_controller_claim.get("lease_seconds") or 0)
            controller_before_sha256 = str(
                owner_canary_controller_claim.get("before_checkpoint_sha256") or ""
            )
            controller_frontier_generation = int(
                owner_canary_controller_claim.get("frontier_generation") or -1
            )
            if (
                controller_pid != os.getpid()
                or not 5 <= controller_lease_seconds <= 12 * 60 * 60
                or not re.fullmatch(r"[0-9a-f]{64}", controller_before_sha256)
                or controller_frontier_generation < 1
                or evaluation_run_id is None
                or evaluation_case_id is None
                or evaluation_authority is None
                or evaluation_authority.get("lane") != "owner_quality_canary"
                or evaluation_authority.get("owned_runtime_before_checkpoint_sha256")
                != controller_before_sha256
                or evaluation_authority.get("owned_runtime_frontier_generation")
                != controller_frontier_generation
            ):
                raise ValueError("owner-canary atomic controller claim is invalid")
            controller_worker_id = f"owner-canary-controller-{controller_pid}-{evaluation_run_id}"
        elif exact_controller_claim is not None:
            controller_pid = int(exact_controller_claim.get("controller_pid") or 0)
            controller_lease_seconds = int(exact_controller_claim.get("lease_seconds") or 0)
            supplied_worker_id = str(exact_controller_claim.get("worker_id") or "")
            supplied_authority_sha256 = str(exact_controller_claim.get("authority_sha256") or "")
            if (
                controller_pid != os.getpid()
                or not 5 <= controller_lease_seconds <= 12 * 60 * 60
                or re.fullmatch(r"[A-Za-z0-9_.:-]{3,128}", supplied_worker_id) is None
                or not supplied_worker_id.startswith(
                    f"candidate-completion-controller-{controller_pid}-"
                )
                or authority_value is None
                or supplied_authority_sha256 != authority_sha256
                or authority_value.get("schema")
                != "legalbot.candidate-completion-nonrelease-job-authority.v1"
                or authority_value.get("lane") != "candidate_completion_preflight"
                or authority_value.get("mode") != "isolated_nonrelease"
                or authority_value.get("candidate_build_id") != pinned_index_build_id
                or authority_value.get("writes_active") is not False
                or authority_value.get("release_allowed") is not False
                or resolved_job_type != JobType.ANSWER
            ):
                raise ValueError("exact non-release controller claim is invalid")
            controller_worker_id = supplied_worker_id
        if question_summary != PRIVATE_QUESTION_SUMMARY:
            question_summary = PRIVATE_QUESTION_SUMMARY
        resolved_word_target = int(
            word_target if word_target is not None else request.get("word_target", 1_500)
        )
        if not 100 <= resolved_word_target <= 10_000:
            raise ValueError("word target is outside the supported runtime range")
        from .jobs import queue_capacity_for

        resolved_queue_capacity = (
            queue_capacity_for(job_type) if queue_capacity is None else int(queue_capacity)
        )
        if not 1 <= resolved_queue_capacity <= 10_000:
            raise ValueError("job queue capacity is outside the supported range")
        trace_id, root_span_id = self._job_trace_ids(job_id)
        now = utc_iso()
        with self.transaction() as conn:
            upload_bindings: list[sqlite3.Row] = []
            for upload_id in upload_ids:
                upload = conn.execute(
                    """
                    SELECT id,content_sha256,byte_size,media_type
                    FROM uploads WHERE id=? AND status='staged'
                    """,
                    (upload_id,),
                ).fetchone()
                if (
                    upload is None
                    or re.fullmatch(r"[0-9a-f]{64}", str(upload["content_sha256"])) is None
                    or int(upload["byte_size"] or 0) <= 0
                    or not str(upload["media_type"] or "")
                ):
                    raise ValueError("job upload reference is unavailable")
                upload_bindings.append(upload)
            if owner_canary_controller_claim is not None:
                session = conn.execute(
                    "SELECT * FROM owner_canary_runtime_sessions WHERE run_id=?",
                    (evaluation_run_id,),
                ).fetchone()
                if (
                    session is None
                    or session["status"] != "active"
                    or int(session["controller_pid"]) != controller_pid
                    or session["active_case_id"] != evaluation_case_id
                    or session["active_before_checkpoint_sha256"] != controller_before_sha256
                    or int(session["frontier_generation"]) != controller_frontier_generation
                    or datetime.fromisoformat(str(session["lease_expires_at"])) <= datetime.now(UTC)
                ):
                    raise RuntimeError("owner_canary_controller_job_claim_refused")
            legacy_evaluation_identity = bool(
                evaluation_run_id
                and evaluation_case_id
                and conn.execute(
                    """SELECT 1 FROM jobs
                       WHERE evaluation_run_id=? AND evaluation_case_id=?
                         AND evaluation_request_sha256 IS NULL""",
                    (evaluation_run_id, evaluation_case_id),
                ).fetchone()
            )
            if legacy_evaluation_identity:
                raise sqlite3.IntegrityError(
                    "legacy evaluation identity cannot be rebound to a new durable request"
                )
            duplicate_identity_exists = bool(
                idempotency_key
                and conn.execute(
                    "SELECT 1 FROM jobs WHERE idempotency_key=?", (idempotency_key,)
                ).fetchone()
            ) or bool(
                evaluation_run_id
                and evaluation_case_id
                and conn.execute(
                    """SELECT 1 FROM jobs
                       WHERE evaluation_run_id=? AND evaluation_case_id=?
                         AND evaluation_request_sha256 IS NOT NULL""",
                    (evaluation_run_id, evaluation_case_id),
                ).fetchone()
            )
            if index_build_values is not None:
                # Aggregate duplicates must reach an immutable identity constraint
                # rather than being hidden by an already-full index queue.  The
                # caller can then reconcile the duplicate without admitting work.
                duplicate_identity_exists = (
                    duplicate_identity_exists
                    or bool(conn.execute("SELECT 1 FROM jobs WHERE id=?", (job_id,)).fetchone())
                    or bool(
                        conn.execute(
                            "SELECT 1 FROM index_builds WHERE id=? OR idempotency_key=?",
                            (pinned_index_build_id, idempotency_key),
                        ).fetchone()
                    )
                )
            # Let an already-bound duplicate reach the existing UNIQUE
            # constraint.  The API's immutable-idempotency reconciliation then
            # returns the original job; queue saturation must not turn a safe
            # concurrent retry into a spurious 429.
            if not duplicate_identity_exists:
                self._require_job_queue_capacity_locked(
                    conn,
                    job_type=job_type,
                    capacity=resolved_queue_capacity,
                )
            conn.execute(
                """
                INSERT INTO jobs(
                  id, status, stage, progress, encrypted_question, question_summary,
                  request_json, route, route_reasons_json, idempotency_key,
                  pinned_index_build_id, job_type, queue_wait_deadline_at,
                  workflow_deadline_at, model_call_deadline_at,
                  evaluation_run_id, evaluation_case_id, evaluation_request_sha256,
                  evaluation_authority_json, evaluation_authority_sha256,
                  trace_id,
                  trace_root_span_id, trace_full_retention, last_progress_at,
                  word_target, created_at, updated_at
                ) VALUES (?, 'queued', 'queued', 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    encrypted_question,
                    question_summary,
                    json.dumps(request),
                    route,
                    json.dumps(list(route_reasons), sort_keys=True),
                    idempotency_key,
                    pinned_index_build_id,
                    job_type,
                    queue_wait_deadline_at,
                    workflow_deadline_at,
                    model_call_deadline_at,
                    evaluation_run_id,
                    evaluation_case_id,
                    evaluation_request_sha256,
                    authority_json,
                    authority_sha256,
                    trace_id,
                    root_span_id,
                    int(trace_full_retention),
                    now,
                    resolved_word_target,
                    now,
                    now,
                ),
            )
            if index_build_values is not None:
                conn.execute(
                    """
                    INSERT INTO index_builds(
                      id, status, stage, path, embedding_model, reranker_model, created_at,
                      corpus_id, scoped_corpus_id, source_manifest_hash, parser_version,
                      chunker_version, index_schema_version, embedding_model_version,
                      rerank_version, job_id, idempotency_key, stage_timings_json,
                      counts_json, promotion_decision, policy_sha256,
                      assessment_bundle_sha256
                    ) VALUES (?, 'queued', 'queued', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              '{}', '{}', 'not_requested', ?, ?)
                    """,
                    (
                        pinned_index_build_id,
                        index_build_values["path"],
                        index_build_values["embedding_model"],
                        index_build_values["reranker_model"],
                        now,
                        index_build_values["corpus_id"],
                        index_build_values["scoped_corpus_id"],
                        index_build_values["source_manifest_hash"],
                        index_build_values["parser_version"],
                        index_build_values["chunker_version"],
                        index_build_values["index_schema_version"],
                        index_build_values["embedding_model_version"],
                        index_build_values["rerank_version"],
                        job_id,
                        idempotency_key,
                        index_build_values["policy_sha256"],
                        index_build_values["assessment_bundle_sha256"],
                    ),
                )
            for ordinal, upload in enumerate(upload_bindings, start=1):
                conn.execute(
                    """
                    INSERT INTO job_upload_bindings(
                      job_id,ordinal,upload_id,content_sha256,byte_size,media_type
                    ) VALUES (?,?,?,?,?,?)
                    """,
                    (
                        job_id,
                        ordinal,
                        str(upload["id"]),
                        str(upload["content_sha256"]),
                        int(upload["byte_size"]),
                        str(upload["media_type"]),
                    ),
                )
            conn.execute(
                """
                INSERT INTO job_events(job_id, stage, progress, message, created_at)
                VALUES (?, 'queued', 0, ?, ?)
                """,
                (
                    job_id,
                    "Index-build job queued" if job_type == "index_build" else "Answer job queued",
                    now,
                ),
            )
            if controller_worker_id is not None:
                claim_now = datetime.now(UTC)
                updated = conn.execute(
                    """
                    UPDATE jobs SET status='running',stage='queued',attempt_count=1,
                      lease_owner=?,lease_expires_at=?,heartbeat_at=?,updated_at=?
                    WHERE id=? AND status='queued' AND lease_owner IS NULL
                      AND attempt_count=0
                    """,
                    (
                        controller_worker_id,
                        (
                            claim_now + timedelta(seconds=int(controller_lease_seconds or 0))
                        ).isoformat(),
                        claim_now.isoformat(),
                        claim_now.isoformat(),
                        job_id,
                    ),
                )
                if updated.rowcount != 1:
                    raise RuntimeError("owner_canary_controller_job_claim_refused")
        return controller_worker_id

    @staticmethod
    def _require_job_queue_capacity_locked(
        conn: sqlite3.Connection,
        *,
        job_type: str,
        capacity: int,
        exclude_job_id: str | None = None,
    ) -> None:
        parameters: list[Any] = [job_type]
        exclusion = ""
        if exclude_job_id is not None:
            exclusion = " AND id<>?"
            parameters.append(exclude_job_id)
        active_count = int(
            conn.execute(
                """SELECT COUNT(*) FROM jobs
                   WHERE job_type=? AND status IN ('queued','running')"""
                + exclusion,
                tuple(parameters),
            ).fetchone()[0]
        )
        if active_count >= capacity:
            raise JobQueueCapacityError(f"{job_type}_queue_capacity_exhausted")

    def job_upload_bindings(self, job_id: str) -> list[sqlite3.Row]:
        """Return the immutable, prose-free upload snapshot for one job."""

        return self.fetchall(
            """
            SELECT ordinal,upload_id,content_sha256,byte_size,media_type
            FROM job_upload_bindings WHERE job_id=? ORDER BY ordinal
            """,
            (job_id,),
        )

    def bind_job_assessment_bundle(self, job_id: str, bundle_sha256: str) -> None:
        """Bind one immutable assessment-guidance bundle to an answer job."""

        if not re.fullmatch(r"[0-9a-f]{64}", bundle_sha256):
            raise ValueError("assessment bundle SHA must be a lowercase SHA-256")
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT assessment_bundle_sha256 FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if row is None:
                raise ValueError("job does not exist")
            existing = str(row["assessment_bundle_sha256"] or "")
            if existing and existing != bundle_sha256:
                raise RuntimeError("job is already bound to a different assessment bundle")
            conn.execute(
                "UPDATE jobs SET assessment_bundle_sha256=?, updated_at=? WHERE id=?",
                (bundle_sha256, utc_iso(), job_id),
            )

    def bind_job_issue_plan_proposition_keys(
        self, job_id: str, proposition_keys: Sequence[str]
    ) -> None:
        """Freeze the prose-free issue taxonomy needed to replay section inputs."""

        keys = tuple(str(value) for value in proposition_keys)
        if (
            len(keys) > 6
            or len(keys) != len(set(keys))
            or any(re.fullmatch(r"[a-z0-9_]{1,64}", value) is None for value in keys)
        ):
            raise ValueError("job issue-plan proposition keys are invalid")
        encoded = json.dumps(list(keys), ensure_ascii=False, separators=(",", ":"))
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT issue_plan_proposition_keys_json FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if row is None:
                raise ValueError("job does not exist")
            existing = str(row["issue_plan_proposition_keys_json"] or "[]")
            released = conn.execute(
                "SELECT 1 FROM release_outbox WHERE job_id=? LIMIT 1", (job_id,)
            ).fetchone()
            if existing not in {"[]", encoded} or (released is not None and existing != encoded):
                raise RuntimeError("job is already bound to a different issue plan")
            conn.execute(
                "UPDATE jobs SET issue_plan_proposition_keys_json=?,updated_at=? WHERE id=?",
                (encoded, utc_iso(), job_id),
            )

    def bind_job_runtime_identity(
        self,
        job_id: str,
        *,
        prompt_version: str,
        router_version: str,
        classifier_version: str,
        policy_sha256: str,
    ) -> None:
        """Bind the worker process identities actually executing an answer job."""

        safe_version = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
        if any(
            safe_version.fullmatch(value) is None
            for value in (prompt_version, router_version, classifier_version)
        ):
            raise ValueError("worker runtime version is not a safe immutable identity")
        if re.fullmatch(r"[0-9a-f]{64}", policy_sha256) is None:
            raise ValueError("worker policy SHA must be a lowercase SHA-256")
        supplied = (
            prompt_version,
            router_version,
            classifier_version,
            policy_sha256,
        )
        with self.transaction() as conn:
            row = conn.execute(
                """
                SELECT worker_prompt_version, worker_router_version,
                       worker_classifier_version, worker_policy_sha256
                FROM jobs WHERE id=?
                """,
                (job_id,),
            ).fetchone()
            if row is None:
                raise ValueError("job does not exist")
            existing = tuple(str(row[index] or "") for index in range(4))
            if any(existing) and existing != supplied:
                raise RuntimeError("job is already bound to another worker runtime")
            conn.execute(
                """
                UPDATE jobs SET worker_prompt_version=?, worker_router_version=?,
                  worker_classifier_version=?, worker_policy_sha256=?, updated_at=?
                WHERE id=?
                """,
                (*supplied, utc_iso(), job_id),
            )

    def store_upload(
        self,
        *,
        upload_id: str,
        content_sha256: str,
        safe_display_name: str,
        encrypted_original_name: bytes,
        media_type: str,
        byte_size: int,
        vault_path: str,
        encrypted_blob: bool = False,
        retention_until: str | None = None,
        review_pinned: bool = False,
        review_completed_at: str | None = None,
        quarantine_status: str = "unreviewed",
    ) -> None:
        if quarantine_status not in {
            "unreviewed",
            "passed",
            "held",
            "blocked",
            "rejected",
            "expired",
        }:
            raise ValueError("upload quarantine status is invalid")
        self.execute(
            """
            INSERT INTO uploads(
              id, content_sha256, safe_display_name, encrypted_original_name,
              media_type, byte_size, vault_path, encrypted_blob, retention_until,
              review_pinned, review_completed_at, quarantine_status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                upload_id,
                content_sha256,
                safe_display_name,
                encrypted_original_name,
                media_type,
                byte_size,
                vault_path,
                int(encrypted_blob),
                retention_until,
                int(review_pinned),
                review_completed_at,
                quarantine_status,
                utc_iso(),
            ),
        )

    def update_upload_lifecycle(
        self,
        upload_id: str,
        *,
        encrypted_blob: bool | None = None,
        retention_until: str | None = None,
        review_pinned: bool | None = None,
        review_completed_at: str | None = None,
        quarantine_status: str | None = None,
    ) -> None:
        """Update only the safe lifecycle fields; file encryption remains external."""

        if quarantine_status is not None and quarantine_status not in {
            "unreviewed",
            "passed",
            "held",
            "blocked",
            "rejected",
            "expired",
        }:
            raise ValueError("upload quarantine status is invalid")
        with self.transaction() as conn:
            row = conn.execute("SELECT id FROM uploads WHERE id=?", (upload_id,)).fetchone()
            if row is None:
                raise KeyError(upload_id)
            conn.execute(
                """
                UPDATE uploads SET
                  encrypted_blob=COALESCE(?, encrypted_blob),
                  retention_until=COALESCE(?, retention_until),
                  review_pinned=COALESCE(?, review_pinned),
                  review_completed_at=COALESCE(?, review_completed_at),
                  quarantine_status=COALESCE(?, quarantine_status)
                WHERE id=?
                """,
                (
                    int(encrypted_blob) if encrypted_blob is not None else None,
                    retention_until,
                    int(review_pinned) if review_pinned is not None else None,
                    review_completed_at,
                    quarantine_status,
                    upload_id,
                ),
            )

    def update_job(
        self,
        job_id: str,
        *,
        status: str,
        stage: str,
        progress: float,
        message: str,
        payload: dict[str, Any] | None = None,
        answer_id: str | None = None,
        release_state: str | None = None,
        error_code: str | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> bool:
        """CAS one non-terminal job transition.

        Durable terminal states are immutable through the generic progress API.
        Explicit owner resume/replay operations use their own bounded transition
        methods; a stale runner therefore cannot turn a cancelled or failed job
        back into ``running`` (or rewrite its terminal evidence).
        """

        now = utc_iso()
        with self.transaction() as conn:
            updated = conn.execute(
                """
                UPDATE jobs
                SET status=?, stage=?, progress=?, user_message=?, answer_id=COALESCE(?, answer_id),
                    release_state=COALESCE(?, release_state), error_code=?,
                    checkpoint_json=COALESCE(?, checkpoint_json), last_progress_at=?, updated_at=?
                WHERE id=? AND status NOT IN
                  ('complete','held_for_review','system_error','failed','cancelled','dlq')
                """,
                (
                    status,
                    stage,
                    progress,
                    message,
                    answer_id,
                    release_state,
                    error_code,
                    json.dumps(checkpoint) if checkpoint is not None else None,
                    now,
                    now,
                    job_id,
                ),
            )
            if updated.rowcount != 1:
                return False
            conn.execute(
                """
                INSERT INTO job_events(job_id, stage, progress, message, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (job_id, stage, progress, message, json.dumps(payload or {}), now),
            )
            if status in {"complete", "held_for_review", "system_error", "cancelled"}:
                self._extend_upload_retention_for_job(conn, job_id, now=now)
            return True

    def arm_stage_deadline(self, job_id: str, *, seconds: int) -> str:
        """Bound the current stage. Does not slide when progress messages update.

        Negative ``seconds`` is permitted so expiry tests can arm an already-past
        deadline. Runtime callers must pass the configured positive stage budget.
        """

        now = datetime.now(UTC)
        started = now.isoformat()
        deadline = (now + timedelta(seconds=seconds)).isoformat()
        terminal = {
            "complete",
            "held_for_review",
            "system_error",
            "failed",
            "cancelled",
            "dlq",
        }
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT status FROM jobs WHERE id=?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise ValueError("cannot arm a stage deadline for an unknown job")
            if str(row["status"]) in terminal:
                raise ValueError("cannot arm a stage deadline on a terminal job")
            conn.execute(
                """
                UPDATE jobs
                SET stage_started_at=?, stage_deadline_at=?, updated_at=?
                WHERE id=?
                """,
                (started, deadline, utc_iso(), job_id),
            )
        return deadline

    def arm_model_call_deadline(self, job_id: str, *, seconds: int) -> tuple[str, str]:
        """Atomically fence and persist one in-flight model invocation."""

        now = datetime.now(UTC)
        deadline = (now + timedelta(seconds=seconds)).isoformat()
        call_token = secrets.token_hex(16)
        terminal = {
            "complete",
            "held_for_review",
            "system_error",
            "failed",
            "cancelled",
            "dlq",
        }
        with self.transaction() as conn:
            row = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise ValueError("cannot arm a model deadline for an unknown job")
            if str(row["status"]) in terminal:
                raise ValueError("cannot arm a model deadline on a terminal job")
            armed = conn.execute(
                """UPDATE jobs
                   SET model_call_deadline_at=?, model_call_token=?, updated_at=?
                   WHERE id=? AND model_call_token IS NULL""",
                (deadline, call_token, now.isoformat(), job_id),
            )
            if armed.rowcount != 1:
                raise RuntimeError("another model invocation already owns this job")
        return call_token, deadline

    def clear_model_call_deadline(self, job_id: str, *, call_token: str) -> bool:
        """Clear only the exact in-flight model invocation that was armed."""

        if re.fullmatch(r"[0-9a-f]{32}", call_token) is None:
            raise ValueError("model-call token is invalid")
        cursor = self.execute(
            """UPDATE jobs SET model_call_deadline_at=NULL,model_call_token=NULL,updated_at=?
               WHERE id=? AND model_call_token=?""",
            (utc_iso(), job_id, call_token),
        )
        return cursor.rowcount == 1

    @staticmethod
    def _extend_upload_retention_for_job(
        conn: sqlite3.Connection, job_id: str, *, now: str
    ) -> None:
        """Apply the terminal-job upload TTL from every terminal transition path."""

        job_request = conn.execute("SELECT request_json FROM jobs WHERE id=?", (job_id,)).fetchone()
        if job_request is None:
            return
        try:
            request_value = json.loads(str(job_request["request_json"] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            return
        upload_ids = request_value.get("upload_ids", []) if isinstance(request_value, dict) else []
        if not isinstance(upload_ids, list):
            return
        try:
            terminal_at = datetime.fromisoformat(now)
        except ValueError:
            terminal_at = datetime.now(UTC)
        if terminal_at.tzinfo is None:
            terminal_at = terminal_at.replace(tzinfo=UTC)
        retention_until = (terminal_at + timedelta(days=30)).isoformat()
        for upload_id in {value for value in upload_ids if isinstance(value, str) and value}:
            conn.execute(
                """
                UPDATE uploads SET retention_until=CASE
                  WHEN retention_until IS NULL OR retention_until<?
                  THEN ? ELSE retention_until END
                WHERE id=? AND status='staged'
                """,
                (retention_until, retention_until, upload_id),
            )

    def job(self, job_id: str) -> sqlite3.Row | None:
        return self.fetchone("SELECT * FROM jobs WHERE id=?", (job_id,))

    def observability_jobs(
        self, *, active_only: bool = True, limit: int = 200
    ) -> list[sqlite3.Row]:
        """Return the fixed, prose-free job projection used by local telemetry."""

        if not 1 <= limit <= 500:
            raise ValueError("observability job limit is out of range")
        where = "WHERE status IN ('queued','running')" if active_only else ""
        return self.fetchall(
            f"""
            SELECT id, trace_id, trace_root_span_id, trace_full_retention,
                   evaluation_run_id, evaluation_case_id, job_type, status, stage,
                   progress, route, word_target, release_state, error_code,
                   attempt_count, created_at, updated_at, last_progress_at
            FROM jobs {where}
            ORDER BY created_at, id LIMIT ?
            """,
            (limit,),
        )

    def job_queue_telemetry(self) -> dict[str, Any]:
        """Queue depth and oldest age split by job class. No question or source text."""

        from datetime import UTC, datetime

        now = datetime.now(UTC)
        rows = self.fetchall(
            """
            SELECT job_type, status, created_at, dlq FROM jobs
            WHERE status IN ('queued','running','dlq','failed')
            """
        )
        classes: dict[str, dict[str, Any]] = {
            "answer": {},
            "index_build": {},
            "scheduled_task": {},
        }
        for name in classes:
            classes[name] = {
                "queue_depth": 0,
                "in_flight": 0,
                "dlq_depth": 0,
                "oldest_age_seconds": None,
            }
        for row in rows:
            job_type = str(row["job_type"] or "answer")
            bucket = classes.setdefault(
                job_type,
                {
                    "queue_depth": 0,
                    "in_flight": 0,
                    "dlq_depth": 0,
                    "oldest_age_seconds": None,
                },
            )
            status = str(row["status"])
            if status == "queued":
                bucket["queue_depth"] += 1
            elif status == "running":
                bucket["in_flight"] += 1
            if status == "dlq" or int(row["dlq"] or 0):
                bucket["dlq_depth"] += 1
            created = str(row["created_at"] or "")
            try:
                parsed = datetime.fromisoformat(created)
            except ValueError:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            age = max(0.0, (now - parsed).total_seconds())
            current = bucket["oldest_age_seconds"]
            if status in {"queued", "running"} and (current is None or age > current):
                bucket["oldest_age_seconds"] = round(age, 3)
        return {"schema": "legalbot.job-queue-telemetry.v1", "by_class": classes}

    def replay_dlq_job(self, job_id: str) -> bool:
        from .jobs import deadline_after, policy_for, queue_capacity_for
        from .orchestration.retry_policy import MAX_ATTEMPTS
        from .types import JobType

        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                return False
            job_type = str(row["job_type"] or JobType.ANSWER)
            if job_type == JobType.ANSWER:
                raise ValueError(
                    "answer jobs are not DLQ-replayed; the owner must retry explicitly"
                )
            if job_type == JobType.SCHEDULED_TASK:
                return False
            if job_type != JobType.INDEX_BUILD:
                raise ValueError("DLQ job type is unsupported")
            if str(row["status"]) not in {"dlq", "failed"} and not int(row["dlq"] or 0):
                return False
            if bool(row["cancel_requested"]):
                # Cancellation is durable owner intent.  Replaying this identity
                # with cancel_requested still set would create unclaimable queued
                # work that consumes the capacity-one index lane forever.
                return False
            if row["lease_owner"] is not None or row["lease_expires_at"] is not None:
                raise RuntimeError("index-build job is still bound to a worker lease")
            if int(row["attempt_count"] or 0) >= min(
                policy_for(job_type).max_attempts, MAX_ATTEMPTS
            ):
                # An exhausted identity is terminal.  A materially changed request
                # must be admitted as new work rather than resetting its counter.
                return False
            self._require_job_queue_capacity_locked(
                conn,
                job_type=job_type,
                capacity=queue_capacity_for(job_type),
                exclude_job_id=job_id,
            )
            now = utc_iso()
            policy = policy_for(job_type)
            updated = conn.execute(
                """
                UPDATE jobs SET status='queued', stage='queued', dlq=0, error_code=NULL,
                  terminal_reason_code=NULL,
                  heartbeat_at=NULL, queue_wait_deadline_at=?, workflow_deadline_at=?,
                  stage_started_at=NULL, stage_deadline_at=NULL,
                  model_call_deadline_at=NULL, model_call_token=NULL,
                  user_message='Replayed from DLQ', last_progress_at=?, updated_at=?
                WHERE id=? AND lease_owner IS NULL AND lease_expires_at IS NULL
                  AND cancel_requested=0
                  AND status IN ('dlq','failed')
                """,
                (
                    deadline_after(policy.queue_wait_seconds),
                    deadline_after(policy.workflow_seconds),
                    now,
                    now,
                    job_id,
                ),
            )
            if updated.rowcount != 1:
                raise RuntimeError("index-build DLQ replay admission changed before commit")
            return True

    def job_by_idempotency_key(self, key: str) -> sqlite3.Row | None:
        return self.fetchone("SELECT * FROM jobs WHERE idempotency_key=?", (key,))

    def job_by_evaluation_binding(self, run_id: str, case_id: str) -> sqlite3.Row | None:
        return self.fetchone(
            "SELECT * FROM jobs WHERE evaluation_run_id=? AND evaluation_case_id=? "
            "ORDER BY created_at, id LIMIT 1",
            (run_id, case_id),
        )

    def job_events(self, job_id: str, after: int = 0) -> list[sqlite3.Row]:
        return self.fetchall(
            "SELECT * FROM job_events WHERE job_id=? AND sequence>? ORDER BY sequence",
            (job_id, after),
        )

    def retry_decisions(self, lane: str, work_id: str) -> list[sqlite3.Row]:
        """Return the safe bounded-retry trace for one durable work identity."""

        if lane not in {"job", "research"}:
            raise ValueError("retry-decision lane is invalid")
        return self.fetchall(
            "SELECT * FROM retry_decisions WHERE lane=? AND work_id=? ORDER BY attempt_number",
            (lane, work_id),
        )

    @staticmethod
    def _decide_retry_locked(
        conn: sqlite3.Connection,
        *,
        lane: str,
        work_id: str,
        attempt_number: int,
        stage: str,
        failure_reason: str,
        input_identity_sha256: str,
        max_attempts: int,
        retryable: bool,
        input_or_condition_changed: bool,
        condition_identity_sha256: str | None,
        retry_operation: str,
    ) -> RetryDecision:
        """Apply and persist the shared prose-free retry policy atomically."""

        from .orchestration.retry_policy import (
            MAX_ATTEMPTS,
            decide_retry,
            failure_fingerprint,
            normalise_failure_reason_code,
        )

        if lane not in {"job", "research"}:
            raise ValueError("retry-decision lane is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", input_identity_sha256):
            raise ValueError("retry input identity is invalid")
        if condition_identity_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", condition_identity_sha256
        ):
            raise ValueError("retry condition identity is invalid")
        bounded_max = max(1, min(int(max_attempts), MAX_ATTEMPTS))
        reason_code = normalise_failure_reason_code(failure_reason)
        stage_code = normalise_failure_reason_code(stage)
        operation_code = normalise_failure_reason_code(retry_operation)
        work_identity_sha256 = hashlib.sha256(
            f"legalbot-retry-work-v1\0{lane}\0{work_id}".encode()
        ).hexdigest()
        fingerprint = failure_fingerprint(
            stage=stage_code,
            reason_code=reason_code,
            # Input identity is a binding, not part of semantic repeat
            # detection: a targeted revision must not make the same failure
            # look novel merely because its bytes changed.
            identity_digests=(work_identity_sha256,),
        )
        prior = tuple(
            str(row["failure_fingerprint_sha256"])
            for row in conn.execute(
                "SELECT failure_fingerprint_sha256 FROM retry_decisions "
                "WHERE lane=? AND work_id=? ORDER BY attempt_number",
                (lane, work_id),
            ).fetchall()
        )
        prior_conditions = {
            str(row["condition_identity_sha256"])
            for row in conn.execute(
                "SELECT condition_identity_sha256 FROM retry_decisions WHERE lane=? AND work_id=?",
                (lane, work_id),
            ).fetchall()
            if row["condition_identity_sha256"]
        }
        effective_condition_changed = bool(
            input_or_condition_changed
            and condition_identity_sha256
            and condition_identity_sha256 not in prior_conditions
        )
        decision = decide_retry(
            attempt_number=attempt_number,
            failure_reason_code=reason_code,
            failure_fingerprint_sha256=fingerprint,
            prior_failure_fingerprints=prior,
            retryable=retryable,
            input_or_condition_changed=effective_condition_changed,
            max_attempts=bounded_max,
        )
        conn.execute(
            """
            INSERT INTO retry_decisions(
              lane, work_id, attempt_number, stage_code, failure_reason_code,
              failure_fingerprint_sha256, input_identity_sha256,
              condition_identity_sha256,
              decision_action, decision_reason,
              retries_remaining, retry_operation, condition_changed, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                lane,
                work_id,
                attempt_number,
                stage_code,
                reason_code,
                fingerprint,
                input_identity_sha256,
                condition_identity_sha256 or "",
                decision.action,
                decision.reason,
                decision.retries_remaining,
                operation_code,
                int(effective_condition_changed),
                utc_iso(),
            ),
        )
        return decision

    def interrupted_jobs(self) -> list[str]:
        rows = self.fetchall(
            "SELECT id FROM jobs WHERE status IN ('queued', 'running') ORDER BY created_at"
        )
        return [str(row["id"]) for row in rows]

    def request_cancel_job(self, job_id: str) -> bool:
        now = utc_iso()
        with self.transaction() as conn:
            row = conn.execute("SELECT status, stage FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                return False
            if row["status"] in {
                "complete",
                "held_for_review",
                "system_error",
                "cancelled",
            }:
                return True
            queued = row["status"] == "queued"
            conn.execute(
                """
                UPDATE jobs SET cancel_requested=1, status=?, stage=?, user_message=?,
                  progress=CASE WHEN ? THEN 1 ELSE progress END,
                  last_progress_at=?, updated_at=?
                WHERE id=?
                """,
                (
                    "cancelled" if queued else row["status"],
                    "cancelled" if queued else row["stage"],
                    (
                        "The queued job was cancelled before execution."
                        if queued
                        else "Cancellation requested; the worker will stop at the next safe checkpoint."
                    ),
                    int(queued),
                    now,
                    now,
                    job_id,
                ),
            )
            if queued:
                self._extend_upload_retention_for_job(conn, job_id, now=now)
            return True

    def resume_answer_job(self, job_id: str) -> bool:
        """Queue one already-authorised answer retry without resetting its identity.

        Completed stage attempts are deliberately retained.  The runner will
        accept them only when their recorded input digest still matches the
        question, evidence pack, policy and assessment bundle.  The failed
        attempt must already have a shared-ledger ``retry`` decision; repeated
        calls therefore cannot mint decisions or reset the three-attempt cap.
        """

        from .jobs import deadline_after, policy_for, queue_capacity_for
        from .orchestration.retry_policy import MAX_ATTEMPTS
        from .types import JobType

        policy = policy_for(JobType.ANSWER)
        now = utc_iso()
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                return False
            if str(row["job_type"] or "answer") != JobType.ANSWER:
                raise ValueError("only answer jobs support owner resume")
            if (
                row["evaluation_run_id"] is not None
                or row["evaluation_case_id"] is not None
                or row["evaluation_request_sha256"] is not None
                or row["evaluation_authority_json"] is not None
                or row["evaluation_authority_sha256"] is not None
                or bool(row["trace_full_retention"])
            ):
                raise ValueError(
                    "evaluation-bound jobs cannot be manually resumed; "
                    "their sealed run controller owns the retry circuit"
                )
            if str(row["status"]) != "system_error":
                raise ValueError("only a system_error answer can be resumed")
            if conn.execute(
                "SELECT 1 FROM release_outbox WHERE job_id=? LIMIT 1", (job_id,)
            ).fetchone():
                raise ValueError("a released answer cannot be resumed")
            attempt_count = int(row["attempt_count"] or 0)
            if attempt_count < 1:
                raise RuntimeError("an answer cannot resume before its initial attempt")
            if attempt_count >= MAX_ATTEMPTS:
                raise RuntimeError(
                    "the answer exhausted its three-attempt identity; "
                    "continue only as a new linked job/version identity"
                )
            decision = conn.execute(
                """
                SELECT decision_action, decision_reason, retries_remaining
                FROM retry_decisions
                WHERE lane='job' AND work_id=? AND attempt_number=?
                """,
                (job_id, attempt_count),
            ).fetchone()
            if (
                decision is None
                or str(decision["decision_action"]) != "retry"
                or str(decision["decision_reason"]) != "retry_allowed"
                or int(decision["retries_remaining"] or 0) < 1
            ):
                raise RuntimeError(
                    "the answer retry circuit is terminal; "
                    "continue only as a new linked job/version identity"
                )
            try:
                checkpoint = json.loads(str(row["checkpoint_json"] or "{}"))
            except json.JSONDecodeError:
                checkpoint = {}
            if not isinstance(checkpoint, dict) or checkpoint.get("resumable") is not True:
                raise RuntimeError(
                    "the answer has no resumable targeted checkpoint; "
                    "continue only as a new linked job/version identity"
                )
            active = conn.execute(
                "SELECT id FROM index_builds WHERE status='active' LIMIT 1"
            ).fetchone()
            pinned = str(row["pinned_index_build_id"] or "")
            if active is None or str(active["id"]) != pinned:
                raise RuntimeError(
                    "the job's frozen index is not ACTIVE; resume would change legal evidence"
                )
            self._require_job_queue_capacity_locked(
                conn,
                job_type=JobType.ANSWER,
                capacity=queue_capacity_for(JobType.ANSWER),
                exclude_job_id=job_id,
            )
            conn.execute(
                """
                UPDATE jobs SET status='queued', stage='queued', progress=0,
                  error_code=NULL, terminal_reason_code=NULL, dlq=0,
                  cancel_requested=0, lease_owner=NULL, lease_expires_at=NULL,
                  heartbeat_at=NULL,
                  queue_wait_deadline_at=?, workflow_deadline_at=?,
                  stage_started_at=NULL, stage_deadline_at=NULL,
                  model_call_deadline_at=NULL, model_call_token=NULL,
                  user_message='Owner requested digest-checked resume',
                  last_progress_at=?, updated_at=?
                WHERE id=?
                """,
                (
                    deadline_after(policy.queue_wait_seconds),
                    deadline_after(policy.workflow_seconds),
                    now,
                    now,
                    job_id,
                ),
            )
            conn.execute(
                """
                INSERT INTO job_events(job_id,stage,progress,message,payload_json,created_at)
                VALUES (?, 'queued', 0, 'Owner requested digest-checked resume',
                        '{"resume":"digest_checked"}', ?)
                """,
                (job_id, now),
            )
        return True

    def claim_next_job(
        self,
        worker_id: str,
        *,
        lease_seconds: int = 60,
        job_types: Sequence[str] | None = None,
    ) -> sqlite3.Row | None:
        """Claim one queued or expired leased job atomically."""

        from .jobs import policy_for
        from .orchestration.retry_policy import MAX_ATTEMPTS
        from .types import JobType

        if not re.fullmatch(r"[A-Za-z0-9_.:-]{3,128}", worker_id):
            raise ValueError("invalid worker identifier")

        valid_types = {"answer", "index_build", "scheduled_task"}
        selected_types = (
            ("answer", "index_build", "scheduled_task") if job_types is None else job_types
        )
        allowed_types = tuple(
            dict.fromkeys(str(getattr(item, "value", item)) for item in selected_types)
        )
        if not allowed_types or any(item not in valid_types for item in allowed_types):
            raise ValueError("unsupported job type in worker capability filter")

        placeholders = ",".join("?" for _ in allowed_types)
        type_filter = f"COALESCE(job_type, 'answer') IN ({placeholders})"

        now = datetime.now(UTC)
        expires = (now + timedelta(seconds=lease_seconds)).isoformat()
        now_text = now.isoformat()
        with self.transaction() as conn:
            expired = (
                conn.execute(
                    f"""
                    SELECT * FROM jobs
                    WHERE cancel_requested=0 AND status='running'
                      AND lease_expires_at IS NOT NULL
                      AND lease_expires_at<?
                      AND COALESCE(job_type, 'answer')='answer'
                      AND {type_filter}
                      AND attempt_count>=1
                    ORDER BY created_at, id
                    """,
                    (now_text, *allowed_types),
                ).fetchall()
                if "answer" in allowed_types
                else []
            )
            for lost in expired:
                request_identity = hashlib.sha256(
                    str(lost["request_json"] or "{}").encode("utf-8")
                ).hexdigest()
                lease_expires_at = str(lost["lease_expires_at"] or "")
                lease_condition = (
                    hashlib.sha256(
                        (
                            "legalbot-expired-answer-lease-v1\0"
                            f"{lost['id']}\0{lost['attempt_count']}\0{lease_expires_at}"
                        ).encode()
                    ).hexdigest()
                    if lease_expires_at
                    else None
                )
                decision = self._decide_retry_locked(
                    conn,
                    lane="job",
                    work_id=str(lost["id"]),
                    attempt_number=int(lost["attempt_count"]),
                    stage=str(lost["stage"] or JobType.ANSWER),
                    failure_reason="lease_lost",
                    input_identity_sha256=request_identity,
                    max_attempts=min(policy_for(JobType.ANSWER).max_attempts, MAX_ATTEMPTS),
                    retryable=True,
                    input_or_condition_changed=lease_condition is not None,
                    condition_identity_sha256=lease_condition,
                    retry_operation="owner_resume_after_lease_loss",
                )
                checkpoint = {
                    "resumable": decision.should_retry,
                    "attempt_count": int(lost["attempt_count"]),
                    "job_type": JobType.ANSWER,
                    "retry_policy": {
                        "decision": decision.action,
                        "reason": decision.reason,
                        "failure_fingerprint_sha256": decision.failure_fingerprint,
                        "retries_remaining": decision.retries_remaining,
                        "operation": "owner_resume_after_lease_loss",
                        "condition_changed": lease_condition is not None,
                    },
                    "continuation_requires_new_linked_job_identity": not decision.should_retry,
                }
                conn.execute(
                    """
                    UPDATE jobs SET status='system_error', stage='system_error', progress=1,
                      terminal_reason_code=?, error_code='lease_lost',
                      checkpoint_json=?, lease_owner=NULL, lease_expires_at=NULL,
                      heartbeat_at=NULL, user_message=?, last_progress_at=?, updated_at=?
                    WHERE id=?
                    """,
                    (
                        None if decision.should_retry else decision.reason,
                        json.dumps(checkpoint, sort_keys=True),
                        (
                            "The answer job lost its lease; an exact owner resume is available under the bounded retry ledger."
                            if decision.should_retry
                            else "The answer job lost its lease and stopped under the bounded retry circuit."
                        ),
                        now_text,
                        now_text,
                        lost["id"],
                    ),
                )
                self._extend_upload_retention_for_job(conn, str(lost["id"]), now=now_text)
            expired_control = conn.execute(
                f"""
                SELECT * FROM jobs
                WHERE cancel_requested=0 AND status='running'
                  AND lease_expires_at IS NOT NULL AND lease_expires_at<?
                  AND COALESCE(job_type, 'answer')<>'answer'
                  AND {type_filter}
                ORDER BY created_at, id
                """,
                (now_text, *allowed_types),
            ).fetchall()
            for lost in expired_control:
                lost_type = str(lost["job_type"] or JobType.SCHEDULED_TASK)
                bounded_max = min(policy_for(lost_type).max_attempts, MAX_ATTEMPTS)
                request_identity = hashlib.sha256(
                    str(lost["request_json"] or "{}").encode("utf-8")
                ).hexdigest()
                lease_condition = hashlib.sha256(
                    (
                        "legalbot-expired-job-lease-v1\0"
                        + str(lost["lease_expires_at"] or "missing")
                    ).encode()
                ).hexdigest()
                decision = self._decide_retry_locked(
                    conn,
                    lane="job",
                    work_id=str(lost["id"]),
                    attempt_number=int(lost["attempt_count"]),
                    stage=str(lost["stage"] or lost_type),
                    failure_reason="worker_lease_expired",
                    input_identity_sha256=request_identity,
                    max_attempts=bounded_max,
                    retryable=True,
                    input_or_condition_changed=True,
                    condition_identity_sha256=lease_condition,
                    retry_operation="resume_after_lease_expiry",
                )
                terminal_status = "failed" if lost_type == JobType.INDEX_BUILD else "dlq"
                terminal = not decision.should_retry
                conn.execute(
                    """
                    UPDATE jobs SET status=?, stage=?, error_code='worker_lease_expired',
                      terminal_reason_code=?, dlq=?, lease_owner=NULL,
                      lease_expires_at=NULL, heartbeat_at=NULL,
                      user_message=?, last_progress_at=?, updated_at=?
                    WHERE id=? AND status='running'
                    """,
                    (
                        terminal_status if terminal else "queued",
                        "failed" if terminal else "queued",
                        decision.reason if terminal else None,
                        int(terminal and terminal_status == "dlq"),
                        (
                            "The expired control-plane lease stopped under the bounded retry policy."
                            if terminal
                            else "The expired control-plane lease will resume from its durable stage."
                        ),
                        now_text,
                        now_text,
                        lost["id"],
                    ),
                )
            queued_control = conn.execute(
                f"""
                SELECT id, job_type, attempt_count FROM jobs
                WHERE cancel_requested=0 AND status='queued' AND {type_filter}
                """,
                tuple(allowed_types),
            ).fetchall()
            for queued in queued_control:
                queued_type = str(queued["job_type"] or JobType.ANSWER)
                bounded_max = min(policy_for(queued_type).max_attempts, MAX_ATTEMPTS)
                if int(queued["attempt_count"] or 0) < bounded_max:
                    continue
                terminal_status = (
                    "system_error"
                    if queued_type == JobType.ANSWER
                    else "failed"
                    if queued_type == JobType.INDEX_BUILD
                    else "dlq"
                )
                conn.execute(
                    """
                    UPDATE jobs SET status=?, stage=?, progress=1,
                      terminal_reason_code='max_attempts_exhausted',
                      error_code=COALESCE(error_code, 'max_attempts_exhausted'),
                      dlq=?, user_message=?, last_progress_at=?, updated_at=?
                    WHERE id=? AND status='queued'
                    """,
                    (
                        terminal_status,
                        "system_error" if queued_type == JobType.ANSWER else "failed",
                        int(terminal_status == "dlq"),
                        "The durable job identity had already exhausted its three-attempt ceiling.",
                        now_text,
                        now_text,
                        queued["id"],
                    ),
                )
            row = conn.execute(
                f"""
                SELECT * FROM jobs
                WHERE cancel_requested=0 AND {type_filter}
                  AND status='queued' AND (
                    queue_wait_deadline_at IS NULL
                    OR queue_wait_deadline_at>=?
                  )
                ORDER BY created_at, id LIMIT 1
                """,
                (*allowed_types, now_text),
            ).fetchone()
            late = conn.execute(
                f"""
                SELECT id FROM jobs
                WHERE cancel_requested=0 AND status='queued'
                  AND {type_filter}
                  AND queue_wait_deadline_at IS NOT NULL
                  AND queue_wait_deadline_at<?
                """,
                (*allowed_types, now_text),
            ).fetchall()
            for item in late:
                conn.execute(
                    """
                    UPDATE jobs SET status=CASE WHEN COALESCE(job_type,'answer')='answer'
                      THEN 'system_error' ELSE 'failed' END,
                      stage='system_error', progress=1, terminal_reason_code='queue_wait_deadline_exceeded',
                      error_code='queue_wait_deadline_exceeded',
                      user_message='The job exceeded its queue-wait deadline.',
                      last_progress_at=?, updated_at=?
                    WHERE id=?
                    """,
                    (now_text, now_text, item["id"]),
                )
                self._extend_upload_retention_for_job(conn, str(item["id"]), now=now_text)
            if row is None:
                return None
            updated = conn.execute(
                """
                UPDATE jobs
                SET status='running', lease_owner=?, lease_expires_at=?, heartbeat_at=?,
                    attempt_count=attempt_count+1, last_progress_at=?, updated_at=?
                WHERE id=? AND cancel_requested=0 AND (
                  status='queued'
                )
                """,
                (worker_id, expires, now_text, now_text, now_text, row["id"]),
            )
            if updated.rowcount != 1:
                return None
            conn.execute(
                """
                UPDATE job_stage_attempts
                SET status='interrupted', error_code='worker_lease_expired', finished_at=?
                WHERE job_id=? AND status='running'
                """,
                (now_text, row["id"]),
            )
            return cast(
                sqlite3.Row,
                conn.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone(),
            )

    def heartbeat_job(
        self,
        job_id: str,
        worker_id: str,
        *,
        lease_seconds: int = 60,
        busy_timeout_ms: int | None = None,
    ) -> bool:
        now = datetime.now(UTC)
        parameters = (
            now.isoformat(),
            (now + timedelta(seconds=lease_seconds)).isoformat(),
            now.isoformat(),
            job_id,
            worker_id,
        )
        statement = """
            UPDATE jobs SET heartbeat_at=?, lease_expires_at=?, updated_at=?
            WHERE id=? AND status='running' AND lease_owner=?
            """
        if busy_timeout_ms is None:
            return self.execute(statement, parameters).rowcount == 1
        if not 1 <= busy_timeout_ms <= 30_000:
            raise ValueError("heartbeat busy timeout is outside the safe range")
        # The dedicated index heartbeat needs a bounded lock wait so it can
        # retry before its lease expires. Preserve the connection's ordinary
        # 30-second policy for every other catalogue operation.
        with self._lock:
            previous_timeout = int(
                self._connection.execute("PRAGMA busy_timeout").fetchone()[0]
            )
            try:
                self._require_primary_connection_identity_current()
                self._connection.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
                cursor = self._connection.execute(statement, parameters)
                self._require_primary_connection_identity_current()
                self._connection.commit()
                self._require_primary_connection_identity_current()
                return cursor.rowcount == 1
            except Exception:
                self._connection.rollback()
                raise
            finally:
                self._connection.execute(f"PRAGMA busy_timeout={previous_timeout}")

    def terminalize_owned_index_execution(
        self,
        job_id: str,
        worker_id: str,
        *,
        reason_code: str,
        message: str,
    ) -> bool:
        """Fail closed one running index job still owned by the exact worker."""

        from .types import JobType

        if re.fullmatch(r"[a-z0-9_]{2,120}", reason_code) is None:
            raise ValueError("index terminal reason code is invalid")
        cancelled = reason_code == "cancelled"
        status = "cancelled" if cancelled else "failed"
        stage = "cancelled" if cancelled else "failed"
        stamp = utc_iso()
        checkpoint = json.dumps(
            {
                "schema": "legalbot.index-worker-hard-stop.v1",
                "reason_code": reason_code,
                "resumable": False,
                "promotion_allowed": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT job_type,pinned_index_build_id FROM jobs "
                "WHERE id=? AND status='running' AND lease_owner=?",
                (job_id, worker_id),
            ).fetchone()
            if row is None or str(row["job_type"] or "") != JobType.INDEX_BUILD:
                return False
            updated = conn.execute(
                """
                UPDATE jobs SET status=?,stage=?,progress=1,cancel_requested=1,
                  error_code=?,terminal_reason_code=?,checkpoint_json=?,
                  user_message=?,lease_owner=NULL,lease_expires_at=NULL,heartbeat_at=NULL,
                  last_progress_at=?,updated_at=?
                WHERE id=? AND status='running' AND lease_owner=?
                """,
                (
                    status,
                    stage,
                    reason_code,
                    reason_code,
                    checkpoint,
                    message,
                    stamp,
                    stamp,
                    job_id,
                    worker_id,
                ),
            )
            if updated.rowcount != 1:
                return False
            build_id = str(row["pinned_index_build_id"] or "")
            if build_id:
                conn.execute(
                    """
                    UPDATE index_builds SET status='failed',stage='failed',
                      failure_reason_code=?,promotion_decision='blocked_failed'
                    WHERE id=? AND status IN ('queued','building','failed')
                    """,
                    (reason_code, build_id),
                )
            conn.execute(
                """
                INSERT INTO job_events(job_id,stage,progress,message,payload_json,created_at)
                VALUES (?, ?, 1, ?, ?, ?)
                """,
                (
                    job_id,
                    stage,
                    message,
                    json.dumps(
                        {"hard_stop": True, "reason_code": reason_code},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    stamp,
                ),
            )
            self._extend_upload_retention_for_job(conn, job_id, now=stamp)
            return True

    def job_lease_is_current(
        self,
        job_id: str,
        worker_id: str,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Return whether one job is still owned by an unexpired lease."""

        row = self.fetchone(
            "SELECT status,lease_owner,lease_expires_at FROM jobs WHERE id=?",
            (job_id,),
        )
        if (
            row is None
            or str(row["status"]) not in {"running", "failed"}
            or str(row["lease_owner"] or "") != worker_id
            or row["lease_expires_at"] in (None, "")
        ):
            return False
        try:
            expires_at = datetime.fromisoformat(str(row["lease_expires_at"]))
        except ValueError:
            return False
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return expires_at > (now or datetime.now(UTC))

    def release_job_lease(self, job_id: str, worker_id: str) -> None:
        self.execute(
            """
            UPDATE jobs SET lease_owner=NULL, lease_expires_at=NULL, heartbeat_at=NULL
            WHERE id=? AND lease_owner=?
            """,
            (job_id, worker_id),
        )

    def retry_or_fail_job(
        self,
        job_id: str,
        worker_id: str,
        *,
        error_code: str,
        input_or_condition_changed: bool,
        condition_identity_sha256: str | None,
        max_attempts: int | None = None,
        retryable: bool = True,
        retry_operation: str = "resume_durable_stage",
    ) -> str:
        from .jobs import policy_for, queue_capacity_for
        from .orchestration.retry_policy import MAX_ATTEMPTS

        now = utc_iso()
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None or row["lease_owner"] != worker_id:
                return "not_owned"
            job_type = str(row["job_type"])
            configured_max = (
                policy_for(job_type).max_attempts if max_attempts is None else max_attempts
            )
            bounded_max = min(max(1, int(configured_max)), MAX_ATTEMPTS)
            attempts = int(row["attempt_count"])
            request_identity = hashlib.sha256(
                str(row["request_json"] or "{}").encode("utf-8")
            ).hexdigest()
            decision = self._decide_retry_locked(
                conn,
                lane="job",
                work_id=job_id,
                attempt_number=attempts,
                stage=str(row["stage"] or job_type),
                failure_reason=error_code,
                input_identity_sha256=request_identity,
                max_attempts=bounded_max,
                retryable=retryable,
                input_or_condition_changed=input_or_condition_changed,
                condition_identity_sha256=condition_identity_sha256,
                retry_operation=retry_operation,
            )
            terminal = not decision.should_retry
            capacity_blocked = False
            if (
                decision.should_retry
                and job_type == "index_build"
                and str(row["status"]) not in {"queued", "running"}
            ):
                try:
                    self._require_job_queue_capacity_locked(
                        conn,
                        job_type=job_type,
                        capacity=queue_capacity_for(job_type),
                        exclude_job_id=job_id,
                    )
                except JobQueueCapacityError:
                    capacity_blocked = True
            if job_type == "answer":
                terminal_status = "system_error"
                use_dlq = False
            elif job_type == "index_build":
                terminal_status = "failed"
                use_dlq = True
            else:
                terminal_status = "dlq"
                use_dlq = True
            # Answer attempts never auto-loop.  A positive retry decision is
            # consumed only by the explicit resume endpoint, which preserves
            # the counter and immutable job identity.
            status = (
                "system_error"
                if job_type == "answer"
                else terminal_status
                if capacity_blocked
                else terminal_status
                if terminal
                else "queued"
            )
            stage = (
                "system_error"
                if job_type == "answer"
                else "failed"
                if terminal or capacity_blocked
                else "queued"
            )
            message = (
                "The local answer stopped after one attempt; an exact owner resume is available under the bounded retry ledger."
                if job_type == "answer" and decision.should_retry
                else "The local job stopped under the bounded retry policy; encrypted checkpoints remain available for owner review."
                if job_type == "answer"
                else (
                    "The index retry remains resumable but was not requeued because its bounded queue is full."
                    if capacity_blocked
                    else "The control-plane job stopped under the bounded retry policy and retained its safe debug trace."
                    if terminal
                    else "A targeted durable-stage retry was scheduled under the bounded retry policy."
                )
            )
            checkpoint = {
                "resumable": (decision.should_retry if job_type == "answer" else not terminal),
                "attempt_count": attempts,
                "job_type": job_type,
                "resume_mode": "owner_digest_checked" if job_type == "answer" else "automatic",
                "continuation_requires_new_linked_job_identity": bool(
                    job_type == "answer" and not decision.should_retry
                ),
                "retry_policy": {
                    "decision": decision.action,
                    "reason": decision.reason,
                    "failure_fingerprint_sha256": decision.failure_fingerprint,
                    "retries_remaining": decision.retries_remaining,
                    "operation": retry_operation,
                    "condition_changed": input_or_condition_changed,
                    "queue_capacity_blocked": capacity_blocked,
                },
            }
            conn.execute(
                """
                UPDATE jobs SET status=?, stage=?, progress=?, user_message=?,
                  error_code=?, checkpoint_json=?, last_progress_at=?, updated_at=?,
                  terminal_reason_code=?, dlq=?, lease_owner=NULL,
                  lease_expires_at=NULL, heartbeat_at=NULL
                WHERE id=? AND lease_owner=?
                """,
                (
                    status,
                    stage,
                    1 if terminal else float(row["progress"]),
                    message,
                    error_code,
                    json.dumps(checkpoint, sort_keys=True),
                    now,
                    now,
                    (
                        "max_attempts_exhausted"
                        if decision.reason == "retry_cap_exhausted"
                        else decision.reason
                        if terminal
                        else None
                    ),
                    int(use_dlq and terminal),
                    job_id,
                    worker_id,
                ),
            )
            conn.execute(
                """
                INSERT INTO job_events(job_id,stage,progress,message,payload_json,created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    stage,
                    1 if terminal else float(row["progress"]),
                    message,
                    json.dumps(
                        {
                            "retry_decision": decision.action,
                            "retry_reason": decision.reason,
                            "failure_fingerprint_sha256": decision.failure_fingerprint,
                        },
                        sort_keys=True,
                    ),
                    now,
                ),
            )
            if job_type == "answer":
                self._extend_upload_retention_for_job(conn, job_id, now=now)
            return status

    def begin_unleased_index_job_attempt(self, job_id: str) -> int:
        """Count a synchronous/operator index run without double-counting worker leases."""

        from .orchestration.retry_policy import MAX_ATTEMPTS
        from .types import JobType

        now = utc_iso()
        blocked_reason: str | None = None
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None or str(row["job_type"]) != JobType.INDEX_BUILD:
                raise ValueError("unleased attempt requires an index-build job")
            if row["lease_owner"]:
                return int(row["attempt_count"])
            if str(row["status"]) not in {"queued", "running"}:
                raise RuntimeError("index-build must be explicitly resumed before another attempt")
            attempt_count = int(row["attempt_count"] or 0)
            latest = conn.execute(
                "SELECT decision_action, decision_reason FROM retry_decisions "
                "WHERE lane='job' AND work_id=? ORDER BY attempt_number DESC LIMIT 1",
                (job_id,),
            ).fetchone()
            if latest is not None and str(latest["decision_action"]) == "stop":
                blocked_reason = str(latest["decision_reason"])
                conn.execute(
                    """
                    UPDATE jobs SET status='failed', stage='failed', progress=1,
                      terminal_reason_code=?,
                      user_message='The index-build retry circuit is terminal.',
                      updated_at=? WHERE id=?
                    """,
                    (blocked_reason, now, job_id),
                )
            elif attempt_count >= MAX_ATTEMPTS:
                blocked_reason = "max_attempts_exhausted"
                conn.execute(
                    """
                    UPDATE jobs SET status='failed', stage='failed', progress=1,
                      terminal_reason_code='max_attempts_exhausted',
                      error_code=COALESCE(error_code, 'max_attempts_exhausted'),
                      user_message='The index-build exhausted its three-attempt ceiling.',
                      updated_at=? WHERE id=?
                    """,
                    (now, job_id),
                )
            else:
                next_attempt = attempt_count + 1
                conn.execute(
                    """
                    UPDATE jobs SET status='running', attempt_count=?,
                      last_progress_at=?, updated_at=?
                    WHERE id=? AND lease_owner IS NULL
                    """,
                    (next_attempt, now, now, job_id),
                )
                return next_attempt
        raise RuntimeError(f"index-build retry circuit is terminal: {blocked_reason}")

    def record_unleased_index_job_failure(self, job_id: str, *, error_code: str) -> str:
        """Persist a safe retry/debug decision for a synchronous index attempt."""

        from .jobs import policy_for
        from .orchestration.retry_policy import MAX_ATTEMPTS
        from .types import JobType

        now = utc_iso()
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None or str(row["job_type"]) != JobType.INDEX_BUILD:
                raise ValueError("unleased failure requires an index-build job")
            if row["lease_owner"]:
                raise RuntimeError("leased index failures are decided by the dedicated worker")
            failed_attempt = conn.execute(
                """
                SELECT id FROM job_stage_attempts
                WHERE job_id=? AND status IN ('failed','interrupted')
                ORDER BY finished_at DESC, attempt_number DESC LIMIT 1
                """,
                (job_id,),
            ).fetchone()
            condition_identity = (
                hashlib.sha256(
                    ("legalbot-index-stage-retry-v1\0" + str(failed_attempt["id"])).encode()
                ).hexdigest()
                if failed_attempt is not None
                else None
            )
            request_identity = hashlib.sha256(
                str(row["request_json"] or "{}").encode("utf-8")
            ).hexdigest()
            decision = self._decide_retry_locked(
                conn,
                lane="job",
                work_id=job_id,
                attempt_number=int(row["attempt_count"]),
                stage=str(row["stage"] or JobType.INDEX_BUILD),
                failure_reason=error_code,
                input_identity_sha256=request_identity,
                max_attempts=min(policy_for(JobType.INDEX_BUILD).max_attempts, MAX_ATTEMPTS),
                retryable=True,
                input_or_condition_changed=condition_identity is not None,
                condition_identity_sha256=condition_identity,
                retry_operation="resume_failed_index_stage",
            )
            conn.execute(
                """
                UPDATE jobs SET terminal_reason_code=?, checkpoint_json=?, updated_at=?
                WHERE id=? AND lease_owner IS NULL
                """,
                (
                    decision.reason if not decision.should_retry else None,
                    json.dumps(
                        {
                            "resumable": decision.should_retry,
                            "attempt_count": int(row["attempt_count"]),
                            "job_type": JobType.INDEX_BUILD,
                            "retry_policy": {
                                "decision": decision.action,
                                "reason": decision.reason,
                                "failure_fingerprint_sha256": decision.failure_fingerprint,
                                "retries_remaining": decision.retries_remaining,
                                "operation": "resume_failed_index_stage",
                                "condition_changed": bool(condition_identity),
                            },
                        },
                        sort_keys=True,
                    ),
                    now,
                    job_id,
                ),
            )
            return decision.reason

    def store_stage_attempt(
        self,
        *,
        attempt_id: str,
        job_id: str,
        stage_key: str,
        section_key: str,
        attempt_number: int,
        status: str,
        encrypted_output: bytes | None,
        output_object_key: str | None = None,
        input_digest: str | None = None,
        evidence_pack_digest: str | None = None,
        metrics: Mapping[str, Any] | None = None,
        error_code: str | None = None,
    ) -> None:
        now = utc_iso()
        self.execute(
            """
            INSERT INTO job_stage_attempts(
              id, job_id, stage_key, section_key, attempt_number, status,
              input_digest, evidence_pack_digest, encrypted_output, output_object_key,
              metrics_json, error_code, started_at, finished_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attempt_id,
                job_id,
                stage_key,
                section_key,
                attempt_number,
                status,
                input_digest,
                evidence_pack_digest,
                encrypted_output,
                output_object_key,
                json.dumps(metrics or {}, sort_keys=True),
                error_code,
                now,
                now if status in {"complete", "failed"} else None,
            ),
        )

    def completed_stage_attempt(
        self, job_id: str, stage_key: str, section_key: str
    ) -> sqlite3.Row | None:
        return self.fetchone(
            """
            SELECT * FROM job_stage_attempts
            WHERE job_id=? AND stage_key=? AND section_key=? AND status='complete'
            ORDER BY attempt_number DESC LIMIT 1
            """,
            (job_id, stage_key, section_key),
        )

    def next_stage_attempt_number(self, job_id: str, stage_key: str, section_key: str) -> int:
        row = self.fetchone(
            """
            SELECT COALESCE(MAX(attempt_number), 0) + 1 AS value
            FROM job_stage_attempts WHERE job_id=? AND stage_key=? AND section_key=?
            """,
            (job_id, stage_key, section_key),
        )
        return int(row["value"]) if row is not None else 1

    def finish_stage_attempt(
        self,
        attempt_id: str,
        *,
        status: str,
        encrypted_output: bytes | None,
        output_object_key: str | None = None,
        metrics: Mapping[str, Any] | None = None,
        error_code: str | None = None,
    ) -> None:
        cursor = self.execute(
            """
            UPDATE job_stage_attempts
            SET status=?, encrypted_output=?, output_object_key=?, metrics_json=?,
                error_code=?, finished_at=?
            WHERE id=? AND status='running'
            """,
            (
                status,
                encrypted_output,
                output_object_key,
                json.dumps(metrics or {}, sort_keys=True),
                error_code,
                utc_iso(),
                attempt_id,
            ),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("stage attempt was not running")

    def freeze_evidence_pack(
        self,
        *,
        pack_id: str,
        job_id: str,
        section_key: str,
        digest: str,
        index_build_id: str,
        source_ids: Sequence[str],
        encrypted_payload: bytes,
        object_key: str | None = None,
    ) -> sqlite3.Row:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO evidence_packs(
                  id, job_id, section_key, digest, index_build_id,
                  source_ids_json, encrypted_payload, object_key, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pack_id,
                    job_id,
                    section_key,
                    digest,
                    index_build_id,
                    json.dumps(sorted(set(source_ids))),
                    encrypted_payload,
                    object_key,
                    utc_iso(),
                ),
            )
            existing = conn.execute(
                "SELECT * FROM evidence_packs WHERE job_id=? AND section_key=?",
                (job_id, section_key),
            ).fetchone()
            if existing is None or existing["digest"] != digest:
                raise RuntimeError("frozen evidence pack changed across resume")
            if object_key and existing["object_key"] != object_key:
                raise RuntimeError("frozen evidence object changed across resume")
            return cast(sqlite3.Row, existing)

    def activate_owner_canary_runtime_session(
        self,
        *,
        run_id: str,
        authorization_sha256: str,
        start_attestation_sha256: str,
        runtime_instance_sha256: str,
        candidate_build_id: str,
        memory_policy_sha256: str,
        controller_pid: int,
    ) -> None:
        """Create the sole DB-held live generation for one serial owner canary."""

        values = (
            authorization_sha256,
            start_attestation_sha256,
            runtime_instance_sha256,
            memory_policy_sha256,
        )
        if not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{2,127}", run_id) or any(
            not re.fullmatch(r"[0-9a-f]{64}", value) for value in values
        ):
            raise ValueError("owner-canary runtime session identity is invalid")
        if controller_pid != os.getpid():
            raise ValueError("owner-canary runtime controller PID is not current")
        now = utc_iso()
        lease_expires = (datetime.now(UTC) + timedelta(seconds=5)).isoformat()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO owner_canary_runtime_sessions(
                  run_id,authorization_sha256,start_attestation_sha256,
                  runtime_instance_sha256,candidate_build_id,memory_policy_sha256,
                  expected_case_count,next_sequence,frontier_generation,controller_pid,
                  heartbeat_at,lease_expires_at,status,updated_at
                ) VALUES (?,?,?,?,?,?,30,1,0,?,?,?,'active',?)
                """,
                (
                    run_id,
                    authorization_sha256,
                    start_attestation_sha256,
                    runtime_instance_sha256,
                    candidate_build_id,
                    memory_policy_sha256,
                    controller_pid,
                    now,
                    lease_expires,
                    now,
                ),
            )

    def heartbeat_owner_canary_runtime_session(
        self,
        *,
        run_id: str,
        start_attestation_sha256: str,
        runtime_instance_sha256: str,
        controller_pid: int,
        lease_seconds: int = 5,
    ) -> None:
        if not 5 <= lease_seconds <= 120:
            raise ValueError("owner-canary runtime heartbeat lease is invalid")
        now_value = datetime.now(UTC)
        now = now_value.isoformat()
        expires = (now_value + timedelta(seconds=lease_seconds)).isoformat()
        with self.transaction() as conn:
            updated = conn.execute(
                """
                UPDATE owner_canary_runtime_sessions
                SET heartbeat_at=?,lease_expires_at=?,updated_at=?
                WHERE run_id=? AND status='active' AND controller_pid=?
                  AND start_attestation_sha256=? AND runtime_instance_sha256=?
                  AND lease_expires_at>?
                """,
                (
                    now,
                    expires,
                    now,
                    run_id,
                    controller_pid,
                    start_attestation_sha256,
                    runtime_instance_sha256,
                    now,
                ),
            )
            if updated.rowcount != 1:
                raise RuntimeError("owner_canary_runtime_heartbeat_rejected")

    def owner_canary_runtime_session(self, run_id: str) -> sqlite3.Row | None:
        return self.fetchone(
            "SELECT * FROM owner_canary_runtime_sessions WHERE run_id=?", (run_id,)
        )

    def advance_owner_canary_runtime_before_case(
        self,
        *,
        run_id: str,
        sequence_number: int,
        case_id: str,
        checkpoint_sha256: str,
        start_attestation_sha256: str,
        runtime_instance_sha256: str,
    ) -> int:
        """CAS the exact serial frontier into one active case."""

        now = utc_iso()
        with self.transaction() as conn:
            updated = conn.execute(
                """
                UPDATE owner_canary_runtime_sessions
                SET active_case_id=?,active_before_checkpoint_sha256=?,
                    frontier_generation=frontier_generation+1,updated_at=?
                WHERE run_id=? AND status='active' AND next_sequence=?
                  AND active_case_id IS NULL AND start_attestation_sha256=?
                  AND runtime_instance_sha256=? AND controller_pid=?
                  AND lease_expires_at>?
                """,
                (
                    case_id,
                    checkpoint_sha256,
                    now,
                    run_id,
                    sequence_number,
                    start_attestation_sha256,
                    runtime_instance_sha256,
                    os.getpid(),
                    datetime.now(UTC).isoformat(),
                ),
            )
            if updated.rowcount != 1:
                raise RuntimeError("owner_canary_runtime_frontier_conflict")
            row = conn.execute(
                "SELECT frontier_generation FROM owner_canary_runtime_sessions WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("owner_canary_runtime_session_missing")
            return int(row["frontier_generation"])

    def advance_owner_canary_runtime_after_case(
        self,
        *,
        run_id: str,
        sequence_number: int,
        case_id: str,
        before_checkpoint_sha256: str,
        start_attestation_sha256: str,
        runtime_instance_sha256: str,
    ) -> int:
        """Close exactly the active case and advance to the next serial slot."""

        now = utc_iso()
        with self.transaction() as conn:
            updated = conn.execute(
                """
                UPDATE owner_canary_runtime_sessions
                SET active_case_id=NULL,active_before_checkpoint_sha256=NULL,
                    next_sequence=next_sequence+1,
                    frontier_generation=frontier_generation+1,updated_at=?
                WHERE run_id=? AND status='active' AND next_sequence=?
                  AND active_case_id=? AND active_before_checkpoint_sha256=?
                  AND start_attestation_sha256=? AND runtime_instance_sha256=?
                  AND controller_pid=? AND lease_expires_at>?
                """,
                (
                    now,
                    run_id,
                    sequence_number,
                    case_id,
                    before_checkpoint_sha256,
                    start_attestation_sha256,
                    runtime_instance_sha256,
                    os.getpid(),
                    datetime.now(UTC).isoformat(),
                ),
            )
            if updated.rowcount != 1:
                raise RuntimeError("owner_canary_runtime_frontier_conflict")
            row = conn.execute(
                "SELECT frontier_generation FROM owner_canary_runtime_sessions WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("owner_canary_runtime_session_missing")
            return int(row["frontier_generation"])

    def revoke_owner_canary_runtime_session(
        self,
        run_id: str,
        *,
        start_attestation_sha256: str,
        runtime_instance_sha256: str,
    ) -> None:
        """Revoke the runtime authority without rewriting immutable releases.

        Owner-evaluation reads replay this session frontier.  Once the CAS
        below marks it revoked, previously published rows are latent but no
        longer readable; the outbox/content graph remains an immutable audit
        record rather than being rewritten during incident handling.
        """

        now = utc_iso()
        with self.transaction() as conn:
            updated = conn.execute(
                """
                UPDATE owner_canary_runtime_sessions
                SET status='revoked',active_case_id=NULL,
                    active_before_checkpoint_sha256=NULL,
                    frontier_generation=frontier_generation+1,updated_at=?
                WHERE run_id=? AND start_attestation_sha256=?
                  AND runtime_instance_sha256=? AND status IN ('active','ended')
                """,
                (now, run_id, start_attestation_sha256, runtime_instance_sha256),
            )
            if updated.rowcount != 1:
                return

    def complete_owner_canary_runtime_session(
        self,
        *,
        run_id: str,
        start_attestation_sha256: str,
        runtime_instance_sha256: str,
        end_attestation_sha256: str,
    ) -> None:
        """CAS a fully traversed frontier to its immutable successful end."""

        with self.transaction() as conn:
            now = datetime.now(UTC)
            updated = conn.execute(
                """
                UPDATE owner_canary_runtime_sessions
                SET status='ended',end_attestation_sha256=?,
                    frontier_generation=frontier_generation+1,updated_at=?
                WHERE run_id=? AND status='active' AND next_sequence=31
                  AND active_case_id IS NULL AND start_attestation_sha256=?
                  AND runtime_instance_sha256=? AND controller_pid=?
                  AND lease_expires_at>?
                """,
                (
                    end_attestation_sha256,
                    utc_iso(),
                    run_id,
                    start_attestation_sha256,
                    runtime_instance_sha256,
                    os.getpid(),
                    now.isoformat(),
                ),
            )
            if updated.rowcount != 1:
                raise RuntimeError("owner_canary_runtime_end_frontier_invalid")

    @staticmethod
    def _verify_owner_canary_runtime_release_frontier(
        conn: sqlite3.Connection,
        authority: Mapping[str, Any],
    ) -> None:
        if authority.get("lane") != "owner_quality_canary":
            return
        row = conn.execute(
            "SELECT * FROM owner_canary_runtime_sessions WHERE run_id=?",
            (str(authority.get("run_id") or ""),),
        ).fetchone()
        if (
            row is None
            or row["status"] != "active"
            or row["authorization_sha256"] != authority.get("authorization_seal_sha256")
            or row["start_attestation_sha256"]
            != authority.get("owned_runtime_start_attestation_sha256")
            or row["runtime_instance_sha256"] != authority.get("owned_runtime_instance_sha256")
            or row["memory_policy_sha256"] != authority.get("owned_runtime_memory_policy_sha256")
            or int(row["controller_pid"]) != os.getpid()
            or datetime.fromisoformat(str(row["lease_expires_at"])) <= datetime.now(UTC)
            or row["active_case_id"] != authority.get("case_id")
            or row["active_before_checkpoint_sha256"]
            != authority.get("owned_runtime_before_checkpoint_sha256")
            or int(row["frontier_generation"])
            != int(authority.get("owned_runtime_frontier_generation") or -1)
        ):
            raise RuntimeError("owner_canary_runtime_release_frontier_changed")

    def release_answer_once(
        self,
        answer_id: str,
        release_state: str,
        *,
        expected_evaluation_authority_sha256: str | None = None,
        evaluation_authority_verifier: Callable[[], object] | None = None,
        normal_live_authority: Mapping[str, Any] | None = None,
        normal_live_authority_verifier: Callable[[], Mapping[str, Any]] | None = None,
    ) -> None:
        if release_state not in PUBLIC_RELEASE_STATES:
            self.execute(
                "UPDATE answer_versions SET release_state=? WHERE id=?",
                (release_state, answer_id),
            )
            return
        if release_state != "verified_full":
            raise RuntimeError(
                "first-live publication requires the exact verified_full release state"
            )
        # Full evaluation replay hashes the candidate/model/workspace and may
        # take longer than the live controller lease.  Perform it before the
        # IMMEDIATE transaction; the transaction below still performs the
        # exact DB frontier CAS plus a fast same-process monitor guard.
        preverified_evaluation_authority = (
            evaluation_authority_verifier() if evaluation_authority_verifier is not None else None
        )
        now = utc_iso()
        with self.transaction() as conn:
            answer = conn.execute(
                "SELECT * FROM answer_versions WHERE id=?", (answer_id,)
            ).fetchone()
            if answer is None:
                raise KeyError(answer_id)
            job_id = str(answer["job_id"])
            job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if (
                job is None
                or bool(job["cancel_requested"])
                or str(job["status"])
                in {"cancelled", "system_error", "held_for_review", "failed", "dlq"}
            ):
                raise RuntimeError("a cancelled or terminal job cannot publish a release")
            evaluation_values = (
                job["evaluation_run_id"],
                job["evaluation_case_id"],
                job["evaluation_request_sha256"],
                job["evaluation_authority_json"],
                job["evaluation_authority_sha256"],
            )
            evaluation_bound = any(value not in (None, "") for value in evaluation_values)
            owner_canary_evaluation = False
            owner_canary_content_graph_sha256: str | None = None
            released_answer_sha256: str | None = None
            if evaluation_bound:
                if not all(value not in (None, "") for value in evaluation_values):
                    raise RuntimeError("malformed evaluation work cannot publish a release")
                if (
                    expected_evaluation_authority_sha256 is None
                    or evaluation_authority_verifier is None
                    or job["evaluation_authority_sha256"] != expected_evaluation_authority_sha256
                ):
                    raise RuntimeError(
                        "evaluation authority was not replayed for this atomic release"
                    )
                from .evaluation.evaluation_job_authority import (
                    verified_evaluation_release_authority_sha256,
                )

                replayed_evaluation_sha256 = verified_evaluation_release_authority_sha256(
                    preverified_evaluation_authority
                )
                if replayed_evaluation_sha256 != expected_evaluation_authority_sha256:
                    raise RuntimeError("evaluation authority changed during atomic release replay")
                try:
                    evaluation_authority = json.loads(str(job["evaluation_authority_json"]))
                except json.JSONDecodeError as exc:
                    raise RuntimeError("evaluation release authority is invalid") from exc
                if not isinstance(evaluation_authority, dict):
                    raise RuntimeError("evaluation release authority is invalid")
                authority_material = dict(evaluation_authority)
                authority_material.pop("seal_sha256", None)
                authority_seal = hashlib.sha256(
                    (
                        json.dumps(
                            authority_material,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n"
                    ).encode("utf-8")
                ).hexdigest()
                if evaluation_authority.get("lane") in {
                    "live60_evaluation_v2",
                    "live60_o04_v1",
                }:
                    raise RuntimeError(
                        "TECHNICAL_IMPLEMENTATION_REQUIRED:"
                        "superseded_evaluation_release_content_certification_missing"
                    )
                if (
                    evaluation_authority.get("schema")
                    != "legalbot.persisted-evaluation-job-authority.v1"
                    or evaluation_authority.get("lane") != "owner_quality_canary"
                    or evaluation_authority.get("release_allowed") is not True
                    or evaluation_authority.get("writes_active") is not False
                    or evaluation_authority.get("seal_sha256") != authority_seal
                    or authority_seal != expected_evaluation_authority_sha256
                ):
                    raise RuntimeError("evaluation lane is not authorised to publish a release")
                owner_canary_evaluation = evaluation_authority.get("lane") == "owner_quality_canary"
                self._verify_owner_canary_runtime_release_frontier(conn, evaluation_authority)
                if evaluation_authority.get("lane") == "owner_quality_canary":
                    from .evaluation.evaluation_job_authority import (
                        verified_owner_canary_content_graph,
                    )
                    from .evaluation.owner_quality_owned_model_runtime import (
                        verify_owner_canary_runtime_atomic_release,
                    )

                    content_graph = verified_owner_canary_content_graph(
                        preverified_evaluation_authority
                    )
                    if content_graph.job_id != job_id or content_graph.answer_id != answer_id:
                        raise RuntimeError("owner-canary content graph release identity differs")
                    owner_canary_content_graph_sha256 = content_graph.graph_sha256
                    released_answer_sha256 = content_graph.answer_sha256
                    verify_owner_canary_runtime_atomic_release(evaluation_authority)
            elif expected_evaluation_authority_sha256 is not None:
                raise RuntimeError("ordinary work cannot use an evaluation release authority")
            elif evaluation_authority_verifier is not None:
                raise RuntimeError("ordinary work cannot use an evaluation authority verifier")
            normal_live_authority_sha256: str | None = None
            if not evaluation_bound:
                raise RuntimeError(
                    "TECHNICAL_IMPLEMENTATION_REQUIRED:"
                    "normal_live_release_content_certification_missing"
                )
            if evaluation_bound:
                if normal_live_authority is not None or normal_live_authority_verifier is not None:
                    raise RuntimeError("evaluation work cannot use normal-live authority")
            else:
                if normal_live_authority is None or normal_live_authority_verifier is None:
                    raise RuntimeError(
                        "ordinary release requires an atomically replayed normal-live authority"
                    )
                supplied_normal = dict(normal_live_authority)
                replayed_normal = dict(normal_live_authority_verifier())
                supplied_bytes = (
                    json.dumps(
                        supplied_normal,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
                replayed_bytes = (
                    json.dumps(
                        replayed_normal,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
                normal_material = dict(replayed_normal)
                normal_material.pop("seal_sha256", None)
                normal_live_authority_sha256 = hashlib.sha256(
                    (
                        json.dumps(
                            normal_material,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n"
                    ).encode("utf-8")
                ).hexdigest()
                pinned_build_id = str(job["pinned_index_build_id"] or "")
                active_row = conn.execute(
                    "SELECT id FROM index_builds WHERE status='active'"
                ).fetchall()
                readiness_state = conn.execute(
                    """
                    SELECT generation_sha256,authority_sha256,candidate_build_id,active
                    FROM normal_live_readiness_state
                    WHERE scope='owner-only-normal-live'
                    """
                ).fetchone()
                if (
                    supplied_bytes != replayed_bytes
                    or replayed_normal.get("schema")
                    != "legalbot.owner-quality-normal-live-release-authority.v1"
                    or replayed_normal.get("normal_live_ready") is not True
                    or replayed_normal.get("release_audience") != "normal_live"
                    or replayed_normal.get("trusted_owner_o04_signature_verified") is not True
                    or replayed_normal.get("trusted_post_run_owner_acceptance_signature_verified")
                    is not True
                    or replayed_normal.get("seal_sha256") != normal_live_authority_sha256
                    or replayed_normal.get("candidate_build_id") != pinned_build_id
                    or len(active_row) != 1
                    or str(active_row[0]["id"]) != pinned_build_id
                    or readiness_state is None
                    or not bool(readiness_state["active"])
                    or readiness_state["generation_sha256"]
                    != replayed_normal.get("readiness_generation_sha256")
                    or readiness_state["authority_sha256"] != normal_live_authority_sha256
                    or readiness_state["candidate_build_id"] != pinned_build_id
                ):
                    raise RuntimeError("normal-live release authority is absent or stale")
            key = hashlib.sha256(f"release-v1\0{job_id}".encode()).hexdigest()
            release_audience = "owner_evaluation" if evaluation_bound else "normal_live"
            existing = conn.execute(
                "SELECT id,job_id,answer_id, release_state, release_audience, "
                "evaluation_authority_sha256, normal_live_authority_sha256, "
                "owner_canary_content_graph_sha256, answer_sha256, "
                "idempotency_key,status,published_at "
                "FROM release_outbox WHERE job_id=?",
                (job_id,),
            ).fetchone()
            if existing is not None and (
                existing["id"] != f"release-{key[:40]}"
                or existing["job_id"] != job_id
                or existing["answer_id"] != answer_id
                or existing["release_state"] != release_state
                or existing["release_audience"] != release_audience
                or existing["evaluation_authority_sha256"] != expected_evaluation_authority_sha256
                or existing["normal_live_authority_sha256"] != normal_live_authority_sha256
                or existing["owner_canary_content_graph_sha256"]
                != owner_canary_content_graph_sha256
                or existing["answer_sha256"] != released_answer_sha256
                or existing["idempotency_key"] != key
                or existing["status"] != "published"
                or existing["published_at"] in (None, "")
            ):
                raise RuntimeError("a different answer was already released for this job")
            if owner_canary_evaluation and existing is None:
                release_now = datetime.now(UTC)

                def _future_fence(value: object) -> bool:
                    if value in (None, ""):
                        return False
                    try:
                        parsed = datetime.fromisoformat(str(value))
                    except ValueError:
                        return False
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=UTC)
                    return parsed > release_now

                if (
                    job["lease_owner"] in (None, "")
                    or not _future_fence(job["lease_expires_at"])
                    or not _future_fence(job["workflow_deadline_at"])
                    or not _future_fence(job["stage_deadline_at"])
                    or job["model_call_deadline_at"] not in (None, "")
                    or job["model_call_token"] not in (None, "")
                ):
                    raise RuntimeError("owner_canary_job_execution_fence_expired")
            if existing is None:
                if (
                    answer["release_state"] is not None
                    or job["answer_id"] is not None
                    or job["release_state"] is not None
                    or str(job["status"] or "") != "running"
                    or str(job["stage"] or "") != "verifying"
                ):
                    raise RuntimeError("atomic release pre-release phase changed")
            elif (
                str(answer["release_state"] or "") != release_state
                or str(job["answer_id"] or "") != answer_id
                or str(job["release_state"] or "") != release_state
                or str(job["status"] or "") != "complete"
                or str(job["stage"] or "") != "complete"
            ):
                raise RuntimeError("atomic release already-released phase changed")
            if owner_canary_evaluation:
                # Full content replay intentionally occurs before BEGIN
                # IMMEDIATE.  At the final write boundary, recheck the opaque
                # capability's exact raw-path metadata snapshot only: no
                # candidate, model, workspace or tracked-input file content is
                # read or hashed while SQLite is locked.  The DB and in-process
                # frontier checks are repeated after that bounded check so the
                # five-second runtime lease is current at the first durable
                # write as well.
                from .evaluation.evaluation_job_authority import (
                    require_verified_owner_canary_content_graph_current,
                    require_verified_owner_canary_release_snapshot_current,
                )
                from .evaluation.owner_quality_owned_model_runtime import (
                    verify_owner_canary_runtime_atomic_release,
                )

                require_verified_owner_canary_release_snapshot_current(
                    preverified_evaluation_authority
                )
                current_graph = require_verified_owner_canary_content_graph_current(
                    conn,
                    authority=preverified_evaluation_authority,
                    candidate_build_id=str(evaluation_authority["candidate_build_id"]),
                    case_id=str(evaluation_authority["case_id"]),
                    as_of_date=date.fromisoformat(str(evaluation_authority["review_date"])),
                    job_id=job_id,
                    answer_id=answer_id,
                )
                if (
                    current_graph.graph_sha256 != owner_canary_content_graph_sha256
                    or current_graph.answer_sha256 != released_answer_sha256
                ):
                    raise RuntimeError("owner-canary content graph capability changed")
                self._verify_owner_canary_runtime_release_frontier(conn, evaluation_authority)
                verify_owner_canary_runtime_atomic_release(evaluation_authority)
                require_release_outbox_schema_contract(conn)
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO release_outbox(
                      id, job_id, answer_id, release_state, release_audience,
                      evaluation_authority_sha256, normal_live_authority_sha256,
                      owner_canary_content_graph_sha256, answer_sha256,
                      idempotency_key, status, created_at, published_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'published', ?, ?)
                    """,
                    (
                        f"release-{key[:40]}",
                        job_id,
                        answer_id,
                        release_state,
                        release_audience,
                        expected_evaluation_authority_sha256,
                        normal_live_authority_sha256,
                        owner_canary_content_graph_sha256,
                        released_answer_sha256,
                        key,
                        now,
                        now,
                    ),
                )
            persisted_outbox = conn.execute(
                "SELECT * FROM release_outbox WHERE job_id=?", (job_id,)
            ).fetchall()
            if len(persisted_outbox) != 1:
                raise RuntimeError("atomic release outbox write was not unique")
            persisted = persisted_outbox[0]
            if (
                persisted["id"] != f"release-{key[:40]}"
                or persisted["job_id"] != job_id
                or persisted["answer_id"] != answer_id
                or persisted["release_state"] != release_state
                or persisted["release_audience"] != release_audience
                or persisted["evaluation_authority_sha256"] != expected_evaluation_authority_sha256
                or persisted["normal_live_authority_sha256"] != normal_live_authority_sha256
                or persisted["owner_canary_content_graph_sha256"]
                != owner_canary_content_graph_sha256
                or persisted["answer_sha256"] != released_answer_sha256
                or persisted["idempotency_key"] != key
                or persisted["status"] != "published"
                or persisted["published_at"] in (None, "")
            ):
                raise RuntimeError("atomic release outbox binding differs")
            if existing is None:
                updated_answer = conn.execute(
                    """
                    UPDATE answer_versions SET release_state=?, purge_after=NULL
                    WHERE id=? AND release_state IS NULL
                    """,
                    (release_state, answer_id),
                )
                if updated_answer.rowcount != 1:
                    raise RuntimeError("answer release state raced with atomic publication")
                stage = "limited" if release_state == "verified_limited" else "complete"
                updated = conn.execute(
                    """
                    UPDATE jobs SET status='complete', stage=?, progress=1,
                      answer_id=?, release_state=?, updated_at=?
                    WHERE id=? AND cancel_requested=0
                      AND status='running' AND stage='verifying'
                      AND answer_id IS NULL AND release_state IS NULL
                    """,
                    (stage, answer_id, release_state, now, job_id),
                )
                if updated.rowcount != 1:
                    raise RuntimeError("job release phase raced with atomic publication")

    def activate_normal_live_readiness_state(
        self,
        authority: Mapping[str, Any],
        *,
        verifier: Callable[[], Mapping[str, Any]],
    ) -> str:
        """CAS one replayed readiness generation into the release transaction domain."""

        supplied = dict(authority)
        replayed = dict(verifier())
        if supplied != replayed:
            raise RuntimeError("normal-live readiness changed during activation")
        material = dict(replayed)
        observed_seal = str(material.pop("seal_sha256", ""))
        expected_seal = hashlib.sha256(
            (
                json.dumps(
                    material,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        ).hexdigest()
        generation = str(replayed.get("readiness_generation_sha256") or "")
        candidate_build_id = str(replayed.get("candidate_build_id") or "")
        if (
            replayed.get("schema") != "legalbot.owner-quality-normal-live-release-authority.v1"
            or replayed.get("normal_live_ready") is not True
            or replayed.get("release_audience") != "normal_live"
            or replayed.get("trusted_owner_o04_signature_verified") is not True
            or replayed.get("trusted_post_run_owner_acceptance_signature_verified") is not True
            or observed_seal != expected_seal
            or not re.fullmatch(r"[0-9a-f]{64}", generation)
            or not candidate_build_id
        ):
            raise RuntimeError("normal-live readiness authority is invalid")
        now = utc_iso()
        with self.transaction() as conn:
            active = conn.execute("SELECT id FROM index_builds WHERE status='active'").fetchall()
            if len(active) != 1 or str(active[0]["id"]) != candidate_build_id:
                raise RuntimeError("normal-live readiness candidate is not ACTIVE")
            conn.execute(
                """
                INSERT INTO normal_live_readiness_state(
                  scope,generation_sha256,authority_sha256,candidate_build_id,active,updated_at
                ) VALUES ('owner-only-normal-live',?,?,?,?,?)
                ON CONFLICT(scope) DO UPDATE SET
                  generation_sha256=excluded.generation_sha256,
                  authority_sha256=excluded.authority_sha256,
                  candidate_build_id=excluded.candidate_build_id,
                  active=excluded.active,
                  updated_at=excluded.updated_at
                """,
                (generation, observed_seal, candidate_build_id, 1, now),
            )
        return observed_seal

    def revoke_normal_live_readiness_state(self) -> None:
        """Atomically revoke the currently admitted readiness generation, if any."""

        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE normal_live_readiness_state SET active=0, updated_at=?
                WHERE scope='owner-only-normal-live'
                """,
                (utc_iso(),),
            )

    def normal_live_readiness_state(self) -> sqlite3.Row | None:
        """Return the single transactional owner-only readiness generation."""

        return self.fetchone(
            "SELECT * FROM normal_live_readiness_state WHERE scope='owner-only-normal-live'"
        )

    def released_outbox_for_job(self, job_id: str) -> sqlite3.Row | None:
        return self.fetchone(
            "SELECT * FROM release_outbox WHERE job_id=? AND status='published'",
            (job_id,),
        )

    def store_runtime_object(
        self,
        *,
        object_key: str,
        namespace: str,
        content_sha256: str,
        relative_path: str,
        byte_size: int,
        metadata: Mapping[str, Any],
        expires_at: str | None,
    ) -> None:
        self.execute(
            """
            INSERT OR IGNORE INTO runtime_objects(
              object_key, namespace, content_sha256, relative_path, byte_size,
              metadata_json, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                object_key,
                namespace,
                content_sha256,
                relative_path,
                byte_size,
                json.dumps(dict(metadata), sort_keys=True),
                expires_at,
                utc_iso(),
            ),
        )

    def pulse_service(
        self,
        service_key: str,
        instance_id: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        self.execute(
            """
            INSERT INTO service_heartbeats(service_key, instance_id, heartbeat_at, metadata_json)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(service_key) DO UPDATE SET
              instance_id=excluded.instance_id,
              heartbeat_at=excluded.heartbeat_at,
              metadata_json=excluded.metadata_json
            """,
            (
                service_key,
                instance_id,
                utc_iso(),
                json.dumps(metadata or {}, sort_keys=True),
            ),
        )

    def service_is_recent(self, service_key: str, *, within_seconds: int = 30) -> bool:
        row = self.fetchone(
            "SELECT heartbeat_at FROM service_heartbeats WHERE service_key=?",
            (service_key,),
        )
        if row is None:
            return False
        try:
            heartbeat = datetime.fromisoformat(str(row["heartbeat_at"]))
        except ValueError:
            return False
        return heartbeat >= datetime.now(UTC) - timedelta(seconds=within_seconds)

    def create_evaluation_issue(
        self,
        *,
        issue_id: str,
        run_id: str | None,
        case_id: str | None,
        job_id: str | None,
        category: str,
        severity: str,
        affected_layer: str,
        expected_ids: Sequence[str],
        observed_ids: Sequence[str],
        encrypted_note: bytes | None,
        create_debug_refinement: bool = False,
        answer_id: str | None = None,
    ) -> None:
        safe_id = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
        if any(not safe_id.fullmatch(value) for value in (*expected_ids, *observed_ids)):
            raise ValueError("evaluation issue contains an unsafe identifier")
        now = utc_iso()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO evaluation_issues(
                  id, run_id, case_id, job_id, category, severity, affected_layer,
                  safe_expected_ids_json, safe_observed_ids_json, status,
                  encrypted_human_note, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)
                """,
                (
                    issue_id,
                    run_id,
                    case_id,
                    job_id,
                    category,
                    severity,
                    affected_layer,
                    json.dumps(list(expected_ids), sort_keys=True),
                    json.dumps(list(observed_ids), sort_keys=True),
                    encrypted_note,
                    now,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO evaluation_issue_events(
                  issue_id, event_type, status, safe_payload_json, encrypted_note, created_at
                ) VALUES (?, 'opened', 'open', '{}', ?, ?)
                """,
                (issue_id, encrypted_note, now),
            )
            if create_debug_refinement:
                if answer_id is None or job_id is None:
                    raise ValueError(
                        "answer-linked evaluation issue requires answer and job identities"
                    )
                priority = {
                    "low": 20,
                    "medium": 60,
                    "high": 90,
                    "critical": 100,
                }.get(severity)
                if priority is None:
                    raise ValueError("evaluation issue severity is invalid")
                refinement_digest = hashlib.sha256(
                    f"legalbot-evaluation-issue-refinement-v1\0{issue_id}".encode()
                ).hexdigest()
                refinement_id = f"refinement-issue-{refinement_digest[:40]}"
                conn.execute(
                    """
                    INSERT INTO refinements(
                      id, fingerprint, category, scope, priority, status, origin,
                      answer_id, job_id, safe_target_json, created_at, updated_at
                    ) VALUES (?, ?, 'debug', 'answer', ?, 'open', 'answer_issue',
                              ?, ?, ?, ?, ?)
                    """,
                    (
                        refinement_id,
                        f"evaluation-issue:{issue_id}",
                        priority,
                        answer_id,
                        job_id,
                        json.dumps(
                            {
                                "issue_id": issue_id,
                                "answer_id": answer_id,
                                "job_id": job_id,
                            },
                            sort_keys=True,
                        ),
                        now,
                        now,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO refinement_events(
                      refinement_id, event_type, from_status, to_status,
                      safe_payload_json, created_at
                    ) VALUES (?, 'created', NULL, 'open', '{}', ?)
                    """,
                    (refinement_id, now),
                )

    def store_answer_version(
        self,
        *,
        answer_id: str,
        job_id: str,
        version_number: int,
        version_kind: str,
        encrypted_content: bytes,
        word_count: int,
        policy_version: str,
        model_version: str,
        index_build_id: str | None,
        release_state: str | None = None,
        parent_version_id: str | None = None,
        encrypted_diff_from_parent: bytes | None = None,
        purge_after_days: int | None = 30,
    ) -> None:
        from .quality.policy import POLICY_SHA256

        purge_after = None
        if purge_after_days is not None:
            purge_after = (datetime.now(UTC) + timedelta(days=purge_after_days)).isoformat()
        self.execute(
            """
            INSERT INTO answer_versions(
              id, job_id, version_number, version_kind, encrypted_content, word_count,
              release_state, parent_version_id, diff_from_parent, encrypted_diff_from_parent,
              policy_version, policy_sha256,
              model_version, index_build_id, purge_after, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                answer_id,
                job_id,
                version_number,
                version_kind,
                encrypted_content,
                word_count,
                release_state,
                parent_version_id,
                encrypted_diff_from_parent,
                policy_version,
                POLICY_SHA256,
                model_version,
                index_build_id,
                purge_after,
                utc_iso(),
            ),
        )

    def answer(self, answer_id: str) -> sqlite3.Row | None:
        return self.fetchone("SELECT * FROM answer_versions WHERE id=?", (answer_id,))

    def answer_versions(self, job_id: str) -> list[sqlite3.Row]:
        return self.fetchall(
            "SELECT * FROM answer_versions WHERE job_id=? ORDER BY version_number",
            (job_id,),
        )

    def next_answer_version_number(self, job_id: str) -> int:
        row = self.fetchone(
            "SELECT COALESCE(MAX(version_number), 0) + 1 AS value FROM answer_versions WHERE job_id=?",
            (job_id,),
        )
        return int(row["value"]) if row is not None else 1

    def store_evidence(self, items: Sequence[dict[str, Any]]) -> None:
        if not items:
            return
        with self.transaction() as conn:
            for item in items:
                citation_json = json.dumps(
                    item.get("citation_data", {}),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                reviews_json = json.dumps(
                    item.get("case_currentness_reviews", []),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                seals_json = json.dumps(
                    item.get("case_currentness_manifest_seals", []),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                threshold_qualified = item.get("retrieval_threshold_qualified")
                expected = (
                    item["source_version_id"],
                    item["chunk_id"],
                    item["text"],
                    item["locator"],
                    item["lane"],
                    item["jurisdiction"],
                    item["subject"],
                    citation_json,
                    item.get("canonical_citation"),
                    item.get("currentness_status", "unknown"),
                    item["content_sha256"],
                    item["index_build_id"],
                    item.get("canonical_url"),
                    item.get("retrieval_relevance_score"),
                    item.get("retrieval_route"),
                    item.get("retrieval_threshold"),
                    item.get("retrieval_threshold_policy_sha256"),
                    (
                        None
                        if threshold_qualified is None
                        else int(bool(threshold_qualified))
                    ),
                    item.get("retrieval_qualification_reason"),
                    item.get("legal_role", "unclassified"),
                    item.get("unapplied_effect_count"),
                    item.get("provision_extent_status", "unverified"),
                    int(bool(item.get("identity_verified"))),
                    int(bool(item.get("currentness_verified"))),
                    reviews_json,
                    seals_json,
                )
                existing = conn.execute(
                    "SELECT * FROM evidence_spans WHERE id=?", (item["id"],)
                ).fetchone()
                if existing is not None:
                    observed = (
                        existing["source_version_id"],
                        existing["chunk_id"],
                        existing["span_text"],
                        existing["locator"],
                        existing["lane"],
                        existing["jurisdiction"],
                        existing["subject"],
                        json.dumps(
                            json.loads(existing["citation_data_json"] or "{}"),
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        existing["canonical_citation"],
                        existing["currentness_status"],
                        existing["content_sha256"],
                        existing["index_build_id"],
                        existing["canonical_url"],
                        existing["retrieval_relevance_score"],
                        existing["retrieval_route"],
                        existing["retrieval_threshold"],
                        existing["retrieval_threshold_policy_sha256"],
                        (
                            None
                            if existing["retrieval_threshold_qualified"] is None
                            else int(existing["retrieval_threshold_qualified"])
                        ),
                        existing["retrieval_qualification_reason"],
                        existing["legal_role"],
                        existing["unapplied_effect_count"],
                        existing["provision_extent_status"],
                        int(existing["identity_verified"] or 0),
                        int(existing["currentness_verified"] or 0),
                        json.dumps(
                            json.loads(existing["case_currentness_reviews_json"] or "[]"),
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        json.dumps(
                            json.loads(existing["case_currentness_manifest_seals_json"] or "[]"),
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    )
                    if observed != expected:
                        raise RuntimeError(
                            "immutable evidence identity collides with different content"
                        )
                    continue
                conn.execute(
                    """
                    INSERT INTO evidence_spans(
                      id, source_version_id, chunk_id, span_text, locator, lane, jurisdiction,
                      subject, citation_data_json, canonical_citation, currentness_status,
                      content_sha256, index_build_id, canonical_url,
                      retrieval_relevance_score, retrieval_route, retrieval_threshold,
                      retrieval_threshold_policy_sha256, retrieval_threshold_qualified,
                      retrieval_qualification_reason, legal_role, unapplied_effect_count,
                      provision_extent_status, identity_verified, currentness_verified,
                      case_currentness_reviews_json,
                      case_currentness_manifest_seals_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (item["id"], *expected, utc_iso()),
                )

    def stage_online_source(
        self,
        *,
        source_id: str,
        canonical_url: str,
        title: str,
        content_sha256: str,
        as_of_date: date,
        currentness_status: str,
        licence_name: str,
        licence_url: str | None,
        lane: str,
        jurisdiction: str,
        subject: str,
        excerpts: Sequence[Mapping[str, str]],
    ) -> dict[str, Any]:
        """Persist non-searchable answer evidence and its review provenance.

        This is deliberately not an ingestion or promotion path: the synthetic
        build has no vectors, is never active, and every document is marked as
        non-canonical/non-searchable.  The rows exist only so a released answer
        can retain a frozen, foreign-key-safe evidence snapshot.
        """

        parsed = urlparse(canonical_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, 443}
        ):
            raise ValueError("online staged evidence requires a public HTTPS identifier")
        if not re.fullmatch(r"[a-z0-9_]+", source_id):
            raise ValueError("invalid registered online source id")
        if not re.fullmatch(r"[0-9a-f]{64}", content_sha256):
            raise ValueError("online staged evidence requires a SHA-256 digest")
        if lane not in {"primary_authority", "official_secondary", "scholarship"}:
            raise ValueError("online staged evidence must use a citable lane")
        normalised_excerpts = [
            {
                "text": " ".join(str(item.get("text", "")).split()),
                "locator": " ".join(str(item.get("locator", "")).split()),
            }
            for item in excerpts
        ]
        if not normalised_excerpts or any(
            not item["text"] or not item["locator"] for item in normalised_excerpts
        ):
            raise ValueError("online staged evidence requires located, non-empty excerpts")

        identity_digest = hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()
        version_digest = hashlib.sha256(
            (
                f"{canonical_url}\0{as_of_date.isoformat()}\0{content_sha256}\0"
                f"{lane}\0{jurisdiction}\0{subject}"
            ).encode()
        ).hexdigest()
        document_id = f"online-doc-{version_digest[:32]}"
        source_version_id = f"online-source-{version_digest[:32]}"
        build_id = f"online-stage:{version_digest[:32]}"
        now = utc_iso()
        chunk_records: list[dict[str, str]] = []
        for ordinal, item in enumerate(normalised_excerpts):
            text_sha256 = hashlib.sha256(item["text"].encode("utf-8")).hexdigest()
            chunk_digest = hashlib.sha256(
                f"{source_version_id}\0{item['locator']}\0{text_sha256}".encode()
            ).hexdigest()
            chunk_records.append(
                {
                    "id": f"online-chunk-{chunk_digest[:32]}",
                    "text": item["text"],
                    "locator": item["locator"],
                    "text_sha256": text_sha256,
                    "ordinal": str(ordinal),
                }
            )

        with self.transaction() as conn:
            existing = conn.execute(
                """
                SELECT id FROM documents
                WHERE content_sha256=? AND id<>?
                  AND COALESCE(lane, '')=COALESCE(?, '')
                  AND COALESCE(jurisdiction, '')=COALESCE(?, '')
                  AND COALESCE(subject_primary, '')=COALESCE(?, '')
                  AND duplicate_of IS NULL
                ORDER BY id LIMIT 1
                """,
                (content_sha256, document_id, lane, jurisdiction, subject),
            ).fetchone()
            duplicate_of = str(existing["id"]) if existing is not None else None
            conn.execute(
                """
                INSERT OR IGNORE INTO documents(
                  id, content_sha256, source_identity_id, representation_group_id,
                  safe_display_name, media_type, status, lane, subject_primary,
                  subject_secondary_json, jurisdiction, duplicate_of,
                  retrieval_canonical, has_annotations, searchable_text, dedupe_status,
                  created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'application/xml', 'citable', ?, ?, '[]', ?, ?,
                          0, 0, 0, 'online_staged_non_searchable', ?, ?)
                """,
                (
                    document_id,
                    content_sha256,
                    f"official-url-sha256:{identity_digest}",
                    f"online-representation:{identity_digest}",
                    f"official-online-{source_id}.xml",
                    lane,
                    subject,
                    jurisdiction,
                    duplicate_of,
                    now,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO source_versions(
                  id, document_id, version_sha256, canonical_markdown_path, title,
                  as_of_date, canonical_url, stable_identifier, currentness_status,
                  licence_name, licence_url, review_status, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'staged', ?, ?)
                """,
                (
                    source_version_id,
                    document_id,
                    content_sha256,
                    f"staged://official-online/{version_digest}",
                    title,
                    as_of_date.isoformat(),
                    canonical_url,
                    canonical_url,
                    currentness_status,
                    licence_name,
                    licence_url,
                    json.dumps(
                        {
                            "source_id": source_id,
                            "disposition": "answer_scoped_staging",
                            "permanent_index_eligible": False,
                            "human_review_required": True,
                        },
                        sort_keys=True,
                    ),
                    now,
                ),
            )
            for record in chunk_records:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO chunks(
                      id, source_version_id, ordinal, locator, text_sha256,
                      markdown_text, token_count, stream, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'online_answer_evidence', ?)
                    """,
                    (
                        record["id"],
                        source_version_id,
                        int(record["ordinal"]),
                        record["locator"],
                        record["text_sha256"],
                        record["text"],
                        max(1, len(record["text"].split())),
                        json.dumps(
                            {
                                "source_id": source_id,
                                "answer_scoped": True,
                                "permanent_index_eligible": False,
                            },
                            sort_keys=True,
                        ),
                    ),
                )
            conn.execute(
                """
                INSERT OR IGNORE INTO index_builds(
                  id, status, path, document_count, chunk_count, vector_count,
                  embedding_model, reranker_model, manifest_sha256, metrics_json, created_at
                ) VALUES (?, 'online_answer_staging_nonpromotable', 'not-indexed', 1, ?, 0,
                          'none', 'none', ?, ?, ?)
                """,
                (
                    build_id,
                    len(chunk_records),
                    content_sha256,
                    json.dumps(
                        {
                            "answer_scoped": True,
                            "permanent_index_eligible": False,
                            "searchable": False,
                            "vectors": 0,
                        },
                        sort_keys=True,
                    ),
                    now,
                ),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO reviews(
                  id, review_type, target_id, status, reason, created_at
                ) VALUES (?, 'online_source_version', ?, 'pending', ?, ?)
                """,
                (
                    f"review-online-{source_version_id}",
                    source_version_id,
                    (
                        "Answer-scoped official evidence requires human review; acceptance "
                        "does not make it searchable or eligible for index promotion"
                    ),
                    now,
                ),
            )
        return {
            "document_id": document_id,
            "source_version_id": source_version_id,
            "index_build_id": build_id,
            "chunks": chunk_records,
        }

    def store_claims(self, answer_version_id: str, items: Sequence[dict[str, Any]]) -> None:
        with self.transaction() as conn:
            for ordinal, item in enumerate(items):
                model_claim_id = str(item["id"])
                persistence_id = _scoped_claim_id(answer_version_id, model_claim_id)
                conn.execute(
                    """
                    INSERT INTO claims(
                      id, answer_version_id, model_claim_id, section_id, ordinal, claim_text,
                      encrypted_claim_text, material, proposition_hash,
                      verification_status, verification_reason
                    ) VALUES (?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?)
                    """,
                    (
                        persistence_id,
                        answer_version_id,
                        model_claim_id,
                        item["section_id"],
                        ordinal,
                        item["encrypted_text"],
                        int(bool(item.get("material", True))),
                        item.get("proposition_hash"),
                        item.get("verification_status", "pending"),
                        item.get("verification_reason"),
                    ),
                )
                for evidence_ordinal, evidence_id in enumerate(item.get("evidence_ids", [])):
                    conn.execute(
                        """
                        INSERT INTO claim_evidence(claim_id, evidence_id, ordinal)
                        VALUES (?, ?, ?)
                        """,
                        (persistence_id, evidence_id, evidence_ordinal),
                    )

    def store_quality_report(
        self,
        report: dict[str, Any],
        policy_version: str,
        *,
        encrypted_source_draft: bytes | None = None,
    ) -> None:
        from .quality.policy import POLICY_SHA256

        self.execute(
            """
            INSERT INTO quality_reports(
              id, answer_version_id, evidence_passed, academic_score, rubric_scores_json,
              findings_json, release_state, policy_version, policy_sha256,
              ai_evidence_review_json, ai_evidence_adjudication_json,
              assessment_standards_json, encrypted_source_draft, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report["id"],
                report["answer_version_id"],
                int(bool(report["evidence_passed"])),
                report["academic_score"],
                json.dumps(report.get("rubric_scores", {})),
                json.dumps(report.get("findings", [])),
                report["release_state"],
                policy_version,
                POLICY_SHA256,
                (
                    json.dumps(report["ai_evidence_review"], sort_keys=True)
                    if report.get("ai_evidence_review") is not None
                    else None
                ),
                (
                    json.dumps(report["ai_evidence_adjudication"], sort_keys=True)
                    if report.get("ai_evidence_adjudication") is not None
                    else None
                ),
                (
                    json.dumps(report["assessment_standards"], sort_keys=True)
                    if report.get("assessment_standards") is not None
                    else None
                ),
                encrypted_source_draft,
                utc_iso(),
            ),
        )

    def store_gap(
        self,
        gap: dict[str, Any],
        review_file: str,
        *,
        encrypted_missing_proposition: bytes,
        proposition_sha256: str,
    ) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", proposition_sha256):
            raise ValueError("knowledge-gap proposition SHA-256 is invalid")
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO knowledge_gaps(
                  id, job_id, missing_proposition, encrypted_missing_proposition,
                  proposition_sha256, jurisdiction, subject, searches_json,
                  rejection_reasons_json, review_file, status, created_at
                ) VALUES (?, ?, '[encrypted]', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    gap["id"],
                    gap["job_id"],
                    encrypted_missing_proposition,
                    proposition_sha256,
                    gap["jurisdiction"],
                    gap.get("subject"),
                    json.dumps(gap.get("searches_attempted", [])),
                    json.dumps(gap.get("rejection_reasons", [])),
                    review_file,
                    gap.get("status", "open"),
                    gap.get("created_at", utc_iso()),
                ),
            )
            conn.execute(
                """
                INSERT INTO reviews(id, review_type, target_id, status, reason, created_at)
                VALUES (?, 'knowledge_gap', ?, 'pending', ?, ?)
                """,
                (
                    f"review-{gap['id']}",
                    gap["id"],
                    "Official evidence was not sufficient for a material proposition",
                    utc_iso(),
                ),
            )

    def store_research_gap_binding(
        self,
        *,
        gap_id: str,
        fingerprint_sha256: str,
        candidate_build_id: str,
        source_manifest_sha256: str,
        case_id: str,
        issue_id: str,
        subject: str,
        jurisdiction: str,
        as_of_date: str,
        attempted_retrieval_sha256: str,
        materiality: str,
        detail_sha256: str,
        encrypted_detail: bytes,
    ) -> sqlite3.Row:
        """Insert or return one semantically identical encrypted research gap."""

        for digest in (
            fingerprint_sha256,
            source_manifest_sha256,
            attempted_retrieval_sha256,
            detail_sha256,
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("research-gap digest is invalid")
        if materiality not in {"material", "potentially_material", "non_material"}:
            raise ValueError("research-gap materiality is invalid")
        date.fromisoformat(as_of_date)
        if not encrypted_detail:
            raise ValueError("research-gap encrypted detail is required")
        immutable = {
            "id": gap_id,
            "candidate_build_id": candidate_build_id,
            "source_manifest_sha256": source_manifest_sha256,
            "case_id": case_id,
            "issue_id": issue_id,
            "subject": subject,
            "jurisdiction": jurisdiction,
            "as_of_date": as_of_date,
            "attempted_retrieval_sha256": attempted_retrieval_sha256,
            "materiality": materiality,
        }
        now = utc_iso()
        with self.transaction() as conn:
            existing = conn.execute(
                "SELECT * FROM research_gap_bindings WHERE fingerprint_sha256=?",
                (fingerprint_sha256,),
            ).fetchone()
            if existing is not None:
                if any(str(existing[key]) != value for key, value in immutable.items()):
                    raise RuntimeError("research-gap fingerprint identity conflict")
                return cast(sqlite3.Row, existing)
            conn.execute(
                """
                INSERT INTO research_gap_bindings(
                  id, fingerprint_sha256, candidate_build_id, source_manifest_sha256,
                  case_id, issue_id, subject, jurisdiction, as_of_date,
                  attempted_retrieval_sha256, materiality, detail_sha256,
                  encrypted_detail, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
                """,
                (
                    gap_id,
                    fingerprint_sha256,
                    candidate_build_id,
                    source_manifest_sha256,
                    case_id,
                    issue_id,
                    subject,
                    jurisdiction,
                    as_of_date,
                    attempted_retrieval_sha256,
                    materiality,
                    detail_sha256,
                    encrypted_detail,
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM research_gap_bindings WHERE id=?", (gap_id,)
            ).fetchone()
            if row is None:
                raise RuntimeError("research-gap binding insert failed")
            return cast(sqlite3.Row, row)

    def research_gap_binding(self, gap_id: str) -> sqlite3.Row | None:
        return self.fetchone("SELECT * FROM research_gap_bindings WHERE id=?", (gap_id,))

    def enqueue_research_task(
        self,
        *,
        task_id: str,
        idempotency_key: str,
        task_type: str,
        trigger_kind: str,
        priority_band: str,
        subject: str,
        jurisdiction: str,
        as_of_date: str,
        query_sha256: str,
        encrypted_query: bytes | None = None,
        source_id: str | None = None,
        origin_host: str | None = None,
        authority_identity_id: str | None = None,
        source_locator: str | None = None,
        knowledge_gap_id: str | None = None,
        answer_id: str | None = None,
        answer_job_id: str | None = None,
        refinement_id: str | None = None,
        pinned_index_build_id: str | None = None,
        source_manifest_sha256: str | None = None,
        candidate_cap: int = 20,
        max_attempts: int = 3,
        initial_status: str | None = None,
        now: datetime | None = None,
    ) -> sqlite3.Row:
        """Admit one research task without sharing the answer-job queue."""

        priorities = {"high": 90, "medium": 60, "low": 20}
        if task_type not in {"source_update_check", "gap_research", "broad_discovery"}:
            raise ValueError("research task type is invalid")
        if trigger_kind not in {"enquiry", "scheduled", "manual"}:
            raise ValueError("research trigger is invalid")
        if priority_band not in priorities:
            raise ValueError("research priority band is invalid")
        if not subject.strip() or not jurisdiction.strip():
            raise ValueError("research subject and jurisdiction are required")
        date.fromisoformat(as_of_date)
        if not re.fullmatch(r"[0-9a-f]{64}", query_sha256):
            raise ValueError("research query SHA-256 is invalid")
        if source_manifest_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", source_manifest_sha256
        ):
            raise ValueError("research source-manifest SHA-256 is invalid")
        if not 1 <= candidate_cap <= 20:
            raise ValueError("research candidate cap must be between 1 and 20")
        from .orchestration.retry_policy import MAX_ATTEMPTS

        if not 1 <= max_attempts <= MAX_ATTEMPTS:
            raise ValueError("research max attempts must be between 1 and 3")
        if not idempotency_key or len(idempotency_key) > 255:
            raise ValueError("research idempotency key is invalid")
        if initial_status not in {None, "staging_sync"}:
            raise ValueError("research initial status is invalid")
        stamp = (now or datetime.now(UTC)).astimezone(UTC).isoformat()
        with self.transaction() as conn:
            existing = conn.execute(
                "SELECT * FROM research_tasks WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                expected = {
                    "task_type": task_type,
                    "trigger_kind": trigger_kind,
                    "priority_band": priority_band,
                    "subject": subject.strip(),
                    "jurisdiction": jurisdiction.strip(),
                    "as_of_date": as_of_date,
                    "source_id": source_id,
                    "origin_host": origin_host.casefold() if origin_host else None,
                    "authority_identity_id": authority_identity_id,
                    "source_locator": source_locator,
                    "knowledge_gap_id": knowledge_gap_id,
                    "answer_id": answer_id,
                    "answer_job_id": answer_job_id,
                    "query_sha256": query_sha256,
                    "pinned_index_build_id": pinned_index_build_id,
                    "source_manifest_sha256": source_manifest_sha256,
                    "candidate_cap": candidate_cap,
                    "max_attempts": max_attempts,
                }
                if any(existing[key] != value for key, value in expected.items()):
                    raise RuntimeError("research task idempotency conflict")
                return cast(sqlite3.Row, existing)
            active_count = int(
                conn.execute(
                    """
                    SELECT COUNT(*) AS n FROM research_tasks
                    WHERE status IN ('queued','running','retry_wait')
                    """
                ).fetchone()["n"]
            )
            status = initial_status or ("queued" if active_count < 20 else "deferred_capacity")
            conn.execute(
                """
                INSERT INTO research_tasks(
                  id, idempotency_key, task_type, trigger_kind, priority_band,
                  base_priority, subject, jurisdiction, as_of_date, source_id,
                  origin_host, authority_identity_id, knowledge_gap_id, answer_id,
                  source_locator,
                  answer_job_id, refinement_id, pinned_index_build_id,
                  source_manifest_sha256, query_sha256, encrypted_query, status,
                  max_attempts, candidate_cap, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    idempotency_key,
                    task_type,
                    trigger_kind,
                    priority_band,
                    priorities[priority_band],
                    subject.strip(),
                    jurisdiction.strip(),
                    as_of_date,
                    source_id,
                    origin_host.casefold() if origin_host else None,
                    authority_identity_id,
                    knowledge_gap_id,
                    answer_id,
                    source_locator,
                    answer_job_id,
                    refinement_id,
                    pinned_index_build_id,
                    source_manifest_sha256,
                    query_sha256,
                    encrypted_query,
                    status,
                    max_attempts,
                    candidate_cap,
                    stamp,
                    stamp,
                ),
            )
            row = conn.execute("SELECT * FROM research_tasks WHERE id=?", (task_id,)).fetchone()
            if row is None:
                raise RuntimeError("research task admission failed")
            return cast(sqlite3.Row, row)

    @staticmethod
    def _activate_deferred_research_locked(conn: sqlite3.Connection, now: datetime) -> int:
        active_count = int(
            conn.execute(
                """
                SELECT COUNT(*) AS n FROM research_tasks
                WHERE status IN ('queued','running','retry_wait')
                """
            ).fetchone()["n"]
        )
        available = max(0, 20 - active_count)
        if available == 0:
            return 0
        rows = conn.execute(
            "SELECT * FROM research_tasks WHERE status='deferred_capacity'"
        ).fetchall()
        ordered = sorted(
            rows,
            key=lambda row: (
                -_research_effective_priority(row, now),
                str(row["created_at"]),
                str(row["id"]),
            ),
        )
        selected = ordered[:available]
        stamp = now.astimezone(UTC).isoformat()
        for row in selected:
            conn.execute(
                """
                UPDATE research_tasks SET status='queued', status_reason=NULL,
                  updated_at=? WHERE id=? AND status='deferred_capacity'
                """,
                (stamp, row["id"]),
            )
        return len(selected)

    def activate_deferred_research_tasks(self, *, now: datetime | None = None) -> int:
        resolved_now = (now or datetime.now(UTC)).astimezone(UTC)
        with self.transaction() as conn:
            return self._activate_deferred_research_locked(conn, resolved_now)

    def claim_research_task(
        self,
        worker_id: str,
        *,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> sqlite3.Row | None:
        """Claim by aged priority, enforcing two global and one-per-origin leases."""

        from .orchestration.retry_policy import MAX_ATTEMPTS

        if not worker_id or not 5 <= lease_seconds <= 900:
            raise ValueError("research worker lease parameters are invalid")
        resolved_now = (now or datetime.now(UTC)).astimezone(UTC)
        stamp = resolved_now.isoformat()
        expires = (resolved_now + timedelta(seconds=lease_seconds)).isoformat()
        with self.transaction() as conn:
            expired = conn.execute(
                """
                SELECT id, task_type, query_sha256, attempt_count, max_attempts,
                  lease_expires_at
                FROM research_tasks
                WHERE status='running' AND lease_expires_at IS NOT NULL
                  AND lease_expires_at<?
                """,
                (stamp,),
            ).fetchall()
            for row in expired:
                lease_condition = hashlib.sha256(
                    (
                        "legalbot-expired-research-lease-v1\0"
                        + str(row["lease_expires_at"] or "missing")
                    ).encode()
                ).hexdigest()
                decision = self._decide_retry_locked(
                    conn,
                    lane="research",
                    work_id=str(row["id"]),
                    attempt_number=int(row["attempt_count"]),
                    stage="research_dispatch",
                    failure_reason="lease_expired",
                    input_identity_sha256=str(row["query_sha256"]),
                    max_attempts=min(int(row["max_attempts"]), MAX_ATTEMPTS),
                    retryable=True,
                    input_or_condition_changed=True,
                    condition_identity_sha256=lease_condition,
                    retry_operation="resume_after_lease_expiry",
                )
                terminal = not decision.should_retry
                conn.execute(
                    """
                    UPDATE research_tasks SET status=?, status_reason=?,
                      lease_owner=NULL, lease_expires_at=NULL, heartbeat_at=NULL,
                      retry_after_at=?, updated_at=?, completed_at=?
                    WHERE id=? AND status='running'
                    """,
                    (
                        "failed" if terminal else "retry_wait",
                        decision.reason if terminal else "lease_expired",
                        None if terminal else stamp,
                        stamp,
                        stamp if terminal else None,
                        row["id"],
                    ),
                )
            # Backwards safety: old catalogues could contain a max_attempts
            # value above three or an exhausted row replayed into the queue.
            conn.execute(
                """
                UPDATE research_tasks
                SET status='failed', status_reason='retry_cap_exhausted',
                    retry_after_at=NULL, lease_owner=NULL, lease_expires_at=NULL,
                    heartbeat_at=NULL, updated_at=?, completed_at=COALESCE(completed_at, ?)
                WHERE status IN ('queued','retry_wait')
                  AND attempt_count>=MIN(max_attempts, ?)
                """,
                (stamp, stamp, MAX_ATTEMPTS),
            )
            self._activate_deferred_research_locked(conn, resolved_now)
            running = conn.execute(
                "SELECT origin_host FROM research_tasks WHERE status='running'"
            ).fetchall()
            if len(running) >= 2:
                return None
            occupied_origins = {str(row["origin_host"]) for row in running if row["origin_host"]}
            candidates = conn.execute(
                """
                SELECT * FROM research_tasks
                WHERE status='queued'
                   OR (status='retry_wait' AND (retry_after_at IS NULL OR retry_after_at<=?))
                """,
                (stamp,),
            ).fetchall()
            eligible = [
                row
                for row in candidates
                if not row["origin_host"] or str(row["origin_host"]) not in occupied_origins
            ]
            if not eligible:
                return None
            chosen = min(
                eligible,
                key=lambda row: (
                    -_research_effective_priority(row, resolved_now),
                    str(row["created_at"]),
                    str(row["id"]),
                ),
            )
            updated = conn.execute(
                """
                UPDATE research_tasks SET status='running', status_reason=NULL,
                  lease_owner=?, lease_expires_at=?, heartbeat_at=?, retry_after_at=NULL,
                  attempt_count=attempt_count+1, started_at=COALESCE(started_at, ?),
                  updated_at=?
                WHERE id=? AND status IN ('queued','retry_wait')
                """,
                (worker_id, expires, stamp, stamp, stamp, chosen["id"]),
            )
            if updated.rowcount != 1:
                return None
            return cast(
                sqlite3.Row,
                conn.execute("SELECT * FROM research_tasks WHERE id=?", (chosen["id"],)).fetchone(),
            )

    def heartbeat_research_task(
        self,
        task_id: str,
        worker_id: str,
        *,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> bool:
        resolved_now = (now or datetime.now(UTC)).astimezone(UTC)
        stamp = resolved_now.isoformat()
        cursor = self.execute(
            """
            UPDATE research_tasks SET heartbeat_at=?, lease_expires_at=?, updated_at=?
            WHERE id=? AND status='running' AND lease_owner=?
            """,
            (
                stamp,
                (resolved_now + timedelta(seconds=lease_seconds)).isoformat(),
                stamp,
                task_id,
                worker_id,
            ),
        )
        return cursor.rowcount == 1

    def finish_research_task(
        self,
        task_id: str,
        worker_id: str,
        *,
        status: str = "completed",
        reason: str | None = None,
        now: datetime | None = None,
    ) -> None:
        if status not in {"completed", "review_required", "cancelled"}:
            raise ValueError("research terminal status is invalid")
        resolved_now = (now or datetime.now(UTC)).astimezone(UTC)
        stamp = resolved_now.isoformat()
        with self.transaction() as conn:
            updated = conn.execute(
                """
                UPDATE research_tasks SET status=?, status_reason=?, lease_owner=NULL,
                  lease_expires_at=NULL, heartbeat_at=NULL, updated_at=?, completed_at=?
                WHERE id=? AND status='running' AND lease_owner=?
                """,
                (status, reason, stamp, stamp, task_id, worker_id),
            )
            if updated.rowcount != 1:
                raise RuntimeError("research task lease was lost")
            self._activate_deferred_research_locked(conn, resolved_now)

    def mark_staged_research_task_for_review(
        self,
        task_id: str,
        *,
        refinement_id: str | None = None,
        reason: str = "official_candidate_requires_review",
    ) -> None:
        """Finish synchronous staging that never acquired a worker lease."""

        now = datetime.now(UTC)
        stamp = now.isoformat()
        with self.transaction() as conn:
            updated = conn.execute(
                """
                UPDATE research_tasks SET status='review_required', status_reason=?,
                  refinement_id=COALESCE(?, refinement_id), updated_at=?, completed_at=?
                WHERE id=? AND status IN ('queued','deferred_capacity','staging_sync')
                """,
                (reason, refinement_id, stamp, stamp, task_id),
            )
            if updated.rowcount != 1:
                row = conn.execute(
                    "SELECT status FROM research_tasks WHERE id=?", (task_id,)
                ).fetchone()
                if row is None:
                    raise KeyError(task_id)
                if str(row["status"]) != "review_required":
                    raise RuntimeError("research task cannot enter review from its current state")
            if refinement_id is not None:
                conn.execute(
                    """
                    UPDATE refinements SET research_task_id=COALESCE(research_task_id, ?),
                      updated_at=? WHERE id=?
                    """,
                    (task_id, stamp, refinement_id),
                )
            self._activate_deferred_research_locked(conn, now)

    def link_research_task_refinement(self, task_id: str, refinement_id: str) -> None:
        with self.transaction() as conn:
            refinement = conn.execute(
                "SELECT id FROM refinements WHERE id=?", (refinement_id,)
            ).fetchone()
            if refinement is None:
                raise KeyError(refinement_id)
            updated = conn.execute(
                """
                UPDATE research_tasks SET refinement_id=COALESCE(refinement_id, ?),
                  updated_at=? WHERE id=?
                """,
                (refinement_id, utc_iso(), task_id),
            )
            if updated.rowcount != 1:
                raise KeyError(task_id)
            row = conn.execute(
                "SELECT refinement_id FROM research_tasks WHERE id=?", (task_id,)
            ).fetchone()
            if row is None or str(row["refinement_id"]) != refinement_id:
                raise RuntimeError("research task is linked to a different refinement")
            conn.execute(
                """
                UPDATE refinements SET research_task_id=COALESCE(research_task_id, ?),
                  updated_at=? WHERE id=?
                """,
                (task_id, utc_iso(), refinement_id),
            )

    def retry_or_fail_research_task(
        self,
        task_id: str,
        worker_id: str,
        *,
        reason: str,
        retryable: bool,
        retry_after_seconds: int = 0,
        now: datetime | None = None,
    ) -> str:
        if not 0 <= retry_after_seconds <= 86_400:
            raise ValueError("research retry delay is invalid")
        from .orchestration.retry_policy import MAX_ATTEMPTS

        resolved_now = (now or datetime.now(UTC)).astimezone(UTC)
        stamp = resolved_now.isoformat()
        with self.transaction() as conn:
            row = conn.execute(
                """
                SELECT * FROM research_tasks
                WHERE id=? AND status='running' AND lease_owner=?
                """,
                (task_id, worker_id),
            ).fetchone()
            if row is None:
                raise RuntimeError("research task lease was lost")
            proposed_retry_at = (
                (resolved_now + timedelta(seconds=retry_after_seconds)).isoformat()
                if retryable and retry_after_seconds > 0
                else None
            )
            condition_identity = (
                hashlib.sha256(
                    f"legalbot-research-retry-wait-v1\0{proposed_retry_at}".encode()
                ).hexdigest()
                if proposed_retry_at is not None
                else None
            )
            decision = self._decide_retry_locked(
                conn,
                lane="research",
                work_id=task_id,
                attempt_number=int(row["attempt_count"]),
                stage="research_dispatch",
                failure_reason=reason,
                input_identity_sha256=str(row["query_sha256"]),
                max_attempts=min(int(row["max_attempts"]), MAX_ATTEMPTS),
                retryable=retryable,
                input_or_condition_changed=proposed_retry_at is not None,
                condition_identity_sha256=condition_identity,
                retry_operation=("deferred_official_fetch" if retryable else "terminal_stop"),
            )
            can_retry = decision.should_retry
            status = "retry_wait" if can_retry else "failed"
            retry_at = proposed_retry_at if can_retry else None
            conn.execute(
                """
                UPDATE research_tasks SET status=?, status_reason=?, retry_after_at=?,
                  lease_owner=NULL, lease_expires_at=NULL, heartbeat_at=NULL,
                  updated_at=?, completed_at=? WHERE id=?
                """,
                (
                    status,
                    reason
                    if can_retry or decision.reason == "non_retryable_failure"
                    else decision.reason,
                    retry_at,
                    stamp,
                    None if can_retry else stamp,
                    task_id,
                ),
            )
            self._activate_deferred_research_locked(conn, resolved_now)
            return status

    def release_research_task_lease(self, task_id: str, worker_id: str) -> None:
        self.execute(
            """
            UPDATE research_tasks SET lease_owner=NULL, lease_expires_at=NULL,
              heartbeat_at=NULL WHERE id=? AND lease_owner=?
            """,
            (task_id, worker_id),
        )

    def research_task(self, task_id: str) -> sqlite3.Row | None:
        return self.fetchone("SELECT * FROM research_tasks WHERE id=?", (task_id,))

    def research_tasks(self, *, limit: int = 200) -> list[sqlite3.Row]:
        if not 1 <= limit <= 500:
            raise ValueError("research task limit is out of range")
        return self.fetchall(
            """
            SELECT id, task_type, trigger_kind, priority_band, base_priority,
              subject, jurisdiction, as_of_date, source_id, origin_host,
              authority_identity_id, knowledge_gap_id, answer_id, answer_job_id,
              refinement_id, pinned_index_build_id, source_manifest_sha256,
              query_sha256, status, status_reason, attempt_count, max_attempts,
              retry_after_at, candidate_cap, created_at, updated_at, started_at,
              completed_at
            FROM research_tasks ORDER BY created_at DESC, id DESC LIMIT ?
            """,
            (limit,),
        )

    def research_queue_telemetry(self, *, now: datetime | None = None) -> dict[str, Any]:
        """Return prose-free queue depth/age counters for owner observability."""

        resolved_now = (now or datetime.now(UTC)).astimezone(UTC)
        rows = self.fetchall(
            """
            SELECT status, priority_band, base_priority, created_at, attempt_count
            FROM research_tasks
            """
        )
        by_priority = {
            band: {"queued": 0, "running": 0, "retry_wait": 0, "deferred_capacity": 0}
            for band in ("high", "medium", "low")
        }
        oldest: float | None = None
        retries = 0
        terminal = 0
        for row in rows:
            status = str(row["status"])
            band = str(row["priority_band"])
            if band in by_priority and status in by_priority[band]:
                by_priority[band][status] += 1
            if status in {"queued", "running", "retry_wait"}:
                age = max(
                    0.0,
                    (resolved_now - _parse_utc_iso(str(row["created_at"]))).total_seconds(),
                )
                oldest = age if oldest is None else max(oldest, age)
            retries += max(0, int(row["attempt_count"]) - 1)
            if status in {"completed", "review_required", "failed", "cancelled"}:
                terminal += 1
        return {
            "active_depth": sum(
                values[status]
                for values in by_priority.values()
                for status in ("queued", "running", "retry_wait")
            ),
            "deferred_depth": sum(values["deferred_capacity"] for values in by_priority.values()),
            "oldest_task_age_seconds": oldest,
            "retries_total": retries,
            "terminal_total": terminal,
            "by_priority": by_priority,
        }

    def add_research_candidate(
        self,
        *,
        candidate_id: str,
        task_id: str,
        source_id: str,
        source_identity: str,
        canonical_url: str,
        metadata_sha256: str,
        content_sha256: str | None = None,
        content_object_key: str | None = None,
        status: str = "detected",
        rights_state: str = "unreviewed",
        safe_metadata: Mapping[str, Any] | None = None,
    ) -> sqlite3.Row:
        parsed = urlparse(canonical_url)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("research candidate URL is not a scrubbed HTTPS URL")
        for digest in (metadata_sha256, content_sha256):
            if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("research candidate digest is invalid")
        if status not in {
            "detected",
            "fetched",
            "quarantined",
            "system_verified",
            "expert_review",
        }:
            raise ValueError("research candidate initial status is invalid")
        now = utc_iso()
        safe_json = json.dumps(dict(safe_metadata or {}), sort_keys=True)
        with self.transaction() as conn:
            task = conn.execute(
                "SELECT candidate_cap FROM research_tasks WHERE id=?", (task_id,)
            ).fetchone()
            if task is None:
                raise KeyError(task_id)
            existing = conn.execute(
                """
                SELECT * FROM research_candidates
                WHERE task_id=? AND source_id=? AND source_identity=?
                """,
                (task_id, source_id, source_identity),
            ).fetchone()
            if existing is not None:
                immutable = {
                    "canonical_url": canonical_url,
                    "content_sha256": content_sha256,
                    "metadata_sha256": metadata_sha256,
                    "content_object_key": content_object_key,
                }
                if any(existing[key] != value for key, value in immutable.items()):
                    raise RuntimeError("research candidate idempotency conflict")
                return cast(sqlite3.Row, existing)
            count = int(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM research_candidates WHERE task_id=?",
                    (task_id,),
                ).fetchone()["n"]
            )
            if count >= int(task["candidate_cap"]) or count >= 20:
                raise RuntimeError("research task candidate cap reached")
            conn.execute(
                """
                INSERT INTO research_candidates(
                  id, task_id, source_id, source_identity, canonical_url,
                  content_sha256, metadata_sha256, content_object_key, status,
                  rights_state, safe_metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate_id,
                    task_id,
                    source_id,
                    source_identity,
                    canonical_url,
                    content_sha256,
                    metadata_sha256,
                    content_object_key,
                    status,
                    rights_state,
                    safe_json,
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM research_candidates WHERE id=?", (candidate_id,)
            ).fetchone()
            if row is None:
                raise RuntimeError("research candidate insert failed")
            return cast(sqlite3.Row, row)

    def add_source_update_observation(
        self,
        *,
        observation_id: str,
        task_id: str,
        source_id: str,
        authority_identity_id: str,
        comparison_state: str,
        candidate_id: str | None = None,
        pinned_index_build_id: str | None = None,
        pinned_source_manifest_sha256: str | None = None,
        observed_active_build_id: str | None = None,
        baseline_version_sha256: str | None = None,
        remote_content_sha256: str | None = None,
        stale_active: bool = False,
        scope_kind: str = "authority",
        legal_locator: str | None = None,
        proposition_sha256: str | None = None,
        materiality_status: str = "unassessed",
        review_status: str = "pending",
        review_id: str | None = None,
        reviewer_ref: str | None = None,
        review_manifest_sha256: str | None = None,
        safe_detail: Mapping[str, Any] | None = None,
    ) -> None:
        if comparison_state not in {
            "unchanged",
            "changed",
            "new",
            "withdrawn",
            "unknown",
        }:
            raise ValueError("source update comparison state is invalid")
        for digest in (
            pinned_source_manifest_sha256,
            baseline_version_sha256,
            remote_content_sha256,
            review_manifest_sha256,
        ):
            if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("source update digest is invalid")
        if materiality_status not in {
            "unassessed",
            "non_material",
            "material",
            "unknown",
        }:
            raise ValueError("source update materiality status is invalid")
        legal_locator = " ".join((legal_locator or "").split()) or None
        if scope_kind not in {"authority", "proposition"}:
            raise ValueError("source update scope is invalid")
        if legal_locator is not None and (
            len(legal_locator) > 500
            or any(ord(character) < 32 for character in legal_locator)
            or scrub_pii(legal_locator) != legal_locator
        ):
            raise ValueError("source update legal locator is invalid")
        if proposition_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", proposition_sha256):
            raise ValueError("source update proposition SHA-256 is invalid")
        if scope_kind == "authority" and (
            legal_locator is not None or proposition_sha256 is not None
        ):
            raise ValueError("authority-scoped update cannot carry proposition fields")
        if scope_kind == "proposition" and (legal_locator is None or proposition_sha256 is None):
            raise ValueError("proposition-scoped update requires locator and proposition SHA-256")
        if review_status not in {"pending", "approved", "rejected", "not_required"}:
            raise ValueError("source update review status is invalid")
        if reviewer_ref is not None and not re.fullmatch(r"reviewer:[0-9a-f]{64}", reviewer_ref):
            raise ValueError("source update reviewer reference is invalid")
        cursor = self.execute(
            """
            INSERT OR IGNORE INTO source_update_observations(
              id, task_id, candidate_id, source_id, authority_identity_id,
              pinned_index_build_id, pinned_source_manifest_sha256,
              observed_active_build_id, baseline_version_sha256,
              remote_content_sha256, comparison_state, stale_active,
              scope_kind, legal_locator, proposition_sha256,
              materiality_status, review_status, review_id, reviewer_ref,
              review_manifest_sha256, safe_detail_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observation_id,
                task_id,
                candidate_id,
                source_id,
                authority_identity_id,
                pinned_index_build_id,
                pinned_source_manifest_sha256,
                observed_active_build_id,
                baseline_version_sha256,
                remote_content_sha256,
                comparison_state,
                int(stale_active),
                scope_kind,
                legal_locator,
                proposition_sha256,
                materiality_status,
                review_status,
                review_id,
                reviewer_ref,
                review_manifest_sha256,
                json.dumps(dict(safe_detail or {}), sort_keys=True),
                utc_iso(),
            ),
        )
        if cursor.rowcount == 0:
            existing = self.fetchone(
                "SELECT * FROM source_update_observations WHERE id=?", (observation_id,)
            )
            if existing is None or any(
                (
                    str(existing["task_id"]) != task_id,
                    str(existing["source_id"]) != source_id,
                    str(existing["authority_identity_id"]) != authority_identity_id,
                    str(existing["comparison_state"]) != comparison_state,
                    str(existing["scope_kind"] or "authority") != scope_kind,
                    (str(existing["legal_locator"] or "") or None) != legal_locator,
                    (str(existing["proposition_sha256"] or "") or None) != proposition_sha256,
                    (str(existing["remote_content_sha256"] or "") or None) != remote_content_sha256,
                )
            ):
                raise RuntimeError("source update observation idempotency conflict")

    def research_candidates(self, *, limit: int = 200) -> list[sqlite3.Row]:
        """Return the explicit safe owner projection; fetched URLs/bytes stay hidden."""

        if not 1 <= limit <= 500:
            raise ValueError("research candidate limit is out of range")
        return self.fetchall(
            """
            SELECT id, task_id, source_id, source_identity, content_sha256,
              metadata_sha256, status, comparison_state, rights_state, review_id,
              system_verification_sha256, system_verified_at, intake_review_id,
              identity_review_state, currentness_review_state, reviewer_ref,
              review_manifest_sha256,
              json_extract(safe_metadata_json, '$.content_type') AS content_type,
              json_extract(safe_metadata_json, '$.disposition') AS disposition,
              json_extract(safe_metadata_json, '$.network_fetch') AS network_fetch_state,
              json_extract(safe_metadata_json, '$.additional_permission_required')
                AS additional_permission_required,
              COALESCE(json_extract(safe_metadata_json, '$.owner_decision_required'), 0)
                AS owner_decision_required,
              CASE WHEN content_object_key IS NULL THEN 0 ELSE 1 END
                AS has_quarantined_content,
              created_at, updated_at
            FROM research_candidates
            ORDER BY created_at DESC, id DESC LIMIT ?
            """,
            (limit,),
        )

    def mark_research_candidate_system_verified(
        self,
        candidate_id: str,
        *,
        verification_manifest_sha256: str,
    ) -> None:
        """Record deterministic verification before any owner/expert decision.

        This transition verifies only the crawler candidate envelope, registered
        source policy and frozen digests.  It does not establish legal identity,
        rights, currentness, source approval, index eligibility or promotion.
        """

        if not re.fullmatch(r"[0-9a-f]{64}", verification_manifest_sha256):
            raise ValueError("research candidate verification SHA-256 is invalid")
        with self.transaction() as conn:
            row = conn.execute(
                """
                SELECT rc.*, rt.status AS task_status
                FROM research_candidates rc
                JOIN research_tasks rt ON rt.id=rc.task_id
                WHERE rc.id=?
                """,
                (candidate_id,),
            ).fetchone()
            if row is None:
                raise KeyError(candidate_id)
            if str(row["status"]) == "system_verified":
                if str(row["system_verification_sha256"] or "") == verification_manifest_sha256:
                    return
                raise RuntimeError("research candidate verification is already sealed")
            if str(row["status"]) not in {"detected", "fetched", "quarantined"}:
                raise RuntimeError("research candidate is not eligible for system verification")
            if str(row["task_status"]) != "review_required":
                raise RuntimeError(
                    "research candidate task must finish staging before system verification"
                )
            now = utc_iso()
            verification_id = f"review-research-system-{candidate_id}"
            conn.execute(
                """
                INSERT INTO reviews(id, review_type, target_id, status, reason,
                  created_at, decided_at)
                VALUES (?, 'research_candidate_system_verification', ?, 'approved', ?, ?, ?)
                """,
                (
                    verification_id,
                    candidate_id,
                    f"Deterministic candidate envelope {verification_manifest_sha256}",
                    now,
                    now,
                ),
            )
            conn.execute(
                """
                UPDATE research_candidates SET status='system_verified',
                  system_verification_sha256=?, system_verified_at=?, updated_at=?
                WHERE id=?
                """,
                (verification_manifest_sha256, now, now, candidate_id),
            )

    def record_research_candidate_review(
        self,
        candidate_id: str,
        *,
        review_id: str,
        decision: str,
        rights_state: str,
        review_manifest_sha256: str,
        identity_review_state: str = "candidate_matched",
        currentness_review_state: str = "requires_source_review",
        reviewer_ref: str | None = None,
    ) -> None:
        """Apply an owner/expert decision after deterministic system verification.

        Acceptance creates a separate pending ordinary source-intake review. It
        never creates or approves a source version, candidate index or ACTIVE
        promotion.
        """

        if decision not in {"approved", "rejected"}:
            raise ValueError("research candidate review decision is invalid")
        if rights_state not in {"verified", "metadata_only", "licensed", "rejected"}:
            raise ValueError("research candidate rights decision is invalid")
        if (decision == "rejected") != (rights_state == "rejected"):
            raise ValueError("research candidate decision and rights state disagree")
        if identity_review_state not in {
            "candidate_matched",
            "ambiguous",
            "rejected",
        }:
            raise ValueError("research candidate identity decision is invalid")
        if currentness_review_state not in {
            "verified",
            "requires_source_review",
            "metadata_only",
            "not_applicable",
            "rejected",
        }:
            raise ValueError("research candidate currentness decision is invalid")
        if decision == "approved" and (
            identity_review_state == "rejected" or currentness_review_state == "rejected"
        ):
            raise ValueError("accepted candidate cannot carry a rejected legal decision")
        if decision == "rejected" and (
            identity_review_state != "rejected" or currentness_review_state != "rejected"
        ):
            raise ValueError("rejected candidate decisions must be consistently rejected")
        if reviewer_ref is None or not re.fullmatch(r"reviewer:[0-9a-f]{64}", reviewer_ref):
            raise ValueError("research candidate reviewer reference is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", review_manifest_sha256):
            raise ValueError("research candidate review manifest SHA-256 is invalid")
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM research_candidates WHERE id=?", (candidate_id,)
            ).fetchone()
            if row is None:
                raise KeyError(candidate_id)
            if row["review_id"] is not None:
                expected_status = "source_intake_pending" if decision == "approved" else "rejected"
                if (
                    str(row["review_id"]) == review_id
                    and str(row["status"]) == expected_status
                    and str(row["review_manifest_sha256"] or "") == review_manifest_sha256
                ):
                    return
                raise RuntimeError("research candidate is already reviewed")
            if str(row["status"]) != "system_verified":
                raise RuntimeError(
                    "research candidate requires sealed system verification before review"
                )
            now = utc_iso()
            conn.execute(
                """
                INSERT INTO reviews(id, review_type, target_id, status, reason,
                  created_at, decided_at)
                VALUES (?, 'official_research_candidate', ?, ?, ?, ?, ?)
                """,
                (
                    review_id,
                    candidate_id,
                    decision,
                    f"Explicit reviewed manifest {review_manifest_sha256}",
                    now,
                    now,
                ),
            )
            if decision == "approved":
                conn.execute(
                    """
                    INSERT INTO reviews(id, review_type, target_id, status, reason,
                      created_at)
                    VALUES (?, 'research_source_intake', ?, 'pending', ?, ?)
                    """,
                    (
                        f"review-research-intake-{candidate_id}",
                        candidate_id,
                        "Owner-accepted official candidate awaiting ordinary source-intake "
                        "identity, rights, jurisdiction, currentness and citation review",
                        now,
                    ),
                )
            conn.execute(
                """
                UPDATE research_candidates SET status=?, rights_state=?, review_id=?,
                  intake_review_id=?, identity_review_state=?,
                  currentness_review_state=?, reviewer_ref=?,
                  review_manifest_sha256=?, updated_at=? WHERE id=?
                """,
                (
                    "source_intake_pending" if decision == "approved" else "rejected",
                    rights_state,
                    review_id,
                    f"review-research-intake-{candidate_id}" if decision == "approved" else None,
                    identity_review_state,
                    currentness_review_state,
                    reviewer_ref,
                    review_manifest_sha256,
                    now,
                    candidate_id,
                ),
            )

    def source_update_observations(self, *, limit: int = 200) -> list[sqlite3.Row]:
        if not 1 <= limit <= 500:
            raise ValueError("source update observation limit is out of range")
        return self.fetchall(
            """
            SELECT id, task_id, candidate_id, source_id, authority_identity_id,
              pinned_index_build_id, pinned_source_manifest_sha256,
              observed_active_build_id, baseline_version_sha256,
              remote_content_sha256, comparison_state, stale_active,
              scope_kind, legal_locator, proposition_sha256,
              materiality_status, review_status, review_id, reviewer_ref,
              review_manifest_sha256,
              json_extract(safe_detail_json, '$.recompare_required') AS recompare_required,
              json_extract(safe_detail_json, '$.change_summary_code') AS change_summary_code,
              created_at
            FROM source_update_observations
            ORDER BY created_at DESC, id DESC LIMIT ?
            """,
            (limit,),
        )

    def record_source_update_review(
        self,
        observation_id: str,
        *,
        review_id: str,
        review_status: str,
        materiality_status: str,
        reviewer_ref: str,
        review_manifest_sha256: str,
        scope_kind: str | None = None,
        legal_locator: str | None = None,
        proposition_sha256: str | None = None,
    ) -> None:
        """Bind an expert decision; comparison alone never determines legal effect."""

        if review_status not in {"approved", "rejected", "not_required"}:
            raise ValueError("source update review decision is invalid")
        if materiality_status not in {"non_material", "material", "unknown"}:
            raise ValueError("source update materiality decision is invalid")
        if not re.fullmatch(r"reviewer:[0-9a-f]{64}", reviewer_ref):
            raise ValueError("source update reviewer reference is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", review_manifest_sha256):
            raise ValueError("source update review manifest SHA-256 is invalid")
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM source_update_observations WHERE id=?", (observation_id,)
            ).fetchone()
            if row is None:
                raise KeyError(observation_id)
            if row["review_id"] is not None:
                if (
                    str(row["review_id"]) == review_id
                    and str(row["review_manifest_sha256"]) == review_manifest_sha256
                ):
                    return
                raise RuntimeError("source update observation is already reviewed")
            effective_scope = scope_kind or str(row["scope_kind"] or "authority")
            effective_locator = (
                " ".join((legal_locator or str(row["legal_locator"] or "")).split()) or None
            )
            effective_proposition = (
                proposition_sha256 or str(row["proposition_sha256"] or "") or None
            )
            if effective_scope not in {"authority", "proposition"}:
                raise ValueError("source update review scope is invalid")
            if effective_locator is not None and (
                len(effective_locator) > 500
                or any(ord(character) < 32 for character in effective_locator)
                or scrub_pii(effective_locator) != effective_locator
            ):
                raise ValueError("source update review legal locator is invalid")
            if effective_proposition is not None and not re.fullmatch(
                r"[0-9a-f]{64}", effective_proposition
            ):
                raise ValueError("source update review proposition SHA-256 is invalid")
            if effective_scope == "authority" and (
                effective_locator is not None or effective_proposition is not None
            ):
                raise ValueError("authority-scoped review cannot carry proposition fields")
            if effective_scope == "proposition" and (
                effective_locator is None or effective_proposition is None
            ):
                raise ValueError(
                    "proposition-scoped review requires locator and proposition SHA-256"
                )
            if bool(row["stale_active"]):
                raise RuntimeError(
                    "source update observation is stale and must be recomputed before review"
                )
            if str(row["comparison_state"]) == "unchanged" and (
                materiality_status != "non_material" or review_status != "not_required"
            ):
                raise ValueError("unchanged source cannot be approved as a material update")
            if materiality_status == "material" and review_status != "approved":
                raise ValueError("material source update requires an approved expert review")
            now = utc_iso()
            conn.execute(
                """
                INSERT INTO reviews(id, review_type, target_id, status, reason, created_at,
                  decided_at)
                VALUES (?, 'source_update_materiality', ?, ?,
                  'Expert materiality/currentness review', ?, ?)
                """,
                (review_id, observation_id, review_status, now, now),
            )
            conn.execute(
                """
                UPDATE source_update_observations SET scope_kind=?, legal_locator=?,
                  proposition_sha256=?, materiality_status=?, review_status=?, review_id=?,
                  reviewer_ref=?, review_manifest_sha256=?
                WHERE id=?
                """,
                (
                    effective_scope,
                    effective_locator,
                    effective_proposition,
                    materiality_status,
                    review_status,
                    review_id,
                    reviewer_ref,
                    review_manifest_sha256,
                    observation_id,
                ),
            )

    def record_source_update_resolution(
        self,
        observation_id: str,
        *,
        resolution_id: str,
        resolved_by_build_id: str,
        source_manifest_sha256: str,
        resolution_kind: str,
        authority_identity_id: str,
        legal_locator: str | None,
        proposition_sha256: str | None,
        evidence_sha256: str,
        reviewer_ref: str,
    ) -> None:
        """Append a build-bound resolution after a reviewed candidate is promoted."""

        for digest in (source_manifest_sha256, evidence_sha256, proposition_sha256):
            if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("source update resolution digest is invalid")
        if resolution_kind not in {
            "updated_authority_included",
            "authority_removed",
            "proposition_reverified",
        }:
            raise ValueError("source update resolution kind is invalid")
        if not re.fullmatch(r"reviewer:[0-9a-f]{64}", reviewer_ref):
            raise ValueError("source update resolution reviewer reference is invalid")
        legal_locator = " ".join((legal_locator or "").split()) or None
        if legal_locator is not None and (
            len(legal_locator) > 500
            or any(ord(character) < 32 for character in legal_locator)
            or scrub_pii(legal_locator) != legal_locator
        ):
            raise ValueError("source update resolution locator is invalid")
        with self.transaction() as conn:
            observation = conn.execute(
                "SELECT * FROM source_update_observations WHERE id=?", (observation_id,)
            ).fetchone()
            if observation is None:
                raise KeyError(observation_id)
            if (
                str(observation["review_status"]) != "approved"
                or str(observation["materiality_status"]) != "material"
                or bool(observation["stale_active"])
            ):
                raise RuntimeError("only a current expert-verified material update can be resolved")
            if str(observation["authority_identity_id"]) != authority_identity_id:
                raise ValueError("source update resolution authority does not match")
            if str(observation["scope_kind"] or "authority") == "proposition":
                if legal_locator != str(
                    observation["legal_locator"] or ""
                ) or proposition_sha256 != str(observation["proposition_sha256"] or ""):
                    raise ValueError("source update resolution proposition scope does not match")
            elif legal_locator is not None or proposition_sha256 is not None:
                raise ValueError("authority-scoped resolution cannot add proposition scope")
            build = conn.execute(
                """
                SELECT status, source_manifest_hash FROM index_builds WHERE id=?
                """,
                (resolved_by_build_id,),
            ).fetchone()
            if (
                build is None
                or str(build["status"]) != "active"
                or str(build["source_manifest_hash"] or "") != source_manifest_sha256
            ):
                raise RuntimeError("source update resolution requires the matching ACTIVE build")
            if resolved_by_build_id in {
                str(observation["pinned_index_build_id"] or ""),
                str(observation["observed_active_build_id"] or ""),
            }:
                raise RuntimeError("source update resolution requires a newly promoted build")
            existing = conn.execute(
                """
                SELECT * FROM source_update_resolution_events
                WHERE observation_id=? AND resolved_by_build_id=?
                """,
                (observation_id, resolved_by_build_id),
            ).fetchone()
            if existing is not None:
                immutable = {
                    "id": resolution_id,
                    "source_manifest_sha256": source_manifest_sha256,
                    "resolution_kind": resolution_kind,
                    "authority_identity_id": authority_identity_id,
                    "legal_locator": legal_locator,
                    "proposition_sha256": proposition_sha256,
                    "evidence_sha256": evidence_sha256,
                    "reviewer_ref": reviewer_ref,
                }
                if all(existing[key] == value for key, value in immutable.items()):
                    return
                raise RuntimeError("source update resolution is already recorded differently")
            conn.execute(
                """
                INSERT INTO source_update_resolution_events(
                  id, observation_id, resolved_by_build_id, source_manifest_sha256,
                  resolution_kind, authority_identity_id, legal_locator,
                  proposition_sha256, evidence_sha256, reviewer_ref, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    resolution_id,
                    observation_id,
                    resolved_by_build_id,
                    source_manifest_sha256,
                    resolution_kind,
                    authority_identity_id,
                    legal_locator,
                    proposition_sha256,
                    evidence_sha256,
                    reviewer_ref,
                    utc_iso(),
                ),
            )

    def source_update_resolutions(self, *, limit: int = 200) -> list[sqlite3.Row]:
        if not 1 <= limit <= 500:
            raise ValueError("source update resolution limit is out of range")
        return self.fetchall(
            """
            SELECT id, observation_id, resolved_by_build_id, source_manifest_sha256,
              resolution_kind, authority_identity_id, legal_locator,
              proposition_sha256, evidence_sha256, reviewer_ref, created_at
            FROM source_update_resolution_events
            ORDER BY created_at DESC, id DESC LIMIT ?
            """,
            (limit,),
        )

    def upsert_research_schedule(
        self,
        *,
        schedule_id: str,
        task_type: str,
        timezone: str,
        local_hour: int,
        local_minute: int,
        weekday: int | None,
        enabled: bool,
        next_due_at: str,
    ) -> None:
        if task_type not in {"source_update_check", "broad_discovery"}:
            raise ValueError("scheduled research task type is invalid")
        if not 0 <= local_hour <= 23 or not 0 <= local_minute <= 59:
            raise ValueError("research schedule time is invalid")
        if weekday is not None and not 0 <= weekday <= 6:
            raise ValueError("research schedule weekday is invalid")
        _parse_utc_iso(next_due_at)
        now = utc_iso()
        self.execute(
            """
            INSERT INTO research_schedules(
              id, task_type, timezone, local_hour, local_minute, weekday,
              enabled, next_due_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              task_type=excluded.task_type, timezone=excluded.timezone,
              local_hour=excluded.local_hour, local_minute=excluded.local_minute,
              weekday=excluded.weekday,
              next_due_at=CASE
                WHEN research_schedules.last_scheduled_for IS NULL
                THEN excluded.next_due_at ELSE research_schedules.next_due_at END,
              updated_at=excluded.updated_at
            """,
            (
                schedule_id,
                task_type,
                timezone,
                local_hour,
                local_minute,
                weekday,
                int(enabled),
                next_due_at,
                now,
                now,
            ),
        )

    def set_research_schedule_enabled(self, schedule_id: str, *, enabled: bool) -> None:
        cursor = self.execute(
            "UPDATE research_schedules SET enabled=?, updated_at=? WHERE id=?",
            (int(enabled), utc_iso(), schedule_id),
        )
        if cursor.rowcount != 1:
            raise KeyError(schedule_id)

    def due_research_schedules(self, *, now: datetime | None = None) -> list[sqlite3.Row]:
        stamp = (now or datetime.now(UTC)).astimezone(UTC).isoformat()
        return self.fetchall(
            """
            SELECT * FROM research_schedules
            WHERE enabled=1 AND next_due_at<=?
            ORDER BY next_due_at, id
            """,
            (stamp,),
        )

    def advance_research_schedule(
        self,
        schedule_id: str,
        *,
        scheduled_for: str,
        next_due_at: str,
    ) -> None:
        _parse_utc_iso(scheduled_for)
        _parse_utc_iso(next_due_at)
        self.execute(
            """
            UPDATE research_schedules SET last_scheduled_for=?, next_due_at=?,
              updated_at=? WHERE id=?
            """,
            (scheduled_for, next_due_at, utc_iso(), schedule_id),
        )

    def create_refinement(
        self,
        *,
        refinement_id: str,
        fingerprint: str,
        category: str,
        scope: str,
        priority: int,
        origin: str,
        answer_id: str | None = None,
        job_id: str | None = None,
        knowledge_gap_id: str | None = None,
        research_task_id: str | None = None,
        safe_target: Mapping[str, Any] | None = None,
        encrypted_note: bytes | None = None,
        note_sha256: str | None = None,
    ) -> sqlite3.Row:
        if category not in {"debug", "missing", "answer_feedback"}:
            raise ValueError("refinement category is invalid")
        if scope not in {"answer", "section", "claim", "evidence", "source", "system"}:
            raise ValueError("refinement scope is invalid")
        if not 0 <= priority <= 100:
            raise ValueError("refinement priority is invalid")
        if note_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", note_sha256):
            raise ValueError("refinement note SHA-256 is invalid")
        now = utc_iso()
        with self.transaction() as conn:
            existing = conn.execute(
                "SELECT * FROM refinements WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if existing is not None:
                expected_links = {
                    "category": category,
                    "scope": scope,
                    "origin": origin,
                    "answer_id": answer_id,
                    "job_id": job_id,
                    "knowledge_gap_id": knowledge_gap_id,
                    "research_task_id": research_task_id,
                }
                if any(existing[key] != value for key, value in expected_links.items()):
                    raise RuntimeError("refinement fingerprint conflict")
                conn.execute(
                    """
                    UPDATE refinements SET occurrence_count=occurrence_count+1,
                      priority=MAX(priority, ?), updated_at=? WHERE id=?
                    """,
                    (priority, now, existing["id"]),
                )
                conn.execute(
                    """
                    INSERT INTO refinement_events(
                      refinement_id, event_type, from_status, to_status,
                      safe_payload_json, created_at
                    ) VALUES (?, 'observed_again', ?, ?, '{}', ?)
                    """,
                    (existing["id"], existing["status"], existing["status"], now),
                )
                return cast(
                    sqlite3.Row,
                    conn.execute(
                        "SELECT * FROM refinements WHERE id=?", (existing["id"],)
                    ).fetchone(),
                )
            conn.execute(
                """
                INSERT INTO refinements(
                  id, fingerprint, category, scope, priority, status, origin,
                  answer_id, job_id, knowledge_gap_id, research_task_id,
                  safe_target_json, encrypted_note, note_sha256, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    refinement_id,
                    fingerprint,
                    category,
                    scope,
                    priority,
                    origin,
                    answer_id,
                    job_id,
                    knowledge_gap_id,
                    research_task_id,
                    json.dumps(dict(safe_target or {}), sort_keys=True),
                    encrypted_note,
                    note_sha256,
                    now,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO refinement_events(
                  refinement_id, event_type, from_status, to_status,
                  safe_payload_json, created_at
                ) VALUES (?, 'created', NULL, 'open', '{}', ?)
                """,
                (refinement_id, now),
            )
            row = conn.execute("SELECT * FROM refinements WHERE id=?", (refinement_id,)).fetchone()
            if row is None:
                raise RuntimeError("refinement insert failed")
            return cast(sqlite3.Row, row)

    def transition_refinement(
        self,
        refinement_id: str,
        *,
        to_status: str,
        event_type: str,
        safe_payload: Mapping[str, Any] | None = None,
        encrypted_note: bytes | None = None,
        root_cause: str | None = None,
        repair_version: str | None = None,
        regression_case_id: str | None = None,
        resolution_evidence: Mapping[str, Any] | None = None,
    ) -> sqlite3.Row:
        transitions = {
            "open": {
                "triaged",
                "source_needed",
                "metadata_currentness_needed",
                "retrieval_fix_needed",
                "accepted_out_of_scope",
                "resolved",
            },
            "triaged": {
                "source_needed",
                "metadata_currentness_needed",
                "retrieval_fix_needed",
                "accepted_out_of_scope",
                "resolved",
            },
            "source_needed": {"triaged", "resolved"},
            "metadata_currentness_needed": {"triaged", "resolved"},
            "retrieval_fix_needed": {"triaged", "resolved"},
            "resolved": {"regression_verified"},
            "accepted_out_of_scope": set(),
            "regression_verified": set(),
        }
        now = utc_iso()
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM refinements WHERE id=?", (refinement_id,)).fetchone()
            if row is None:
                raise KeyError(refinement_id)
            current = str(row["status"])
            if to_status != current and to_status not in transitions.get(current, set()):
                raise ValueError(f"invalid refinement transition: {current} -> {to_status}")
            event_payload = dict(safe_payload or {})
            changes: dict[str, dict[str, Any]] = {}
            for field, supplied in (
                ("root_cause", root_cause),
                ("repair_version", repair_version),
                ("regression_case_id", regression_case_id),
            ):
                previous = row[field]
                if supplied is not None and supplied != previous:
                    changes[field] = {"from": previous, "to": supplied}
            resolution_value = dict(resolution_evidence or {})
            if resolution_value:
                try:
                    previous_resolution = json.loads(str(row["resolution_evidence_json"] or "{}"))
                except json.JSONDecodeError as exc:
                    raise RuntimeError("stored refinement resolution evidence is invalid") from exc
                if previous_resolution != resolution_value:
                    changes["resolution_evidence"] = {
                        "from": previous_resolution,
                        "to": resolution_value,
                    }
            effective_root_cause = root_cause or row["root_cause"]
            effective_repair_version = repair_version or row["repair_version"]
            effective_regression_case = regression_case_id or row["regression_case_id"]
            if to_status == "accepted_out_of_scope" and encrypted_note is None:
                raise ValueError("accepted-out-of-scope requires an encrypted owner reason")
            if to_status == "resolved" and not all(
                (
                    effective_root_cause,
                    effective_repair_version,
                    effective_regression_case,
                    resolution_value,
                )
            ):
                raise ValueError(
                    "resolved refinement requires root cause, repair version, "
                    "regression case and resolution evidence"
                )
            if to_status == "regression_verified" and not all(
                (effective_regression_case, resolution_value)
            ):
                raise ValueError(
                    "regression verification requires a regression case and passing rerun evidence"
                )
            if changes:
                event_payload["changes"] = changes
            if to_status == current and not event_payload and encrypted_note is None:
                raise ValueError("same-status transition must append a changed field or note")
            closed_at = (
                now
                if to_status
                in {
                    "accepted_out_of_scope",
                    "resolved",
                    "regression_verified",
                }
                else None
            )
            conn.execute(
                """
                UPDATE refinements SET status=?, root_cause=COALESCE(?, root_cause),
                  repair_version=COALESCE(?, repair_version),
                  regression_case_id=COALESCE(?, regression_case_id),
                  resolution_evidence_json=CASE WHEN ?='{}'
                    THEN resolution_evidence_json ELSE ? END,
                  updated_at=?, closed_at=? WHERE id=?
                """,
                (
                    to_status,
                    root_cause,
                    repair_version,
                    regression_case_id,
                    json.dumps(resolution_value, sort_keys=True),
                    json.dumps(resolution_value, sort_keys=True),
                    now,
                    closed_at,
                    refinement_id,
                ),
            )
            conn.execute(
                """
                INSERT INTO refinement_events(
                  refinement_id, event_type, from_status, to_status,
                  safe_payload_json, encrypted_note, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    refinement_id,
                    event_type,
                    current,
                    to_status,
                    json.dumps(event_payload, sort_keys=True),
                    encrypted_note,
                    now,
                ),
            )
            return cast(
                sqlite3.Row,
                conn.execute("SELECT * FROM refinements WHERE id=?", (refinement_id,)).fetchone(),
            )

    def refinements(self, *, limit: int = 200) -> list[sqlite3.Row]:
        if not 1 <= limit <= 500:
            raise ValueError("refinement limit is out of range")
        return self.fetchall(
            """
            SELECT id, fingerprint, category, scope, priority, status, origin,
              answer_id, job_id, knowledge_gap_id, research_task_id,
              safe_target_json, note_sha256, occurrence_count, root_cause,
              repair_version, regression_case_id, resolution_evidence_json,
              created_at, updated_at, closed_at
            FROM refinements ORDER BY priority DESC, created_at DESC, id DESC LIMIT ?
            """,
            (limit,),
        )

    def owner_refinement_note(self, refinement_id: str, *, access_ref: str) -> sqlite3.Row:
        """Read one encrypted owner note and append a prose-free access event."""

        safe_id = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
        if safe_id.fullmatch(refinement_id) is None or safe_id.fullmatch(access_ref) is None:
            raise ValueError("owner sensitive-read identity is invalid")
        with self.transaction() as conn:
            row = conn.execute(
                """
                SELECT id,status,encrypted_note,note_sha256
                FROM refinements WHERE id=?
                """,
                (refinement_id,),
            ).fetchone()
            if row is None:
                raise KeyError(refinement_id)
            conn.execute(
                """
                INSERT INTO refinement_events(
                  refinement_id,event_type,from_status,to_status,
                  safe_payload_json,created_at
                ) VALUES (?, 'owner_sensitive_read', ?, ?, ?, ?)
                """,
                (
                    refinement_id,
                    row["status"],
                    row["status"],
                    json.dumps({"access_ref": access_ref}, sort_keys=True),
                    utc_iso(),
                ),
            )
            return cast(sqlite3.Row, row)

    def record_legacy_research_gap_import(
        self,
        *,
        manifest_sha256: str,
        schema_name: str,
        imported_count: int,
        skipped_count: int,
    ) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
            raise ValueError("legacy research-gap manifest SHA-256 is invalid")
        self.execute(
            """
            INSERT OR IGNORE INTO legacy_research_gap_imports(
              manifest_sha256, schema_name, imported_count, skipped_count, imported_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (manifest_sha256, schema_name, imported_count, skipped_count, utc_iso()),
        )

    def legacy_research_gap_imported(self, manifest_sha256: str) -> bool:
        return (
            self.fetchone(
                "SELECT 1 FROM legacy_research_gap_imports WHERE manifest_sha256=?",
                (manifest_sha256,),
            )
            is not None
        )

    def answer_claims_and_evidence(
        self, answer_id: str
    ) -> tuple[list[sqlite3.Row], list[sqlite3.Row], list[sqlite3.Row]]:
        claims = self.fetchall(
            "SELECT * FROM claims WHERE answer_version_id=? ORDER BY ordinal",
            (answer_id,),
        )
        links = self.fetchall(
            """
            SELECT ce.* FROM claim_evidence ce
            JOIN claims c ON c.id=ce.claim_id
            WHERE c.answer_version_id=? ORDER BY c.ordinal, ce.ordinal
            """,
            (answer_id,),
        )
        evidence = self.fetchall(
            """
            SELECT DISTINCT
              es.id, es.source_version_id, es.chunk_id, es.locator, es.lane,
              es.jurisdiction, es.subject, es.citation_data_json,
              es.canonical_citation, es.currentness_status, es.content_sha256,
              es.index_build_id, es.retrieval_relevance_score, es.retrieval_route,
              es.retrieval_threshold, es.retrieval_threshold_policy_sha256,
              es.retrieval_threshold_qualified, es.retrieval_qualification_reason,
              es.legal_role,
              es.unapplied_effect_count, es.provision_extent_status,
              es.identity_verified, es.currentness_verified,
              es.case_currentness_reviews_json,
              es.case_currentness_manifest_seals_json
            FROM evidence_spans es
            JOIN claim_evidence ce ON ce.evidence_id=es.id
            JOIN claims c ON c.id=ce.claim_id
            WHERE c.answer_version_id=?
            """,
            (answer_id,),
        )
        return claims, links, evidence

    def released_answers(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.fetchall(
            """
            SELECT av.*, j.question_summary
            FROM answer_versions av JOIN jobs j ON j.id=av.job_id
            WHERE av.release_state='verified_full'
            ORDER BY av.created_at DESC LIMIT ?
            """,
            (limit,),
        )

    def active_index_id(self) -> str | None:
        row = self.fetchone(
            "SELECT id FROM index_builds WHERE status='active' ORDER BY promoted_at DESC LIMIT 1"
        )
        return str(row["id"]) if row else None

    def admin_overview(self) -> dict[str, Any]:
        def grouped(table: str, column: str) -> dict[str, int]:
            rows = self.fetchall(
                f"SELECT {column} AS key, COUNT(*) AS count FROM {table} GROUP BY {column}"
            )
            return {str(row["key"]): int(row["count"]) for row in rows}

        def count(sql: str) -> int:
            row = self.fetchone(sql)
            return int(row["n"]) if row is not None else 0

        return {
            "sources_total": count("SELECT COUNT(*) AS n FROM documents"),
            "source_statuses": grouped("documents", "status"),
            "source_identity_groups": count(
                "SELECT COUNT(DISTINCT representation_group_id) AS n "
                "FROM documents WHERE representation_group_id IS NOT NULL"
            ),
            "retrieval_canonical_sources": count(
                "SELECT COUNT(*) AS n FROM documents "
                "WHERE retrieval_canonical=1 AND duplicate_of IS NULL"
            ),
            "representation_duplicates": count(
                "SELECT COUNT(*) AS n FROM documents "
                "WHERE retrieval_canonical=0 AND duplicate_of IS NULL "
                "AND representation_group_id IS NOT NULL"
            ),
            "exact_duplicates": count(
                "SELECT COUNT(*) - COUNT(DISTINCT content_sha256) AS n FROM documents"
            ),
            "logical_exact_duplicates": count(
                "SELECT COUNT(*) AS n FROM documents WHERE duplicate_of IS NOT NULL"
            ),
            "annotation_sources": count(
                "SELECT COUNT(*) AS n FROM documents WHERE has_annotations=1"
            ),
            "jobs": grouped("jobs", "status"),
            "releases": grouped("quality_reports", "release_state"),
            "open_gaps": count("SELECT COUNT(*) AS n FROM knowledge_gaps WHERE status='open'"),
            "pending_reviews": self.admin_review_count(status="pending"),
            "active_index": self.active_index_id(),
            "latest_source_scan": (
                _row_dict(row)
                if (
                    row := self.fetchone(
                        "SELECT * FROM source_scans ORDER BY created_at DESC LIMIT 1"
                    )
                )
                else None
            ),
        }

    @staticmethod
    def _source_root_descriptors(roots: Sequence[Path]) -> list[dict[str, str]]:
        return [
            {
                "id": f"source-root-{index}",
                "fingerprint": digest,
            }
            for index, root in enumerate(roots, start=1)
            if (
                digest := hashlib.sha256(
                    ("legalbot-source-root-v1\0" + str(root.expanduser().absolute())).encode(
                        "utf-8"
                    )
                ).hexdigest()
            )
        ]

    @staticmethod
    def _active_source_scan(conn: sqlite3.Connection) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            conn.execute(
                """
                SELECT id, status FROM source_scans
                WHERE status IN ('queued', 'running')
                ORDER BY created_at, id LIMIT 1
                """
            ).fetchone(),
        )

    def create_source_scan(self, scan_id: str, roots: Sequence[Path]) -> list[dict[str, str]]:
        """Create one queued scan, idempotently admitting its own background worker."""

        descriptors = self._source_root_descriptors(roots)
        encoded_roots = json.dumps(descriptors, sort_keys=True)
        with self.transaction() as conn:
            existing = conn.execute(
                "SELECT status, required_roots_json FROM source_scans WHERE id=?",
                (scan_id,),
            ).fetchone()
            if existing is not None:
                if existing["required_roots_json"] != encoded_roots:
                    raise SourceScanStateError(
                        "The existing source scan was created for different configured roots"
                    )
                if existing["status"] in {"queued", "running"}:
                    return descriptors
                raise SourceScanStateError(
                    f"Source scan {scan_id} is already {existing['status']} and cannot be recreated"
                )
            if active := self._active_source_scan(conn):
                raise SourceScanConflictError(str(active["id"]), str(active["status"]))
            conn.execute(
                """
                INSERT INTO source_scans(
                  id, status, required_roots_json, created_at
                ) VALUES (?, 'queued', ?, ?)
                """,
                (scan_id, encoded_roots, utc_iso()),
            )
        return descriptors

    def resume_source_scan(
        self,
        prior_scan_id: str,
        new_scan_id: str,
        roots: Sequence[Path],
    ) -> list[dict[str, str]]:
        """Queue a fresh, linked attempt while retaining an immutable failed attempt."""

        descriptors = self._source_root_descriptors(roots)
        encoded_roots = json.dumps(descriptors, sort_keys=True)
        with self.transaction() as conn:
            prior = conn.execute(
                "SELECT status, required_roots_json FROM source_scans WHERE id=?",
                (prior_scan_id,),
            ).fetchone()
            if prior is None:
                raise SourceScanStateError("Source scan not found")
            if prior["status"] != "failed":
                raise SourceScanStateError(
                    f"Only a failed source scan can be resumed; this scan is {prior['status']}"
                )
            if prior["required_roots_json"] != encoded_roots:
                raise SourceScanStateError(
                    "Configured source roots changed; start a new scan instead of resuming"
                )
            if active := self._active_source_scan(conn):
                raise SourceScanConflictError(str(active["id"]), str(active["status"]))
            conn.execute(
                """
                INSERT INTO source_scans(
                  id, resumed_from_scan_id, status, required_roots_json, created_at
                ) VALUES (?, ?, 'queued', ?, ?)
                """,
                (new_scan_id, prior_scan_id, encoded_roots, utc_iso()),
            )
        return descriptors

    def start_source_scan(
        self,
        scan_id: str,
        *,
        roots_seen: Sequence[dict[str, str]],
        expected_file_count: int,
    ) -> None:
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                UPDATE source_scans
                SET status='running', roots_seen_json=?, expected_file_count=?, started_at=?,
                    error_code=NULL, error_message=NULL
                WHERE id=? AND status='queued'
                """,
                (
                    json.dumps(list(roots_seen), sort_keys=True),
                    expected_file_count,
                    utc_iso(),
                    scan_id,
                ),
            )
            if cursor.rowcount == 1:
                return
            row = conn.execute("SELECT status FROM source_scans WHERE id=?", (scan_id,)).fetchone()
            if row is not None and row["status"] == "running":
                raise SourceScanStateError(
                    "Source scan is already running; a duplicate worker was refused"
                )
            raise SourceScanStateError("Source scan is missing or is no longer runnable")

    def record_source_scan_file(
        self,
        scan_id: str,
        *,
        path_fingerprint: str,
        document_id: str | None,
        status: str,
        content_sha256: str | None,
        reason: str | None = None,
    ) -> None:
        try:
            reason = validate_exclusion_reason(status, reason)
        except ValueError as exc:
            raise SourceScanStateError(
                f"Source scan status {status} requires a recognised exclusion reason"
            ) from exc
        with self.transaction() as conn:
            scan = conn.execute("SELECT status FROM source_scans WHERE id=?", (scan_id,)).fetchone()
            if scan is None or scan["status"] != "running":
                raise SourceScanStateError(
                    "Source scan file accounting is accepted only while the scan is running"
                )
            conn.execute(
                """
                INSERT INTO source_scan_files(
                  scan_id, path_fingerprint, document_id, status, content_sha256, reason
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, path_fingerprint) DO UPDATE SET
                  document_id=excluded.document_id, status=excluded.status,
                  content_sha256=excluded.content_sha256, reason=excluded.reason
                """,
                (
                    scan_id,
                    path_fingerprint,
                    document_id,
                    status,
                    content_sha256,
                    reason,
                ),
            )

    def complete_source_scan(self, scan_id: str) -> dict[str, Any]:
        with self.transaction() as conn:
            scan = conn.execute("SELECT * FROM source_scans WHERE id=?", (scan_id,)).fetchone()
            if scan is None or scan["status"] != "running":
                raise ValueError("Source scan is missing or is not running")
            rows = conn.execute(
                """
                SELECT path_fingerprint, document_id, status, content_sha256, reason
                FROM source_scan_files WHERE scan_id=? ORDER BY path_fingerprint
                """,
                (scan_id,),
            ).fetchall()
            expected = int(scan["expected_file_count"])
            if len(rows) != expected:
                raise RuntimeError(
                    f"Source accounting incomplete: expected {expected}, accounted {len(rows)}"
                )
            statuses: dict[str, int] = {}
            manifest_rows: list[dict[str, Any]] = []
            for row in rows:
                key = str(row["status"])
                try:
                    validate_exclusion_reason(key, row["reason"])
                except ValueError as exc:
                    raise RuntimeError(
                        f"Source accounting diagnostics incomplete for status {key}"
                    ) from exc
                statuses[key] = statuses.get(key, 0) + 1
                manifest_rows.append(
                    {
                        "path_fingerprint": row["path_fingerprint"],
                        "document_id": row["document_id"],
                        "status": key,
                        "content_sha256": row["content_sha256"],
                        "reason": row["reason"],
                    }
                )
            encoded = json.dumps(
                manifest_rows, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            manifest_sha256 = hashlib.sha256(encoded).hexdigest()
            now = utc_iso()
            conn.execute(
                """
                UPDATE source_scans
                SET status='complete', files_accounted=?, statuses_json=?, manifest_sha256=?,
                    completed_at=?
                WHERE id=?
                """,
                (
                    len(rows),
                    json.dumps(statuses, sort_keys=True),
                    manifest_sha256,
                    now,
                    scan_id,
                ),
            )
        return {
            "scan_id": scan_id,
            "status": "complete",
            "files_accounted": len(rows),
            "statuses": statuses,
            "manifest_sha256": manifest_sha256,
        }

    def fail_source_scan(self, scan_id: str, *, error_code: str, error_message: str) -> bool:
        with self.transaction() as conn:
            accounted = conn.execute(
                "SELECT COUNT(*) AS n FROM source_scan_files WHERE scan_id=?",
                (scan_id,),
            ).fetchone()["n"]
            cursor = conn.execute(
                """
                UPDATE source_scans
                SET status='failed', files_accounted=?, error_code=?, error_message=?,
                    completed_at=? WHERE id=? AND status IN ('queued', 'running')
                """,
                (accounted, error_code, error_message, utc_iso(), scan_id),
            )
            return cursor.rowcount == 1

    def admin_source_scans(self, limit: int = 100) -> list[sqlite3.Row]:
        return self.fetchall(
            "SELECT * FROM source_scans ORDER BY created_at DESC LIMIT ?", (limit,)
        )

    def fail_interrupted_source_scans(self) -> list[str]:
        """Close the sole active attempt after process restart without erasing its manifest."""

        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT id FROM source_scans WHERE status IN ('queued', 'running') "
                "ORDER BY created_at, id"
            ).fetchall()
            if not rows:
                return []
            now = utc_iso()
            scan_ids = [str(row["id"]) for row in rows]
            for scan_id in scan_ids:
                conn.execute(
                    """
                    UPDATE source_scans
                    SET status='failed', files_accounted=(
                          SELECT COUNT(*) FROM source_scan_files WHERE scan_id=?
                        ),
                        error_code='interrupted_source_scan',
                        error_message='Application restarted before the source scan completed',
                        completed_at=?
                    WHERE id=? AND status IN ('queued', 'running')
                    """,
                    (scan_id, now, scan_id),
                )
            return scan_ids

    def source_scan_files(self, scan_id: str) -> list[sqlite3.Row]:
        return self.fetchall(
            "SELECT * FROM source_scan_files WHERE scan_id=? ORDER BY path_fingerprint",
            (scan_id,),
        )

    def source_scan_exclusion_counts(self, scan_id: str) -> list[sqlite3.Row]:
        placeholders = ",".join("?" for _ in EXCLUSION_STATUSES)
        return self.fetchall(
            f"""
            SELECT status, reason, COUNT(*) AS count
            FROM source_scan_files
            WHERE scan_id=? AND status IN ({placeholders})
            GROUP BY status, reason ORDER BY status, reason
            """,
            (scan_id, *sorted(EXCLUSION_STATUSES)),
        )

    def repair_empty_chunks(self, backup_dir: Path) -> dict[str, Any]:
        """Back up SQLite, then remove unreferenced empty chunks idempotently."""

        with self._lock:
            count = int(
                self._connection.execute(
                    "SELECT COUNT(*) AS n FROM chunks "
                    "WHERE length(trim(markdown_text, char(9) || char(10) || char(13) || ' '))=0"
                ).fetchone()["n"]
            )
            if count == 0:
                return {"removed": 0, "backup": None}
            referenced = int(
                self._connection.execute(
                    """
                    SELECT COUNT(*) AS n FROM chunks c
                    WHERE length(trim(c.markdown_text, char(9) || char(10) || char(13) || ' '))=0
                      AND EXISTS (SELECT 1 FROM evidence_spans es WHERE es.chunk_id=c.id)
                    """
                ).fetchone()["n"]
            )
            if referenced:
                raise RuntimeError(
                    "Empty chunks are referenced by persisted evidence; manual evidence review is required"
                )
            backup_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
            backup_path = backup_dir / f"catalog-before-empty-chunk-repair-{stamp}.sqlite3"
            destination = sqlite3.connect(backup_path)
            try:
                self._connection.backup(destination)
                destination.commit()
            finally:
                destination.close()
            os.chmod(backup_path, 0o600)
            descriptor = os.open(backup_path, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = self._connection.execute(
                    "DELETE FROM chunks "
                    "WHERE length(trim(markdown_text, char(9) || char(10) || char(13) || ' '))=0"
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
            removed = int(cursor.rowcount)
        return {"removed": removed, "backup": backup_path.name}

    def admin_sources(self, limit: int = 500, offset: int = 0) -> list[sqlite3.Row]:
        return self.fetchall(
            """
            SELECT d.*, COUNT(DISTINCT sa.id) AS alias_count,
                   (SELECT current_sv.review_status
                    FROM source_versions current_sv
                    WHERE current_sv.document_id=d.id
                      AND current_sv.superseded_by IS NULL
                      AND current_sv.version_sha256=d.content_sha256
                    ORDER BY current_sv.created_at DESC, current_sv.id DESC
                    LIMIT 1) AS review_status
            FROM documents d
            LEFT JOIN source_aliases sa ON sa.document_id=d.id
            GROUP BY d.id ORDER BY d.created_at DESC LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )

    def admin_index_builds(self) -> list[sqlite3.Row]:
        return self.fetchall("SELECT * FROM index_builds ORDER BY created_at DESC")

    def admin_gaps(self) -> list[sqlite3.Row]:
        """Return an owner-safe list DTO; encrypted prose and file paths stay private.

        Never use ``SELECT *`` here.  Besides being an unstable API contract,
        it exposes the encrypted BLOB to the JSON encoder and the local review
        path to browser state.
        """

        return self.fetchall(
            """
            SELECT id,job_id,proposition_sha256,jurisdiction,subject,status,
                   created_at,resolved_at,
                   COALESCE(json_array_length(searches_json), 0) AS search_count,
                   COALESCE(json_array_length(rejection_reasons_json), 0)
                     AS rejection_reason_count
            FROM knowledge_gaps
            ORDER BY created_at DESC
            """
        )

    def admin_quality(self, limit: int = 200) -> list[dict[str, Any]]:
        """Project safe aggregate quality metadata without review payloads."""

        rows = self.fetchall(
            """
            SELECT id,answer_version_id,evidence_passed,academic_score,
                   release_state,policy_version,policy_sha256,created_at,
                   rubric_scores_json,findings_json,
                   CASE WHEN ai_evidence_review_json IS NULL OR
                                  ai_evidence_review_json='' THEN 0 ELSE 1 END
                     AS ai_evidence_review_present,
                   CASE WHEN ai_evidence_adjudication_json IS NULL OR
                                  ai_evidence_adjudication_json='' THEN 0 ELSE 1 END
                     AS ai_evidence_adjudication_present,
                   CASE WHEN assessment_standards_json IS NULL OR
                                  assessment_standards_json='' THEN 0 ELSE 1 END
                     AS assessment_standards_present,
                   CASE WHEN encrypted_source_draft IS NULL OR
                                  length(encrypted_source_draft)=0 THEN 0 ELSE 1 END
                     AS source_draft_present
            FROM quality_reports
            ORDER BY created_at DESC LIMIT ?
            """,
            (limit,),
        )
        projected: list[dict[str, Any]] = []
        for row in rows:
            raw_rubric_scores = str(row["rubric_scores_json"] or "")
            raw_findings = str(row["findings_json"] or "")
            try:
                rubric_scores = json.loads(raw_rubric_scores)
                findings = json.loads(raw_findings)
            except json.JSONDecodeError:
                raise RuntimeError("quality_report_safe_projection_invalid") from None
            if not isinstance(rubric_scores, dict) or not isinstance(findings, list):
                raise RuntimeError("quality_report_safe_projection_invalid")
            projected.append(
                {
                    "quality_report_id": str(row["id"]),
                    "answer_version_id": str(row["answer_version_id"]),
                    "evidence_passed": bool(row["evidence_passed"]),
                    "academic_score": float(row["academic_score"]),
                    "release_state": str(row["release_state"]),
                    "policy_version": str(row["policy_version"]),
                    "policy_sha256": str(row["policy_sha256"] or ""),
                    "created_at": str(row["created_at"]),
                    "rubric_score_count": len(rubric_scores),
                    "rubric_scores_sha256": hashlib.sha256(
                        raw_rubric_scores.encode("utf-8")
                    ).hexdigest(),
                    "finding_count": len(findings),
                    "findings_sha256": hashlib.sha256(raw_findings.encode("utf-8")).hexdigest(),
                    "ai_evidence_review_present": bool(row["ai_evidence_review_present"]),
                    "ai_evidence_adjudication_present": bool(
                        row["ai_evidence_adjudication_present"]
                    ),
                    "assessment_standards_present": bool(row["assessment_standards_present"]),
                    "source_draft_present": bool(row["source_draft_present"]),
                }
            )
        return projected

    def admin_failures(self, limit: int = 200) -> list[sqlite3.Row]:
        """Return only owner-safe failure fields; never expose internal_detail."""

        return self.fetchall(
            """
            SELECT failure_id,state,component,stage,failure_code,job_id,build_id,
                   retryable,blocking,occurrence_count,first_seen,last_seen,
                   closed_at,user_or_owner_safe
            FROM failure_ledger
            ORDER BY CASE state WHEN 'open' THEN 0 WHEN 'retrying' THEN 1 ELSE 2 END,
                     last_seen DESC
            LIMIT ?
            """,
            (limit,),
        )

    def admin_evaluation_issues(self, limit: int = 200) -> list[sqlite3.Row]:
        """Return safe issue metadata; encrypted human notes remain server-side."""

        return self.fetchall(
            """
            SELECT id,run_id,case_id,job_id,category,severity,affected_layer,
                   safe_expected_ids_json,safe_observed_ids_json,root_cause,
                   corrective_action,regression_case_id,fixed_version,status,
                   CASE WHEN encrypted_human_note IS NOT NULL THEN 1 ELSE 0 END AS has_note,
                   created_at,updated_at
            FROM evaluation_issues
            ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END,
                     updated_at DESC
            LIMIT ?
            """,
            (limit,),
        )

    def owner_evaluation_issue_note(self, issue_id: str, *, access_ref: str) -> sqlite3.Row:
        """Read one encrypted issue note and append a prose-free access event."""

        safe_id = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
        if safe_id.fullmatch(issue_id) is None or safe_id.fullmatch(access_ref) is None:
            raise ValueError("owner sensitive-read identity is invalid")
        with self.transaction() as conn:
            row = conn.execute(
                """
                SELECT id,status,encrypted_human_note
                FROM evaluation_issues WHERE id=?
                """,
                (issue_id,),
            ).fetchone()
            if row is None:
                raise KeyError(issue_id)
            conn.execute(
                """
                INSERT INTO evaluation_issue_events(
                  issue_id,event_type,status,safe_payload_json,created_at
                ) VALUES (?, 'owner_sensitive_read', ?, ?, ?)
                """,
                (
                    issue_id,
                    row["status"],
                    json.dumps({"access_ref": access_ref}, sort_keys=True),
                    utc_iso(),
                ),
            )
            return cast(sqlite3.Row, row)

    @staticmethod
    def _admin_review_filter(
        review_type: str | None, status: str | None
    ) -> tuple[str, tuple[str, ...]]:
        clauses = [
            """
            NOT (
              r.status='pending'
              AND r.review_type IN ('source_version', 'online_source_version')
              AND sv.superseded_by IS NOT NULL
            )
            """
        ]
        parameters: list[str] = []
        if review_type is not None:
            clauses.append("r.review_type=?")
            parameters.append(review_type)
        if status is not None:
            clauses.append("r.status=?")
            parameters.append(status)
        return " AND ".join(f"({clause.strip()})" for clause in clauses), tuple(parameters)

    def admin_review_count(
        self, *, review_type: str | None = None, status: str | None = None
    ) -> int:
        where, parameters = self._admin_review_filter(review_type, status)
        row = self.fetchone(
            f"""
            SELECT COUNT(*) AS count
            FROM reviews r
            LEFT JOIN source_versions sv
              ON r.review_type IN ('source_version', 'online_source_version')
             AND sv.id=r.target_id
            WHERE {where}
            """,
            parameters,
        )
        return int(row["count"]) if row is not None else 0

    def admin_reviews(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        review_type: str | None = None,
        status: str | None = None,
    ) -> list[sqlite3.Row]:
        where, parameters = self._admin_review_filter(review_type, status)
        return self.fetchall(
            f"""
            SELECT r.*,
                   d.safe_display_name, d.media_type, d.status AS document_status,
                   d.lane, d.subject_primary, d.jurisdiction, d.content_sha256,
                   sv.title AS source_title, sv.stable_identifier,
                   sv.as_of_date, sv.canonical_url, sv.currentness_status,
                   sv.licence_name, sv.licence_url, sv.metadata_json,
                   sv.processing_fingerprint, sv.superseded_by,
                   (SELECT c.markdown_text FROM chunks c
                    WHERE c.source_version_id=sv.id ORDER BY c.ordinal LIMIT 1) AS source_preview,
                   rr.task_type, rr.subject AS rule_subject, rr.criterion,
                   rr.polarity, rr.grade_band, rr.rule_text, rr.remediation_text
            FROM reviews r
            LEFT JOIN source_versions sv
              ON r.review_type IN ('source_version', 'online_source_version')
             AND sv.id=r.target_id
            LEFT JOIN documents d ON d.id=sv.document_id
            LEFT JOIN rubric_rules rr
              ON r.review_type='assessment_rule' AND rr.id=r.target_id
            WHERE {where}
            ORDER BY r.created_at DESC, r.id DESC
            LIMIT ? OFFSET ?
            """,
            (*parameters, limit, offset),
        )

    def admin_review_page(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        review_type: str | None = None,
        status: str | None = None,
    ) -> tuple[int, list[sqlite3.Row]]:
        """Return a count and page from one lock-consistent review snapshot."""

        with self._lock:
            total = self.admin_review_count(review_type=review_type, status=status)
            items = self.admin_reviews(
                limit=limit,
                offset=offset,
                review_type=review_type,
                status=status,
            )
        return total, items

    def approved_assessment_rules(
        self, *, task_type: str, subject: str | None
    ) -> list[sqlite3.Row]:
        """Return reviewed rules in specific-to-general precedence order.

        Subject ``NULL`` / empty / ``general`` marks a cross-subject owner
        standard (not a subject-area filter). Those rows apply to any question
        subject so TaskType.GENERAL and subject-specific drafting both inherit
        the 70+ / anti-pattern baselines.
        """

        normalized_subject = " ".join((subject or "").casefold().split())
        return self.fetchall(
            """
            SELECT rr.* FROM rubric_rules rr
            LEFT JOIN source_versions sv ON sv.id=rr.source_version_id
            LEFT JOIN documents d ON d.id=sv.document_id
            WHERE rr.review_status='approved'
              AND (
                -- Owner-authorised standards keep historical assessment provenance
                -- even after those assessment_guidance versions are superseded/rejected.
                rr.id LIKE 'assessment-canonical-%'
                OR rr.source_version_id IS NULL
                OR (
                  sv.superseded_by IS NULL
                  AND d.id IS NOT NULL
                  AND sv.version_sha256=d.content_sha256
                )
              )
              AND (rr.task_type IS NULL OR rr.task_type=?)
              AND (
                rr.subject IS NULL
                OR TRIM(LOWER(rr.subject)) IN ('', 'general')
                OR LOWER(rr.subject)=?
              )
            ORDER BY
              CASE
                WHEN TRIM(LOWER(COALESCE(rr.subject, ''))) NOT IN ('', 'general')
                     AND LOWER(rr.subject)=?
                     AND rr.task_type=? THEN 0
                WHEN TRIM(LOWER(COALESCE(rr.subject, ''))) NOT IN ('', 'general')
                     AND LOWER(rr.subject)=? THEN 1
                WHEN rr.task_type=? THEN 2
                ELSE 3
              END,
              CASE rr.polarity
                WHEN 'positive_pattern' THEN 0
                WHEN 'error_to_avoid' THEN 1
                ELSE 2
              END,
              CASE rr.grade_band
                WHEN '70+' THEN 0
                WHEN '60-69' THEN 1
                WHEN '50-59' THEN 2
                ELSE 3
              END,
              rr.criterion, rr.id
            """,
            (
                task_type,
                normalized_subject,
                normalized_subject,
                task_type,
                normalized_subject,
                task_type,
            ),
        )

    def decide_review(
        self,
        review_id: str,
        decision: str,
        note: str | None,
        source_approval: dict[str, Any] | None = None,
        encrypted_note: bytes | None = None,
        *,
        trusted_case_snapshot_approval: bool = False,
    ) -> bool:
        if decision not in {"approved", "rejected"}:
            raise ValueError("Review decision must be approved or rejected")
        decided_at = datetime.now(UTC)
        decided_at_iso = decided_at.isoformat()
        with self.transaction() as conn:
            review = conn.execute(
                "SELECT review_type, target_id FROM reviews WHERE id=? AND status='pending'",
                (review_id,),
            ).fetchone()
            if review is None:
                return False
            source = None
            if review["review_type"] in {"source_version", "online_source_version"}:
                source = conn.execute(
                    """
                    SELECT sv.*, d.lane AS document_lane
                    FROM source_versions sv JOIN documents d ON d.id=sv.document_id
                    WHERE sv.id=?
                    """,
                    (review["target_id"],),
                ).fetchone()
                if source is None:
                    raise ValueError("Source version for review no longer exists")
                if source["superseded_by"] is not None:
                    raise ValueError(
                        "Source version review is superseded; review the current successor"
                    )
            conn.execute(
                """
                UPDATE reviews
                SET status=?, decision_note=?, encrypted_decision_note=?, decided_at=?
                WHERE id=? AND status='pending'
                """,
                (
                    decision,
                    (
                        "[encrypted]"
                        if encrypted_note is not None
                        else "[redacted]"
                        if note
                        else None
                    ),
                    encrypted_note,
                    decided_at_iso,
                    review_id,
                ),
            )
            if review["review_type"] == "source_version":
                if decision == "approved":
                    assert source is not None
                    approved = _validate_source_approval(
                        source_approval,
                        expected_lane=str(source["document_lane"] or ""),
                        trusted_case_snapshot_approval=trusted_case_snapshot_approval,
                    )
                    try:
                        existing_metadata = json.loads(source["metadata_json"])
                    except (TypeError, json.JSONDecodeError) as exc:
                        raise ValueError(
                            "Source metadata is invalid and cannot be approved"
                        ) from exc
                    if not isinstance(existing_metadata, dict):
                        raise ValueError("Source metadata is invalid and cannot be approved")
                    metadata = {
                        **existing_metadata,
                        "identity_verified": approved["identity_verified"],
                        "currentness_verified": approved["currentness_verified"],
                        "currentness_applicable": approved["currentness_applicable"],
                        "authority_eligible": approved["authority_eligible"],
                        "citation_rendering_enabled": approved["citation_rendering_enabled"],
                        "citation_data": approved["citation_data"],
                        "canonical_citation": approved["canonical_citation"],
                        "approval_as_of_date": approved["as_of_date"],
                        "material_type": approved["material_type"],
                    }
                    if approved.get("identity_title"):
                        metadata["identity_title"] = approved["identity_title"]
                    conn.execute(
                        """
                        UPDATE source_versions
                        SET stable_identifier=?, as_of_date=?, canonical_url=?,
                            currentness_status=?, licence_name=?, licence_url=?,
                            metadata_json=?, review_status='approved'
                        WHERE id=?
                        """,
                        (
                            approved["stable_identifier"],
                            approved["as_of_date"],
                            approved.get("canonical_url"),
                            approved["currentness_status"],
                            approved.get("licence_name"),
                            approved.get("licence_url"),
                            json.dumps(metadata, ensure_ascii=False, sort_keys=True),
                            review["target_id"],
                        ),
                    )
                else:
                    conn.execute(
                        "UPDATE source_versions SET review_status='rejected' WHERE id=?",
                        (review["target_id"],),
                    )
            elif review["review_type"] == "online_source_version":
                # This decision records review of the frozen answer snapshot only.
                # A separate licensed ingestion is required for retrieval promotion.
                if decision == "rejected":
                    conn.execute(
                        "UPDATE source_versions SET review_status='rejected' WHERE id=?",
                        (review["target_id"],),
                    )
            elif review["review_type"] == "assessment_rule":
                conn.execute(
                    "UPDATE rubric_rules SET review_status=? WHERE id=?",
                    (decision, review["target_id"]),
                )
            elif review["review_type"] == "upload_source_candidate":
                # This decision approves or rejects only entry into the normal
                # source-intake workflow. It never creates a document, source
                # version, index candidate or ACTIVE promotion. Once the
                # review ends, retain the encrypted bytes for thirty more days
                # so the owner can complete the separate identity/rights/
                # currentness review, then allow normal upload expiry.
                retention_until = (decided_at + timedelta(days=30)).isoformat()
                cursor = conn.execute(
                    """
                    UPDATE uploads SET review_pinned=0, review_completed_at=?,
                      retention_until=?, quarantine_status=?
                    WHERE content_sha256=? AND status='staged'
                    """,
                    (
                        decided_at_iso,
                        retention_until,
                        "passed" if decision == "approved" else "rejected",
                        review["target_id"],
                    ),
                )
                if cursor.rowcount < 1:
                    raise ValueError("Upload source-intake review target is unavailable")
        return True

    def queue_document_safety_review(self, source_version_id: str) -> None:
        """Retain an unsafe source and surface it without prompting its contents."""

        self.execute(
            """
            INSERT OR IGNORE INTO reviews(
              id, review_type, target_id, status, reason, created_at
            ) VALUES (?, 'document_safety', ?, 'pending', ?, ?)
            """,
            (
                f"review-document-safety-{source_version_id}",
                source_version_id,
                "Document-borne instruction patterns were excluded before model prompting",
                utc_iso(),
            ),
        )

    def purge_expired_unreleased_versions(self) -> int:
        now = utc_iso()
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE answer_versions SET parent_version_id=NULL
                WHERE parent_version_id IN (
                  SELECT id FROM answer_versions
                  WHERE (release_state IS NULL OR release_state='held_for_review')
                    AND purge_after < ?
                )
                """,
                (now,),
            )
            cursor = conn.execute(
                """
                DELETE FROM answer_versions
                WHERE (release_state IS NULL OR release_state='held_for_review')
                  AND purge_after < ?
                """,
                (now,),
            )
            return int(cursor.rowcount)


def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {str(key): row[key] for key in tuple(row.keys())}


def _scrub_root_descriptors(encoded: Any) -> str:
    """Migrate legacy scan-root JSON to path-free, idempotent descriptors."""

    try:
        decoded = json.loads(str(encoded or "[]"))
    except json.JSONDecodeError:
        decoded = []
    if not isinstance(decoded, list):
        decoded = []
    safe: list[dict[str, str]] = []
    for index, raw in enumerate(decoded, start=1):
        if isinstance(raw, dict):
            identifier = str(raw.get("id") or "")
            fingerprint = str(raw.get("fingerprint") or "")
            already_safe = bool(
                re.fullmatch(r"source-root-\d+", identifier)
                and re.fullmatch(r"[0-9a-f]{64}", fingerprint)
            )
            if already_safe:
                safe.append({"id": identifier, "fingerprint": fingerprint})
                continue
            seed = json.dumps(raw, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        else:
            seed = str(raw)
        digest = hashlib.sha256(f"legalbot-source-root-migration-v1\0{seed}".encode()).hexdigest()
        safe.append({"id": f"source-root-{index}", "fingerprint": digest})
    return json.dumps(safe, ensure_ascii=True, sort_keys=True)


def _validate_source_approval(
    value: dict[str, Any] | None,
    *,
    expected_lane: str,
    trusted_case_snapshot_approval: bool = False,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(
            "Source approval requires verified citation identity and currentness metadata"
        )
    lane_material_types = {
        "primary_authority": {"case", "legislation", "rule"},
        "official_secondary": {"official_guidance"},
        "scholarship": {"journal", "book"},
        "private_teaching": {"lecture", "tutorial", "seminar", "course_note"},
        "assessment_guidance": {"assessment", "rubric", "marker_feedback"},
    }
    if expected_lane not in lane_material_types:
        raise ValueError("Source lane is not eligible for approval")
    if value.get("identity_verified") is not True:
        raise ValueError("Source identity must be explicitly verified")
    material_type = " ".join(str(value.get("material_type") or "").split()).lower()
    if material_type not in lane_material_types[expected_lane]:
        raise ValueError("Material type is not valid for the source lane")
    stable_identifier = " ".join(str(value.get("stable_identifier") or "").split())
    if expected_lane in {"private_teaching", "assessment_guidance"}:
        result = _validate_internal_source_approval(
            value,
            stable_identifier=stable_identifier,
            material_type=material_type,
        )
    else:
        result = _validate_citable_source_approval(
            value,
            stable_identifier=stable_identifier,
            material_type=material_type,
            trusted_case_snapshot_approval=trusted_case_snapshot_approval,
        )

    for field in ("canonical_url", "licence_url"):
        raw = " ".join(str(value.get(field) or "").split())
        if raw:
            parsed = urlparse(raw)
            if parsed.scheme != "https" or not parsed.hostname:
                raise ValueError(f"{field} must be a valid HTTPS URL")
            result[field] = raw
    licence_name = " ".join(str(value.get("licence_name") or "").split())
    if licence_name:
        result["licence_name"] = licence_name
    return result


_INTERNAL_IDENTIFIER = re.compile(
    r"^(?:sha256|content-sha256|source-identity-sha256|local-representation-sha256|"
    r"doi-sha256|neutral-citation-sha256):[0-9a-f]{64}$"
)


def _validate_internal_source_approval(
    value: dict[str, Any], *, stable_identifier: str, material_type: str
) -> dict[str, Any]:
    """Validate a non-authority source without inventing public citation metadata."""

    if not _INTERNAL_IDENTIFIER.fullmatch(stable_identifier):
        raise ValueError(
            "Private teaching and assessment sources require a privacy-safe SHA-256 source identity"
        )
    currentness_status = " ".join(str(value.get("currentness_status") or "").split()).lower()
    if currentness_status != "not_applicable":
        raise ValueError("Internal source currentness_status must be not_applicable")
    currentness_verified = value.get("currentness_verified")
    if currentness_verified is not None and currentness_verified is not False:
        raise ValueError("Currentness verification is not applicable to internal sources")
    supplied_as_of_date = value.get("as_of_date")
    if supplied_as_of_date is not None and supplied_as_of_date != "":
        raise ValueError("Internal sources must not fabricate a legal currentness as-of date")
    citation_data = value.get("citation_data")
    if citation_data is None:
        citation_data = {}
    if not isinstance(citation_data, dict):
        raise ValueError("Internal source citation_data must be an object when supplied")
    if set(citation_data) - {"title"}:
        raise ValueError("Internal sources must not include OSCOLA citation fields")
    identity_title = " ".join(
        str(value.get("identity_title") or citation_data.get("title") or "").split()
    )
    if not identity_title:
        raise ValueError("Internal teaching and assessment sources require an identity title")
    return {
        "identity_verified": True,
        "currentness_verified": False,
        "currentness_applicable": False,
        "authority_eligible": False,
        "citation_rendering_enabled": False,
        "stable_identifier": stable_identifier,
        "as_of_date": None,
        "currentness_status": currentness_status,
        "material_type": material_type,
        "identity_title": identity_title,
        "citation_data": {},
        "canonical_citation": None,
    }


def _validate_citable_source_approval(
    value: dict[str, Any],
    *,
    stable_identifier: str,
    material_type: str,
    trusted_case_snapshot_approval: bool = False,
) -> dict[str, Any]:
    case_snapshot = material_type == "case"
    if case_snapshot and not trusted_case_snapshot_approval:
        raise ValueError(
            "Generic source review cannot approve case currentness; use the trusted, "
            "rights-reviewed historical snapshot workflow"
        )
    if case_snapshot and value.get("currentness_verified") is not False:
        raise ValueError("A historical case snapshot must remain currentness_verified=false")
    if not case_snapshot and value.get("currentness_verified") is not True:
        raise ValueError("Source identity and currentness must both be explicitly verified")
    if (
        not stable_identifier
        or stable_identifier.startswith(("local-", "opaque_local:"))
        or (_INTERNAL_IDENTIFIER.fullmatch(stable_identifier) is not None)
    ):
        raise ValueError("A verified public or bibliographic stable identifier is required")
    try:
        as_of = date.fromisoformat(str(value.get("as_of_date") or ""))
    except ValueError as exc:
        raise ValueError("A valid currentness as-of date is required") from exc
    if as_of > date.today():
        raise ValueError("The currentness as-of date cannot be in the future")
    currentness_status = " ".join(str(value.get("currentness_status") or "").split()).lower()
    if currentness_status not in {
        "current",
        "historical",
        "point_in_time",
        "latest_available_revised_snapshot",
    }:
        raise ValueError(
            "Currentness status must be current, historical, point_in_time, "
            "or latest_available_revised_snapshot"
        )
    if case_snapshot and currentness_status not in {"historical", "point_in_time"}:
        raise ValueError("A trusted case snapshot must use historical or point_in_time status")
    if case_snapshot:
        licence_name = " ".join(str(value.get("licence_name") or "").split())
        if not stable_identifier.startswith("neutral-citation:") or not licence_name.startswith(
            ("Open Government Licence", "Open Parliament Licence")
        ):
            raise ValueError(
                "Trusted case snapshots require a neutral citation and reviewed OGL/OPL rights"
            )
    citation_data = value.get("citation_data")
    if not isinstance(citation_data, dict):
        raise ValueError("Structured OSCOLA citation_data is required")
    citation_types = {
        "case": {"case"},
        "legislation": {"legislation", "statutory_instrument"},
        "rule": {"rule"},
        "journal": {"journal"},
        "book": {"book", "book_chapter"},
        "official_guidance": {"official_guidance", "web", "parliamentary", "report"},
    }
    if str(citation_data.get("source_type") or "").lower() not in citation_types[material_type]:
        raise ValueError("OSCOLA source_type does not match the reviewed material type")
    try:
        canonical_citation = render_oscola(citation_data)
    except CitationMetadataError as exc:
        raise ValueError(str(exc)) from exc

    return {
        "identity_verified": True,
        "currentness_verified": not case_snapshot,
        "currentness_applicable": True,
        "authority_eligible": True,
        "citation_rendering_enabled": True,
        "stable_identifier": stable_identifier,
        "as_of_date": as_of.isoformat(),
        "currentness_status": currentness_status,
        "material_type": material_type,
        "citation_data": citation_data,
        "canonical_citation": canonical_citation,
    }
