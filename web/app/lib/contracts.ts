export type TaskMode = "auto" | "essay" | "problem" | "general";
export type Jurisdiction =
  | "England and Wales"
  | "Hong Kong"
  | "European Union"
  | "United States"
  | "Other";
export type OnlineMode = "auto" | "always" | "local_only";

export type JobStage =
  | "queued"
  | "researching"
  | "qualifying_evidence"
  | "drafting"
  | "verifying"
  | "repairing"
  | "assembling"
  | "complete"
  | "limited"
  | "held_for_review"
  | "system_error"
  | "cancelled";

export type JobStatus =
  | "queued"
  | "running"
  | "complete"
  | "held_for_review"
  | "system_error"
  | "cancelled";

export type ReleaseState =
  | "verified_full"
  | "verified_concise"
  | "verified_limited"
  | "held_for_review"
  | "system_error";

export interface QuestionRequest {
  question: string;
  task_type: TaskMode;
  jurisdiction: string;
  as_of_date?: string;
  word_target: number;
  online_mode: OnlineMode;
  upload_ids: string[];
  conversation_id?: string;
}

export interface QuestionAccepted {
  job_id: string;
  status: JobStatus;
  stage: JobStage;
  events_url: string;
  conversation_id?: string | null;
}

export interface JobRecord {
  id: string;
  status: JobStatus;
  stage: JobStage;
  progress: number;
  question_summary: string;
  answer_id: string | null;
  release_state: ReleaseState | null;
  message: string | null;
  trace_id: string;
  last_progress_at: string;
  created_at: string;
  updated_at: string;
}

export interface JobProgressEvent {
  stage: JobStage;
  progress: number;
  message: string | null;
  payload: Record<string, unknown>;
}

export interface JobDoneEvent {
  status: JobStatus;
  answer_id: string | null;
  release_state: ReleaseState | null;
  message: string | null;
}

export interface JobEventEnvelope {
  schema: "legalbot.job-event.v1";
  sequence: number;
  event: "progress" | "done";
  data: JobProgressEvent | JobDoneEvent;
}

export interface QualityFinding {
  gate: string;
  code: string;
  message: string;
  severity: "hard_blocker" | "repairable" | "informational";
  section_id?: string | null;
  claim_id?: string | null;
  corrective_action?: string | null;
}

export interface AnswerQuality {
  id: string;
  answer_version_id: string;
  evidence_passed: number | boolean;
  academic_score: number;
  rubric_scores_json?: string;
  findings_json?: string;
  rubric_scores?: Record<string, number>;
  findings?: QualityFinding[];
  release_state: ReleaseState;
  policy_version: string;
  created_at: string;
}

export interface AnswerRecord {
  id: string;
  job_id: string;
  content: string;
  word_count: number;
  release_state: ReleaseState;
  policy_version: string;
  model_version: string;
  index_build_id: string | null;
  quality: AnswerQuality | null;
  created_at: string;
}

export interface ConversationSummary {
  answer_id: string;
  job_id: string;
  question_summary: string;
  release_state: ReleaseState;
  word_count: number;
  created_at: string;
}

export interface AttachmentRecord {
  upload_id: string;
  display_name: string;
  status: "staged";
}

export interface EvidenceClaim {
  id: string;
  section_id: string;
  text: string;
  material: boolean;
  verification_status: string;
  verification_reason: string | null;
  evidence_ids: string[];
}

export interface EvidenceCitationData {
  source_type?: string;
  title?: string;
  case_name?: string;
  neutral_citation?: string;
  report_citation?: string;
  decision_date?: string;
  neutral_court_identifier?: string;
  court_identifier?: string;
  court_identifier_not_required?: boolean;
  pinpoint_type?: string;
  provision?: string;
  instrument_number?: string;
  author?: string;
  author_or_body?: string;
  journal?: string;
  year?: string;
  year_format?: string;
  volume?: string;
  issue?: string;
  first_page?: string;
  online_only?: boolean;
  publisher?: string;
  translator?: string;
  editor?: string;
  editor_role?: string;
  additional_information?: string;
  edition?: string;
  book_title?: string;
  report_type?: string;
  report_number?: string;
  session?: string;
  paper_number?: string;
  publication_date?: string;
  title_style?: string;
  parliamentary_type?: string;
  house?: string;
  date?: string;
  column?: string;
  columns?: string;
}

export interface CaseCurrentnessReviewSummary {
  exact_span_sha256: string;
  proposition_hash: string;
  legal_role: "holding_ratio" | "binding_legal_rule";
  later_treatment_reviewed_as_of_date: string;
  later_treatment_status:
    | "confirmed_current"
    | "qualified_current"
    | "not_current"
    | "uncertain_hold";
  reviewer_role: string;
  review_scope: "ordinary" | "critical" | "disputed";
  second_review_status: "not_required" | "pending" | "confirmed" | "disagreed";
  seal_sha256: string;
}

export interface EvidenceRecord {
  id: string;
  source_version_id: string;
  chunk_id: string;
  locator: string;
  lane:
    | "primary_authority"
    | "official_secondary"
    | "scholarship"
    | "private_teaching"
    | "assessment_guidance";
  jurisdiction: string;
  subject: string;
  citation_data: EvidenceCitationData;
  canonical_citation: string | null;
  currentness_status: string;
  content_sha256: string;
  index_build_id: string;
  retrieval_relevance_score: number | null;
  retrieval_route: string | null;
  retrieval_threshold: number | null;
  retrieval_threshold_policy_sha256: string | null;
  retrieval_threshold_qualified: boolean | null;
  retrieval_qualification_reason: string | null;
  legal_role: string;
  unapplied_effect_count: number | null;
  provision_extent_status: string;
  identity_verified: boolean;
  currentness_verified: boolean;
  case_currentness_reviews: CaseCurrentnessReviewSummary[];
  case_currentness_manifest_seals: string[];
}

export interface AnswerEvidence {
  answer_id: string;
  claims: EvidenceClaim[];
  evidence: EvidenceRecord[];
}

export type AnswerFeedbackRating = "helpful" | "partly_helpful" | "not_helpful";
export type AnswerFeedbackCategory =
  | "accuracy"
  | "currentness"
  | "authority"
  | "citation"
  | "completeness"
  | "application"
  | "structure"
  | "clarity"
  | "length"
  | "privacy"
  | "other";

export interface AnswerFeedbackRequest {
  rating: AnswerFeedbackRating;
  category: AnswerFeedbackCategory;
  scope: "answer" | "section" | "claim" | "evidence";
  target_id?: string;
  note?: string;
  idempotency_key: string;
}

export interface AnswerFeedbackResult {
  refinement_id: string;
  status: string;
  priority: number;
  duplicate: boolean;
}

export interface HealthRecord {
  status: string;
  api_version: string;
  owner_only: boolean;
  database_ready: boolean;
  worker_ready: boolean;
  active_index: string | null;
  model_ready: boolean;
  model_id: string;
  prompt_version: string;
  router_version: string;
  classifier_version: string;
  policy_sha256: string;
  assessment_bundle_sha256: string;
  reasons: string[];
}

export interface AdminOverview {
  sources_total: number;
  source_statuses: Record<string, number>;
  jobs: Record<string, number>;
  releases: Record<string, number>;
  open_gaps: number;
  pending_reviews: number;
  active_index: string | null;
  model_ready: boolean;
  owner_only: boolean;
}

export interface ObservabilityPolicySummary {
  policy_id: string;
  internal_only: boolean;
  external_sla: boolean;
  provisional: boolean;
  baseline_calibrated: boolean;
  enforcement: "observe_only" | string;
  default_sampling: string;
  live30_retention: string;
}

export interface MetricSeriesRow {
  metric: string;
  labels: Record<string, string>;
  value?: number;
  count?: number;
  sample_count?: number;
  sum?: number;
  min?: number | null;
  max?: number | null;
  p50?: number | null;
  p95?: number | null;
  p99?: number | null;
}

export interface ObservabilitySnapshot {
  schema: "legalbot.live-metrics-snapshot.v1" | string;
  generated_at: string;
  window: string;
  counters: MetricSeriesRow[];
  gauges: MetricSeriesRow[];
  histograms: MetricSeriesRow[];
}

export interface SloCheck {
  metric: string;
  scope: string;
  route?: string;
  state: string;
  observed?: number | null;
  observed_p95?: number | null;
  threshold?: number;
  threshold_p95?: number;
  stuck_threshold?: number;
  samples?: number;
  minimum_samples?: number;
  successful_runs?: number;
  minimum_successful_runs?: number;
  passed?: boolean | null;
}

export interface SloEvaluation {
  schema: "legalbot.observability-slo-evaluation.v1" | string;
  policy_id: string;
  internal_only: boolean;
  external_sla: boolean;
  provisional: boolean;
  baseline_calibrated: boolean;
  enforcement: string;
  gate_eligible: boolean;
  evaluation_complete: boolean;
  within_provisional_targets: boolean;
  checks: SloCheck[];
}

export interface ActiveObservedJob {
  job_id: string;
  trace_id: string;
  run_id: string | null;
  case_id: string | null;
  status: string;
  stage: string;
  progress: number;
  route: "direct" | "sectioned" | "full_enquiry";
  word_target: number;
  word_band: string;
  trace_retention: "full" | "sampled";
  last_progress_at: string;
  progress_age_seconds: number;
  progress_state: "fresh" | "stale" | "stuck" | "unbanded";
  attempt: number;
}

export interface ObservabilityAdminView {
  schema: "legalbot.admin-observability.v1" | string;
  policy: ObservabilityPolicySummary;
  snapshots: Array<{ component: "api" | "worker" | string; snapshot: ObservabilitySnapshot }>;
  slo_evaluations: Array<{ component: "api" | "worker" | string; evaluation: SloEvaluation }>;
  active_jobs: ActiveObservedJob[];
}

export interface SourceRecord {
  id: string;
  content_sha256: string;
  source_identity_id: string;
  safe_display_name: string;
  media_type: string;
  status: string;
  lane: string | null;
  subject_primary: string | null;
  subject_secondary_json: string;
  jurisdiction: string | null;
  duplicate_of: string | null;
  created_at: string;
  updated_at: string;
  alias_count: number;
  review_status: string | null;
}

export interface SourceScanSummary {
  id: string;
  resumed_from_scan_id: string | null;
  status: "queued" | "running" | "complete" | "failed";
  expected_file_count: number;
  files_accounted: number;
  statuses: Record<string, number>;
  exclusion_diagnostics: SourceExclusionDiagnostic[];
  manifest_sha256: string | null;
  error_code: string | null;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface SourceExclusionDiagnostic {
  status: "unsupported" | "quarantined" | "encrypted" | "ocr_required";
  reason_code: string;
  count: number;
  explanation: string;
  corrective_action: string;
}

export interface IndexBuildSummary {
  id: string;
  status: string;
  document_count: number;
  chunk_count: number;
  vector_count: number;
  embedding_model: string;
  reranker_model: string;
  manifest_sha256: string | null;
  metrics_json: string;
  created_at: string;
  promoted_at: string | null;
}

export interface CoverageRecord {
  subject: string;
  status: string;
  lane: string;
  count: number;
}

export interface KnowledgeGap {
  id: string;
  job_id: string;
  missing_proposition: string;
  proposition_sha256: string | null;
  jurisdiction: string;
  subject: string | null;
  search_count: number;
  rejection_reason_count: number;
  status: string;
  created_at: string;
  resolved_at: string | null;
}

export interface QualityReport extends AnswerQuality {
  rubric_scores: Record<string, number>;
  findings: QualityFinding[];
}

export interface FailureLedgerRecord {
  failure_id: string;
  state: "open" | "retrying" | "recovered" | "terminal" | "waived";
  component: string;
  stage: string | null;
  failure_code: string | null;
  job_id: string | null;
  build_id: string | null;
  retryable: number | boolean;
  blocking: number | boolean;
  occurrence_count: number;
  first_seen: string;
  last_seen: string;
  closed_at: string | null;
  user_or_owner_safe: string;
}

export interface EvaluationIssueRecord {
  id: string;
  run_id: string | null;
  case_id: string | null;
  job_id: string | null;
  category: string;
  severity: "low" | "medium" | "high" | "critical";
  affected_layer: string;
  expected_ids: string[];
  observed_ids: string[];
  root_cause: string;
  corrective_action: string;
  regression_case_id: string | null;
  fixed_version: string | null;
  status: string;
  has_note: boolean;
  created_at: string;
  updated_at: string;
}

export interface OwnerSensitiveNoteDetail {
  id: string;
  note: string | null;
  note_sha256?: string | null;
  access_ref: string;
}

export interface RefinementRecord {
  id: string;
  category: "debug" | "missing" | "answer_feedback";
  scope: string;
  priority: number;
  status: string;
  origin: string;
  answer_id: string | null;
  job_id: string | null;
  knowledge_gap_id: string | null;
  research_task_id: string | null;
  target: Record<string, unknown>;
  note_sha256: string | null;
  occurrence_count: number;
  root_cause: string | null;
  repair_version: string | null;
  regression_case_id: string | null;
  resolution_evidence: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}

export interface ResearchTaskRecord {
  id: string;
  task_type: string;
  trigger_kind: string;
  priority_band: "high" | "medium" | "low";
  base_priority: number;
  subject: string;
  jurisdiction: string;
  as_of_date: string;
  source_id: string | null;
  authority_identity_id: string | null;
  knowledge_gap_id: string | null;
  pinned_index_build_id: string | null;
  source_manifest_sha256: string | null;
  query_sha256: string;
  status: string;
  status_reason: string | null;
  attempt_count: number;
  max_attempts: number;
  candidate_cap: number;
  created_at: string;
  updated_at: string;
}

export interface ResearchCandidateRecord {
  id: string;
  task_id: string;
  source_id: string;
  source_identity: string;
  content_sha256: string | null;
  metadata_sha256: string;
  status: string;
  comparison_state: string | null;
  rights_state: string;
  system_verification_sha256: string | null;
  identity_review_state: string;
  currentness_review_state: string;
  reviewer_ref: string | null;
  intake_review_id: string | null;
  content_type: string | null;
  disposition: string | null;
  network_fetch_state: string | null;
  additional_permission_required: boolean | null;
  created_at: string;
  updated_at: string;
}

export interface SourceUpdateRecord {
  id: string;
  task_id: string;
  candidate_id: string | null;
  source_id: string;
  authority_identity_id: string;
  pinned_index_build_id: string | null;
  pinned_source_manifest_sha256: string | null;
  observed_active_build_id: string | null;
  baseline_version_sha256: string | null;
  remote_content_sha256: string | null;
  comparison_state: "unchanged" | "changed" | "new" | "withdrawn" | "unknown";
  stale_active: boolean;
  scope_kind: "authority" | "proposition";
  legal_locator: string | null;
  proposition_sha256: string | null;
  materiality_status: "unassessed" | "non_material" | "material" | "unknown";
  review_status: "pending" | "approved" | "rejected" | "not_required";
  reviewer_ref: string | null;
  review_manifest_sha256: string | null;
  recompare_required: boolean;
  change_summary_code: string | null;
  created_at: string;
}

export interface ResearchCheckNowRequest {
  task_type: "source_update_check" | "gap_research" | "broad_discovery";
  priority: "high" | "medium" | "low";
  subject: string;
  source_id?: string;
  authority_identity_id?: string;
  knowledge_gap_id?: string;
  idempotency_key?: string;
}

export interface ResearchCheckNowResult {
  task_id: string;
  status: string;
  priority: "high" | "medium" | "low";
  pinned_index_build_id: string | null;
}

export interface SubjectReadinessView {
  build_id: string | null;
  source_manifest_sha256: string | null;
  source_policy_id: string | null;
  current_law_as_of_date: string | null;
  diagnostic_only: true;
  subjects: Array<{
    subject: string;
    source_count: number;
    chunk_count: number;
    identity_verified_source_count: number;
    currentness_verified_source_count: number;
    full_current_law_source_count: number;
    extent_verified_source_count: number;
    later_treatment_required_source_count: number;
    later_treatment_verified_source_count: number;
    reviewed_case_span_count: number;
    unresolved_gap_count: number;
    last_official_update_check: string | null;
    diagnostic_only: true;
  }>;
}

export interface LiveEvaluationRunSummary {
  run_id: string;
  suite_id: string;
  suite_version: string;
  created_at: string;
  as_of_date: string;
  status: string;
  expected_case_count: number;
  selected_generation_case_count?: number;
  coverage_only_case_count?: number;
  completed_case_count: number;
  pass_outcome_count: number;
  released_outcome_count: number;
  limited_outcome_count: number;
  held_or_failed_outcome_count: number;
  privacy_report_passed: boolean | null;
  local_only: true;
  purpose: "evaluation_only";
  eligible_for_training: false;
  training_export_allowed: false;
  model_version: string | null;
  index_build_id: string | null;
  policy_sha256: string | null;
  assessment_rules_sha256: string | null;
}

export interface LiveEvaluationEvidenceRecord {
  evidence_span_id: string;
  stable_source_id: string;
  legal_locator: string;
  legal_role: string;
  identity_state: string;
  support_state: string;
  retrieval_rank: number | null;
  currentness_state: string;
  jurisdiction_state: string;
}

export interface LiveEvaluationRubricRecord {
  criterion_id: string;
  score: number | null;
  status: string;
  assessment_rule_ids: string[];
  verification_signal: string | null;
}

export interface LiveEvaluationRepairRecord {
  repair_id: string;
  section_id: string | null;
  reason_code: string;
  status: string;
  attempt_count: number;
}

export interface LiveEvaluationDiagnosticRecord {
  id: string;
  category: string;
  severity: string;
  affected_layer: string | null;
  status: string;
  expected_ids: string[];
  observed_ids: string[];
  regression_case_id: string | null;
  fixed_version: string | null;
}

export interface LiveEvaluationPassRecord {
  pass_number: number;
  job_id: string | null;
  trace_id: string | null;
  status: string;
  release_state: string;
  released: boolean;
  privacy_passed: boolean;
  evidence_passed: boolean;
  word_count: number | null;
  word_target: number | null;
  word_target_within_tolerance: boolean | null;
  word_target_delta: number | null;
  route: string | null;
  model_version: string | null;
  index_build_id: string | null;
  policy_version: string | null;
  assessment_bundle_sha256: string | null;
  assessment_rule_ids: string[];
  triggered_assessment_rule_ids: string[];
  rule_evaluation_state: "recorded" | "not_recorded";
  evidence: LiveEvaluationEvidenceRecord[];
  rubric: LiveEvaluationRubricRecord[];
  repairs: LiveEvaluationRepairRecord[];
  failure_codes: string[];
  completion_duration_ms: number | null;
}

export interface LiveEvaluationCaseRecord {
  case_id: string;
  ordinal: number;
  status: string;
  release_state: string;
  released: boolean;
  word_target: number;
  expected_research_route: string | null;
  expected_drafting_route: string | null;
  as_of_date: string | null;
  passes: LiveEvaluationPassRecord[];
  issues: LiveEvaluationDiagnosticRecord[];
  knowledge_gaps: LiveEvaluationDiagnosticRecord[];
}

export interface LiveEvaluationRunList {
  items: LiveEvaluationRunSummary[];
  invalid_run_count: number;
}

export interface LiveEvaluationRunDetail {
  run: LiveEvaluationRunSummary;
  cases: LiveEvaluationCaseRecord[];
}

export interface LiveEvaluationReleasedAnswer {
  run_id: string;
  case_id: string;
  pass_number: number;
  release_state: string;
  word_count: number | null;
  answer_sha256: string;
  content: string;
}

export interface RuntimeRecordsStatus {
  schema: "legalbot.runtime-records-status.v1" | string;
  feedback_count: number;
  open_incident_count: number;
  regression_count: number;
  curation_counts: Record<string, number>;
  eligible_for_training: false;
  training_export_allowed: false;
  plaintext_secrets: false;
}

export interface ReviewItem {
  id: string;
  review_type: string;
  target_id: string;
  status: "pending" | "approved" | "rejected";
  reason: string | null;
  decision_note: string | null;
  created_at: string;
  decided_at: string | null;
  source_context?: {
    display_name: string;
    title: string;
    media_type: string;
    document_status: string;
    lane: string;
    subject: string | null;
    jurisdiction: string | null;
    content_sha256: string;
    preview: string;
    stable_identifier: string | null;
    as_of_date: string | null;
    canonical_url: string | null;
    currentness_status: string;
    licence_name: string | null;
    licence_url: string | null;
    citation_data: Record<string, unknown>;
    material_type: string | null;
    public_identifier_candidate: {
      scheme: "doi" | "neutral_citation";
      value: string;
      stable_identifier: string;
    } | null;
    identity_title: string | null;
    identity_verified: boolean;
    currentness_verified: boolean;
    subsequent_treatment_check_required: boolean;
    subsequent_treatment_verified: boolean;
  };
  rule_context?: {
    task_type: string | null;
    subject: string | null;
    criterion: string;
    polarity: string;
    grade_band: string;
    rule_text: string;
    remediation_text: string;
  };
}

export type ReviewStatusFilter = "pending" | "approved" | "rejected";

export interface ReviewPageRequest {
  limit?: number;
  offset?: number;
  review_type?: string;
  status?: ReviewStatusFilter;
}

export interface ReviewPageResponse {
  total: number;
  limit: number;
  offset: number;
  items: ReviewItem[];
}

export interface ReviewDecisionPayload {
  note?: string;
  source_approval?: {
    identity_verified: boolean;
    currentness_verified?: boolean;
    stable_identifier: string;
    identity_title?: string;
    as_of_date?: string;
    currentness_status: string;
    material_type: string;
    citation_data?: Record<string, unknown>;
    canonical_url?: string;
    licence_name?: string;
    licence_url?: string;
  };
}

export interface ReviewDecision {
  review_id: string;
  status: "approved" | "rejected";
}
