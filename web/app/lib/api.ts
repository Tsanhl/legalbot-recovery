import type {
  AdminOverview,
  AnswerFeedbackRequest,
  AnswerFeedbackResult,
  AnswerEvidence,
  AnswerRecord,
  AttachmentRecord,
  ConversationSummary,
  CoverageRecord,
  EvaluationIssueRecord,
  FailureLedgerRecord,
  HealthRecord,
  IndexBuildSummary,
  JobRecord,
  KnowledgeGap,
  LiveEvaluationReleasedAnswer,
  LiveEvaluationRunDetail,
  LiveEvaluationRunList,
  ObservabilityAdminView,
  OwnerSensitiveNoteDetail,
  QualityReport,
  QuestionAccepted,
  QuestionRequest,
  RefinementRecord,
  ResearchCandidateRecord,
  ResearchCheckNowRequest,
  ResearchCheckNowResult,
  ResearchTaskRecord,
  ReviewDecision,
  ReviewDecisionPayload,
  ReviewPageRequest,
  ReviewPageResponse,
  RuntimeRecordsStatus,
  SourceScanSummary,
  SubjectReadinessView,
  SourceUpdateRecord,
  SourceRecord,
} from "./contracts";

const configuredBase = import.meta.env.VITE_LEGAL_API_BASE?.replace(/\/$/, "");
export const API_BASE = configuredBase || "/api/v1";

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(message: string, status: number, code = "api_error") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

function endpoint(path: string): string {
  return `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(endpoint(path), {
    ...init,
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...init?.headers,
    },
  });
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    const record = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
    throw new ApiError(
      String(record.message || record.detail || `Request failed (${response.status})`),
      response.status,
      String(record.code || "api_error"),
    );
  }
  return body as T;
}

async function items<T>(path: string): Promise<T[]> {
  const result = await request<{ items: T[] }>(path);
  return result.items;
}

export function eventUrl(jobId: string, supplied?: string): string {
  if (supplied?.startsWith("http://") || supplied?.startsWith("https://")) return supplied;
  if (supplied?.startsWith("/api/v1/")) {
    if (configuredBase) return `${configuredBase}${supplied.slice("/api/v1".length)}`;
    return supplied;
  }
  return endpoint(supplied || `/jobs/${encodeURIComponent(jobId)}/events`);
}

export function jobWebSocketUrl(jobId: string, supplied?: string, after = 0): string {
  const events = eventUrl(jobId, supplied);
  const url = new URL(events, window.location.href);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  if (!url.pathname.endsWith("/ws")) url.pathname = `${url.pathname.replace(/\/$/, "")}/ws`;
  url.searchParams.set("after", String(Math.max(0, Math.trunc(after))));
  return url.toString();
}

export const api = {
  health: () => request<HealthRecord>("/health"),
  conversations: () => items<ConversationSummary>("/conversations"),
  createAnswer: (body: QuestionRequest, idempotencyKey: string) =>
    request<QuestionAccepted>("/questions", {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "X-Idempotency-Key": idempotencyKey },
    }),
  answer: (id: string) => request<AnswerRecord>(`/answers/${encodeURIComponent(id)}`),
  job: (id: string) => request<JobRecord>(`/jobs/${encodeURIComponent(id)}`),
  cancelJob: (id: string) =>
    request<{ job_id: string; cancel_requested: boolean }>(
      `/jobs/${encodeURIComponent(id)}/cancel`,
      { method: "POST" },
    ),
  jobEventsUrl: (id: string, supplied?: string) => eventUrl(id, supplied),
  jobEventsWebSocketUrl: (id: string, supplied?: string, after = 0) =>
    jobWebSocketUrl(id, supplied, after),
  evidence: (answerId: string) =>
    request<AnswerEvidence>(`/answers/${encodeURIComponent(answerId)}/evidence`),
  feedback: (answerId: string, body: AnswerFeedbackRequest) =>
    request<AnswerFeedbackResult>(`/answers/${encodeURIComponent(answerId)}/feedback`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  reportIssue: (
    answerId: string,
    body: {
      category: string;
      severity: "low" | "medium" | "high" | "critical";
      affected_layer: string;
      expected_ids: string[];
      observed_ids: string[];
      note?: string;
    },
  ) => request<{ issue_id: string; status: string }>(
    `/answers/${encodeURIComponent(answerId)}/issues`,
    { method: "POST", body: JSON.stringify(body) },
  ),
  upload: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<AttachmentRecord>("/uploads", { method: "POST", body: form });
  },
  admin: {
    overview: () => request<AdminOverview>("/admin/overview"),
    observability: () => request<ObservabilityAdminView>("/admin/observability"),
    sources: () => items<SourceRecord>("/admin/sources"),
    sourceScans: () => items<SourceScanSummary>("/admin/source-scans"),
    scanSources: () =>
      request<{ scan_id: string; status: "queued" }>("/admin/sources/scan", {
        method: "POST",
      }),
    resumeSourceScan: (id: string) =>
      request<{ scan_id: string; status: "queued"; resumed_from_scan_id: string }>(
        `/admin/source-scans/${encodeURIComponent(id)}/resume`,
        { method: "POST" },
      ),
    indexBuilds: () => items<IndexBuildSummary>("/admin/index-builds"),
    coverage: () => items<CoverageRecord>("/admin/coverage"),
    gaps: () => items<KnowledgeGap>("/admin/gaps"),
    quality: () => items<QualityReport>("/admin/quality"),
    failures: () => items<FailureLedgerRecord>("/admin/failures"),
    evaluationIssues: () => items<EvaluationIssueRecord>("/admin/evaluation-issues"),
    evaluationIssueDetail: (id: string) =>
      request<OwnerSensitiveNoteDetail>(
        `/admin/evaluation-issues/${encodeURIComponent(id)}/detail`,
      ),
    refinements: () => items<RefinementRecord>("/admin/refinements"),
    refinementDetail: (id: string) =>
      request<OwnerSensitiveNoteDetail>(
        `/admin/refinements/${encodeURIComponent(id)}/detail`,
      ),
    researchTasks: () => items<ResearchTaskRecord>("/admin/research/tasks"),
    researchCandidates: () => items<ResearchCandidateRecord>("/admin/research/candidates"),
    systemVerifyResearchCandidate: (id: string) =>
      request<{ candidate_id: string; system_verification_sha256: string }>(
        `/admin/research/candidates/${encodeURIComponent(id)}/system-verify`,
        { method: "POST" },
      ),
    reviewResearchCandidate: (
      id: string,
      body: {
        decision: "accept_for_source_intake" | "reject";
        rights_state: "verified" | "metadata_only" | "licensed" | "rejected";
        identity_review_state: "candidate_matched" | "ambiguous" | "rejected";
        currentness_review_state: "requires_source_review" | "metadata_only" | "not_applicable" | "rejected";
        reviewer_ref: string;
        review_manifest_sha256: string;
      },
    ) => request<{ candidate_id: string; decision: string; source_intake_review_id: string | null }>(
      `/admin/research/candidates/${encodeURIComponent(id)}/review`,
      { method: "POST", body: JSON.stringify(body) },
    ),
    sourceUpdates: () => items<SourceUpdateRecord>("/admin/source-updates"),
    reviewSourceUpdate: (
      id: string,
      body: {
        materiality_status: "non_material" | "material" | "unknown";
        review_status: "approved" | "rejected" | "not_required";
        scope_kind: "authority" | "proposition";
        legal_locator?: string;
        proposition_sha256?: string;
        reviewer_ref: string;
        review_manifest_sha256: string;
      },
    ) => request<{ observation_id: string; review_id: string; materiality_status: string }>(
      `/admin/source-updates/${encodeURIComponent(id)}/review`,
      { method: "POST", body: JSON.stringify(body) },
    ),
    resolveSourceUpdate: (
      id: string,
      body: { evidence_sha256: string; reviewer_ref: string },
    ) => request<{ observation_id: string; resolution_id: string }>(
      `/admin/source-updates/${encodeURIComponent(id)}/resolve`,
      { method: "POST", body: JSON.stringify(body) },
    ),
    checkResearchNow: (body: ResearchCheckNowRequest) =>
      request<ResearchCheckNowResult>("/admin/research/check-now", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    subjectReadiness: () => request<SubjectReadinessView>("/admin/subject-readiness"),
    transitionRefinement: (
      id: string,
      body: {
        to_status: string;
        event_type: string;
        root_cause?: string;
        repair_version?: string;
        regression_case_id?: string;
        note?: string;
      },
    ) => request<{ id: string; status: string; updated_at: string }>(
      `/admin/refinements/${encodeURIComponent(id)}/transition`,
      { method: "POST", body: JSON.stringify(body) },
    ),
    liveEvaluations: () => request<LiveEvaluationRunList>("/admin/live-evaluations"),
    liveEvaluation: (runId: string) =>
      request<LiveEvaluationRunDetail>(
        `/admin/live-evaluations/${encodeURIComponent(runId)}`,
      ),
    liveEvaluationAnswer: (runId: string, caseId: string, passNumber: number) =>
      request<LiveEvaluationReleasedAnswer>(
        `/admin/live-evaluations/${encodeURIComponent(runId)}/cases/${encodeURIComponent(caseId)}/passes/${encodeURIComponent(String(passNumber))}/answer`,
      ),
    runtimeRecords: () => request<RuntimeRecordsStatus>("/admin/runtime-records"),
    reviews: (page: ReviewPageRequest = {}, signal?: AbortSignal) => {
      const query = new URLSearchParams();
      if (page.limit !== undefined) query.set("limit", String(page.limit));
      if (page.offset !== undefined) query.set("offset", String(page.offset));
      if (page.review_type) query.set("review_type", page.review_type);
      if (page.status) query.set("status", page.status);
      const suffix = query.size ? `?${query.toString()}` : "";
      return request<ReviewPageResponse>(`/admin/reviews${suffix}`, { signal });
    },
    decideReview: (
      id: string,
      decision: "approved" | "rejected",
      payload: ReviewDecisionPayload = {},
    ) =>
      request<ReviewDecision>(`/admin/reviews/${encodeURIComponent(id)}/${decision}`, {
        method: "POST",
        body: JSON.stringify(payload),
      }),
  },
};

export function formatApiError(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "The service could not be reached.";
}
