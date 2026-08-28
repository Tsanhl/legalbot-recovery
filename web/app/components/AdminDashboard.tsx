import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { api, formatApiError } from "../lib/api";
import type {
  AdminOverview,
  CoverageRecord,
  EvaluationIssueRecord,
  FailureLedgerRecord,
  IndexBuildSummary,
  KnowledgeGap,
  LiveEvaluationReleasedAnswer,
  LiveEvaluationRunDetail,
  LiveEvaluationRunList,
  MetricSeriesRow,
  ObservabilityAdminView,
  OwnerSensitiveNoteDetail,
  QualityReport,
  RefinementRecord,
  ResearchCandidateRecord,
  ResearchTaskRecord,
  ReviewItem,
  ReviewPageResponse,
  ReviewStatusFilter,
  SourceScanSummary,
  SourceUpdateRecord,
  SubjectReadinessView,
  SourceRecord,
} from "../lib/contracts";
import { Icons } from "./Icons";
import { LiveEvaluationPanel } from "./admin/LiveEvaluationPanel";
import { RuntimeRecordsPanel } from "./admin/RuntimeRecordsPanel";
import { MetricCard, Status, duration, number } from "./admin/widgets";

interface AdminState {
  overview: AdminOverview | null;
  sources: SourceRecord[];
  scans: SourceScanSummary[];
  builds: IndexBuildSummary[];
  coverage: CoverageRecord[];
  gaps: KnowledgeGap[];
  quality: QualityReport[];
  failures: FailureLedgerRecord[];
  evaluationIssues: EvaluationIssueRecord[];
  refinements: RefinementRecord[];
  researchTasks: ResearchTaskRecord[];
  researchCandidates: ResearchCandidateRecord[];
  sourceUpdates: SourceUpdateRecord[];
  subjectReadiness: SubjectReadinessView | null;
  observability: ObservabilityAdminView | null;
  liveEvaluations: LiveEvaluationRunList;
}

interface SubjectCoverage {
  subject: string;
  total: number;
  citable: number;
  primary: number;
  scholarship: number;
  exceptions: number;
  score: number;
  status: "ready" | "thin" | "blocked";
}

const EMPTY_ADMIN: AdminState = {
  overview: null,
  sources: [],
  scans: [],
  builds: [],
  coverage: [],
  gaps: [],
  quality: [],
  failures: [],
  evaluationIssues: [],
  refinements: [],
  researchTasks: [],
  researchCandidates: [],
  sourceUpdates: [],
  subjectReadiness: null,
  observability: null,
  liveEvaluations: { items: [], invalid_run_count: 0 },
};

const REVIEW_PAGE_LIMIT = 50;
const EMPTY_REVIEW_PAGE: ReviewPageResponse = {
  total: 0,
  limit: REVIEW_PAGE_LIMIT,
  offset: 0,
  items: [],
};

const REVIEW_TYPES = [
  ["", "All queues (advanced)"],
  ["source_version", "Source verification (system)"],
  ["online_source_version", "Online source snapshots"],
  ["assessment_rule", "Assessment standards (owner)"],
  ["upload_source_candidate", "Upload source-intake candidates"],
  ["knowledge_gap", "Knowledge gaps"],
  ["document_safety", "Document safety"],
] as const;

const RESEARCH_SUBJECT_OPTIONS = [
  ["general", "General legislation"],
  ["contract", "Contract"],
  ["consumer", "Consumer"],
  ["tort", "Tort and professional negligence"],
  ["criminal", "Criminal law"],
  ["evidence", "Evidence"],
  ["employment", "Employment and equality"],
  ["land_law", "Land law"],
  ["trusts", "Equity and trusts"],
  ["public law", "Public and administrative law"],
  ["constitutional law", "Constitutional law"],
  ["human rights", "Human rights"],
  ["company law", "Company and corporate governance"],
  ["family law", "Family law"],
  ["civil litigation", "Civil litigation"],
  ["intellectual property", "Intellectual property"],
  ["banking", "Banking, fraud and restitution"],
  ["competition", "Competition and digital markets"],
  ["medical law", "Medical law"],
  ["procurement", "Public procurement"],
  ["environmental law", "Environmental and climate law"],
  ["data protection", "Data protection and privacy"],
  ["legal ethics", "Legal ethics and AI"],
  ["insolvency", "Insolvency"],
  ["construction", "Construction and commercial law"],
] as const;

const INTERNAL_SOURCE_ID =
  /^(?:sha256|content-sha256|source-identity-sha256|local-representation-sha256|doi-sha256|neutral-citation-sha256):[0-9a-f]{64}$/;

export function internalSourceIdentifier(context: ReviewItem["source_context"]): string {
  const existing = context?.stable_identifier || "";
  if (INTERNAL_SOURCE_ID.test(existing)) return existing;
  return `content-sha256:${context?.content_sha256 || ""}`;
}

export function citableSourceIdentifier(context: ReviewItem["source_context"]): string {
  return (
    context?.public_identifier_candidate?.stable_identifier || context?.stable_identifier || ""
  );
}

export function sourceReadyForOwnerApproval(item: ReviewItem): boolean {
  // This approves only an encrypted upload's handoff into the ordinary source
  // intake queue. It never approves the upload as legal authority.
  if (item.review_type === "upload_source_candidate") return true;
  if (item.review_type !== "source_version" || !item.source_context) return true;
  const context = item.source_context;
  const internal = context.lane === "private_teaching" || context.lane === "assessment_guidance";
  if (!context.identity_verified) return false;
  if (internal) return true;
  // A source-wide flag cannot prove the later treatment of every proposition
  // in a historical judgment. Generic owner approval stays blocked until a
  // separate span+proposition-scoped review workflow exists.
  if (context.material_type === "case" && context.currentness_status === "historical") {
    return false;
  }
  return Boolean(
    context.currentness_verified
    && context.stable_identifier
    && context.material_type
    && Object.keys(context.citation_data).length,
  );
}

function percent(value: number | undefined): string {
  if (typeof value !== "number" || Number.isNaN(value)) return "—";
  return `${Math.round(value <= 1 ? value * 100 : value)}%`;
}

function ratio(numerator: number, denominator: number): number | undefined {
  return denominator > 0 ? numerator / denominator : undefined;
}

function metricValue(
  observability: ObservabilityAdminView | null,
  metric: string,
): number | undefined {
  const values = observability?.snapshots.flatMap(({ snapshot }) =>
    snapshot.gauges
      .filter((row) => row.metric === metric)
      .map((row) => row.value)
      .filter((value): value is number => typeof value === "number"),
  ) || [];
  return values.length ? Math.max(...values) : undefined;
}

interface LatencyRow extends MetricSeriesRow {
  component: string;
}

function latencyRows(observability: ObservabilityAdminView | null): LatencyRow[] {
  return (observability?.snapshots.flatMap(({ component, snapshot }) =>
    snapshot.histograms.map((row) => ({ ...row, component })),
  ) || []).sort((left, right) => {
    const stage = left.metric.localeCompare(right.metric);
    if (stage) return stage;
    return `${left.labels.route || ""}:${left.labels.word_band || ""}:${left.component}`
      .localeCompare(`${right.labels.route || ""}:${right.labels.word_band || ""}:${right.component}`);
  });
}

function sloState(observability: ObservabilityAdminView | null): {
  label: string;
  tone: "default" | "green" | "amber";
  note: string;
} {
  const evaluations = observability?.slo_evaluations.map((item) => item.evaluation) || [];
  if (!evaluations.length) {
    return { label: "Awaiting samples", tone: "default", note: "No process snapshot has been evaluated yet" };
  }
  if (evaluations.some((evaluation) => evaluation.checks.some((check) => check.passed === false))) {
    return { label: "Target breach", tone: "amber", note: "An internal observe-only target is outside its provisional range" };
  }
  if (evaluations.every((evaluation) => evaluation.evaluation_complete && evaluation.within_provisional_targets)) {
    return { label: "Within targets", tone: "green", note: "All reported checks are within provisional internal targets" };
  }
  return { label: "Collecting baseline", tone: "default", note: "Some checks lack enough samples for evaluation" };
}

function aggregateCoverage(rows: CoverageRecord[]): SubjectCoverage[] {
  const subjects = new Map<string, Omit<SubjectCoverage, "score" | "status">>();
  for (const row of rows) {
    const current = subjects.get(row.subject) || {
      subject: row.subject,
      total: 0,
      citable: 0,
      primary: 0,
      scholarship: 0,
      exceptions: 0,
    };
    current.total += row.count;
    if (row.status === "citable") current.citable += row.count;
    if (row.lane === "primary_authority") current.primary += row.count;
    if (row.lane === "scholarship") current.scholarship += row.count;
    if (["ocr_required", "encrypted", "quarantined", "unsupported"].includes(row.status)) current.exceptions += row.count;
    subjects.set(row.subject, current);
  }
  return [...subjects.values()].map((item) => {
    const score = item.total ? (item.citable / item.total) * 100 : 0;
    const status: SubjectCoverage["status"] = item.primary > 0 && score >= 80
      ? "ready"
      : item.primary > 0 || item.citable > 0
        ? "thin"
        : "blocked";
    return { ...item, score, status };
  }).sort((a, b) => a.subject.localeCompare(b.subject));
}

export function AdminDashboard() {
  const [data, setData] = useState<AdminState>(EMPTY_ADMIN);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [coverageQuery, setCoverageQuery] = useState("");
  const [activeSection, setActiveSection] = useState("overview");
  const [scanAction, setScanAction] = useState(false);
  const [reviewPage, setReviewPage] = useState<ReviewPageResponse>(EMPTY_REVIEW_PAGE);
  const [reviewOffset, setReviewOffset] = useState(0);
  const [reviewStatus, setReviewStatus] = useState<ReviewStatusFilter | "">("pending");
  const [reviewType, setReviewType] = useState("assessment_rule");
  const [reviewsLoading, setReviewsLoading] = useState(false);
  const [decidingReviewId, setDecidingReviewId] = useState("");
  const [selectedLiveRunId, setSelectedLiveRunId] = useState("");
  const [liveRunDetail, setLiveRunDetail] = useState<LiveEvaluationRunDetail | null>(null);
  const [liveRunLoading, setLiveRunLoading] = useState(false);
  const [releasedEvaluationAnswer, setReleasedEvaluationAnswer] = useState<LiveEvaluationReleasedAnswer | null>(null);
  const [researchTaskType, setResearchTaskType] = useState<"source_update_check" | "gap_research" | "broad_discovery">("broad_discovery");
  const [researchPriority, setResearchPriority] = useState<"high" | "medium" | "low">("medium");
  const [researchSubject, setResearchSubject] = useState("general");
  const [researchSourceId, setResearchSourceId] = useState("");
  const [researchAuthorityId, setResearchAuthorityId] = useState("");
  const [researchGapId, setResearchGapId] = useState("");
  const [researchSubmitting, setResearchSubmitting] = useState(false);
  const [researchActionStatus, setResearchActionStatus] = useState("");
  const [ownerNoteDetails, setOwnerNoteDetails] = useState<
    Record<string, OwnerSensitiveNoteDetail>
  >({});
  const reviewRequestSequence = useRef(0);
  const reviewAbortController = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const results = await Promise.allSettled([
      api.admin.overview(),
      api.admin.sources(),
      api.admin.sourceScans(),
      api.admin.indexBuilds(),
      api.admin.coverage(),
      api.admin.gaps(),
      api.admin.quality(),
      api.admin.failures(),
      api.admin.evaluationIssues(),
      api.admin.refinements(),
      api.admin.researchTasks(),
      api.admin.researchCandidates(),
      api.admin.sourceUpdates(),
      api.admin.subjectReadiness(),
      api.admin.observability(),
      api.admin.liveEvaluations(),
    ]);
    const failures = results.filter((item) => item.status === "rejected");
    setData({
      overview: results[0].status === "fulfilled" ? results[0].value : null,
      sources: results[1].status === "fulfilled" ? results[1].value : [],
      scans: results[2].status === "fulfilled" ? results[2].value : [],
      builds: results[3].status === "fulfilled" ? results[3].value : [],
      coverage: results[4].status === "fulfilled" ? results[4].value : [],
      gaps: results[5].status === "fulfilled" ? results[5].value : [],
      quality: results[6].status === "fulfilled" ? results[6].value : [],
      failures: results[7].status === "fulfilled" ? results[7].value : [],
      evaluationIssues: results[8].status === "fulfilled" ? results[8].value : [],
      refinements: results[9].status === "fulfilled" ? results[9].value : [],
      researchTasks: results[10].status === "fulfilled" ? results[10].value : [],
      researchCandidates: results[11].status === "fulfilled" ? results[11].value : [],
      sourceUpdates: results[12].status === "fulfilled" ? results[12].value : [],
      subjectReadiness: results[13].status === "fulfilled" ? results[13].value : null,
      observability: results[14].status === "fulfilled" ? results[14].value : null,
      liveEvaluations: results[15].status === "fulfilled"
        ? results[15].value
        : { items: [], invalid_run_count: 0 },
    });
    if (failures.length) {
      setError(`${failures.length} dashboard feed${failures.length === 1 ? " is" : "s are"} unavailable. ${formatApiError((failures[0] as PromiseRejectedResult).reason)}`);
    }
    setLoading(false);
  }, []);

  const loadObservability = useCallback(async () => {
    try {
      const observability = await api.admin.observability();
      setData((current) => ({ ...current, observability }));
    } catch {
      // The full refresh reports feed failures. Background polling stays quiet
      // so a transient telemetry read never hides the last safe snapshot.
    }
  }, []);

  const loadLiveRun = useCallback(async (runId: string) => {
    if (!runId) {
      setLiveRunDetail(null);
      setReleasedEvaluationAnswer(null);
      return;
    }
    setLiveRunLoading(true);
    setReleasedEvaluationAnswer(null);
    try {
      setLiveRunDetail(await api.admin.liveEvaluation(runId));
    } catch (reason) {
      setLiveRunDetail(null);
      setError(formatApiError(reason));
    } finally {
      setLiveRunLoading(false);
    }
  }, []);

  const loadReviews = useCallback(async () => {
    const requestId = ++reviewRequestSequence.current;
    reviewAbortController.current?.abort();
    const controller = new AbortController();
    reviewAbortController.current = controller;
    setReviewsLoading(true);
    try {
      const page = await api.admin.reviews(
        {
          limit: REVIEW_PAGE_LIMIT,
          offset: reviewOffset,
          ...(reviewType ? { review_type: reviewType } : {}),
          ...(reviewStatus ? { status: reviewStatus } : {}),
        },
        controller.signal,
      );
      if (requestId !== reviewRequestSequence.current) return;
      const lastOffset = page.total > 0
        ? Math.floor((page.total - 1) / page.limit) * page.limit
        : 0;
      if (page.offset > lastOffset) {
        setReviewOffset(lastOffset);
        return;
      }
      setReviewPage(page);
    } catch (reason) {
      if (controller.signal.aborted || requestId !== reviewRequestSequence.current) return;
      setError(formatApiError(reason));
    } finally {
      if (requestId === reviewRequestSequence.current) setReviewsLoading(false);
    }
  }, [reviewOffset, reviewStatus, reviewType]);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  useEffect(() => {
    const timer = window.setInterval(() => void loadObservability(), 5_000);
    return () => window.clearInterval(timer);
  }, [loadObservability]);

  const effectiveLiveRunId = data.liveEvaluations.items.some(
    (run) => run.run_id === selectedLiveRunId,
  )
    ? selectedLiveRunId
    : data.liveEvaluations.items[0]?.run_id || "";

  useEffect(() => {
    const timer = window.setTimeout(() => void loadLiveRun(effectiveLiveRunId), 0);
    return () => window.clearTimeout(timer);
  }, [effectiveLiveRunId, loadLiveRun]);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadReviews(), 0);
    return () => {
      window.clearTimeout(timer);
      reviewAbortController.current?.abort();
    };
  }, [loadReviews]);

  const subjectCoverage = useMemo(() => aggregateCoverage(data.coverage), [data.coverage]);
  const filteredCoverage = useMemo(() => {
    const query = coverageQuery.trim().toLocaleLowerCase();
    return query ? subjectCoverage.filter((item) => item.subject.toLocaleLowerCase().includes(query)) : subjectCoverage;
  }, [coverageQuery, subjectCoverage]);
  const activeBuild = data.builds.find((build) => build.status === "active") || data.builds[0];
  const activeScan = data.scans.find((scan) => scan.status === "queued" || scan.status === "running");
  const latestScan = data.scans[0];
  const statusCounts = data.overview?.source_statuses || {};
  const releases = data.overview?.releases || {};
  const releaseTotal = Object.values(releases).reduce((sum, count) => sum + count, 0);
  const verifiedReleases = (releases.verified_full || 0) + (releases.verified_concise || 0) + (releases.verified_limited || 0);
  const evidencePassed = data.quality.filter((item) => Boolean(item.evidence_passed)).length;
  const academicPassed = data.quality.filter((item) => item.academic_score >= 70).length;
  const rubricAverages = useMemo(() => {
    const values = new Map<string, number[]>();
    for (const report of data.quality) {
      for (const [label, value] of Object.entries(report.rubric_scores || {})) {
        values.set(label, [...(values.get(label) || []), value]);
      }
    }
    return [...values.entries()].map(([label, entries]) => ({
      label,
      value: entries.reduce((sum, value) => sum + value, 0) / entries.length,
      samples: entries.length,
    })).slice(0, 4);
  }, [data.quality]);
  const observabilityLatency = useMemo(
    () => latencyRows(data.observability),
    [data.observability],
  );
  const provisionalSlo = useMemo(
    () => sloState(data.observability),
    [data.observability],
  );
  const queueDepth = metricValue(data.observability, "queue_depth");
  const oldestJobAge = metricValue(data.observability, "oldest_job_age_seconds");
  const stuckJobs = data.observability?.active_jobs.filter((job) => job.progress_state === "stuck").length || 0;
  const sloChecks = data.observability?.slo_evaluations.flatMap(({ component, evaluation }) =>
    evaluation.checks.map((check) => ({ ...check, component })),
  ) || [];
  const evaluatedSloChecks = sloChecks.filter((check) => check.passed !== null && check.passed !== undefined);
  const passedSloChecks = evaluatedSloChecks.filter((check) => check.passed).length;
  const latestObservabilityAt = data.observability?.snapshots
    .map(({ snapshot }) => snapshot.generated_at)
    .sort()
    .at(-1);
  const selectedLiveRun = data.liveEvaluations.items.find(
    (run) => run.run_id === effectiveLiveRunId,
  );

  const openReleasedEvaluationAnswer = async (
    caseId: string,
    passNumber: number,
  ) => {
    if (!effectiveLiveRunId) return;
    setError("");
    try {
      setReleasedEvaluationAnswer(
        await api.admin.liveEvaluationAnswer(
          effectiveLiveRunId,
          caseId,
          passNumber,
        ),
      );
    } catch (reason) {
      setReleasedEvaluationAnswer(null);
      setError(formatApiError(reason));
    }
  };

  const decide = async (item: ReviewItem, decision: "approved" | "rejected") => {
    setDecidingReviewId(item.id);
    setError("");
    try {
      let payload = {};
      if (decision === "approved" && item.review_type === "source_version") {
        const context = item.source_context;
        const isInternal = context?.lane === "private_teaching" || context?.lane === "assessment_guidance";
        const template = isInternal
          ? {
              note: "Private source identity and material role checked. This approval does not make it legal authority.",
              source_approval: {
                identity_verified: true,
                currentness_verified: false,
                stable_identifier: internalSourceIdentifier(context),
                identity_title: context?.identity_title || context?.title || context?.display_name || "",
                currentness_status: "not_applicable",
                material_type: context?.material_type || (context?.lane === "assessment_guidance" ? "rubric" : "lecture"),
                citation_data: {},
              },
            }
          : {
              note: "Identity, citation and currentness checked against the reviewed source.",
              source_approval: {
                identity_verified: true,
                currentness_verified: true,
                stable_identifier: citableSourceIdentifier(context),
                as_of_date: context?.as_of_date || new Date().toISOString().slice(0, 10),
                currentness_status: context?.currentness_status === "unknown" ? "current" : context?.currentness_status || "current",
                material_type: context?.material_type || "",
                citation_data: context?.citation_data || {},
                ...(context?.canonical_url ? { canonical_url: context.canonical_url } : {}),
                ...(context?.licence_name ? { licence_name: context.licence_name } : {}),
                ...(context?.licence_url ? { licence_url: context.licence_url } : {}),
              },
            };
        const supplied = window.prompt(
          isInternal
            ? "Verify the privacy-safe identity, title and material type. Internal material remains non-authority and receives no OSCOLA citation."
            : "Verify and complete the source approval JSON. Approval is blocked until identity, material type, OSCOLA fields and currentness are valid.",
          JSON.stringify(template, null, 2),
        );
        if (supplied === null) return;
        try {
          payload = JSON.parse(supplied) as typeof template;
        } catch {
          setError("Source approval must be valid JSON.");
          return;
        }
      }
      await api.admin.decideReview(item.id, decision, payload);
      const overviewPromise = api.admin.overview();
      await loadReviews();
      const overview = await overviewPromise;
      setData((current) => ({ ...current, overview }));
    } catch (reason) {
      setError(formatApiError(reason));
    } finally {
      setDecidingReviewId("");
    }
  };

  const runSourceScan = async (resumeId?: string) => {
    setScanAction(true);
    setError("");
    try {
      if (resumeId) await api.admin.resumeSourceScan(resumeId);
      else await api.admin.scanSources();
      await load();
    } catch (reason) {
      setError(formatApiError(reason));
    } finally {
      setScanAction(false);
    }
  };

  const triageRefinement = async (item: RefinementRecord) => {
    setError("");
    try {
      await api.admin.transitionRefinement(item.id, {
        to_status: "triaged",
        event_type: "owner_triaged",
      });
      const refinements = await api.admin.refinements();
      setData((current) => ({ ...current, refinements }));
    } catch (reason) {
      setError(formatApiError(reason));
    }
  };

  const revealOwnerNote = async (
    kind: "refinement" | "issue",
    id: string,
  ) => {
    setError("");
    try {
      const detail = kind === "refinement"
        ? await api.admin.refinementDetail(id)
        : await api.admin.evaluationIssueDetail(id);
      setOwnerNoteDetails((current) => ({ ...current, [`${kind}:${id}`]: detail }));
    } catch (reason) {
      setError(formatApiError(reason));
    }
  };

  const submitResearchCheck = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setResearchSubmitting(true);
    setResearchActionStatus("");
    setError("");
    try {
      const result = await api.admin.checkResearchNow({
        task_type: researchTaskType,
        priority: researchPriority,
        subject: researchSubject.trim(),
        ...(researchSourceId.trim() ? { source_id: researchSourceId.trim() } : {}),
        ...(researchAuthorityId.trim() ? { authority_identity_id: researchAuthorityId.trim() } : {}),
        ...(researchGapId.trim() ? { knowledge_gap_id: researchGapId.trim() } : {}),
        idempotency_key: crypto.randomUUID(),
      });
      setResearchActionStatus(`Queued ${result.task_id}. It can stage review candidates only.`);
      const researchTasks = await api.admin.researchTasks();
      setData((current) => ({ ...current, researchTasks }));
    } catch (reason) {
      setError(formatApiError(reason));
    } finally {
      setResearchSubmitting(false);
    }
  };

  const refreshResearchReviewData = async () => {
    const [researchCandidates, sourceUpdates, reviews] = await Promise.all([
      api.admin.researchCandidates(),
      api.admin.sourceUpdates(),
      api.admin.reviews({ status: "pending", limit: REVIEW_PAGE_LIMIT, offset: 0 }),
    ]);
    setData((current) => ({ ...current, researchCandidates, sourceUpdates }));
    setReviewPage(reviews);
  };

  const systemVerifyResearchCandidate = async (item: ResearchCandidateRecord) => {
    setError("");
    try {
      const result = await api.admin.systemVerifyResearchCandidate(item.id);
      setResearchActionStatus(`System envelope verified: ${result.system_verification_sha256}`);
      await refreshResearchReviewData();
    } catch (reason) {
      setError(formatApiError(reason));
    }
  };

  const reviewResearchCandidate = async (item: ResearchCandidateRecord) => {
    const supplied = window.prompt(
      "Enter the qualified owner/expert candidate-review JSON. Acceptance creates only an ordinary pending source-intake review; it does not approve law, build an index or promote ACTIVE.",
      JSON.stringify({
        decision: "accept_for_source_intake",
        rights_state: "verified",
        identity_review_state: "candidate_matched",
        currentness_review_state: "requires_source_review",
        reviewer_ref: "reviewer:<64-lowercase-hex>",
        review_manifest_sha256: "<64-lowercase-hex>",
      }, null, 2),
    );
    if (supplied === null) return;
    try {
      const body = JSON.parse(supplied) as Parameters<typeof api.admin.reviewResearchCandidate>[1];
      const result = await api.admin.reviewResearchCandidate(item.id, body);
      setResearchActionStatus(result.source_intake_review_id
        ? `Candidate handed to ordinary source intake: ${result.source_intake_review_id}`
        : "Candidate rejected. No source or index state changed.");
      await refreshResearchReviewData();
    } catch (reason) {
      setError(formatApiError(reason));
    }
  };

  const reviewSourceUpdate = async (item: SourceUpdateRecord) => {
    const supplied = window.prompt(
      "Enter the qualified materiality review JSON. A reviewed material or unknown update blocks the affected authority/proposition until a new owner-promoted ACTIVE build is separately resolved.",
      JSON.stringify({
        materiality_status: "unknown",
        review_status: "approved",
        scope_kind: "authority",
        reviewer_ref: "reviewer:<64-lowercase-hex>",
        review_manifest_sha256: "<64-lowercase-hex>",
      }, null, 2),
    );
    if (supplied === null) return;
    try {
      const body = JSON.parse(supplied) as Parameters<typeof api.admin.reviewSourceUpdate>[1];
      await api.admin.reviewSourceUpdate(item.id, body);
      setResearchActionStatus(`Update ${item.id} received an explicit reviewed materiality decision.`);
      await refreshResearchReviewData();
    } catch (reason) {
      setError(formatApiError(reason));
    }
  };

  const resolveSourceUpdate = async (item: SourceUpdateRecord) => {
    const supplied = window.prompt(
      "After a new eligible candidate is owner-promoted, enter the exact resolution evidence JSON. The server verifies the newly promoted ACTIVE manifest.",
      JSON.stringify({
        evidence_sha256: "<64-lowercase-hex>",
        reviewer_ref: "reviewer:<64-lowercase-hex>",
      }, null, 2),
    );
    if (supplied === null) return;
    try {
      const body = JSON.parse(supplied) as Parameters<typeof api.admin.resolveSourceUpdate>[1];
      const result = await api.admin.resolveSourceUpdate(item.id, body);
      setResearchActionStatus(`Material update resolved by promoted ACTIVE: ${result.resolution_id}`);
      await refreshResearchReviewData();
    } catch (reason) {
      setError(formatApiError(reason));
    }
  };

  const navItems = [
    ["overview", "Overview", Icons.dashboard],
    ["observability", "Observability", Icons.activity],
    ["live-evaluation", "Live evaluation", Icons.file],
    ["runtime-records", "Runtime records", Icons.alert],
    ["sources", "Sources", Icons.book],
    ["coverage", "Coverage", Icons.target],
    ["quality", "Quality", Icons.shield],
    ["refinements", "Refinements", Icons.alert],
    ["research-updates", "Law updates", Icons.search],
    ["failures", "Failures", Icons.alert],
    ["reviews", "Reviews", Icons.file],
  ] as const;

  const refreshAll = () => {
    setError("");
    void Promise.all([load(), loadReviews()]);
  };

  const reviewStart = reviewPage.total > 0 ? reviewPage.offset + 1 : 0;
  const reviewEnd = Math.min(reviewPage.offset + reviewPage.items.length, reviewPage.total);
  const reviewPageNumber = Math.floor(reviewPage.offset / reviewPage.limit) + 1;
  const reviewPageCount = Math.max(1, Math.ceil(reviewPage.total / reviewPage.limit));
  const reviewBusy = reviewsLoading || Boolean(decidingReviewId);
  const researchRequestIncomplete = !researchSubject.trim()
    || (researchTaskType === "source_update_check"
      && (!researchSourceId.trim() || !researchAuthorityId.trim()))
    || (researchTaskType === "gap_research"
      && !researchGapId.trim() && !researchAuthorityId.trim());

  return (
    <div className="admin-shell">
      <aside className="admin-sidebar">
        <div className="brand-row">
          <span className="brand-mark"><Icons.mark size={23} /></span>
          <div><strong>Counsel</strong><span>Operations</span></div>
        </div>
        <nav aria-label="Operations sections">
          {navItems.map(([id, label, Icon]) => (
            <a className={activeSection === id ? "active" : ""} href={`#${id}`} key={id} onClick={() => setActiveSection(id)}>
              <Icon size={18} />{label}
            </a>
          ))}
        </nav>
        <div className="admin-sidebar-foot">
          <a href="/"><Icons.chat size={18} />Back to research</a>
          <p>Local owner console</p>
        </div>
      </aside>

      <main className="admin-main">
        <header className="admin-topbar">
          <div><span className="eyebrow">Clean-room system</span><h1>Operations</h1></div>
          <div className="admin-actions">
            <span className={`api-indicator ${error ? "warning" : ""}`}><i />{loading || reviewsLoading ? "Refreshing" : error ? "Partial data" : "All systems reporting"}</span>
            <button className="refresh-button" type="button" onClick={refreshAll} disabled={loading || reviewsLoading}>
              {loading || reviewsLoading ? <span className="mini-spinner" /> : "↻"} Refresh
            </button>
          </div>
        </header>

        {error && <div className="admin-alert" role="alert"><Icons.alert size={17} /><span>{error}</span><button type="button" onClick={() => setError("")}>Dismiss</button></div>}

        <div className="admin-content">
          <section className="admin-section" id="overview">
            <div className="section-heading">
              <div><span className="eyebrow">System overview</span><h2>Source and release health</h2></div>
              <p>Every count comes from the current FastAPI registry, never browser state.</p>
            </div>
            <div className="metric-grid">
              <MetricCard label="Accounted sources" value={number(data.overview?.sources_total)} note={`${number(statusCounts.citable)} citable source records`} />
              <MetricCard label="Primary authorities" value={number(data.coverage.filter((item) => item.lane === "primary_authority").reduce((sum, item) => sum + item.count, 0))} note="Cases, legislation and procedural rules" tone="green" />
              <MetricCard label="Open evidence gaps" value={number(data.overview?.open_gaps)} note={`${number(data.gaps.length)} gap records visible`} tone={(data.overview?.open_gaps || 0) > 0 ? "amber" : "default"} />
              <MetricCard label="Verified release rate" value={percent(ratio(verifiedReleases, releaseTotal))} note={`${number(releaseTotal)} recorded quality outcomes`} />
            </div>
          </section>

          <section className="admin-section" id="observability">
            <div className="section-heading">
              <div><span className="eyebrow">Metrics · logs · traces</span><h2>Live evaluation observability</h2></div>
              <p>
                Privacy-safe operational telemetry only. Timings are process-lifetime samples;
                trace IDs connect a slow job to its retained spans without exposing its question or answer.
              </p>
            </div>
            <div className="metric-grid">
              <MetricCard
                label="Provisional SLO"
                value={provisionalSlo.label}
                note={`${provisionalSlo.note} · ${passedSloChecks}/${evaluatedSloChecks.length} evaluated checks passed`}
                tone={provisionalSlo.tone}
              />
              <MetricCard
                label="Queue depth"
                value={number(queueDepth)}
                note="Answer jobs waiting in the local durable queue"
                tone={(queueDepth || 0) >= 4 ? "amber" : "default"}
              />
              <MetricCard
                label="Oldest queued job"
                value={duration(oldestJobAge)}
                note="Age of the oldest answer job still waiting"
                tone={(oldestJobAge || 0) >= 300 ? "amber" : "default"}
              />
              <MetricCard
                label="Active / stuck"
                value={`${number(data.observability?.active_jobs.length)} / ${number(stuckJobs)}`}
                note="Stuck means no progress beyond the route and word-band threshold"
                tone={stuckJobs > 0 ? "amber" : "green"}
              />
            </div>

            <div className="observability-notice" role="note">
              <Icons.activity size={18} />
              <div>
                <strong>Internal, provisional and observe-only</strong>
                <p>
                  {data.observability?.policy.policy_id || "No SLO policy reported"} is not an SLA or promotion gate.
                  Baseline calibrated: {data.observability?.policy.baseline_calibrated ? "yes" : "no"}.
                  Ordinary INFO traces retain 10%; WARN, ERROR and FATAL retain 100%. Validated live-evaluation-30 runs retain full traces.
                </p>
              </div>
              <small>{latestObservabilityAt ? `Updated ${new Date(latestObservabilityAt).toLocaleString()}` : "Awaiting snapshot"}</small>
            </div>

            <div className="observability-grid">
              <article className="admin-panel observability-panel">
                <div className="panel-heading">
                  <div><span className="eyebrow">Trace progress</span><h2>Active jobs</h2></div>
                  <span>{data.observability?.active_jobs.length || 0} jobs</span>
                </div>
                <div className="table-shell observability-table-shell">
                  <table>
                    <thead><tr><th>Trace</th><th>Route / word band</th><th>Stage</th><th>Progress</th><th>Last progress</th><th>State</th></tr></thead>
                    <tbody>
                      {data.observability?.active_jobs.map((job) => (
                        <tr key={job.job_id}>
                          <td>
                            <code>{job.trace_id}</code>
                            <small className="table-subline">{job.case_id || "non-suite"} · attempt {job.attempt} · {job.trace_retention}</small>
                          </td>
                          <td>
                            <strong>{job.route.replaceAll("_", " ")}</strong>
                            <small className="table-subline">{job.word_target.toLocaleString()} words · {job.word_band.replaceAll("_", " ")}</small>
                          </td>
                          <td><Status value={job.stage} /><small className="table-subline">{job.status.replaceAll("_", " ")}</small></td>
                          <td>
                            <div className="job-progress-meter" aria-label={`${Math.round(job.progress * 100)} percent complete`}>
                              <span><i style={{ width: `${Math.max(0, Math.min(100, job.progress * 100))}%` }} /></span>
                              <b>{Math.round(job.progress * 100)}%</b>
                            </div>
                          </td>
                          <td>{duration(job.progress_age_seconds)}<small className="table-subline">{new Date(job.last_progress_at).toLocaleTimeString()}</small></td>
                          <td><Status value={job.progress_state} /></td>
                        </tr>
                      ))}
                      {!data.observability?.active_jobs.length && <tr><td colSpan={6} className="empty-table">No active jobs. New jobs appear here with their route, stage and safe trace ID.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </article>

              <article className="admin-panel observability-panel">
                <div className="panel-heading">
                  <div><span className="eyebrow">Latency distribution</span><h2>Stage percentiles</h2></div>
                  <span>{observabilityLatency.length} series</span>
                </div>
                <div className="table-shell observability-table-shell">
                  <table>
                    <thead><tr><th>Stage</th><th>Component</th><th>Route / word band</th><th>Samples</th><th>P50</th><th>P95</th><th>P99</th></tr></thead>
                    <tbody>
                      {observabilityLatency.map((row) => (
                        <tr key={`${row.component}:${row.metric}:${row.labels.route || "none"}:${row.labels.word_band || "none"}`}>
                          <td><strong>{row.metric.replace(/_seconds$/, "").replaceAll("_", " ")}</strong></td>
                          <td>{row.component}</td>
                          <td>{row.labels.route?.replaceAll("_", " ") || "—"}<small className="table-subline">{row.labels.word_band?.replaceAll("_", " ") || "—"}</small></td>
                          <td>{number(row.sample_count ?? row.count)}</td>
                          <td>{duration(row.p50)}</td>
                          <td>{duration(row.p95)}</td>
                          <td>{duration(row.p99)}</td>
                        </tr>
                      ))}
                      {!observabilityLatency.length && <tr><td colSpan={7} className="empty-table">No stage latency samples yet. Retrieval, rerank, generation, verification, release and completion are measured separately.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </article>
            </div>
            <article className="admin-panel observability-panel">
              <div className="panel-heading"><div><span className="eyebrow">One authority store · derived view</span><h2>Subject readiness diagnostics</h2></div><span>{data.subjectReadiness?.subjects.length || 0} subjects</span></div>
              <p className="academic-advisory">Counts are keyed to ACTIVE and its source-manifest digest. They help locate thin areas but never prove that a legal answer is supportable.</p>
              <div className="table-shell"><table><thead><tr><th>Subject</th><th>Sources / chunks</th><th>Current-law qualified</th><th>Case review</th><th>Open gaps</th><th>Last update check</th></tr></thead><tbody>
                {data.subjectReadiness?.subjects.map((item) => <tr key={item.subject}><td><strong>{item.subject}</strong></td><td>{item.source_count} / {item.chunk_count}</td><td>{item.full_current_law_source_count} sources</td><td>{item.reviewed_case_span_count} spans · {item.later_treatment_verified_source_count}/{item.later_treatment_required_source_count} sources</td><td>{item.unresolved_gap_count}</td><td>{item.last_official_update_check ? new Date(item.last_official_update_check).toLocaleString() : "Never"}</td></tr>)}
                {!data.subjectReadiness?.subjects.length && <tr><td colSpan={6} className="empty-table">No ACTIVE build is available for a build-keyed subject view.</td></tr>}
              </tbody></table></div>
            </article>
          </section>

          <LiveEvaluationPanel
            liveEvaluations={data.liveEvaluations}
            selectedLiveRun={selectedLiveRun}
            effectiveLiveRunId={effectiveLiveRunId}
            liveRunDetail={liveRunDetail}
            liveRunLoading={liveRunLoading}
            releasedEvaluationAnswer={releasedEvaluationAnswer}
            onSelectRun={setSelectedLiveRunId}
            onOpenReleasedAnswer={(caseId, passNumber) => void openReleasedEvaluationAnswer(caseId, passNumber)}
            onCloseReleasedAnswer={() => setReleasedEvaluationAnswer(null)}
          />

          <RuntimeRecordsPanel />

          <section className="admin-section split-section" id="sources">
            <article className="admin-panel index-panel">
              <div className="panel-heading">
                <div><span className="eyebrow">Hybrid index</span><h2>Active build</h2></div>
                {activeBuild && <Status value={activeBuild.status} />}
              </div>
              {activeBuild ? (
                <>
                  <div className="build-id"><span>{activeBuild.id}</span><small>{new Date(activeBuild.created_at).toLocaleString()}</small></div>
                  <div className="build-stats">
                    <div><strong>{number(activeBuild.document_count)}</strong><span>documents</span></div>
                    <div><strong>{number(activeBuild.chunk_count)}</strong><span>evidence chunks</span></div>
                    <div><strong>{number(activeBuild.vector_count)}</strong><span>vectors</span></div>
                  </div>
                  <div className="index-lanes">
                    <span className={activeBuild.chunk_count > 0 ? "ready" : "blocked"}><Icons.check size={15} />Lexical data</span>
                    <span className={activeBuild.vector_count > 0 ? "ready" : "blocked"}><Icons.check size={15} />Vector data</span>
                    <span className={activeBuild.reranker_model ? "ready" : "blocked"}><Icons.check size={15} />{activeBuild.reranker_model || "No reranker"}</span>
                  </div>
                  <p className="build-model">Embeddings: {activeBuild.embedding_model}</p>
                </>
              ) : <div className="panel-empty">No index build has been reported.</div>}
            </article>

            <article className="admin-panel inventory-panel">
              <div className="panel-heading">
                <div><span className="eyebrow">Source registry</span><h2>Processing exceptions</h2></div>
                {latestScan && <Status value={latestScan.status} />}
              </div>
              <div className="exception-list">
                <div><span className="exception-icon ocr">OCR</span><p><strong>{number(statusCounts.ocr_required)}</strong><small>Scans need text recognition</small></p></div>
                <div><span className="exception-icon lock">ENC</span><p><strong>{number(statusCounts.encrypted)}</strong><small>Encrypted or restricted files</small></p></div>
                <div><span className="exception-icon quarantine">Q</span><p><strong>{number(statusCounts.quarantined)}</strong><small>Awaiting human classification</small></p></div>
                <div><span className="exception-icon duplicate">DUP</span><p><strong>{number(statusCounts.duplicate)}</strong><small>Recorded aliases, indexed once</small></p></div>
              </div>
              <small className="registry-note">Showing {data.sources.length.toLocaleString()} latest source records; totals come from the full registry.</small>
              <div className="source-scan-control">
                <div>
                  <strong>{activeScan ? `Scan ${activeScan.status}` : latestScan ? `Last scan ${latestScan.status}` : "No source scan yet"}</strong>
                  <small>
                    {activeScan
                      ? `${number(activeScan.files_accounted)} of ${number(activeScan.expected_file_count)} files accounted. A second scan is blocked.`
                      : latestScan?.error_message || (latestScan ? `${number(latestScan.files_accounted)} files accounted with a durable manifest.` : "Start the first clean-room source accounting pass.")}
                  </small>
                </div>
                {latestScan?.status === "failed" && !activeScan ? (
                  <button type="button" onClick={() => void runSourceScan(latestScan.id)} disabled={scanAction}>
                    {scanAction ? <span className="mini-spinner" /> : "Retry failed scan"}
                  </button>
                ) : (
                  <button type="button" onClick={() => void runSourceScan()} disabled={scanAction || Boolean(activeScan)}>
                    {scanAction ? <span className="mini-spinner" /> : activeScan ? "Scan in progress" : "Scan sources"}
                  </button>
                )}
              </div>
              {latestScan?.exclusion_diagnostics?.length ? (
                <div className="scan-diagnostic-list" aria-label="Source exclusion diagnostics">
                  {latestScan.exclusion_diagnostics.slice(0, 8).map((diagnostic) => (
                    <div className="scan-diagnostic" key={`${diagnostic.status}:${diagnostic.reason_code}`}>
                      <strong>{diagnostic.count.toLocaleString()} · {diagnostic.reason_code.replaceAll("_", " ")}</strong>
                      <span>{diagnostic.explanation}</span>
                      <small>{diagnostic.corrective_action}</small>
                    </div>
                  ))}
                </div>
              ) : null}
            </article>
          </section>

          <section className="admin-section">
            <div className="section-heading">
              <div><span className="eyebrow">Source inventory</span><h2>Latest registry records</h2></div>
              <p>Read-only inventory of the newest {data.sources.length.toLocaleString()} records. Privacy-safe source IDs are not tasks; “citable” means parsed, not automatically approved or current.</p>
            </div>
            <div className="table-shell">
              <table>
                <thead><tr><th>Source</th><th>Lane</th><th>Subject</th><th>Jurisdiction</th><th>Aliases</th><th>Status</th></tr></thead>
                <tbody>
                  {data.sources.slice(0, 10).map((source) => (
                    <tr key={source.id}>
                      <td><strong>{source.safe_display_name}</strong><small className="table-subline">{source.media_type}</small></td>
                      <td>{source.lane?.replaceAll("_", " ") || "Unclassified"}</td>
                      <td>{source.subject_primary || "Unclassified"}</td>
                      <td>{source.jurisdiction || "—"}</td>
                      <td>{number(source.alias_count)}</td>
                      <td><Status value={source.status} /></td>
                    </tr>
                  ))}
                  {!data.sources.length && <tr><td colSpan={6} className="empty-table">No source records reported.</td></tr>}
                </tbody>
              </table>
            </div>
          </section>

          <section className="admin-section">
            <div className="section-heading">
              <div><span className="eyebrow">Hybrid retrieval</span><h2>Index build history</h2></div>
              <p>Candidate and active builds remain distinct until promotion.</p>
            </div>
            <div className="table-shell">
              <table>
                <thead><tr><th>Build</th><th>Documents</th><th>Chunks</th><th>Vectors</th><th>Created</th><th>Status</th></tr></thead>
                <tbody>
                  {data.builds.slice(0, 8).map((build) => (
                    <tr key={build.id}>
                      <td><strong>{build.id}</strong><small className="table-subline">{build.embedding_model}</small></td>
                      <td>{number(build.document_count)}</td><td>{number(build.chunk_count)}</td><td>{number(build.vector_count)}</td>
                      <td>{new Date(build.created_at).toLocaleString()}</td><td><Status value={build.status} /></td>
                    </tr>
                  ))}
                  {!data.builds.length && <tr><td colSpan={6} className="empty-table">No index builds reported.</td></tr>}
                </tbody>
              </table>
            </div>
          </section>

          <section className="admin-section" id="coverage">
            <div className="section-heading inline-heading">
              <div><span className="eyebrow">Coverage ledger</span><h2>Subject readiness</h2></div>
              <label className="table-search"><Icons.search size={17} /><input value={coverageQuery} onChange={(event) => setCoverageQuery(event.target.value)} placeholder="Find a subject" /></label>
            </div>
            <div className="table-shell">
              <table>
                <thead><tr><th>Subject</th><th>Registry readiness</th><th>Primary</th><th>Scholarship</th><th>Exceptions</th><th>Status</th></tr></thead>
                <tbody>
                  {filteredCoverage.map((item) => (
                    <tr key={item.subject}>
                      <td><strong>{item.subject}</strong></td>
                      <td><div className="coverage-cell"><span><i style={{ width: `${Math.max(0, Math.min(100, item.score))}%` }} /></span><b>{Math.round(item.score)}%</b></div></td>
                      <td>{number(item.primary)}</td><td>{number(item.scholarship)}</td><td>{number(item.exceptions)}</td><td><Status value={item.status} /></td>
                    </tr>
                  ))}
                  {!filteredCoverage.length && <tr><td colSpan={6} className="empty-table">No subject coverage records reported.</td></tr>}
                </tbody>
              </table>
            </div>
          </section>

          <section className="admin-section split-section" id="quality">
            <article className="admin-panel quality-panel">
              <div className="panel-heading"><div><span className="eyebrow">Answer quality</span><h2>Gate outcomes</h2></div><small>{data.quality[0]?.created_at ? new Date(data.quality[0].created_at).toLocaleString() : "Awaiting report"}</small></div>
              <div className="quality-bars">
                {[
                  ["Evidence gate passed", ratio(evidencePassed, data.quality.length)],
                  ["Advisory 70+ structure target", ratio(academicPassed, data.quality.length)],
                  ["Full verified releases", ratio(releases.verified_full || 0, releaseTotal)],
                  ["Limited releases", ratio(releases.verified_limited || 0, releaseTotal)],
                ].map(([label, value]) => {
                  const numeric = typeof value === "number" ? value * 100 : 0;
                  return <div key={String(label)}><p><span>{label}</span><strong>{percent(value as number | undefined)}</strong></p><span><i style={{ width: `${numeric}%` }} /></span></div>;
                })}
              </div>
              <p className="academic-advisory">
                The automated academic score is advisory, has not been blind-calibrated, and is not a release gate or a guarantee of a 70+ mark. Evidence, citation, jurisdiction and privacy gates remain independent blockers.
              </p>
              <div className="mode-quality">
                {rubricAverages.map((item) => <div key={item.label}><span>{item.label.replaceAll("_", " ")}</span><strong>{item.value.toFixed(1)}</strong><small>{item.samples} reports</small></div>)}
                {!rubricAverages.length && <div><span>Rubric detail</span><strong>—</strong><small>No reports yet</small></div>}
              </div>
            </article>

            <article className="admin-panel gaps-panel">
              <div className="panel-heading"><div><span className="eyebrow">Knowledge gaps</span><h2>Recorded propositions</h2></div><span>{data.gaps.length} records</span></div>
              <div className="gap-list">
                {data.gaps.slice(0, 6).map((gap) => (
                  <div key={gap.id}>
                    <span className={`priority-dot ${gap.status === "open" ? "high" : "normal"}`} />
                    <p><strong>{gap.missing_proposition}</strong><small>{gap.subject || "Unclassified"} · {gap.jurisdiction}</small></p>
                    <Status value={gap.status} />
                  </div>
                ))}
                {!data.gaps.length && <div className="panel-empty">No knowledge gaps reported.</div>}
              </div>
            </article>
          </section>

          <section className="admin-section" id="refinements">
            <div className="section-heading"><div><span className="eyebrow">Debug · missing · answer feedback</span><h2>Unified refinement inbox</h2></div><p>Notes stay encrypted. Triage never changes sources, prompts, ACTIVE or model weights automatically.</p></div>
            <div className="gap-list">
              {data.refinements.slice(0, 100).map((item) => (
                <div key={item.id}>
                  <span className={`priority-dot ${item.priority >= 85 ? "high" : "normal"}`} />
                  <p>
                    <strong>{item.category.replaceAll("_", " ")} · {item.scope}</strong>
                    <small>Priority {item.priority} · {item.origin.replaceAll("_", " ")} · {item.occurrence_count} occurrence{item.occurrence_count === 1 ? "" : "s"}</small>
                    <small><code>{item.id}</code>{item.answer_id ? ` · answer ${item.answer_id}` : ""}</small>
                  </p>
                  <Status value={item.status} />
                  {item.note_sha256 && !ownerNoteDetails[`refinement:${item.id}`] && <button className="text-button" type="button" onClick={() => void revealOwnerNote("refinement", item.id)}>View encrypted note</button>}
                  {item.status === "open" && <button className="text-button" type="button" onClick={() => void triageRefinement(item)}>Mark triaged</button>}
                  {ownerNoteDetails[`refinement:${item.id}`] && <p className="owner-sensitive-detail"><strong>Owner-only note</strong><small>{ownerNoteDetails[`refinement:${item.id}`].note || "No note content."}</small><small>Audited read {ownerNoteDetails[`refinement:${item.id}`].access_ref}</small></p>}
                </div>
              ))}
              {!data.refinements.length && <div className="panel-empty">No refinement items recorded.</div>}
            </div>
          </section>

          <section className="admin-section" id="research-updates">
            <div className="section-heading"><div><span className="eyebrow">Allowlisted official sources</span><h2>Law update control plane</h2></div><p>Discovery and changed bytes create review candidates only. They never establish legal materiality, approve a source or promote ACTIVE.</p></div>
            <form className="research-check-form" onSubmit={(event) => void submitResearchCheck(event)}>
              <label><span>Check type</span><select value={researchTaskType} onChange={(event) => setResearchTaskType(event.target.value as typeof researchTaskType)}><option value="broad_discovery">Broad allowlisted discovery</option><option value="source_update_check">Known-source update</option><option value="gap_research">Knowledge-gap research</option></select></label>
              <label><span>Subject family</span><select required value={researchSubject} onChange={(event) => setResearchSubject(event.target.value)}>{RESEARCH_SUBJECT_OPTIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
              <label><span>Priority</span><select value={researchPriority} onChange={(event) => setResearchPriority(event.target.value as typeof researchPriority)}><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
              <label><span>Registered source</span><select disabled={researchTaskType !== "source_update_check"} required={researchTaskType === "source_update_check"} value={researchTaskType === "source_update_check" ? researchSourceId : "legislation_gov_uk"} onChange={(event) => setResearchSourceId(event.target.value)}><option value="">Select a registered source</option><option value="legislation_gov_uk">Legislation.gov.uk</option><option value="find_case_law">Find Case Law metadata</option><option value="uk_supreme_court">UK Supreme Court</option><option value="judiciary">Judiciary</option><option value="gov_uk">GOV.UK</option></select></label>
              <label><span>Stable authority identity</span><input maxLength={500} placeholder="Required for a known-source update" required={researchTaskType === "source_update_check"} value={researchAuthorityId} onChange={(event) => setResearchAuthorityId(event.target.value)} /></label>
              {researchTaskType === "gap_research" && <label><span>Knowledge-gap ID</span><input maxLength={255} placeholder="Gap ID or authority identity required" value={researchGapId} onChange={(event) => setResearchGapId(event.target.value)} /></label>}
              <button disabled={researchSubmitting || researchRequestIncomplete} type="submit">{researchSubmitting ? "Queuing…" : "Check now"}</button>
              <p role="status">{researchActionStatus || "No URL or raw user question is sent. The worker uses only reviewed source adapters and public identities."}</p>
            </form>
            <div className="metric-grid">
              <MetricCard label="Research tasks" value={number(data.researchTasks.length)} note={`${data.researchTasks.filter((item) => ["queued", "running", "retry_wait"].includes(item.status)).length} active-capacity tasks`} />
              <MetricCard label="Candidates" value={number(data.researchCandidates.length)} note="Rights and identity remain separately reviewed" />
              <MetricCard label="Update observations" value={number(data.sourceUpdates.length)} note={`${data.sourceUpdates.filter((item) => item.stale_active).length} stale ACTIVE comparisons`} />
              <MetricCard label="Connected scheduling" value="Disabled" note="Enabled only after the separate connected-crawler canary" />
            </div>
            <div className="observability-grid">
              <article className="admin-panel observability-panel">
                <div className="panel-heading"><div><span className="eyebrow">Priority queue</span><h2>Research tasks</h2></div><span>{data.researchTasks.length} tasks</span></div>
                <div className="table-shell"><table><thead><tr><th>Task</th><th>Subject / source</th><th>Priority</th><th>Status</th></tr></thead><tbody>
                  {data.researchTasks.slice(0, 50).map((item) => <tr key={item.id}><td><strong>{item.task_type.replaceAll("_", " ")}</strong><small className="table-subline"><code>{item.id}</code></small></td><td>{item.subject}<small className="table-subline">{item.source_id || "registered family"}</small></td><td>{item.priority_band} · {item.attempt_count}/{item.max_attempts}</td><td><Status value={item.status} /></td></tr>)}
                  {!data.researchTasks.length && <tr><td colSpan={4} className="empty-table">No crawler task has been admitted.</td></tr>}
                </tbody></table></div>
              </article>
              <article className="admin-panel observability-panel">
                <div className="panel-heading"><div><span className="eyebrow">Pinned ACTIVE comparison</span><h2>Source updates</h2></div><span>{data.sourceUpdates.length} observations</span></div>
                <div className="table-shell"><table><thead><tr><th>Authority</th><th>Source</th><th>State</th><th>ACTIVE</th><th>Owner action</th></tr></thead><tbody>
                  {data.sourceUpdates.slice(0, 50).map((item) => <tr key={item.id}><td><code>{item.authority_identity_id}</code><small className="table-subline">{item.scope_kind}{item.legal_locator ? ` · ${item.legal_locator}` : ""}</small></td><td>{item.source_id}</td><td><Status value={item.comparison_state} /><small className="table-subline">{item.materiality_status} · {item.review_status}</small></td><td>{item.stale_active ? "stale — recompare" : item.observed_active_build_id || "no ACTIVE"}</td><td>{!item.stale_active && item.review_status === "pending" && item.comparison_state !== "unchanged" && <button className="text-button" type="button" onClick={() => void reviewSourceUpdate(item)}>Review update</button>}{!item.stale_active && item.review_status === "approved" && item.materiality_status === "material" && <button className="text-button" type="button" onClick={() => void resolveSourceUpdate(item)}>Bind new ACTIVE resolution</button>}</td></tr>)}
                  {!data.sourceUpdates.length && <tr><td colSpan={5} className="empty-table">No official-source comparison has run.</td></tr>}
                </tbody></table></div>
              </article>
              <article className="admin-panel observability-panel">
                <div className="panel-heading"><div><span className="eyebrow">Quarantined official material</span><h2>Research candidates</h2></div><span>{data.researchCandidates.length} candidates</span></div>
                <div className="table-shell"><table><thead><tr><th>Candidate</th><th>Source / identity</th><th>Rights / state</th><th>Owner action</th></tr></thead><tbody>
                  {data.researchCandidates.slice(0, 50).map((item) => <tr key={item.id}><td><code>{item.id}</code><small className="table-subline">{item.content_sha256 || "metadata only"}</small></td><td>{item.source_id}<small className="table-subline"><code>{item.source_identity}</code></small></td><td><Status value={item.status} /><small className="table-subline">{item.rights_state} · {item.identity_review_state}</small></td><td>{["detected", "fetched", "quarantined"].includes(item.status) && <button className="text-button" type="button" onClick={() => void systemVerifyResearchCandidate(item)}>Verify envelope</button>}{item.status === "system_verified" && <button className="text-button" type="button" onClick={() => void reviewResearchCandidate(item)}>Owner review</button>}{item.intake_review_id && <small className="table-subline">Pending ordinary source intake: <code>{item.intake_review_id}</code></small>}</td></tr>)}
                  {!data.researchCandidates.length && <tr><td colSpan={4} className="empty-table">No quarantined or metadata-only candidates.</td></tr>}
                </tbody></table></div>
              </article>
            </div>
          </section>

          <section className="admin-section split-section" id="failures">
            <article className="admin-panel gaps-panel">
              <div className="panel-heading"><div><span className="eyebrow">Operational failures</span><h2>Failure ledger</h2></div><span>{data.failures.length} records</span></div>
              <div className="gap-list">
                {data.failures.slice(0, 20).map((failure) => (
                  <div key={failure.failure_id}>
                    <span className={`priority-dot ${failure.blocking ? "high" : "normal"}`} />
                    <p>
                      <strong>{failure.failure_code || "unclassified_failure"}</strong>
                      <small>{failure.component} · {failure.stage || "unknown stage"} · {failure.occurrence_count} occurrence{failure.occurrence_count === 1 ? "" : "s"}</small>
                      <small>{failure.user_or_owner_safe}</small>
                    </p>
                    <Status value={failure.state} />
                  </div>
                ))}
                {!data.failures.length && <div className="panel-empty">No operational failures recorded.</div>}
              </div>
            </article>

            <article className="admin-panel gaps-panel">
              <div className="panel-heading"><div><span className="eyebrow">Evaluation defects</span><h2>Quality issues</h2></div><span>{data.evaluationIssues.length} records</span></div>
              <div className="gap-list">
                {data.evaluationIssues.slice(0, 20).map((issue) => (
                  <div key={issue.id}>
                    <span className={`priority-dot ${["critical", "high"].includes(issue.severity) ? "high" : "normal"}`} />
                    <p>
                      <strong>{issue.category.replaceAll("_", " ")}</strong>
                      <small>{issue.affected_layer} · {issue.severity}{issue.case_id ? ` · ${issue.case_id}` : ""}</small>
                      {(issue.root_cause || issue.corrective_action) && <small>{issue.root_cause || issue.corrective_action}</small>}
                    </p>
                    <Status value={issue.status} />
                    {issue.has_note && !ownerNoteDetails[`issue:${issue.id}`] && <button className="text-button" type="button" onClick={() => void revealOwnerNote("issue", issue.id)}>View encrypted note</button>}
                    {ownerNoteDetails[`issue:${issue.id}`] && <p className="owner-sensitive-detail"><strong>Owner-only note</strong><small>{ownerNoteDetails[`issue:${issue.id}`].note || "No note content."}</small><small>Audited read {ownerNoteDetails[`issue:${issue.id}`].access_ref}</small></p>}
                  </div>
                ))}
                {!data.evaluationIssues.length && <div className="panel-empty">No evaluation issues recorded.</div>}
              </div>
            </article>
          </section>

          <section className="admin-section" id="reviews">
            <div className="section-heading"><div><span className="eyebrow">Human decisions</span><h2>Review queue</h2></div><p>Source and assessment decisions are separate from sealed Live60 expert gold. An upload submission is only an encrypted source-intake candidate; it cannot be approved as law from this screen.</p></div>
            <div className="review-toolbar">
              <div className="review-filters" aria-label="Review filters">
                <label className="review-filter">
                  <span>Status</span>
                  <select
                    aria-label="Review status"
                    disabled={reviewBusy}
                    value={reviewStatus}
                    onChange={(event) => {
                      setReviewOffset(0);
                      setReviewStatus(event.target.value as ReviewStatusFilter | "");
                    }}
                  >
                    <option value="pending">Pending</option>
                    <option value="approved">Approved</option>
                    <option value="rejected">Rejected</option>
                    <option value="">All statuses</option>
                  </select>
                </label>
                <label className="review-filter">
                  <span>Type</span>
                  <select
                    aria-label="Review type"
                    disabled={reviewBusy}
                    value={reviewType}
                    onChange={(event) => {
                      setReviewOffset(0);
                      setReviewType(event.target.value);
                    }}
                  >
                    {REVIEW_TYPES.map(([value, label]) => <option key={label} value={value}>{label}</option>)}
                  </select>
                </label>
              </div>
              <div className="review-pagination" aria-label="Review pages">
                <button
                  type="button"
                  disabled={reviewBusy || reviewPage.offset === 0}
                  onClick={() => setReviewOffset(Math.max(0, reviewPage.offset - reviewPage.limit))}
                >
                  Previous
                </button>
                <span>Page {reviewPageNumber} of {reviewPageCount}</span>
                <button
                  type="button"
                  disabled={reviewBusy || reviewPage.offset + reviewPage.limit >= reviewPage.total}
                  onClick={() => setReviewOffset(reviewPage.offset + reviewPage.limit)}
                >
                  Next
                </button>
              </div>
            </div>
            <p className="review-page-status" aria-live="polite">
              {reviewsLoading
                ? `Refreshing reviews ${reviewStart}–${reviewEnd}…`
                : `Showing ${reviewStart}–${reviewEnd} of ${reviewPage.total.toLocaleString()} matching reviews`}
            </p>
            <div className="review-list" aria-busy={reviewsLoading}>
              {reviewPage.items.map((item) => {
                const sourceNeedsVerification = !sourceReadyForOwnerApproval(item);
                const uploadIntake = item.review_type === "upload_source_candidate";
                return <article key={item.id}>
                  <div className={`review-kind ${item.review_type}`}><Icons.file size={18} /></div>
                  <div className="review-copy">
                    <span>{item.review_type.replaceAll("_", " ")} · {new Date(item.created_at).toLocaleDateString()}</span>
                    <h3>{item.source_context?.title || item.source_context?.display_name || item.target_id}</h3>
                    <p>{item.reason || "Human approval is required before this target can be promoted."}</p>
                    {item.source_context && <p><strong>{item.source_context.lane.replaceAll("_", " ")} · {item.source_context.subject || "unclassified"}</strong><br />{item.source_context.preview || "No text preview available."}</p>}
                    {item.rule_context && <p><strong>{item.rule_context.grade_band} · {item.rule_context.criterion}</strong><br />{item.rule_context.rule_text}</p>}
                    {uploadIntake && <p className="review-verification-note">Acceptance sends this encrypted content hash to normal source intake only. Identity, rights, jurisdiction, currentness and citation still require separate review.</p>}
                    {sourceNeedsVerification && <p className="review-verification-note">System verification is incomplete. This is not ready for owner approval.</p>}
                  </div>
                  <div className="review-actions">
                    <Status value={item.status} />
                    {item.status === "pending" && (
                      <>
                        <button className="reject" disabled={reviewBusy} type="button" onClick={() => void decide(item, "rejected")}>Reject</button>
                        <button className="approve" disabled={reviewBusy || sourceNeedsVerification} type="button" onClick={() => void decide(item, "approved")}>
                          {decidingReviewId === item.id ? <span className="mini-spinner" /> : <Icons.check size={15} />}
                          {decidingReviewId === item.id ? "Saving…" : sourceNeedsVerification ? "Needs verification" : uploadIntake ? "Accept for source review" : "Approve"}
                        </button>
                      </>
                    )}
                  </div>
                </article>;
              })}
              {!reviewPage.items.length && !reviewsLoading && (
                <div className="review-empty">
                  <Icons.check size={24} />
                  <strong>{reviewStatus === "pending" && reviewType === "assessment_rule"
                    ? "Owner review complete"
                    : reviewStatus === "pending" && !reviewType
                      ? "Review queue clear"
                      : "No matching reviews"}</strong>
                  <p>{reviewStatus === "pending" && reviewType === "assessment_rule"
                    ? "No canonical assessment standards are waiting for your decision."
                    : reviewStatus === "pending" && !reviewType
                      ? "No actionable source or rule decisions are waiting."
                      : "Change the status or type filter to inspect another part of the registry."}</p>
                </div>
              )}
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}
