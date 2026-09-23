import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { api, formatApiError } from "../lib/api";
import type {
  AnswerRecord,
  AnswerFeedbackCategory,
  AnswerFeedbackRating,
  AttachmentRecord,
  ConversationSummary,
  HealthRecord,
  JobDoneEvent,
  JobEventEnvelope,
  JobProgressEvent,
  JobRecord,
  JobStage,
  Jurisdiction,
  OnlineMode,
  TaskMode,
} from "../lib/contracts";
import { AnswerMarkdown, type CitationToken } from "./AnswerMarkdown";
import { EvidenceDrawer, type EvidenceSelection } from "./EvidenceDrawer";
import { Icons } from "./Icons";

const TASKS: Array<{ value: TaskMode; label: string; description: string }> = [
  { value: "auto", label: "Auto", description: "Detect the right legal answer structure" },
  { value: "essay", label: "Essay", description: "Critical argument and scholarship" },
  { value: "problem", label: "Problem", description: "Issues, rules, application and outcome" },
  { value: "general", label: "General", description: "Clear, authoritative explanation" },
];

const JURISDICTIONS: Array<{ value: Jurisdiction; label: string }> = [
  { value: "England and Wales", label: "England & Wales" },
  { value: "England", label: "England" },
  { value: "Wales", label: "Wales" },
  { value: "Scotland", label: "Scotland" },
  { value: "Northern Ireland", label: "Northern Ireland" },
  { value: "Hong Kong", label: "Hong Kong" },
  { value: "European Union", label: "European Union" },
  { value: "United States", label: "United States" },
  { value: "US federal", label: "United States — federal" },
  { value: "California", label: "United States — California" },
  { value: "New York", label: "United States — New York" },
  { value: "Texas", label: "United States — Texas" },
  { value: "Other", label: "Other / specify in question" },
];

const STAGE_LABELS: Record<JobStage, string> = {
  queued: "Queued",
  researching: "Researching sources",
  qualifying_evidence: "Qualifying evidence",
  drafting: "Drafting answer",
  verifying: "Verifying every claim",
  repairing: "Repairing weak sections",
  assembling: "Assembling verified sections",
  complete: "Verified answer ready",
  limited: "Verified limited answer ready",
  held_for_review: "Held for human review",
  system_error: "Research could not be completed",
  cancelled: "Research cancelled",
};

const PROGRESS_STAGES: JobStage[] = [
  "researching",
  "qualifying_evidence",
  "drafting",
  "verifying",
  "repairing",
  "assembling",
];

const STARTERS = [
  {
    mode: "essay" as TaskMode,
    icon: Icons.book,
    title: "Build a critical essay",
    copy: "Develop a defensible thesis with primary authority and current scholarship.",
  },
  {
    mode: "problem" as TaskMode,
    icon: Icons.target,
    title: "Analyse a problem question",
    copy: "Work through each issue, apply the facts and rank likely outcomes.",
  },
  {
    mode: "general" as TaskMode,
    icon: Icons.search,
    title: "Explain a legal doctrine",
    copy: "Start with the governing rule, limits and verified authorities.",
  },
];

function readableDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat("en", { month: "short", day: "numeric" }).format(date);
}

function stageIndex(stage: JobStage): number {
  return ["queued", ...PROGRESS_STAGES, "complete"].indexOf(stage);
}

function releaseLabel(answer: AnswerRecord): string {
  if (answer.release_state === "verified_full") return "Evidence verified";
  if (answer.release_state === "verified_concise") return "Verified concise answer";
  if (answer.release_state === "verified_limited") return "Verified limited answer";
  if (answer.release_state === "held_for_review") return "Held for review";
  return "System error";
}

function clearJobQuery() {
  const url = new URL(window.location.href);
  url.searchParams.delete("job");
  window.history.replaceState({}, "", url);
}

interface AnswerCardProps {
  answer: AnswerRecord;
  onEvidence: (citation: CitationToken) => void;
  onIssue: () => void;
}

function AnswerCard({ answer, onEvidence, onIssue }: AnswerCardProps) {
  const [copied, setCopied] = useState(false);
  const [feedbackRating, setFeedbackRating] = useState<AnswerFeedbackRating>("helpful");
  const [feedbackCategory, setFeedbackCategory] = useState<AnswerFeedbackCategory>("clarity");
  const [feedbackNote, setFeedbackNote] = useState("");
  const [feedbackStatus, setFeedbackStatus] = useState("");
  const [feedbackSending, setFeedbackSending] = useState(false);
  const feedbackIdempotency = useRef(crypto.randomUUID());
  const copyText = async () => {
    await navigator.clipboard.writeText(answer.content);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };
  const submitFeedback = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFeedbackSending(true);
    setFeedbackStatus("");
    try {
      const result = await api.feedback(answer.id, {
        rating: feedbackRating,
        category: feedbackCategory,
        scope: "answer",
        note: feedbackNote.trim() || undefined,
        idempotency_key: feedbackIdempotency.current,
      });
      setFeedbackStatus(`Saved for owner review · ${result.refinement_id}`);
      setFeedbackNote("");
      feedbackIdempotency.current = crypto.randomUUID();
    } catch (error) {
      setFeedbackStatus(formatApiError(error));
    } finally {
      setFeedbackSending(false);
    }
  };
  return (
    <article className="answer-card">
      <header className="answer-meta">
        <span className={`verified-badge ${answer.release_state}`}>
          <Icons.shield size={15} />{releaseLabel(answer)}
        </span>
        <span>{answer.word_count.toLocaleString()} words</span>
        {typeof answer.quality?.academic_score === "number" && (
          <span title="Automated, advisory and not blind-marker calibrated">
            {Math.round(answer.quality.academic_score)} advisory structure score
          </span>
        )}
      </header>

      <AnswerMarkdown content={answer.content} onEvidence={onEvidence} />

      <footer className="answer-footer">
        <div>
          <span>Immutable released answer</span>
          {answer.index_build_id && <span> · Index {answer.index_build_id}</span>}
          <span> · Policy {answer.policy_version}</span>
        </div>
        <button className="text-button" type="button" onClick={() => void copyText()}>
          {copied ? <Icons.check size={16} /> : <Icons.copy size={16} />}
          {copied ? "Copied" : "Copy Markdown"}
        </button>
        <button className="text-button" type="button" onClick={onIssue}>
          <Icons.alert size={16} /> Log quality issue
        </button>
      </footer>
      <form className="answer-feedback" onSubmit={(event) => void submitFeedback(event)}>
        <div>
          <strong>Help improve this answer</strong>
          <span>Encrypted feedback is queued for owner review; it never changes sources or model weights automatically.</span>
        </div>
        <label>
          <span>Rating</span>
          <select value={feedbackRating} onChange={(event) => setFeedbackRating(event.target.value as AnswerFeedbackRating)}>
            <option value="helpful">Helpful</option>
            <option value="partly_helpful">Partly helpful</option>
            <option value="not_helpful">Not helpful</option>
          </select>
        </label>
        <label>
          <span>Category</span>
          <select value={feedbackCategory} onChange={(event) => setFeedbackCategory(event.target.value as AnswerFeedbackCategory)}>
            <option value="clarity">Clarity</option>
            <option value="accuracy">Legal accuracy</option>
            <option value="currentness">Current law</option>
            <option value="authority">Authority selection</option>
            <option value="citation">Citation</option>
            <option value="completeness">Completeness</option>
            <option value="application">Application</option>
            <option value="structure">Structure</option>
            <option value="length">Length</option>
            <option value="privacy">Privacy</option>
            <option value="other">Other</option>
          </select>
        </label>
        <label className="feedback-note">
          <span>Optional note</span>
          <textarea maxLength={4000} rows={2} value={feedbackNote} onChange={(event) => setFeedbackNote(event.target.value)} />
        </label>
        <button disabled={feedbackSending} type="submit">{feedbackSending ? "Saving…" : "Send feedback"}</button>
        {feedbackStatus && <p role="status">{feedbackStatus}</p>}
      </form>
    </article>
  );
}

function JobProgress({ stage, detail, progress }: { stage: JobStage; detail: string; progress: number }) {
  const current = stageIndex(stage);
  return (
    <div className="job-card" role="status" aria-live="polite">
      <div className="job-card-head">
        <div className="job-orb"><span /></div>
        <div>
          <strong>{STAGE_LABELS[stage]}</strong>
          <p>{detail || "Working locally. You can leave this page and reconnect to the same job."}</p>
        </div>
        <strong>{Math.round(Math.max(0, Math.min(1, progress)) * 100)}%</strong>
      </div>
      <ol className="stage-track" aria-label="Answer progress">
        {PROGRESS_STAGES.map((item) => {
          const index = stageIndex(item);
          const state = index < current ? "done" : index === current ? "active" : "pending";
          return (
            <li className={state} key={item}>
              <span>{state === "done" ? <Icons.check size={13} /> : null}</span>
              {STAGE_LABELS[item]}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

export function LegalBotApp() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [selectedAnswerId, setSelectedAnswerId] = useState("");
  const [currentQuestion, setCurrentQuestion] = useState("");
  const [answer, setAnswer] = useState<AnswerRecord | null>(null);
  const [health, setHealth] = useState<HealthRecord | null>(null);
  const [developmentChat, setDevelopmentChat] = useState(false);
  const [developmentAuthoritySha, setDevelopmentAuthoritySha] = useState("");
  const [developmentAccessKey, setDevelopmentAccessKey] = useState("");
  const [developmentRoute, setDevelopmentRoute] = useState<"qwen_local" | "local_endpoint" | "hosted_api" | "anthropic_api" | "gemini_api" | "codex_bridge">("qwen_local");
  const [developmentRemoteConsent, setDevelopmentRemoteConsent] = useState(false);
  const [taskMode, setTaskMode] = useState<TaskMode>("auto");
  const [jurisdiction, setJurisdiction] = useState<Jurisdiction>("England and Wales");
  const [customJurisdiction, setCustomJurisdiction] = useState("");
  const developmentHistory = useRef<string[]>([]);
  const [asOfDate, setAsOfDate] = useState(() => {
    const today = new Date();
    const year = today.getFullYear();
    const month = String(today.getMonth() + 1).padStart(2, "0");
    const day = String(today.getDate()).padStart(2, "0");
    return `${year}-${month}-${day}`;
  });
  const [onlineMode, setOnlineMode] = useState<OnlineMode>("local_only");
  const [targetWords, setTargetWords] = useState(1500);
  const [prompt, setPrompt] = useState("");
  const [attachments, setAttachments] = useState<AttachmentRecord[]>([]);
  const [uploading, setUploading] = useState(false);
  const [activeJobId, setActiveJobId] = useState("");
  const [activeEventsUrl, setActiveEventsUrl] = useState("");
  const [stage, setStage] = useState<JobStage>("queued");
  const [progress, setProgress] = useState(0);
  const [stageDetail, setStageDetail] = useState("");
  const [terminalNotice, setTerminalNotice] = useState<{ stage: "held_for_review" | "system_error" | "cancelled"; message: string } | null>(null);
  const [serviceError, setServiceError] = useState("");
  const [evidence, setEvidence] = useState<EvidenceSelection | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const messageEnd = useRef<HTMLDivElement>(null);
  const submitIdempotency = useRef("");
  const conversationId = useRef(`conversation-${crypto.randomUUID()}`);

  useEffect(() => {
    api.setDevelopmentChatConnection(
      developmentChat && /^[0-9a-f]{64}$/.test(developmentAuthoritySha) && developmentAccessKey
        ? { authoritySha256: developmentAuthoritySha, accessKey: developmentAccessKey, routeId: developmentRoute, remoteConsent: developmentRemoteConsent }
        : null,
    );
  }, [developmentChat, developmentAuthoritySha, developmentAccessKey, developmentRoute, developmentRemoteConsent]);

  const refreshConversations = useCallback(async () => {
    try {
      const list = await api.conversations();
      setConversations(list);
      return list;
    } catch (error) {
      setServiceError(formatApiError(error));
      return [];
    }
  }, []);

  const openReleasedAnswer = useCallback(async (item: ConversationSummary) => {
    try {
      const released = await api.answer(item.answer_id);
      setSelectedAnswerId(item.answer_id);
      setCurrentQuestion(item.question_summary);
      setAnswer(released);
      setTerminalNotice(null);
      submitIdempotency.current = "";
      setActiveJobId("");
      setSidebarOpen(false);
      clearJobQuery();
      setServiceError("");
    } catch (error) {
      setServiceError(formatApiError(error));
    }
  }, []);

  useEffect(() => {
    let current = true;
    Promise.allSettled([api.health(), api.conversations()]).then(([healthResult, conversationResult]) => {
      if (!current) return;
      if (healthResult.status === "fulfilled") setHealth(healthResult.value);
      if (conversationResult.status === "fulfilled") setConversations(conversationResult.value);
      if (healthResult.status === "rejected" && conversationResult.status === "rejected") {
        setServiceError(formatApiError(healthResult.reason));
      }
      const reconnectId = new URLSearchParams(window.location.search).get("job");
      if (reconnectId) setActiveJobId(reconnectId);
    });
    return () => {
      current = false;
    };
  }, []);

  const installAnswer = useCallback((released: AnswerRecord) => {
    setAnswer(released);
    setSelectedAnswerId(released.id);
    setActiveJobId("");
    setActiveEventsUrl("");
    setTerminalNotice(null);
    setStage(released.release_state === "verified_limited" ? "limited" : "complete");
    setProgress(1);
    submitIdempotency.current = "";
    clearJobQuery();
    void refreshConversations();
  }, [refreshConversations]);

  useEffect(() => {
    if (!activeJobId) return;
    let current = true;
    let terminal = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let lastSequence = 0;

    const endWithoutAnswer = (nextStage: "held_for_review" | "system_error" | "cancelled", message?: string | null) => {
      if (!current) return;
      terminal = true;
      setStage(nextStage);
      setTerminalNotice({
        stage: nextStage,
        message: message || (
          nextStage === "held_for_review"
            ? "The evidence or quality gate requires human review. No unverified answer was released."
            : nextStage === "cancelled"
              ? "The research job stopped after its last encrypted checkpoint."
              : "The research job ended safely without releasing an answer."
        ),
      });
      setActiveJobId("");
      setActiveEventsUrl("");
      submitIdempotency.current = "";
      clearJobQuery();
    };

    const loadReleased = async (answerId: string | null) => {
      if (!answerId) {
        endWithoutAnswer("system_error", "The job completed without a released answer identifier.");
        return;
      }
      try {
        const released = await api.answer(answerId);
        if (current) installAnswer(released);
      } catch (error) {
        if (current) setServiceError(formatApiError(error));
      }
    };

    const handleJob = async (job: JobRecord) => {
      if (!current) return;
      if (job.conversation_id) conversationId.current = job.conversation_id;
      if (job.jurisdiction && JURISDICTIONS.some((item) => item.value === job.jurisdiction)) {
        setJurisdiction(job.jurisdiction as Jurisdiction);
      }
      if (job.as_of_date) setAsOfDate(job.as_of_date);
      if (job.question_summary !== "Private encrypted question") setCurrentQuestion(job.question_summary);
      setStage(job.stage);
      setProgress(job.progress);
      setStageDetail(job.message || "");
      if (job.status === "complete") {
        terminal = true;
        await loadReleased(job.answer_id);
      }
      else if (job.status === "held_for_review") endWithoutAnswer("held_for_review", job.message);
      else if (job.status === "system_error") endWithoutAnswer("system_error", job.message);
      else if (job.status === "cancelled") endWithoutAnswer("cancelled", job.message);
    };

    const hydrate = async () => {
      try {
        await handleJob(await api.job(activeJobId));
      } catch (error) {
        if (current) setServiceError(formatApiError(error));
      }
    };

    const connect = () => {
      if (!current) return;
      socket = new WebSocket(
        api.jobEventsWebSocketUrl(activeJobId, activeEventsUrl, lastSequence),
        "legalbot.job-events.v1",
      );
      socket.onmessage = (raw) => {
        try {
          const envelope = JSON.parse(String(raw.data)) as JobEventEnvelope;
          if (
            envelope.schema !== "legalbot.job-event.v1"
            || envelope.job_id !== activeJobId
            || !envelope.event_id
            || !envelope.attempt_id
            || !Number.isSafeInteger(envelope.lease_generation)
            || !Number.isSafeInteger(envelope.sequence)
            || envelope.sequence < lastSequence
          ) throw new Error("invalid websocket event envelope");
          lastSequence = envelope.sequence;
          if (!current) return;
          if (envelope.event === "progress") {
            const event = envelope.data as JobProgressEvent;
            if (event.stage) setStage(event.stage);
            if (event.progress !== null) setProgress(event.progress);
            setStageDetail(event.message_code);
            return;
          }
          if (envelope.event === "reset_required") {
            void hydrate();
            return;
          }
          const event = envelope.data as JobDoneEvent;
          if (event.status === "complete" && event.terminal_kind === "committed") {
            terminal = true;
            void loadReleased(event.answer_id);
          }
          else if (event.status === "held") endWithoutAnswer("held_for_review", event.message_code);
          else if (event.status === "cancelled") endWithoutAnswer("cancelled", event.message_code);
          else endWithoutAnswer("system_error", event.message_code);
        } catch {
          setServiceError("A WebSocket progress update could not be read. The durable job remains available.");
          void hydrate();
        }
      };
      socket.onerror = () => {
        if (!terminal) void hydrate();
      };
      socket.onclose = () => {
        socket = null;
        if (!current || terminal) return;
        void hydrate().finally(() => {
          if (current && !terminal) reconnectTimer = window.setTimeout(connect, 750);
        });
      };
    };

    if (developmentChat) {
      void hydrate();
      const poll = window.setInterval(() => {
        if (current && !terminal) void hydrate();
      }, 1200);
      return () => {
        current = false;
        window.clearInterval(poll);
      };
    }

    void hydrate().then(() => {
      if (current && !terminal) connect();
    });
    return () => {
      current = false;
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [activeEventsUrl, activeJobId, installAnswer, developmentChat, developmentAuthoritySha, developmentAccessKey, developmentRoute, developmentRemoteConsent]);

  useEffect(() => {
    messageEnd.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [answer, activeJobId, stage, terminalNotice]);

  const newResearch = () => {
    setSelectedAnswerId("");
    setCurrentQuestion("");
    setAnswer(null);
    setActiveJobId("");
    setActiveEventsUrl("");
    setPrompt("");
    setAttachments([]);
    setTerminalNotice(null);
    setSidebarOpen(false);
    submitIdempotency.current = "";
    conversationId.current = `conversation-${crypto.randomUUID()}`;
    clearJobQuery();
  };

  const addFiles = async (files: FileList | null) => {
    if (!files?.length) return;
    setUploading(true);
    const uploaded = await Promise.allSettled([...files].map((file) => api.upload(file)));
    setAttachments((current) => [
      ...current,
      ...uploaded
        .filter((item): item is PromiseFulfilledResult<AttachmentRecord> => item.status === "fulfilled")
        .map((item) => item.value),
    ]);
    const failed = uploaded.filter((item) => item.status === "rejected");
    if (failed.length) setServiceError(`${failed.length} file${failed.length === 1 ? "" : "s"} could not be staged.`);
    setUploading(false);
    if (fileInput.current) fileInput.current.value = "";
  };

  const submit = async () => {
    const question = prompt.trim();
    if (!question || activeJobId) return;
    const connectionIntent = question.toLowerCase().replace(/[.!?]+$/, "");
    const requestedRoute = (
      /^(link|connect|use) codex$/.test(connectionIntent) ? "codex_bridge"
        : /^(link|connect|use) (api|openai api)$/.test(connectionIntent) ? "hosted_api"
          : /^(link|connect|use) (claude|anthropic api)$/.test(connectionIntent) ? "anthropic_api"
            : /^(link|connect|use) (gemini|gemini api)$/.test(connectionIntent) ? "gemini_api"
          : /^(link|connect|use) (local model|my local model)$/.test(connectionIntent) ? "local_endpoint"
            : null
    );
    if (requestedRoute) {
      setDevelopmentChat(true);
      setDevelopmentRoute(requestedRoute);
      setPrompt("");
      setServiceError("Enter the pinned owner development authority and access key, then ask a legal question.");
      return;
    }
    setServiceError("");
    setTerminalNotice(null);
    try {
      if (developmentChat) {
        if (!/^[0-9a-f]{64}$/.test(developmentAuthoritySha) || !developmentAccessKey) {
          throw new Error("Enter the pinned development authority SHA-256 and owner access key.");
        }
        if (attachments.length) {
          throw new Error("Development chat currently accepts text only; remove staged uploads.");
        }
        api.setDevelopmentChatConnection({
          authoritySha256: developmentAuthoritySha,
          accessKey: developmentAccessKey,
          routeId: developmentRoute,
          remoteConsent: developmentRemoteConsent,
        });
      } else {
        api.setDevelopmentChatConnection(null);
      }
      const selectedJurisdiction = jurisdiction === "Other" ? customJurisdiction.trim() : jurisdiction;
      if (!selectedJurisdiction || selectedJurisdiction.length > 120) {
        throw new Error("Enter a specific jurisdiction (country and, where relevant, state or region).");
      }
      const contextualQuestion = developmentChat && developmentHistory.current.length
        ? `Earlier messages in this case:\n${developmentHistory.current.map((item, index) => `${index + 1}. ${item}`).join("\n\n")}\n\nCurrent message:\n${question}`
        : question;
      if (contextualQuestion.length > 30_000) {
        throw new Error("This case history is too long. Start a new development chat.");
      }
      if (!submitIdempotency.current) submitIdempotency.current = crypto.randomUUID();
      const created = await api.createAnswer({
        question: contextualQuestion,
        task_type: taskMode,
        jurisdiction: selectedJurisdiction,
        as_of_date: asOfDate || undefined,
        word_target: targetWords,
        online_mode: developmentChat ? "local_only" : onlineMode,
        upload_ids: developmentChat ? [] : attachments.map((item) => item.upload_id),
        conversation_id: developmentChat ? undefined : conversationId.current,
      }, submitIdempotency.current);
      if (created.conversation_id) conversationId.current = created.conversation_id;
      if (developmentChat) developmentHistory.current = [...developmentHistory.current, question].slice(-4);
      setCurrentQuestion(question);
      setAnswer(null);
      setSelectedAnswerId("");
      setPrompt("");
      setAttachments([]);
      setStage(created.stage);
      setProgress(0);
      setStageDetail("");
      setActiveEventsUrl(created.events_url);
      setActiveJobId(created.job_id);
      const url = new URL(window.location.href);
      url.searchParams.set("job", created.job_id);
      window.history.replaceState({}, "", url);
    } catch (error) {
      setServiceError(formatApiError(error));
    }
  };

  const openEvidence = (citation: CitationToken) => {
    if (!answer) return;
    setEvidence({ answerId: answer.id, evidenceId: citation.evidenceId, citationLabel: citation.label });
  };

  const reportIssue = async () => {
    if (!answer) return;
    const note = window.prompt(
      "Describe the legal, source, citation, privacy or completeness issue. The note is encrypted locally.",
      "",
    );
    if (note === null || !note.trim()) return;
    try {
      const result = await api.reportIssue(answer.id, {
        category: "owner_quality_review",
        severity: "medium",
        affected_layer: "end_to_end",
        expected_ids: [],
        observed_ids: [answer.id],
        note: note.trim(),
      });
      setServiceError(`Quality issue ${result.issue_id} logged for review.`);
    } catch (error) {
      setServiceError(formatApiError(error));
    }
  };

  const cancelActiveJob = async () => {
    if (!activeJobId) return;
    try {
      await api.cancelJob(activeJobId);
      setStageDetail("Cancellation requested; stopping after the current safe checkpoint.");
    } catch (error) {
      setServiceError(formatApiError(error));
    }
  };

  const selectedTask = useMemo(() => TASKS.find((item) => item.value === taskMode) || TASKS[0], [taskMode]);
  const hasResearch = Boolean(currentQuestion || answer);
  const systemReady = Boolean(
    developmentChat
      ? health?.database_ready && health?.worker_ready
      : health?.status === "ready" && health?.database_ready && health?.model_ready && health?.worker_ready && health?.active_index,
  );

  return (
    <div className="legal-app">
      <button className={`mobile-scrim ${sidebarOpen ? "show" : ""}`} aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />
      <aside className={`app-sidebar ${sidebarOpen ? "open" : ""}`}>
        <div className="brand-row">
          <span className="brand-mark"><Icons.mark size={23} /></span>
          <div><strong>Counsel</strong><span>Verified legal research</span></div>
        </div>
        <button className="new-chat-button" type="button" onClick={newResearch}>
          <Icons.plus size={18} /> New research
        </button>
        <nav className="primary-nav" aria-label="Primary navigation">
          <a className="active" href="/"><Icons.chat size={18} /> Research</a>
          <a href="/admin"><Icons.dashboard size={18} /> Operations</a>
        </nav>
        <div className="sidebar-section-title"><span>Released work</span><button type="button" onClick={() => void refreshConversations()}>Refresh</button></div>
        <div className="conversation-list">
          {conversations.length === 0 && <p className="sidebar-empty">Verified research will appear here after release.</p>}
          {conversations.map((item) => (
            <button
              className={`conversation-link ${selectedAnswerId === item.answer_id ? "active" : ""}`}
              key={item.answer_id}
              onClick={() => void openReleasedAnswer(item)}
              type="button"
            >
              <span>{item.question_summary || "Released legal research"}</span>
              <small>{item.word_count.toLocaleString()} words · {readableDate(item.created_at)}</small>
              <i>{item.release_state.replaceAll("_", " ")}</i>
            </button>
          ))}
        </div>
        <footer className="sidebar-footer">
          <div className={`system-dot ${systemReady ? "ready" : ""}`} />
          <div>
            <strong>{developmentChat && systemReady ? "Development backend connected" : systemReady ? "Local system ready" : serviceError ? "API unavailable" : "Checking local system"}</strong>
            <span>{developmentChat ? "Route checked on submission" : health?.model_id || "Qwen legal model"}</span>
          </div>
        </footer>
      </aside>

      <main className="chat-workspace">
        <header className="workspace-header">
          <button className="menu-button" type="button" onClick={() => setSidebarOpen(true)} aria-label="Open navigation"><Icons.menu /></button>
          <div className="task-switcher" role="group" aria-label="Answer type">
            {TASKS.map((item) => (
              <button aria-pressed={taskMode === item.value} className={taskMode === item.value ? "active" : ""} key={item.value} onClick={() => setTaskMode(item.value)} type="button">
                {item.label}
              </button>
            ))}
          </div>
          <div className="header-controls">
            <label>
              <Icons.globe size={17} /><span className="sr-only">Jurisdiction</span>
              <select value={jurisdiction} onChange={(event) => setJurisdiction(event.target.value as Jurisdiction)}>
                {JURISDICTIONS.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
              </select>
            </label>
            {jurisdiction === "Other" && (
              <label>Jurisdiction
                <input aria-label="Specify jurisdiction" value={customJurisdiction}
                  onChange={(event) => setCustomJurisdiction(event.target.value)}
                  placeholder="Country and state or region" maxLength={120} />
              </label>
            )}
            <a className="admin-shortcut" href="/admin" aria-label="Open operations dashboard"><Icons.dashboard size={18} /></a>
          </div>
        </header>

        <div className="chat-scroll">
          {!hasResearch && !activeJobId && (
            <section className="welcome">
              <div className="welcome-mark"><Icons.mark size={30} /></div>
              <span className="eyebrow">Evidence before assertion</span>
              <h1>Legal research you can inspect.</h1>
              <p>Ask for a critical essay, problem analysis or clear explanation. Every material legal proposition is bound to the exact source span used to support it.</p>
              <div className="starter-grid">
                {STARTERS.map((item) => {
                  const StarterIcon = item.icon;
                  return (
                    <button key={item.mode} type="button" onClick={() => { setTaskMode(item.mode); setPrompt(`${item.title}: `); }}>
                      <span><StarterIcon size={20} /></span><strong>{item.title}</strong><p>{item.copy}</p>
                    </button>
                  );
                })}
              </div>
              <div className="trust-strip">
                <span><Icons.shield size={16} /> Claim-level evidence</span>
                <span><Icons.book size={16} /> Full OSCOLA by default</span>
                <span><Icons.target size={16} /> Advisory academic guidance</span>
              </div>
            </section>
          )}

          {hasResearch && (
            <section className="message-thread" aria-live="polite">
              <div className="thread-heading">
                <span className="eyebrow">{selectedTask.label} · {jurisdiction}</span>
                <h1>{currentQuestion || "Legal research"}</h1>
              </div>
              {currentQuestion && <div className="user-message"><p>{currentQuestion}</p></div>}
              {answer && <AnswerCard answer={answer} onEvidence={openEvidence} onIssue={() => void reportIssue()} />}
            </section>
          )}

          {activeJobId && (
            <>
              <JobProgress stage={stage} detail={stageDetail} progress={progress} />
              <button className="text-button cancel-job" type="button" onClick={() => void cancelActiveJob()}>
                Cancel after checkpoint
              </button>
            </>
          )}

          {terminalNotice && (
            <section className="generation-error" role="alert">
              <Icons.alert size={22} />
              <div>
                <strong>{STAGE_LABELS[terminalNotice.stage]}</strong>
                <p>{terminalNotice.message}</p>
                <small>No unsupported draft was released or shown as a legal answer.</small>
              </div>
              <button type="button" onClick={() => setTerminalNotice(null)}>Dismiss</button>
            </section>
          )}

          <div ref={messageEnd} />
        </div>

        <div className="composer-dock">
          <div className="development-chat-controls">
            <label>
              <input type="checkbox" checked={developmentChat} onChange={(event) => {
                setDevelopmentChat(event.target.checked);
                developmentHistory.current = [];
                if (!event.target.checked) api.setDevelopmentChatConnection(null);
              }} /> Owner development chat
            </label>
            {developmentChat && (
              <>
                <label>Model
                  <select aria-label="Development model route" value={developmentRoute} onChange={(event) => {
                    developmentHistory.current = [];
                    setDevelopmentRoute(event.target.value as typeof developmentRoute);
                  }}>
                    <option value="qwen_local">Own local Qwen</option>
                    <option value="local_endpoint">Linked local model</option>
                    <option value="hosted_api">OpenAI API</option>
                    <option value="anthropic_api">Claude API</option>
                    <option value="gemini_api">Gemini API</option>
                    <option value="codex_bridge">Codex bridge</option>
                  </select>
                </label>
                <label>Authority SHA-256
                  <input aria-label="Development authority SHA-256" type="text" value={developmentAuthoritySha} onChange={(event) => setDevelopmentAuthoritySha(event.target.value.trim())} autoComplete="off" />
                </label>
                <label>Owner access key
                  <input aria-label="Development owner access key" type="password" value={developmentAccessKey} onChange={(event) => setDevelopmentAccessKey(event.target.value)} autoComplete="off" />
                </label>
                {(["hosted_api", "anthropic_api", "gemini_api", "codex_bridge"] as const).includes(developmentRoute as "hosted_api" | "anthropic_api" | "gemini_api" | "codex_bridge") && (
                  <label><input type="checkbox" checked={developmentRemoteConsent} onChange={(event) => setDevelopmentRemoteConsent(event.target.checked)} />
                    Send this question and selected evidence to the remote model</label>
                )}
                <span>Isolated candidate and reviewed index only. Text questions; no uploads or conversation history.</span>
              </>
            )}
          </div>
          {serviceError && (
            <div className="service-alert" role="alert">
              <Icons.alert size={16} /><span>{serviceError}</span><button type="button" onClick={() => setServiceError("")}>Dismiss</button>
            </div>
          )}
          {attachments.length > 0 && (
            <div className="attachment-row">
              {attachments.map((item) => (
                <span key={item.upload_id}><Icons.file size={15} />{item.display_name}<button aria-label={`Remove ${item.display_name}`} type="button" onClick={() => setAttachments((current) => current.filter((file) => file.upload_id !== item.upload_id))}>×</button></span>
              ))}
            </div>
          )}
          <div className="composer">
            <textarea
              aria-label="Legal research question"
              disabled={Boolean(activeJobId)}
              onChange={(event) => setPrompt(event.target.value)}
              onKeyDown={(event) => {
                if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
                  event.preventDefault();
                  void submit();
                }
              }}
              placeholder={`${selectedTask.description}. Ask your question…`}
              rows={3}
              value={prompt}
            />
            <div className="composer-toolbar">
              <button className="attach-control" disabled={developmentChat || uploading || Boolean(activeJobId)} type="button" onClick={() => fileInput.current?.click()}>
                {uploading ? <span className="mini-spinner" /> : <Icons.paperclip size={18} />}
                {uploading ? "Processing…" : "Attach sources"}
              </button>
              <input ref={fileInput} type="file" hidden multiple accept=".pdf,.docx,.pptx,.odt,.txt,.md,.html" onChange={(event) => void addFiles(event.target.files)} />
              <label className="compact-control">
                <span>Online</span>
                <select value={developmentChat ? "local_only" : onlineMode} disabled={developmentChat} onChange={(event) => setOnlineMode(event.target.value as OnlineMode)}>
                  <option value="auto">Auto</option><option value="always">Always</option><option value="local_only">Local only</option>
                </select>
              </label>
              <label className="compact-control">
                <span>Words</span>
                <input min={100} max={10000} step={100} type="number" value={targetWords} onChange={(event) => setTargetWords(Math.max(100, Math.min(10000, Number(event.target.value) || 1500)))} />
              </label>
              <label className="compact-control date-control">
                <span>Law as of</span>
                <input aria-label="Law as of date" type="date" value={asOfDate} onChange={(event) => setAsOfDate(event.target.value)} />
              </label>
              <span className="composer-spacer" />
              <button className="send-button" disabled={!prompt.trim() || Boolean(activeJobId) || !systemReady} type="button" onClick={() => void submit()}>
                <span>Research</span><Icons.send size={18} />
              </button>
            </div>
          </div>
          <p className="legal-note"><Icons.shield size={14} /> Legal information and academic research, not legal advice. Verify deadlines with a qualified lawyer.</p>
        </div>
      </main>

      <EvidenceDrawer selection={evidence} onClose={() => setEvidence(null)} />
    </div>
  );
}
