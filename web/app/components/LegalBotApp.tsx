import { useCallback, useEffect, useRef, useState } from "react";
import { api, formatApiError } from "../lib/api";
import type { DevelopmentRouteId, JobRecord, JobStage, OnlineMode, TaskMode } from "../lib/contracts";
import { chatApi, type ChatSession, type ChatMessage, type Connection, type DraftPreview } from "../lib/chat-api";
import { AnswerMarkdown } from "./AnswerMarkdown";
import { EvidenceDrawer, type EvidenceSelection } from "./EvidenceDrawer";
import { Icons } from "./Icons";

const TASKS: Array<{ value: TaskMode; label: string; description: string }> = [
  { value: "auto", label: "Auto", description: "Detect the right legal answer structure" },
  { value: "essay", label: "Essay", description: "Critical argument and scholarship" },
  { value: "problem", label: "Problem question", description: "Issues, rules, application and outcome" },
  { value: "general", label: "General question", description: "Clear, authoritative explanation" },
];

const PROVIDER_LABELS: Record<DevelopmentRouteId, string> = {
  qwen_local: "Local Qwen",
};

const STAGE_LABELS: Record<JobStage, string> = {
  queued: "Queued",
  researching: "Researching sources",
  qualifying_evidence: "Checking sources",
  drafting: "Writing the answer",
  verifying: "Checking every claim",
  repairing: "Fixing weak sections",
  assembling: "Putting the answer together",
  complete: "Answer ready",
  limited: "Limited answer ready",
  held_for_review: "Held for review",
  system_error: "Something went wrong",
  cancelled: "Cancelled",
};

const PROGRESS_STAGES: JobStage[] = [
  "researching",
  "qualifying_evidence",
  "drafting",
  "verifying",
  "repairing",
  "assembling",
];

function stageIndex(stage: JobStage): number {
  return ["queued", ...PROGRESS_STAGES, "complete"].indexOf(stage);
}

function JobProgress({ stage, detail, createdAt, onCancel }: { stage: JobStage; detail: string; createdAt?: string; onCancel: () => void }) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const elapsed = createdAt ? Math.max(0, Math.floor((now - Date.parse(createdAt)) / 1000)) : 0;
  const current = Math.max(0, stageIndex(stage));
  const percent = Math.min(100, Math.round((current / (PROGRESS_STAGES.length + 1)) * 100));
  return (
    <div className="progress" role="status" aria-live="polite">
      <div className="progress-line">
        <span className="progress-dot" aria-hidden="true" />
        <strong>{STAGE_LABELS[stage]}</strong>
        <span className="progress-time" aria-label="Elapsed time">{Math.floor(elapsed / 60)}m {elapsed % 60}s</span>
        <button type="button" className="link-button" onClick={onCancel}>Cancel</button>
      </div>
      <div className="progress-bar" aria-hidden="true"><span style={{ width: `${percent}%` }} /></div>
      <p>{detail || "Working on this computer. You can leave and come back to the same question."}</p>
    </div>
  );
}

type VisibleDraft = Extract<DraftPreview, {available: true}>;

function DraftPreviewCard({ preview }: { preview: VisibleDraft }) {
  return <details className="draft-preview" aria-label="Private diagnostic draft">
    <summary>Unchecked draft (not an answer)</summary>
    <p>This is the model’s saved text before checking. It may contain errors or unsupported claims, and it is not used as a fact in follow-up questions.</p>
    <small>{preview.model_version} · version {preview.version} · {preview.word_count} words · {preview.review_complete ? 'Review findings below' : 'Review in progress'}</small>
    <pre>{preview.content}</pre>
    {preview.review_findings.length > 0 && <details><summary>Why it was held ({preview.review_findings.length})</summary><ul>{preview.review_findings.map((finding, i) => <li key={`${finding.code}-${i}`}><strong>{finding.code}:</strong> {finding.message}</li>)}</ul></details>}
  </details>;
}

export function LegalBotApp() {
  const [session, setSession] = useState<ChatSession | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [connectionId, setConnectionId] = useState("");
  const [consent, setConsent] = useState(false);
  const [panel, setPanel] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [taskMode, setTaskMode] = useState<TaskMode>("general");
  const [jurisdiction, setJurisdiction] = useState("England");
  const [asOfDate, setAsOfDate] = useState(new Date().toLocaleDateString('en-CA'));
  const [onlineMode, setOnlineMode] = useState<OnlineMode>("auto");
  const [targetWords, setTargetWords] = useState(450);
  const [prompt, setPrompt] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draftPreviews, setDraftPreviews] = useState<Record<string, VisibleDraft>>({});
  const [conversation, setConversation] = useState(() => new URLSearchParams(location.search).get('conversation') || `conversation-${crypto.randomUUID()}`);
  const [history, setHistory] = useState<{id:string}[]>([]);
  const [jobId, setJobId] = useState("");
  const [job, setJob] = useState<JobRecord | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [sidebar, setSidebar] = useState(false);
  const [options, setOptions] = useState(false);
  const [evidence, setEvidence] = useState<EvidenceSelection | null>(null);
  const [attachments, setAttachments] = useState<{id: string; name: string}[]>([]);
  const [uploading, setUploading] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const idempotency = useRef("");
  const end = useRef<HTMLDivElement>(null);
  const conversationRef = useRef(conversation);
  const selected = connections.find(c => c.id === connectionId);
  const selectedRoute = session?.routes.find(r => r.route_id === selected?.route_id);

  const loadPreview = useCallback(async (id: string) => {
    const preview = await chatApi.draftPreview(id);
    if (preview.available) setDraftPreviews(old => ({...old, [id]:preview}));
  }, []);

  const refresh = useCallback(async (id: string, restoreSettings = false) => {
    const value = await chatApi.conversation(id);
    if (conversationRef.current !== id) return value;
    setMessages(value.messages);
    const previewJobs = value.jobs.filter(item => item.status !== 'complete');
    void Promise.allSettled(previewJobs.map(item => loadPreview(item.id)));
    const last = value.jobs.at(-1);
    if (last && restoreSettings) { setJurisdiction(last.jurisdiction); setAsOfDate(last.as_of_date); setTargetWords(last.word_target); setTaskMode(last.task_type as TaskMode); setConnectionId(last.connection_id); }
    if (last && ['queued','running'].includes(last.status)) setJobId(last.id);
    return value;
  }, [loadPreview]);

  useEffect(() => {
    let active = true;
    void chatApi.session().then(async value => {
      if (!active) return;
      setSession(value); setConnections(value.connections);
      setConnectionId(value.connections.find(c => c.route_id === 'qwen_local')?.id || value.connections[0]?.id || '');
      const list = await chatApi.conversations();
      if (!active) return;
      setHistory(list.items);
      const current = new URLSearchParams(location.search).get('conversation');
      if (current && list.items.some(i => i.id === current)) await refresh(current, true);
      if (!value.connections.length) setPanel(true);
    }).catch(e => { if (active) setError(formatApiError(e)); });
    return () => { active = false; };
  }, [refresh]);

  useEffect(() => {
    if (!jobId) return;
    let active = true;
    let timer: number;
    const poll = async () => {
      try {
        const value = await api.job(jobId);
        if (!active) return;
        setJob(value);
        if (['complete','held_for_review','system_error','cancelled','failed','dlq'].includes(value.status)) {
          setJobId(''); idempotency.current = '';
          await refresh(conversation);
          const list = await chatApi.conversations(); setHistory(list.items);
          return;
        }
      } catch(e) { if (active) setError(formatApiError(e)); }
      if (active) timer = window.setTimeout(() => void poll(), 1200);
    };
    void poll();
    return () => { active = false; window.clearTimeout(timer); };
  }, [jobId, conversation, refresh]);

  useEffect(() => {
    if (!jobId) return;
    const initial = window.setTimeout(() => void loadPreview(jobId).catch(() => {}), 0);
    const timer = window.setInterval(() => void loadPreview(jobId).catch(() => {}), 10000);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); };
  }, [jobId, loadPreview]);

  useEffect(() => {
    if (!messages.length) return;
    const nodes = Array.from(document.querySelectorAll<HTMLElement>('[data-message-id]'));
    const displayed = nodes.map(node => ({id:node.dataset.messageId!, role:node.dataset.messageRole!, text:node.innerText}));
    if (displayed.length === messages.length) void chatApi.displayReceipt(conversation, displayed).catch(() => { /* Evidence capture failure never changes an answer. */ });
  }, [messages, conversation]);

  useEffect(() => { end.current?.scrollIntoView({behavior:'smooth'}); }, [messages, jobId]);

  const connect = async () => {
    setConnecting(true); setError(''); setNotice('');
    try {
      const value = await chatApi.connect('qwen_local');
      setConnections(old => [...old, value]); setConnectionId(value.id);
      setNotice('Connected. Press Test to check that the model responds.');
    } catch(e) { setError(formatApiError(e)); }
    finally { setConnecting(false); }
  };
  const test = async () => {
    if (!selected) return;
    setConnecting(true); setNotice('Testing the model…');
    try {
      const result = await chatApi.test(selected.id);
      setConnections(old => old.map(c => c.id === selected.id ? {...c,test_status:result.status} : c));
      setNotice(result.status === 'passed' ? 'The model responded.' : 'The model did not respond. Check that Qwen is running, then test again.');
    } catch(e) { setError(formatApiError(e)); }
    finally { setConnecting(false); }
  };
  const submit = async () => {
    if (!prompt.trim() || jobId || connecting) return;
    setError(''); setNotice('');
    if (!selected) { setPanel(true); setError('Connect the model before sending a question.'); return; }
    if (selected.test_status === 'failed') { setPanel(true); setError('The model failed its test. Fix the connection before sending a question.'); return; }
    const parsedLawDate = new Date(`${asOfDate}T00:00:00Z`);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(asOfDate) || Number.isNaN(parsedLawDate.getTime()) || parsedLawDate.toISOString().slice(0, 10) !== asOfDate) {
      setOptions(true); setError('Enter the law date as YYYY-MM-DD.'); return;
    }
    if (!consent && onlineMode !== 'local_only') {
      setOptions(true); setError('Allow online research on official sources, or choose local sources only.'); return;
    }
    if (!idempotency.current) idempotency.current = crypto.randomUUID();
    try {
      const accepted = await chatApi.ask({question:prompt.trim(), task_type:taskMode, jurisdiction, as_of_date:asOfDate, word_target:targetWords, online_mode:onlineMode, upload_ids:attachments.map(item => item.id), conversation_id:conversation, connection_id:connectionId}, idempotency.current, consent);
      const url = new URL(location.href); url.searchParams.set('conversation', conversation); window.history.replaceState({},'',url);
      setPrompt(''); setAttachments([]); setJob(null); setJobId(accepted.job_id); await refresh(conversation);
    } catch(e) { setError(formatApiError(e)); }
  };
  const attach = async (files: FileList | null) => {
    if (!files?.length) return;
    setError(''); setUploading(true);
    try {
      for (const file of Array.from(files)) {
        const stored = await api.upload(file);
        setAttachments(current => [...current, {id: stored.upload_id, name: file.name}]);
      }
      idempotency.current = '';
    } catch(e) { setError(formatApiError(e)); }
    finally { setUploading(false); if (fileInput.current) fileInput.current.value = ''; }
  };
  const detach = (id: string) => { setAttachments(current => current.filter(item => item.id !== id)); idempotency.current = ''; };
  const newChat = () => {
    const id = `conversation-${crypto.randomUUID()}`; conversationRef.current = id; setConversation(id); setMessages([]); setDraftPreviews({}); setJobId(''); setJob(null); setError(''); idempotency.current='';
    window.history.replaceState({},'', '/'); setSidebar(false);
  };
  const openConversation = (id: string) => {
    conversationRef.current = id; setConversation(id); setJobId(''); setJob(null); setSidebar(false);
    const url = new URL(location.href); url.searchParams.set('conversation', id); window.history.replaceState({}, '', url);
    void refresh(id, true).catch(e => setError(formatApiError(e)));
  };
  const chooseMode = (mode: TaskMode) => { setTaskMode(mode); setTargetWords(mode === 'essay' || mode === 'problem' ? 700 : 450); };
  const status = !selected ? 'none' : selected.test_status === 'passed' ? 'ok' : selected.test_status === 'failed' ? 'failed' : 'pending';

  return <div className="app-shell">
    <aside className={`sidebar${sidebar ? ' open' : ''}`} aria-label="Conversations">
      <div className="sidebar-top">
        <span className="brand">Law</span>
        <button className="icon-button sidebar-close" type="button" aria-label="Close conversations" onClick={() => setSidebar(false)}><Icons.close size={18}/></button>
      </div>
      <button type="button" className="new-chat" onClick={newChat}><Icons.plus size={16}/>New chat</button>
      {history.length > 0 && <p className="sidebar-label">Recent</p>}
      <nav className="chat-list">
        {history.map((item, i) => <button type="button" key={item.id} className={item.id === conversation ? 'active' : ''} onClick={() => openConversation(item.id)}>Conversation {history.length - i}</button>)}
      </nav>
      <p className="sidebar-note">Chats stay on this computer and are removed after {session?.conversation_retention_days || 30} days without a new message.</p>
    </aside>
    {sidebar && <button type="button" className="sidebar-scrim" aria-label="Close conversations" onClick={() => setSidebar(false)} tabIndex={-1}/>}
    <main className="main-panel">
      <header className="topbar">
        <button className="icon-button menu-button" type="button" aria-label="Open conversations" onClick={() => setSidebar(!sidebar)}><Icons.menu size={20}/></button>
        <span className="topbar-title">Law</span>
        <button type="button" className="model-pill" aria-expanded={panel} onClick={() => setPanel(!panel)}>
          <span className={`status-dot ${status}`} aria-hidden="true"/>
          {selected ? `Qwen · ${status === 'ok' ? 'ready' : status === 'failed' ? 'not working' : 'untested'}` : 'Not connected'}
        </button>
      </header>
      {panel && <section className="connection-panel" aria-label="Model connection">
        <div className="panel-head"><h2>Model</h2><button className="icon-button" type="button" aria-label="Close model settings" onClick={() => setPanel(false)}><Icons.close size={16}/></button></div>
        <p>Qwen runs on this computer. Your questions stay here unless you allow online research on official sources.</p>
        <label>Connection<select aria-label="Active connection" value={connectionId} onChange={e => setConnectionId(e.target.value)}><option value="">Choose connection</option>{connections.map(c => <option key={c.id} value={c.id}>{PROVIDER_LABELS[c.route_id]} · {session?.routes.find(r => r.route_id === c.route_id)?.model_id || 'unknown model'} · {c.test_status}</option>)}</select></label>
        <div className="panel-actions">
          <button type="button" className="button" disabled={connecting || !session?.routes.some(r => r.route_id === 'qwen_local')} onClick={() => void connect()}>Connect</button>
          <button type="button" className="button" disabled={!selected || connecting} onClick={() => void test()}>Test</button>
          <button type="button" className="button subtle" disabled={!selected || connecting} onClick={() => { if (selected) void chatApi.disconnect(selected.id).then(() => { setConnections(old => old.filter(c => c.id !== selected.id)); setConnectionId(''); }).catch(e => setError(formatApiError(e))); }}>Disconnect</button>
        </div>
        {selectedRoute && selected && <small>{selectedRoute.model_id}</small>}
      </section>}
      <section className="chat-content" aria-label="Conversation">
        <div className="thread">
          {!messages.length && !jobId && <div className="welcome"><h1>What would you like to ask?</h1><p>A legal question, an essay title or a problem question. Choose the answer type below.</p></div>}
          {messages.map(message => message.role === 'user'
            ? <div key={message.id} className="msg user" data-message-role={message.role} data-message-id={message.id}><div className="bubble">{message.content}</div></div>
            : <div key={message.id} className="msg assistant" data-message-role={message.role} data-message-id={message.id}>
                <div className="answer-prose"><AnswerMarkdown content={message.content} onEvidence={citation => { if (message.answer_id) setEvidence({ answerId: message.answer_id, evidenceId: citation.evidenceId, citationLabel: citation.label }); }}/></div>
                <small className="message-provenance">{message.display_origin === 'released_answer' ? 'Checked answer' : 'Clarification or incomplete result'} · {message.selected_model || message.selected_provider || 'unknown model'}</small>
                {!message.answer_id && message.job_id && draftPreviews[message.job_id] && <DraftPreviewCard preview={draftPreviews[message.job_id]}/>}
              </div>)}
          {jobId && <><JobProgress stage={job?.stage || 'queued'} detail={job?.message || 'Your question is saved. Checking sources.'} createdAt={job?.created_at} onCancel={() => void api.cancelJob(jobId).catch(e => setError(formatApiError(e)))}/>{draftPreviews[jobId] && <DraftPreviewCard preview={draftPreviews[jobId]}/>}</>}
          <div ref={end}/>
        </div>
      </section>
      <form className="composer" onSubmit={e => { e.preventDefault(); void submit(); }}>
        {error && <p className="service-alert" role="alert">{error}</p>}
        {notice && <p className="notice" role="status">{notice}</p>}
        <div className="composer-box">
          <textarea aria-label="Your legal question" placeholder="Ask a legal question…" value={prompt} rows={1} maxLength={30000}
            onChange={e => { setPrompt(e.target.value); idempotency.current = ''; e.target.style.height = 'auto'; e.target.style.height = `${Math.min(e.target.scrollHeight, 260)}px`; }}
            onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); void submit(); } }}/>
          {attachments.length > 0 && <ul className="attachments" aria-label="Attached documents">
            {attachments.map(item => <li key={item.id} className="attachment"><Icons.file size={14}/><span>{item.name}</span>
              <button type="button" aria-label={`Remove ${item.name}`} onClick={() => detach(item.id)}><Icons.close size={12}/></button></li>)}
          </ul>}
          <div className="composer-row">
            <input ref={fileInput} type="file" hidden multiple accept=".pdf,.docx,.doc,.odt,.txt,.md,.html,.htm" onChange={e => void attach(e.target.files)}/>
            <button type="button" className="icon-button attach-button" aria-label="Attach a document" title="Attach a document (PDF, Word)" disabled={uploading} onClick={() => fileInput.current?.click()}><Icons.paperclip size={18}/></button>
            <select className="chip" aria-label="Answer mode" value={taskMode} onChange={e => chooseMode(e.target.value as TaskMode)}>{TASKS.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}</select>
            <button type="button" className="chip" aria-expanded={options} onClick={() => setOptions(!options)}>Options</button>
            <span className="composer-summary">{jurisdiction} · law as of {asOfDate} · about {targetWords} words</span>
            <button className="send-button" type="submit" disabled={!prompt.trim() || Boolean(jobId) || connecting} aria-label="Send question"><Icons.send size={18}/></button>
          </div>
          {options && <div className="composer-options">
            <label>Words<input aria-label="Words" type="number" min={100} max={10000} value={targetWords} onChange={e => setTargetWords(Number(e.target.value))}/></label>
            <label>Law as of<input aria-label="Law as of" type="text" inputMode="numeric" placeholder="YYYY-MM-DD" maxLength={10} value={asOfDate} onChange={e => setAsOfDate(e.target.value)}/></label>
            <label>Jurisdiction<input aria-label="Jurisdiction" value={jurisdiction} onChange={e => setJurisdiction(e.target.value)} placeholder="e.g. England"/></label>
            <label>Sources<select aria-label="Sources" value={onlineMode} onChange={e => setOnlineMode(e.target.value as OnlineMode)}><option value="local_only">Local sources only</option><option value="auto">Local and official online sources</option></select></label>
            <label className="remote-consent"><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)}/>Allow online research on legislation.gov.uk and Find Case Law</label>
          </div>}
        </div>
        <p className="composer-foot">Answers can be wrong. Check the cited sources before relying on them.</p>
      </form>
    </main>
    {evidence && <EvidenceDrawer selection={evidence} onClose={() => setEvidence(null)}/>}
  </div>;
}
