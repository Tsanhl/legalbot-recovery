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
  { value: "problem", label: "Problem", description: "Issues, rules, application and outcome" },
  { value: "general", label: "General", description: "Clear, authoritative explanation" },
];

const PROVIDER_LABELS: Record<DevelopmentRouteId, string> = {
  codex_bridge: "Codex",
  codex_bridge_sol: "Codex",
  codex_bridge_astra: "Codex",
  codex_bridge_luna: "Codex",
  qwen_local: "Local Qwen",
  local_endpoint: "Local endpoint",
  hosted_api: "OpenAI API",
  anthropic_api: "Claude API",
  gemini_api: "Gemini API",
};

const CODEX_MODELS = [
  { id: "gpt-6-sol", label: "6 Sol" },
  { id: "gpt-6-astra", label: "6 Astra" },
  { id: "gpt-6-luna", label: "6 Luna" },
] as const;

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

function stageIndex(stage: JobStage): number {
  return ["queued", ...PROGRESS_STAGES, "complete"].indexOf(stage);
}

function JobProgress({ stage, detail, createdAt }: { stage: JobStage; detail: string; createdAt?: string }) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const elapsed = createdAt ? Math.max(0, Math.floor((now - Date.parse(createdAt)) / 1000)) : 0;
  const current = stageIndex(stage);
  return (
    <div className="job-card" role="status" aria-live="polite">
      <div className="job-card-head">
        <div className="job-orb"><span /></div>
        <div>
          <strong>{STAGE_LABELS[stage]}</strong>
          <p>{detail || "Working locally. You can leave this page and reconnect to the same job."}</p>
        </div>
        <strong aria-label="Elapsed time">{Math.floor(elapsed / 60)}m {elapsed % 60}s</strong>
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

type VisibleDraft = Extract<DraftPreview, {available: true}>;

function DraftPreviewCard({ preview }: { preview: VisibleDraft }) {
  return <details className="draft-preview" aria-label="Private diagnostic draft">
    <summary>Private diagnostic draft — unverified</summary>
    <p>This is the model’s saved text, not a released legal answer. It may contain errors or unsupported claims. It is not added to the case facts for follow-up questions.</p>
    <small>{preview.model_version} · version {preview.version} · {preview.word_count} words · {preview.review_complete ? 'Review findings below' : 'Review in progress'}</small>
    <pre>{preview.content}</pre>
    {preview.review_findings.length > 0 && <details><summary>Why this draft was held ({preview.review_findings.length} findings shown)</summary><ul>{preview.review_findings.map((finding, i) => <li key={`${finding.code}-${i}`}><strong>{finding.code}:</strong> {finding.message}</li>)}</ul></details>}
  </details>;
}

export function LegalBotApp() {
  const [session, setSession] = useState<ChatSession | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [connectionId, setConnectionId] = useState("");
  const [route, setRoute] = useState<DevelopmentRouteId>("codex_bridge");
  const [apiKey, setApiKey] = useState("");
  const [remember, setRemember] = useState(false);
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
  const [evidence, setEvidence] = useState<EvidenceSelection | null>(null);
  const idempotency = useRef("");
  const end = useRef<HTMLDivElement>(null);
  const conversationRef = useRef(conversation);
  const selected = connections.find(c => c.id === connectionId);
  const selectedRoute = session?.routes.find(r => r.route_id === selected?.route_id);
  const codexRoutes = session?.routes.filter(r => r.kind === 'codex_bridge') || [];

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
      setConnectionId(value.connections.find(c => c.route_id === 'codex_bridge')?.id || value.connections[0]?.id || '');
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
      const connectRoute = route === 'codex_bridge' && selectedRoute?.kind === 'codex_bridge'
        ? selectedRoute.route_id : route;
      const value = await chatApi.connect(connectRoute, apiKey, remember);
      setApiKey(''); setConnections(old => [...old, value]); setConnectionId(value.id);
      setNotice('Connection saved. Run Test connection to check a real model response.');
    } catch(e) { setError(formatApiError(e)); }
    finally { setConnecting(false); }
  };
  const chooseCodexModel = async (modelId: string) => {
    if (jobId || connecting) return;
    const target = codexRoutes.find(item => item.model_id === modelId);
    if (!target) return;
    setError(''); setNotice('');
    const existing = connections.find(item => item.route_id === target.route_id);
    if (existing) { setConnectionId(existing.id); idempotency.current = ''; return; }
    setConnecting(true);
    try {
      const value = await chatApi.connect(target.route_id, '', false);
      setConnections(old => [...old, value]);
      setConnectionId(value.id);
      idempotency.current = '';
      setNotice(`${modelId} selected for the next question. Run Test connection to check model access.`);
    } catch(e) { setError(formatApiError(e)); }
    finally { setConnecting(false); }
  };
  const test = async () => {
    if (!selected) return;
    setConnecting(true); setNotice('Testing a short model response…');
    try {
      const result = await chatApi.test(selected.id);
      setConnections(old => old.map(c => c.id === selected.id ? {...c,test_status:result.status} : c));
      setNotice(result.status === 'passed' ? 'Model responded. Legal answer quality is checked separately.' : 'Model test failed. This connection cannot answer questions; check model access or choose another connection.');
    } catch(e) { setError(formatApiError(e)); }
    finally { setConnecting(false); }
  };
  const submit = async () => {
    if (!prompt.trim() || jobId || connecting) return;
    if (/^(link|connect|use) (codex|claude|gemini|api|local model)[.!?]?$/i.test(prompt.trim())) {
      const text = prompt.toLowerCase();
      setRoute(text.includes('claude')?'anthropic_api':text.includes('gemini')?'gemini_api':text.includes('api')?'hosted_api':text.includes('local')?'qwen_local':'codex_bridge');
      setPanel(true); setPrompt(''); return;
    }
    setError(''); setNotice('');
    if (!selected) { setPanel(true); setError('Connect a model before sending your question.'); return; }
    if (selected.test_status === 'failed') { setPanel(true); setError('This model failed its connection test. Choose a working connection before sending your question.'); return; }
    const parsedLawDate = new Date(`${asOfDate}T00:00:00Z`);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(asOfDate) || Number.isNaN(parsedLawDate.getTime()) || parsedLawDate.toISOString().slice(0, 10) !== asOfDate) {
      setError('Enter the law date as YYYY-MM-DD.'); return;
    }
    if (!consent && (selected.route_id !== 'qwen_local' || onlineMode !== 'local_only')) {
      setError('Confirm remote processing, or choose local Qwen with indexed sources only.'); return;
    }
    if (!idempotency.current) idempotency.current = crypto.randomUUID();
    try {
      const accepted = await chatApi.ask({question:prompt.trim(), task_type:taskMode, jurisdiction, as_of_date:asOfDate, word_target:targetWords, online_mode:onlineMode, upload_ids:[], conversation_id:conversation, connection_id:connectionId}, idempotency.current, consent);
      const url = new URL(location.href); url.searchParams.set('conversation', conversation); window.history.replaceState({},'',url);
      setPrompt(''); setJob(null); setJobId(accepted.job_id); await refresh(conversation);
    } catch(e) { setError(formatApiError(e)); }
  };
  const newChat = () => {
    const id = `conversation-${crypto.randomUUID()}`; conversationRef.current = id; setConversation(id); setMessages([]); setDraftPreviews({}); setJobId(''); setJob(null); setError(''); idempotency.current='';
    window.history.replaceState({},'', '/'); setSidebar(false);
  };
  const chooseMode = (mode: TaskMode) => { setTaskMode(mode); setTargetWords(mode === 'essay' || mode === 'problem' ? 700 : 450); };
  return <div className="app-shell">
    {sidebar && <aside className="sidebar"><button type="button" onClick={newChat}>New conversation</button><h2>Saved conversations</h2><p>Private chats expire after {session?.conversation_retention_days || 30} days without a new message.</p>{history.map((item, i) => <button type="button" key={item.id} onClick={() => { conversationRef.current = item.id; setConversation(item.id); setJobId(''); setJob(null); setSidebar(false); const url=new URL(location.href); url.searchParams.set('conversation',item.id); window.history.replaceState({},'',url); void refresh(item.id, true).catch(e=>setError(formatApiError(e))); }}>Conversation {history.length-i}</button>)}</aside>}
    <main className="main-panel">
      <header className="topbar"><button className="icon-button" type="button" aria-label="Open conversations" onClick={()=>setSidebar(!sidebar)}><Icons.menu size={22}/></button>
        <nav className="task-switcher" aria-label="Answer mode">{TASKS.map(item=><button type="button" className={taskMode===item.value?'active':''} key={item.value} onClick={()=>chooseMode(item.value)}>{item.label}</button>)}</nav>
        <button type="button" className="text-button" onClick={()=>setPanel(!panel)}>Model connection</button>
      </header>
      {panel && <section className="connection-panel" aria-label="Model connection">
        <h2>Choose your model</h2>
        <p>Codex uses this Mac’s signed-in CLI and a remote model. Qwen runs on this Mac. API keys belong to this browser session.</p>
        <label>Provider<select aria-label="Provider" value={route} onChange={e=>{setRoute(e.target.value as DevelopmentRouteId);setApiKey('');}}>
          <option value="codex_bridge">Codex</option><option value="qwen_local">Local Qwen</option><option value="hosted_api">OpenAI API</option><option value="anthropic_api">Claude API</option><option value="gemini_api">Gemini API</option>
        </select></label>
        <p>{(route === 'codex_bridge' && selectedRoute?.kind === 'codex_bridge' ? selectedRoute : session?.routes.find(r=>r.route_id===route))?.model_id || 'This provider has not been configured by the local launcher.'}</p>
        {['hosted_api','anthropic_api','gemini_api'].includes(route) && <><label>API key<input aria-label="API key" type="password" autoComplete="off" value={apiKey} onChange={e=>setApiKey(e.target.value)}/></label><label><input type="checkbox" checked={remember} onChange={e=>setRemember(e.target.checked)}/>Remember connection in the operating system credential store</label></>}
        <button type="button" disabled={connecting||!session?.routes.some(r=>r.route_id===route)} onClick={()=>void connect()}>Connect</button>
        <label>Active connection<select aria-label="Active connection" value={connectionId} onChange={e=>setConnectionId(e.target.value)}><option value="">Choose connection</option>{connections.map(c=><option key={c.id} value={c.id}>{PROVIDER_LABELS[c.route_id]} · {session?.routes.find(r=>r.route_id===c.route_id)?.model_id || 'unknown model'} · {c.test_status}</option>)}</select></label>
        <button type="button" disabled={!selected||connecting} onClick={()=>void test()}>Test connection</button>
        <button type="button" disabled={!selected||connecting} onClick={()=>{if(selected) void chatApi.disconnect(selected.id).then(()=>{setConnections(old=>old.filter(c=>c.id!==selected.id));setConnectionId('');}).catch(e=>setError(formatApiError(e)));}}>Disconnect</button>
      </section>}
      <div className="connection-status" role="status">{selectedRoute && selected ? `${PROVIDER_LABELS[selected.route_id]} · ${selectedRoute.model_id} · ${selected.test_status === 'passed' ? 'connection tested' : selected.test_status === 'failed' ? 'connection failed' : 'connection test pending'}` : 'No model connected'} · UK and USA coverage is checked per question.</div>
      <section className="chat-content" aria-label="Conversation">
        {!messages.length && <section className="welcome"><div className="welcome-mark">A</div><p className="eyebrow">Evidence before assertion</p><h1>Legal research you can inspect.</h1><p>Ask for a critical essay, problem analysis or clear explanation. Inspect the sources used and any remaining limitations.</p><div className="starter-grid">{STARTERS.map(item=><button key={item.mode} type="button" className="starter-card" onClick={()=>chooseMode(item.mode)}><span><item.icon size={24}/></span><strong>{item.title}</strong><p>{item.copy}</p></button>)}</div><p>Claim-level evidence · Full OSCOLA by default · Advisory academic guidance</p></section>}
        {messages.map(message=><article key={message.id} className={message.role==='user'?'question-card':'answer-card'} data-message-role={message.role} data-message-id={message.id}><header>{message.role==='user'?'You':'LegalBot'}</header>{message.role==='assistant'&&<small className="message-provenance">Selected: {message.selected_model || message.selected_provider || 'unknown'} · {message.display_origin==='released_answer'?'Reviewed answer':'System clarification or incomplete result'}</small>}<div className="answer-prose"><AnswerMarkdown content={message.content} onEvidence={citation=>{if(message.answer_id)setEvidence({answerId:message.answer_id,evidenceId:citation.evidenceId,citationLabel:citation.label});}}/></div>{message.role==='assistant' && !message.answer_id && message.job_id && draftPreviews[message.job_id] && <DraftPreviewCard preview={draftPreviews[message.job_id]}/>}</article>)}
        {jobId && <><JobProgress stage={job?.stage||'queued'} detail={job?.message||'Your question is saved. Checking sources and selected model.'} createdAt={job?.created_at}/>{draftPreviews[jobId] && <DraftPreviewCard preview={draftPreviews[jobId]}/>}<button type="button" onClick={()=>void api.cancelJob(jobId).catch(e=>setError(formatApiError(e)))}>Cancel</button></>}
        <div ref={end}/>
      </section>
      <form className="composer" onSubmit={e=>{e.preventDefault();void submit();}}>
        {error && <p className="service-alert" role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
        <textarea aria-label="Your legal question" placeholder="Ask your legal question…" value={prompt} onChange={e=>{setPrompt(e.target.value);idempotency.current='';}} maxLength={30000} rows={4}/>
        <div className="composer-controls"><label>Words<input aria-label="Words" type="number" min={100} max={10000} value={targetWords} onChange={e=>setTargetWords(Number(e.target.value))}/></label>{selectedRoute?.kind === 'codex_bridge' && <label>Model<select aria-label="Codex model" value={selectedRoute.model_id} onChange={e=>void chooseCodexModel(e.target.value)} disabled={Boolean(jobId)||connecting}>{!CODEX_MODELS.some(item=>item.id===selectedRoute.model_id) && <option value={selectedRoute.model_id}>{selectedRoute.model_id} (configured)</option>}{CODEX_MODELS.map(item=><option key={item.id} value={item.id} disabled={!codexRoutes.some(route=>route.model_id===item.id)}>{item.label}{codexRoutes.some(route=>route.model_id===item.id)?'':' (next session)'}</option>)}</select></label>}<label>Law as of<input aria-label="Law as of" type="text" inputMode="numeric" placeholder="YYYY-MM-DD" maxLength={10} value={asOfDate} onChange={e=>setAsOfDate(e.target.value)}/></label><label>Jurisdiction<input aria-label="Jurisdiction" value={jurisdiction} onChange={e=>setJurisdiction(e.target.value)} placeholder="Country and state or UK nation"/></label><label>Sources<select aria-label="Sources" value={onlineMode} onChange={e=>setOnlineMode(e.target.value as OnlineMode)}><option value="local_only">Indexed sources only</option><option value="auto">Index + online research</option></select></label></div>
        <label className="remote-consent"><input type="checkbox" checked={consent} onChange={e=>setConsent(e.target.checked)}/>Allow this question and selected context to be processed by the chosen remote provider and official-source research services</label>
        <button className="send-button" type="submit" disabled={!prompt.trim()||Boolean(jobId)||connecting} aria-label="Send question"><Icons.send size={22}/></button>
      </form>
    </main>
    {evidence && <EvidenceDrawer selection={evidence} onClose={()=>setEvidence(null)}/>}
  </div>;
}
