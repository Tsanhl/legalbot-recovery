import type { QuestionRequest, QuestionAccepted, DevelopmentRouteId } from './contracts';

export interface Connection { id: string; route_id: DevelopmentRouteId; remembered: boolean; expires_at: number; test_status: string }
export interface ChatMessage { id: string; role: 'user'|'assistant'; content: string; job_id: string|null; answer_id: string|null; selected_provider?:string; selected_model?:string; publication_status?:string; display_origin?:string }
export interface ChatWindow { conversation_id: string; messages: ChatMessage[]; truncated: boolean; jobs: {id: string; status: string; stage: string; connection_id: string; jurisdiction: string; as_of_date: string; task_type: string; word_target: number}[] }
export interface ChatSession { connections: Connection[]; routes: {route_id: DevelopmentRouteId; model_id: string; kind: string}[]; online_research_available: boolean; coverage: string }
export type DraftPreview =
  | { available: false; reason: string }
  | { available: true; status: 'unverified_draft'; job_status: string; version: number; model_version: string; word_count: number; content: string; review_findings: {code:string;message:string}[]; review_complete: boolean; not_conversation_history: true; not_released_answer: true };
async function call<T>(path: string, body?: unknown, headers: Record<string,string> = {}): Promise<T> {
  const response = await fetch(`/api/v1/chat${path}`, { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: {'Content-Type':'application/json', ...headers}, ...(body === undefined ? {} : {body: JSON.stringify(body)}) });
  const result = await response.json();
  if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : `Request failed (${response.status})`);
  return result;
}
export const chatApi = {
  session: () => call<ChatSession>('/session', {}),
  connect: (route_id: string, api_key: string, remember: boolean) => call<Connection>('/connections', {route_id, ...(api_key ? {api_key} : {}), remember}),
  disconnect: (id: string) => call(`/connections/${encodeURIComponent(id)}/disconnect`, {}),
  test: (id: string) => call<{status:string}>(`/connections/${encodeURIComponent(id)}/test`, {}),
  conversations: () => call<{items:{id:string}[]}>('/conversations'),
  conversation: (id: string) => call<ChatWindow>(`/conversations/${encodeURIComponent(id)}`),
  draftPreview: (jobId: string) => call<DraftPreview>(`/jobs/${encodeURIComponent(jobId)}/draft-preview`),
  displayReceipt: (id:string, messages:{id:string;role:string;text:string}[]) => call(`/conversations/${encodeURIComponent(id)}/display-receipts`, {messages}),
  ask: (body: QuestionRequest & {connection_id:string}, idempotency: string, consent: boolean) => call<QuestionAccepted>('/questions', body, {'X-Idempotency-Key':idempotency, 'X-Remote-Processing-Consent':consent?'yes':'no'}),
};
