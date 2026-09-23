# LegalBot chat UI

One Vite/React/TypeScript application serves both the owner and local testers.
There is no Operations dashboard or separate owner build. `/admin` redirects to
`/`; management APIs are disabled by default independently of the frontend.

## Run the complete local application

Use the repository's `scripts/launch_session_chat.py` with a fresh isolated state
and an existing reviewed retrieval manifest. See the repository README. The
launcher supplies the development capability privately to the API and durable
worker. The browser never receives an owner access key or authority hash.

The chat opens at `http://127.0.0.1:8777/`, with the API on loopback port 8776 and
optional pinned Qwen runtime on 8778. Codex uses the host's signed-in CLI and is a
remote model. Selecting it does not access a website visitor's own desktop CLI.

## Development commands

```bash
npm ci
npm run dev
npm run typecheck
npm run lint
npm test
```

`npm test` builds the single application and checks its public surface, safe
Markdown citations and credential handling. The API/worker must also run for
real answering. A built web page alone does not qualify the model or sources.

## Conversation and connection behavior

- Session-owned conversations, messages and matter facts live in encrypted backend storage.
- Refresh uses an opaque conversation ID. Browser history is not the model's case memory.
- Qwen, Codex, OpenAI, Claude and Gemini use the same evidence/review pipeline.
- API keys are held temporarily in encrypted server storage, or in the native OS
  credential store if **Remember connection** is selected. No keys enter browser
  storage, URLs or process-wide environment changes.
- **Test connection** invokes the selected model. Passing does not establish legal quality.
- **Indexed sources only** and **Index + online research** are explicit choices.
  Remote models/research require consent. Fetching a page is not source approval.
- A host clarification or evidence hold is labelled separately from a released
  model answer. Selected model identity is displayed on each assistant message.
- Rendered transcript receipts are encrypted diagnostic records; they are
  client observations, not legal verification or publication authority.

Raw private transcripts, API keys and licence documents must not enter Git.
Public hosting, user accounts and visitor-owned desktop connections are later work.
