# Counsel web interface

A clean-room Vite/React/TypeScript single-page interface for the local Counsel
legal research service. The browser consumes the FastAPI `/api/v1` surface; the
backend remains the only source of truth for conversations, jobs, answers,
evidence and operator status.

## Prerequisites

- Node.js 24 LTS

## Quick Start

```bash
npm ci
npm run dev
npm run build
npm start
```

Development and Vite preview bind the owner interface to
`http://127.0.0.1:8777`. Both proxy `/api` directly to the development FastAPI
service at `http://127.0.0.1:8776`, including uploads and SSE job events.

For the production-style local application, `npm run build` creates `dist/`
and the repository-level `scripts/start.sh` makes FastAPI serve the SPA and API
from the single origin `http://127.0.0.1:8777`. No Vite server or CORS proxy is
used in production.

## Application shape

- `/` provides task selection, jurisdiction, uploads, durable job progress,
  immutable Markdown answers and claim-level evidence inspection.
- `/admin` provides source inventory, hybrid-index, subject coverage, gap,
  quality and human-review views.
- `src/main.tsx` selects the owner view from the browser pathname.
- `app/lib/api.ts` is the single versioned FastAPI client boundary.
- `vite.config.ts` owns the loopback-only ports and `/api` proxy.
- Set `VITE_LEGAL_API_BASE` only to bypass same-origin `/api/v1` during
  specialized local development.

This build is local owner-only. It intentionally contains no application auth,
cloud identity, local database or browser-side persistence.

## Useful Commands

- `npm run dev`: start local development
- `npm run build`: type-check and create the static Vite build
- `npm start`: preview `dist/` locally with the API proxy
- `npm run lint`: run the TypeScript/React accessibility rules
- `npm run typecheck`: run strict TypeScript checking
- `npm test`: rebuild and verify the SPA, routes and API boundaries

There is no browser database, local storage, Cloudflare runtime, Next.js server
or cloud identity dependency in this interface.
