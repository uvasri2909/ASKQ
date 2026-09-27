# ASKQ frontend

React 19 + Vite + TypeScript. See the root [README](../README.md) for setup and
[docs/architecture.md](../docs/architecture.md#frontend-phase-6) for the design.

| Command | Purpose |
|---|---|
| `npm run dev` | Dev server on http://localhost:5173 (proxies `/api` and `/health` to the backend) |
| `npm test` | Run Vitest tests once |
| `npm run lint` | Lint with oxlint |
| `npm run typecheck` | TypeScript type check |
| `npm run build` | Type check + production build into `dist/` |

## Environment variables (optional)

| Variable | Used by | Default | Purpose |
|---|---|---|---|
| `VITE_BACKEND_URL` | `vite.config.ts` (dev server only) | `http://127.0.0.1:8000` | Where the dev proxy forwards `/api` and `/health` |
| `VITE_API_BASE_URL` | the browser bundle | empty (same origin) | Prefix for API calls when the backend is served elsewhere (add that origin to the backend's `CORS_ORIGINS`) |

Every `VITE_*` value is compiled into public JavaScript. **Never** put API keys,
database credentials, JWT secrets or passwords in a frontend variable. The
frontend needs none.

## Structure

- `src/api/`: `client.ts` (the only place that calls `fetch`), `validate.ts`
  (runtime checks for every response), `askq.ts` (endpoint functions), `types.ts`
- `src/auth/`: session context (current user; token held in memory only)
- `src/components/`: login page, app shell, Ask page, result card/table/chart,
  history, profile, status widgets
- `src/test/`: test setup and `mockApi.ts` (fetch mock + sample responses)

## Security rules the code follows

- Requests carry only what the user typed (question, conversation id) plus the
  bearer token. Role, scope, SQL and decisions always come from the backend.
- No `dangerouslySetInnerHTML`, no web storage for the token, `credentials: 'omit'`.
- The API sends no SQL, risk scores or reason codes (Phase 6), and the validator
  would drop them anyway. 5xx error bodies are never displayed; unexpected response
  shapes are rejected as "unexpected response".
