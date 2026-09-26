# ASKQ frontend

React 19 + Vite + TypeScript. See the root [README](../README.md) for setup.

| Command | Purpose |
|---|---|
| `npm run dev` | Dev server on http://localhost:5173 (proxies `/api` and `/health` to the backend) |
| `npm test` | Run Vitest tests once |
| `npm run lint` | Lint with oxlint |
| `npm run typecheck` | TypeScript type check |
| `npm run build` | Type check + production build into `dist/` |

Structure:

- `src/api/`: typed client for the backend API
- `src/test/`: test setup (jest-dom matchers, cleanup)
- `src/App.tsx`: current Phase 1 smoke page (shows backend health)
