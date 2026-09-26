# ASKQ architecture

ASKQ (Ask Questions to your Data) turns natural-language questions into SQL,
and runs a query only after it passes validation, role-based authorization and
CAIR (Conversation-Aware Inference Risk) analysis.

## Components

| Component | Technology | Responsibility |
|---|---|---|
| Frontend | React 19 + Vite + TypeScript | Presentation only; never makes security decisions |
| Backend | Python 3.13 + FastAPI | Authentication, pipeline orchestration, all enforcement |
| LLM | Claude API | Translates questions into candidate SQL (treated as **untrusted**) |
| SQL safety | sqlglot | Parses SQL to an AST; enforces single read-only SELECT |
| RBAC | Backend policy module | Table/column/aggregate checks; server-side row-scope rewriting |
| CAIR | Backend module | Per-user knowledge ledger + six inference audits → ALLOW / RESTRICT / BLOCK |
| Database | MySQL 8 | `askq_university` (org data), `askq_system` (history, ledger, eval) |

## Request pipeline

```
Browser ──JSON + JWT──► FastAPI
  1. Authenticate      verify JWT → user id, role, department/student/teacher scope
  2. Context           load recent conversation turns
  3. Generate          Claude: question + context + schema visible to this role → SQL text
  4. Validate          parse; exactly one SELECT; no DDL/DML, stacked statements,
                       system schemas or file I/O; enforce row LIMIT
  5. Authorize         every table/column/aggregate checked against role policy;
                       row-scope predicates injected server-side
  6. CAIR              descriptor from the *rewritten* AST vs. user's ledger
                       → risk score + reasons → ALLOW / RESTRICT / BLOCK
  7. Execute           SELECT-only DB account, statement timeout
  8. Record            ledger update, query history, security audit
  ◄── {sql, columns, rows, chart hint, decision, risk score, reasons}
```

## Security principles

- **LLM output is never trusted.** It is parsed, validated, authorised and rewritten before execution.
- **Defence in depth.** Even if validation had a bug, the `askq_reader` MySQL
  account has SELECT privilege only on `askq_university`.
- **Backend-only enforcement.** Frontend route guards exist for usability, not security.
- **Context supplies meaning, never permission.** Every follow-up question is
  re-authorised and re-audited from scratch.
- **Deterministic, explainable CAIR.** Descriptors come from the parsed SQL, not
  from the LLM, so the same query sequence always produces the same decision.
- **Honest limits.** CAIR is a heuristic risk detector, not a formal privacy guarantee.
