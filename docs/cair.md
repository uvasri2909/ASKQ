# CAIR: Conversation-Aware Inference Risk

CAIR judges what a user could **learn** from an answer when it's combined with
what they already learned, can already see, or were refused. A question can be
harmless on its own and dangerous as the next step of a conversation, and CAIR
looks at it in that context.

This document describes what is implemented (Phase 5, policy `cair-1.0`).
Code: `backend/app/cair/`, `backend/app/query/statistics.py`,
`backend/app/evaluation/`. Scenarios: [attack-scenarios.md](attack-scenarios.md).

## Where CAIR sits

```
authenticate → SQL validation → authorization ─┬─ RECORD tier (Phase 4 row scope)
                                               └─ STATISTICAL tier (aggregate-only)
             → CAIR guard → execute as askq_reader → record (askq_app)
```

CAIR runs **after** validation and authorization, and it can only make a
result smaller:
- **ALLOW** runs the query as authorized.
- **RESTRICT** withholds groups of the result. The restricted SQL goes through
  validation and authorization again.
- **BLOCK** runs nothing.

CAIR never grants access, widens a scope or overrides RBAC. Its inputs are the
parsed SQL, server-computed populations and server-side history. It never uses
the model's explanation, the question text as a signal, or anything supplied
by the client.

### The two tiers

- **RECORD** (Phase 4, unchanged): a user reads individual rows within their
  row scope. Anything they could infer is already theirs to see, so CAIR's
  answer is always ALLOW.
- **STATISTICAL** (Phase 5): HOD, TEACHER and STUDENT users may ask for
  **aggregates over the whole university**. This is new capability, so it's
  only offered while CAIR is enabled (`CAIR_ENABLED=true`). Otherwise
  "university" questions fall back to the record tier. Its authorizer
  (`app/query/statistics.py`) enforces the following on the SQL:
  - **Tables:** statistical tables only (never `teachers`).
  - **Identifiers:** no direct identifiers anywhere (names, e-mail,
    student/employee numbers, date of birth, receipt numbers, salary).
  - **Record keys:** `student_id`, `enrollment_id`, … may only join tables
    (column = column) or be counted. They may not be compared with a literal
    (targeting one person), summed, projected, grouped or ordered by.
  - **Aggregate-only output:** every output is an aggregate or a GROUP BY key.
    Not GROUP_CONCAT, window functions or DISTINCT rows.
  - **Contributors = population.** The people behind every aggregate must be
    exactly the population that CAIR and the minimum-size rule reason about.
    So the tier refuses:
    - any subquery, derived table or CTE;
    - any join other than a plain `INNER JOIN … ON/USING`;
    - person-bearing tables that aren't all joined on the **same person**
      (checked by key equalities on `student_id` / `enrollment_id` / `fee_id`);
    - aggregate arguments other than `*`, a column or `DISTINCT column`,
      anywhere in the query. No CASE, IF, comparisons, arithmetic or NULLIF
      inside an aggregate.

    It also adds `<column> IS NOT NULL` for every aggregated column.
  - **Minimum group size:** `HAVING COUNT(DISTINCT <person>) >= k` is added to
    every statistical SELECT, so a statistic about fewer than
    `CAIR_MIN_GROUP_SIZE` (default 5) people is never returned. A small group
    and an empty group look the same: both are absent. A user-written HAVING is
    parenthesised and combined with AND, so it can't lower the threshold.
  - **Refuse rather than guess.** A shape these rules can't vouch for is refused
    (`STATISTICS_UNSUPPORTED` / `STATISTICS_AGGREGATE_ONLY`); it is never
    assessed optimistically.

**Who decides the tier.** The model marks each query's `population` as `scope`
or `university`. That only picks which of the user's two server-defined views
the question uses:
- **Eligibility is server-controlled:** only HOD, TEACHER and STUDENT, and only
  while CAIR is enabled. ADMIN is always in the record tier.
- **Both views are enforced on the SQL.** A query that doesn't meet the tier's
  rules is DENIED, never silently widened.
- **The client can't choose:** the request accepts no tier, mode or state (422).

**Security review (Phase 5).** An adversarial review found that the first
version of the tier trusted the outer FROM/WHERE population. It accepted shapes
in which the people contributing to an aggregate differ from that population.
In one example, `AVG(CASE WHEN <one student> THEN balance END)` over everyone
returned one student's balance on real data. The contributors = population
rules above close that class. `tests/test_cair_adversarial.py` asserts that 36
such shapes are refused and 12 legitimate shapes still work.

## Threat model

**Attacker.** An authenticated HOD, TEACHER or STUDENT who controls their
questions (and, through them, the model's SQL). They can:
- ask many questions, in one or many conversations;
- see every response, including refusals;
- combine answers with what they may already read at record level.

**Protected.** Any statistic about fewer than *k* people whose records the
attacker may not read. That includes values (marks, balances, award amounts,
attendance), attribute membership (gender, residency, region), and the size
of such a group, including whether it's empty.

**Out of scope.**
- Timing side channels.
- Collusion between different accounts: CAIR's history is per user.
- Background knowledge the system never saw.
- Attacks that need more than `CAIR_WINDOW_QUERIES` statistical questions or
  longer than `CAIR_WINDOW_HOURS`.

CAIR is a deterministic, explainable heuristic, not a differential-privacy
guarantee.

## Descriptor (`descriptor.py`)

Derived from the validated query tree only. Every list is sorted, so the
same query always yields the same JSON. Fields:
- `tables`, `columns` (resolved to `table.column` through aliases);
- `predicates` (op, columns, literal values), `filter_dimensions`,
  `group_dimensions`;
- `aggregates`, and `measures` of the form `kind:metric`. The kinds are `count`,
  `sum` (SUM and AVG, since an average times a count is a sum), `min`, `max` and
  `spread`;
- `ordering`, `limit`, `exposes` (count / sum / average / min_max / records /
  existence);
- `quasi_identifiers` and `sensitive_metrics` used;
- `tier`, `role`, and the server-side `scope`.

## Populations (`population.py`)

*Who* a statistic is about is computed, not guessed. For each output SELECT,
CAIR derives a probe:

```sql
SELECT DISTINCT <group expressions>, <person id> AS cair_subject
FROM <same FROM / JOINs> WHERE <same WHERE>      -- no HAVING, ORDER BY, LIMIT
```

The probe:
- **Source:** built from the **authorized** tree, so it can't see more rows than
  the query.
- **Output:** person ids only.
- **Checks and execution:** it passes the SQL validator and runs as
  `askq_reader` with the statement timeout.

The person id comes straight from tables that carry `student_id`. Grades,
attendance and payments reach it through a correlated lookup on `enrollments`
or `fees`.

Each output row's population is a **cell**. The people the user can already see
(`known`) are computed the same way, by authorizing the same query in the
**record** tier.

**What's stored.** Ids are kept only in memory. What's stored is the probe SQL,
cell sizes and a SHA-256 population fingerprint. Earlier populations are
recomputed from the stored probes, so the ledger never holds lists of people.

## Conversation security state (`state.py`)

Rebuilt for every question from `askq_system`: the `cair_assessments` CAIR
wrote, joined with `query_history` for ownership and outcome.
- **Window:** the user's last `CAIR_WINDOW_QUERIES` (default 20) statistical
  questions within `CAIR_WINDOW_HOURS` (default 24). It spans **all** of the
  user's conversations, because switching conversation must not reset what
  CAIR remembers. CONTEXT_CARRYOVER additionally uses the current conversation.
- **What counts as revealed:** only executed queries' cells of at least k
  people, minus any groups CAIR withheld. Refused queries count as refusals.
- **Client input:** the request model accepts only `question` and
  `conversation_id`. Scores, decisions, "revealed facts" or state sent by a
  client are rejected (422).

## The six audits (`detectors.py`)

Notation: *k* is the minimum group size; U = unknown people (the people in a set
minus those the user may already see). **Leak** means a statistic about 1..k−1
unknown people.

| Audit | Triggers when (implemented rule) |
|---|---|
| **NARROWING** | The query would reveal **no** cell of at least k people (a small *or* empty population, treated alike). Refinement chains (earlier supersets with fewer dimensions) are reported as evidence. |
| **DIFFERENCING** | A revealed cell is a strict subset or superset of an earlier (or sibling) revealed cell with a **common measure**, and the difference holds 1..k−1 unknown people. |
| **ARITHMETIC_RECOVERY** | For a sum-like measure (COUNT, SUM, AVG), a revealed **parent** cell minus disjoint revealed **part** cells (chosen greedily, largest first) leaves 1..k−1 unknown people. This covers total − subtotals, complementary groups, and defeating small-group suppression. The current question must contribute the parent or a part. |
| **CROSS_VIEW_LINKING** | A revealed cell of at least k people contains people the user can see record by record, leaving only 1..k−1 unknown: the record view and the statistical view combined isolate them. |
| **REFUSAL_SIDE_CHANNEL** | At least `CAIR_REFUSAL_PROBE_LIMIT` (default 3) earlier statistical questions over overlapping attributes (dimension Jaccard ≥ 0.5) were refused. Probing the refusal boundary is itself refused. |
| **CONTEXT_CARRYOVER** | Every unknown person the question is about was singled out by an earlier turn of **this** conversation: a refused or sub-k population. |

**Scoring.**
- **Small-set rules:** these score 0.8 (k−1 unknown people) up to 1.0 (one
  person).
- **Narrowing:** 1.0 when triggered, otherwise ≤ 0.45 from the refinement chain.
- **Context carryover:** 0.9.
- **Refusal side channel:** grows with the number of related refusals.
- **Threshold:** a finding counts as triggered at score ≥
  `CAIR_TRIGGER_THRESHOLD` (default 0.5).

## Risk and decision (`scoring.py`)

```
risk = 1 − Π (1 − score_i)          over all six audits
level: LOW < 0.3 ≤ MEDIUM < 0.7 ≤ HIGH
```

1. **Nothing triggered:** ALLOW.
2. **NARROWING or REFUSAL_SIDE_CHANNEL triggered**, or an **ungrouped** query:
   BLOCK. There's no safe part to return.
3. **Grouped query:** withhold the groups the findings implicate. For
   arithmetic recovery this includes **complementary suppression**: the
   smallest visible parts are withheld until what can't be subtracted holds at
   least k unknown people. Then all six audits are re-run on what remains
   (up to 5 rounds). If a safe, non-empty result remains, the answer is
   RESTRICT; otherwise BLOCK.

Restriction adds `HAVING NOT (<group> = <value>)` to the **user's** query. The
pipeline validates and authorizes that SQL again, re-applying the minimum group
size, before it may run. The guard's output is never trusted to be narrower.

## Refusal uniformity

- **One BLOCK message:** every CAIR BLOCK has the same message and reason code
  (`INFERENCE_RISK`, stored in `query_history.error_code`; since Phase 6 no
  reason code is returned to the client), empty rows, no SQL and no timing,
  whichever audit fired.
  A 0-person and a 1-person group get identical responses; the tests compare
  them field by field.
- **No score, reasons or SQL:** the response carries neither the risk score nor
  the internal reasons. Since Phase 6 it carries no SQL either, because a
  statistical query's SQL states k and a RESTRICT query's SQL names the withheld
  group. Guard reasons pass an allowlist. `guard_reasons` is one fixed sentence per decision. Detector
  outcomes, thresholds and evidence are stored server-side only (in
  `cair_audit_findings` and the logs).
- **k is not stated:** the statistical tier's note never states k.
- **Earlier layers:** validation already answers "data not available" alike
  for protected, system and non-existent tables.

## What is recorded

All writes go through `askq_app`, in the same transaction as the query's history
row.

| Table | Content |
|---|---|
| `query_history` | Decision (`cair_decision`), risk score, `final_status`, generated and executed SQL. For statistical queries, `authorization_status` is `ALLOWED`. |
| `cair_assessments.reasons` | JSON: tier, decision, risk level, triggered classes, public reason, probe SQL, known-people probe SQL, measures, dimensions, withheld groups, cell sizes, full descriptor. |
| `cair_audit_findings` | Six rows per statistical question: audit type, score, triggered, internal explanation, evidence (sizes and counts only). |
| `cair_ledger_entries` | Executed statistical questions only (what the user learned): descriptor, probe SQL, population fingerprint, result cardinality. |
| `security_audit_log` | `QUERY_BLOCKED` for every block. |

None of these tables store passwords, tokens, keys, result rows or lists of people.

## Evaluation

`backend/app/evaluation/` runs deterministic scenarios through the real
pipeline. The model is replaced by the scenario's SQL; everything else is real.
Each scenario runs in its own savepoint, and the whole run is rolled back.

```powershell
cd C:\ASKQ\backend
.\.venv\Scripts\python -m app.evaluation            # CAIR and NO_CONTROL (B0)
.\.venv\Scripts\python -m app.evaluation --mode ALL # CAIR, K_ONLY (B1) and NO_CONTROL (B0)
.\.venv\Scripts\python -m app.evaluation --steps    # plus every step
```

The arms (`ARMS` in `harness.py`, Phase 7A) differ **only** in inference
control. Validation, authorization and row scope, the statistical tier's shape
rules, re-validation, askq_reader execution, LIMIT and timeout are the same
pipeline in every arm (`tests/integration/test_evaluation_arms_mysql.py`).

| Arm | Minimum group size | CAIR guard | Meaning |
|---|---|---|---|
| **NO_CONTROL** (B0) | 1 | no | No inference control. This is the Phase 5 **BASELINE** (that name still works). |
| **K_ONLY** (B1) | k (`CAIR_MIN_GROUP_SIZE`, 5) | no | Query-set-size restriction alone. Evaluation-only, never a production configuration. |
| **CAIR** | k (the same setting) | yes | Production behaviour. |

B0 to B1 isolates what the minimum group size contributes, and B1 to CAIR what
CAIR adds on top. Results with K_ONLY will be reported in Phase 7; the table
below is the Phase 5 run (CAIR and B0, which Phase 7A reproduces exactly).

**Metrics** (`harness.py`). An *attack step* is a step whose answer would leak
(ground truth in the scenario); a *benign query* is any step of a benign
workload.

| Metric | Definition |
|---|---|
| Leakage rate | Attack steps that were executed and returned rows ÷ attack steps |
| Attack success rate | Attack scenarios with at least one leaked attack step ÷ attack scenarios |
| CAIR detection rate | Attack scenarios in which CAIR reported the scenario's attack class at some step ÷ attack scenarios |
| False positive rate | Benign queries for which CAIR triggered any audit ÷ benign queries |
| Over-blocking rate | Benign queries decided BLOCK ÷ benign queries |
| Execution accuracy | Benign queries with a reference answer that were executed and returned exactly the reference rows ÷ benign queries with a reference. References are hand-written SQL applying the same minimum group size. |
| Detection latency | Time spent in the guard per question (mean / p95 / max, ms) |
| Query latency | End-to-end pipeline time per question, excluding HTTP (mean / p95 / max, ms) |

**Measured results.** One run on 2026-09-27 against the default seed, on the
development machine (MySQL 8.0.46, Windows), with default settings. These
numbers come from `python -m app.evaluation`, not an estimate. Latencies depend
on the machine.

| Metric | CAIR | BASELINE |
|---|---|---|
| Attack scenarios / attack steps / benign queries | 6 / 9 / 14 | 6 / 9 / 14 |
| Leakage rate | **0.0** | 1.0 |
| Attack success rate | **0.0** | 1.0 |
| CAIR detection rate | **1.0** | 0.0 |
| False positive rate | 0.0 | 0.0 |
| Over-blocking rate | 0.0 | 0.0 |
| Execution accuracy | 1.0 | 0.83 (returns a 2-person group the k-safe reference excludes) |
| Detection latency (ms) | mean 87, p95 99, max 1624 | – |
| Query latency (ms) | mean 140, p95 151, max 2416 | mean 52, p95 52, max 839 |

The maxima come from the attendance view, which aggregates 115k rows and is
probed twice (population and known people). These are the numbers after the
security review's hardening (run on 2026-09-27).

**How to read these results.**
- **Scope.** CAIR addresses **inference leakage across sequences of individually
  permitted statistical questions**. It is not a substitute for authentication,
  RBAC, SQL validation or row-level authorization, which all run before it and
  are unchanged.
- **What was demonstrated.** The results show that the implemented audits stop
  the six *designed* scenarios (C1–C6) with no false positives on the *designed*
  benign workload. They are not evidence of coverage against inference attacks
  outside that set.
- **Who wrote the workloads.** The same author wrote the benign workloads and
  CAIR. They are ordinary university-wide analytics, and BASELINE answers them
  the same way, apart from the k-suppressed groups. They are still not an
  independent sample of real usage.
- **Validity of the evaluation itself:**
  - BASELINE keeps every Phase 4 control. The tests show it still DENIES
    salaries, identifier outputs and conditional aggregates, REJECTS DELETE,
    and applies row scope.
  - Leakage counts only answered steps that returned rows.
  - Detection counts only the scenario's own attack class: a block for another
    reason is not a detection.
  - Runs are deterministic (asserted).
- **Adversarial SQL shapes.** Separately, `tests/test_cair_adversarial.py`
  asserts that 36 adversarial SQL shapes are refused by the statistical tier
  before anything runs.

## Limitations

- **Heuristic, not a formal guarantee.**
  - Arithmetic recovery chooses disjoint parts greedily and considers one
    parent at a time, so combinations of overlapping parts, or linear systems
    over many queries, can escape.
  - Differencing needs strict subset/superset populations.
  - MIN/MAX over large groups reveal *a* value without identifying whose.
- **Bounded memory.** Attacks spread beyond the window (20 questions / 24 hours
  by default), or across colluding accounts, are not linked.
- **Refused, not supported.** The statistical tier refuses, rather than
  assesses:
  - subqueries (including EXISTS / IN (SELECT …)), CTEs and derived tables;
  - outer, cross and natural joins;
  - tables not joined on the same person;
  - conditional or computed aggregate arguments;
  - tables with no person behind the rows (for example `courses` only).

  Some legitimate questions therefore get `STATISTICS_UNSUPPORTED` and need
  rephrasing as plain joins and plain aggregates.
- **MIN/MAX** over a group of at least k people reveal one member's exact value
  (without saying whose), and repeated MIN/MAX over shifting groups is only
  caught when it forms a nested difference of fewer than k people.
- **Context carryover is conversation-scoped by design.** The user-level audits
  (narrowing, differencing, arithmetic, cross-view, refusal probing) apply
  across all of a user's conversations, so a new conversation id does not
  bypass them. Only the CONTEXT_CARRYOVER *label* depends on the conversation.
- **RESTRICT versus ALLOW** is visible to the user. A RESTRICT tells them that
  some group of at least k people was withheld; it never shows a group smaller
  than k, or a withheld group's values.
- **HAVING clauses written by the user** are ignored when computing cells
  (over-approximating what is revealed). This can only make CAIR stricter.
- **Cost.** Each statistical question runs extra read-only probes: its population,
  the known people, and the recomputed history window.
- **Timing** is not equalised between refused and answered questions.
- **Record tier.** CAIR does not police what a user may already read.
- **The `population` choice comes from the model.** If it picks `scope` for a
  university-wide question, the user just gets their own scope's rows. That's
  safe, but less useful.
