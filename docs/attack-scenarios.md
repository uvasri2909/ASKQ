# Attack scenarios (C1–C6)

These are six reproducible attacks against the planted Phase 2 cohorts
(`database/seed/askq_seed/cohorts.py`), plus benign workloads. They're defined
as data in `backend/app/evaluation/scenarios.py`, run by the evaluation harness
(`python -m app.evaluation`), and asserted step by step in
`backend/tests/integration/test_cair_mysql.py`. How CAIR detects each one is
described in [cair.md](cair.md).

Each step carries its SQL, so no language model is involved and runs are
deterministic. The numbers are for the default seed; the cohort properties hold
for every seed. **k = 5**. The attackers are heads of department whose record
scope doesn't include the target: `t0016` (HOD of MECH) and `t0001` (HOD of CSE).
Statistical steps ask for population `university`.

| # | Attack class | Attacker | Target (cohort) |
|---|---|---|---|
| C1 | Differencing | t0016 | The only international Astrophysics student's marks |
| C2 | Narrowing | t0016 | The one female, year-3 Mathematics student from Highland who lives in the hostel |
| C3 | Arithmetic recovery | t0016 | The three Meridian Hardship Fund awards (programme below k) |
| C4 | Cross-view linking | t0001 | The only year-2 ECE student from Saltmarsh: their Fall balance |
| C5 | Refusal side channel | t0016 | Whether Biotechnology has a gender-X student in years 1–3 |
| C6 | Context carryover | t0016 | The CSE year-4 hostel resident who holds the Chancellor's scholarship |

## C1: Differencing

**Security property.** Two k-safe averages over nested populations must not
isolate one person.

| Step | Question | Population | CAIR | Classes | Leaks if answered |
|---|---|---|---|---|---|
| 1 | Average Spring marks of Astrophysics students | 20 | ALLOW | – | no |
| 2 | …of domestic Astrophysics students | 19 | **BLOCK** | DIFFERENCING (and ARITHMETIC_RECOVERY) | yes: step 1 − step 2 gives the international student's marks |

The integration tests also run these variations, and every one is blocked:
- the steps in reverse order;
- the second step as an equivalent query with different aliases, join order
  and `<> 'INTERNATIONAL'` instead of `= 'DOMESTIC'`;
- the two steps in **different conversations**.

## C2: Narrowing

**Security property.** Progressive filters must not reach a group smaller than k.

| Step | Question | Population | CAIR | Classes | Leaks |
|---|---|---|---|---|---|
| 1 | Year-3 Mathematics students | 26 | ALLOW | – | no |
| 2 | …female | 14 | ALLOW | – | no |
| 3 | …from Highland | 2 | **BLOCK** | NARROWING | yes (a count of 2) |
| 4 | Average marks of those in the hostel | 1 | **BLOCK** | NARROWING, CONTEXT_CARRYOVER | yes (one person's marks) |

## C3: Arithmetic recovery

**Security property.** A total minus the visible subtotals must not recover a
group too small to be shown.

| Step | Question | Cells | CAIR | Classes | Leaks |
|---|---|---|---|---|---|
| 1 | Total need-based award amount this term | 60 | ALLOW | – | no |
| 2 | …broken down by programme | ORCHARD 57, MERIDIAN 3 (withheld by k) | **BLOCK** | ARITHMETIC_RECOVERY (and DIFFERENCING) | yes: total − ORCHARD = MERIDIAN |

Withholding ORCHARD (complementary suppression) would leave nothing to return,
so the step is blocked. In reverse order, the breakdown is ALLOWed (only ORCHARD
is visible) and the later total is BLOCKed.

## C4: Cross-view linking

**Security property.** A k-sized statistic must not be de-anonymised by
subtracting people the user already sees record by record.

| Step | Question | Tier | CAIR | Classes | Leaks |
|---|---|---|---|---|---|
| 1 | List the Fall balances of my department's Saltmarsh students | record (own scope) | ALLOW | – | no (the HOD may read these) |
| 2 | Average Fall balance of Saltmarsh students in CSE **or** in ECE year 2 | statistical, 5 people (4 known) | **BLOCK** | CROSS_VIEW_LINKING | yes: 5 × average − the 4 known balances gives the ECE student's balance |

## C5: Refusal side channel

**Security property.** A refusal must look the same for 0 people and for 1..k−1
people, and probing the refusal boundary must itself be refused.

| Step | Question (gender X in Biotechnology) | Population | CAIR | Classes |
|---|---|---|---|---|
| 1 | Year 1 | 1 | BLOCK | NARROWING |
| 2 | Year 2 | 0 | BLOCK | NARROWING |
| 3 | Year 3 | 0 | BLOCK | NARROWING |
| 4 | Year 4 | 5 (= k, allowed alone) | **BLOCK** | REFUSAL_SIDE_CHANNEL |
| 5 | All years | 6 | **BLOCK** | REFUSAL_SIDE_CHANNEL |

The responses to steps 1 (one person) and 2 (nobody) are **identical**, which the
tests assert field by field. Without step-4/5 blocking, "all years = 6" minus
"year 4 = 5" would reveal the single year-1 student.

## C6: Context carryover

**Security property.** A follow-up must not reveal anything about a person
singled out earlier in the same conversation.

| Step | Question (one conversation) | Population | CAIR | Classes |
|---|---|---|---|---|
| 1 | CSE year-4 students living in the hostel | 23 | ALLOW | – |
| 2 | How many of them hold the Chancellor's scholarship? | 1 | **BLOCK** | NARROWING |
| 3 | What is their average outstanding Fall balance? | 1 | **BLOCK** | CONTEXT_CARRYOVER, NARROWING |

Asked on its own, in a new conversation, step 3 is still blocked, but only as
NARROWING. The tests check that CONTEXT_CARRYOVER is *not* reported without the
earlier turn. The steps use plain joins to `student_scholarships`, because the
statistical tier refuses subqueries.

## Reverse orders, nearby questions and boundaries

`tests/integration/test_cair_mysql.py` also checks, on the real data, the
following.

**Every attack in reverse order.**
- **C1:** allowed, then blocked (DIFFERENCING).
- **C2:** the two narrow steps are blocked; the broad ones are allowed.
- **C3:** allowed, then the total is blocked (ARITHMETIC_RECOVERY).
- **C4:** the statistic is blocked first (CROSS_VIEW_LINKING).
- **C5:** the total of 6 is allowed, then year 4 (5) is blocked
  (ARITHMETIC_RECOVERY), then years 3–1 are blocked.
- **C6:** blocked, then blocked with CONTEXT_CARRYOVER, then the broad count is
  allowed.

**A harmless nearby question per attack is allowed.**
- **C1:** ASTRO, then CSE averages.
- **C2:** MATH year-3 female, then male.
- **C3:** the total, then a breakdown by category, whose need-based cell equals
  the total.
- **C4:** all Saltmarsh students (16 unknown people).
- **C5:** Biotechnology by gender.
- **C6:** the average balance of all 23 CSE year-4 hostel residents.

**Minimum group size on real data.**
- 4 people (CSE Saltmarsh students): refused.
- 5 people (BIOT gender X, year 4): answered 5.
- 6 people (BIOT gender X in total): answered 6.

The test-only SQLite population in `tests/test_cair_adversarial.py` covers the
same 4 / 5 / 6 boundaries, grouped and ungrouped, together with
complementary-group recovery.

## Benign workloads

These are used for the false-positive rate, over-blocking rate and execution
accuracy.

| Code | Contents | Expected |
|---|---|---|
| B1 | Six university-wide breakdowns (marks, year level, balances, scholarships, attendance, gender), each with a hand-written reference answer | ALLOW, exact results |
| B2 | Nested but large populations (all → year 2; CSE; ECE) | ALLOW |
| B3 | A total, then a breakdown whose parts cover it completely | ALLOW |
| B4 | Record-tier questions inside the HOD's own department | ALLOW (CAIR not involved) |

## Results

Measured on 2026-09-27 against the default seed, with CAIR:
- **All scenarios:** every step reached its expected decision, with the expected
  classes reported.
- **Leakage and attack success:** 0.
- **Detection rate:** 1.0.
- **False positives and over-blocking:** 0.
- **Execution accuracy:** 1.0.

With BASELINE (no inference control), every attack succeeds (leakage 1.0).
The full table and metric definitions are in [cair.md](cair.md#evaluation).
