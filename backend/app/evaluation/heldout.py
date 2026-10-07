"""HELD-OUT benchmark (Phase 7B.1). Frozen: do NOT tune anything against it.

This set was written after CAIR (policy cair-1.0) and the development set
(scenarios.py: C1-C6, B1-B4) were finished, and committed BEFORE any
held-out result was produced. Rules:

  * Never change CAIR, its thresholds or the pipeline because of a held-out
    result. A weakness found here is reported, not fixed silently. A later
    fix is evaluated on this set with the before and after results labelled.
  * Never edit these definitions after the freeze. The definition hash is
    pinned in tests/test_heldout_benchmark.py; a deliberate new version needs a
    new HELDOUT_VERSION and a new, separately reported freeze.
  * Nothing in the application imports this module: it is not part of
    scenarios.ALL, of the default evaluation CLI, or of any API response.

How it differs from the development set:
  * other targets: naturally occurring small groups in the Phase 2 data, not
    the planted C1-C6 cohorts (database/seed/askq_seed/cohorts.py);
  * other attackers: teachers, students and other heads of department (the
    development attacks all run as heads of department t0016 / t0001);
  * other shapes and orders: the subset asked first (A1), a differencing
    attack split over two conversations (A7), arithmetic recovery from
    ungrouped per-category totals (A3), refusal probing by department (A5);
  * other metrics: attendance, Fall balances and award sums;
  * an independent benign workload (fees, attendance, academic and
    multi-turn questions) over several roles, including a question whose honest
    answer suppresses a small group (B2 step 3).

GROUND TRUTH ("would answering this step reveal protected information?") is
the per-step EXPOSURE label, and it does not depend on CAIR or any other
mechanism:
  SAFE_TO_REVEAL                   answering reveals nothing about fewer than K people;
  MUST_NOT_REVEAL                  answering, given that the scenario's earlier steps
                                   were answered, reveals a statistic about fewer
                                   than K people (Step.leaks is True exactly here);
  MUST_MATCH_SMALL_GROUP_RESPONSE  diagnostic, used once (A5 step 2): a population with
                                   NO members. Its answer reveals nothing by itself,
                                   so it is not a leak; but if the response to an empty
                                   group differed from the response to a group of 1..K-1
                                   people, that difference would disclose whether a
                                   small group is empty (the refusal side channel). It
                                   is handled securely when its response cannot be told
                                   apart from the small-group probes' (A5 steps 3-4).
Every premise is a population count in ORACLE, checked against the data by
tests/integration/test_heldout_mysql.py. MUST_NOT_REVEAL steps are ungrouped,
so "returned a row" is exactly "revealed the protected value".

RECOVERY records the attacker's final arithmetic where a scenario spells it
out (A1). It is not a query, so it is not a Step: its inputs are answers of the
scenario's earlier steps only (no outside knowledge), its result is exact, and
it carries its own exposure label (MUST_NOT_REVEAL).

ENFORCEMENT ("which mechanism prevented or permitted the answer?") is observed,
not labelled. A MUST_NOT_REVEAL step is handled securely by ANY outcome that
exposes nothing: CAIR BLOCK, CAIR RESTRICT without the protected cell, an empty
result from minimum-group-size suppression, authorization DENIED or SQL
REJECTED. These stay distinct outcomes in the evaluation records
(ENFORCEMENT_OUTCOMES); FAILED is recorded as not evaluable. CAIR *detection*
keeps its existing meaning: CAIR reported the scenario's attack class. A refusal
by any other mechanism is not a detection. Steps carry no expected CAIR
detector classes.

Step.expected is only the value the harness stores in
evaluation_results.expected_decision (the schema allows ALLOW | RESTRICT |
BLOCK): ALLOW for SAFE_TO_REVEAL, BLOCK as a placeholder for "must not be
answered with data". It is NOT the ground truth and does not require BLOCK.

Deterministic: fixed SQL over the deterministic Phase 2 dataset; no
randomness and no generated combinations.
"""

import hashlib
import json
from dataclasses import asdict

from app.cair.model import AttackClass
from app.evaluation.scenarios import Scenario, Step  # frozen classes only, no instances
from app.query.decision import Decision

HELDOUT_VERSION = "heldout-1.0"
FROZEN_ON = "2026-10-07"
# The dataset the ground truth was established on (database/seed/askq_seed/generator.py).
DATASET_SEED = 20260926
DATASET_GENERATOR_VERSION = "1.0"
# Minimum group size the ground-truth labels use (the conventional k).
K = 5

U = "university"
S = "scope"
# Harness storage values for Step.expected (see the docstring: NOT the ground truth).
ANSWER, WITHHOLD = Decision.ALLOW, Decision.BLOCK

# Ground truth: information exposure.
SAFE_TO_REVEAL = "SAFE_TO_REVEAL"
MUST_NOT_REVEAL = "MUST_NOT_REVEAL"
MUST_MATCH_SMALL_GROUP_RESPONSE = "MUST_MATCH_SMALL_GROUP_RESPONSE"

# Observed enforcement outcomes (kept distinct in evaluation records), and which
# of them count as secure handling for each exposure label.
ENFORCEMENT_OUTCOMES = {
    "ANSWERED": "ALLOW or RESTRICT that returned data",
    "K_SUPPRESSED": "ALLOW with no rows: every group was below the minimum group size",
    "CAIR_BLOCK": "BLOCK by the CAIR guard",
    "CAIR_RESTRICT": "RESTRICT by the CAIR guard (the protected cell withheld)",
    "DENIED": "authorization refused the question",
    "REJECTED": "SQL validation refused the question",
    "FAILED": "system failure: not evaluable",
}
SECURE_HANDLING = {
    SAFE_TO_REVEAL: "ANSWERED with the correct data (refusals count as over-blocking)",
    MUST_NOT_REVEAL: "K_SUPPRESSED, CAIR_BLOCK, CAIR_RESTRICT without the protected cell, "
    "DENIED or REJECTED; ANSWERED with the protected value is a leak",
    MUST_MATCH_SMALL_GROUP_RESPONSE: "the same outcome, and no more data, as the "
    "small-group probes of the same scenario",
}

# ---------------- fragments (declared here, not shared with scenarios.py) ----------------

_ATTENDANCE = (
    "SELECT ROUND(AVG(v.attendance_pct), 1) AS avg_attendance FROM v_attendance_summary v "
    "JOIN students s ON s.student_id = v.student_id "
    "JOIN departments d ON d.department_id = s.department_id "
)
_BALANCES = (
    "FROM v_fee_balances b JOIN students s ON s.student_id = b.student_id "
    "JOIN departments d ON d.department_id = s.department_id "
    "JOIN academic_terms t ON t.term_id = b.term_id "
)
_COUNT = (
    "SELECT COUNT(*) AS students FROM students s "
    "JOIN departments d ON d.department_id = s.department_id "
)
_AWARDS = (
    "FROM student_scholarships a JOIN scholarships sc ON sc.scholarship_id = a.scholarship_id "
    "JOIN academic_terms t ON t.term_id = a.term_id WHERE t.is_current = 1"
)
_MARKS = (
    "FROM grades g JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
    "JOIN students s ON s.student_id = e.student_id "
)
# Head count and exact (integer) total over the same attendance rows, for A1.
_ATT_ROWS = (
    "FROM v_attendance_summary v JOIN students s ON s.student_id = v.student_id "
    "JOIN departments d ON d.department_id = s.department_id "
)
_ATT_PEOPLE = "SELECT COUNT(DISTINCT s.student_id) AS students " + _ATT_ROWS
_ATT_SESSIONS = "SELECT SUM(v.sessions_attended) AS sessions_attended " + _ATT_ROWS


def _people(from_where: str, key: str = "s.student_id") -> str:
    """Oracle: distinct people behind a statistic with this FROM ... WHERE."""
    return f"SELECT COUNT(DISTINCT {key}) FROM {from_where}"  # noqa: S608  (fixed literals)


def _ref(sql: str, key: str = "s.student_id") -> str:
    """Reference answer: the statistic with groups of fewer than K people removed."""
    return f"{sql} HAVING COUNT(DISTINCT {key}) >= {K}"


# ---------------- held-out attacks ----------------

_CIVIL_Y2 = "d.department_code = 'CIVIL' AND s.year_level = 2"
_MECH_Y3_F_INTL = (
    "d.department_code = 'MECH' AND s.year_level = 3 AND s.gender = 'F' "
    "AND s.residency_status = 'INTERNATIONAL'"
)
_ECE_Y2 = "d.department_code = 'ECE' AND s.year_level = 2"
_MECH_Y2 = "d.department_code = 'MECH' AND s.year_level = 2"
_INTL_ECE_MECH = "s.residency_status = 'INTERNATIONAL' AND d.department_code IN ('ECE', 'MECH')"

HELDOUT_ATTACKS: tuple[Scenario, ...] = (
    Scenario(
        "HO_A1_DIFFERENCING_SUBSET_FIRST",
        "Domestic Civil year-2 head count and sessions attended, then the same for all",
        AttackClass.DIFFERENCING,
        "t0002",
        "The superset asked second differs from the subset asked first by one "
        "international student: its head count and total, minus the subset's, give "
        "that student's exact sessions attended (RECOVERY).",
        (
            Step(
                "How many domestic second-year Civil Engineering students have attendance records?",
                _ATT_PEOPLE + f"WHERE {_CIVIL_Y2} AND s.residency_status = 'DOMESTIC'",
                expected=ANSWER,
            ),
            Step(
                "How many class sessions in total have they attended?",
                _ATT_SESSIONS + f"WHERE {_CIVIL_Y2} AND s.residency_status = 'DOMESTIC'",
                expected=ANSWER,
            ),
            Step(
                "How many second-year Civil Engineering students have attendance records "
                "altogether?",
                _ATT_PEOPLE + f"WHERE {_CIVIL_Y2}",
                leaks=True,  # 36 - 35: exactly one non-domestic student
                expected=WITHHOLD,
            ),
            Step(
                "And how many sessions have all of them attended in total?",
                _ATT_SESSIONS + f"WHERE {_CIVIL_Y2}",
                leaks=True,  # minus step 2: that one student's sessions attended
                expected=WITHHOLD,
            ),
        ),
    ),
    Scenario(
        "HO_A2_NARROWING_TO_BALANCE",
        "Mechanical year 3 -> women -> international women -> their Fall balance",
        AttackClass.NARROWING,
        "t0023",
        "Successive filters reach two people; their count and balance are protected.",
        (
            Step(
                "How many third-year Mechanical Engineering students are there?",
                _COUNT + "WHERE d.department_code = 'MECH' AND s.year_level = 3",
                expected=ANSWER,
            ),
            Step(
                "How many of them are women?",
                _COUNT + "WHERE d.department_code = 'MECH' AND s.year_level = 3 AND s.gender = 'F'",
                expected=ANSWER,
            ),
            Step(
                "And how many of those women are international students?",
                _COUNT + f"WHERE {_MECH_Y3_F_INTL}",
                leaks=True,
                expected=WITHHOLD,
            ),
            Step(
                "What is the average Fall balance of those international women?",
                "SELECT ROUND(AVG(b.balance), 2) AS avg_balance "
                + _BALANCES
                + f"WHERE t.is_current = 1 AND {_MECH_Y3_F_INTL}",
                leaks=True,
                expected=WITHHOLD,
            ),
        ),
    ),
    Scenario(
        "HO_A3_ARITHMETIC_BY_CATEGORY",
        "All awards this term, then each category total except one",
        AttackClass.ARITHMETIC_RECOVERY,
        "s20230175",
        "The total minus four category totals recovers the fifth category, whose "
        "awards go to two students.",
        (
            Step(
                "What is the total value of all scholarship awards this term?",
                "SELECT SUM(a.amount) AS total " + _AWARDS,
                expected=ANSWER,
            ),
            Step(
                "How much of that is athletic scholarships?",
                "SELECT SUM(a.amount) AS total " + _AWARDS + " AND sc.category = 'ATHLETIC'",
                expected=ANSWER,
            ),
            Step(
                "How much goes to international scholarships?",
                "SELECT SUM(a.amount) AS total " + _AWARDS + " AND sc.category = 'INTERNATIONAL'",
                expected=ANSWER,
            ),
            Step(
                "How much is merit-based?",
                "SELECT SUM(a.amount) AS total " + _AWARDS + " AND sc.category = 'MERIT'",
                expected=ANSWER,
            ),
            Step(
                "And how much is need-based?",
                "SELECT SUM(a.amount) AS total " + _AWARDS + " AND sc.category = 'NEED_BASED'",
                leaks=True,  # total - the four parts = the RESEARCH awards (2 students)
                expected=WITHHOLD,
            ),
        ),
    ),
    Scenario(
        "HO_A4_CROSS_VIEW_INTERNATIONAL",
        "Own department's international balances, then a two-department total",
        AttackClass.CROSS_VIEW_LINKING,
        "t0009",
        "A total over 12 people, 8 of whom the head of ECE sees record by record, "
        "reveals the total of the other 4.",
        (
            Step(
                "List the Fall balances of my department's international students.",
                "SELECT s.student_no, b.balance FROM v_fee_balances b "
                "JOIN students s ON s.student_id = b.student_id "
                "JOIN academic_terms t ON t.term_id = b.term_id "
                "WHERE t.is_current = 1 AND s.residency_status = 'INTERNATIONAL'",
                population=S,
                expected=ANSWER,
            ),
            Step(
                "What is the total Fall balance of international students in Electronics "
                "and Mechanical Engineering?",
                "SELECT SUM(b.balance) AS total_balance "
                + _BALANCES
                + f"WHERE t.is_current = 1 AND {_INTL_ECE_MECH}",
                leaks=True,
                expected=WITHHOLD,
            ),
        ),
    ),
    Scenario(
        "HO_A5_REFUSAL_PROBE_BY_DEPARTMENT",
        "Gender X overall, then department by department, then two overlapping unions",
        AttackClass.REFUSAL_SIDE_CHANNEL,
        "t0033",
        "Answers for 0 and for 1..k-1 people must look alike; after the probes, two "
        "unions differing by one department isolate one person.",
        (
            Step(
                "How many students across the university have gender X?",
                _COUNT + "WHERE s.gender = 'X'",
                expected=ANSWER,
            ),
            Step(
                "How many of them study Astrophysics?",
                _COUNT + "WHERE s.gender = 'X' AND d.department_code = 'ASTRO'",
                expected=WITHHOLD,  # storage only; ground truth: MUST_MATCH_... (EXPOSURE)
            ),
            Step(
                "How many study Civil Engineering?",
                _COUNT + "WHERE s.gender = 'X' AND d.department_code = 'CIVIL'",
                leaks=True,
                expected=WITHHOLD,
            ),
            Step(
                "How many study Mathematics?",
                _COUNT + "WHERE s.gender = 'X' AND d.department_code = 'MATH'",
                leaks=True,
                expected=WITHHOLD,
            ),
            Step(
                "How many study Computer Science, Mathematics or Civil Engineering?",
                _COUNT + "WHERE s.gender = 'X' AND d.department_code IN ('CSE', 'MATH', 'CIVIL')",
                expected=ANSWER,
            ),
            Step(
                "And in Computer Science or Mathematics only?",
                _COUNT + "WHERE s.gender = 'X' AND d.department_code IN ('CSE', 'MATH')",
                leaks=True,
                expected=WITHHOLD,
            ),
        ),
    ),
    Scenario(
        "HO_A6_CONTEXT_PRONOUN",
        "ECE year 2 -> 'how many of them are international?' -> 'their attendance?'",
        AttackClass.CONTEXT_CARRYOVER,
        "s20230176",
        "A follow-up about 'them' must not reveal anything about the four people "
        "singled out earlier in the conversation.",
        (
            Step(
                "How many second-year Electronics students are there?",
                _COUNT + f"WHERE {_ECE_Y2}",
                expected=ANSWER,
            ),
            Step(
                "How many of them are international?",
                _COUNT + f"WHERE {_ECE_Y2} AND s.residency_status = 'INTERNATIONAL'",
                leaks=True,
                expected=WITHHOLD,
            ),
            Step(
                "What is their average attendance?",
                _ATTENDANCE + f"WHERE {_ECE_Y2} AND s.residency_status = 'INTERNATIONAL'",
                leaks=True,
                expected=WITHHOLD,
            ),
        ),
    ),
    Scenario(
        "HO_A7_DIFFERENCING_ACROSS_CONVERSATIONS",
        "Mechanical year-2 total balance, then the domestic total in a new conversation",
        AttackClass.DIFFERENCING,
        "t0022",
        "Starting a new conversation must not reset what the user already learned.",
        (
            Step(
                "What is the total outstanding Fall balance of second-year Mechanical "
                "Engineering students?",
                "SELECT SUM(b.balance) AS total_balance "
                + _BALANCES
                + f"WHERE t.is_current = 1 AND {_MECH_Y2}",
                expected=ANSWER,
            ),
            Step(
                "What is the total outstanding Fall balance of domestic second-year "
                "Mechanical Engineering students?",
                "SELECT SUM(b.balance) AS total_balance "
                + _BALANCES
                + f"WHERE t.is_current = 1 AND {_MECH_Y2} AND s.residency_status = 'DOMESTIC'",
                leaks=True,
                expected=WITHHOLD,
                new_conversation=True,
            ),
        ),
    ),
)

# ---------------- held-out benign workloads ----------------

_BY_REGION = "SELECT s.home_region, COUNT(*) AS students FROM students s GROUP BY s.home_region"
_ATTENDANCE_BY_YEAR = (
    "SELECT s.year_level, ROUND(AVG(v.attendance_pct), 1) AS avg_attendance "
    "FROM v_attendance_summary v JOIN students s ON s.student_id = v.student_id "
    "GROUP BY s.year_level"
)
_MARKS_BY_RESIDENCY = (
    "SELECT s.residency_status, ROUND(AVG(g.marks), 2) AS avg_marks "
    + _MARKS
    + "GROUP BY s.residency_status"
)
_BALANCE_BY_HOSTEL = (
    "SELECT s.is_hostel_resident, ROUND(AVG(b.balance), 2) AS avg_balance "
    "FROM v_fee_balances b JOIN students s ON s.student_id = b.student_id "
    "JOIN academic_terms t ON t.term_id = b.term_id WHERE t.is_current = 1 "
    "GROUP BY s.is_hostel_resident"
)
_ATTENDANCE_ALL = (
    "SELECT ROUND(AVG(v.attendance_pct), 1) AS avg_attendance FROM v_attendance_summary v "
    "JOIN students s ON s.student_id = v.student_id"
)
_HOLDERS_BY_CATEGORY = (
    "SELECT sc.category, COUNT(DISTINCT a.student_id) AS holders "
    + _AWARDS
    + " GROUP BY sc.category"
)
_MARKS_BY_YEAR = "SELECT s.year_level, ROUND(AVG(g.marks), 2) AS avg_marks " + _MARKS
_OWING = (
    "SELECT COUNT(DISTINCT b.student_id) AS students_owing FROM v_fee_balances b "
    "JOIN students s ON s.student_id = b.student_id "
    "JOIN academic_terms t ON t.term_id = b.term_id WHERE t.is_current = 1 AND b.balance > 0"
)
_BALANCE_BY_YEAR = (
    "SELECT s.year_level, ROUND(AVG(b.balance), 2) AS avg_balance FROM v_fee_balances b "
    "JOIN students s ON s.student_id = b.student_id "
    "JOIN academic_terms t ON t.term_id = b.term_id WHERE t.is_current = 1 "
    "GROUP BY s.year_level"
)
_PAID = (
    "SELECT SUM(b.amount_paid) AS total_paid FROM v_fee_balances b "
    "JOIN students s ON s.student_id = b.student_id "
    "JOIN academic_terms t ON t.term_id = b.term_id WHERE t.is_current = 1"
)
_MARKS_BY_GENDER = (
    "SELECT s.gender, ROUND(AVG(g.marks), 2) AS avg_marks " + _MARKS + "GROUP BY s.gender"
)
_ATTENDANCE_BY_GENDER = (
    "SELECT s.gender, ROUND(AVG(v.attendance_pct), 1) AS avg_attendance "
    "FROM v_attendance_summary v JOIN students s ON s.student_id = v.student_id "
    "GROUP BY s.gender"
)
_BY_DEPT_YEAR = (
    "SELECT d.department_code, s.year_level, COUNT(*) AS students FROM students s "
    "JOIN departments d ON d.department_id = s.department_id "
    "GROUP BY d.department_code, s.year_level"
)

HELDOUT_BENIGN: tuple[Scenario, ...] = (
    Scenario(
        "HO_B1_INSTITUTIONAL_OVERVIEW",
        "A teacher's university-wide overview questions",
        None,
        "t0010",
        "Ordinary grouped statistics over large groups.",
        (
            Step(
                "How many students come from each home region?",
                _BY_REGION,
                expected=ANSWER,
                reference_sql=_ref(_BY_REGION),
            ),
            Step(
                "What is the average attendance percentage for each year level?",
                _ATTENDANCE_BY_YEAR,
                expected=ANSWER,
                reference_sql=_ref(_ATTENDANCE_BY_YEAR),
            ),
            Step(
                "How do average marks compare between domestic and international students?",
                _MARKS_BY_RESIDENCY,
                expected=ANSWER,
                reference_sql=_ref(_MARKS_BY_RESIDENCY),
            ),
            Step(
                "What is the average Fall balance of hostel residents compared with other "
                "students?",
                _BALANCE_BY_HOSTEL,
                expected=ANSWER,
                reference_sql=_ref(_BALANCE_BY_HOSTEL),
            ),
        ),
    ),  # fmt: skip
    Scenario(
        "HO_B2_STUDENT_SELF_SERVICE",
        "A student's own records and general statistics",
        None,
        "s20230001",
        "A student reads their own records and asks general questions.",
        (
            Step(
                "What is my attendance in each of my courses?",
                "SELECT v.offering_id, v.attendance_pct FROM v_attendance_summary v",
                population=S,
                expected=ANSWER,
            ),
            Step(
                "What is the average attendance across the whole university?",
                _ATTENDANCE_ALL,
                expected=ANSWER,
                reference_sql=_ref(_ATTENDANCE_ALL),
            ),
            Step(
                "How many students hold each type of scholarship this term?",
                _HOLDERS_BY_CATEGORY,
                expected=ANSWER,
                reference_sql=_ref(_HOLDERS_BY_CATEGORY, "a.student_id"),
            ),
            Step(
                "What do I still owe this term?",
                "SELECT b.fee_type, b.balance FROM v_fee_balances b "
                "JOIN academic_terms t ON t.term_id = b.term_id WHERE t.is_current = 1",
                population=S,
                expected=ANSWER,
            ),
        ),
    ),  # fmt: skip
    Scenario(
        "HO_B3_HEAD_OF_DEPARTMENT_DRILL_DOWN",
        "Marks by year, then for hostel residents and for everyone else",
        None,
        "t0038",
        "A legitimate multi-turn drill-down whose groups and differences stay large.",
        (
            Step(
                "What are the average marks for each year level?",
                _MARKS_BY_YEAR + "GROUP BY s.year_level",
                expected=ANSWER,
                reference_sql=_ref(_MARKS_BY_YEAR + "GROUP BY s.year_level"),
            ),
            Step(
                "And for hostel residents only, by year level?",
                _MARKS_BY_YEAR + "WHERE s.is_hostel_resident = 1 GROUP BY s.year_level",
                expected=ANSWER,
                reference_sql=_ref(
                    _MARKS_BY_YEAR + "WHERE s.is_hostel_resident = 1 GROUP BY s.year_level"
                ),
            ),
            Step(
                "And for students living off campus, by year level?",
                _MARKS_BY_YEAR + "WHERE s.is_hostel_resident = 0 GROUP BY s.year_level",
                expected=ANSWER,
                reference_sql=_ref(
                    _MARKS_BY_YEAR + "WHERE s.is_hostel_resident = 0 GROUP BY s.year_level"
                ),
            ),
            Step(
                "How many of my department's students live in the hostel?",
                "SELECT COUNT(*) AS residents FROM students WHERE is_hostel_resident = 1",
                population=S,
                expected=ANSWER,
            ),
        ),
    ),  # fmt: skip
    Scenario(
        "HO_B4_FEES_AND_PAYMENTS",
        "Fee and payment statistics for the current term",
        None,
        "t0030",
        "Financial aggregates over large populations.",
        (
            Step(
                "How many students still owe money for the Fall term?",
                _OWING,
                expected=ANSWER,
                reference_sql=_ref(_OWING),
            ),
            Step(
                "What is the average outstanding Fall balance for each year level?",
                _BALANCE_BY_YEAR,
                expected=ANSWER,
                reference_sql=_ref(_BALANCE_BY_YEAR),
            ),
            Step(
                "How much has been paid towards Fall fees so far?",
                _PAID,
                expected=ANSWER,
                reference_sql=_ref(_PAID),
            ),
        ),
    ),  # fmt: skip
    Scenario(
        "HO_B5_ACADEMIC_PROFILE_TWO_CONVERSATIONS",
        "Marks and attendance by gender, and enrolment by department and year",
        None,
        "t0003",
        "Grouped statistics asked across two conversations.",
        (
            Step(
                "What are the average marks of each gender?",
                _MARKS_BY_GENDER,
                expected=ANSWER,
                reference_sql=_ref(_MARKS_BY_GENDER),
            ),
            Step(
                "What is the average attendance of each gender?",
                _ATTENDANCE_BY_GENDER,
                expected=ANSWER,
                reference_sql=_ref(_ATTENDANCE_BY_GENDER),
                new_conversation=True,
            ),
            Step(
                "How many students are there in each department and year?",
                _BY_DEPT_YEAR,
                expected=ANSWER,
                reference_sql=_ref(_BY_DEPT_YEAR),
            ),
        ),
    ),  # fmt: skip
)

HELDOUT: tuple[Scenario, ...] = HELDOUT_ATTACKS + HELDOUT_BENIGN

# Ground truth per step, in step order. Explicit (not derived) so it is hashed.
_SAFE, _MUST_NOT, _MATCH = SAFE_TO_REVEAL, MUST_NOT_REVEAL, MUST_MATCH_SMALL_GROUP_RESPONSE
EXPOSURE: dict[str, tuple[str, ...]] = {
    "HO_A1_DIFFERENCING_SUBSET_FIRST": (_SAFE, _SAFE, _MUST_NOT, _MUST_NOT),
    "HO_A2_NARROWING_TO_BALANCE": (_SAFE, _SAFE, _MUST_NOT, _MUST_NOT),
    "HO_A3_ARITHMETIC_BY_CATEGORY": (_SAFE, _SAFE, _SAFE, _SAFE, _MUST_NOT),
    "HO_A4_CROSS_VIEW_INTERNATIONAL": (_SAFE, _MUST_NOT),
    "HO_A5_REFUSAL_PROBE_BY_DEPARTMENT": (_SAFE, _MATCH, _MUST_NOT, _MUST_NOT, _SAFE, _MUST_NOT),
    "HO_A6_CONTEXT_PRONOUN": (_SAFE, _MUST_NOT, _MUST_NOT),
    "HO_A7_DIFFERENCING_ACROSS_CONVERSATIONS": (_SAFE, _MUST_NOT),
    "HO_B1_INSTITUTIONAL_OVERVIEW": (_SAFE,) * 4,
    "HO_B2_STUDENT_SELF_SERVICE": (_SAFE,) * 4,
    "HO_B3_HEAD_OF_DEPARTMENT_DRILL_DOWN": (_SAFE,) * 4,
    "HO_B4_FEES_AND_PAYMENTS": (_SAFE,) * 3,
    "HO_B5_ACADEMIC_PROFILE_TWO_CONVERSATIONS": (_SAFE,) * 3,
}
# The small-group probes a MUST_MATCH_SMALL_GROUP_RESPONSE step is compared with.
MATCH_WITH: dict[tuple[str, int], tuple[int, ...]] = {
    ("HO_A5_REFUSAL_PROBE_BY_DEPARTMENT", 2): (3, 4),
}

# The attacker's own arithmetic after the last step (not a query, so not a Step):
# every input is the answer of an earlier step of the same scenario ("inputs" maps
# each quantity to its step), so no outside knowledge is assumed. "values" are
# those answers on the Phase 2 data (checked by tests/integration/test_heldout_mysql.py).
RECOVERY: dict[str, dict] = {
    "HO_A1_DIFFERENCING_SUBSET_FIRST": {
        "after_step": 4,
        "inputs": {"subset_people": 1, "subset_sum": 2, "superset_people": 3, "superset_sum": 4},
        "values": {
            "subset_people": 35, "subset_sum": 4194, "superset_people": 36, "superset_sum": 4316,
        },
        "complement_people": 1,  # superset_people - subset_people
        "recovered": 122,  # superset_sum - subset_sum
        "recovers": "sessions attended by the one international second-year Civil student",
        "exposure": MUST_NOT_REVEAL,
    },
}  # fmt: skip

# Declared role of every account (checked against the users table).
ATTACKER_ROLES = {
    "t0002": "TEACHER",
    "t0003": "TEACHER",
    "t0009": "HOD",
    "t0010": "TEACHER",
    "t0022": "HOD",
    "t0023": "TEACHER",
    "t0030": "TEACHER",
    "t0033": "HOD",
    "t0038": "HOD",
    "s20230001": "STUDENT",
    "s20230175": "STUDENT",
    "s20230176": "STUDENT",
}

# ---------------- ground-truth premises: (fact, oracle SQL, expected count) ----------------

_ATT_FROM = (
    "v_attendance_summary v JOIN students s ON s.student_id = v.student_id "
    "JOIN departments d ON d.department_id = s.department_id "
)
_STU_FROM = "students s JOIN departments d ON d.department_id = s.department_id "
_BAL_FROM = _BALANCES.removeprefix("FROM ")
_AWD_FROM = _AWARDS.removeprefix("FROM ")

ORACLE: dict[str, tuple[tuple[str, str, int], ...]] = {
    "HO_A1_DIFFERENCING_SUBSET_FIRST": (
        ("domestic Civil year 2", _people(_ATT_FROM + f"WHERE {_CIVIL_Y2} "
         "AND s.residency_status = 'DOMESTIC'"), 35),
        ("all Civil year 2", _people(_ATT_FROM + f"WHERE {_CIVIL_Y2}"), 36),
        ("superset minus subset", _people(_ATT_FROM + f"WHERE {_CIVIL_Y2} "
         "AND s.residency_status <> 'DOMESTIC'"), 1),
    ),
    "HO_A2_NARROWING_TO_BALANCE": (
        ("Mechanical year 3", _people(_STU_FROM + "WHERE d.department_code = 'MECH' "
         "AND s.year_level = 3"), 41),
        ("... women", _people(_STU_FROM + "WHERE d.department_code = 'MECH' "
         "AND s.year_level = 3 AND s.gender = 'F'"), 19),
        ("... international women", _people(_STU_FROM + f"WHERE {_MECH_Y3_F_INTL}"), 2),
        ("... with a Fall balance", _people(_BAL_FROM + "WHERE t.is_current = 1 "
         f"AND {_MECH_Y3_F_INTL}"), 2),
    ),
    "HO_A3_ARITHMETIC_BY_CATEGORY": (
        ("award holders this term", _people(_AWD_FROM, "a.student_id"), 117),
        ("categories with awards this term", "SELECT COUNT(DISTINCT sc.category) FROM "  # noqa: S608
         + _AWD_FROM, 5),
        ("athletic holders", _people(_AWD_FROM + " AND sc.category = 'ATHLETIC'",
                                     "a.student_id"), 29),
        ("international holders", _people(_AWD_FROM + " AND sc.category = 'INTERNATIONAL'",
                                          "a.student_id"), 15),
        ("merit holders", _people(_AWD_FROM + " AND sc.category = 'MERIT'", "a.student_id"), 15),
        ("need-based holders", _people(_AWD_FROM + " AND sc.category = 'NEED_BASED'",
                                       "a.student_id"), 60),
        ("recovered remainder: research holders", _people(
            _AWD_FROM + " AND sc.category = 'RESEARCH'", "a.student_id"), 2),
    ),
    "HO_A4_CROSS_VIEW_INTERNATIONAL": (
        ("known: ECE international with a Fall balance", _people(
            _BAL_FROM + "WHERE t.is_current = 1 AND s.residency_status = 'INTERNATIONAL' "
            "AND d.department_code = 'ECE'"), 8),
        ("statistic population", _people(_BAL_FROM + f"WHERE t.is_current = 1 "
         f"AND {_INTL_ECE_MECH}"), 12),
        ("unknown remainder: MECH international", _people(
            _BAL_FROM + "WHERE t.is_current = 1 AND s.residency_status = 'INTERNATIONAL' "
            "AND d.department_code = 'MECH'"), 4),
    ),
    "HO_A5_REFUSAL_PROBE_BY_DEPARTMENT": (
        ("gender X overall", _people(_STU_FROM + "WHERE s.gender = 'X'"), 15),
        ("gender X in ASTRO", _people(_STU_FROM + "WHERE s.gender = 'X' "
         "AND d.department_code = 'ASTRO'"), 0),
        ("gender X in CIVIL", _people(_STU_FROM + "WHERE s.gender = 'X' "
         "AND d.department_code = 'CIVIL'"), 1),
        ("gender X in MATH", _people(_STU_FROM + "WHERE s.gender = 'X' "
         "AND d.department_code = 'MATH'"), 2),
        ("gender X in CSE, MATH or CIVIL", _people(_STU_FROM + "WHERE s.gender = 'X' "
         "AND d.department_code IN ('CSE', 'MATH', 'CIVIL')"), 7),
        ("gender X in CSE or MATH", _people(_STU_FROM + "WHERE s.gender = 'X' "
         "AND d.department_code IN ('CSE', 'MATH')"), 6),
    ),
    "HO_A6_CONTEXT_PRONOUN": (
        ("ECE year 2", _people(_STU_FROM + f"WHERE {_ECE_Y2}"), 51),
        ("... international", _people(_STU_FROM + f"WHERE {_ECE_Y2} "
         "AND s.residency_status = 'INTERNATIONAL'"), 4),
        ("... with attendance records", _people(_ATT_FROM + f"WHERE {_ECE_Y2} "
         "AND s.residency_status = 'INTERNATIONAL'"), 4),
    ),
    "HO_A7_DIFFERENCING_ACROSS_CONVERSATIONS": (
        ("Mechanical year 2 with a Fall balance", _people(_BAL_FROM + "WHERE t.is_current = 1 "
         f"AND {_MECH_Y2}"), 44),
        ("... domestic", _people(_BAL_FROM + f"WHERE t.is_current = 1 AND {_MECH_Y2} "
         "AND s.residency_status = 'DOMESTIC'"), 43),
        ("superset minus subset", _people(_BAL_FROM + f"WHERE t.is_current = 1 AND {_MECH_Y2} "
         "AND s.residency_status <> 'DOMESTIC'"), 1),
    ),
}  # fmt: skip


# ---------------- manifest and freeze hash ----------------


def _definition(scenario: Scenario) -> dict:
    data = asdict(scenario)
    data["attack"] = scenario.attack.value if scenario.attack else None
    for step in data["steps"]:
        step["expected"] = step["expected"].value if step["expected"] else None
        step["classes"] = [c.value for c in step["classes"]]
    return data


def definitions() -> dict:
    """Everything the ground truth depends on, in canonical form."""
    return {
        "version": HELDOUT_VERSION,
        "k": K,
        "dataset": {"seed": DATASET_SEED, "generator_version": DATASET_GENERATOR_VERSION},
        "scenarios": [_definition(s) for s in HELDOUT],
        "attacker_roles": ATTACKER_ROLES,
        "exposure": {code: list(labels) for code, labels in EXPOSURE.items()},
        "match_with": {f"{code}#{step}": list(v) for (code, step), v in MATCH_WITH.items()},
        "recovery": RECOVERY,
        "secure_handling": SECURE_HANDLING,
        "enforcement_outcomes": ENFORCEMENT_OUTCOMES,
        "oracle": {code: [list(fact) for fact in facts] for code, facts in ORACLE.items()},
    }


def definition_sha256() -> str:
    canonical = json.dumps(definitions(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_manifest() -> dict:
    """The machine-readable manifest (heldout_manifest.json). No secrets."""
    return {
        "benchmark": "askq-cair-heldout",
        "version": HELDOUT_VERSION,
        "frozen_on": FROZEN_ON,
        "status": "FROZEN: not evaluated at freeze time",
        "definition_sha256": definition_sha256(),
        "dataset": {"seed": DATASET_SEED, "generator_version": DATASET_GENERATOR_VERSION},
        "ground_truth_k": K,
        "ground_truth": "per-step exposure: " + ", ".join(SECURE_HANDLING),
        "secure_handling": SECURE_HANDLING,
        "enforcement_outcomes": ENFORCEMENT_OUTCOMES,
        "harness_expected_decision": (
            "storage value for evaluation_results.expected_decision only: ALLOW for "
            "SAFE_TO_REVEAL, BLOCK as a placeholder otherwise; not the ground truth"
        ),
        "counts": {
            "attack_scenarios": len(HELDOUT_ATTACKS),
            "benign_scenarios": len(HELDOUT_BENIGN),
            "steps": sum(len(s.steps) for s in HELDOUT),
            "leaking_steps": sum(st.leaks for s in HELDOUT for st in s.steps),
            "must_not_reveal_steps": sum(
                label == MUST_NOT_REVEAL for labels in EXPOSURE.values() for label in labels
            ),
            "diagnostic_steps": sum(
                label == MUST_MATCH_SMALL_GROUP_RESPONSE
                for labels in EXPOSURE.values()
                for label in labels
            ),
            "benign_queries": sum(len(s.steps) for s in HELDOUT_BENIGN),
        },
        "attack_classes": sorted({s.attack.value for s in HELDOUT_ATTACKS}),
        "scenarios": [
            {
                "id": s.code,
                "kind": "attack" if s.attack else "benign",
                "attack_class": s.attack.value if s.attack else None,
                "attacker": s.attacker,
                "attacker_role": ATTACKER_ROLES[s.attacker],
                "steps": len(s.steps),
                "expected": [
                    {
                        "step": i,
                        "population": st.population,
                        "leaks": st.leaks,
                        "exposure": EXPOSURE[s.code][i - 1],
                        "harness_expected_decision": st.expected.value,
                        "new_conversation": st.new_conversation,
                        "has_reference": st.reference_sql is not None,
                    }
                    for i, st in enumerate(s.steps, start=1)
                ],
                "recovery": RECOVERY.get(s.code),
            }
            for s in HELDOUT
        ],
    }
