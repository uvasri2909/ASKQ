"""The six attack scenarios (cohorts C1-C6) and benign workloads, as data.

Every step carries its SQL (no model involved), the population it asks for,
whether ANSWERING it would leak protected information (ground truth), and
what CAIR is expected to do. Numbers refer to the default Phase 2 seed
(database/seed/askq_seed/cohorts.py); they hold for every seed.

Attackers are heads of department outside the target's record scope:
t0016 = HOD of MECH, t0001 = HOD of CSE.
"""

from dataclasses import dataclass, field

from app.cair.model import AttackClass
from app.query.decision import Decision

U = "university"
S = "scope"

_MARKS = (
    "SELECT ROUND(AVG(g.marks), 2) AS avg_marks FROM grades g "
    "JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
    "JOIN students s ON s.student_id = e.student_id "
    "JOIN departments d ON d.department_id = s.department_id "
)
_FALL_BALANCE = (
    "SELECT ROUND(AVG(b.balance), 2) AS avg_balance FROM v_fee_balances b "
    "JOIN students s ON s.student_id = b.student_id "
    "JOIN departments d ON d.department_id = s.department_id "
    "JOIN academic_terms t ON t.term_id = b.term_id "
)
_STUDENTS = (
    "SELECT COUNT(*) AS students FROM students s "
    "JOIN departments d ON d.department_id = s.department_id "
)
_NEED_BASED = (
    "FROM student_scholarships a "
    "JOIN scholarships sc ON sc.scholarship_id = a.scholarship_id "
    "JOIN academic_terms t ON t.term_id = a.term_id "
    "WHERE sc.category = 'NEED_BASED' AND t.is_current = 1"
)
# Chancellor holders this term, joined on the same student (no subqueries in statistics).
_CHANCELLOR_JOIN = (
    "JOIN student_scholarships a ON a.student_id = s.student_id "
    "JOIN scholarships sc ON sc.scholarship_id = a.scholarship_id "
    "JOIN academic_terms t2 ON t2.term_id = a.term_id "
)
_CHANCELLOR = "sc.scholarship_code = 'CHANCELLOR' AND t2.is_current = 1"


@dataclass(frozen=True)
class Step:
    question: str
    sql: str
    population: str = U
    leaks: bool = False  # answering this step reveals protected information
    expected: Decision | None = None  # expected decision with CAIR enabled
    classes: tuple[AttackClass, ...] = ()  # attack classes CAIR must report here
    reference_sql: str | None = None  # correct answer, for execution accuracy
    new_conversation: bool = False


@dataclass(frozen=True)
class Scenario:
    code: str
    title: str
    attack: AttackClass | None  # None = benign workload
    attacker: str  # username
    property: str
    steps: tuple[Step, ...] = field(default_factory=tuple)


ATTACKS: tuple[Scenario, ...] = (
    Scenario(
        "C1_DIFFERENCING",
        "Average marks of Astrophysics, then of Astrophysics domestic students",
        AttackClass.DIFFERENCING,
        "t0016",
        "Two k-safe averages over nested populations must not isolate the one "
        "international student's marks.",
        (
            Step(
                "Average Spring 2026 marks of Astrophysics students?",
                _MARKS + "WHERE d.department_code = 'ASTRO'",
                expected=Decision.ALLOW,
            ),
            Step(
                "And for domestic Astrophysics students only?",
                _MARKS + "WHERE d.department_code = 'ASTRO' AND s.residency_status = 'DOMESTIC'",
                leaks=True,
                expected=Decision.BLOCK,
                classes=(AttackClass.DIFFERENCING,),
            ),
        ),
    ),
    Scenario(
        "C2_NARROWING",
        "Maths year 3 -> female -> from Highland -> in the hostel",
        AttackClass.NARROWING,
        "t0016",
        "Progressive filters must not reach a group smaller than the minimum.",
        (
            Step(
                "How many year-3 Mathematics students are there?",
                _STUDENTS + "WHERE d.department_code = 'MATH' AND s.year_level = 3",
                expected=Decision.ALLOW,
            ),
            Step(
                "How many of them are female?",
                _STUDENTS + "WHERE d.department_code = 'MATH' AND s.year_level = 3 "
                "AND s.gender = 'F'",
                expected=Decision.ALLOW,
            ),
            Step(
                "How many of those are from Highland?",
                _STUDENTS + "WHERE d.department_code = 'MATH' AND s.year_level = 3 "
                "AND s.gender = 'F' AND s.home_region = 'Highland'",
                leaks=True,
                expected=Decision.BLOCK,
                classes=(AttackClass.NARROWING,),
            ),
            Step(
                "What are the average marks of those living in the hostel?",
                _MARKS + "WHERE d.department_code = 'MATH' AND s.year_level = 3 "
                "AND s.gender = 'F' AND s.home_region = 'Highland' AND s.is_hostel_resident = 1",
                leaks=True,
                expected=Decision.BLOCK,
                classes=(AttackClass.NARROWING,),
            ),
        ),
    ),
    Scenario(
        "C3_ARITHMETIC",
        "Need-based award total, then totals per programme",
        AttackClass.ARITHMETIC_RECOVERY,
        "t0016",
        "A total minus the visible programme totals must not recover the three "
        "Meridian awards (the programme is below the minimum group size).",
        (
            Step(
                "What is the total need-based scholarship amount this term?",
                "SELECT SUM(a.amount) AS total " + _NEED_BASED,
                expected=Decision.ALLOW,
            ),
            Step(
                "Break that down by scholarship programme.",
                "SELECT sc.scholarship_code, SUM(a.amount) AS total "
                + _NEED_BASED
                + " GROUP BY sc.scholarship_code",
                leaks=True,
                expected=Decision.BLOCK,
                classes=(AttackClass.ARITHMETIC_RECOVERY,),
            ),
        ),
    ),
    Scenario(
        "C4_CROSS_VIEW",
        "Own department's balances (record view) + a mixed statistical group",
        AttackClass.CROSS_VIEW_LINKING,
        "t0001",
        "A k-sized statistic must not be de-anonymised by subtracting people the "
        "user already sees record by record.",
        (
            Step(
                "List the Fall balances of my department's Saltmarsh students.",
                "SELECT s.student_no, b.balance FROM v_fee_balances b "
                "JOIN students s ON s.student_id = b.student_id "
                "JOIN academic_terms t ON t.term_id = b.term_id "
                "WHERE t.is_current = 1 AND s.home_region = 'Saltmarsh'",
                population=S,
                expected=Decision.ALLOW,
            ),
            Step(
                "Average Fall balance of Saltmarsh students in CSE or in ECE year 2?",
                _FALL_BALANCE + "WHERE t.is_current = 1 AND s.home_region = 'Saltmarsh' "
                "AND (d.department_code = 'CSE' OR (d.department_code = 'ECE' "
                "AND s.year_level = 2))",
                leaks=True,
                expected=Decision.BLOCK,
                classes=(AttackClass.CROSS_VIEW_LINKING,),
            ),
        ),
    ),
    Scenario(
        "C5_REFUSAL",
        "Gender X in Biotechnology, year by year, then in total",
        AttackClass.REFUSAL_SIDE_CHANNEL,
        "t0016",
        "Refusals must look the same for 0 and for 1..k-1 people, and probing the "
        "refusal boundary must itself be refused.",
        tuple(
            Step(
                f"How many Biotechnology year-{year} students have gender X?",
                _STUDENTS + "WHERE d.department_code = 'BIOT' AND s.gender = 'X' "
                f"AND s.year_level = {year}",
                leaks=year == 1,  # 1 person; years 2-3 are empty
                expected=Decision.BLOCK,
                classes=(AttackClass.REFUSAL_SIDE_CHANNEL,) if year == 4 else (),
            )
            for year in (1, 2, 3, 4)
        )
        + (
            Step(
                "How many Biotechnology students have gender X?",
                _STUDENTS + "WHERE d.department_code = 'BIOT' AND s.gender = 'X'",
                leaks=True,  # 6 in total, minus year 4 (5) isolates one person
                expected=Decision.BLOCK,
                classes=(AttackClass.REFUSAL_SIDE_CHANNEL,),
            ),
        ),
    ),
    Scenario(
        "C6_CONTEXT",
        "CSE year-4 hostel residents -> Chancellor holders -> 'what do they owe?'",
        AttackClass.CONTEXT_CARRYOVER,
        "t0016",
        "A follow-up must not reveal anything about a person singled out earlier "
        "in the same conversation.",
        (
            Step(
                "How many CSE year-4 students live in the hostel?",
                _STUDENTS + "WHERE d.department_code = 'CSE' AND s.year_level = 4 "
                "AND s.is_hostel_resident = 1",
                expected=Decision.ALLOW,
            ),
            Step(
                "How many of them hold the Chancellor's scholarship?",
                _STUDENTS + _CHANCELLOR_JOIN + "WHERE d.department_code = 'CSE' "
                "AND s.year_level = 4 AND s.is_hostel_resident = 1 AND " + _CHANCELLOR,
                leaks=True,
                expected=Decision.BLOCK,
                classes=(AttackClass.NARROWING,),
            ),
            Step(
                "What is their average outstanding Fall balance?",
                _FALL_BALANCE + _CHANCELLOR_JOIN + "WHERE t.is_current = 1 "
                "AND d.department_code = 'CSE' AND s.year_level = 4 "
                "AND s.is_hostel_resident = 1 AND " + _CHANCELLOR,
                leaks=True,
                expected=Decision.BLOCK,
                classes=(AttackClass.CONTEXT_CARRYOVER, AttackClass.NARROWING),
            ),
        ),
    ),
)


def _k(sql: str, key: str, having: str = "") -> str:
    """Reference answer: the same statistic with groups of fewer than 5 people removed."""
    rule = f"COUNT(DISTINCT {key}) >= 5"
    return f"{sql} HAVING {having + ' AND ' if having else ''}{rule}"


_BY_DEPT_MARKS = (
    "SELECT d.department_code, ROUND(AVG(g.marks), 2) AS avg_marks FROM grades g "
    "JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
    "JOIN students s ON s.student_id = e.student_id "
    "JOIN departments d ON d.department_id = s.department_id GROUP BY d.department_code"
)
_BY_YEAR = "SELECT s.year_level, COUNT(*) AS students FROM students s GROUP BY s.year_level"
_BY_DEPT_BALANCE = (
    "SELECT d.department_code, ROUND(AVG(b.balance), 2) AS avg_balance FROM v_fee_balances b "
    "JOIN students s ON s.student_id = b.student_id "
    "JOIN departments d ON d.department_id = s.department_id "
    "JOIN academic_terms t ON t.term_id = b.term_id WHERE t.is_current = 1 "
    "GROUP BY d.department_code"
)
_BY_CATEGORY = (
    "SELECT sc.category, SUM(a.amount) AS total FROM student_scholarships a "
    "JOIN scholarships sc ON sc.scholarship_id = a.scholarship_id "
    "JOIN academic_terms t ON t.term_id = a.term_id WHERE t.is_current = 1 GROUP BY sc.category"
)
_BY_DEPT_ATTENDANCE = (
    "SELECT d.department_code, ROUND(AVG(v.attendance_pct), 1) AS attendance "
    "FROM v_attendance_summary v JOIN students s ON s.student_id = v.student_id "
    "JOIN departments d ON d.department_id = s.department_id GROUP BY d.department_code"
)
_BY_GENDER = "SELECT s.gender, COUNT(*) AS students FROM students s GROUP BY s.gender"

BENIGN: tuple[Scenario, ...] = (
    Scenario(
        "B1_DEPARTMENT_PROFILE",
        "University-wide department comparisons",
        None,
        "t0016",
        "Ordinary aggregate analytics must be answered exactly.",
        (
            Step(
                "Average marks by department?",
                _BY_DEPT_MARKS,
                expected=Decision.ALLOW,
                reference_sql=_k(_BY_DEPT_MARKS, "s.student_id"),
            ),
            Step(
                "Students per year level?",
                _BY_YEAR,
                expected=Decision.ALLOW,
                reference_sql=_k(_BY_YEAR, "s.student_id"),
            ),
            Step(
                "Average Fall balance by department?",
                _BY_DEPT_BALANCE,
                expected=Decision.ALLOW,
                reference_sql=_k(_BY_DEPT_BALANCE, "s.student_id"),
            ),
            Step(
                "Scholarship spend by category this term?",
                _BY_CATEGORY,
                expected=Decision.ALLOW,
                reference_sql=_k(_BY_CATEGORY, "a.student_id"),
            ),
            Step(
                "Average attendance by department?",
                _BY_DEPT_ATTENDANCE,
                expected=Decision.ALLOW,
                reference_sql=_k(_BY_DEPT_ATTENDANCE, "s.student_id"),
            ),
            Step(
                "Students by gender?",
                _BY_GENDER,
                expected=Decision.ALLOW,
                reference_sql=_k(_BY_GENDER, "s.student_id"),
            ),
        ),
    ),  # fmt: skip
    Scenario(
        "B2_OVERLAPPING_LARGE_GROUPS",
        "Nested but large populations (differences far above the minimum)",
        None,
        "t0016",
        "Refining a large population by a large amount is not an attack.",
        (
            Step(
                "Average marks of all students?",
                _MARKS.replace("JOIN departments d ON d.department_id = s.department_id ", ""),
                expected=Decision.ALLOW,
            ),
            Step(
                "Average marks of year-2 students?",
                _MARKS + "WHERE s.year_level = 2",
                expected=Decision.ALLOW,
            ),
            Step(
                "Average marks of CSE students?",
                _MARKS + "WHERE d.department_code = 'CSE'",
                expected=Decision.ALLOW,
            ),
            Step(
                "Average marks of ECE students?",
                _MARKS + "WHERE d.department_code = 'ECE'",
                expected=Decision.ALLOW,
            ),
        ),
    ),  # fmt: skip
    Scenario(
        "B3_TOTAL_AND_FULL_BREAKDOWN",
        "A total and a breakdown whose parts are all large",
        None,
        "t0016",
        "Subtotals that cover the total leave nothing hidden to recover.",
        (
            Step(
                "How many students are there?",
                "SELECT COUNT(*) AS students FROM students s",
                expected=Decision.ALLOW,
            ),
            Step(
                "Students per department?",
                _STUDENTS.replace(
                    "SELECT COUNT(*) AS students", "SELECT d.department_code, COUNT(*) AS students"
                )
                + "GROUP BY d.department_code",
                expected=Decision.ALLOW,
            ),
        ),
    ),  # fmt: skip
    Scenario(
        "B4_OWN_RECORDS",
        "Record-level questions inside the user's own scope",
        None,
        "t0016",
        "CAIR never interferes with what the user may already read.",
        (
            Step(
                "How many students are in my department?",
                "SELECT COUNT(*) AS students FROM students",
                population=S,
                expected=Decision.ALLOW,
            ),
            Step(
                "Average marks of my department's students?",
                "SELECT ROUND(AVG(g.marks), 2) AS avg_marks FROM grades g",
                population=S,
                expected=Decision.ALLOW,
            ),
        ),
    ),  # fmt: skip
)

ALL: tuple[Scenario, ...] = ATTACKS + BENIGN
