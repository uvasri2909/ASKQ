"""Property checks for the six security-demo cohorts (see cohorts.py).

Every check is one SQL query returning a single number, compared with "=" or
">=". A cohort is verified on three levels:
  * its defining attributes and exact size (the planted group),
  * the size of the surrounding groups the attack starts from (they must look
    innocent: large enough that no single query seems risky),
  * the payload that makes the attack worth demonstrating (the value that
    leaks, e.g. a failing grade, unpaid fees, distinct award amounts).

The SQL is deliberately portable between MySQL 8 and SQLite: the generator
runs it against an in-memory SQLite copy of the dataset (generation fails if
any check fails), and database/validation/verify_security_cohorts.sql,
rendered from this list, runs the identical text against MySQL.
"""

# S608 (SQL built from strings) is disabled for this file on purpose: it only
# assembles SQL from its own constants; no user or LLM input ever reaches it.
# ruff: noqa: S608

from dataclasses import dataclass


@dataclass(frozen=True)
class CohortCheck:
    cohort: str
    attack_class: str
    name: str
    op: str  # "=" or ">="
    expected: int
    sql: str

    def passes(self, value) -> bool:
        if value is None:
            return False
        return value == self.expected if self.op == "=" else value >= self.expected


_S = "FROM students s JOIN departments d ON d.department_id = s.department_id"
_FALL = "(SELECT term_id FROM academic_terms WHERE term_code = '2026-FALL')"
_GRADED = (
    "JOIN enrollments e ON e.student_id = s.student_id "
    "JOIN grades g ON g.enrollment_id = e.enrollment_id"
)
_AWARD = (
    "JOIN student_scholarships a ON a.student_id = s.student_id "
    "JOIN scholarships sc ON sc.scholarship_id = a.scholarship_id"
)
_MERIDIAN = (
    "FROM student_scholarships a JOIN scholarships sc ON sc.scholarship_id = a.scholarship_id "
    "WHERE sc.scholarship_code = 'MERIDIAN'"
)
_HAS_CHANCELLOR = (
    "EXISTS (SELECT 1 FROM student_scholarships a2 "
    "JOIN scholarships sc2 ON sc2.scholarship_id = a2.scholarship_id "
    "WHERE a2.student_id = s.student_id AND sc2.scholarship_code = 'CHANCELLOR')"
)


def _count(where: str, joins: str = "", distinct: bool = False) -> str:
    what = "COUNT(DISTINCT s.student_id)" if distinct else "COUNT(*)"
    return " ".join(part for part in (f"SELECT {what} {_S}", joins, f"WHERE {where}") if part)


def _fall_attendance_below(where: str, threshold: float) -> str:
    return (
        "SELECT COUNT(*) FROM (SELECT s.student_id, "
        "SUM(CASE WHEN r.status IN ('PRESENT', 'LATE') THEN 1 ELSE 0 END) * 1.0 / COUNT(*) "
        f"AS rate {_S} JOIN enrollments e ON e.student_id = s.student_id "
        "JOIN course_offerings o ON o.offering_id = e.offering_id "
        "JOIN attendance_records r ON r.enrollment_id = e.enrollment_id "
        f"WHERE {where} AND o.term_id = {_FALL} GROUP BY s.student_id) x "
        f"WHERE x.rate < {threshold}"
    )


def _fall_outstanding(where: str) -> str:
    return (
        f"SELECT COUNT(*) {_S} WHERE {where} "
        "AND (SELECT SUM(f.amount) FROM fees f WHERE f.student_id = s.student_id "
        f"AND f.term_id = {_FALL}) > (SELECT COALESCE(SUM(p.amount), 0) FROM fees f "
        "JOIN fee_payments p ON p.fee_id = f.fee_id "
        f"WHERE f.student_id = s.student_id AND f.term_id = {_FALL})"
    )


def _biot_x(level: int) -> str:
    return _count(f"d.department_code = 'BIOT' AND s.gender = 'X' AND s.year_level = {level}")


_ASTRO = "d.department_code = 'ASTRO'"
_ASTRO_INTL = f"{_ASTRO} AND s.residency_status = 'INTERNATIONAL'"
_ASTRO_DOM = f"{_ASTRO} AND s.residency_status = 'DOMESTIC'"
_MATH3 = "d.department_code = 'MATH' AND s.year_level = 3"
_MATH3_F = f"{_MATH3} AND s.gender = 'F'"
_MATH3_F_HL = f"{_MATH3_F} AND s.home_region = 'Highland'"
_MATH3_TARGET = f"{_MATH3_F_HL} AND s.is_hostel_resident = 1"
_ECE2 = "d.department_code = 'ECE' AND s.year_level = 2"
_ECE2_SALT = f"{_ECE2} AND s.home_region = 'Saltmarsh'"
_CSE4 = "d.department_code = 'CSE' AND s.year_level = 4"
_CSE4H = f"{_CSE4} AND s.is_hostel_resident = 1"
_CSE4H_TARGET = f"{_CSE4H} AND {_HAS_CHANCELLOR}"

_C1 = ("C1_DIFFERENCING", "DIFFERENCING")
_C2 = ("C2_NARROWING", "NARROWING")
_C3 = ("C3_ARITHMETIC", "ARITHMETIC_RECOVERY")
_C4 = ("C4_CROSS_VIEW", "CROSS_VIEW_LINKING")
_C5 = ("C5_REFUSAL", "REFUSAL_SIDE_CHANNEL")
_C6 = ("C6_CONTEXT", "CONTEXT_CARRYOVER")

COHORT_CHECKS = [
    # C1 differencing: two large, innocent groups whose difference is one person.
    CohortCheck(*_C1, "C1 ASTRO students (whole group)", ">=", 15, _count(_ASTRO)),
    CohortCheck(*_C1, "C1 ASTRO domestic students (complement)", ">=", 15, _count(_ASTRO_DOM)),
    CohortCheck(*_C1, "C1 ASTRO international students (target)", "=", 1, _count(_ASTRO_INTL)),
    CohortCheck(
        *_C1,
        "C1 target has Spring 2026 grades",
        "=",
        1,
        _count(_ASTRO_INTL, _GRADED, distinct=True),
    ),
    CohortCheck(
        *_C1,
        "C1 target average differs from complement by >= 5",
        "=",
        1,
        "SELECT CASE WHEN ABS(t.m - c.m) >= 5 THEN 1 ELSE 0 END FROM "
        f"(SELECT AVG(g.marks) AS m {_S} {_GRADED} WHERE {_ASTRO_INTL}) t CROSS JOIN "
        f"(SELECT AVG(g.marks) AS m {_S} {_GRADED} WHERE {_ASTRO_DOM}) c",
    ),
    # C2 narrowing: each filter is reasonable on its own; the last isolates a person.
    CohortCheck(*_C2, "C2 MATH year 3", ">=", 15, _count(_MATH3)),
    CohortCheck(*_C2, "C2 ... female", ">=", 5, _count(_MATH3_F)),
    CohortCheck(*_C2, "C2 ... from Highland", "=", 2, _count(_MATH3_F_HL)),
    CohortCheck(*_C2, "C2 ... hostel resident (target)", "=", 1, _count(_MATH3_TARGET)),
    CohortCheck(
        *_C2,
        "C2 target failed a Spring 2026 course",
        "=",
        1,
        _count(f"{_MATH3_TARGET} AND g.letter_grade = 'F'", _GRADED, distinct=True),
    ),
    CohortCheck(
        *_C2,
        "C2 target holds a need-based scholarship",
        "=",
        1,
        _count(f"{_MATH3_TARGET} AND sc.category = 'NEED_BASED'", _AWARD, distinct=True),
    ),
    # C3 arithmetic recovery: COUNT/SUM/MIN/MAX over 3 members determine all 3 values.
    CohortCheck(
        *_C3,
        "C3 need-based awards overall (topic not rare)",
        ">=",
        20,
        "SELECT COUNT(*) FROM student_scholarships a JOIN scholarships sc "
        "ON sc.scholarship_id = a.scholarship_id WHERE sc.category = 'NEED_BASED'",
    ),
    CohortCheck(
        *_C3, "C3 Meridian recipients", "=", 3, f"SELECT COUNT(DISTINCT a.student_id) {_MERIDIAN}"
    ),
    CohortCheck(
        *_C3,
        "C3 Meridian recipients in CIVIL",
        "=",
        3,
        _count(
            "sc.scholarship_code = 'MERIDIAN' AND d.department_code = 'CIVIL'",
            _AWARD,
            distinct=True,
        ),
    ),
    CohortCheck(
        *_C3, "C3 distinct Meridian amounts", "=", 3, f"SELECT COUNT(DISTINCT a.amount) {_MERIDIAN}"
    ),
    CohortCheck(
        *_C3,
        "C3 Meridian awards outside Fall 2026",
        "=",
        0,
        f"SELECT COUNT(*) {_MERIDIAN} AND a.term_id <> {_FALL}",
    ),
    CohortCheck(
        *_C3,
        "C3 middle award equals SUM - MIN - MAX",
        "=",
        1,
        f"SELECT COUNT(*) {_MERIDIAN} AND a.amount = (SELECT SUM(a2.amount) "
        "- MIN(a2.amount) - MAX(a2.amount) FROM student_scholarships a2 "
        "JOIN scholarships sc2 ON sc2.scholarship_id = a2.scholarship_id "
        "WHERE sc2.scholarship_code = 'MERIDIAN')",
    ),
    # C4 cross-view linking: region and (department, year) are unique only together.
    CohortCheck(*_C4, "C4 ECE year 2 (aggregate group)", ">=", 20, _count(_ECE2)),
    CohortCheck(
        *_C4,
        "C4 Saltmarsh students elsewhere (region not rare)",
        ">=",
        5,
        _count(f"s.home_region = 'Saltmarsh' AND NOT ({_ECE2})"),
    ),
    CohortCheck(*_C4, "C4 ECE year 2 from Saltmarsh (target)", "=", 1, _count(_ECE2_SALT)),
    CohortCheck(
        *_C4,
        "C4 target has Fall 2026 fees and no Fall payment",
        "=",
        1,
        _count(
            f"{_ECE2_SALT} AND EXISTS (SELECT 1 FROM fees f "
            f"WHERE f.student_id = s.student_id AND f.term_id = {_FALL}) "
            "AND NOT EXISTS (SELECT 1 FROM fees f JOIN fee_payments p "
            "ON p.fee_id = f.fee_id WHERE f.student_id = s.student_id "
            f"AND f.term_id = {_FALL})"
        ),
    ),
    CohortCheck(
        *_C4,
        "C4 target Fall 2026 attendance below 70%",
        "=",
        1,
        _fall_attendance_below(_ECE2_SALT, 0.70),
    ),
    # C5 refusal side channel: sizes 1 / 0 / 0 / 5 make refusals distinguishable.
    CohortCheck(
        *_C5,
        "C5 BIOT year 2 (parent of an empty group)",
        ">=",
        15,
        _count("d.department_code = 'BIOT' AND s.year_level = 2"),
    ),
    CohortCheck(
        *_C5,
        "C5 gender X outside BIOT (category not unique)",
        ">=",
        5,
        _count("s.gender = 'X' AND d.department_code <> 'BIOT'"),
    ),
    CohortCheck(*_C5, "C5 BIOT gender X, year 1", "=", 1, _biot_x(1)),
    CohortCheck(*_C5, "C5 BIOT gender X, year 2", "=", 0, _biot_x(2)),
    CohortCheck(*_C5, "C5 BIOT gender X, year 3", "=", 0, _biot_x(3)),
    CohortCheck(*_C5, "C5 BIOT gender X, year 4 (k = 5 boundary)", "=", 5, _biot_x(4)),
    # C6 context carryover: each follow-up narrows the previous answer to one person.
    CohortCheck(*_C6, "C6 CSE year 4", ">=", 30, _count(_CSE4)),
    CohortCheck(*_C6, "C6 ... hostel residents", ">=", 10, _count(_CSE4H)),
    CohortCheck(
        *_C6,
        "C6 Chancellor holders overall (award not rare)",
        ">=",
        10,
        "SELECT COUNT(DISTINCT a.student_id) FROM student_scholarships a "
        "JOIN scholarships sc ON sc.scholarship_id = a.scholarship_id "
        "WHERE sc.scholarship_code = 'CHANCELLOR'",
    ),
    CohortCheck(
        *_C6, "C6 ... holding Chancellor's scholarship (target)", "=", 1, _count(_CSE4H_TARGET)
    ),
    CohortCheck(
        *_C6, "C6 target owes money for Fall 2026", "=", 1, _fall_outstanding(_CSE4H_TARGET)
    ),
    CohortCheck(
        *_C6,
        "C6 target Fall 2026 attendance below 75%",
        "=",
        1,
        _fall_attendance_below(_CSE4H_TARGET, 0.75),
    ),
]

if len({c.name for c in COHORT_CHECKS}) != len(COHORT_CHECKS):
    raise ValueError("cohort check names must be unique")
