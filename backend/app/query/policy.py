"""Per-role data policy: which tables a role may query, which columns it may not
see, and the row-scope predicate the SERVER injects for each table.

This is enforcement, not guidance. The model is told about the policy only so
that it writes useful SQL; the authorizer (authorization.py) applies it to
whatever SQL comes back, whatever the model or the user said.

  Reference data (departments, academic_terms, grade_scale, courses,
  course_offerings, class_sessions, scholarships) is visible to every role.

  ADMIN    everything, no row filter
  HOD      people, enrollments, grades, attendance, fees and awards of their
           own department (students in it, or offerings of its courses)
  TEACHER  their department's teachers; students they teach or advise, and
           those students' enrollments/grades/attendance in the teacher's
           offerings or as advisees; no financial data
  STUDENT  their own records; the teachers of their offerings and their advisor

Scope ids are integers from the server-side UserContext and are rendered with
int(), so nothing from the client or the model reaches these predicates.
"""

from dataclasses import dataclass, field

from app.rbac.roles import Role
from app.rbac.scope import Scope

REFERENCE_TABLES = frozenset(
    {
        "departments",
        "academic_terms",
        "grade_scale",
        "courses",
        "course_offerings",
        "class_sessions",
        "scholarships",
    }
)
FINANCIAL_TABLES = frozenset({"fees", "fee_payments", "student_scholarships", "v_fee_balances"})
PEOPLE_AND_RECORDS = frozenset(
    {
        "teachers",
        "students",
        "enrollments",
        "grades",
        "attendance_records",
        "v_attendance_summary",
    }
)
ALL_TABLES = REFERENCE_TABLES | FINANCIAL_TABLES | PEOPLE_AND_RECORDS


@dataclass(frozen=True, slots=True)
class RolePolicy:
    tables: frozenset[str]
    # table -> columns hidden from this role (removed from the derived table).
    denied_columns: dict[str, frozenset[str]] = field(default_factory=dict)
    # table -> WHERE predicate template; {db} and scope ids are filled in by the server.
    row_scope: dict[str, str] = field(default_factory=dict)
    scope_description: str = ""

    def hidden_columns(self, table: str) -> frozenset[str]:
        return self.denied_columns.get(table, frozenset())


# ---- reusable scope subqueries (templates) ----
_DEPT_STUDENTS = "SELECT student_id FROM {db}.students WHERE department_id = {department_id}"
_DEPT_OFFERINGS = (
    "SELECT o.offering_id FROM {db}.course_offerings o "
    "JOIN {db}.courses c ON c.course_id = o.course_id WHERE c.department_id = {department_id}"
)
_DEPT_ENROLLMENTS = (
    f"SELECT enrollment_id FROM {{db}}.enrollments "
    f"WHERE student_id IN ({_DEPT_STUDENTS}) OR offering_id IN ({_DEPT_OFFERINGS})"
)
_TEACHER_OFFERINGS = "SELECT offering_id FROM {db}.course_offerings WHERE teacher_id = {teacher_id}"
_TEACHER_ADVISEES = "SELECT student_id FROM {db}.students WHERE advisor_teacher_id = {teacher_id}"
_TEACHER_ENROLLMENTS = (
    f"SELECT enrollment_id FROM {{db}}.enrollments "
    f"WHERE offering_id IN ({_TEACHER_OFFERINGS}) OR student_id IN ({_TEACHER_ADVISEES})"
)
_TEACHER_STUDENTS = (
    f"SELECT student_id FROM {{db}}.enrollments WHERE offering_id IN ({_TEACHER_OFFERINGS}) "
    f"UNION {_TEACHER_ADVISEES}"
)
_OWN_ENROLLMENTS = "SELECT enrollment_id FROM {db}.enrollments WHERE student_id = {student_id}"
_OWN_TEACHERS = (
    "SELECT o.teacher_id FROM {db}.course_offerings o "
    "JOIN {db}.enrollments e ON e.offering_id = o.offering_id WHERE e.student_id = {student_id} "
    "UNION SELECT advisor_teacher_id FROM {db}.students WHERE student_id = {student_id}"
)

_SALARY = {"teachers": frozenset({"annual_salary"})}

POLICIES: dict[Role, RolePolicy] = {
    Role.ADMIN: RolePolicy(
        tables=ALL_TABLES,
        scope_description="the whole university",
    ),
    Role.HOD: RolePolicy(
        tables=ALL_TABLES,
        denied_columns={**_SALARY, "students": frozenset({"date_of_birth"})},
        row_scope={
            "teachers": "department_id = {department_id}",
            "students": "department_id = {department_id}",
            "enrollments": (
                f"student_id IN ({_DEPT_STUDENTS}) OR offering_id IN ({_DEPT_OFFERINGS})"
            ),
            "grades": f"enrollment_id IN ({_DEPT_ENROLLMENTS})",
            "attendance_records": f"enrollment_id IN ({_DEPT_ENROLLMENTS})",
            "v_attendance_summary": f"enrollment_id IN ({_DEPT_ENROLLMENTS})",
            "fees": f"student_id IN ({_DEPT_STUDENTS})",
            "fee_payments": (
                f"fee_id IN (SELECT fee_id FROM {{db}}.fees WHERE student_id IN ({_DEPT_STUDENTS}))"
            ),
            "student_scholarships": f"student_id IN ({_DEPT_STUDENTS})",
            "v_fee_balances": f"student_id IN ({_DEPT_STUDENTS})",
        },
        scope_description="your own department (department_id = {department_id})",
    ),
    Role.TEACHER: RolePolicy(
        tables=REFERENCE_TABLES | PEOPLE_AND_RECORDS,
        denied_columns={**_SALARY, "students": frozenset({"date_of_birth", "gender"})},
        row_scope={
            "teachers": (
                "department_id = (SELECT department_id FROM {db}.teachers "
                "WHERE teacher_id = {teacher_id})"
            ),
            "students": f"student_id IN ({_TEACHER_STUDENTS})",
            "enrollments": (
                f"offering_id IN ({_TEACHER_OFFERINGS}) OR student_id IN ({_TEACHER_ADVISEES})"
            ),
            "grades": f"enrollment_id IN ({_TEACHER_ENROLLMENTS})",
            "attendance_records": f"enrollment_id IN ({_TEACHER_ENROLLMENTS})",
            "v_attendance_summary": f"enrollment_id IN ({_TEACHER_ENROLLMENTS})",
        },
        scope_description=(
            "the offerings you teach and the students you teach or advise "
            "(teacher_id = {teacher_id})"
        ),
    ),
    Role.STUDENT: RolePolicy(
        tables=ALL_TABLES,
        denied_columns=_SALARY,
        row_scope={
            "students": "student_id = {student_id}",
            "teachers": f"teacher_id IN ({_OWN_TEACHERS})",
            "enrollments": "student_id = {student_id}",
            "grades": f"enrollment_id IN ({_OWN_ENROLLMENTS})",
            "attendance_records": f"enrollment_id IN ({_OWN_ENROLLMENTS})",
            "v_attendance_summary": "student_id = {student_id}",
            "fees": "student_id = {student_id}",
            "fee_payments": (
                "fee_id IN (SELECT fee_id FROM {db}.fees WHERE student_id = {student_id})"
            ),
            "student_scholarships": "student_id = {student_id}",
            "v_fee_balances": "student_id = {student_id}",
        },
        scope_description="your own records (student_id = {student_id})",
    ),
}


class ScopeError(Exception):
    """The user's scope lacks an id its role's policy needs (fail closed)."""


def _scope_values(scope: Scope) -> dict[str, int]:
    values = {}
    for name in ("department_id", "teacher_id", "student_id"):
        value = getattr(scope, name)
        if value is not None:
            values[name] = int(value)
    return values


def render(template: str, scope: Scope, db: str) -> str:
    try:
        return template.format(db=db, **_scope_values(scope))
    except KeyError as exc:
        raise ScopeError(f"scope has no {exc.args[0]}") from None


def policy_for(role: Role) -> RolePolicy:
    return POLICIES[role]
