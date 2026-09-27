"""Application-controlled description of the queryable organisational data.

These are exactly the 15 tables and 2 views granted to askq_reader in
database/accounts/grants.sql. users, roles and all of askq_system are
deliberately absent: they are not queryable and are never described to the
model. The column lists mirror database/schema/02_university_schema.sql and
05_views.sql (bookkeeping columns such as created_at are left out);
tests/integration checks them against the live database.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ColumnSpec:
    name: str
    type: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class TableSpec:
    name: str
    description: str
    columns: tuple[ColumnSpec, ...]
    is_view: bool = False

    @property
    def column_names(self) -> tuple[str, ...]:
        return tuple(c.name for c in self.columns)


def _c(name: str, type_: str, description: str = "") -> ColumnSpec:
    return ColumnSpec(name, type_, description)


TABLES: tuple[TableSpec, ...] = (
    TableSpec(
        "departments",
        "Academic departments.",
        (
            _c("department_id", "SMALLINT", "primary key"),
            _c("department_code", "VARCHAR(10)", "e.g. CSE, ECE"),
            _c("department_name", "VARCHAR(100)"),
            _c("building", "VARCHAR(100)"),
            _c("established_year", "SMALLINT"),
            _c("head_teacher_id", "INT", "-> teachers.teacher_id (head of department)"),
        ),
    ),
    TableSpec(
        "academic_terms",
        "Terms: Spring 2026 (completed) and Fall 2026 (current).",
        (
            _c("term_id", "SMALLINT", "primary key"),
            _c("term_code", "VARCHAR(12)", "e.g. 2026-SPRING, 2026-FALL"),
            _c("term_name", "VARCHAR(50)"),
            _c("academic_year", "CHAR(9)", "e.g. 2025-2026"),
            _c("season", "VARCHAR(6)", "SPRING | SUMMER | FALL"),
            _c("start_date", "DATE"),
            _c("end_date", "DATE"),
            _c("is_current", "TINYINT(1)", "1 for the current term"),
        ),
    ),
    TableSpec(
        "grade_scale",
        "Letter grades: a letter applies to marks >= min_marks.",
        (
            _c("letter_grade", "VARCHAR(2)", "primary key, e.g. A, B+, F"),
            _c("min_marks", "DECIMAL(5,2)"),
            _c("grade_points", "DECIMAL(3,2)", "4.0 scale"),
            _c("description", "VARCHAR(50)"),
        ),
    ),
    TableSpec(
        "teachers",
        "Teaching staff.",
        (
            _c("teacher_id", "INT", "primary key"),
            _c("employee_no", "VARCHAR(10)", "e.g. T0001"),
            _c("first_name", "VARCHAR(50)"),
            _c("last_name", "VARCHAR(50)"),
            _c("email", "VARCHAR(255)"),
            _c("department_id", "SMALLINT", "-> departments"),
            _c("designation", "VARCHAR(30)", "Professor | Associate Professor | ..."),
            _c("hire_date", "DATE"),
            _c("annual_salary", "DECIMAL(10,2)"),
            _c("is_active", "TINYINT(1)"),
        ),
    ),
    TableSpec(
        "students",
        "Students.",
        (
            _c("student_id", "INT", "primary key"),
            _c("student_no", "VARCHAR(12)", "e.g. S20230001"),
            _c("first_name", "VARCHAR(50)"),
            _c("last_name", "VARCHAR(50)"),
            _c("email", "VARCHAR(255)"),
            _c("gender", "CHAR(1)", "F | M | X"),
            _c("date_of_birth", "DATE"),
            _c("department_id", "SMALLINT", "-> departments"),
            _c("admission_year", "SMALLINT"),
            _c("year_level", "TINYINT", "1-4"),
            _c("residency_status", "VARCHAR(13)", "DOMESTIC | INTERNATIONAL"),
            _c("home_region", "VARCHAR(50)"),
            _c("is_hostel_resident", "TINYINT(1)"),
            _c("advisor_teacher_id", "INT", "-> teachers (academic advisor)"),
            _c("enrollment_status", "VARCHAR(10)", "ACTIVE | ON_LEAVE | ... | GRADUATED"),
        ),
    ),
    TableSpec(
        "courses",
        "Course catalogue.",
        (
            _c("course_id", "SMALLINT", "primary key"),
            _c("course_code", "VARCHAR(10)", "e.g. CSE101"),
            _c("title", "VARCHAR(150)"),
            _c("department_id", "SMALLINT", "-> departments"),
            _c("course_level", "SMALLINT", "100 | 200 | 300 | 400"),
            _c("credits", "TINYINT"),
            _c("is_elective", "TINYINT(1)"),
            _c("is_active", "TINYINT(1)"),
        ),
    ),
    TableSpec(
        "course_offerings",
        "A section of a course in a term, taught by one teacher.",
        (
            _c("offering_id", "INT", "primary key"),
            _c("course_id", "SMALLINT", "-> courses"),
            _c("term_id", "SMALLINT", "-> academic_terms"),
            _c("section_code", "CHAR(1)"),
            _c("teacher_id", "INT", "-> teachers"),
            _c("capacity", "SMALLINT"),
            _c("room", "VARCHAR(30)"),
        ),
    ),
    TableSpec(
        "enrollments",
        "A student enrolled in an offering.",
        (
            _c("enrollment_id", "INT", "primary key"),
            _c("student_id", "INT", "-> students"),
            _c("offering_id", "INT", "-> course_offerings"),
            _c("enrolled_on", "DATE"),
            _c("status", "VARCHAR(10)", "ENROLLED | COMPLETED | DROPPED"),
        ),
    ),
    TableSpec(
        "grades",
        "Final grade of a completed enrollment (Spring 2026).",
        (
            _c("grade_id", "INT", "primary key"),
            _c("enrollment_id", "INT", "-> enrollments (one grade per enrollment)"),
            _c("marks", "DECIMAL(5,2)", "0-100"),
            _c("letter_grade", "VARCHAR(2)", "-> grade_scale"),
            _c("graded_on", "DATE"),
        ),
    ),
    TableSpec(
        "class_sessions",
        "Scheduled meetings of an offering.",
        (
            _c("session_id", "INT", "primary key"),
            _c("offering_id", "INT", "-> course_offerings"),
            _c("session_no", "SMALLINT"),
            _c("session_date", "DATE"),
        ),
    ),
    TableSpec(
        "attendance_records",
        "Attendance of an enrolled student at one session.",
        (
            _c("attendance_id", "BIGINT", "primary key"),
            _c("session_id", "INT", "-> class_sessions"),
            _c("enrollment_id", "INT", "-> enrollments"),
            _c("offering_id", "INT", "-> course_offerings"),
            _c("status", "VARCHAR(7)", "PRESENT | ABSENT | LATE | EXCUSED"),
        ),
    ),
    TableSpec(
        "fees",
        "Charges raised against a student for a term.",
        (
            _c("fee_id", "INT", "primary key"),
            _c("student_id", "INT", "-> students"),
            _c("term_id", "SMALLINT", "-> academic_terms"),
            _c("fee_type", "VARCHAR(10)", "TUITION | LAB | LIBRARY | EXAM | HOSTEL"),
            _c("amount", "DECIMAL(10,2)"),
            _c("due_date", "DATE"),
        ),
    ),
    TableSpec(
        "fee_payments",
        "Payments against a fee.",
        (
            _c("payment_id", "INT", "primary key"),
            _c("fee_id", "INT", "-> fees"),
            _c("amount", "DECIMAL(10,2)"),
            _c("paid_on", "DATE"),
            _c("payment_method", "VARCHAR(13)", "BANK_TRANSFER | CARD | CASH | CHEQUE"),
            _c("receipt_no", "VARCHAR(20)"),
        ),
    ),
    TableSpec(
        "scholarships",
        "Scholarship programmes (catalogue).",
        (
            _c("scholarship_id", "SMALLINT", "primary key"),
            _c("scholarship_code", "VARCHAR(20)"),
            _c("scholarship_name", "VARCHAR(100)"),
            _c("category", "VARCHAR(13)", "MERIT | NEED_BASED | ATHLETIC | ..."),
            _c("sponsor", "VARCHAR(100)"),
            _c("department_id", "SMALLINT", "-> departments; NULL = open to all"),
            _c("standard_amount", "DECIMAL(10,2)"),
            _c("is_active", "TINYINT(1)"),
        ),
    ),
    TableSpec(
        "student_scholarships",
        "A scholarship awarded to a student for a term.",
        (
            _c("award_id", "INT", "primary key"),
            _c("student_id", "INT", "-> students"),
            _c("scholarship_id", "SMALLINT", "-> scholarships"),
            _c("term_id", "SMALLINT", "-> academic_terms"),
            _c("amount", "DECIMAL(10,2)"),
            _c("award_status", "VARCHAR(9)", "ACTIVE | COMPLETED | REVOKED"),
            _c("awarded_on", "DATE"),
        ),
    ),
    TableSpec(
        "v_fee_balances",
        "View: amount due, paid and outstanding per fee, as of 2026-09-25.",
        (
            _c("fee_id", "INT"),
            _c("student_id", "INT"),
            _c("term_id", "SMALLINT"),
            _c("fee_type", "VARCHAR(10)"),
            _c("amount_due", "DECIMAL(10,2)"),
            _c("amount_paid", "DECIMAL"),
            _c("balance", "DECIMAL"),
            _c("due_date", "DATE"),
            _c("status_as_of", "DATE"),
            _c("payment_status", "VARCHAR(7)", "PAID | OVERDUE | PARTIAL | UNPAID"),
        ),
        is_view=True,
    ),
    TableSpec(
        "v_attendance_summary",
        "View: attendance counts and percentage per enrollment (LATE counts as attended).",
        (
            _c("enrollment_id", "INT"),
            _c("student_id", "INT"),
            _c("offering_id", "INT"),
            _c("sessions_recorded", "BIGINT"),
            _c("sessions_attended", "DECIMAL"),
            _c("sessions_absent", "DECIMAL"),
            _c("sessions_excused", "DECIMAL"),
            _c("attendance_pct", "DECIMAL(5,1)"),
        ),
        is_view=True,
    ),
)

CATALOG: dict[str, TableSpec] = {t.name: t for t in TABLES}
