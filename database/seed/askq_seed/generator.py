"""Builds the complete synthetic ASKQ university dataset in memory.

Determinism: every stage draws from its own random.Random seeded with a string
derived from (seed, stage name). Python seeds str values via SHA-512, so the
output is identical across runs and machines, and changing one stage (e.g.
attendance) does not reshuffle another (e.g. students).
"""

from __future__ import annotations

import math
import random
import sqlite3
from dataclasses import dataclass, field
from datetime import date, timedelta
from decimal import Decimal

from askq_seed import cohort_checks, cohorts
from askq_seed.reference import (
    COURSE_TITLES,
    CURRENT_ACADEMIC_START_YEAR,
    DATA_AS_OF,
    DEPARTMENTS,
    DESIGNATION_SALARY,
    DOMESTIC_REGIONS,
    EMAIL_DOMAIN,
    FALL,
    FEE_FLAT,
    FIRST_NAME_ENDS,
    FIRST_NAME_STARTS,
    GRADE_SCALE,
    GRADES_RELEASED_ON,
    INTERNATIONAL_TUITION_FACTOR,
    LAST_NAME_ENDS,
    LAST_NAME_STARTS,
    OVERSEAS_REGION,
    ROLE_ID,
    ROLES,
    SCHOLARSHIP_BY_CODE,
    SCHOLARSHIPS,
    SECTION_CAPACITY,
    SPRING,
    TERMS,
    Department,
    Term,
    letter_for,
)

GENERATOR_VERSION = "1.0"
DEFAULT_SEED = 20260926

LEVEL_SHARES = (0.27, 0.26, 0.24, 0.23)
PAYMENT_PROFILE_WEIGHTS = {
    SPRING.code: (("FULL", 93), ("PARTIAL", 5), ("NONE", 2)),
    FALL.code: (("FULL", 70), ("PARTIAL", 18), ("NONE", 12)),
}
PAYMENT_METHODS = (("BANK_TRANSFER", 55), ("CARD", 35), ("CASH", 7), ("CHEQUE", 3))


# ---------------------------------------------------------------------------
# Output containers
# ---------------------------------------------------------------------------


@dataclass
class Table:
    name: str
    columns: tuple[str, ...]
    rows: list[tuple] = field(default_factory=list)
    # Parallel to rows: True if the row belongs to a security-demo student.
    planted: list[bool] = field(default_factory=list)

    def add(self, values: tuple, planted: bool = False) -> None:
        if len(values) != len(self.columns):
            raise ValueError(f"{self.name}: expected {len(self.columns)} values, got {values}")
        self.rows.append(values)
        self.planted.append(planted)


@dataclass
class Dataset:
    seed: int
    tables: dict[str, Table]
    # (department_id, head_teacher_id), applied after teachers are inserted.
    department_heads: list[tuple[int, int]]
    # cohort id -> list of {student_no, ...} for the planted students.
    cohort_members: dict[str, list[dict]]

    def table(self, name: str) -> Table:
        return self.tables[name]


# ---------------------------------------------------------------------------
# Internal model
# ---------------------------------------------------------------------------


@dataclass
class _Teacher:
    teacher_id: int
    employee_no: str
    first_name: str
    last_name: str
    email: str
    dept: Department
    designation: str
    hire_date: date
    salary: int
    is_head: bool


@dataclass
class _Student:
    gen_index: int
    dept: Department
    year_level: int
    gender: str
    residency: str
    region: str
    hostel: bool
    ability: float
    attendance_rate: float
    first_name: str
    last_name: str
    date_of_birth: date
    status: str = "ACTIVE"
    spec: cohorts.PlantedStudent | None = None
    student_id: int = 0
    student_no: str = ""
    advisor_id: int | None = None

    @property
    def planted(self) -> bool:
        return self.spec is not None

    @property
    def admission_year(self) -> int:
        return CURRENT_ACADEMIC_START_YEAR + 1 - self.year_level

    @property
    def international(self) -> bool:
        return self.residency == "INTERNATIONAL"

    def level_in(self, term: Term) -> int:
        return self.year_level if term is FALL else self.year_level - 1

    def attends(self, term: Term) -> bool:
        if self.level_in(term) < 1:
            return False
        return term is not FALL or self.status == "ACTIVE"


@dataclass
class _Course:
    course_id: int
    code: str
    title: str
    dept: Department
    level: int  # 1..4 for core; 2 for electives
    credits: int
    is_elective: bool
    difficulty: float


@dataclass
class _Enrollment:
    enrollment_id: int
    student: _Student
    offering_id: int
    course: _Course
    term: Term
    core_index: int | None
    status: str
    enrolled_on: date
    sessions_attended_until: int | None  # dropped after N sessions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rng(seed: int, stage: str) -> random.Random:
    return random.Random(f"askq:{seed}:{stage}")  # noqa: S311 - synthetic data, not security


def _weighted(rng: random.Random, options) -> str:
    values = [v for v, _ in options]
    weights = [w for _, w in options]
    return rng.choices(values, weights=weights)[0]


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _first_name(rng: random.Random) -> str:
    return rng.choice(FIRST_NAME_STARTS) + rng.choice(FIRST_NAME_ENDS)


def _last_name(rng: random.Random) -> str:
    return rng.choice(LAST_NAME_STARTS) + rng.choice(LAST_NAME_ENDS)


def _date_of_birth(rng: random.Random, admission_year: int) -> date:
    # Aged 17-19 when starting in September of the admission year.
    return date(admission_year - 19, 9, 1) + timedelta(days=rng.randrange(730))


def _level_counts(total: int) -> list[int]:
    counts = [round(total * share) for share in LEVEL_SHARES[:3]]
    counts.append(total - sum(counts))
    return counts


def _money(amount: float) -> Decimal:
    return Decimal(f"{amount:.2f}")


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------


def _build_teachers(seed: int) -> list[_Teacher]:
    rng = _rng(seed, "teachers")
    teachers: list[_Teacher] = []
    used_emails: set[str] = set()
    for dept in DEPARTMENTS:
        for i in range(dept.teacher_count):
            teacher_id = len(teachers) + 1
            if i == 0:
                designation = "Professor"
                hire_year = rng.randint(dept.established_year, dept.established_year + 4)
            else:
                designation = _weighted(
                    rng,
                    (
                        ("Professor", 2),
                        ("Associate Professor", 3),
                        ("Assistant Professor", 4),
                        ("Lecturer", 2),
                    ),
                )
                hire_year = rng.randint(max(dept.established_year, 2000), 2025)
            first, last = _first_name(rng), _last_name(rng)
            local = f"{first}.{last}".lower()
            email, n = f"{local}@staff.{EMAIL_DOMAIN}", 2
            while email in used_emails:
                email, n = f"{local}{n}@staff.{EMAIL_DOMAIN}", n + 1
            used_emails.add(email)
            salary = round(DESIGNATION_SALARY[designation] * rng.uniform(0.92, 1.08), -2)
            teachers.append(
                _Teacher(
                    teacher_id=teacher_id,
                    employee_no=f"T{teacher_id:04d}",
                    first_name=first,
                    last_name=last,
                    email=email,
                    dept=dept,
                    designation=designation,
                    hire_date=date(hire_year, rng.choice((1, 7, 8)), 1),
                    salary=int(salary),
                    is_head=(i == 0),
                )
            )
    return teachers


def _build_students(seed: int) -> list[_Student]:
    rng = _rng(seed, "students")
    planted_rng = _rng(seed, "planted-students")
    students: list[_Student] = []

    for spec in cohorts.PLANTED:
        dept = next(d for d in DEPARTMENTS if d.code == spec.department)
        admission_year = CURRENT_ACADEMIC_START_YEAR + 1 - spec.year_level
        students.append(
            _Student(
                gen_index=len(students),
                dept=dept,
                year_level=spec.year_level,
                gender=spec.gender,
                residency=spec.residency,
                region=spec.region,
                hostel=spec.hostel,
                ability=spec.ability,
                attendance_rate=spec.attendance_rate,
                first_name=_first_name(planted_rng),
                last_name=_last_name(planted_rng),
                date_of_birth=_date_of_birth(planted_rng, admission_year),
                spec=spec,
            )
        )

    for dept in DEPARTMENTS:
        for level_index, target in enumerate(_level_counts(dept.student_count)):
            level = level_index + 1
            already = sum(1 for s in students if s.dept is dept and s.year_level == level)
            for _ in range(target - already):
                while True:
                    gender = _weighted(rng, (("F", 470), ("M", 515), ("X", 15)))
                    international = rng.random() < 0.04
                    residency = "INTERNATIONAL" if international else "DOMESTIC"
                    region = OVERSEAS_REGION if international else _weighted(rng, DOMESTIC_REGIONS)
                    if not cohorts.is_reserved(dept.code, level, gender, residency, region):
                        break
                hostel = rng.random() < (0.85 if international else 0.42)
                attendance_rate = _clamp(rng.gauss(0.87, 0.07), 0.45, 0.99)
                ability = _clamp(rng.gauss(71, 9) + (attendance_rate - 0.87) * 40, 35, 96)
                admission_year = CURRENT_ACADEMIC_START_YEAR + 1 - level
                students.append(
                    _Student(
                        gen_index=len(students),
                        dept=dept,
                        year_level=level,
                        gender=gender,
                        residency=residency,
                        region=region,
                        hostel=hostel,
                        ability=ability,
                        attendance_rate=attendance_rate,
                        first_name=_first_name(rng),
                        last_name=_last_name(rng),
                        date_of_birth=_date_of_birth(rng, admission_year),
                        status="ON_LEAVE" if rng.random() < 0.01 else "ACTIVE",
                    )
                )

    # Interleave planted and ordinary students: ids follow admission year,
    # department and name, so a student's id says nothing about cohorts.
    students.sort(
        key=lambda s: (
            s.admission_year,
            s.dept.department_id,
            s.last_name,
            s.first_name,
            s.gen_index,
        )
    )
    per_year: dict[int, int] = {}
    for student_id, s in enumerate(students, start=1):
        per_year[s.admission_year] = per_year.get(s.admission_year, 0) + 1
        s.student_id = student_id
        s.student_no = f"S{s.admission_year}{per_year[s.admission_year]:04d}"
    return students


def _build_courses(seed: int) -> list[_Course]:
    rng = _rng(seed, "courses")
    courses: list[_Course] = []
    for dept in DEPARTMENTS:
        *levels, elective_title = COURSE_TITLES[dept.code]
        for level_index, titles in enumerate(levels):
            level = level_index + 1
            for i, title in enumerate(titles):
                courses.append(
                    _Course(
                        course_id=len(courses) + 1,
                        code=f"{dept.course_prefix}{level * 100 + i + 1}",
                        title=title,
                        dept=dept,
                        level=level,
                        credits=6 if title == "Research Project" else 4,
                        is_elective=False,
                        difficulty=rng.uniform(-6, 4),
                    )
                )
        courses.append(
            _Course(
                course_id=len(courses) + 1,
                code=f"{dept.course_prefix}250",
                title=elective_title,
                dept=dept,
                level=2,
                credits=3,
                is_elective=True,
                difficulty=rng.uniform(-2, 6),
            )
        )
    return courses


def _session_dates(term: Term, offering_id: int) -> list[date]:
    weekdays = (0, 2) if offering_id % 2 else (1, 3)  # Mon/Wed or Tue/Thu
    last_day = min(term.end_date, DATA_AS_OF)
    dates: list[date] = []
    day = term.start_date
    while len(dates) < term.max_sessions and day <= last_day:
        if day.weekday() in weekdays:
            dates.append(day)
        day += timedelta(days=1)
    return dates


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def build_dataset(seed: int = DEFAULT_SEED) -> Dataset:
    t = {
        name: Table(name, cols)
        for name, cols in [
            ("roles", ("role_id", "role_code", "role_name", "description")),
            (
                "departments",
                (
                    "department_id",
                    "department_code",
                    "department_name",
                    "building",
                    "established_year",
                ),
            ),
            (
                "academic_terms",
                (
                    "term_id",
                    "term_code",
                    "term_name",
                    "academic_year",
                    "season",
                    "start_date",
                    "end_date",
                    "is_current",
                ),
            ),
            ("grade_scale", ("letter_grade", "min_marks", "grade_points", "description")),
            (
                "courses",
                (
                    "course_id",
                    "course_code",
                    "title",
                    "department_id",
                    "course_level",
                    "credits",
                    "is_elective",
                ),
            ),
            (
                "scholarships",
                (
                    "scholarship_id",
                    "scholarship_code",
                    "scholarship_name",
                    "category",
                    "sponsor",
                    "department_id",
                    "standard_amount",
                ),
            ),
            (
                "teachers",
                (
                    "teacher_id",
                    "employee_no",
                    "first_name",
                    "last_name",
                    "email",
                    "department_id",
                    "designation",
                    "hire_date",
                    "annual_salary",
                ),
            ),
            (
                "students",
                (
                    "student_id",
                    "student_no",
                    "first_name",
                    "last_name",
                    "email",
                    "gender",
                    "date_of_birth",
                    "department_id",
                    "admission_year",
                    "year_level",
                    "residency_status",
                    "home_region",
                    "is_hostel_resident",
                    "advisor_teacher_id",
                    "enrollment_status",
                ),
            ),
            ("users", ("user_id", "username", "role_id", "teacher_id", "student_id")),
            (
                "course_offerings",
                (
                    "offering_id",
                    "course_id",
                    "term_id",
                    "section_code",
                    "teacher_id",
                    "capacity",
                    "room",
                ),
            ),
            ("class_sessions", ("session_id", "offering_id", "session_no", "session_date")),
            (
                "enrollments",
                ("enrollment_id", "student_id", "offering_id", "enrolled_on", "status"),
            ),
            ("grades", ("grade_id", "enrollment_id", "marks", "letter_grade", "graded_on")),
            (
                "attendance_records",
                ("attendance_id", "session_id", "enrollment_id", "offering_id", "status"),
            ),
            ("fees", ("fee_id", "student_id", "term_id", "fee_type", "amount", "due_date")),
            (
                "fee_payments",
                ("payment_id", "fee_id", "amount", "paid_on", "payment_method", "receipt_no"),
            ),
            (
                "student_scholarships",
                (
                    "award_id",
                    "student_id",
                    "scholarship_id",
                    "term_id",
                    "amount",
                    "award_status",
                    "awarded_on",
                ),
            ),
        ]
    }

    # ---- Reference data ----
    for role in ROLES:
        t["roles"].add(role)
    for d in DEPARTMENTS:
        t["departments"].add((d.department_id, d.code, d.name, d.building, d.established_year))
    for term in TERMS:
        t["academic_terms"].add(
            (
                term.term_id,
                term.code,
                term.name,
                term.academic_year,
                term.season,
                term.start_date,
                term.end_date,
                term.is_current,
            )
        )
    for letter, minimum, points, description in GRADE_SCALE:
        t["grade_scale"].add((letter, Decimal(minimum), Decimal(points), description))
    dept_id_by_code = {d.code: d.department_id for d in DEPARTMENTS}
    for s in SCHOLARSHIPS:
        t["scholarships"].add(
            (
                s.scholarship_id,
                s.code,
                s.name,
                s.category,
                s.sponsor,
                dept_id_by_code.get(s.department_code) if s.department_code else None,
                _money(s.standard_amount),
            )
        )

    courses = _build_courses(seed)
    for c in courses:
        t["courses"].add(
            (
                c.course_id,
                c.code,
                c.title,
                c.dept.department_id,
                c.level * 100,
                c.credits,
                c.is_elective,
            )
        )
    core = {(c.dept.code, c.level): [] for c in courses if not c.is_elective}
    for c in courses:
        if not c.is_elective:
            core[(c.dept.code, c.level)].append(c)
    elective = {c.dept.code: c for c in courses if c.is_elective}

    # ---- People ----
    teachers = _build_teachers(seed)
    for tr in teachers:
        t["teachers"].add(
            (
                tr.teacher_id,
                tr.employee_no,
                tr.first_name,
                tr.last_name,
                tr.email,
                tr.dept.department_id,
                tr.designation,
                tr.hire_date,
                _money(tr.salary),
            )
        )
    heads = [(tr.dept.department_id, tr.teacher_id) for tr in teachers if tr.is_head]
    teachers_by_dept = {d.code: [tr for tr in teachers if tr.dept is d] for d in DEPARTMENTS}

    students = _build_students(seed)
    advisor_cursor = {d.code: 0 for d in DEPARTMENTS}
    for s in students:
        pool = teachers_by_dept[s.dept.code]
        s.advisor_id = pool[advisor_cursor[s.dept.code] % len(pool)].teacher_id
        advisor_cursor[s.dept.code] += 1
        t["students"].add(
            (
                s.student_id,
                s.student_no,
                s.first_name,
                s.last_name,
                f"{s.student_no.lower()}@students.{EMAIL_DOMAIN}",
                s.gender,
                s.date_of_birth,
                s.dept.department_id,
                s.admission_year,
                s.year_level,
                s.residency,
                s.region,
                s.hostel,
                s.advisor_id,
                s.status,
            ),
            s.planted,
        )

    # ---- Users (1 admin, one per teacher, one per student) ----
    t["users"].add((1, "admin", ROLE_ID["ADMIN"], None, None))
    for tr in teachers:
        role = ROLE_ID["HOD"] if tr.is_head else ROLE_ID["TEACHER"]
        t["users"].add((1 + tr.teacher_id, tr.employee_no.lower(), role, tr.teacher_id, None))
    for s in students:
        t["users"].add(
            (
                1 + len(teachers) + s.student_id,
                s.student_no.lower(),
                ROLE_ID["STUDENT"],
                None,
                s.student_id,
            ),
            s.planted,
        )

    # ---- Course requests -> offerings (sections of <= SECTION_CAPACITY) ----
    rng_enrol = _rng(seed, "enrollments")
    requests: dict[tuple[int, int], list[tuple[_Student, int | None]]] = {}
    for term in TERMS:
        for s in students:
            if not s.attends(term):
                continue
            level = s.level_in(term)
            other_depts = [d.code for d in DEPARTMENTS if d.code != s.dept.code]
            picks = [(c, i) for i, c in enumerate(core[(s.dept.code, level)])]
            picks.append((elective[rng_enrol.choice(other_depts)], None))
            for course, core_index in picks:
                requests.setdefault((term.term_id, course.course_id), []).append((s, core_index))

    course_by_id = {c.course_id: c for c in courses}
    term_by_id = {term.term_id: term for term in TERMS}
    teacher_cursor: dict[tuple[int, str], int] = {}
    room_cursor: dict[str, int] = {}
    enrollments: list[_Enrollment] = []
    sessions_by_offering: dict[int, list[int]] = {}
    offering_id = session_id = 0

    for (term_id, course_id), requesters in sorted(requests.items()):
        term, course = term_by_id[term_id], course_by_id[course_id]
        n_sections = math.ceil(len(requesters) / SECTION_CAPACITY)
        for section_index in range(n_sections):
            offering_id += 1
            key = (term_id, course.dept.code)
            pool = teachers_by_dept[course.dept.code]
            teacher = pool[teacher_cursor.get(key, 0) % len(pool)]
            teacher_cursor[key] = teacher_cursor.get(key, 0) + 1
            room_cursor[course.dept.code] = room_cursor.get(course.dept.code, 0) + 1
            room = f"{course.dept.building.split()[0]} {100 + room_cursor[course.dept.code]}"
            t["course_offerings"].add(
                (
                    offering_id,
                    course.course_id,
                    term_id,
                    chr(ord("A") + section_index),
                    teacher.teacher_id,
                    SECTION_CAPACITY,
                    room,
                )
            )
            for session_no, day in enumerate(_session_dates(term, offering_id), start=1):
                session_id += 1
                t["class_sessions"].add((session_id, offering_id, session_no, day))
                sessions_by_offering.setdefault(offering_id, []).append(session_id)

            members = sorted(requesters[section_index::n_sections], key=lambda r: r[0].student_id)
            for s, core_index in members:
                dropped = not s.planted and rng_enrol.random() < (0.02 if term is SPRING else 0.015)
                if dropped:
                    status = "DROPPED"
                else:
                    status = "COMPLETED" if term is SPRING else "ENROLLED"
                enrollments.append(
                    _Enrollment(
                        enrollment_id=len(enrollments) + 1,
                        student=s,
                        offering_id=offering_id,
                        course=course,
                        term=term,
                        core_index=core_index,
                        status=status,
                        enrolled_on=term.start_date - timedelta(days=rng_enrol.randint(3, 28)),
                        sessions_attended_until=rng_enrol.randint(2, 6) if dropped else None,
                    )
                )

    for e in enrollments:
        t["enrollments"].add(
            (e.enrollment_id, e.student.student_id, e.offering_id, e.enrolled_on, e.status),
            e.student.planted,
        )

    # ---- Grades (completed Spring 2026 enrollments) ----
    rng_grades = _rng(seed, "grades")
    grade_id = 0
    for e in enrollments:
        if e.status != "COMPLETED":
            continue
        forced = e.student.spec.forced_spring_marks if e.student.spec else {}
        if e.core_index is not None and e.core_index in forced:
            marks = forced[e.core_index]
        elif e.student.planted:
            # Noise-free, so a cohort's properties hold for every seed.
            marks = _clamp(e.student.ability + e.course.difficulty, 15, 100)
        else:
            marks = _clamp(rng_grades.gauss(e.student.ability + e.course.difficulty, 7), 15, 100)
        marks = round(marks, 1)
        grade_id += 1
        t["grades"].add(
            (
                grade_id,
                e.enrollment_id,
                Decimal(f"{marks:.1f}"),
                letter_for(marks),
                GRADES_RELEASED_ON,
            ),
            e.student.planted,
        )

    # ---- Attendance ----
    rng_att = _rng(seed, "attendance")
    attendance_id = 0
    for e in enrollments:
        session_ids = sessions_by_offering.get(e.offering_id, [])
        if e.sessions_attended_until is not None:
            session_ids = session_ids[: e.sessions_attended_until]
        for k, sid in enumerate(session_ids):
            rate = e.student.attendance_rate
            if e.student.planted:
                # Exact rate, evenly spread (no randomness) for security-demo students.
                status = "PRESENT" if int((k + 1) * rate) > int(k * rate) else "ABSENT"
            elif rng_att.random() < rate:
                status = "LATE" if rng_att.random() < 0.08 else "PRESENT"
            else:
                status = "EXCUSED" if rng_att.random() < 0.2 else "ABSENT"
            attendance_id += 1
            t["attendance_records"].add(
                (attendance_id, sid, e.enrollment_id, e.offering_id, status), e.student.planted
            )

    # ---- Fees and payments ----
    rng_fees = _rng(seed, "fees")
    enrolled_terms = {(e.student.student_id, e.term.term_id) for e in enrollments}
    fee_id = payment_id = 0
    for term in TERMS:
        for s in students:
            if (s.student_id, term.term_id) not in enrolled_terms:
                continue
            tuition = s.dept.tuition_per_term * (
                INTERNATIONAL_TUITION_FACTOR if s.international else 1
            )
            items = [("TUITION", tuition)]
            if s.dept.has_lab:
                items.append(("LAB", FEE_FLAT["LAB"]))
            items += [("LIBRARY", FEE_FLAT["LIBRARY"]), ("EXAM", FEE_FLAT["EXAM"])]
            if s.hostel:
                items.append(("HOSTEL", FEE_FLAT["HOSTEL"]))
            if s.spec and term.code in s.spec.payment:
                profile = s.spec.payment[term.code]
            else:
                profile = _weighted(rng_fees, PAYMENT_PROFILE_WEIGHTS[term.code])

            for fee_type, amount in items:
                fee_id += 1
                t["fees"].add(
                    (
                        fee_id,
                        s.student_id,
                        term.term_id,
                        fee_type,
                        _money(amount),
                        term.fee_due_date,
                    ),
                    s.planted,
                )
                payments: list[tuple[int, date]] = []
                due = term.fee_due_date
                if profile == "FULL" or (
                    profile == "PARTIAL" and fee_type not in ("TUITION", "HOSTEL")
                ):
                    if amount >= 10000 and rng_fees.random() < 0.2:
                        first = int(round(amount / 2, -2))
                        payments.append((first, due - timedelta(days=rng_fees.randint(10, 30))))
                        payments.append(
                            (int(amount) - first, due + timedelta(days=rng_fees.randint(-5, 20)))
                        )
                    elif rng_fees.random() < 0.88:
                        payments.append(
                            (int(amount), due - timedelta(days=rng_fees.randint(0, 25)))
                        )
                    else:
                        payments.append(
                            (int(amount), due + timedelta(days=rng_fees.randint(1, 20)))
                        )
                elif profile == "PARTIAL" and fee_type == "TUITION":
                    share = rng_fees.choice((0.4, 0.5, 0.6))
                    payments.append(
                        (
                            int(round(amount * share, -2)),
                            due - timedelta(days=rng_fees.randint(0, 20)),
                        )
                    )
                for paid, paid_on in payments:
                    if paid_on > DATA_AS_OF:
                        continue  # a late payment that has not happened yet
                    payment_id += 1
                    t["fee_payments"].add(
                        (
                            payment_id,
                            fee_id,
                            _money(paid),
                            paid_on,
                            _weighted(rng_fees, PAYMENT_METHODS),
                            f"RCP{term.start_date.year}-{payment_id:06d}",
                        ),
                        s.planted,
                    )

    # ---- Scholarships ----
    rng_sch = _rng(seed, "scholarships")
    awards: dict[tuple[int, str, int], int] = {}  # (term_id, code, student_id) -> amount

    def award(term: Term, code: str, s: _Student, amount: int | None = None) -> None:
        awards[(term.term_id, code, s.student_id)] = (
            amount if amount is not None else SCHOLARSHIP_BY_CODE[code].standard_amount
        )

    attending = {
        term.term_id: [s for s in students if (s.student_id, term.term_id) in enrolled_terms]
        for term in TERMS
    }
    ordinary = {tid: [s for s in group if not s.planted] for tid, group in attending.items()}

    def by_merit(group: list[_Student]) -> list[_Student]:
        return sorted(group, key=lambda s: (-s.ability, s.student_id))

    for term, top_n in ((SPRING, 12), (FALL, 14)):
        eligible = [
            s
            for s in ordinary[term.term_id]
            if s.year_level >= 2
            and not cohorts.excluded_from_chancellor(s.dept.code, s.year_level, s.hostel)
        ]
        for s in by_merit(eligible)[:top_n]:
            award(term, "CHANCELLOR", s)

    spring_ids = {s.student_id for s in ordinary[SPRING.term_id]}
    domestic = [s for s in ordinary[FALL.term_id] if not s.international]
    orchard = rng_sch.sample(domestic, k=round(0.06 * len(domestic)))
    summit = rng_sch.sample(ordinary[FALL.term_id], k=round(0.03 * len(ordinary[FALL.term_id])))
    horizon = [s for s in ordinary[FALL.term_id] if s.international and rng_sch.random() < 0.4]
    for code, group, keep_spring in (
        ("ORCHARD", orchard, 0.8),
        ("SUMMIT", summit, 0.85),
        ("HORIZON", horizon, 1.0),
    ):
        for s in sorted(group, key=lambda s: s.student_id):
            award(FALL, code, s)
            if s.student_id in spring_ids and rng_sch.random() < keep_spring:
                award(SPRING, code, s)
    astro = [s for s in ordinary[FALL.term_id] if s.dept.code == "ASTRO" and s.year_level >= 3]
    for s in by_merit(astro)[:2]:
        award(FALL, "STELLAR", s)
    for s in by_merit([s for s in astro if s.student_id in spring_ids])[:1]:
        award(SPRING, "STELLAR", s)

    term_by_code = {term.code: term for term in TERMS}
    for s in students:
        if s.spec:
            for code, per_term in s.spec.awards.items():
                for term_code, amount in per_term.items():
                    award(term_by_code[term_code], code, s, amount)

    student_by_id = {s.student_id: s for s in students}
    for award_id, ((term_id, code, student_id), amount) in enumerate(
        sorted(
            awards.items(),
            key=lambda kv: (kv[0][0], SCHOLARSHIP_BY_CODE[kv[0][1]].scholarship_id, kv[0][2]),
        ),
        start=1,
    ):
        term = term_by_id[term_id]
        t["student_scholarships"].add(
            (
                award_id,
                student_id,
                SCHOLARSHIP_BY_CODE[code].scholarship_id,
                term_id,
                _money(amount),
                "ACTIVE" if term is FALL else "COMPLETED",
                term.scholarship_awarded_on,
            ),
            student_by_id[student_id].planted,
        )

    members: dict[str, list[dict]] = {}
    for s in students:
        if s.spec:
            members.setdefault(s.spec.cohort, []).append(
                {
                    "student_no": s.student_no,
                    "department": s.dept.code,
                    "year_level": s.year_level,
                    "gender": s.gender,
                    "home_region": s.region,
                    "is_hostel_resident": s.hostel,
                }
            )

    dataset = Dataset(seed=seed, tables=t, department_heads=heads, cohort_members=members)
    self_check(dataset)
    return dataset


# ---------------------------------------------------------------------------
# Self-check: run the cohort SQL against an in-memory SQLite copy
# ---------------------------------------------------------------------------


# Tables the cohort checks read, and the columns worth indexing in the copy.
_CHECK_TABLES = {
    "departments": (),
    "students": ("department_id",),
    "academic_terms": (),
    "course_offerings": ("term_id",),
    "enrollments": ("student_id", "offering_id"),
    "grades": ("enrollment_id",),
    "attendance_records": ("enrollment_id",),
    "fees": ("student_id",),
    "fee_payments": ("fee_id",),
    "scholarships": (),
    "student_scholarships": ("student_id", "scholarship_id"),
}


def _sqlite_value(value):
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, date):
        return value.isoformat()
    return value  # bool is stored as 0/1


def cohort_values(dataset: Dataset) -> dict[str, float]:
    """Evaluate every cohort_checks.COHORT_CHECKS query; returns {check name: value}.

    The same SQL runs against MySQL in database/validation/verify_security_cohorts.sql.
    """
    con = sqlite3.connect(":memory:")
    try:
        for name, indexed in _CHECK_TABLES.items():
            table = dataset.table(name)
            con.execute(f"CREATE TABLE {name} ({', '.join(table.columns)})")
            con.executemany(
                f"INSERT INTO {name} VALUES ({', '.join('?' * len(table.columns))})",  # noqa: S608
                [tuple(_sqlite_value(v) for v in row) for row in table.rows],
            )
            for column in indexed:
                con.execute(f"CREATE INDEX ix_{name}_{column} ON {name} ({column})")
        return {c.name: con.execute(c.sql).fetchone()[0] for c in cohort_checks.COHORT_CHECKS}
    finally:
        con.close()


def self_check(dataset: Dataset) -> None:
    values = cohort_values(dataset)
    wrong = {
        c.name: (f"{c.op} {c.expected}", values[c.name])
        for c in cohort_checks.COHORT_CHECKS
        if not c.passes(values[c.name])
    }
    if wrong:
        raise AssertionError(f"security-demo cohort checks failed (expected, actual): {wrong}")
