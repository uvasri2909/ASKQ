"""Fixed reference data: roles, departments, terms, grade scale, courses, scholarships.

Everything here is hand-written and fictional. It does not depend on the seed.
"""

from dataclasses import dataclass
from datetime import UTC, date, datetime

# Temporal model. The dataset is a snapshot of one fixed moment; nothing reads
# the machine's clock or time zone.
#   DATA_AS_OF   business "today": attendance and payments stop here, and
#                v_fee_balances (05_views.sql) judges OVERDUE against it.
#   SNAPSHOT_AT  value of every created_at/updated_at written by the seed
#                (the seed SQL pins MySQL's clock to it with SET timestamp).
DATA_AS_OF = date(2026, 9, 25)
SNAPSHOT_AT = datetime(2026, 9, 25, 18, 0, 0, tzinfo=UTC)

EMAIL_DOMAIN = "askq-uni.example"  # .example is reserved (RFC 2606): never a real mailbox

ROLES = [
    # (role_id, code, name, description)
    (1, "ADMIN", "Administrator", "University-wide access to all academic and financial data"),
    (2, "HOD", "Head of Department", "Access scoped to their own department"),
    (3, "TEACHER", "Teacher", "Access scoped to the course offerings they teach"),
    (4, "STUDENT", "Student", "Access scoped to their own records"),
]
ROLE_ID = {code: role_id for role_id, code, _, _ in ROLES}


@dataclass(frozen=True)
class Department:
    department_id: int
    code: str
    name: str
    building: str
    established_year: int
    student_count: int
    teacher_count: int
    tuition_per_term: int
    has_lab: bool
    course_prefix: str


DEPARTMENTS = [
    Department(
        1,
        "CSE",
        "Computer Science and Engineering",
        "Turing Block",
        1998,
        255,
        8,
        62000,
        True,
        "CSE",
    ),
    Department(
        2,
        "ECE",
        "Electronics and Communication Engineering",
        "Faraday Block",
        1998,
        195,
        7,
        58000,
        True,
        "ECE",
    ),
    Department(3, "MECH", "Mechanical Engineering", "Watt Block", 1995, 170, 6, 55000, True, "MEC"),
    Department(4, "CIVIL", "Civil Engineering", "Brunel Block", 1995, 140, 6, 52000, True, "CIV"),
    Department(5, "MATH", "Mathematics", "Noether Hall", 2001, 110, 5, 40000, False, "MAT"),
    Department(6, "BIOT", "Biotechnology", "Mendel Hall", 2008, 110, 5, 50000, True, "BIO"),
    # Deliberately tiny: small cohorts are what make inference attacks possible.
    Department(7, "ASTRO", "Astrophysics", "Hubble Annex", 2019, 20, 3, 45000, False, "AST"),
]
DEPT_BY_CODE = {d.code: d for d in DEPARTMENTS}
DEPT_BY_ID = {d.department_id: d for d in DEPARTMENTS}


@dataclass(frozen=True)
class Term:
    term_id: int
    code: str
    name: str
    academic_year: str
    season: str
    start_date: date
    end_date: date
    is_current: bool
    fee_due_date: date
    scholarship_awarded_on: date
    max_sessions: int  # class meetings per offering (twice weekly)


TERMS = [
    Term(
        1,
        "2026-SPRING",
        "Spring 2026",
        "2025-2026",
        "SPRING",
        date(2026, 1, 12),
        date(2026, 5, 8),
        False,
        date(2026, 1, 31),
        date(2026, 1, 5),
        24,
    ),
    Term(
        2,
        "2026-FALL",
        "Fall 2026",
        "2026-2027",
        "FALL",
        date(2026, 8, 17),
        date(2026, 12, 11),
        True,
        date(2026, 9, 15),
        date(2026, 8, 10),
        28,
    ),
]
SPRING, FALL = TERMS
GRADES_RELEASED_ON = date(2026, 5, 20)

# Current (Fall 2026) year level L was admitted in 2027 - L.
CURRENT_ACADEMIC_START_YEAR = 2026

GRADE_SCALE = [
    # (letter, min_marks, grade_points, description)
    ("A", 90, "4.00", "Outstanding"),
    ("A-", 85, "3.70", "Excellent"),
    ("B+", 80, "3.30", "Very good"),
    ("B", 75, "3.00", "Good"),
    ("B-", 70, "2.70", "Above average"),
    ("C+", 65, "2.30", "Average"),
    ("C", 60, "2.00", "Satisfactory"),
    ("D", 50, "1.00", "Pass"),
    ("F", 0, "0.00", "Fail"),
]


def letter_for(marks: float) -> str:
    for letter, minimum, _, _ in GRADE_SCALE:
        if marks >= minimum:
            return letter
    raise ValueError(marks)


# Three core courses per year level, plus one elective open to other departments.
COURSE_TITLES = {
    "CSE": [
        ["Programming Fundamentals", "Discrete Structures", "Digital Logic"],
        ["Data Structures", "Computer Organization", "Object-Oriented Design"],
        ["Algorithms", "Operating Systems", "Database Systems"],
        ["Computer Networks", "Compiler Design", "Machine Learning"],
        "Introduction to Data Science",
    ],
    "ECE": [
        ["Circuit Analysis", "Electronic Devices", "Engineering Physics"],
        ["Signals and Systems", "Analog Electronics", "Electromagnetic Fields"],
        ["Digital Signal Processing", "Communication Systems", "Microprocessors"],
        ["Wireless Networks", "VLSI Design", "Embedded Systems"],
        "Consumer Electronics",
    ],
    "MECH": [
        ["Engineering Mechanics", "Engineering Drawing", "Materials Science"],
        ["Thermodynamics", "Strength of Materials", "Manufacturing Processes"],
        ["Fluid Mechanics", "Machine Design", "Heat Transfer"],
        ["Robotics", "Automobile Engineering", "Finite Element Analysis"],
        "Product Design Studio",
    ],
    "CIVIL": [
        ["Surveying", "Building Materials", "Engineering Geology"],
        ["Structural Analysis", "Soil Mechanics", "Hydraulics"],
        ["Concrete Structures", "Transportation Engineering", "Environmental Engineering"],
        ["Steel Structures", "Construction Management", "Urban Planning"],
        "Sustainable Cities",
    ],
    "MATH": [
        ["Calculus", "Linear Algebra", "Foundations of Mathematics"],
        ["Real Analysis", "Probability", "Differential Equations"],
        ["Abstract Algebra", "Complex Analysis", "Numerical Methods"],
        ["Topology", "Functional Analysis", "Mathematical Statistics"],
        "Applied Statistics",
    ],
    "BIOT": [
        ["Cell Biology", "General Chemistry", "Laboratory Techniques"],
        ["Biochemistry", "Microbiology", "Genetics"],
        ["Molecular Biology", "Bioprocess Engineering", "Immunology"],
        ["Genetic Engineering", "Bioinformatics", "Pharmaceutical Biotechnology"],
        "Science of Nutrition",
    ],
    "ASTRO": [
        ["Introductory Astronomy", "Classical Mechanics", "Mathematical Methods"],
        ["Stellar Astrophysics", "Electrodynamics", "Observational Techniques"],
        ["Galactic Dynamics", "Quantum Mechanics", "Radiative Processes"],
        ["Cosmology", "High-Energy Astrophysics", "Research Project"],
        "Exploring the Night Sky",
    ],
}

SECTION_CAPACITY = 80

FEE_FLAT = {"LAB": 6000, "LIBRARY": 1500, "EXAM": 2500, "HOSTEL": 32000}
INTERNATIONAL_TUITION_FACTOR = 1.5


@dataclass(frozen=True)
class Scholarship:
    scholarship_id: int
    code: str
    name: str
    category: str
    sponsor: str
    department_code: str | None
    standard_amount: int


SCHOLARSHIPS = [
    Scholarship(
        1,
        "CHANCELLOR",
        "Chancellor's Merit Scholarship",
        "MERIT",
        "ASKQ University Foundation",
        None,
        25000,
    ),
    Scholarship(
        2,
        "ORCHARD",
        "Orchard Need-Based Grant",
        "NEED_BASED",
        "Orchard Community Trust",
        None,
        15000,
    ),
    Scholarship(
        3, "SUMMIT", "Summit Athletics Award", "ATHLETIC", "Summit Sports Council", None, 8000
    ),
    Scholarship(
        4,
        "HORIZON",
        "Horizon International Scholarship",
        "INTERNATIONAL",
        "Horizon Exchange Fund",
        None,
        20000,
    ),
    Scholarship(
        5,
        "STELLAR",
        "Stellar Research Fellowship",
        "RESEARCH",
        "Stellar Observatory Society",
        "ASTRO",
        18000,
    ),
    # Amounts vary per recipient (assessed hardship); used by the
    # arithmetic-recovery demonstration.
    Scholarship(
        6,
        "MERIDIAN",
        "Meridian Hardship Fund",
        "NEED_BASED",
        "Meridian Civic Trust",
        "CIVIL",
        30000,
    ),
]
SCHOLARSHIP_BY_CODE = {s.code: s for s in SCHOLARSHIPS}

# Fictional home regions. Weights are for domestic students; international
# students have home_region 'Overseas'.
DOMESTIC_REGIONS = [
    ("North Vale", 18),
    ("East Harbor", 17),
    ("Westmere", 16),
    ("Central Plains", 16),
    ("South Ridge", 15),
    ("Lakeshore", 10),
    ("Highland", 5),
    ("Saltmarsh", 3),
]
OVERSEAS_REGION = "Overseas"

DESIGNATION_SALARY = {
    "Professor": 185000,
    "Associate Professor": 145000,
    "Assistant Professor": 115000,
    "Lecturer": 85000,
}

# Syllables for obviously-invented names (no real-person data is used anywhere).
FIRST_NAME_STARTS = [
    "Al",
    "Bel",
    "Cor",
    "Dar",
    "El",
    "Fen",
    "Gal",
    "Hal",
    "Is",
    "Jor",
    "Kal",
    "Lin",
    "Mar",
    "Nor",
    "Or",
    "Pel",
    "Quin",
    "Ren",
    "Sol",
    "Tam",
    "Ul",
    "Vor",
    "Wen",
    "Yar",
    "Zel",
]
FIRST_NAME_ENDS = ["a", "en", "ia", "or", "yn", "is", "ara", "eth", "o", "ine", "an", "el"]
LAST_NAME_STARTS = [
    "Ash",
    "Brin",
    "Cald",
    "Dun",
    "Evers",
    "Fal",
    "Grim",
    "Hollow",
    "Ivel",
    "Jast",
    "Kest",
    "Lorn",
    "Mire",
    "Nith",
    "Orr",
    "Pry",
    "Quell",
    "Ros",
    "Sten",
    "Thorn",
    "Umber",
    "Vey",
    "Wick",
    "Yew",
    "Zorn",
]
LAST_NAME_ENDS = [
    "ford",
    "wick",
    "mere",
    "dale",
    "ton",
    "by",
    "holt",
    "vane",
    "ley",
    "stead",
    "wyn",
    "crest",
]
