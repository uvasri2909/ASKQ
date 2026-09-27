"""Security-demonstration cohorts for the six planned CAIR attack classes.

Each cohort is a small, realistic-looking group of synthetic students with an
EXACT, guaranteed size. They are planted among the ordinary students (same
tables, interleaved ids, no marker column), so the only way to find them is
by querying, which is exactly what the later attack demonstrations do.

Guarantees:
  * Planted students are defined below (PLANTED).
  * Ordinary students are re-rolled until they match none of RESERVED, so no
    ordinary student can accidentally change a cohort's size.
  * Scholarship programmes used by a cohort are never given to ordinary
    students where that would change the cohort (see generator.py).
  * Planted students get noise-free marks and exact attendance rates, so the
    properties below hold for every seed.
  * cohort_checks.py verifies each cohort's attributes, size, surrounding
    groups and payload; generation fails if any check fails.

Nothing here is real: every person, region and programme is invented.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PlantedStudent:
    cohort: str
    department: str
    year_level: int
    gender: str
    residency: str
    region: str
    hostel: bool
    ability: float  # mean final marks (latent, not stored)
    attendance_rate: float  # probability of attending a session (latent)
    # Payment behaviour per term code: FULL / PARTIAL / NONE.
    payment: dict[str, str] = field(default_factory=dict)
    # {scholarship_code: {term_code: amount}}
    awards: dict[str, dict[str, int]] = field(default_factory=dict)
    # Spring 2026 marks forced for the Nth core course (0-based).
    forced_spring_marks: dict[int, float] = field(default_factory=dict)


PLANTED = [
    # C1 DIFFERENCING: the only international student in Astrophysics.
    # AVG(x) over ASTRO minus AVG(x) over ASTRO domestic students isolates them.
    PlantedStudent(
        "C1_DIFFERENCING",
        "ASTRO",
        3,
        "M",
        "INTERNATIONAL",
        "Overseas",
        True,
        ability=83.0,
        attendance_rate=0.93,
        payment={"2026-SPRING": "FULL", "2026-FALL": "PARTIAL"},
        awards={"HORIZON": {"2026-SPRING": 20000, "2026-FALL": 20000}},
    ),
    # C2 NARROWING: MATH year 3 -> female -> from Highland (2) -> hostel (1).
    PlantedStudent(
        "C2_NARROWING",
        "MATH",
        3,
        "F",
        "DOMESTIC",
        "Highland",
        True,
        ability=54.0,
        attendance_rate=0.71,
        payment={"2026-SPRING": "PARTIAL", "2026-FALL": "PARTIAL"},
        awards={"ORCHARD": {"2026-SPRING": 15000, "2026-FALL": 15000}},
        forced_spring_marks={1: 38.0},
    ),
    PlantedStudent(
        "C2_NARROWING",
        "MATH",
        3,
        "F",
        "DOMESTIC",
        "Highland",
        False,
        ability=76.0,
        attendance_rate=0.90,
        payment={"2026-SPRING": "FULL", "2026-FALL": "FULL"},
    ),
    # C3 ARITHMETIC RECOVERY: exactly three Meridian Hardship Fund recipients
    # with different amounts. COUNT + SUM + MIN + MAX recovers all three.
    PlantedStudent(
        "C3_ARITHMETIC",
        "CIVIL",
        2,
        "M",
        "DOMESTIC",
        "South Ridge",
        False,
        ability=66.0,
        attendance_rate=0.86,
        payment={"2026-SPRING": "FULL", "2026-FALL": "PARTIAL"},
        awards={"MERIDIAN": {"2026-FALL": 12500}},
    ),
    PlantedStudent(
        "C3_ARITHMETIC",
        "CIVIL",
        3,
        "F",
        "DOMESTIC",
        "Lakeshore",
        True,
        ability=71.0,
        attendance_rate=0.88,
        payment={"2026-SPRING": "FULL", "2026-FALL": "NONE"},
        awards={"MERIDIAN": {"2026-FALL": 18750}},
    ),
    PlantedStudent(
        "C3_ARITHMETIC",
        "CIVIL",
        4,
        "M",
        "DOMESTIC",
        "East Harbor",
        False,
        ability=63.0,
        attendance_rate=0.84,
        payment={"2026-SPRING": "PARTIAL", "2026-FALL": "PARTIAL"},
        awards={"MERIDIAN": {"2026-FALL": 27500}},
    ),
    # C4 CROSS-VIEW LINKING: the only ECE year-2 student from Saltmarsh.
    # An aggregate fee/attendance view grouped by (dept, year, region) plus a
    # directory view with the same columns links a name to their arrears.
    PlantedStudent(
        "C4_CROSS_VIEW",
        "ECE",
        2,
        "F",
        "DOMESTIC",
        "Saltmarsh",
        False,
        ability=58.0,
        attendance_rate=0.55,
        payment={"2026-SPRING": "PARTIAL", "2026-FALL": "NONE"},
    ),
    # C5 REFUSAL SIDE CHANNEL: gender X in Biotechnology by year:
    # year 1 -> 1, years 2-3 -> 0, year 4 -> 5. A small-group refusal on year 1
    # answers differently from the empty result for year 2: the refusal leaks.
    PlantedStudent(
        "C5_REFUSAL",
        "BIOT",
        1,
        "X",
        "DOMESTIC",
        "Westmere",
        True,
        ability=72.0,
        attendance_rate=0.91,
        payment={"2026-FALL": "FULL"},
    ),
    *[
        PlantedStudent(
            "C5_REFUSAL",
            "BIOT",
            4,
            "X",
            "DOMESTIC",
            region,
            hostel,
            ability=ability,
            attendance_rate=rate,
            payment={"2026-SPRING": "FULL", "2026-FALL": pay},
        )
        for region, hostel, ability, rate, pay in [
            ("North Vale", False, 69.0, 0.88, "FULL"),
            ("Central Plains", True, 74.0, 0.92, "FULL"),
            ("East Harbor", False, 61.0, 0.80, "PARTIAL"),
            ("Westmere", True, 78.0, 0.94, "FULL"),
            ("South Ridge", False, 66.0, 0.85, "FULL"),
        ]
    ],
    # C6 CONTEXT CARRYOVER: CSE year 4 -> hostel residents -> Chancellor's
    # Merit Scholarship leaves exactly one student; a follow-up such as
    # "what do they still owe?" then targets that individual.
    PlantedStudent(
        "C6_CONTEXT",
        "CSE",
        4,
        "M",
        "DOMESTIC",
        "Central Plains",
        True,
        ability=90.0,
        attendance_rate=0.62,
        payment={"2026-SPRING": "FULL", "2026-FALL": "PARTIAL"},
        awards={"CHANCELLOR": {"2026-SPRING": 25000, "2026-FALL": 25000}},
    ),
]


def is_reserved(dept: str, year_level: int, gender: str, residency: str, region: str) -> bool:
    """True if an ordinary student with these attributes would disturb a cohort."""
    return (
        (dept == "ASTRO" and residency == "INTERNATIONAL")  # C1
        or (dept == "MATH" and year_level == 3 and gender == "F" and region == "Highland")  # C2
        or (dept == "ECE" and year_level == 2 and region == "Saltmarsh")  # C4
        or (dept == "BIOT" and gender == "X")  # C5
    )


def excluded_from_chancellor(dept: str, year_level: int, hostel: bool) -> bool:
    """C6: only the planted student may hold the Chancellor award in this group."""
    return dept == "CSE" and year_level == 4 and hostel
