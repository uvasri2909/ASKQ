"""Phase 7B.1: the held-out benchmark is frozen, separate and correctly labelled.

No evaluation happens here (nothing runs the pipeline or CAIR). The data-side
checks of the ground truth are in tests/integration/test_heldout_mysql.py.

If a FROZEN hash below fails, the definitions changed after the freeze. Do
not update the pin to make the test pass: restore the definitions, or create a
new HELDOUT_VERSION whose freeze is committed (and reported) separately.
"""

import dataclasses
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from app.evaluation import heldout
from app.evaluation import scenarios as development
from app.evaluation.heldout import (
    ENFORCEMENT_OUTCOMES,
    EXPOSURE,
    HELDOUT,
    HELDOUT_ATTACKS,
    HELDOUT_BENIGN,
    MATCH_WITH,
    MUST_MATCH_SMALL_GROUP_RESPONSE,
    MUST_NOT_REVEAL,
    ORACLE,
    RECOVERY,
    SAFE_TO_REVEAL,
    SECURE_HANDLING,
    build_manifest,
    definition_sha256,
)
from app.query.decision import Decision

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent

# Pinned at the freeze (2026-10-07). See the module docstring before touching these.
FROZEN_HELDOUT_SHA256 = "5c6f9f9c0b0862e30b0b502a364e89ef5e0e232665006e2b7ea2a01617a20025"
# The development set (C1-C6, B1-B4) as committed in Phase 5 and used in Phase 7A.
FROZEN_DEVELOPMENT_SHA256 = "3b44540d32f4bf0aefe37795bea0e78f69adc3eb26eccf322f55912467b60a47"


def _sha(obj) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


# ---------------- freeze ----------------


def test_heldout_definitions_match_the_frozen_hash():
    assert definition_sha256() == FROZEN_HELDOUT_SHA256


def test_committed_manifest_matches_the_definitions():
    committed = json.loads((BACKEND / "app/evaluation/heldout_manifest.json").read_text("utf-8"))
    assert committed == build_manifest()
    assert committed["definition_sha256"] == FROZEN_HELDOUT_SHA256
    assert committed["status"].startswith("FROZEN")


def test_development_set_is_unchanged():
    assert _sha([heldout._definition(s) for s in development.ALL]) == FROZEN_DEVELOPMENT_SHA256
    assert [s.code for s in development.ALL] == [
        "C1_DIFFERENCING", "C2_NARROWING", "C3_ARITHMETIC", "C4_CROSS_VIEW", "C5_REFUSAL",
        "C6_CONTEXT", "B1_DEPARTMENT_PROFILE", "B2_OVERLAPPING_LARGE_GROUPS",
        "B3_TOTAL_AND_FULL_BREAKDOWN", "B4_OWN_RECORDS",
    ]  # fmt: skip


def test_definitions_are_deterministic():
    assert heldout.definitions() == heldout.definitions()
    assert definition_sha256() == definition_sha256()
    source = (BACKEND / "app/evaluation/heldout.py").read_text("utf-8")
    assert not re.search(r"^\s*(import|from)\s+(random|secrets|uuid|datetime|time)\b", source, re.M)


def test_dataset_is_the_phase2_seed():
    generator = (REPO / "database/seed/askq_seed/generator.py").read_text("utf-8")
    assert re.search(rf"^DEFAULT_SEED = {heldout.DATASET_SEED}$", generator, re.M)
    assert re.search(
        rf'^GENERATOR_VERSION = "{re.escape(heldout.DATASET_GENERATOR_VERSION)}"$', generator, re.M
    )


# ---------------- separation from the development set ----------------


def test_ids_do_not_collide_and_are_marked_heldout():
    dev = {s.code for s in development.ALL}
    held = [s.code for s in HELDOUT]
    assert len(held) == len(set(held))
    assert not dev & set(held)
    assert all(code.startswith("HO_") for code in held)
    assert set(ORACLE) == {s.code for s in HELDOUT_ATTACKS}


def test_no_question_or_sql_is_copied_from_the_development_set():
    dev_steps = [st for s in development.ALL for st in s.steps]
    dev_questions = {st.question for st in dev_steps}
    dev_sql = {st.sql for st in dev_steps} | {st.reference_sql for st in dev_steps}
    dev_sql.discard(None)
    for scenario in HELDOUT:
        for step in scenario.steps:
            assert step.question not in dev_questions, step.question
            assert step.sql not in dev_sql, step.question
            assert step.reference_sql is None or step.reference_sql not in dev_sql, step.question
            assert all(step is not d for d in dev_steps)


def test_development_benchmark_does_not_include_heldout():
    codes = {s.code for s in HELDOUT}
    assert not codes & {s.code for s in development.ALL}
    assert not codes & {s.code for s in development.ATTACKS + development.BENIGN}


def test_no_production_code_imports_the_heldout_benchmark():
    for path in (BACKEND / "app").rglob("*.py"):
        if path.name == "heldout.py":
            continue
        assert "heldout" not in path.read_text("utf-8"), path
    # Importing the application (and the evaluation CLI) does not load it.
    code = (
        "import sys, app.main, app.evaluation.__main__, app.evaluation.harness; "
        "print('app.evaluation.heldout' in sys.modules)"
    )
    out = subprocess.run(  # noqa: S603  (this interpreter, fixed arguments)
        [sys.executable, "-c", code], cwd=BACKEND, capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "False"


# ---------------- labels ----------------


def test_all_six_attack_classes_are_covered():
    assert {s.attack.value for s in HELDOUT_ATTACKS} == {
        "DIFFERENCING", "NARROWING", "ARITHMETIC_RECOVERY", "CROSS_VIEW_LINKING",
        "REFUSAL_SIDE_CHANNEL", "CONTEXT_CARRYOVER",
    }  # fmt: skip


def test_attacks_and_benign_are_labelled_consistently():
    for scenario in HELDOUT_ATTACKS:
        assert scenario.attack is not None
        assert any(st.leaks for st in scenario.steps), scenario.code
        assert any(not st.leaks for st in scenario.steps), scenario.code
    for scenario in HELDOUT_BENIGN:
        assert scenario.attack is None
        assert not any(st.leaks for st in scenario.steps), scenario.code
        assert all(st.expected is Decision.ALLOW for st in scenario.steps), scenario.code


def test_exposure_is_labelled_for_every_step():
    assert set(EXPOSURE) == {s.code for s in HELDOUT}
    for scenario in HELDOUT:
        labels = EXPOSURE[scenario.code]
        assert len(labels) == len(scenario.steps), scenario.code
        assert set(labels) <= {SAFE_TO_REVEAL, MUST_NOT_REVEAL, MUST_MATCH_SMALL_GROUP_RESPONSE}


def test_must_not_reveal_is_exactly_the_leaking_steps():
    for scenario in HELDOUT:
        for step, label in zip(scenario.steps, EXPOSURE[scenario.code], strict=True):
            assert (label == MUST_NOT_REVEAL) is step.leaks, step.question


def test_the_zero_person_probe_is_diagnostic_not_a_leak():
    diagnostic = [
        (s.code, i)
        for s in HELDOUT
        for i, label in enumerate(EXPOSURE[s.code], start=1)
        if label == MUST_MATCH_SMALL_GROUP_RESPONSE
    ]
    assert diagnostic == [("HO_A5_REFUSAL_PROBE_BY_DEPARTMENT", 2)]
    assert list(MATCH_WITH) == diagnostic
    code, index = diagnostic[0]
    scenario = next(s for s in HELDOUT if s.code == code)
    assert not scenario.steps[index - 1].leaks  # an empty group reveals nothing by itself
    # It is compared with this scenario's small-group probes, which must not reveal.
    for other in MATCH_WITH[diagnostic[0]]:
        assert EXPOSURE[code][other - 1] == MUST_NOT_REVEAL
    assert ORACLE[code][1][2] == 0  # the probed population really is empty


def test_benign_steps_are_all_safe_to_reveal():
    for scenario in HELDOUT_BENIGN:
        assert set(EXPOSURE[scenario.code]) == {SAFE_TO_REVEAL}, scenario.code


def test_harness_storage_value_is_not_the_ground_truth():
    # Step.expected only feeds evaluation_results.expected_decision.
    for scenario in HELDOUT:
        for step, label in zip(scenario.steps, EXPOSURE[scenario.code], strict=True):
            assert step.classes == ()  # no expectations about CAIR's detectors
            expected = Decision.ALLOW if label == SAFE_TO_REVEAL else Decision.BLOCK
            assert step.expected is expected, step.question
    manifest = build_manifest()
    for entry in (e for s in manifest["scenarios"] for e in s["expected"]):
        assert "secure_outcome" not in entry
        assert entry["exposure"] in SECURE_HANDLING
        assert entry["harness_expected_decision"] in {"ALLOW", "BLOCK"}
    assert "not the ground truth" in manifest["harness_expected_decision"]


def test_enforcement_outcomes_stay_distinct():
    # Every mechanism that can stop an answer is its own outcome; none is "detection".
    assert set(ENFORCEMENT_OUTCOMES) == {
        "ANSWERED", "K_SUPPRESSED", "CAIR_BLOCK", "CAIR_RESTRICT", "DENIED", "REJECTED",
        "FAILED",
    }  # fmt: skip
    must_not = SECURE_HANDLING[MUST_NOT_REVEAL]
    for outcome in ("K_SUPPRESSED", "CAIR_BLOCK", "CAIR_RESTRICT", "DENIED", "REJECTED"):
        assert outcome in must_not
    assert "FAILED" not in must_not and "not evaluable" in ENFORCEMENT_OUTCOMES["FAILED"]


def test_must_not_reveal_steps_are_ungrouped():
    # So "returned a row" means exactly "revealed the protected value".
    for scenario in HELDOUT_ATTACKS:
        for step, label in zip(scenario.steps, EXPOSURE[scenario.code], strict=True):
            if label == MUST_NOT_REVEAL:
                assert "GROUP BY" not in step.sql.upper(), step.question


def test_variation_from_the_development_set():
    by_code = {s.code: s for s in HELDOUT}
    # Subset asked before its superset (development C1 asks the superset first).
    a1 = by_code["HO_A1_DIFFERENCING_SUBSET_FIRST"].steps
    assert all("DOMESTIC" in st.sql and not st.leaks for st in a1[:2])
    assert all("DOMESTIC" not in st.sql and st.leaks for st in a1[2:])
    # A differencing attack split across conversations.
    assert by_code["HO_A7_DIFFERENCING_ACROSS_CONVERSATIONS"].steps[1].new_conversation
    # Attackers include roles the development attacks never use.
    assert {heldout.ATTACKER_ROLES[s.attacker] for s in HELDOUT_ATTACKS} >= {
        "TEACHER", "STUDENT", "HOD",
    }  # fmt: skip
    assert {s.attacker for s in HELDOUT} >= {"t0002", "s20230175"}
    assert not {s.attacker for s in HELDOUT} & {"t0016", "t0001"}


# ---------------- A1: a complete, self-contained differencing attack ----------------

A1 = "HO_A1_DIFFERENCING_SUBSET_FIRST"
_DOMESTIC = " AND s.residency_status = 'DOMESTIC'"


def _a1():
    return next(s for s in HELDOUT if s.code == A1)


def _split(sql):
    select, where = sql.split(" WHERE ")
    return select, where


def test_a1_is_differencing():
    assert _a1().attack.value == "DIFFERENCING"
    assert _a1().attacker == "t0002" and heldout.ATTACKER_ROLES["t0002"] == "TEACHER"


def test_a1_asks_counts_and_exact_sums_of_subset_then_superset():
    steps = _a1().steps
    assert len(steps) == 4
    selects, wheres = zip(*(_split(st.sql) for st in steps), strict=True)
    # 1, 3: head counts; 2, 4: exact integer totals; all over the same attendance rows.
    assert selects[0] == selects[2] == heldout._ATT_PEOPLE.rstrip()
    assert selects[1] == selects[3] == heldout._ATT_SESSIONS.rstrip()
    assert "COUNT(DISTINCT s.student_id)" in selects[0]
    assert "SUM(v.sessions_attended)" in selects[1]
    assert "AVG" not in " ".join(selects) and "ROUND" not in " ".join(selects)
    # Count and total of the same population; the subset is the superset + DOMESTIC.
    assert wheres[0] == wheres[1] and wheres[2] == wheres[3]
    assert wheres[0] == wheres[2] + _DOMESTIC
    assert all(st.population == "university" and not st.new_conversation for st in steps)


def test_a1_exposure_labels():
    assert EXPOSURE[A1] == (SAFE_TO_REVEAL, SAFE_TO_REVEAL, MUST_NOT_REVEAL, MUST_NOT_REVEAL)
    assert [st.leaks for st in _a1().steps] == [False, False, True, True]
    assert RECOVERY[A1]["exposure"] == MUST_NOT_REVEAL


def test_a1_recovery_uses_only_answers_of_earlier_steps():
    recovery, steps = RECOVERY[A1], _a1().steps
    assert recovery["after_step"] == len(steps)
    # Every input is an earlier step's answer; nothing else is assumed known.
    assert set(recovery["inputs"]) == set(recovery["values"])
    assert sorted(recovery["inputs"].values()) == [1, 2, 3, 4]
    kinds = {"people": heldout._ATT_PEOPLE, "sum": heldout._ATT_SESSIONS}
    for name, index in recovery["inputs"].items():
        assert 1 <= index <= recovery["after_step"], name
        assert steps[index - 1].sql.startswith(kinds[name.rsplit("_", 1)[1]]), name
        has_domestic = _DOMESTIC in steps[index - 1].sql
        assert has_domestic is name.startswith("subset"), name


def test_a1_recovery_is_exact():
    recovery = RECOVERY[A1]
    v = recovery["values"]
    assert all(isinstance(x, int) for x in v.values())
    assert recovery["complement_people"] == v["superset_people"] - v["subset_people"] == 1
    assert recovery["complement_people"] < heldout.K
    assert recovery["recovered"] == v["superset_sum"] - v["subset_sum"] == 122
    # The counts the attacker obtains are the oracle's population counts.
    counts = [n for _, _, n in ORACLE[A1]]
    assert counts == [v["subset_people"], v["superset_people"], recovery["complement_people"]]


def test_recovery_is_declared_only_for_a1_and_is_in_the_manifest():
    assert set(RECOVERY) == {A1}
    entries = {e["id"]: e for e in build_manifest()["scenarios"]}
    assert entries[A1]["recovery"] == RECOVERY[A1]
    assert all(e["recovery"] is None for code, e in entries.items() if code != A1)
    assert heldout.definitions()["recovery"] == RECOVERY


def test_benign_workload_spans_roles_and_topics():
    roles = {heldout.ATTACKER_ROLES[s.attacker] for s in HELDOUT_BENIGN}
    assert roles == {"TEACHER", "STUDENT", "HOD"}
    sql = " ".join(st.sql for s in HELDOUT_BENIGN for st in s.steps)
    for table in ("v_attendance_summary", "v_fee_balances", "grades", "student_scholarships"):
        assert table in sql
    assert any(len(s.steps) > 1 for s in HELDOUT_BENIGN)  # multi-turn
    assert any(st.new_conversation for s in HELDOUT_BENIGN for st in s.steps)


@pytest.mark.parametrize("key", ["password", "secret", "jwt", "api_key", "askq_reader", "askq_app"])
def test_manifest_has_no_secrets_or_sql(key):
    text = json.dumps(build_manifest()).lower()
    assert key not in text
    assert "select " not in text


def _replace_step(scenario_index, step_index, **change):
    scenario = heldout.HELDOUT[scenario_index]
    steps = list(scenario.steps)
    steps[step_index] = dataclasses.replace(steps[step_index], **change)
    held = list(heldout.HELDOUT)
    held[scenario_index] = dataclasses.replace(scenario, steps=tuple(steps))
    return tuple(held)


def _mutations():
    first = heldout.HELDOUT[0]
    a1 = first.code
    premise = ORACLE[a1][0]
    return {
        "question": ("HELDOUT", _replace_step(0, 1, question=first.steps[1].question + "?")),
        "sql": ("HELDOUT", _replace_step(0, 1, sql=first.steps[1].sql + " ")),
        "exposure label": ("EXPOSURE", {**EXPOSURE, a1: (SAFE_TO_REVEAL,) * len(first.steps)}),
        "enforcement expectation": ("HELDOUT", _replace_step(0, 1, expected=Decision.RESTRICT)),
        "attacker": (
            "HELDOUT",
            (dataclasses.replace(first, attacker="t0003"),) + heldout.HELDOUT[1:],
        ),
        "role": ("ATTACKER_ROLES", {**heldout.ATTACKER_ROLES, first.attacker: "HOD"}),
        "premise": ("ORACLE", {**ORACLE, a1: ((premise[0], premise[1], premise[2] + 1),)
                               + ORACLE[a1][1:]}),
        "secure handling": ("SECURE_HANDLING", {**SECURE_HANDLING, MUST_NOT_REVEAL: "BLOCK"}),
        "recovered value": ("RECOVERY", {a1: {**RECOVERY[a1], "recovered": 0}}),
        "recovery exposure": ("RECOVERY", {a1: {**RECOVERY[a1], "exposure": SAFE_TO_REVEAL}}),
    }  # fmt: skip


@pytest.mark.parametrize("field", list(_mutations()))
def test_any_change_to_the_definition_changes_the_hash(monkeypatch, field):
    name, value = _mutations()[field]
    monkeypatch.setattr(heldout, name, value)
    assert definition_sha256() != FROZEN_HELDOUT_SHA256, field


def test_unchanged_definitions_keep_the_hash():
    assert definition_sha256() == FROZEN_HELDOUT_SHA256
