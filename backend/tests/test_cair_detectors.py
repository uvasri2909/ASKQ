"""The six audits over hand-built populations (no SQL, no database)."""

import pytest

from app.cair import detectors
from app.cair.model import AttackClass, Cell, Measure, Observation
from app.cair.scoring import assess, combined_risk, risk_level
from app.cair.state import ConversationSecurityState
from app.query.decision import Decision

K = 5
AVG_MARKS = frozenset({Measure("sum", "grades.marks")})
COUNT = frozenset({Measure("count", "*")})
SUM_AWARD = frozenset({Measure("sum", "student_scholarships.amount")})


def ids(*ranges):
    people = set()
    for r in ranges:
        people |= set(r)
    return frozenset(people)


def obs(cells, *, measures=AVG_MARKS, dims=("d",), decision="ALLOW", known=frozenset(),
        revealed=None, conversation=1, qid=1):  # fmt: skip
    cells = tuple(cells)
    if revealed is None:
        revealed = tuple(c for c in cells if c.size >= K) if decision != "BLOCK" else ()
    return Observation(
        query_id=qid,
        conversation_id=conversation,
        decision=decision,
        cells=cells,
        revealed=revealed,
        measures=measures,
        dimensions=frozenset(dims),
        known=known,
    )


def cell(people, key=()):
    return Cell(key, frozenset(people))


def run(current, history=(), *, grouped=False, conversation=1):
    state = ConversationSecurityState(conversation, tuple(history))
    return assess(current, state, k=K, refusal_limit=3, threshold=0.5, grouped=grouped)


def classes(assessment):
    return set(assessment.attack_classes)


ASTRO = ids(range(1, 21))  # 20 people
ASTRO_DOMESTIC = ids(range(1, 20))  # 19: excludes person 20


# ---------------- DIFFERENCING ----------------


def test_benign_aggregate_sequence():
    first = obs([cell(ids(range(1, 101)))])
    second = obs([cell(ids(range(1, 51)))], qid=2)  # differs by 50 people
    assert run(second, [first]).decision is Decision.ALLOW


def test_differencing_detected():
    first = obs([cell(ASTRO)])
    second = obs([cell(ASTRO_DOMESTIC)], qid=2)
    result = run(second, [first])
    assert result.decision is Decision.BLOCK
    assert AttackClass.DIFFERENCING.value in classes(result)


def test_differencing_detected_in_either_order():
    first = obs([cell(ASTRO_DOMESTIC)])
    second = obs([cell(ASTRO)], qid=2)
    assert AttackClass.DIFFERENCING.value in classes(run(second, [first]))


def test_differencing_needs_a_common_measure():
    first = obs([cell(ASTRO)], measures=frozenset({Measure("sum", "fees.amount")}))
    second = obs([cell(ASTRO_DOMESTIC)], qid=2)
    finding = detectors.differencing(second, second.revealed, (first,), K)
    assert not finding.triggered


def test_differencing_inside_one_query():
    both = obs([cell(ASTRO, (0,)), cell(ASTRO_DOMESTIC, (1,))])
    finding = detectors.differencing(both, both.revealed, (), K)
    assert finding.triggered and finding.evidence["difference"] == 1


@pytest.mark.parametrize(("difference", "triggered"), [(1, True), (4, True), (5, False)])
def test_differencing_boundary(difference, triggered):
    big = ids(range(1, 31))
    small = ids(range(1, 31 - difference))
    finding = detectors.differencing(
        obs([cell(small)], qid=2), (cell(small),), (obs([cell(big)]),), K
    )
    assert finding.triggered is triggered


def test_known_people_do_not_count_as_a_difference():
    # The one person in the difference is someone the user can already see.
    first = obs([cell(ASTRO)], known=frozenset({20}))
    second = obs([cell(ASTRO_DOMESTIC)], qid=2)
    assert detectors.differencing(second, second.revealed, (first,), K).triggered is False


# ---------------- NARROWING ----------------


def test_normal_filtering_is_fine():
    assert run(obs([cell(range(1, 27))])).decision is Decision.ALLOW


def test_progressive_narrowing_blocked_at_the_small_group():
    steps = [range(1, 27), range(1, 15), range(1, 3), range(1, 2)]
    history = []
    decisions = []
    for i, people in enumerate(steps, start=1):
        current = obs([cell(people)], dims=[f"d{j}" for j in range(i)], qid=i)
        result = run(current, history)
        decisions.append(result.decision)
        history.append(
            obs([cell(people)], dims=[f"d{j}" for j in range(i)], qid=i,
                decision=result.decision.value)
        )  # fmt: skip
    assert decisions == [Decision.ALLOW, Decision.ALLOW, Decision.BLOCK, Decision.BLOCK]


def test_refinement_chain_is_reported():
    first = obs([cell(range(1, 27))], dims=["a"])
    second = obs([cell(range(1, 15))], dims=["a", "b"], qid=2)
    finding = detectors.narrowing(second, second.revealed, (first,), K)
    assert finding.evidence["refinement_chain"] == 1 and not finding.triggered


@pytest.mark.parametrize(("size", "blocked"), [(0, True), (1, True), (4, True), (5, False)])
def test_narrowing_threshold_boundary(size, blocked):
    current = obs([cell(range(1, size + 1))] if size else [])
    assert (run(current).decision is Decision.BLOCK) is blocked


def test_empty_and_small_groups_are_indistinguishable():
    empty, single = run(obs([])), run(obs([cell([7])]))
    assert empty.decision is single.decision is Decision.BLOCK
    assert empty.attack_classes == single.attack_classes == ["NARROWING"]


def test_reordered_harmless_queries_stay_allowed():
    a, b = obs([cell(range(1, 101))]), obs([cell(range(101, 201))], qid=2)
    assert run(b, [a]).decision is run(a, [b]).decision is Decision.ALLOW


# ---------------- ARITHMETIC RECOVERY ----------------

NEED = ids(range(1, 61))  # 60 recipients
ORCHARD = ids(range(1, 58))  # 57
MERIDIAN = ids(range(58, 61))  # 3 (below k: suppressed)


def test_independent_aggregates_are_safe():
    a = obs([cell(NEED)], measures=SUM_AWARD)
    b = obs([cell(ids(range(100, 200)))], measures=SUM_AWARD, qid=2)
    assert run(b, [a]).decision is Decision.ALLOW


def test_total_minus_visible_parts_recovers_a_suppressed_group():
    total = obs([cell(NEED)], measures=SUM_AWARD)
    by_programme = obs([cell(ORCHARD, (0, "ORCHARD")), cell(MERIDIAN, (0, "MERIDIAN"))],
                       measures=SUM_AWARD, qid=2)  # fmt: skip
    result = run(by_programme, [total], grouped=True)
    assert AttackClass.ARITHMETIC_RECOVERY.value in classes(result)
    assert result.decision is Decision.BLOCK  # withholding ORCHARD leaves nothing


def test_arithmetic_in_the_other_order():
    by_programme = obs([cell(ORCHARD, (0, "ORCHARD")), cell(MERIDIAN, (0, "MERIDIAN"))],
                       measures=SUM_AWARD)  # fmt: skip
    total = obs([cell(NEED)], measures=SUM_AWARD, qid=2)
    result = run(total, [by_programme])
    assert AttackClass.ARITHMETIC_RECOVERY.value in classes(result)
    assert result.decision is Decision.BLOCK


def test_average_times_count_is_covered():
    # Averages are sum-like: AVG over the total and AVG over the visible part.
    total = obs([cell(NEED)], measures=frozenset({Measure("sum", "x")}))
    part = obs([cell(ORCHARD)], measures=frozenset({Measure("sum", "x")}), qid=2)
    assert detectors.arithmetic_recovery(part, part.revealed, (total,), K).triggered


def test_parts_covering_the_whole_are_safe():
    total = obs([cell(ids(range(1, 41)))], measures=COUNT)
    parts = obs([cell(range(1, 21), (0, "a")), cell(range(21, 41), (0, "b"))],
                measures=COUNT, qid=2)  # fmt: skip
    assert run(parts, [total], grouped=True).decision is Decision.ALLOW


@pytest.mark.parametrize(("remainder", "triggered"), [(4, True), (5, False)])
def test_arithmetic_boundary(remainder, triggered):
    whole = ids(range(1, 51))
    part = ids(range(1, 51 - remainder))
    finding = detectors.arithmetic_recovery(
        obs([cell(part)], measures=COUNT, qid=2), (cell(part),),
        (obs([cell(whole)], measures=COUNT),), K,
    )  # fmt: skip
    assert finding.triggered is triggered


def test_complementary_suppression_restricts_instead_of_blocking():
    total = obs([cell(ids(range(1, 101)))], measures=COUNT)
    groups = obs(
        [
            cell(range(1, 31), (0, "a")),
            cell(range(31, 61), (0, "b")),
            cell(range(61, 99), (0, "c")),
            cell(range(99, 101), (0, "tiny")),  # 2 people, suppressed
        ],
        measures=COUNT,
        qid=2,
    )
    result = run(groups, [total], grouped=True)
    assert result.decision is Decision.RESTRICT
    assert result.excluded == {(0, "a")}  # smallest visible part withheld
    assert {c.key for c in result.revealed} == {(0, "b"), (0, "c")}


# ---------------- CROSS-VIEW LINKING ----------------

GROUP = ids(range(1, 6))  # 5 people


def test_independent_views_are_safe():
    assert run(obs([cell(GROUP)], known=frozenset())).decision is Decision.ALLOW


def test_record_view_plus_statistic_isolates_the_rest():
    result = run(obs([cell(GROUP)], known=frozenset({1, 2, 3, 4})))
    assert AttackClass.CROSS_VIEW_LINKING.value in classes(result)
    assert result.decision is Decision.BLOCK


def test_fully_known_group_is_not_a_leak():
    finding = detectors.cross_view_linking(obs([cell(GROUP)], known=GROUP), (cell(GROUP),), (), K)
    assert not finding.triggered


def test_linking_in_a_grouped_query_restricts_the_linked_group():
    current = obs(
        [cell(GROUP, (0, "x")), cell(range(10, 30), (0, "y"))],
        known=frozenset({1, 2, 3}),
    )
    result = run(current, grouped=True)
    assert result.decision is Decision.RESTRICT and result.excluded == {(0, "x")}


# ---------------- REFUSAL SIDE CHANNEL ----------------


def refused(qid, dims=("dept", "gender", "year")):
    return obs([cell([qid])], dims=dims, decision="BLOCK", qid=qid)


def test_allowed_query_without_refusals():
    assert run(obs([cell(range(1, 10))], dims=("dept", "gender", "year"))).decision is (
        Decision.ALLOW
    )


def test_repeated_probing_is_refused():
    current = obs([cell(range(1, 6))], dims=("dept", "gender", "year"), qid=9)
    result = run(current, [refused(1), refused(2), refused(3)])
    assert AttackClass.REFUSAL_SIDE_CHANNEL.value in classes(result)
    assert result.decision is Decision.BLOCK


def test_two_refusals_are_not_yet_probing():
    current = obs([cell(range(1, 6))], dims=("dept", "gender", "year"), qid=9)
    assert run(current, [refused(1), refused(2)]).decision is Decision.ALLOW


def test_unrelated_refusals_do_not_count():
    current = obs([cell(range(1, 6))], dims=("fees", "term"), qid=9)
    assert run(current, [refused(1), refused(2), refused(3)]).decision is Decision.ALLOW


# ---------------- CONTEXT CARRYOVER ----------------

TARGET = frozenset({42})


def test_same_query_without_context():
    current = obs([cell(TARGET)], qid=3)
    result = run(current, [])
    assert classes(result) == {"NARROWING"}


def test_same_query_after_identifying_context():
    context = obs([cell(TARGET)], decision="BLOCK", qid=2)
    current = obs([cell(TARGET)], qid=3)
    result = run(current, [context])
    assert {"NARROWING", "CONTEXT_CARRYOVER"} <= classes(result)


def test_benign_context_is_not_carried_over():
    context = obs([cell(range(1, 24))], qid=1)  # 23 people, answered
    current = obs([cell(range(1, 24))], qid=2)
    assert detectors.context_carryover(current, (context,), K).triggered is False


def test_context_from_another_conversation_is_not_carryover():
    context = obs([cell(TARGET)], decision="BLOCK", qid=2, conversation=7)
    current = obs([cell(TARGET)], qid=3, conversation=1)
    assert "CONTEXT_CARRYOVER" not in classes(run(current, [context], conversation=1))


def test_multi_turn_context():
    turns = [
        obs([cell(range(1, 24))], qid=1),
        obs([cell(TARGET)], decision="BLOCK", qid=2),
        obs([cell(range(100, 140))], qid=3),
    ]
    current = obs([cell(TARGET)], qid=4)
    assert "CONTEXT_CARRYOVER" in classes(run(current, turns))


# ---------------- risk ----------------


def test_risk_combines_and_levels():
    result = run(obs([cell(ASTRO_DOMESTIC)], qid=2), [obs([cell(ASTRO)])])
    assert result.risk == combined_risk(result.findings) >= 0.8
    assert risk_level(result.risk) == "HIGH"
    assert risk_level(0.0) == "LOW" and risk_level(0.5) == "MEDIUM"
    assert run(obs([cell(range(1, 50))])).risk == 0.0


def test_every_audit_always_reports():
    result = run(obs([cell(range(1, 50))]))
    assert sorted(f.attack.value for f in result.findings) == sorted(a.value for a in AttackClass)
