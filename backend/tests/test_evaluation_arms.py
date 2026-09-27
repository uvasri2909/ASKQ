"""Phase 7A: the evaluation arms (no database needed).

The arms differ only in the inference-control layer: the guard and the minimum
group size. The MySQL behaviour of each arm is tested in
tests/integration/test_evaluation_arms_mysql.py.
"""

import pytest

from app.evaluation import __main__ as cli
from app.evaluation.harness import (
    ARMS,
    BASELINE,
    CAIR,
    K_ONLY,
    NO_CONTROL,
    Arm,
    StepResult,
    compute_metrics,
    get_arm,
)
from app.evaluation.scenarios import ALL
from tests.conftest import make_settings


def test_exactly_three_arms():
    assert list(ARMS) == [NO_CONTROL, K_ONLY, CAIR]


def test_b0_no_control_has_k1_and_no_cair():
    arm = ARMS[NO_CONTROL]
    assert (arm.group_size(make_settings()), arm.cair) == (1, False)
    assert arm.description.startswith("B0")


def test_b1_k_only_has_k5_and_no_cair():
    arm = ARMS[K_ONLY]
    assert (arm.group_size(make_settings()), arm.cair) == (5, False)
    assert arm.description.startswith("B1")


def test_cair_has_k5_and_cair():
    arm = ARMS[CAIR]
    assert (arm.group_size(make_settings()), arm.cair) == (5, True)


def test_k_only_and_cair_always_share_the_configured_k():
    # So the two can only ever differ in the guard, whatever k is configured.
    settings = make_settings(cair_min_group_size=7)
    assert ARMS[K_ONLY].group_size(settings) == ARMS[CAIR].group_size(settings) == 7
    assert ARMS[NO_CONTROL].group_size(settings) == 1


def test_arms_differ_only_in_inference_control():
    fields = {name for arm in ARMS.values() for name in arm.__slots__}
    assert fields == {"id", "min_group_size", "cair", "description"}


def test_arm_definitions_are_immutable():
    with pytest.raises(AttributeError):
        ARMS[CAIR].cair = False  # type: ignore[misc]


def test_phase5_mode_names_still_work():
    assert get_arm(BASELINE) is ARMS[NO_CONTROL]
    assert get_arm(CAIR) is ARMS[CAIR]
    assert get_arm(ARMS[K_ONLY]) is ARMS[K_ONLY]


@pytest.mark.parametrize("name", ["", "cair", "PRODUCTION", "K5", "NONE"])
def test_unknown_arm_is_refused(name):
    with pytest.raises(ValueError, match="unknown evaluation arm"):
        get_arm(name)


def test_recorded_mode_fits_the_schema():
    # evaluation_runs.mode is CHECKed to BASELINE | CAIR: it records whether CAIR ran.
    assert {a.id: a.record_mode for a in ARMS.values()} == {
        NO_CONTROL: BASELINE,
        K_ONLY: BASELINE,
        CAIR: CAIR,
    }


def test_cli_selections():
    assert cli.SELECTIONS == {"BOTH": [CAIR, NO_CONTROL], "ALL": [CAIR, K_ONLY, NO_CONTROL]}


def _result(guard_ms):
    return StepResult(
        scenario="B4_OWN_RECORDS",
        attack=None,
        step=1,
        question="q",
        tier_requested="scope",
        decision="ALLOW",
        reason_code=None,
        attack_classes=[],
        expected_decision="ALLOW",
        expected_classes=[],
        leaks_if_answered=False,
        leaked=False,
        row_count=1,
        accurate=None,
        query_ms=1.0,
        guard_ms=guard_ms,
        query_id=1,
    )


@pytest.mark.parametrize(("arm", "latency"), [(NO_CONTROL, False), (K_ONLY, False), (CAIR, True)])
def test_metrics_are_labelled_by_arm(arm, latency):
    metrics = compute_metrics(arm, ALL, [_result(0.5)])
    assert metrics.mode == arm
    assert (metrics.detection_latency_ms is not None) is latency  # only CAIR detects


def test_baseline_metrics_are_labelled_no_control():
    assert compute_metrics(BASELINE, ALL, [_result(0.5)]).mode == NO_CONTROL


def test_arm_type():
    assert all(isinstance(a, Arm) for a in ARMS.values())
