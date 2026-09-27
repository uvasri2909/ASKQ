"""Run the CAIR scenarios against the local ASKQ MySQL and print the metrics.

    cd C:\\ASKQ\\backend
    .venv\\Scripts\\python -m app.evaluation            # CAIR and NO_CONTROL (B0), summary
    .venv\\Scripts\\python -m app.evaluation --mode ALL # CAIR, K_ONLY (B1) and NO_CONTROL (B0)
    .venv\\Scripts\\python -m app.evaluation --steps    # plus every step

Uses the real .env (values are never printed). All writes, including the
evaluation_runs/results rows, happen in one transaction that is ROLLED BACK,
so a run leaves askq_system exactly as it was.
"""

import argparse
import json
from dataclasses import asdict

from app.config import get_settings
from app.db.session import Database
from app.evaluation.harness import (
    ARMS,
    BASELINE,
    CAIR,
    K_ONLY,
    NO_CONTROL,
    EvaluationHarness,
    compute_metrics,
    get_arm,
)
from app.evaluation.scenarios import ALL

SELECTIONS = {"BOTH": [CAIR, NO_CONTROL], "ALL": [CAIR, K_ONLY, NO_CONTROL]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CAIR scenario evaluation (rolled back)")
    parser.add_argument("--steps", action="store_true", help="print every step")
    parser.add_argument(
        "--mode",
        choices=[*ARMS, BASELINE, *SELECTIONS],
        default="BOTH",
        help="an arm (BASELINE = NO_CONTROL), BOTH (CAIR + NO_CONTROL) or ALL (three arms)",
    )
    args = parser.parse_args(argv)

    settings = get_settings()
    database = Database(settings)
    report = {}
    try:
        with database.app_engine.connect() as connection:
            outer = connection.begin()
            try:
                harness = EvaluationHarness(connection, database, settings)
                for arm in map(get_arm, SELECTIONS.get(args.mode, [args.mode])):
                    results = harness.run(ALL, arm)
                    metrics = compute_metrics(arm, ALL, results)
                    harness.record(arm, results, metrics)
                    report[arm.id] = {"description": arm.description, "metrics": asdict(metrics)}
                    if args.steps:
                        report[arm.id]["steps"] = [
                            {k: v for k, v in asdict(r).items() if k != "response"} for r in results
                        ]
            finally:
                outer.rollback()
    finally:
        database.dispose()
    print(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
