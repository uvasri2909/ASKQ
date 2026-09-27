"""Run the CAIR scenarios against the local ASKQ MySQL and print the metrics.

    cd C:\\ASKQ\\backend
    .venv\\Scripts\\python -m app.evaluation            # both modes, summary
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
from app.evaluation.harness import BASELINE, CAIR, EvaluationHarness, compute_metrics
from app.evaluation.scenarios import ALL


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CAIR scenario evaluation (rolled back)")
    parser.add_argument("--steps", action="store_true", help="print every step")
    parser.add_argument("--mode", choices=[CAIR, BASELINE, "BOTH"], default="BOTH")
    args = parser.parse_args(argv)

    settings = get_settings()
    database = Database(settings)
    report = {}
    try:
        with database.app_engine.connect() as connection:
            outer = connection.begin()
            try:
                harness = EvaluationHarness(connection, database, settings)
                for mode in [CAIR, BASELINE] if args.mode == "BOTH" else [args.mode]:
                    results = harness.run(ALL, mode)
                    metrics = compute_metrics(mode, ALL, results)
                    harness.record(mode, results, metrics)
                    report[mode] = {"metrics": asdict(metrics)}
                    if args.steps:
                        report[mode]["steps"] = [
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
