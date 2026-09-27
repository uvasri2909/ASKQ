"""Generate the ASKQ seed SQL into database/seed/generated/.

Usage (from C:\\ASKQ):
    backend\\.venv\\Scripts\\python database\\seed\\generate_seed.py [--seed N] [--out DIR]
    backend\\.venv\\Scripts\\python database\\seed\\generate_seed.py --refresh-validation

Standard library only; no database connection. The same seed always writes
byte-identical files. database\\setup_db.ps1 runs this automatically.

--refresh-validation rewrites the committed database/validation/verify_security_cohorts.sql
after askq_seed/cohort_checks.py changes (a test fails until you do).
"""

import argparse
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from askq_seed import (  # noqa: E402
    DEFAULT_SEED,
    build_dataset,
    render_cohort_checks,
    render_sql_files,
)

COHORT_CHECK_SQL = HERE.parent / "validation" / "verify_security_cohorts.sql"


def _write(path: Path, content: str) -> None:
    data = content.encode("utf-8")
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()[:16]
    print(f"  {path.name:32} {len(data) / 1024:9.1f} KiB  sha256 {digest}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", type=Path, default=HERE / "generated")
    parser.add_argument(
        "--refresh-validation",
        action="store_true",
        help=f"only rewrite {COHORT_CHECK_SQL.name} from cohort_checks.py",
    )
    args = parser.parse_args()

    if args.refresh_validation:
        print(f"Refreshing {COHORT_CHECK_SQL}")
        _write(COHORT_CHECK_SQL, render_cohort_checks())
        return 0

    dataset = build_dataset(args.seed)  # raises if any security-demo cohort check fails
    args.out.mkdir(parents=True, exist_ok=True)
    print(f"ASKQ seed generator: seed {args.seed} -> {args.out}")
    for name, content in render_sql_files(dataset).items():
        _write(args.out / name, content)
    print("Rows:")
    for table in dataset.tables.values():
        print(f"  {table.name:22} {len(table.rows):7}  (security-demo rows: {sum(table.planted)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
