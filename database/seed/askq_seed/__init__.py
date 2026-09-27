"""Deterministic synthetic-data generator for the ASKQ MySQL databases.

Standard library only. The same seed always produces byte-identical SQL.
Entry point: database/seed/generate_seed.py (see database/README.md).
"""

from askq_seed.generator import DEFAULT_SEED, GENERATOR_VERSION, Dataset, build_dataset
from askq_seed.sqlwriter import render_cohort_checks, render_sql_files

__all__ = [
    "DEFAULT_SEED",
    "GENERATOR_VERSION",
    "Dataset",
    "build_dataset",
    "render_cohort_checks",
    "render_sql_files",
]
