"""CAIR evaluation: deterministic attack/benign scenarios and a metrics harness.

Scenarios bypass the language model (each step carries its SQL), so runs are
reproducible against the fixed Phase 2 seed. See docs/attack-scenarios.md and
docs/cair.md ("Evaluation").
"""
