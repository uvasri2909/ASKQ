"""CAIR: Conversation-Aware Inference Risk.

Judges what a user could LEARN from a statistical (aggregate-only) answer when
it is combined with what they already learned, can already see, or were
refused. It runs after validation and authorization, never widens anything,
and is deterministic: every signal comes from the parsed SQL, server-computed
populations and the server-side history, never from the model's text.

  descriptor.py  what a query is about (tables, predicates, groups, measures)
  population.py  WHO a query is about: server-generated probes -> id sets
  state.py       what the user already knows / was refused (from askq_system)
  detectors.py   the six attack classes over populations
  scoring.py     findings -> risk score -> ALLOW / RESTRICT / BLOCK
  guard.py       the InferenceGuard used by the query pipeline
"""
