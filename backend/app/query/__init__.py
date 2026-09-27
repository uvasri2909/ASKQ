"""Natural-language query pipeline.

    question ─► Claude (UNTRUSTED SQL) ─► validate ─► authorize + row scope
             ─► bound LIMIT ─► guard (CAIR in Phase 5) ─► askq_reader ─► history (askq_app)

Nothing produced by the model is trusted: the SQL that runs is regenerated
from an AST that passed every check, with the user's row scope injected by
the server. See backend/README.md ("Query pipeline").
"""
