"""CairGuard: the InferenceGuard the query pipeline uses when CAIR is enabled.

For RECORD-tier questions (the user's own row scope) nothing can leak beyond
what the user may already read, so the answer is ALLOW. For STATISTICAL-tier
questions:

  1. describe the query (descriptor.py, from the parsed SQL only);
  2. compute its cells (population.py) and the people the user can already
     see record by record (the same query under record-tier authorization);
  3. rebuild what the user learned or was refused (state.py);
  4. run the six audits and decide (detectors.py, scoring.py);
  5. for RESTRICT, return the user's query plus HAVING clauses that withhold
     the implicated groups; the pipeline re-validates and re-authorizes it.

Any error raises: the pipeline then records FAILED at stage CAIR and nothing
runs (fail closed). Responses carry only fixed, generic reasons.
"""

from collections.abc import Callable
from datetime import datetime

from sqlalchemy.orm import Session
from sqlglot import exp

from app.cair.descriptor import describe
from app.cair.model import Observation
from app.cair.population import PopulationProbe, build_probes, fingerprint
from app.cair.scoring import assess, risk_level
from app.cair.state import load_state
from app.clock import utcnow
from app.config import Settings
from app.query.authorization import AuthorizationDenied, authorize
from app.query.decision import Decision, GuardInput, GuardResult
from app.query.statistics import STATISTICAL_TIER, group_expressions, outer_selects

POLICY_VERSION = "cair-1.0"
_DIALECT = "mysql"

PUBLIC_REASONS = {
    Decision.ALLOW: "No inference risk was found for this statistic.",
    Decision.RESTRICT: "Part of the result was withheld to protect individuals.",
    Decision.BLOCK: "The answer could reveal information about individuals, so it was withheld.",
}
RECORD_REASON = "Record-level access within your permitted scope."


def _value(value) -> exp.Expression:
    return exp.Null() if value is None else exp.convert(value)


def restricted_sql(validated_tree: exp.Query, excluded: frozenset[tuple]) -> str:
    """The user's query with the excluded output groups withheld (HAVING NOT ...)."""
    tree = validated_tree.copy()
    for branch, select in enumerate(outer_selects(tree)):
        groups = group_expressions(select)
        conditions = []
        for key in sorted((k for k in excluded if k and k[0] == branch), key=repr):
            parts = [
                exp.Is(this=g.copy(), expression=exp.Null())
                if v is None
                else exp.EQ(this=g.copy(), expression=_value(v))
                for g, v in zip(groups, key[1:], strict=True)
            ]
            conditions.append(exp.Not(this=exp.Paren(this=exp.and_(*parts))))
        if not conditions:
            continue
        having = select.args.get("having")
        condition = exp.and_(*([having.this] if having is not None else []), *conditions)
        select.set("having", exp.Having(this=condition))
    return tree.sql(dialect=_DIALECT)


class CairGuard:
    policy_version = POLICY_VERSION
    gates_statistics = True  # the statistical tier is only offered behind this guard

    def __init__(
        self,
        session: Session,
        database,
        settings: Settings,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._session = session
        self._settings = settings
        self._clock = clock
        self._probe = PopulationProbe(
            database,
            timeout_ms=settings.sql_timeout_ms,
            cap=settings.cair_population_cap,
            university_db=settings.db_university_name,
        )

    def assess(self, request: GuardInput) -> GuardResult:
        if request.authorized.tier != STATISTICAL_TIER:
            return GuardResult(
                decision=Decision.ALLOW,
                risk_score=0.0,
                policy_version=POLICY_VERSION,
                reasons=(RECORD_REASON,),
                assessment={"tier": "RECORD", "public": [RECORD_REASON]},
                disclose=False,
            )
        settings = self._settings
        db = settings.db_university_name
        k = settings.cair_min_group_size
        user = request.user
        descriptor = describe(request.validated, STATISTICAL_TIER, user)

        probes = build_probes(request.authorized.ast, db)
        cells = self._probe.cells(probes)
        known_probes = []
        known: frozenset[int] = frozenset()
        try:
            record = authorize(request.validated, user, university_db=db, max_rows=1)
        except AuthorizationDenied:
            record = None  # the user cannot see any of these people record by record
        if record is not None:
            # Any failure here propagates (fail closed): an unknown "known" set
            # would silently weaken CROSS_VIEW_LINKING.
            known_probes = build_probes(record.ast, db)
            known = self._probe.ids(known_probes)

        state = load_state(
            self._session,
            self._probe,
            user_id=user.user_id,
            conversation_id=request.conversation_id,
            now=self._clock(),
            window_queries=settings.cair_window_queries,
            window_hours=settings.cair_window_hours,
            min_size=k,
        )
        current = Observation(
            query_id=None,
            conversation_id=request.conversation_id,
            decision="",
            cells=cells,
            revealed=(),
            measures=descriptor.measure_set(),
            dimensions=descriptor.dimension_set(),
            known=known,
        )
        grouped = any(group_expressions(s) for s in outer_selects(request.validated.ast))
        result = assess(
            current,
            state,
            k=k,
            refusal_limit=settings.cair_refusal_probe_limit,
            threshold=settings.cair_trigger_threshold,
            grouped=grouped,
        )

        public = PUBLIC_REASONS[result.decision]
        probe_json = [p.to_json() for p in probes]
        excluded = sorted([list(key) for key in result.excluded], key=repr)
        assessment = {
            "tier": STATISTICAL_TIER,
            "decision": result.decision.value,
            "risk_level": risk_level(result.risk),
            "attack_classes": result.attack_classes,
            "public": [public],
            "probes": probe_json,
            "known_probes": [p.to_json() for p in known_probes],
            "measures": descriptor.measures,
            "dimensions": sorted(descriptor.dimension_set()),
            "excluded": excluded,
            "cell_sizes": sorted(c.size for c in cells),
            "descriptor": descriptor.to_json(),
        }
        revealed_ids = frozenset().union(*(c.ids for c in result.revealed))
        population_fingerprint = fingerprint(revealed_ids, probes[0].sql if probes else "")
        ledger = {
            "descriptor": descriptor.to_json(),
            "probes": probe_json,
            "excluded": excluded,
            "revealed_cells": len(result.revealed),
        }
        return GuardResult(
            decision=result.decision,
            risk_score=result.risk,
            policy_version=POLICY_VERSION,
            reasons=(public,),
            restricted_sql=(
                restricted_sql(request.validated.ast, result.excluded)
                if result.decision is Decision.RESTRICT
                else None
            ),
            findings=result.findings,
            assessment=assessment,
            ledger=ledger,
            population_fingerprint=population_fingerprint,
            disclose=False,
        )
