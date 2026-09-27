"""The six CAIR audits, as pure functions over populations (sets of person ids).

Notation: k = minimum group size; a "cell" is the population behind one
returned statistic; `known` = people whose records the user may already read
(record tier), who therefore cannot leak. U = unknown people = set - known.
Leakage means revealing a statistic about fewer than k unknown people.

  NARROWING           the query reveals no cell of >= k people (it isolates a
                      small or empty group: both treated alike, for uniformity);
                      refinement chains are reported as evidence.
  DIFFERENCING        a revealed cell is a strict subset/superset of an earlier
                      (or sibling) revealed cell with the same measure, and the
                      difference holds 1..k-1 unknown people.
  ARITHMETIC_RECOVERY for a sum-like measure (COUNT, SUM, AVG*COUNT), a revealed
                      parent cell minus disjoint revealed part cells leaves
                      1..k-1 unknown people (totals defeat suppression).
  CROSS_VIEW_LINKING  a revealed statistical cell of >= k people contains
                      people the user can see record by record, leaving only
                      1..k-1 unknown: record view + statistical view isolate them.
  REFUSAL_SIDE_CHANNEL the user has already been refused `limit` statistical
                      questions over the same attributes: continued probing of
                      the refusal boundary is itself refused.
  CONTEXT_CARRYOVER   the question is about people a previous turn of THIS
                      conversation singled out (a refused or sub-k population).
"""

from collections.abc import Iterable

from app.cair.model import AttackClass, Cell, Finding, Observation

SUM_LIKE = ("count", "sum")


def _unknown(ids: frozenset[int], known: frozenset[int]) -> frozenset[int]:
    return ids - known


def _small(n: int, k: int) -> bool:
    return 1 <= n < k


def _score_small(n: int, k: int) -> float:
    """0.8 for k-1 unknown people up to 1.0 for a single person."""
    if k <= 2:
        return 1.0
    return round(0.8 + 0.2 * (k - 1 - n) / (k - 2), 4) if n >= 1 else 1.0


def narrowing(current: Observation, candidate: tuple[Cell, ...], history, k: int) -> Finding:
    population = current.population
    supersets = [
        o.query_id
        for o in history
        if o.population and population < o.population and o.dimensions < current.dimensions
    ]
    evidence = {
        "cells": len(current.cells),
        "revealed_cells": len(candidate),
        "refinement_chain": len(supersets),
    }
    if not candidate:
        return Finding(
            AttackClass.NARROWING,
            1.0,
            True,
            "No group of at least the minimum size would be revealed.",
            evidence,
        )
    score = round(min(0.45, 0.1 * len(supersets)), 4)
    return Finding(
        AttackClass.NARROWING, score, False, "Revealed groups are large enough.", evidence
    )


def _compatible(a: Observation, b: Observation) -> set[str]:
    return {m.as_key() for m in a.measures} & {m.as_key() for m in b.measures}


def differencing(current: Observation, candidate: tuple[Cell, ...], history, k: int) -> Finding:
    known = current.known
    best: tuple[float, dict] | None = None
    implicated: set[tuple] = set()
    others: list[tuple[Cell, Observation, bool]] = [
        (cell, o, False) for o in history for cell in o.revealed
    ]
    others += [(cell, current, True) for cell in candidate]  # siblings in one query
    for cell in candidate:
        for other, observation, sibling in others:
            if other is cell or not _compatible(current, observation):
                continue
            a, b = cell.ids, other.ids
            if not (a < b or b < a):
                continue
            unknown = _unknown(a ^ b, known | observation.known)
            if _small(len(unknown), k):
                score = _score_small(len(unknown), k)
                implicated.add(cell.key)
                if best is None or score > best[0]:
                    best = (
                        score,
                        {
                            "difference": len(unknown),
                            "cell": len(a),
                            "other": len(b),
                            "other_query": None if sibling else observation.query_id,
                        },
                    )
    if best is None:
        return Finding(AttackClass.DIFFERENCING, 0.0, False, "No small population difference.")
    return Finding(
        AttackClass.DIFFERENCING,
        best[0],
        True,
        "Two statistics over nested populations differ by fewer than the minimum group.",
        best[1],
        frozenset(implicated),
    )


def _disjoint(cells: Iterable[Cell]) -> list[Cell]:
    chosen: list[Cell] = []
    covered: set[int] = set()
    for cell in sorted(cells, key=lambda c: (-c.size, repr(c.key))):
        if not (cell.ids & covered):
            chosen.append(cell)
            covered |= cell.ids
    return chosen


def arithmetic_recovery(
    current: Observation, candidate: tuple[Cell, ...], history, k: int
) -> Finding:
    # Pool revealed cells per sum-like measure, remembering which are current.
    pool: dict[str, list[tuple[Cell, bool, frozenset[int]]]] = {}
    for observation, cells, is_current in [
        *[(o, o.revealed, False) for o in history],
        (current, candidate, True),
    ]:
        for measure in observation.measures:
            if measure.kind not in SUM_LIKE:
                continue
            for cell in cells:
                pool.setdefault(measure.as_key(), []).append((cell, is_current, observation.known))
    for measure, entries in sorted(pool.items()):
        for parent, parent_current, parent_known in entries:
            parts = [
                (cell, cur)
                for cell, cur, _ in entries
                if cell.ids < parent.ids and cell is not parent
            ]
            if not parts:
                continue
            chosen = _disjoint(cell for cell, _ in parts)
            chosen_current = {c.key for c, cur in parts if cur and c in chosen}
            if not (parent_current or chosen_current):
                continue  # nothing new in this question
            covered = frozenset().union(*(c.ids for c in chosen))
            known = current.known | parent_known
            remainder = _unknown(parent.ids - covered, known)
            if not _small(len(remainder), k):
                continue
            # Complementary suppression: drop current parts (smallest first) until
            # what can no longer be subtracted holds at least k unknown people.
            implicated: set[tuple] = set()
            hidden = set(remainder)
            for cell in sorted(
                (c for c in chosen if c.key in chosen_current), key=lambda c: c.size
            ):
                if len(hidden) >= k:
                    break
                implicated.add(cell.key)
                hidden |= _unknown(cell.ids, known)
            return Finding(
                AttackClass.ARITHMETIC_RECOVERY,
                _score_small(len(remainder), k),
                True,
                "A total minus known subtotals isolates fewer than the minimum group.",
                {
                    "measure": measure,
                    "parent": parent.size,
                    "parts": len(chosen),
                    "remainder": len(remainder),
                },
                frozenset(implicated) if len(hidden) >= k and not parent_current else frozenset(),
            )
    return Finding(AttackClass.ARITHMETIC_RECOVERY, 0.0, False, "No recoverable remainder.")


def cross_view_linking(
    current: Observation, candidate: tuple[Cell, ...], history, k: int
) -> Finding:
    known = current.known
    worst: tuple[float, dict] | None = None
    implicated: set[tuple] = set()
    for cell in candidate:
        overlap = cell.ids & known
        unknown = cell.ids - known
        if overlap and _small(len(unknown), k):
            score = _score_small(len(unknown), k)
            implicated.add(cell.key)
            if worst is None or score > worst[0]:
                worst = (score, {"cell": cell.size, "known": len(overlap), "unknown": len(unknown)})
    if worst is None:
        return Finding(AttackClass.CROSS_VIEW_LINKING, 0.0, False, "No record/statistic link.")
    return Finding(
        AttackClass.CROSS_VIEW_LINKING,
        worst[0],
        True,
        "People visible record by record leave fewer than the minimum group unknown.",
        worst[1],
        frozenset(implicated),
    )


def refusal_side_channel(current: Observation, history, limit: int, threshold: float) -> Finding:
    related = [
        o.query_id
        for o in history
        if o.decision == "BLOCK"
        and o.dimensions
        and current.dimensions
        and len(o.dimensions & current.dimensions) / len(o.dimensions | current.dimensions) >= 0.5
    ]
    count = len(related)
    if count >= limit:
        score = round(min(1.0, threshold + (1 - threshold) * count / (limit * 2)), 4)
        return Finding(
            AttackClass.REFUSAL_SIDE_CHANNEL,
            score,
            True,
            "Repeated refused questions over the same attributes: probing the refusal boundary.",
            {"related_refusals": count},
        )
    score = round(threshold * count / limit * 0.99, 4)
    return Finding(
        AttackClass.REFUSAL_SIDE_CHANNEL,
        score,
        False,
        "Refusals so far are not a probing pattern.",
        {"related_refusals": count},
    )


def context_carryover(current: Observation, conversation, k: int) -> Finding:
    unknown = current.population - current.known
    if not unknown:
        return Finding(AttackClass.CONTEXT_CARRYOVER, 0.0, False, "Nothing unknown is asked.")
    for observation in reversed(conversation):
        subject = observation.population - observation.known
        sensitive = observation.decision == "BLOCK" or _small(len(subject), k)
        if sensitive and subject and unknown <= subject:
            implicated = frozenset(c.key for c in current.cells if c.ids & subject)
            return Finding(
                AttackClass.CONTEXT_CARRYOVER,
                0.9,
                True,
                "The question is about people singled out earlier in this conversation.",
                {"earlier_query": observation.query_id, "subject": len(subject)},
                implicated,
            )
    return Finding(AttackClass.CONTEXT_CARRYOVER, 0.0, False, "No sensitive earlier subject.")
