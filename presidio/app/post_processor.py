"""Post-processing filters applied after Presidio analysis.

Removes lower-confidence entities whose spans overlap with a
higher-confidence entity of a different type (e.g. DATE_TIME on
text already covered by US_SSN).
"""

from __future__ import annotations

from typing import Sequence


def _spans_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """True if the two character ranges share at least one position."""
    return a_start < b_end and b_start < a_end


_COMPLEMENTARY_PAIRS: frozenset[frozenset[str]] = frozenset({
    frozenset({"STREET_ADDRESS", "LOCATION"}),
    frozenset({"STREET_ADDRESS", "PERSON"}),
})


def _remove_overlapping_lower_confidence(results: list) -> list:
    """When two different entity types overlap, keep the higher-confidence one.

    Handles cases like "880 32 4565" being detected as both US_SSN (0.85)
    and DATE_TIME (0.40) — the lower-score DATE_TIME is suppressed.
    Same-type overlaps are left to Presidio's built-in deduplication.
    Complementary pairs (e.g. STREET_ADDRESS + LOCATION) are never suppressed.
    """
    if len(results) <= 1:
        return results

    suppressed: set[int] = set()
    for i, a in enumerate(results):
        if i in suppressed:
            continue
        for j, b in enumerate(results):
            if j <= i or j in suppressed:
                continue
            if a.entity_type == b.entity_type:
                continue
            if frozenset({a.entity_type, b.entity_type}) in _COMPLEMENTARY_PAIRS:
                continue
            if not _spans_overlap(a.start, a.end, b.start, b.end):
                continue
            if a.score >= b.score:
                suppressed.add(j)
            else:
                suppressed.add(i)
                break

    return [r for idx, r in enumerate(results) if idx not in suppressed]


def filter_false_positives(
    text: str,
    results: Sequence,
) -> list:
    """Remove false-positive detections from Presidio results.

    Removes any entity whose span overlaps with a higher-confidence
    entity of a different type.

    Args:
        text: The original input text that was analyzed.
        results: Presidio ``RecognizerResult`` objects from ``analyzer.analyze()``.

    Returns:
        Filtered list with false-positive entries removed.
    """
    return _remove_overlapping_lower_confidence(list(results))


filter_datetime_false_positives = filter_false_positives
