"""Rank VulnMatch records by competition impact, confidence, and effort.

score = severity_weight * exploitability_weight * status_multiplier *
        confidence_factor / effort_factor

``effort_factor`` grows with ``time_to_validate_minutes``, so two findings
equal on severity/confidence/exploitability put the quicker-to-verify one
first - matching the requested ranking criteria: impact, confidence,
exploitability, and time required to validate.
"""
from __future__ import annotations

from scripter.models import EXPLOITABILITY_WEIGHT, SEVERITY_WEIGHT, MatchStatus, PrioritizedFinding, VulnMatch

#: CONFIRMED findings are worth acting on first; RULED_OUT ones are kept in
#: the record for honesty (never silently dropped) but should sink to the
#: bottom. HYPOTHESIS/INCONCLUSIVE sit in between, ordered mainly by the
#: signature's own confidence_base.
_STATUS_MULTIPLIER: dict[MatchStatus, float] = {
    MatchStatus.CONFIRMED: 1.5,
    MatchStatus.HYPOTHESIS: 1.0,
    MatchStatus.INCONCLUSIVE: 0.8,
    MatchStatus.RULED_OUT: 0.05,
}


def score_match(match: VulnMatch) -> float:
    severity_weight = SEVERITY_WEIGHT[match.severity]
    exploitability_weight = EXPLOITABILITY_WEIGHT[match.exploitability]
    status_multiplier = _STATUS_MULTIPLIER[match.status]
    confidence_factor = 0.4 + 0.6 * match.confidence
    effort_factor = 1.0 + (match.time_to_validate_minutes / 60.0)
    return (severity_weight * exploitability_weight * status_multiplier * confidence_factor) / effort_factor


def prioritize(matches: list[VulnMatch]) -> list[PrioritizedFinding]:
    scored = [(score_match(m), m) for m in matches]
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [PrioritizedFinding(match=m, score=round(score, 3), rank=i + 1) for i, (score, m) in enumerate(scored)]
