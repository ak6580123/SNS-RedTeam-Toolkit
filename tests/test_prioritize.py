import datetime as dt

from scripter.models import Exploitability, MatchStatus, Severity, VulnMatch
from scripter.prioritize import prioritize, score_match


def _match(status, severity=Severity.HIGH, exploitability=Exploitability.TRIVIAL, confidence=0.5, ttv=5):
    return VulnMatch(
        host="10.10.1.5", port=21, service="ftp", version="2.3.4", signature_id="sig",
        cve_id="CVE-TEST", description="test", severity=severity, exploitability=exploitability,
        time_to_validate_minutes=ttv, status=status, confidence=confidence, evidence="",
        matched_at=dt.datetime.now(dt.timezone.utc),
    )


def test_confirmed_outranks_hypothesis_at_equal_severity():
    confirmed = _match(MatchStatus.CONFIRMED)
    hypothesis = _match(MatchStatus.HYPOTHESIS)
    assert score_match(confirmed) > score_match(hypothesis)


def test_ruled_out_sinks_to_bottom():
    ruled_out = _match(MatchStatus.RULED_OUT)
    hypothesis = _match(MatchStatus.HYPOTHESIS)
    assert score_match(ruled_out) < score_match(hypothesis)


def test_higher_severity_outranks_lower():
    critical = _match(MatchStatus.HYPOTHESIS, severity=Severity.CRITICAL)
    low = _match(MatchStatus.HYPOTHESIS, severity=Severity.LOW)
    assert score_match(critical) > score_match(low)


def test_faster_to_validate_outranks_slower_at_equal_everything_else():
    fast = _match(MatchStatus.HYPOTHESIS, ttv=2)
    slow = _match(MatchStatus.HYPOTHESIS, ttv=60)
    assert score_match(fast) > score_match(slow)


def test_prioritize_assigns_ranks_in_score_order():
    matches = [_match(MatchStatus.RULED_OUT), _match(MatchStatus.CONFIRMED), _match(MatchStatus.HYPOTHESIS)]
    ranked = prioritize(matches)
    assert [r.rank for r in ranked] == [1, 2, 3]
    assert ranked[0].match.status == MatchStatus.CONFIRMED
    assert ranked[-1].match.status == MatchStatus.RULED_OUT
