import datetime as dt

from scripter.models import Exploitability, MatchStatus, Severity, VulnMatch
from scripter.scope import parse_scope
from scripter.validation.checks import CHECKS, run_validation


def _match(signature_id="sig"):
    return VulnMatch(
        host="10.10.1.5", port=21, service="ftp", version=None, signature_id=signature_id,
        cve_id="CVE-TEST", description="test", severity=Severity.HIGH, exploitability=Exploitability.TRIVIAL,
        time_to_validate_minutes=5, status=MatchStatus.HYPOTHESIS, confidence=0.3, evidence="banner",
        matched_at=dt.datetime.now(dt.timezone.utc),
    )


def test_registered_checks_are_exactly_the_three_documented():
    assert set(CHECKS) == {"ftp_anonymous_login_check", "redis_unauthenticated_check", "tls_weak_protocol_check"}


def test_match_without_registered_check_passes_through_unchanged():
    scope = parse_scope(["10.10.1.5"])
    match = _match()
    updated = run_validation([match], {}, scope, timeout=1.0)
    assert updated == [match]


def test_check_exception_degrades_to_inconclusive_without_crashing(monkeypatch):
    def boom(match, scope, timeout):
        raise RuntimeError("simulated failure")

    monkeypatch.setitem(CHECKS, "boom_check", boom)
    scope = parse_scope(["10.10.1.5"])
    match = _match()
    updated = run_validation([match], {"sig": "boom_check"}, scope, timeout=1.0)
    assert updated[0].status == MatchStatus.INCONCLUSIVE
    assert "check raised an error" in updated[0].evidence
