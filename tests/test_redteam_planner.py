import datetime as dt

from scripter.intel.vuln_db import Signature
from scripter.models import Exploitability, MatchStatus, Severity, VulnMatch
from scripter.redteam.planner import build_plan
from scripter.scope import parse_scope


def _sig(id_: str, check: str | None = None) -> Signature:
    return Signature(
        id=id_, cve="CVE-TEST", service_pattern="^http$", version_pattern=None, description="d",
        severity=Severity.HIGH, exploitability=Exploitability.TRIVIAL, time_to_validate_minutes=5,
        confidence_base=0.5, check=check,
    )


def _match(
    host="10.10.1.5", port=80, service="http", status=MatchStatus.HYPOTHESIS, signature_id="sig-a",
    severity=Severity.HIGH, confidence=0.5,
) -> VulnMatch:
    return VulnMatch(
        host=host, port=port, service=service, version=None, signature_id=signature_id, cve_id="CVE-TEST",
        description="d", severity=severity, exploitability=Exploitability.TRIVIAL, time_to_validate_minutes=5,
        status=status, confidence=confidence, evidence="banner", matched_at=dt.datetime.now(dt.timezone.utc),
    )


def test_plan_is_deterministic_for_identical_inputs():
    scope = parse_scope(["10.10.1.5"])
    matches = [_match()]
    sigs = [_sig("sig-a")]
    plan1 = build_plan(1, matches, sigs, scope)
    plan2 = build_plan(1, matches, sigs, scope)
    assert plan1.items == plan2.items
    assert plan1.skipped == plan2.skipped


def test_out_of_scope_host_is_skipped_not_planned():
    scope = parse_scope(["10.10.1.5"])
    matches = [_match(host="10.10.9.9")]
    plan = build_plan(1, matches, [_sig("sig-a")], scope)
    assert plan.items == ()
    assert any("outside the currently configured scope" in s for s in plan.skipped)


def test_ruled_out_match_is_never_planned():
    scope = parse_scope(["10.10.1.5"])
    matches = [_match(status=MatchStatus.RULED_OUT)]
    plan = build_plan(1, matches, [_sig("sig-a")], scope)
    assert plan.items == ()
    assert any("ruled out" in s for s in plan.skipped)


def test_confirmed_outranks_hypothesis_of_equal_severity():
    scope = parse_scope(["10.10.1.5", "10.10.1.6"])
    confirmed = _match(host="10.10.1.5", signature_id="sig-confirmed", status=MatchStatus.CONFIRMED, confidence=0.9)
    hypothesis = _match(host="10.10.1.6", signature_id="sig-hyp", status=MatchStatus.HYPOTHESIS, confidence=0.9)
    sigs = [_sig("sig-confirmed"), _sig("sig-hyp")]
    plan = build_plan(1, [hypothesis, confirmed], sigs, scope)
    assert plan.items[0].host == "10.10.1.5"
    assert plan.items[0].source_status == "confirmed"


def test_unmapped_service_is_left_for_manual_review():
    scope = parse_scope(["10.10.1.5"])
    matches = [_match(service="telnet")]
    plan = build_plan(1, matches, [_sig("sig-a")], scope)
    assert plan.items == ()
    assert any("manual review required" in s for s in plan.skipped)


def test_ssh_smtp_mysql_services_map_to_their_audit_tools():
    scope = parse_scope(["10.10.1.5"])
    for service, expected_tool in (("ssh", "ssh_audit"), ("smtp", "smtp_audit"), ("mysql", "mysql_audit")):
        plan = build_plan(1, [_match(service=service)], [_sig("sig-a")], scope)
        assert len(plan.items) == 1
        assert plan.items[0].tool_name == expected_tool


def test_only_one_action_planned_per_endpoint():
    scope = parse_scope(["10.10.1.5"])
    m1 = _match(signature_id="sig-a", confidence=0.9)
    m2 = _match(signature_id="sig-b", confidence=0.1)
    plan = build_plan(1, [m1, m2], [_sig("sig-a"), _sig("sig-b")], scope)
    assert len(plan.items) == 1
    assert any("already covers this endpoint" in s for s in plan.skipped)


def test_manual_review_required_when_signature_has_no_automated_check():
    scope = parse_scope(["10.10.1.5"])
    matches = [_match(status=MatchStatus.CONFIRMED)]
    plan = build_plan(1, matches, [_sig("sig-a", check=None)], scope)
    assert plan.items[0].manual_review_required is True


def test_manual_review_not_required_for_confirmed_with_automated_check():
    scope = parse_scope(["10.10.1.5"])
    matches = [_match(status=MatchStatus.CONFIRMED)]
    plan = build_plan(1, matches, [_sig("sig-a", check="some_check")], scope)
    assert plan.items[0].manual_review_required is False


def test_hypothesis_is_never_described_as_confirmed():
    scope = parse_scope(["10.10.1.5"])
    matches = [_match(status=MatchStatus.HYPOTHESIS)]
    plan = build_plan(1, matches, [_sig("sig-a")], scope)
    assert plan.items[0].source_status == "hypothesis"
    assert "status=hypothesis" in plan.items[0].rationale
    assert "confirmed" not in plan.items[0].rationale


def test_planner_performs_no_network_access(monkeypatch):
    import socket

    def boom(*args, **kwargs):
        raise AssertionError("planner must never open a socket")

    monkeypatch.setattr(socket, "create_connection", boom)
    scope = parse_scope(["10.10.1.5"])
    build_plan(1, [_match()], [_sig("sig-a")], scope)
