import datetime as dt
import socket
import threading

from scripter.models import Exploitability, MatchStatus, Severity, VulnMatch
from scripter.scope import parse_scope
from scripter.validation.checks import CHECKS, openssh_legacy_version_check, run_validation


def _match(signature_id="sig", service="ftp", port=21, host="10.10.1.5"):
    return VulnMatch(
        host=host, port=port, service=service, version=None, signature_id=signature_id,
        cve_id="CVE-TEST", description="test", severity=Severity.HIGH, exploitability=Exploitability.TRIVIAL,
        time_to_validate_minutes=5, status=MatchStatus.HYPOTHESIS, confidence=0.3, evidence="banner",
        matched_at=dt.datetime.now(dt.timezone.utc),
    )


def test_registered_checks_are_exactly_the_four_documented():
    assert set(CHECKS) == {
        "ftp_anonymous_login_check",
        "redis_unauthenticated_check",
        "tls_weak_protocol_check",
        "openssh_legacy_version_check",
    }


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


def _banner_server(banner: bytes):
    """A bare TCP server that sends ``banner`` to the first connection and
    closes - just enough to exercise a passive banner-read check without
    a real SSH server."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def serve():
        conn, _ = srv.accept()
        with conn:
            conn.sendall(banner)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return srv, host, port, thread


def test_openssh_legacy_version_check_confirms_legacy_banner():
    srv, host, port, thread = _banner_server(b"SSH-2.0-OpenSSH_4.3\r\n")
    try:
        scope = parse_scope([host])
        status, _confidence, note = openssh_legacy_version_check(
            _match(service="ssh", port=port, host=host), scope, timeout=2.0
        )
        assert status == MatchStatus.CONFIRMED
        assert "legacy" in note.lower()
    finally:
        thread.join(timeout=2)
        srv.close()


def test_openssh_legacy_version_check_rules_out_current_banner():
    srv, host, port, thread = _banner_server(b"SSH-2.0-OpenSSH_9.6\r\n")
    try:
        scope = parse_scope([host])
        status, _confidence, _note = openssh_legacy_version_check(
            _match(service="ssh", port=port, host=host), scope, timeout=2.0
        )
        assert status == MatchStatus.RULED_OUT
    finally:
        thread.join(timeout=2)
        srv.close()


def test_openssh_legacy_version_check_inconclusive_for_non_ssh_banner():
    srv, host, port, thread = _banner_server(b"220 not-an-ssh-server\r\n")
    try:
        scope = parse_scope([host])
        status, _confidence, note = openssh_legacy_version_check(
            _match(service="ssh", port=port, host=host), scope, timeout=2.0
        )
        assert status == MatchStatus.INCONCLUSIVE
        assert "no SSH identification string" in note
    finally:
        thread.join(timeout=2)
        srv.close()
