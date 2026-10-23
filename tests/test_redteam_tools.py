import http.server
import socket
import threading

import pytest

from scripter.models import MatchStatus
from scripter.redteam.results import sanitize_evidence
from scripter.redteam.tools import ftp_audit, http_audit, mysql_audit, nmap_adapter, redis_audit, smtp_audit, ssh_audit
from scripter.scope import ScopeError, parse_scope


class _FixedHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"x" * 20000
        self.send_response(200)
        self.send_header("Server", "TestServer/1.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - matches BaseHTTPRequestHandler signature
        pass


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://example.invalid/elsewhere")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture
def make_http_server():
    started = []

    def _make(handler_cls):
        server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        started.append((server, thread))
        return server

    yield _make
    for server, thread in started:
        server.shutdown()
        thread.join(timeout=2)


def test_http_audit_enforces_max_response_bytes(make_http_server):
    server = make_http_server(_FixedHandler)
    host, port = server.server_address
    scope = parse_scope([host])
    evidence = http_audit.run(host, port, scope, timeout=2.0, max_response_bytes=100)
    assert "body_bytes_read=100 (truncated at limit)" in evidence


def test_http_audit_reports_missing_security_headers(make_http_server):
    server = make_http_server(_FixedHandler)
    host, port = server.server_address
    scope = parse_scope([host])
    evidence = http_audit.run(host, port, scope, timeout=2.0, max_response_bytes=1000)
    assert "status=200" in evidence
    assert "Strict-Transport-Security" in evidence
    assert "TestServer/1.0" in evidence


def test_http_audit_does_not_follow_redirect(make_http_server):
    server = make_http_server(_RedirectHandler)
    host, port = server.server_address
    scope = parse_scope([host])
    evidence = http_audit.run(host, port, scope, timeout=2.0, max_response_bytes=1000)
    assert "redirect_location" in evidence
    assert "not followed automatically" in evidence


def test_http_audit_rejects_out_of_scope_host(make_http_server):
    server = make_http_server(_FixedHandler)
    host, port = server.server_address
    scope = parse_scope(["127.0.0.2"])  # deliberately does not include `host`
    with pytest.raises(ScopeError):
        http_audit.run(host, port, scope, timeout=2.0, max_response_bytes=1000)


def test_ftp_audit_skips_check_when_validate_disabled(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("anonymous-login check must not run when disabled")

    monkeypatch.setattr(ftp_audit, "ftp_anonymous_login_check", boom)
    scope = parse_scope(["127.0.0.1"])
    evidence = ftp_audit.run("127.0.0.1", 1, scope, timeout=0.2, run_anonymous_check=False)
    assert "anonymous_login=skipped" in evidence


def test_ftp_audit_reuses_existing_check_when_enabled(monkeypatch):
    calls = []

    def fake_check(match, scope, timeout):
        calls.append((match.host, match.port))
        return MatchStatus.CONFIRMED, 0.95, "fake evidence"

    monkeypatch.setattr(ftp_audit, "ftp_anonymous_login_check", fake_check)
    scope = parse_scope(["127.0.0.1"])
    evidence = ftp_audit.run("127.0.0.1", 21, scope, timeout=0.2, run_anonymous_check=True)
    assert calls == [("127.0.0.1", 21)]
    assert "anonymous_login=confirmed" in evidence


def test_redis_audit_reuses_existing_check_when_enabled(monkeypatch):
    calls = []

    def fake_check(match, scope, timeout):
        calls.append((match.host, match.port))
        return MatchStatus.RULED_OUT, 0.1, "fake evidence"

    monkeypatch.setattr(redis_audit, "redis_unauthenticated_check", fake_check)
    scope = parse_scope(["127.0.0.1"])
    evidence = redis_audit.run("127.0.0.1", 6379, scope, timeout=0.2, run_ping_check=True)
    assert calls == [("127.0.0.1", 6379)]
    assert "unauthenticated_ping=ruled_out" in evidence


def test_ssh_audit_reuses_existing_legacy_version_check(monkeypatch):
    calls = []

    def fake_check(match, scope, timeout):
        calls.append((match.host, match.port))
        return MatchStatus.CONFIRMED, 0.8, "fake evidence"

    monkeypatch.setattr(ssh_audit, "openssh_legacy_version_check", fake_check)
    scope = parse_scope(["127.0.0.1"])
    evidence = ssh_audit.run("127.0.0.1", 1, scope, timeout=0.2)
    assert calls == [("127.0.0.1", 1)]
    assert "legacy_version_check=confirmed" in evidence


def test_ssh_audit_rejects_out_of_scope_host():
    scope = parse_scope(["127.0.0.2"])
    with pytest.raises(ScopeError):
        ssh_audit.run("127.0.0.1", 22, scope, timeout=0.2)


def _tcp_server(payload: bytes, *, expect_recvs: int = 0):
    """A bare TCP server that sends ``payload`` to the first connection -
    optionally reading ``expect_recvs`` lines from the client first -
    just enough to exercise a tool's run() without a real target server."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def serve():
        conn, _ = srv.accept()
        with conn:
            if isinstance(payload, list):
                conn.sendall(payload[0])
                for chunk in payload[1:]:
                    conn.recv(1024)
                    conn.sendall(chunk)
            else:
                conn.sendall(payload)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return srv, host, port, thread


def test_smtp_audit_lists_ehlo_extensions_and_starttls():
    banner = b"220 mail.example.com ESMTP\r\n"
    ehlo = b"250-mail.example.com Hello\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 HELP\r\n"
    srv, host, port, thread = _tcp_server([banner, ehlo])
    try:
        scope = parse_scope([host])
        evidence = smtp_audit.run(host, port, scope, timeout=2.0)
        assert "starttls_offered=True" in evidence
        assert "AUTH PLAIN LOGIN" in evidence
    finally:
        thread.join(timeout=2)
        srv.close()


def test_smtp_audit_rejects_out_of_scope_host():
    scope = parse_scope(["127.0.0.2"])
    with pytest.raises(ScopeError):
        smtp_audit.run("127.0.0.1", 25, scope, timeout=0.2)


def test_mysql_audit_parses_server_version_from_handshake():
    body = bytes([0x0A]) + b"8.0.31-TestServer\x00" + b"\x00" * 10
    header = bytes([len(body) & 0xFF, (len(body) >> 8) & 0xFF, (len(body) >> 16) & 0xFF, 0])
    srv, host, port, thread = _tcp_server(header + body)
    try:
        scope = parse_scope([host])
        evidence = mysql_audit.run(host, port, scope, timeout=2.0)
        assert "server_version='8.0.31-TestServer'" in evidence
        assert "protocol_version=10" in evidence
    finally:
        thread.join(timeout=2)
        srv.close()


def test_mysql_audit_reports_unrecognized_handshake():
    srv, host, port, thread = _tcp_server(b"NOT-MYSQL-DATA")
    try:
        scope = parse_scope([host])
        evidence = mysql_audit.run(host, port, scope, timeout=2.0)
        assert "unrecognized handshake" in evidence
    finally:
        thread.join(timeout=2)
        srv.close()


def test_mysql_audit_rejects_out_of_scope_host():
    scope = parse_scope(["127.0.0.2"])
    with pytest.raises(ScopeError):
        mysql_audit.run("127.0.0.1", 3306, scope, timeout=0.2)


def test_nmap_adapter_reports_unavailable_when_nmap_missing(monkeypatch):
    monkeypatch.setattr(nmap_adapter, "nmap_available", lambda: False)
    scope = parse_scope(["127.0.0.1"])
    result = nmap_adapter.run("127.0.0.1", (80,), scope)
    assert "not found on PATH" in result


def test_nmap_adapter_delegates_to_existing_wrapper_without_new_flags(monkeypatch):
    captured = {}

    def fake_scan(host, ports, scope, timeout_seconds=120):
        captured["args"] = (host, ports, timeout_seconds)
        return {"status": "done", "output": "nmap output here", "error": ""}

    monkeypatch.setattr(nmap_adapter, "nmap_available", lambda: True)
    monkeypatch.setattr(nmap_adapter, "run_nmap_version_scan", fake_scan)
    scope = parse_scope(["127.0.0.1"])
    result = nmap_adapter.run("127.0.0.1", (80, 443), scope, timeout_seconds=30)
    assert captured["args"] == ("127.0.0.1", (80, 443), 30)
    assert "nmap output here" in result


def test_sanitize_evidence_redacts_authorization_header():
    redacted = sanitize_evidence("Authorization: Bearer super-secret-token")
    assert "super-secret-token" not in redacted
    assert "redacted" in redacted.lower()


def test_sanitize_evidence_redacts_password_field():
    redacted = sanitize_evidence("password=hunter2")
    assert "hunter2" not in redacted


def test_sanitize_evidence_truncates_long_text():
    redacted = sanitize_evidence("a" * 5000, max_chars=100)
    assert len(redacted) <= 120
    assert redacted.endswith("...<truncated>")
