"""Non-destructive validation checks for a subset of vuln signatures.

Every function here follows the same contract: given a VulnMatch, the
active Scope, and a socket timeout, return
``(new_status, new_confidence, evidence_note)``. None of them write data,
authenticate as a privileged user, exploit a bug, or leave anything
different on the target than before the check ran - they only observe
and report, per the "prefer non-destructive proofs of vulnerability over
payloads that modify systems" operating constraint.

Deliberately NOT implemented here: credential brute forcing, triggering
known backdoors (e.g. the vsftpd 2.3.4 smiley-face trigger, the
UnrealIRCd backdoor), or any protocol exploit that reads/writes target
memory or files. Those require case-by-case authorization review, not
blanket automation - see docs/security-model.md.
"""
from __future__ import annotations

import dataclasses
import socket
import ssl
from typing import Callable

from scripter.logging_setup import get_logger
from scripter.models import MatchStatus, VulnMatch
from scripter.scope import Scope, require_in_scope

log = get_logger("validation")

CheckResult = tuple[MatchStatus, float, str]
CheckFn = Callable[[VulnMatch, Scope, float], CheckResult]


def ftp_anonymous_login_check(match: VulnMatch, scope: Scope, timeout: float) -> CheckResult:
    """Attempt an anonymous FTP login (USER anonymous / PASS anonymous@)
    and immediately QUIT. This authenticates with the public, deliberately
    non-privileged identity the FTP protocol itself defines for this exact
    purpose; nothing is uploaded, downloaded, listed, or deleted."""
    require_in_scope(match.host, scope)
    try:
        with socket.create_connection((match.host, match.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.recv(512)  # banner
            sock.sendall(b"USER anonymous\r\n")
            sock.recv(512)
            sock.sendall(b"PASS anonymous@scripter.local\r\n")
            pass_reply = sock.recv(512).decode("utf-8", errors="replace")
            sock.sendall(b"QUIT\r\n")
            try:
                sock.recv(128)
            except (OSError, socket.timeout):
                pass
    except (OSError, socket.timeout) as exc:
        return MatchStatus.INCONCLUSIVE, match.confidence, f"check failed: could not connect/communicate: {exc}"

    if pass_reply.strip().startswith("230"):
        return MatchStatus.CONFIRMED, 0.95, f"anonymous login accepted: {pass_reply.strip()!r}"
    return MatchStatus.RULED_OUT, 0.1, f"anonymous login rejected: {pass_reply.strip()!r}"


def redis_unauthenticated_check(match: VulnMatch, scope: Scope, timeout: float) -> CheckResult:
    """Send a plain Redis ``PING`` with no AUTH. A ``+PONG`` reply proves
    the instance accepts commands without authentication. This check never
    issues a write command (SET/FLUSHALL/CONFIG/etc.)."""
    require_in_scope(match.host, scope)
    try:
        with socket.create_connection((match.host, match.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"PING\r\n")
            reply = sock.recv(256).decode("utf-8", errors="replace")
    except (OSError, socket.timeout) as exc:
        return MatchStatus.INCONCLUSIVE, match.confidence, f"check failed: could not connect/communicate: {exc}"

    upper = reply.upper()
    if "PONG" in upper:
        return MatchStatus.CONFIRMED, 0.95, f"unauthenticated PING succeeded: {reply.strip()!r}"
    if "NOAUTH" in upper or "-ERR" in upper:
        return MatchStatus.RULED_OUT, 0.1, f"server requires authentication: {reply.strip()!r}"
    return MatchStatus.INCONCLUSIVE, match.confidence, f"unexpected reply, could not determine auth state: {reply.strip()!r}"


def tls_weak_protocol_check(match: VulnMatch, scope: Scope, timeout: float) -> CheckResult:
    """Attempt a TLS handshake restricted to SSLv3/TLS1.0 only. If the
    server accepts it, that is a direct, zero-risk observation of a weak
    protocol being negotiable - a handshake reveals nothing and changes
    nothing on the target."""
    require_in_scope(match.host, scope)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.SSLv3
        ctx.maximum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        return (
            MatchStatus.INCONCLUSIVE,
            match.confidence,
            "local OpenSSL build does not support negotiating legacy TLS/SSL versions - cannot test",
        )

    try:
        with socket.create_connection((match.host, match.port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=match.host) as tls:
                version = tls.version()
    except ssl.SSLError as exc:
        return MatchStatus.RULED_OUT, 0.1, f"server rejected legacy TLS/SSL versions: {exc}"
    except (OSError, socket.timeout) as exc:
        return MatchStatus.INCONCLUSIVE, match.confidence, f"check failed: could not connect: {exc}"

    return MatchStatus.CONFIRMED, 0.9, f"server negotiated weak protocol version: {version}"


CHECKS: dict[str, CheckFn] = {
    "ftp_anonymous_login_check": ftp_anonymous_login_check,
    "redis_unauthenticated_check": redis_unauthenticated_check,
    "tls_weak_protocol_check": tls_weak_protocol_check,
}


def run_validation(
    matches: list[VulnMatch], signature_checks: dict[str, str], scope: Scope, timeout: float
) -> list[VulnMatch]:
    """For every match whose signature names a registered check, run it
    and return a new list of VulnMatch with updated status/confidence/
    evidence. Matches with no registered check are returned unchanged."""
    updated: list[VulnMatch] = []
    for match in matches:
        check_name = signature_checks.get(match.signature_id)
        check_fn = CHECKS.get(check_name) if check_name else None
        if check_fn is None:
            updated.append(match)
            continue
        try:
            status, confidence, note = check_fn(match, scope, timeout)
        except Exception as exc:  # noqa: BLE001 - a check failing must never crash the run
            log.warning("validation check %s failed for %s:%s: %s", check_name, match.host, match.port, exc)
            status, confidence, note = MatchStatus.INCONCLUSIVE, match.confidence, f"check raised an error: {exc}"
        updated.append(
            dataclasses.replace(
                match, status=status, confidence=confidence, evidence=f"{match.evidence} | validation: {note}"
            )
        )
    return updated
