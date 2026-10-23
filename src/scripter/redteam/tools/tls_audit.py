"""TLS certificate/protocol metadata audit.

Uses a normal, certificate-verifying handshake (ssl.create_default_context,
hostname checking on) for the metadata read - certificate verification is
never disabled here. The existing SSLv3/TLS1.0-only weak-protocol check
(validation/checks.py's tls_weak_protocol_check, which intentionally does
disable verification for that one diagnostic connection) is reused
as-is and only invoked when the caller explicitly opts in by passing a
VulnMatch for it - no new weak-protocol logic is added here.
"""
from __future__ import annotations

import datetime as dt
import socket
import ssl

from scripter.models import VulnMatch
from scripter.redteam.results import sanitize_evidence
from scripter.scope import Scope, require_in_scope
from scripter.validation.checks import tls_weak_protocol_check


class TlsAuditError(RuntimeError):
    pass


def _cert_expired(not_after: str | None) -> bool | None:
    if not not_after:
        return None
    try:
        expiry = dt.datetime.strptime(not_after.replace(" GMT", ""), "%b %d %H:%M:%S %Y")
    except ValueError:
        return None
    return expiry < dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def run(
    host: str, port: int, scope: Scope, timeout: float, *, weak_protocol_match: VulnMatch | None = None
) -> str:
    require_in_scope(host, scope)
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
                cipher = tls.cipher()
    except ssl.SSLCertVerificationError as exc:
        return sanitize_evidence(f"certificate verification failed (hostname/trust): {exc}")
    except (OSError, socket.timeout, ssl.SSLError) as exc:
        raise TlsAuditError(str(exc)) from exc

    not_after = cert.get("notAfter") if cert else None
    parts = [
        f"negotiated_protocol={version}",
        f"cipher={cipher[0] if cipher else 'unknown'}",
        f"cert_subject={cert.get('subject') if cert else None}",
        f"cert_not_after={not_after}",
        f"cert_expired={_cert_expired(not_after)}",
    ]
    if weak_protocol_match is not None:
        status, confidence, note = tls_weak_protocol_check(weak_protocol_match, scope, timeout)
        parts.append(f"weak_protocol_check={status.value} confidence={confidence} note={note}")
    return sanitize_evidence(" | ".join(parts))
