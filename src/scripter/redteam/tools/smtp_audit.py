"""SMTP audit: one benign EHLO (no authentication, no VRFY/EXPN user
enumeration, no mail actually sent), then QUIT. Only lists the
extensions/mechanisms the server itself advertises - the same
"one non-authenticating protocol command, read the reply" shape as
http_audit's single GET.
"""
from __future__ import annotations

import socket

from scripter.redteam.results import sanitize_evidence
from scripter.scope import Scope, require_in_scope

_READ_BUFFER = 2048


class SmtpAuditError(RuntimeError):
    pass


def _extensions(ehlo_reply: str) -> list[str]:
    # RFC 5321 multiline reply: "250-TEXT" for every line but the last,
    # "250 TEXT" for the last - strip the 3-digit code and separator only.
    return [line[4:].strip() for line in ehlo_reply.splitlines() if len(line) > 3 and line[:3].isdigit()]


def run(host: str, port: int, scope: Scope, timeout: float) -> str:
    require_in_scope(host, scope)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(_READ_BUFFER).decode("utf-8", errors="replace").strip()
            sock.sendall(b"EHLO scripter.local\r\n")
            ehlo_reply = sock.recv(_READ_BUFFER).decode("utf-8", errors="replace").strip()
            sock.sendall(b"QUIT\r\n")
            try:
                sock.recv(128)
            except (OSError, socket.timeout):
                pass
    except (OSError, socket.timeout) as exc:
        raise SmtpAuditError(str(exc)) from exc

    extensions = _extensions(ehlo_reply)
    starttls_offered = any(e.upper() == "STARTTLS" for e in extensions)
    auth_line = next((e for e in extensions if e.upper().startswith("AUTH")), None)
    parts = [
        f"banner={banner[:160]!r}" if banner else "banner=<empty>",
        f"ehlo_extensions={extensions or '<none>'}",
        f"starttls_offered={starttls_offered}",
        f"auth_mechanisms={auth_line or 'none advertised'}",
    ]
    return sanitize_evidence(" | ".join(parts))
