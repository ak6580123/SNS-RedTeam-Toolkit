"""Bounded HTTP audit: one GET request, no automatic redirect following,
no form submission, no file upload, and a hard cap on bytes read.

Uses http.client directly (not urllib.request) specifically because
http.client never auto-follows redirects - the response, including any
Location header, is always handed back to the caller to observe, never
acted on automatically.
"""
from __future__ import annotations

import http.client
import socket

from scripter.redteam.results import sanitize_evidence
from scripter.scope import Scope, require_in_scope

_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
)
_INTERESTING_HEADERS = ("Server", "X-Powered-By", "Via")


class HttpAuditError(RuntimeError):
    pass


def run(host: str, port: int, scope: Scope, *, timeout: float, max_response_bytes: int, use_tls: bool = False) -> str:
    require_in_scope(host, scope)
    conn_cls = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
    conn = conn_cls(host, port, timeout=timeout)
    try:
        conn.request(
            "GET", "/", headers={"Host": host, "User-Agent": "scripter-redteam/0.1 (authorized-audit)"}
        )
        resp = conn.getresponse()
        body = resp.read(max_response_bytes)
        headers = dict(resp.getheaders())
        status, reason = resp.status, resp.reason
    except (OSError, socket.timeout, http.client.HTTPException) as exc:
        raise HttpAuditError(str(exc)) from exc
    finally:
        conn.close()

    truncated = len(body) >= max_response_bytes
    missing = [h for h in _SECURITY_HEADERS if h not in headers]
    present_interesting = {h: headers[h] for h in _INTERESTING_HEADERS if h in headers}
    redirect_location = headers.get("Location") if 300 <= status < 400 else None

    parts = [
        f"status={status} {reason}",
        f"missing_security_headers={missing or 'none'}",
        f"interesting_headers={present_interesting or 'none'}",
        f"body_bytes_read={len(body)}{' (truncated at limit)' if truncated else ''}",
    ]
    if redirect_location:
        parts.append(f"redirect_location={redirect_location!r} (not followed automatically)")
    return sanitize_evidence(" | ".join(parts))
