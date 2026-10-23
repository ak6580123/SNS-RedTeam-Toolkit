"""MySQL audit: passive read of the initial handshake packet a MySQL
(protocol 10) server sends unprompted on connect - it contains the
server's version string in plain text. No login is attempted, no
credentials are sent, no query runs; the connection is simply read
from once and closed.
"""
from __future__ import annotations

import socket

from scripter.redteam.results import sanitize_evidence
from scripter.scope import Scope, require_in_scope

_READ_BUFFER = 512
_PROTOCOL_VERSION_10 = 0x0A


def run(host: str, port: int, scope: Scope, timeout: float) -> str:
    require_in_scope(host, scope)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(_READ_BUFFER)
    except (OSError, socket.timeout) as exc:
        return sanitize_evidence(f"no response: {exc}")

    if len(data) < 6 or data[4] != _PROTOCOL_VERSION_10:
        return sanitize_evidence(
            f"unrecognized handshake (first_bytes={data[:16]!r}) - not a standard MySQL protocol-10 greeting"
        )

    terminator = data.find(b"\x00", 5)
    server_version = data[5:terminator].decode("utf-8", errors="replace") if terminator != -1 else "<could not parse>"
    return sanitize_evidence(
        f"protocol_version={data[4]} server_version={server_version!r} raw_bytes_read={len(data)}"
    )
