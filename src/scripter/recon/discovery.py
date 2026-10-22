"""Host/port discovery across an explicitly configured scope.

Every probe is a plain TCP connect - no raw sockets, no SYN scanning, no
ICMP floods, and no retry/backoff tuning aimed at evading detection.
Concurrency is bounded (``max_concurrency``) specifically so this cannot
turn into a stress test against a competition's shared infrastructure.
"""
from __future__ import annotations

import datetime as dt
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from scripter.logging_setup import get_logger
from scripter.models import Host
from scripter.scope import Scope, require_in_scope

log = get_logger("discovery")


def probe_port(host: str, port: int, timeout: float) -> bool:
    """Pure network check: can we TCP-connect to host:port? No data is
    sent or read - this is strictly a liveness/openness probe."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _probe_job(host: str, port: int, timeout: float) -> tuple[str, int, bool]:
    return host, port, probe_port(host, port, timeout)


def discover_hosts(scope: Scope, ports: tuple[int, ...], timeout: float, max_concurrency: int) -> list[Host]:
    """Sweep every host in ``scope`` across ``ports``, bounded by
    ``max_concurrency`` concurrent connect attempts. Returns one Host per
    scope entry that answered on at least one port."""
    now = dt.datetime.now(dt.timezone.utc)
    open_ports: dict[str, list[int]] = {}

    with ThreadPoolExecutor(max_workers=max_concurrency) as pool:
        jobs = []
        for host in scope.hosts:
            require_in_scope(host, scope)
            for port in ports:
                jobs.append(pool.submit(_probe_job, host, port, timeout))

        for future in as_completed(jobs):
            host, port, is_open = future.result()
            if is_open:
                open_ports.setdefault(host, []).append(port)
                log.info("open: %s:%s", host, port)

    hosts = [
        Host(ip=host, discovered_at=now, open_ports=tuple(sorted(ports_found)))
        for host, ports_found in open_ports.items()
    ]
    hosts.sort(key=lambda h: h.ip)
    return hosts
