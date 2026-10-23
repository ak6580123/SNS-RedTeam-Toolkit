"""Passive banner re-read for a host:port recon already found open.

Thin wrapper over the existing recon.enumeration functions - no new
network logic is introduced here.
"""
from __future__ import annotations

from scripter.recon.enumeration import grab_banner, parse_service
from scripter.scope import Scope, require_in_scope


def run(host: str, port: int, scope: Scope, timeout: float) -> tuple[str, str]:
    """Returns (evidence, service_guess)."""
    require_in_scope(host, scope)
    banner = grab_banner(host, port, timeout)
    service, version = parse_service(port, banner)
    evidence = f"service={service or 'unknown'} version={version or 'unknown'} banner={banner[:160]!r}"
    return evidence, (service or "unknown")
