"""Redis audit: passive banner read, plus (only when explicitly enabled)
the EXISTING unauthenticated-PING validation check - no new write
commands or key enumeration are added here.
"""
from __future__ import annotations

import datetime as dt

from scripter.models import Exploitability, MatchStatus, Severity, VulnMatch
from scripter.recon.enumeration import grab_banner
from scripter.redteam.results import sanitize_evidence
from scripter.scope import Scope, require_in_scope
from scripter.validation.checks import redis_unauthenticated_check


def _probe_match(host: str, port: int) -> VulnMatch:
    return VulnMatch(
        host=host, port=port, service="redis", version=None, signature_id="redteam-redis-audit-probe",
        cve_id="N/A", description="redteam redis_audit probe", severity=Severity.HIGH,
        exploitability=Exploitability.TRIVIAL, time_to_validate_minutes=5, status=MatchStatus.HYPOTHESIS,
        confidence=0.4, evidence="redteam-probe", matched_at=dt.datetime.now(dt.timezone.utc),
    )


def run(host: str, port: int, scope: Scope, timeout: float, *, run_ping_check: bool) -> str:
    require_in_scope(host, scope)
    banner = grab_banner(host, port, timeout)
    parts = [f"banner={banner[:160]!r}" if banner else "banner=<empty>"]
    if run_ping_check:
        status, confidence, note = redis_unauthenticated_check(_probe_match(host, port), scope, timeout)
        parts.append(f"unauthenticated_ping={status.value} confidence={confidence} note={note}")
    else:
        parts.append("unauthenticated_ping=skipped ([validate] enabled = false)")
    return sanitize_evidence(" | ".join(parts))
