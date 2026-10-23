"""SSH audit: passive re-read of the unprompted protocol identification
string every SSH server sends before any key exchange (RFC 4253), plus
the existing openssh_legacy_version_check - no key exchange, no
authentication, nothing beyond what the server volunteers on connect.
"""
from __future__ import annotations

import datetime as dt

from scripter.models import Exploitability, MatchStatus, Severity, VulnMatch
from scripter.recon.enumeration import grab_banner
from scripter.redteam.results import sanitize_evidence
from scripter.scope import Scope, require_in_scope
from scripter.validation.checks import openssh_legacy_version_check


def _probe_match(host: str, port: int) -> VulnMatch:
    return VulnMatch(
        host=host, port=port, service="ssh", version=None, signature_id="redteam-ssh-audit-probe",
        cve_id="N/A", description="redteam ssh_audit probe", severity=Severity.MEDIUM,
        exploitability=Exploitability.MODERATE, time_to_validate_minutes=2, status=MatchStatus.HYPOTHESIS,
        confidence=0.3, evidence="redteam-probe", matched_at=dt.datetime.now(dt.timezone.utc),
    )


def run(host: str, port: int, scope: Scope, timeout: float) -> str:
    require_in_scope(host, scope)
    banner = grab_banner(host, port, timeout)
    status, confidence, note = openssh_legacy_version_check(_probe_match(host, port), scope, timeout)
    parts = [
        f"banner={banner[:160]!r}" if banner else "banner=<empty>",
        f"legacy_version_check={status.value} confidence={confidence} note={note}",
    ]
    return sanitize_evidence(" | ".join(parts))
