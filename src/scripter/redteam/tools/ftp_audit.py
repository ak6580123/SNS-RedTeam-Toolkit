"""FTP audit: passive banner read, plus (only when explicitly enabled)
the EXISTING anonymous-login validation check - no new authentication
logic is added here.
"""
from __future__ import annotations

import datetime as dt

from scripter.models import Exploitability, MatchStatus, Severity, VulnMatch
from scripter.recon.enumeration import grab_banner
from scripter.redteam.results import sanitize_evidence
from scripter.scope import Scope, require_in_scope
from scripter.validation.checks import ftp_anonymous_login_check


def _probe_match(host: str, port: int) -> VulnMatch:
    return VulnMatch(
        host=host, port=port, service="ftp", version=None, signature_id="redteam-ftp-audit-probe",
        cve_id="N/A", description="redteam ftp_audit probe", severity=Severity.MEDIUM,
        exploitability=Exploitability.TRIVIAL, time_to_validate_minutes=2, status=MatchStatus.HYPOTHESIS,
        confidence=0.3, evidence="redteam-probe", matched_at=dt.datetime.now(dt.timezone.utc),
    )


def run(host: str, port: int, scope: Scope, timeout: float, *, run_anonymous_check: bool) -> str:
    require_in_scope(host, scope)
    banner = grab_banner(host, port, timeout)
    parts = [f"banner={banner[:160]!r}" if banner else "banner=<empty>"]
    if run_anonymous_check:
        status, confidence, note = ftp_anonymous_login_check(_probe_match(host, port), scope, timeout)
        parts.append(f"anonymous_login={status.value} confidence={confidence} note={note}")
    else:
        parts.append("anonymous_login=skipped ([validate] enabled = false)")
    return sanitize_evidence(" | ".join(parts))
