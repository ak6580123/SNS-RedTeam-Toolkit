"""Match enumerated services against the offline vulnerability signature
set.

Every match starts as ``MatchStatus.HYPOTHESIS`` - only the opt-in checks
in ``validation/checks.py`` can promote a match to CONFIRMED or RULED_OUT.
This mirrors the project's own rule for every other module: never claim
more certainty than was actually observed.
"""
from __future__ import annotations

import datetime as dt
import re

from scripter.intel.vuln_db import Signature
from scripter.models import MatchStatus, ServiceFinding, VulnMatch


def match_findings(findings: list[ServiceFinding], signatures: list[Signature]) -> list[VulnMatch]:
    now = dt.datetime.now(dt.timezone.utc)
    matches: list[VulnMatch] = []
    for finding in findings:
        if not finding.service:
            continue
        for sig in signatures:
            if not re.search(sig.service_pattern, finding.service, re.IGNORECASE):
                continue
            if sig.version_pattern is not None:
                if not finding.version or not re.search(sig.version_pattern, finding.version, re.IGNORECASE):
                    continue

            evidence = (
                f"banner: {finding.banner[:160]!r}"
                if finding.banner
                else "matched on port/service heuristic only, no banner text captured"
            )
            matches.append(
                VulnMatch(
                    host=finding.host,
                    port=finding.port,
                    service=finding.service,
                    version=finding.version,
                    signature_id=sig.id,
                    cve_id=sig.cve,
                    description=sig.description,
                    severity=sig.severity,
                    exploitability=sig.exploitability,
                    time_to_validate_minutes=sig.time_to_validate_minutes,
                    status=MatchStatus.HYPOTHESIS,
                    confidence=sig.confidence_base,
                    evidence=evidence,
                    matched_at=now,
                )
            )
    return matches
