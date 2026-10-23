"""Deterministic, offline attack planner.

build_plan() performs no network access and no I/O beyond reading the
VulnMatch list and Signature dataset already passed in - it only decides
*what could be done*, never does it. Only redteam.executor (via the CLI's
``redteam simulate``/``redteam audit-*`` commands or the TUI) ever turns a
plan item into a ToolResult.
"""
from __future__ import annotations

import datetime as dt

from scripter.intel.vuln_db import Signature
from scripter.models import MatchStatus, VulnMatch
from scripter.prioritize import prioritize as prioritize_matches
from scripter.redteam.models import AttackPlan, AttackPlanItem
from scripter.scope import Scope

#: service (as recorded on ServiceFinding/VulnMatch) -> the one redteam
#: tool that can audit it. Deliberately conservative and 1:1 - anything
#: not listed here has no automated tool and is left for manual review.
_SERVICE_TOOL_MAP: dict[str, str] = {
    "http": "http_audit",
    "http-alt": "http_audit",
    "https": "tls_audit",
    "https-alt": "tls_audit",
    "ftp": "ftp_audit",
    "redis": "redis_audit",
    "ssh": "ssh_audit",
    "smtp": "smtp_audit",
    "mysql": "mysql_audit",
}

#: Tools whose audit includes the existing opt-in validation checks
#: (ftp_anonymous_login_check / redis_unauthenticated_check), which only
#: ever run when [validate] enabled = true - surfaced here so a plan item
#: honestly states that prerequisite up front.
_REQUIRES_VALIDATE_ENABLED = {"ftp_audit", "redis_audit"}


def build_plan(run_id: int, matches: list[VulnMatch], signatures: list[Signature], scope: Scope) -> AttackPlan:
    """Deterministic: identical ``matches``/``signatures``/``scope`` always
    produce an identical plan (same items in the same order, same skip
    reasons). Ranking reuses ``prioritize.prioritize`` - the exact same
    severity x confidence x exploitability / effort scoring the ``report``
    command already uses - so a CONFIRMED match outranks a HYPOTHESIS one
    of equal severity without the planner reimplementing that logic.
    """
    has_check = {s.id: bool(s.check) for s in signatures}
    ranked = prioritize_matches(matches)

    items: list[AttackPlanItem] = []
    skipped: list[str] = []
    planned_endpoints: set[tuple[str, int]] = set()

    for pf in ranked:
        m = pf.match
        label = f"{m.host}:{m.port} ({m.signature_id})"

        if m.host not in scope.hosts:
            skipped.append(f"{label}: host is outside the currently configured scope - no action planned")
            continue
        if m.status == MatchStatus.RULED_OUT:
            skipped.append(f"{label}: signature was ruled out by validation - no action planned")
            continue
        if (m.host, m.port) in planned_endpoints:
            skipped.append(f"{label}: a higher-ranked finding on {m.host}:{m.port} already covers this endpoint")
            continue

        tool_name = _SERVICE_TOOL_MAP.get(m.service)
        if tool_name is None:
            skipped.append(f"{label}: no red-team tool is mapped to service {m.service!r} - manual review required")
            continue

        # A match is never described as more than it is: HYPOTHESIS/
        # INCONCLUSIVE status, or a signature with no automated check at
        # all, both mean a human still has to confirm this by hand even
        # after the audit tool runs.
        manual_review_required = m.status != MatchStatus.CONFIRMED or not has_check.get(m.signature_id, False)
        prerequisites = ("[validate] enabled = true",) if tool_name in _REQUIRES_VALIDATE_ENABLED else ()
        rationale = (
            f"rank {pf.rank} (score {pf.score}) - status={m.status.value}, severity={m.severity.value}, "
            f"confidence={m.confidence:.2f}: {m.description}"
        )

        items.append(
            AttackPlanItem(
                host=m.host,
                port=m.port,
                service=m.service,
                signature_id=m.signature_id,
                tool_name=tool_name,
                rationale=rationale,
                prerequisites=prerequisites,
                planned_action=f"run {tool_name} against {m.host}:{m.port}",
                manual_review_required=manual_review_required,
                source_status=m.status.value,
                source_score=pf.score,
            )
        )
        planned_endpoints.add((m.host, m.port))

    return AttackPlan(
        run_id=run_id,
        created_at=dt.datetime.now(dt.timezone.utc),
        items=tuple(items),
        skipped=tuple(skipped),
    )
