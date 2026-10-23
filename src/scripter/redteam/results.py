"""Evidence sanitization and the ToolResult -> RedTeamEvent mapping.

Every tool module in redteam/tools/ routes its evidence string through
sanitize_evidence before returning it, so no plaintext credential,
Authorization header, or session cookie can ever reach storage or a
report, and no evidence string can grow unbounded.
"""
from __future__ import annotations

import re
import uuid

from scripter.redteam.models import RedTeamEvent, ToolResult

_DEFAULT_MAX_EVIDENCE_CHARS = 2000

#: (pattern, replacement) pairs applied in order. Each replacement keeps
#: the matched key name (via a backreference) but redacts the value, so
#: evidence stays readable ("authorization=<redacted>") without ever
#: retaining the secret itself.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b(authorization)\s*:\s*[^|]+"), r"\1=<redacted>"),
    (re.compile(r"(?i)\b(set-cookie)\s*:\s*[^|]+"), r"\1=<redacted>"),
    (re.compile(r"(?i)\b(password|passwd|pwd|api[_-]?key|token|secret)\s*=\s*\S+"), r"\1=<redacted>"),
)


def sanitize_evidence(text: str, max_chars: int = _DEFAULT_MAX_EVIDENCE_CHARS) -> str:
    """Redact common secret-bearing patterns and bound the string's length
    before it is stored or reported."""
    redacted = text
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    if len(redacted) > max_chars:
        redacted = redacted[:max_chars] + "...<truncated>"
    return redacted


def to_event(result: ToolResult, *, scope_decision: str, action_category: str) -> RedTeamEvent:
    """Project a ToolResult into the stable event shape documented in
    docs/architecture.md, for future blue/purple-team correlation."""
    return RedTeamEvent(
        event_id=str(uuid.uuid4()),
        run_id=result.run_id,
        timestamp=result.finished_at,
        target=f"{result.host}:{result.port}",
        tool_name=result.tool_name,
        action_category=action_category,
        outcome=result.status.value,
        evidence=result.evidence,
        scope_decision=scope_decision,
        simulated=result.simulated,
    )
