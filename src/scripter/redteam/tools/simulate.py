"""Deterministic offline mock executor.

Never touches the network. The same AttackPlanItem always produces the
same simulated outcome (a stable hash of its identifying fields selects
one of four fixed outcomes) - this is what makes most of the red-team
workflow testable without any live target, and what Section 11's
"reproducible test fixtures" requirement refers to.
"""
from __future__ import annotations

import hashlib

from scripter.redteam.models import AttackPlanItem, ExecutionStatus

_OUTCOMES: tuple[tuple[ExecutionStatus, str], ...] = (
    (ExecutionStatus.COMPLETED, "simulated audit completed - mock evidence collected, no real target contacted"),
    (ExecutionStatus.FAILED, "simulated audit failed - mock timeout/connection-refused outcome"),
    (ExecutionStatus.BLOCKED, "simulated audit blocked - mock policy/scope rejection outcome"),
    (ExecutionStatus.INCONCLUSIVE, "simulated audit inconclusive - mock ambiguous-response outcome"),
)


def run(item: AttackPlanItem) -> tuple[ExecutionStatus, str]:
    digest = hashlib.sha256(f"{item.host}:{item.port}:{item.tool_name}:{item.signature_id}".encode()).digest()
    status, note = _OUTCOMES[digest[0] % len(_OUTCOMES)]
    return status, f"SIMULATED: {note}"
