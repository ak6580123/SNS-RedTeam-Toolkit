"""Shared dataclasses for the red-team planning/execution extension.

Mirrors the base pipeline's own models.py convention: frozen dataclasses,
str Enums, no plaintext secrets ever stored on a result (see
redteam/results.py's sanitize_evidence, which every tool module routes
its evidence string through before it reaches these models).
"""
from __future__ import annotations

import dataclasses
import datetime as dt
from enum import Enum


class RiskLevel(str, Enum):
    PASSIVE = "passive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ToolCapability(str, Enum):
    PASSIVE_PROBE = "passive_probe"
    NON_AUTHENTICATING_PROBE = "non_authenticating_probe"
    AUTHENTICATED_AUDIT = "authenticated_audit"
    EXTERNAL_ADAPTER = "external_adapter"


class ExecutionStatus(str, Enum):
    PLANNED = "planned"
    SKIPPED = "skipped"
    SIMULATED = "simulated"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"


@dataclasses.dataclass(frozen=True)
class ToolDefinition:
    """A registered red-team tool's static metadata - never the tool's
    implementation itself (that lives in redteam/tools/*.py and is looked
    up by name in redteam/executor.py)."""

    name: str
    description: str
    protocols: tuple[str, ...]
    required_inputs: tuple[str, ...]
    capability: ToolCapability
    risk: RiskLevel
    requires_network: bool
    requires_validate_enabled: bool = False
    enabled_by_default: bool = True


@dataclasses.dataclass(frozen=True)
class AttackPlanItem:
    """One planned action: a single tool against a single host:port,
    produced by redteam.planner.build_plan from an existing VulnMatch.
    Never implies the action has run - see ExecutionStatus/ToolResult for
    that."""

    host: str
    port: int
    service: str
    signature_id: str
    tool_name: str
    rationale: str
    prerequisites: tuple[str, ...]
    planned_action: str
    manual_review_required: bool
    source_status: str
    source_score: float


@dataclasses.dataclass(frozen=True)
class AttackPlan:
    run_id: int
    created_at: dt.datetime
    items: tuple[AttackPlanItem, ...]
    #: Human-readable reasons a candidate finding did NOT become a plan
    #: item (out of scope, ruled out, no tool mapped, already covered by a
    #: higher-ranked finding on the same host:port) - kept for auditability,
    #: never silently dropped.
    skipped: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class ToolResult:
    """The outcome of actually running (or simulating) one AttackPlanItem.
    ``simulated=True`` must never be reported as a real finding - every
    reporter/consumer of this type has to surface that flag."""

    run_id: int
    host: str
    port: int
    tool_name: str
    status: ExecutionStatus
    simulated: bool
    started_at: dt.datetime
    finished_at: dt.datetime
    evidence: str
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class RedTeamEvent:
    """Stable, documented event shape for future blue/purple-team
    correlation (see docs/architecture.md). Derived from a ToolResult via
    redteam.results.to_event - never constructed by hand elsewhere."""

    event_id: str
    run_id: int
    timestamp: dt.datetime
    target: str
    tool_name: str
    action_category: str
    outcome: str
    evidence: str
    scope_decision: str
    simulated: bool
