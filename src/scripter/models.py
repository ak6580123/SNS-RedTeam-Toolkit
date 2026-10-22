"""Shared dataclasses for the recon -> enumeration -> vuln-map -> validate ->
prioritize -> report pipeline. Every stage reads/writes these types rather
than ad-hoc dicts, so storage and reporting have one stable shape to target.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Ordering used by prioritization scoring - higher index = more severe.
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.LOW: 1.0,
    Severity.MEDIUM: 2.5,
    Severity.HIGH: 5.0,
    Severity.CRITICAL: 8.0,
}


class MatchStatus(str, Enum):
    """How much we actually know about a candidate vulnerability.

    HYPOTHESIS: service/version string matched a signature - unverified.
    CONFIRMED: a non-destructive validation check observed the condition
      directly (e.g. anonymous FTP login succeeded, weak TLS version
      negotiated).
    RULED_OUT: a validation check ran and did *not* observe the condition -
      the signature matched on banner text alone but the live check
      disagrees (e.g. version string present but behavior patched).
    INCONCLUSIVE: no automated check exists for this signature, or the
      check could not run (host unreachable, feature disabled).
    """

    HYPOTHESIS = "hypothesis"
    CONFIRMED = "confirmed"
    RULED_OUT = "ruled_out"
    INCONCLUSIVE = "inconclusive"


class Exploitability(str, Enum):
    TRIVIAL = "trivial"
    MODERATE = "moderate"
    DIFFICULT = "difficult"


EXPLOITABILITY_WEIGHT: dict[Exploitability, float] = {
    Exploitability.TRIVIAL: 3.0,
    Exploitability.MODERATE: 1.5,
    Exploitability.DIFFICULT: 0.75,
}


@dataclasses.dataclass(frozen=True)
class Host:
    """A single scope-validated host that answered on at least one probed
    port during discovery."""

    ip: str
    discovered_at: dt.datetime
    open_ports: tuple[int, ...] = ()


@dataclasses.dataclass(frozen=True)
class ServiceFinding:
    """One enumerated service: an open port with whatever banner/version
    information a non-intrusive probe could read."""

    host: str
    port: int
    protocol: str  # "tcp"
    service: str | None
    version: str | None
    banner: str
    discovered_at: dt.datetime


@dataclasses.dataclass(frozen=True)
class VulnMatch:
    """A candidate vulnerability: a signature that matched an enumerated
    service, plus whatever validation status/evidence we have for it."""

    host: str
    port: int
    service: str
    version: str | None
    signature_id: str
    cve_id: str
    description: str
    severity: Severity
    exploitability: Exploitability
    time_to_validate_minutes: int
    status: MatchStatus
    confidence: float  # 0.0-1.0
    evidence: str
    matched_at: dt.datetime


@dataclasses.dataclass(frozen=True)
class PrioritizedFinding:
    match: VulnMatch
    score: float
    rank: int
