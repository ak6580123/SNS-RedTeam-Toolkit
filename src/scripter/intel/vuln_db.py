"""Load and validate the offline vulnerability-signature dataset.

Deliberately offline (ships as a bundled JSON file, no network fetch) so
Scripter keeps working with zero connectivity during a competition. The
dataset is a small, honest starting set, not a comprehensive CVE feed -
extend ``intel/data/signatures.json`` as you learn the competition's
actual service mix.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from scripter.models import Exploitability, Severity

_DEFAULT_SIGNATURES_PATH = Path(__file__).resolve().parent / "data" / "signatures.json"

_REQUIRED_FIELDS = {
    "id", "cve", "service_pattern", "description", "severity",
    "exploitability", "time_to_validate_minutes", "confidence_base",
}


class SignatureError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class Signature:
    id: str
    cve: str
    service_pattern: str
    version_pattern: str | None
    description: str
    severity: Severity
    exploitability: Exploitability
    time_to_validate_minutes: int
    confidence_base: float
    check: str | None


def _parse_signature(raw: dict) -> Signature:
    missing = _REQUIRED_FIELDS - raw.keys()
    if missing:
        raise SignatureError(f"signature {raw.get('id', '<unknown>')!r} missing fields: {sorted(missing)}")

    try:
        severity = Severity(raw["severity"])
    except ValueError as exc:
        raise SignatureError(f"signature {raw['id']!r} has invalid severity {raw['severity']!r}") from exc
    try:
        exploitability = Exploitability(raw["exploitability"])
    except ValueError as exc:
        raise SignatureError(f"signature {raw['id']!r} has invalid exploitability {raw['exploitability']!r}") from exc

    confidence = float(raw["confidence_base"])
    if not (0.0 <= confidence <= 1.0):
        raise SignatureError(f"signature {raw['id']!r} confidence_base must be 0.0-1.0, got {confidence}")

    ttv = int(raw["time_to_validate_minutes"])
    if ttv < 0:
        raise SignatureError(f"signature {raw['id']!r} time_to_validate_minutes must be >= 0, got {ttv}")

    return Signature(
        id=raw["id"],
        cve=raw["cve"],
        service_pattern=raw["service_pattern"],
        version_pattern=raw.get("version_pattern"),
        description=raw["description"],
        severity=severity,
        exploitability=exploitability,
        time_to_validate_minutes=ttv,
        confidence_base=confidence,
        check=raw.get("check"),
    )


def load_signatures(path: Path | None = None) -> list[Signature]:
    """Load signatures from ``path``, or the bundled default dataset
    (``intel/data/signatures.json``) if ``path`` is None."""
    target = path or _DEFAULT_SIGNATURES_PATH
    if not target.is_file():
        raise SignatureError(f"signature dataset not found: {target}")
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SignatureError(f"malformed signature JSON in {target}: {exc}") from exc

    entries = raw.get("signatures", [])
    if not isinstance(entries, list):
        raise SignatureError("'signatures' must be a list")

    signatures = [_parse_signature(entry) for entry in entries]
    ids = [s.id for s in signatures]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise SignatureError(f"duplicate signature ids: {sorted(duplicates)}")
    return signatures
