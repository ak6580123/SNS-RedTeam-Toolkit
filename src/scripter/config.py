"""TOML configuration loading and validation (stdlib tomllib).

Unlike a typical tool that falls back to sane defaults when a config file
is missing, Scripter's active modules have no safe default scope - a
missing or empty ``[scope]`` section must fail loudly, not quietly scan
nothing or, worse, something unintended. See scope.py.
"""
from __future__ import annotations

import dataclasses
import json
import re
import tomllib
from pathlib import Path

from scripter.scope import Scope, ScopeError, parse_scope


class ConfigError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class StorageConfig:
    data_dir: Path
    reports_dir: Path
    db_path: Path


@dataclasses.dataclass(frozen=True)
class LoggingConfig:
    level: str
    log_dir: Path
    max_bytes: int
    backup_count: int


@dataclasses.dataclass(frozen=True)
class ScanConfig:
    ports: tuple[int, ...]
    timeout_seconds: float
    max_concurrency: int
    use_nmap: bool


@dataclasses.dataclass(frozen=True)
class ValidateConfig:
    enabled: bool
    timeout_seconds: float


@dataclasses.dataclass(frozen=True)
class RedTeamConfig:
    """Gates for the redteam/ planning+execution extension. ``enabled``
    only governs the master switch for the feature existing at all -
    planning, list-tools, and simulation stay available regardless of it
    (they're offline/deterministic by construction); real network audits
    and external-tool adapters each have their own, separately-gated
    flag below, matching the project's existing [validate] enabled
    pattern."""

    enabled: bool
    simulate_enabled: bool
    network_audits_enabled: bool
    external_tools_enabled: bool
    max_concurrency: int
    timeout_seconds: float
    max_response_bytes: int
    allowed_categories: tuple[str, ...]
    max_evidence_chars: int


@dataclasses.dataclass(frozen=True)
class IntelConfig:
    """Gates the only outbound call in this codebase that targets a third
    party instead of something inside ``[scope]``: looking up CVEs for an
    enumerated service/version against the public NVD CVE API (see
    ``intel/cve_lookup.py``). Off by default - the same opt-in-network
    pattern as ``[validate] enabled``/``[redteam] network_audits_enabled`` -
    so an air-gapped lab/competition network doesn't get a surprise
    external request just from opening the Findings tab or running
    ``scripter cve-lookup``.
    """

    cve_lookup_enabled: bool
    cve_lookup_timeout_seconds: float
    cve_lookup_max_results: int
    cve_lookup_max_pairs: int
    cve_lookup_delay_seconds: float
    nvd_api_key: str


@dataclasses.dataclass(frozen=True)
class Config:
    scope: Scope
    scope_allow_public: bool
    scope_max_hosts: int
    storage: StorageConfig
    logging: LoggingConfig
    scan: ScanConfig
    validate: ValidateConfig
    redteam: RedTeamConfig
    intel: IntelConfig
    path: Path


#: A broad but bounded default port list covering common CTF/lab services.
#: Operators should narrow [scan] ports in config for a specific box/OS.
DEFAULT_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
)


def _require_int(value: object, field: str, minimum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"'{field}' must be an integer, got {value!r}")
    if minimum is not None and value < minimum:
        raise ConfigError(f"'{field}' must be >= {minimum}, got {value}")
    return value


def load_config(path: Path, *, allow_empty_scope: bool = False) -> Config:
    """Load and validate the TOML config at ``path``.

    ``allow_empty_scope`` exists only for the TUI dashboard: it lets the
    app open with ``[scope] targets = []`` so the operator can set scope
    from inside the TUI (see ``tui/app.py``'s scope editor) instead of
    hand-editing the file first. Every CLI active command still loads
    with the default (``False``) and fails loudly on empty scope, per
    docs/security-model.md.
    """
    if not path.is_file():
        raise ConfigError(
            f"config file not found: {path} - copy config/config.example.toml to a config file "
            "and set [scope] targets before running any active command"
        )
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"malformed TOML in {path}: {exc}") from exc

    scope_section = raw.get("scope", {})
    targets = scope_section.get("targets", [])
    if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
        raise ConfigError("[scope] targets must be a list of strings")
    allow_public = bool(scope_section.get("allow_public", False))
    max_hosts = _require_int(scope_section.get("max_hosts", 4096), "scope.max_hosts", minimum=1)
    if not targets and allow_empty_scope:
        scope = Scope(hosts=(), raw_entries=())
    else:
        try:
            scope = parse_scope(targets, allow_public=allow_public, max_hosts=max_hosts)
        except ScopeError as exc:
            raise ConfigError(str(exc)) from exc

    storage_section = raw.get("storage", {})
    storage = StorageConfig(
        data_dir=Path(storage_section.get("data_dir", "data")),
        reports_dir=Path(storage_section.get("reports_dir", "reports")),
        db_path=Path(storage_section.get("db_path", "data/scripter.db")),
    )

    logging_section = raw.get("logging", {})
    level = str(logging_section.get("level", "INFO")).upper()
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        raise ConfigError(f"[logging] level must be one of DEBUG/INFO/WARNING/ERROR, got {level!r}")
    logging_cfg = LoggingConfig(
        level=level,
        log_dir=Path(logging_section.get("log_dir", "data/logs")),
        max_bytes=_require_int(logging_section.get("max_bytes", 5_000_000), "logging.max_bytes", minimum=1),
        backup_count=_require_int(logging_section.get("backup_count", 3), "logging.backup_count", minimum=0),
    )

    scan_section = raw.get("scan", {})
    ports_raw = scan_section.get("ports", list(DEFAULT_PORTS))
    if not isinstance(ports_raw, list) or not all(isinstance(p, int) and not isinstance(p, bool) for p in ports_raw):
        raise ConfigError("[scan] ports must be a list of integers")
    for p in ports_raw:
        if not (1 <= p <= 65535):
            raise ConfigError(f"[scan] ports entries must be 1-65535, got {p}")
    scan_cfg = ScanConfig(
        ports=tuple(ports_raw),
        timeout_seconds=float(scan_section.get("timeout_seconds", 2.0)),
        max_concurrency=_require_int(scan_section.get("max_concurrency", 50), "scan.max_concurrency", minimum=1),
        use_nmap=bool(scan_section.get("use_nmap", False)),
    )

    validate_section = raw.get("validate", {})
    validate_cfg = ValidateConfig(
        enabled=bool(validate_section.get("enabled", False)),
        timeout_seconds=float(validate_section.get("timeout_seconds", 5.0)),
    )

    redteam_section = raw.get("redteam", {})
    allowed_categories_raw = redteam_section.get(
        "allowed_categories",
        ["http", "tls", "ftp", "redis", "ssh", "smtp", "mysql", "diagnostics", "nmap", "passive"],
    )
    if not isinstance(allowed_categories_raw, list) or not all(isinstance(c, str) for c in allowed_categories_raw):
        raise ConfigError("[redteam] allowed_categories must be a list of strings")
    redteam_cfg = RedTeamConfig(
        enabled=bool(redteam_section.get("enabled", True)),
        simulate_enabled=bool(redteam_section.get("simulate_enabled", True)),
        network_audits_enabled=bool(redteam_section.get("network_audits_enabled", False)),
        external_tools_enabled=bool(redteam_section.get("external_tools_enabled", False)),
        max_concurrency=_require_int(redteam_section.get("max_concurrency", 10), "redteam.max_concurrency", minimum=1),
        timeout_seconds=float(redteam_section.get("timeout_seconds", 5.0)),
        max_response_bytes=_require_int(
            redteam_section.get("max_response_bytes", 65536), "redteam.max_response_bytes", minimum=1
        ),
        allowed_categories=tuple(allowed_categories_raw),
        max_evidence_chars=_require_int(
            redteam_section.get("max_evidence_chars", 2000), "redteam.max_evidence_chars", minimum=1
        ),
    )

    intel_section = raw.get("intel", {})
    intel_cfg = IntelConfig(
        cve_lookup_enabled=bool(intel_section.get("cve_lookup_enabled", False)),
        cve_lookup_timeout_seconds=float(intel_section.get("cve_lookup_timeout_seconds", 10.0)),
        cve_lookup_max_results=_require_int(
            intel_section.get("cve_lookup_max_results", 5), "intel.cve_lookup_max_results", minimum=1
        ),
        cve_lookup_max_pairs=_require_int(
            intel_section.get("cve_lookup_max_pairs", 15), "intel.cve_lookup_max_pairs", minimum=1
        ),
        cve_lookup_delay_seconds=float(intel_section.get("cve_lookup_delay_seconds", 6.0)),
        nvd_api_key=str(intel_section.get("nvd_api_key", "")),
    )

    return Config(
        scope=scope, scope_allow_public=allow_public, scope_max_hosts=max_hosts,
        storage=storage, logging=logging_cfg,
        scan=scan_cfg, validate=validate_cfg, redteam=redteam_cfg, intel=intel_cfg, path=path,
    )


_TARGETS_LINE_RE = re.compile(r"(?m)^(\s*targets\s*=\s*)\[[^\]]*\]")


def write_scope_targets(path: Path, targets: list[str]) -> None:
    """Rewrite just the ``[scope] targets`` line of an existing config file
    in place, leaving every other line (comments, other sections) as-is.
    Used by the TUI's scope editor so a target set entered in the dashboard
    survives a restart without hand-editing the file.
    """
    text = path.read_text(encoding="utf-8")
    rendered = "[" + ", ".join(json.dumps(t) for t in targets) + "]"
    new_text, count = _TARGETS_LINE_RE.subn(lambda m: f"{m.group(1)}{rendered}", text, count=1)
    if count == 0:
        raise ConfigError(f"could not find a 'targets = [...]' line in {path} to update")
    path.write_text(new_text, encoding="utf-8")
