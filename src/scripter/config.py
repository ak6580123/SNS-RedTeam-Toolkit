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
class Config:
    scope: Scope
    scope_allow_public: bool
    scope_max_hosts: int
    storage: StorageConfig
    logging: LoggingConfig
    scan: ScanConfig
    validate: ValidateConfig
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

    return Config(
        scope=scope, scope_allow_public=allow_public, scope_max_hosts=max_hosts,
        storage=storage, logging=logging_cfg,
        scan=scan_cfg, validate=validate_cfg, path=path,
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
