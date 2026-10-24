"""Turns one AttackPlanItem into a ToolResult - the ONLY place in the
redteam extension that is allowed to touch the network or a subprocess.

Every gate here is checked in order, every failure degrades to a
structured BLOCKED/FAILED ToolResult rather than raising past the
caller, and ``simulate_only`` always wins: a simulated run never reaches
any of the network/subprocess gates below it.
"""
from __future__ import annotations

import datetime as dt

from scripter.config import Config
from scripter.logging_setup import get_logger
from scripter.redteam import registry
from scripter.redteam.models import AttackPlanItem, ExecutionStatus, ToolResult
from scripter.redteam.tools import (
    banner_probe,
    ftp_audit,
    http_audit,
    mysql_audit,
    nmap_adapter,
    redis_audit,
    simulate,
    smtp_audit,
    ssh_audit,
    tls_audit,
)
from scripter.scope import ScopeError, require_in_scope
from scripter.storage.db import Store

log = get_logger("redteam.executor")

#: tool name -> the [redteam] allowed_categories label it is gated behind.
_CATEGORY_BY_TOOL: dict[str, str] = {
    "banner_probe": "passive",
    "http_audit": "http",
    "tls_audit": "tls",
    "ftp_audit": "ftp",
    "redis_audit": "redis",
    "ssh_audit": "ssh",
    "smtp_audit": "smtp",
    "mysql_audit": "mysql",
    "nmap_adapter": "nmap",
    "diagnostics": "diagnostics",
}


class ExecutorError(RuntimeError):
    pass


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _blocked(item: AttackPlanItem, run_id: int, started: dt.datetime, reason: str) -> ToolResult:
    log.info("run=%s blocked %s against %s:%s: %s", run_id, item.tool_name, item.host, item.port, reason)
    return ToolResult(
        run_id=run_id, host=item.host, port=item.port, tool_name=item.tool_name,
        status=ExecutionStatus.BLOCKED, simulated=False, started_at=started, finished_at=_now(),
        evidence=f"blocked: {reason}", error=None,
    )


def execute_item(
    item: AttackPlanItem, cfg: Config, *, simulate_only: bool, run_id: int, store: Store | None = None
) -> ToolResult:
    registry.ensure_builtin_tools_registered()
    tool_def = registry.get_tool(item.tool_name)
    started = _now()

    if simulate_only:
        log.info("run=%s simulate %s against %s:%s", run_id, item.tool_name, item.host, item.port)
        status, evidence = simulate.run(item)
        log.info(
            "run=%s simulate %s against %s:%s -> %s: %s",
            run_id, item.tool_name, item.host, item.port, status.value, evidence,
        )
        return ToolResult(
            run_id=run_id, host=item.host, port=item.port, tool_name=item.tool_name,
            status=status, simulated=True, started_at=started, finished_at=_now(), evidence=evidence, error=None,
        )

    if tool_def.requires_network and not cfg.redteam.network_audits_enabled:
        return _blocked(item, run_id, started, "[redteam] network_audits_enabled = false")
    if tool_def.capability.value == "external_adapter" and not cfg.redteam.external_tools_enabled:
        return _blocked(item, run_id, started, "[redteam] external_tools_enabled = false")
    category = _CATEGORY_BY_TOOL.get(item.tool_name)
    if category is not None and category not in cfg.redteam.allowed_categories:
        return _blocked(item, run_id, started, f"category {category!r} not in [redteam] allowed_categories")
    if tool_def.requires_validate_enabled and not cfg.validate.enabled:
        return _blocked(item, run_id, started, f"{item.tool_name} requires [validate] enabled = true")

    try:
        require_in_scope(item.host, cfg.scope)
    except ScopeError as exc:
        return _blocked(item, run_id, started, str(exc))

    log.info("run=%s run %s against %s:%s", run_id, item.tool_name, item.host, item.port)
    try:
        evidence = _dispatch(item, cfg, store, run_id)
        status = ExecutionStatus.COMPLETED
        error = None
    except Exception as exc:  # noqa: BLE001 - a tool failing must never crash the run
        log.warning("redteam tool %s failed for %s:%s: %s", item.tool_name, item.host, item.port, exc)
        status = ExecutionStatus.FAILED
        evidence = f"tool execution failed: {exc}"
        error = str(exc)

    log.info(
        "run=%s run %s against %s:%s -> %s: %s",
        run_id, item.tool_name, item.host, item.port, status.value, evidence,
    )
    return ToolResult(
        run_id=run_id, host=item.host, port=item.port, tool_name=item.tool_name,
        status=status, simulated=False, started_at=started, finished_at=_now(), evidence=evidence, error=error,
    )


def _dispatch(item: AttackPlanItem, cfg: Config, store: Store | None, run_id: int) -> str:
    timeout = cfg.redteam.timeout_seconds
    if item.tool_name == "banner_probe":
        evidence, _service = banner_probe.run(item.host, item.port, cfg.scope, timeout)
        return evidence
    if item.tool_name == "http_audit":
        return http_audit.run(
            item.host, item.port, cfg.scope, timeout=timeout, max_response_bytes=cfg.redteam.max_response_bytes,
            use_tls=False,
        )
    if item.tool_name == "tls_audit":
        return tls_audit.run(item.host, item.port, cfg.scope, timeout)
    if item.tool_name == "ftp_audit":
        return ftp_audit.run(item.host, item.port, cfg.scope, timeout, run_anonymous_check=cfg.validate.enabled)
    if item.tool_name == "redis_audit":
        return redis_audit.run(item.host, item.port, cfg.scope, timeout, run_ping_check=cfg.validate.enabled)
    if item.tool_name == "ssh_audit":
        return ssh_audit.run(item.host, item.port, cfg.scope, timeout)
    if item.tool_name == "smtp_audit":
        return smtp_audit.run(item.host, item.port, cfg.scope, timeout)
    if item.tool_name == "mysql_audit":
        return mysql_audit.run(item.host, item.port, cfg.scope, timeout)
    if item.tool_name == "nmap_adapter":
        return nmap_adapter.run(item.host, (item.port,), cfg.scope, timeout_seconds=int(timeout) or 120)
    if item.tool_name == "diagnostics":
        if store is None:
            raise ExecutorError("diagnostics requires a Store instance")
        from scripter.redteam.tools import diagnostics

        return diagnostics.run(store, run_id, item.host, item.port)
    raise ExecutorError(f"no dispatcher registered for tool {item.tool_name!r}")
