"""Scripter CLI: discover -> enumerate -> vuln-map -> validate -> report,
one Typer sub-command per stage, plus a run-all convenience pipeline.

Every active command loads its scope from an explicit config file (see
scope.py/config.py) - there is no default target and no command will act
without one. Exit codes follow the project convention: 0 ok, 1 error,
2 usage/config error.
"""
from __future__ import annotations

import datetime as dt
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from scripter import __version__
from scripter.config import Config, ConfigError, load_config
from scripter.intel.cve_lookup import CveLookupError, lookup_cves
from scripter.intel.matcher import match_findings
from scripter.intel.vuln_db import SignatureError, load_signatures
from scripter.logging_setup import configure_logging, get_logger
from scripter.models import MatchStatus
from scripter.prioritize import prioritize as prioritize_matches
from scripter.recon.discovery import discover_hosts
from scripter.recon.enumeration import enumerate_services, nmap_available, run_nmap_version_scan
from scripter.redteam import registry
from scripter.redteam.executor import execute_item
from scripter.redteam.models import AttackPlanItem, ExecutionStatus
from scripter.redteam.planner import build_plan
from scripter.redteam.storage import RedTeamStore
from scripter.reporting.report import (
    write_csv,
    write_html,
    write_json,
    write_redteam_csv,
    write_redteam_html,
    write_redteam_json,
)
from scripter.scope import ScopeError, require_in_scope
from scripter.storage.db import Store
from scripter.validation.checks import run_validation

app = typer.Typer(help="Authorized red-team recon/enumeration/vuln-mapping toolkit for A/D CTF competitions.")
redteam_app = typer.Typer(
    help="Offline attack planning, deterministic simulation, and bounded scope-gated audit tools."
)
app.add_typer(redteam_app, name="redteam")
console = Console()
log = get_logger("cli")

_DEFAULT_CONFIG_PATH = Path("config/config.toml")
ConfigOption = typer.Option(_DEFAULT_CONFIG_PATH, "--config", "-c", help="Path to the TOML config file.")


def _load(config_path: Path, *, allow_empty_scope: bool = False) -> Config:
    try:
        cfg = load_config(config_path, allow_empty_scope=allow_empty_scope)
    except ConfigError as exc:
        console.print(f"[red]config error:[/red] {escape(str(exc))}")
        raise typer.Exit(code=2)
    configure_logging(cfg.logging.log_dir, cfg.logging.level, cfg.logging.max_bytes, cfg.logging.backup_count)
    return cfg


def _stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%dT%H%M%S")


def _write_reports(findings, reports_dir: Path, run_id: int, formats: str) -> list[Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    written: list[Path] = []
    for fmt in {f.strip().lower() for f in formats.split(",") if f.strip()}:
        if fmt == "json":
            written.append(write_json(findings, reports_dir / f"run{run_id}_{stamp}.json"))
        elif fmt == "csv":
            written.append(write_csv(findings, reports_dir / f"run{run_id}_{stamp}.csv"))
        elif fmt == "html":
            written.append(
                write_html(findings, reports_dir / f"run{run_id}_{stamp}.html", title=f"Scripter findings - run {run_id}")
            )
        else:
            console.print(f"[yellow]unknown report format '{fmt}' - skipped[/yellow]")
    return written


def _write_redteam_reports(results, reports_dir: Path, run_id: int, formats: str) -> list[Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    written: list[Path] = []
    for fmt in {f.strip().lower() for f in formats.split(",") if f.strip()}:
        if fmt == "json":
            written.append(write_redteam_json(results, reports_dir / f"redteam_run{run_id}_{stamp}.json"))
        elif fmt == "csv":
            written.append(write_redteam_csv(results, reports_dir / f"redteam_run{run_id}_{stamp}.csv"))
        elif fmt == "html":
            written.append(
                write_redteam_html(
                    results, reports_dir / f"redteam_run{run_id}_{stamp}.html",
                    title=f"Scripter red-team results - run {run_id}",
                )
            )
    return written


@app.callback()
def _main(
    version: bool = typer.Option(False, "--version", help="Print the version and exit.", is_eager=True),
) -> None:
    if version:
        console.print(f"scripter {__version__}")
        raise typer.Exit()


@app.command()
def tui(config: Path = ConfigOption) -> None:
    """Launch the interactive TUI dashboard (same pipeline, nicer view)."""
    cfg = _load(config, allow_empty_scope=True)
    from scripter.tui.app import ScripterApp

    ScripterApp(cfg, config).run()


@app.command()
def doctor(config: Path = ConfigOption) -> None:
    """Report what this environment and config will actually let you do."""
    console.print(f"[bold]scripter[/bold] {__version__}")
    console.print(f"nmap on PATH: {'yes' if nmap_available() else 'no'}")
    if not config.is_file():
        console.print(f"[yellow]no config at {escape(str(config))}[/yellow] - copy config/config.example.toml and set \\[scope] targets")
        raise typer.Exit(code=2)
    try:
        cfg = load_config(config)
    except ConfigError as exc:
        console.print(f"[red]config error:[/red] {escape(str(exc))}")
        raise typer.Exit(code=2)
    console.print(f"scope: {len(cfg.scope.hosts)} host(s) - {', '.join(cfg.scope.raw_entries)}")
    console.print(f"scan ports configured: {len(cfg.scan.ports)}")
    console.print(f"use_nmap: {cfg.scan.use_nmap}")
    console.print(f"validate enabled: {cfg.validate.enabled}")
    console.print("config OK")


@app.command()
def discover(config: Path = ConfigOption) -> None:
    """Sweep the configured scope for live hosts/open ports (TCP connect only, no raw sockets)."""
    cfg = _load(config)
    with Store(cfg.storage.db_path) as store:
        run_id = store.start_run(str(config))
        hosts = discover_hosts(cfg.scope, cfg.scan.ports, cfg.scan.timeout_seconds, cfg.scan.max_concurrency)
        store.save_hosts(run_id, hosts)

    table = Table(title=f"Discovery - run {run_id}")
    table.add_column("Host")
    table.add_column("Open ports")
    for h in hosts:
        table.add_row(h.ip, ", ".join(str(p) for p in h.open_ports))
    console.print(table)
    if not hosts:
        console.print("[yellow]no live hosts found in scope[/yellow]")


@app.command(name="enumerate")
def enumerate_cmd(
    config: Path = ConfigOption,
    run_id: Optional[int] = typer.Option(None, help="Run to enumerate (defaults to the latest run)."),
    use_nmap: Optional[bool] = typer.Option(None, help="Override [scan] use_nmap for this invocation."),
) -> None:
    """Grab banners / lightweight version info for every open port discover found."""
    cfg = _load(config)
    with Store(cfg.storage.db_path) as store:
        rid = run_id or store.latest_run_id()
        if rid is None:
            console.print("[red]no run found - run 'scripter discover' first[/red]")
            raise typer.Exit(code=1)
        hosts = store.load_hosts(rid)
        if not hosts:
            console.print("[yellow]no hosts recorded for this run[/yellow]")
            raise typer.Exit(code=0)

        hosts_with_ports = {h.ip: h.open_ports for h in hosts}
        findings = enumerate_services(cfg.scope, hosts_with_ports, cfg.scan.timeout_seconds)

        effective_use_nmap = cfg.scan.use_nmap if use_nmap is None else use_nmap
        if effective_use_nmap:
            for h in hosts:
                result = run_nmap_version_scan(h.ip, h.open_ports, cfg.scope)
                if result["status"] == "done":
                    log.info("nmap -sV for %s:\n%s", h.ip, result["output"])
                elif result["status"] != "unsupported":
                    log.warning("nmap -sV for %s failed: %s", h.ip, result["error"])

        store.save_services(rid, findings)

    table = Table(title=f"Enumeration - run {rid}")
    table.add_column("Host")
    table.add_column("Port")
    table.add_column("Service")
    table.add_column("Version")
    for f in findings:
        table.add_row(f.host, str(f.port), f.service or "-", f.version or "-")
    console.print(table)


@app.command(name="vuln-map")
def vuln_map(
    config: Path = ConfigOption,
    run_id: Optional[int] = typer.Option(None, help="Run to map (defaults to the latest run)."),
    signatures_path: Optional[Path] = typer.Option(None, "--signatures", help="Override the bundled signature dataset."),
) -> None:
    """Match enumerated services against the offline vulnerability-signature dataset."""
    cfg = _load(config)
    try:
        signatures = load_signatures(signatures_path)
    except SignatureError as exc:
        console.print(f"[red]signature dataset error:[/red] {escape(str(exc))}")
        raise typer.Exit(code=2)

    with Store(cfg.storage.db_path) as store:
        rid = run_id or store.latest_run_id()
        if rid is None:
            console.print("[red]no run found - run 'scripter discover' and 'scripter enumerate' first[/red]")
            raise typer.Exit(code=1)
        findings = store.load_services(rid)
        matches = match_findings(findings, signatures)
        store.clear_matches_for_run(rid)
        store.save_matches(rid, matches)

    console.print(f"{len(matches)} candidate match(es) found for run {rid} (status=hypothesis until validated)")


@app.command()
def validate(
    config: Path = ConfigOption,
    run_id: Optional[int] = typer.Option(None, help="Run to validate (defaults to the latest run)."),
    signatures_path: Optional[Path] = typer.Option(None, "--signatures", help="Override the bundled signature dataset."),
) -> None:
    """Run non-destructive validation checks for matches whose signature has one registered."""
    cfg = _load(config)
    if not cfg.validate.enabled:
        console.print("[yellow]\\[validate] enabled = false in config - refusing to run active validation checks[/yellow]")
        raise typer.Exit(code=2)
    try:
        signatures = load_signatures(signatures_path)
    except SignatureError as exc:
        console.print(f"[red]signature dataset error:[/red] {escape(str(exc))}")
        raise typer.Exit(code=2)
    signature_checks = {s.id: s.check for s in signatures if s.check}

    with Store(cfg.storage.db_path) as store:
        rid = run_id or store.latest_run_id()
        if rid is None:
            console.print("[red]no run found - run discover/enumerate/vuln-map first[/red]")
            raise typer.Exit(code=1)
        matches = store.load_matches(rid)
        if not matches:
            console.print("[yellow]no candidate matches recorded - run 'scripter vuln-map' first[/yellow]")
            raise typer.Exit(code=0)
        updated = run_validation(matches, signature_checks, cfg.scope, cfg.validate.timeout_seconds)
        store.clear_matches_for_run(rid)
        store.save_matches(rid, updated)

    confirmed = sum(1 for m in updated if m.status.value == "confirmed")
    console.print(f"validated {len(updated)} match(es) for run {rid} - {confirmed} confirmed")


@app.command()
def report(
    config: Path = ConfigOption,
    run_id: Optional[int] = typer.Option(None, help="Run to report on (defaults to the latest run)."),
    formats: str = typer.Option("json,csv", help="Comma-separated: json,csv,html"),
    out_dir: Optional[Path] = typer.Option(None, help="Override [storage] reports_dir for this invocation."),
    redteam: bool = typer.Option(
        False, "--redteam", help="Also write redteam_* reports for this run's saved plan/execution results."
    ),
) -> None:
    """Generate ranked, machine-readable findings reports for a run."""
    cfg = _load(config)
    with Store(cfg.storage.db_path) as store:
        rid = run_id or store.latest_run_id()
        if rid is None:
            console.print("[red]no run found[/red]")
            raise typer.Exit(code=1)
        matches = store.load_matches(rid)
        redteam_results = RedTeamStore(store).load_results(rid) if redteam else []

    findings = prioritize_matches(matches)
    written = _write_reports(findings, out_dir or cfg.storage.reports_dir, rid, formats)
    if redteam:
        written += _write_redteam_reports(redteam_results, out_dir or cfg.storage.reports_dir, rid, formats)

    table = Table(title=f"Prioritized findings - run {rid}")
    table.add_column("#")
    table.add_column("Score")
    table.add_column("Host:Port")
    table.add_column("Signature")
    table.add_column("Severity")
    table.add_column("Status")
    for f in findings[:25]:
        table.add_row(
            str(f.rank), f"{f.score:.2f}", f"{f.match.host}:{f.match.port}",
            f.match.signature_id, f.match.severity.value, f.match.status.value,
        )
    console.print(table)
    for path in written:
        console.print(f"wrote {path}")


@app.command(name="run-all")
def run_all(
    config: Path = ConfigOption,
    with_validate: bool = typer.Option(
        False, "--validate", help="Also run validation checks (still gated by [validate] enabled in config)."
    ),
    formats: str = typer.Option("json,csv", help="Report formats to generate at the end."),
) -> None:
    """Full pipeline: discover -> enumerate -> vuln-map -> (validate) -> report, in one run."""
    cfg = _load(config)
    try:
        signatures = load_signatures()
    except SignatureError as exc:
        console.print(f"[red]signature dataset error:[/red] {escape(str(exc))}")
        raise typer.Exit(code=2)

    with Store(cfg.storage.db_path) as store:
        run_id = store.start_run(str(config))

        hosts = discover_hosts(cfg.scope, cfg.scan.ports, cfg.scan.timeout_seconds, cfg.scan.max_concurrency)
        store.save_hosts(run_id, hosts)
        console.print(f"discover: {len(hosts)} live host(s)")

        hosts_with_ports = {h.ip: h.open_ports for h in hosts}
        findings = enumerate_services(cfg.scope, hosts_with_ports, cfg.scan.timeout_seconds)
        store.save_services(run_id, findings)
        console.print(f"enumerate: {len(findings)} service(s)")

        matches = match_findings(findings, signatures)
        if with_validate and cfg.validate.enabled:
            signature_checks = {s.id: s.check for s in signatures if s.check}
            matches = run_validation(matches, signature_checks, cfg.scope, cfg.validate.timeout_seconds)
        elif with_validate:
            console.print("[yellow]--validate passed but \\[validate] enabled = false in config - skipping[/yellow]")

        store.save_matches(run_id, matches)
        console.print(f"vuln-map: {len(matches)} candidate match(es)")

    findings_ranked = prioritize_matches(matches)
    written = _write_reports(findings_ranked, cfg.storage.reports_dir, run_id, formats)
    console.print(f"run {run_id} complete - {len(written)} report(s) written to {cfg.storage.reports_dir}")


@app.command(name="cve-lookup")
def cve_lookup(
    config: Path = ConfigOption,
    run_id: Optional[int] = typer.Option(None, help="Run to look up (defaults to the latest run)."),
) -> None:
    """Query the public NVD CVE API for every distinct service/version pair enumerated in a run.

    Gated by [intel] cve_lookup_enabled - this is the only command in
    Scripter that calls out to a third party (nvd.nist.gov) instead of a
    scoped target or the bundled offline signature dataset. Pairs come
    from the raw enumeration (``enumerate``), not from vuln-map's
    signature matches - a version too new for the bundled offline
    signature set to recognise still has a version string worth asking
    NVD about.
    """
    cfg = _load(config)
    if not cfg.intel.cve_lookup_enabled:
        console.print("[yellow]\\[intel] cve_lookup_enabled = false in config - refusing to query NVD[/yellow]")
        raise typer.Exit(code=2)

    with Store(cfg.storage.db_path) as store:
        rid = run_id or store.latest_run_id()
        if rid is None:
            console.print("[red]no run found - run 'scripter discover/enumerate/vuln-map' first[/red]")
            raise typer.Exit(code=1)
        services = store.load_services(rid)
    if not services:
        console.print("[yellow]no services enumerated for this run - run 'scripter enumerate' first[/yellow]")
        raise typer.Exit(code=0)

    pairs = sorted({(s.service, s.version or "") for s in services if s.service})[: cfg.intel.cve_lookup_max_pairs]
    console.print(f"querying NVD for {len(pairs)} service/version pair(s)...")

    table = Table(title=f"NVD CVE lookup - run {rid}")
    table.add_column("Service:Version")
    table.add_column("CVE")
    table.add_column("Severity")
    table.add_column("Score")
    table.add_column("Summary")
    for i, (service, version) in enumerate(pairs):
        label = f"{service}:{version}" if version else service
        try:
            results = lookup_cves(
                service, version or None,
                timeout_seconds=cfg.intel.cve_lookup_timeout_seconds,
                max_results=cfg.intel.cve_lookup_max_results,
                api_key=cfg.intel.nvd_api_key or None,
            )
        except CveLookupError as exc:
            table.add_row(label, "-", "-", "-", f"[red]{escape(str(exc))}[/red]")
            results = None
        if results is not None:
            if not results:
                table.add_row(label, "-", "-", "-", "no CVEs found")
            for r in results:
                summary = r.summary[:100] + ("..." if len(r.summary) > 100 else "")
                score = f"{r.cvss_score:.1f}" if r.cvss_score is not None else "-"
                table.add_row(label, r.cve_id, r.severity or "-", score, escape(summary))
        if i < len(pairs) - 1:
            time.sleep(cfg.intel.cve_lookup_delay_seconds)
    console.print(table)


# --- redteam sub-app --------------------------------------------------
#
# Every command below shares one rule: list-tools/plan/simulate never
# touch the network (planning reads already-collected VulnMatch rows;
# simulation is a deterministic offline mock - see redteam/tools/
# simulate.py). audit-*/diagnostics perform a real, scope-gated action
# and require [redteam] network_audits_enabled = true in config.


@redteam_app.command("list-tools")
def redteam_list_tools() -> None:
    """List every registered red-team tool. Fully offline - no config or scope required."""
    registry.ensure_builtin_tools_registered()
    table = Table(title="Red-team tool registry")
    table.add_column("Tool")
    table.add_column("Capability")
    table.add_column("Risk")
    table.add_column("Network")
    table.add_column("Description")
    for t in registry.list_tools():
        table.add_row(t.name, t.capability.value, t.risk.value, "yes" if t.requires_network else "no", t.description)
    console.print(table)


@redteam_app.command("plan")
def redteam_plan(
    config: Path = ConfigOption,
    run_id: Optional[int] = typer.Option(None, help="Run to plan for (defaults to the latest run)."),
) -> None:
    """Build a deterministic attack plan from a run's vuln-map matches. Reads the database only - no network access."""
    cfg = _load(config)
    registry.ensure_builtin_tools_registered()
    try:
        signatures = load_signatures()
    except SignatureError as exc:
        console.print(f"[red]signature dataset error:[/red] {escape(str(exc))}")
        raise typer.Exit(code=2)

    with Store(cfg.storage.db_path) as store:
        rid = run_id or store.latest_run_id()
        if rid is None:
            console.print("[red]no run found - run 'scripter discover/enumerate/vuln-map' first[/red]")
            raise typer.Exit(code=1)
        matches = store.load_matches(rid)
        if not matches:
            console.print("[yellow]no candidate matches recorded for this run - run 'scripter vuln-map' first[/yellow]")
            raise typer.Exit(code=0)
        plan = build_plan(rid, matches, signatures, cfg.scope)
        RedTeamStore(store).save_plan(plan)

    table = Table(title=f"Attack plan - run {rid}")
    table.add_column("Host:Port")
    table.add_column("Tool")
    table.add_column("Manual review")
    table.add_column("Rationale")
    for item in plan.items:
        table.add_row(
            f"{item.host}:{item.port}", item.tool_name, "yes" if item.manual_review_required else "no",
            item.rationale,
        )
    console.print(table)
    console.print(f"{len(plan.items)} planned action(s), {len(plan.skipped)} skipped")
    for reason in plan.skipped:
        console.print(f"[dim]skipped: {escape(reason)}[/dim]")


@redteam_app.command("simulate")
def redteam_simulate(
    config: Path = ConfigOption,
    run_id: Optional[int] = typer.Option(None, help="Run to simulate (defaults to the latest run)."),
) -> None:
    """Execute the saved attack plan through the deterministic offline simulator. Never touches the network."""
    cfg = _load(config, allow_empty_scope=True)
    if not cfg.redteam.simulate_enabled:
        console.print("[yellow]\\[redteam] simulate_enabled = false in config[/yellow]")
        raise typer.Exit(code=2)
    registry.ensure_builtin_tools_registered()

    with Store(cfg.storage.db_path) as store:
        rid = run_id or store.latest_run_id()
        if rid is None:
            console.print("[red]no run found[/red]")
            raise typer.Exit(code=1)
        rt_store = RedTeamStore(store)
        plan = rt_store.load_plan(rid)
        if plan is None or not plan.items:
            console.print("[yellow]no plan recorded for this run - run 'scripter redteam plan' first[/yellow]")
            raise typer.Exit(code=0)
        results = [execute_item(item, cfg, simulate_only=True, run_id=rid) for item in plan.items]
        rt_store.save_results(results)

    table = Table(title=f"Simulation results - run {rid}")
    table.add_column("Host:Port")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Evidence")
    for r in results:
        table.add_row(f"{r.host}:{r.port}", r.tool_name, r.status.value, escape(r.evidence))
    console.print(table)


def _adhoc_item(host: str, port: int, service: str, tool_name: str) -> AttackPlanItem:
    return AttackPlanItem(
        host=host, port=port, service=service, signature_id="adhoc", tool_name=tool_name,
        rationale="ad-hoc CLI invocation", prerequisites=(), planned_action=f"run {tool_name} against {host}:{port}",
        manual_review_required=False, source_status=MatchStatus.HYPOTHESIS.value, source_score=0.0,
    )


def _run_adhoc_audit(cfg: Config, run_id: Optional[int], host: str, port: int, service: str, tool_name: str) -> None:
    try:
        require_in_scope(host, cfg.scope)
    except ScopeError as exc:
        console.print(f"[red]scope error:[/red] {escape(str(exc))}")
        raise typer.Exit(code=2)

    item = _adhoc_item(host, port, service, tool_name)
    with Store(cfg.storage.db_path) as store:
        rid = run_id or store.latest_run_id() or store.start_run(str(cfg.path))
        result = execute_item(item, cfg, simulate_only=False, run_id=rid, store=store)
        RedTeamStore(store).save_results([result])

    console.print(f"[bold]{tool_name}[/bold] {host}:{port} -> {result.status.value}")
    console.print(escape(result.evidence))
    if result.status == ExecutionStatus.FAILED:
        raise typer.Exit(code=1)


@redteam_app.command("audit-http")
def redteam_audit_http(
    config: Path = ConfigOption,
    host: str = typer.Option(..., "--host", help="Target host - must already be inside [scope] targets."),
    port: int = typer.Option(80, "--port"),
    run_id: Optional[int] = typer.Option(None, help="Attach this result to a specific run id."),
) -> None:
    """Bounded HTTP GET + security-header review for one scoped host:port. Performs a real network request."""
    cfg = _load(config)
    _run_adhoc_audit(cfg, run_id, host, port, "http", "http_audit")


@redteam_app.command("audit-tls")
def redteam_audit_tls(
    config: Path = ConfigOption,
    host: str = typer.Option(..., "--host", help="Target host - must already be inside [scope] targets."),
    port: int = typer.Option(443, "--port"),
    run_id: Optional[int] = typer.Option(None, help="Attach this result to a specific run id."),
) -> None:
    """Certificate metadata + negotiated protocol/cipher for one scoped host:port. Performs a real network request."""
    cfg = _load(config)
    _run_adhoc_audit(cfg, run_id, host, port, "https", "tls_audit")


@redteam_app.command("audit-ftp")
def redteam_audit_ftp(
    config: Path = ConfigOption,
    host: str = typer.Option(..., "--host", help="Target host - must already be inside [scope] targets."),
    port: int = typer.Option(21, "--port"),
    run_id: Optional[int] = typer.Option(None, help="Attach this result to a specific run id."),
) -> None:
    """Passive FTP banner, plus the existing anonymous-login check if [validate] is enabled. Real network request."""
    cfg = _load(config)
    _run_adhoc_audit(cfg, run_id, host, port, "ftp", "ftp_audit")


@redteam_app.command("audit-redis")
def redteam_audit_redis(
    config: Path = ConfigOption,
    host: str = typer.Option(..., "--host", help="Target host - must already be inside [scope] targets."),
    port: int = typer.Option(6379, "--port"),
    run_id: Optional[int] = typer.Option(None, help="Attach this result to a specific run id."),
) -> None:
    """Passive Redis banner, plus the existing unauthenticated-PING check if [validate] is enabled. Real network request."""
    cfg = _load(config)
    _run_adhoc_audit(cfg, run_id, host, port, "redis", "redis_audit")


@redteam_app.command("audit-ssh")
def redteam_audit_ssh(
    config: Path = ConfigOption,
    host: str = typer.Option(..., "--host", help="Target host - must already be inside [scope] targets."),
    port: int = typer.Option(22, "--port"),
    run_id: Optional[int] = typer.Option(None, help="Attach this result to a specific run id."),
) -> None:
    """Passive SSH identification-string read, plus the existing legacy-OpenSSH-version check. Real network request."""
    cfg = _load(config)
    _run_adhoc_audit(cfg, run_id, host, port, "ssh", "ssh_audit")


@redteam_app.command("audit-smtp")
def redteam_audit_smtp(
    config: Path = ConfigOption,
    host: str = typer.Option(..., "--host", help="Target host - must already be inside [scope] targets."),
    port: int = typer.Option(25, "--port"),
    run_id: Optional[int] = typer.Option(None, help="Attach this result to a specific run id."),
) -> None:
    """One benign EHLO + QUIT - lists advertised extensions/AUTH mechanisms, sends no mail. Real network request."""
    cfg = _load(config)
    _run_adhoc_audit(cfg, run_id, host, port, "smtp", "smtp_audit")


@redteam_app.command("audit-mysql")
def redteam_audit_mysql(
    config: Path = ConfigOption,
    host: str = typer.Option(..., "--host", help="Target host - must already be inside [scope] targets."),
    port: int = typer.Option(3306, "--port"),
    run_id: Optional[int] = typer.Option(None, help="Attach this result to a specific run id."),
) -> None:
    """Passive read of the unprompted MySQL handshake packet - reveals the server version, attempts no login. Real network request."""
    cfg = _load(config)
    _run_adhoc_audit(cfg, run_id, host, port, "mysql", "mysql_audit")


@redteam_app.command("diagnostics")
def redteam_diagnostics(
    config: Path = ConfigOption,
    run_id: Optional[int] = typer.Option(None, help="Run to compare (defaults to the latest run)."),
) -> None:
    """Compare this run's recorded host/port availability against the previous run. Local database only."""
    cfg = _load(config)
    with Store(cfg.storage.db_path) as store:
        rid = run_id or store.latest_run_id()
        if rid is None:
            console.print("[red]no run found[/red]")
            raise typer.Exit(code=1)
        hosts = store.load_hosts(rid)
        if not hosts:
            console.print("[yellow]no hosts recorded for this run[/yellow]")
            raise typer.Exit(code=0)

        results = []
        for h in hosts:
            for p in h.open_ports:
                item = _adhoc_item(h.ip, p, "tcp", "diagnostics")
                results.append(execute_item(item, cfg, simulate_only=False, run_id=rid, store=store))
        RedTeamStore(store).save_results(results)

    table = Table(title=f"Diagnostics - run {rid}")
    table.add_column("Host:Port")
    table.add_column("Status")
    table.add_column("Evidence")
    for r in results:
        table.add_row(f"{r.host}:{r.port}", r.status.value, escape(r.evidence))
    console.print(table)
