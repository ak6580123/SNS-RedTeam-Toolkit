"""Scripter CLI: discover -> enumerate -> vuln-map -> validate -> report,
one Typer sub-command per stage, plus a run-all convenience pipeline.

Every active command loads its scope from an explicit config file (see
scope.py/config.py) - there is no default target and no command will act
without one. Exit codes follow the project convention: 0 ok, 1 error,
2 usage/config error.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from scripter import __version__
from scripter.config import Config, ConfigError, load_config
from scripter.intel.matcher import match_findings
from scripter.intel.vuln_db import SignatureError, load_signatures
from scripter.logging_setup import configure_logging, get_logger
from scripter.prioritize import prioritize as prioritize_matches
from scripter.recon.discovery import discover_hosts
from scripter.recon.enumeration import enumerate_services, nmap_available, run_nmap_version_scan
from scripter.reporting.report import write_csv, write_html, write_json
from scripter.storage.db import Store
from scripter.validation.checks import run_validation

app = typer.Typer(help="Authorized red-team recon/enumeration/vuln-mapping toolkit for A/D CTF competitions.")
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
) -> None:
    """Generate ranked, machine-readable findings reports for a run."""
    cfg = _load(config)
    with Store(cfg.storage.db_path) as store:
        rid = run_id or store.latest_run_id()
        if rid is None:
            console.print("[red]no run found[/red]")
            raise typer.Exit(code=1)
        matches = store.load_matches(rid)

    findings = prioritize_matches(matches)
    written = _write_reports(findings, out_dir or cfg.storage.reports_dir, rid, formats)

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
