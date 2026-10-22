"""Scripter's interactive TUI: a live, keyboard-driven dashboard over the
discover -> enumerate -> vuln-map -> validate -> report pipeline.

The TUI is a thin presentation layer - every action it can trigger calls
the exact same scope-gated functions the CLI commands use
(recon.discovery.discover_hosts, recon.enumeration.enumerate_services,
intel.matcher.match_findings, validation.checks.run_validation,
prioritize.prioritize, reporting.report.write_*). There is no second
implementation of the pipeline here, only a nicer way to watch it run.

Network/subprocess work happens in Textual's thread workers
(``@work(thread=True)``) so the UI never blocks; each worker hands its
result back to the UI thread via ``call_from_thread``.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, RichLog, Static, TabbedContent, TabPane

from scripter.config import Config, write_scope_targets
from scripter.intel.matcher import match_findings
from scripter.intel.vuln_db import load_signatures
from scripter.models import Host, MatchStatus, ServiceFinding, Severity, VulnMatch
from scripter.prioritize import prioritize as prioritize_matches
from scripter.recon.discovery import discover_hosts
from scripter.recon.enumeration import enumerate_services
from scripter.reporting.report import write_csv, write_html, write_json
from scripter.scope import Scope, ScopeError, parse_scope
from scripter.storage.db import Store
from scripter.validation.checks import run_validation

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold green",
}

_STATUS_STYLE: dict[MatchStatus, str] = {
    MatchStatus.CONFIRMED: "bold green",
    MatchStatus.HYPOTHESIS: "yellow",
    MatchStatus.INCONCLUSIVE: "grey58",
    MatchStatus.RULED_OUT: "dim strike",
}

_ACCENT = "#39ff88"


class ScopeEditorScreen(ModalScreen[Scope | None]):
    """Modal for setting ``[scope] targets`` without leaving the TUI.

    Dismisses with a validated ``Scope`` on Apply, or ``None`` on Cancel.
    Re-uses ``scope.parse_scope`` so a target entered here is held to the
    exact same rules (no public addresses, max_hosts safety valve, ...) as
    the CLI's config loader.
    """

    CSS = f"""
    ScopeEditorScreen {{
        align: center middle;
    }}
    #scope_dialog {{
        width: 76;
        height: auto;
        border: round {_ACCENT};
        background: #0a0e0b;
        padding: 1 2;
    }}
    #scope_dialog Label {{
        color: {_ACCENT};
    }}
    #scope_error {{
        color: #ff5f5f;
        height: auto;
        margin-top: 1;
    }}
    #scope_buttons {{
        height: auto;
        margin-top: 1;
        align: right middle;
    }}
    """

    def __init__(self, current_targets: tuple[str, ...], allow_public: bool, max_hosts: int):
        super().__init__()
        self._current = ", ".join(current_targets)
        self._allow_public = allow_public
        self._max_hosts = max_hosts

    def compose(self) -> ComposeResult:
        with Vertical(id="scope_dialog"):
            yield Label("[scope] targets - comma-separated hosts/CIDRs you are authorized to target")
            yield Input(value=self._current, placeholder="10.10.1.0/24, 10.10.2.5", id="scope_input")
            yield Label("", id="scope_error")
            with Horizontal(id="scope_buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Apply", variant="success", id="apply")

    def on_mount(self) -> None:
        self.query_one("#scope_input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
        else:
            self._apply()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._apply()

    def _apply(self) -> None:
        raw = self.query_one("#scope_input", Input).value
        targets = [t.strip() for t in raw.split(",") if t.strip()]
        try:
            scope = parse_scope(targets, allow_public=self._allow_public, max_hosts=self._max_hosts)
        except ScopeError as exc:
            self.query_one("#scope_error", Label).update(str(exc))
            return
        self.dismiss(scope)


class ScripterApp(App):
    """Launch with ``scripter tui``. See docs/architecture.md for how this
    maps onto the same pipeline the CLI uses, stage by stage."""

    TITLE = "SCRIPTER // RED TEAM"

    CSS = f"""
    Screen {{
        background: #0a0e0b;
    }}
    #status {{
        height: 3;
        border: round {_ACCENT};
        padding: 0 1;
        color: {_ACCENT};
        text-style: bold;
    }}
    DataTable {{
        border: round {_ACCENT};
        height: 1fr;
    }}
    RichLog {{
        border: round {_ACCENT};
        height: 12;
        color: #7cfc9b;
    }}
    Tabs {{
        background: #0a0e0b;
    }}
    Tab {{
        color: {_ACCENT};
    }}
    Footer {{
        background: #0a0e0b;
    }}
    Header {{
        background: #0a0e0b;
        color: {_ACCENT};
        text-style: bold;
    }}
    """

    BINDINGS = [
        Binding("s", "edit_scope", "Scope"),
        Binding("d", "run_discover", "Discover"),
        Binding("e", "run_enumerate", "Enumerate"),
        Binding("m", "run_vuln_map", "Vuln-map"),
        Binding("v", "run_validate", "Validate"),
        Binding("r", "run_report", "Report"),
        Binding("a", "run_all", "Run-all"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, cfg: Config, config_path: Path):
        super().__init__()
        self.cfg = cfg
        self.config_path = config_path
        self.store = Store(cfg.storage.db_path)
        self.signatures = load_signatures()
        self.run_id: int | None = None

    # --- layout ------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(self._status_text(), id="status")
        with TabbedContent(initial="hosts"):
            with TabPane("Hosts", id="hosts"):
                yield DataTable(id="hosts_table", zebra_stripes=True, cursor_type="row")
            with TabPane("Services", id="services"):
                yield DataTable(id="services_table", zebra_stripes=True, cursor_type="row")
            with TabPane("Findings", id="findings"):
                yield DataTable(id="findings_table", zebra_stripes=True, cursor_type="row")
        with Vertical():
            yield RichLog(id="log", highlight=True, markup=True, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#hosts_table", DataTable).add_columns("Host", "Open ports", "Discovered")
        self.query_one("#services_table", DataTable).add_columns("Host", "Port", "Service", "Version", "Banner")
        self.query_one("#findings_table", DataTable).add_columns(
            "#", "Score", "Host:Port", "Signature", "CVE", "Severity", "Status"
        )
        self.run_id = self.store.latest_run_id()
        self._refresh_status()
        self._log(
            f"[bold {_ACCENT}]scripter TUI ready[/] - scope has {len(self.cfg.scope.hosts)} host(s). "
            "s=scope  d=discover  e=enumerate  m=vuln-map  v=validate  r=report  a=run-all  q=quit"
        )
        if not self.cfg.scope.hosts:
            self._log("[yellow]no scope configured - press s to set \\[scope] targets before running discover[/]")
        if self.run_id is not None:
            self._load_existing_run()

    def on_unmount(self) -> None:
        self.store.close()

    # --- helpers -------------------------------------------------------

    def _log(self, message: str) -> None:
        self.query_one("#log", RichLog).write(message)

    def _status_text(self) -> str:
        return (
            f"scope: {len(self.cfg.scope.hosts)} host(s)   "
            f"run: {self.run_id if self.run_id is not None else '-'}   "
            f"validate: {'enabled' if self.cfg.validate.enabled else 'disabled'}"
        )

    def _refresh_status(self) -> None:
        self.query_one("#status", Static).update(self._status_text())

    def _load_existing_run(self) -> None:
        assert self.run_id is not None
        self._apply_discover(self.run_id, self.store.load_hosts(self.run_id), log=False)
        self._apply_enumerate(self.store.load_services(self.run_id), log=False)
        self._apply_findings(self.store.load_matches(self.run_id), log=False)

    # --- apply-result callbacks (run on the UI thread) ----------------

    def _apply_discover(self, run_id: int, hosts: list[Host], log: bool = True) -> None:
        self.run_id = run_id
        self._refresh_status()
        table = self.query_one("#hosts_table", DataTable)
        table.clear()
        for h in hosts:
            table.add_row(h.ip, ", ".join(str(p) for p in h.open_ports) or "-", h.discovered_at.strftime("%H:%M:%S"))
        if log:
            self._log(f"[green]discover complete[/]: {len(hosts)} live host(s) - run {run_id}")

    def _apply_enumerate(self, findings: list[ServiceFinding], log: bool = True) -> None:
        table = self.query_one("#services_table", DataTable)
        table.clear()
        for f in findings:
            banner = f.banner.replace("\n", " ").replace("\r", "")
            if len(banner) > 60:
                banner = banner[:60] + "..."
            table.add_row(f.host, str(f.port), f.service or "-", f.version or "-", banner or "-")
        if log:
            self._log(f"[green]enumerate complete[/]: {len(findings)} service(s)")

    def _apply_findings(self, matches: list[VulnMatch], log: bool = True) -> None:
        ranked = prioritize_matches(matches)
        table = self.query_one("#findings_table", DataTable)
        table.clear()
        for f in ranked:
            m = f.match
            severity_style = _SEVERITY_STYLE.get(m.severity, "white")
            status_style = _STATUS_STYLE.get(m.status, "white")
            table.add_row(
                str(f.rank),
                f"{f.score:.2f}",
                f"{m.host}:{m.port}",
                m.signature_id,
                m.cve_id,
                f"[{severity_style}]{m.severity.value}[/]",
                f"[{status_style}]{m.status.value}[/]",
            )
        if log:
            self._log(f"[green]vuln-map complete[/]: {len(matches)} candidate match(es)")

    # --- pure pipeline steps (no UI access - safe to call off-thread) -

    def _do_discover(self) -> tuple[int, list[Host]]:
        run_id = self.store.start_run(str(self.config_path))
        hosts = discover_hosts(self.cfg.scope, self.cfg.scan.ports, self.cfg.scan.timeout_seconds, self.cfg.scan.max_concurrency)
        self.store.save_hosts(run_id, hosts)
        return run_id, hosts

    def _do_enumerate(self, run_id: int) -> list[ServiceFinding]:
        hosts = self.store.load_hosts(run_id)
        hosts_with_ports = {h.ip: h.open_ports for h in hosts}
        findings = enumerate_services(self.cfg.scope, hosts_with_ports, self.cfg.scan.timeout_seconds)
        self.store.save_services(run_id, findings)
        return findings

    def _do_vuln_map(self, run_id: int) -> list[VulnMatch]:
        findings = self.store.load_services(run_id)
        matches = match_findings(findings, self.signatures)
        self.store.clear_matches_for_run(run_id)
        self.store.save_matches(run_id, matches)
        return matches

    def _do_validate(self, run_id: int) -> list[VulnMatch]:
        matches = self.store.load_matches(run_id)
        signature_checks = {s.id: s.check for s in self.signatures if s.check}
        updated = run_validation(matches, signature_checks, self.cfg.scope, self.cfg.validate.timeout_seconds)
        self.store.clear_matches_for_run(run_id)
        self.store.save_matches(run_id, updated)
        return updated

    def _do_report(self, run_id: int) -> list[Path]:
        matches = self.store.load_matches(run_id)
        ranked = prioritize_matches(matches)
        reports_dir = self.cfg.storage.reports_dir
        reports_dir.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
        return [
            write_json(ranked, reports_dir / f"run{run_id}_{stamp}.json"),
            write_csv(ranked, reports_dir / f"run{run_id}_{stamp}.csv"),
            write_html(ranked, reports_dir / f"run{run_id}_{stamp}.html", title=f"Scripter findings - run {run_id}"),
        ]

    # --- actions (keybindings) ----------------------------------------

    def action_edit_scope(self) -> None:
        self.push_screen(
            ScopeEditorScreen(self.cfg.scope.raw_entries, self.cfg.scope_allow_public, self.cfg.scope_max_hosts),
            self._on_scope_submitted,
        )

    def _on_scope_submitted(self, scope: Scope | None) -> None:
        if scope is None:
            return
        self.cfg = dataclasses.replace(self.cfg, scope=scope)
        write_scope_targets(self.config_path, list(scope.raw_entries))
        self._refresh_status()
        self._log(f"[green]scope updated[/]: {len(scope.hosts)} host(s) - saved to {self.config_path}")

    def action_run_discover(self) -> None:
        if not self.cfg.scope.hosts:
            self._log("[red]no scope configured - press s to set \\[scope] targets[/]")
            return
        self.worker_discover()

    def action_run_enumerate(self) -> None:
        if self.run_id is None:
            self._log("[red]no run yet - press d first[/]")
            return
        self.worker_enumerate()

    def action_run_vuln_map(self) -> None:
        if self.run_id is None:
            self._log("[red]no run yet - press d first[/]")
            return
        self.worker_vuln_map()

    def action_run_validate(self) -> None:
        if not self.cfg.validate.enabled:
            self._log("[yellow]validate disabled - set \\[validate] enabled = true in config[/]")
            return
        if self.run_id is None:
            self._log("[red]no run yet - press d first[/]")
            return
        self.worker_validate()

    def action_run_report(self) -> None:
        if self.run_id is None:
            self._log("[red]no run yet - press d first[/]")
            return
        self.worker_report()

    def action_run_all(self) -> None:
        if not self.cfg.scope.hosts:
            self._log("[red]no scope configured - press s to set \\[scope] targets[/]")
            return
        self.worker_run_all()

    # --- background workers -------------------------------------------

    @work(thread=True, exclusive=True)
    def worker_discover(self) -> None:
        self.call_from_thread(self._log, "[cyan]discover: sweeping scope...[/]")
        run_id, hosts = self._do_discover()
        self.call_from_thread(self._apply_discover, run_id, hosts)

    @work(thread=True, exclusive=True)
    def worker_enumerate(self) -> None:
        assert self.run_id is not None
        self.call_from_thread(self._log, "[cyan]enumerate: grabbing banners...[/]")
        findings = self._do_enumerate(self.run_id)
        self.call_from_thread(self._apply_enumerate, findings)

    @work(thread=True, exclusive=True)
    def worker_vuln_map(self) -> None:
        assert self.run_id is not None
        self.call_from_thread(self._log, "[cyan]vuln-map: matching signatures...[/]")
        matches = self._do_vuln_map(self.run_id)
        self.call_from_thread(self._apply_findings, matches)

    @work(thread=True, exclusive=True)
    def worker_validate(self) -> None:
        assert self.run_id is not None
        self.call_from_thread(self._log, "[cyan]validate: running non-destructive checks...[/]")
        updated = self._do_validate(self.run_id)
        self.call_from_thread(self._apply_findings, updated)

    @work(thread=True, exclusive=True)
    def worker_report(self) -> None:
        assert self.run_id is not None
        paths = self._do_report(self.run_id)
        for p in paths:
            self.call_from_thread(self._log, f"[green]wrote[/] {p}")

    @work(thread=True, exclusive=True)
    def worker_run_all(self) -> None:
        self.call_from_thread(self._log, f"[bold {_ACCENT}]run-all: starting full pipeline...[/]")
        run_id, hosts = self._do_discover()
        self.call_from_thread(self._apply_discover, run_id, hosts)
        findings = self._do_enumerate(run_id)
        self.call_from_thread(self._apply_enumerate, findings)
        matches = self._do_vuln_map(run_id)
        if self.cfg.validate.enabled:
            self.call_from_thread(self._log, "[cyan]validate: running non-destructive checks...[/]")
            matches = self._do_validate(run_id)
        self.call_from_thread(self._apply_findings, matches)
        self.call_from_thread(self._log, f"[bold {_ACCENT}]run-all complete[/] - run {run_id}")
