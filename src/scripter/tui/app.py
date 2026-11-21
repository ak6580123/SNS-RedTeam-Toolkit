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
import time
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.theme import Theme
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, RichLog, Static, TabbedContent, TabPane

# Only the lightweight, always-needed pieces load at import time. Everything
# in the discover->report pipeline (executor, cve_lookup, enumeration,
# validation, reporting, ...) is imported inside the worker method that
# uses it - those methods already run on a background thread, so the
# import cost lands there instead of delaying the dashboard's first paint.
from scripter.config import write_scope_targets
from scripter.models import MatchStatus, Severity
from scripter.redteam.models import ExecutionStatus
from scripter.redteam.storage import RedTeamStore
# Scope is referenced at runtime in a class base (ModalScreen[Scope | None]),
# which is evaluated at class-definition time, so it must be a real import.
from scripter.scope import Scope, ScopeError, parse_scope
from scripter.storage.db import Store

if TYPE_CHECKING:  # annotation-only names - never imported at runtime
    from scripter.config import Config
    from scripter.intel.cve_lookup import CveResult
    from scripter.models import Host, ServiceFinding, VulnMatch
    from scripter.redteam.models import AttackPlan, ToolResult

# --- palette ---------------------------------------------------------
# A single refined dark palette drives both the Textual theme (widget
# chrome, via the design tokens below) and the inline Rich markup we
# write into tables/logs (the hex constants here). Keeping them in one
# place is what stops the UI drifting into the old neon-green terminal
# look - everything now reads as one quiet, cohesive surface.
_ACCENT = "#9ece6a"   # muted green - the one accent
_BLUE = "#7aa2f7"
_MUTED = "#565f7e"
_WARN = "#e0af68"
_ERR = "#f7768e"

_REDTEAM_STATUS_STYLE: dict[ExecutionStatus, str] = {
    ExecutionStatus.COMPLETED: f"bold {_ACCENT}",
    ExecutionStatus.SIMULATED: _WARN,
    ExecutionStatus.BLOCKED: "dim strike",
    ExecutionStatus.FAILED: f"bold {_ERR}",
    ExecutionStatus.INCONCLUSIVE: _MUTED,
}

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: f"bold #0b0d12 on {_ERR}",
    Severity.HIGH: f"bold {_ERR}",
    Severity.MEDIUM: f"bold {_WARN}",
    Severity.LOW: f"bold {_ACCENT}",
}

_STATUS_STYLE: dict[MatchStatus, str] = {
    MatchStatus.CONFIRMED: f"bold {_ACCENT}",
    MatchStatus.HYPOTHESIS: _WARN,
    MatchStatus.INCONCLUSIVE: _MUTED,
    MatchStatus.RULED_OUT: "dim strike",
}

#: Registered on the app at mount; a Tokyo-Night-leaning dark theme that
#: gives the whole dashboard the quiet, low-contrast-but-legible feel of
#: a modern editor TUI rather than a high-vis hacker console.
SCRIPTER_THEME = Theme(
    name="scripter",
    primary=_ACCENT,
    secondary=_BLUE,
    accent=_ACCENT,
    foreground="#c0caf5",
    background="#0b0d12",
    surface="#12151c",
    panel="#161a22",
    success=_ACCENT,
    warning=_WARN,
    error=_ERR,
    dark=True,
    variables={
        "border": "#232838",
        "border-blurred": "#1b1f2a",
        "text-muted": _MUTED,
        "block-cursor-foreground": "#0b0d12",
        "block-cursor-background": _ACCENT,
        "block-cursor-text-style": "bold",
        "footer-key-foreground": _ACCENT,
        "footer-description-foreground": "#8089b3",
        "footer-background": "#0b0d12",
        "scrollbar": "#232838",
        "scrollbar-hover": "#2d3344",
        "scrollbar-active": _ACCENT,
        "input-selection-background": "#9ece6a40",
    },
)

#: Full keymap, shown by the `?` overlay so the footer can stay short.
_HELP_TEXT = (
    f"[b {_ACCENT}]RECON PIPELINE[/]\n"
    f"  [b]d[/] discover        [b]D[/] deep-scan (nmap -p-)\n"
    f"  [b]e[/] enumerate       [b]m[/] vuln-map\n"
    f"  [b]v[/] validate        [b]r[/] report\n"
    f"  [b]a[/] run-all (discover -> report)\n\n"
    f"[b {_ACCENT}]RED TEAM[/]\n"
    f"  [b]p[/] plan            [b]x[/] simulate\n"
    f"  [b]c[/] cve-lookup (NVD)\n\n"
    f"[b {_ACCENT}]GENERAL[/]\n"
    f"  [b]s[/] edit scope      [b]?[/] this help\n"
    f"  [b]q[/] quit\n\n"
    f"[{_MUTED}]Click a Services row to run a tool against that host.\n"
    f"Click a CVEs row for detail and an \"Explain with AI\" shortcut.[/]"
)

#: service (as recorded on ServiceFinding) -> red-team tool(s) worth
#: offering first when a user clicks that service in the TUI. Broader
#: than redteam.planner's 1:1 _SERVICE_TOOL_MAP on purpose - this just
#: orders *choices* for a human, it never decides anything by itself.
_SERVICE_SPECIFIC_TOOLS: dict[str, tuple[str, ...]] = {
    "http": ("http_audit",),
    "http-alt": ("http_audit",),
    "https": ("tls_audit", "http_audit"),
    "https-alt": ("tls_audit", "http_audit"),
    "ftp": ("ftp_audit",),
    "redis": ("redis_audit",),
    "ssh": ("ssh_audit",),
    "smtp": ("smtp_audit",),
    "mysql": ("mysql_audit",),
}
#: Offered for every service, specific or not - these never assume a
#: particular protocol beyond "an open TCP port".
_GENERIC_TOOLS: tuple[str, ...] = ("banner_probe", "nmap_adapter", "diagnostics")


def _tools_for_service(service: str) -> tuple[str, ...]:
    ordered = _SERVICE_SPECIFIC_TOOLS.get(service, ()) + _GENERIC_TOOLS
    return tuple(dict.fromkeys(ordered))


class ScopeEditorScreen(ModalScreen[Scope | None]):
    """Modal for setting ``[scope] targets`` without leaving the TUI.

    Dismisses with a validated ``Scope`` on Apply, or ``None`` on Cancel.
    Re-uses ``scope.parse_scope`` so a target entered here is held to the
    exact same rules (no public addresses, max_hosts safety valve, ...) as
    the CLI's config loader.
    """

    CSS = """
    ScopeEditorScreen {
        align: center middle;
    }
    #scope_dialog {
        width: 76;
        height: auto;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }
    #scope_dialog Label {
        color: $primary;
    }
    #scope_error {
        color: $error;
        height: auto;
        margin-top: 1;
    }
    #scope_buttons {
        height: auto;
        margin-top: 1;
        align: right middle;
    }
    #scope_buttons Button {
        margin-left: 1;
    }
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


class ServiceActionsScreen(ModalScreen[None]):
    """Modal opened by clicking a row in the Services table.

    Lets you run the red-team tool(s) appropriate for that one
    host:port:service. Re-uses redteam.executor.execute_item exactly as the
    CLI's ``redteam audit-*`` commands do - no new gating logic here;
    scope/category/network/validate checks all still run inside
    execute_item, so a blocked/disabled tool just reports BLOCKED instead
    of silently doing nothing.
    """

    CSS = """
    ServiceActionsScreen {
        align: center middle;
    }
    #actions_dialog {
        width: 92;
        height: auto;
        max-height: 90%;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }
    #actions_dialog Label {
        color: $text-muted;
    }
    #actions_target {
        color: $primary;
        text-style: bold;
    }
    #actions_tools {
        height: auto;
        margin-top: 1;
        margin-bottom: 1;
    }
    #actions_tools Button {
        margin-right: 1;
        margin-bottom: 1;
    }
    #actions_log {
        border: round $border;
        background: $panel;
        height: 10;
        color: $foreground;
    }
    #actions_close {
        margin-top: 1;
        align: right middle;
    }
    """

    def __init__(
        self,
        host: str,
        port: int,
        service: str,
        cfg: Config,
        run_id: int | None,
        store: Store,
        redteam_store: RedTeamStore,
    ):
        super().__init__()
        self._host = host
        self._port = port
        self._service = service
        self._cfg = cfg
        self._run_id = run_id
        self._store = store
        self._redteam_store = redteam_store
        self._tools = _tools_for_service(service)

    def compose(self) -> ComposeResult:
        with Vertical(id="actions_dialog"):
            yield Label(f"{self._host}:{self._port} ({self._service or 'unknown service'})", id="actions_target")
            yield Label("pick a red-team tool to run - the real, scope-gated action:")
            with Horizontal(id="actions_tools"):
                for tool_name in self._tools:
                    yield Button(f"Run {tool_name}", variant="warning", id=f"run__{tool_name}")
            yield RichLog(id="actions_log", highlight=True, markup=True, wrap=True)
            with Horizontal(id="actions_close"):
                yield Button("Close", id="close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "close":
            self.dismiss(None)
            return
        if button_id.startswith("run__"):
            self._launch(button_id[len("run__"):])

    def _launch(self, tool_name: str) -> None:
        self.query_one("#actions_log", RichLog).write(
            f"[cyan]run: {tool_name} against {self._host}:{self._port}...[/]"
        )
        self._execute(tool_name)

    @work(thread=True, exclusive=False)
    def _execute(self, tool_name: str) -> None:
        from scripter.redteam import registry
        from scripter.redteam.executor import execute_item
        from scripter.redteam.models import AttackPlanItem

        registry.ensure_builtin_tools_registered()
        item = AttackPlanItem(
            host=self._host, port=self._port, service=self._service or "unknown", signature_id="tui-adhoc",
            tool_name=tool_name, rationale="launched from the TUI Services screen", prerequisites=(),
            planned_action=f"run {tool_name} against {self._host}:{self._port}",
            manual_review_required=False, source_status=MatchStatus.HYPOTHESIS.value, source_score=0.0,
        )
        run_id = self._run_id or self._store.latest_run_id() or self._store.start_run("tui-adhoc")
        result = execute_item(item, self._cfg, simulate_only=False, run_id=run_id, store=self._store)
        self._redteam_store.save_results([result])
        self.app.call_from_thread(self._apply_result, result)

    def _apply_result(self, result: ToolResult) -> None:
        style = _REDTEAM_STATUS_STYLE.get(result.status, "white")
        self.query_one("#actions_log", RichLog).write(f"[{style}]{result.status.value}[/]: {result.evidence}")
        app = self.app
        if isinstance(app, ScripterApp):
            app.refresh_redteam_results()


class CveDetailScreen(ModalScreen[None]):
    """Modal opened by clicking a row in the CVEs tab's results table.

    Shows the full NVD record for the one CVE that was clicked, and offers
    an "Explain with AI" button that opens the user's default browser on
    ChatGPT with a ready-made prompt about this CVE pre-filled via its
    ``?q=`` query parameter - the same prefill mechanism Streamlit's
    chat-link widget uses, so there is no API key and no extra network
    call from this process itself.
    """

    CSS = """
    CveDetailScreen {
        align: center middle;
    }
    #cve_detail_dialog {
        width: 96;
        height: auto;
        max-height: 90%;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }
    #cve_detail_dialog Label {
        color: $primary;
    }
    #cve_detail_body {
        border: round $border;
        background: $panel;
        height: 16;
        color: $foreground;
    }
    #cve_detail_buttons {
        margin-top: 1;
        align: right middle;
    }
    #cve_detail_buttons Button {
        margin-left: 1;
    }
    """

    def __init__(self, service: str, version: str, result: CveResult):
        super().__init__()
        self._service = service
        self._version = version
        self._result = result

    def compose(self) -> ComposeResult:
        label = f"{self._service}:{self._version}" if self._version else self._service
        with Vertical(id="cve_detail_dialog"):
            yield Label(f"{self._result.cve_id} - {label}")
            yield RichLog(id="cve_detail_body", highlight=True, markup=True, wrap=True)
            with Horizontal(id="cve_detail_buttons"):
                yield Button("Explain with AI", variant="primary", id="explain_ai")
                yield Button("Close", id="close")

    def on_mount(self) -> None:
        r = self._result
        severity = r.severity or "-"
        score = f"{r.cvss_score:.1f}" if r.cvss_score is not None else "-"
        body = self.query_one("#cve_detail_body", RichLog)
        body.write(f"[bold]severity:[/] {severity}   [bold]cvss:[/] {score}")
        body.write(f"[bold]url:[/] {r.url}")
        body.write("")
        body.write(r.summary)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close":
            self.dismiss(None)
        elif event.button.id == "explain_ai":
            self._open_in_chatgpt()

    def _open_in_chatgpt(self) -> None:
        r = self._result
        label = f"{self._service}:{self._version}" if self._version else self._service
        prompt = (
            f"Explain {r.cve_id} (affecting {label}) in plain terms: what the vulnerability is, "
            f"how severe it is (severity={r.severity or 'unknown'}, "
            f"CVSS={r.cvss_score if r.cvss_score is not None else 'unknown'}), how it could be "
            f"exploited, and how to remediate it.\n\nNVD summary: {r.summary}\n\nSource: {r.url}"
        )
        webbrowser.open("https://chatgpt.com/?q=" + quote(prompt))


class HelpScreen(ModalScreen[None]):
    """The full keymap, on `?`. Keeps the footer short by giving the
    less-central bindings a home instead of crowding the status bar."""

    CSS = """
    HelpScreen {
        align: center middle;
    }
    #help_dialog {
        width: 60;
        height: auto;
        max-height: 90%;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }
    #help_title {
        color: $primary;
        text-style: bold;
        margin-bottom: 1;
    }
    #help_hint {
        color: $text-muted;
        margin-top: 1;
    }
    """

    BINDINGS = [Binding("escape,q,question_mark", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        with Vertical(id="help_dialog"):
            yield Static("SCRIPTER · keymap", id="help_title")
            yield Static(_HELP_TEXT, id="help_body")
            yield Static("esc to close", id="help_hint")


class ScripterApp(App):
    """Launch with ``scripter tui``. See docs/architecture.md for how this
    maps onto the same pipeline the CLI uses, stage by stage."""

    TITLE = "SCRIPTER"
    SUB_TITLE = "red-team automation"

    CSS = """
    Screen {
        background: $background;
        color: $foreground;
    }

    Header {
        background: $background;
        color: $primary;
        text-style: bold;
    }

    /* A single quiet status line instead of a boxed, bold banner. */
    #status {
        height: 1;
        padding: 0 2;
        background: $background;
        color: $text-muted;
    }

    TabbedContent {
        height: 1fr;
    }
    Tabs {
        background: $background;
    }
    Tab {
        color: $text-muted;
        padding: 0 2;
    }

    /* Subtle bordered surfaces - no more neon outlines on every widget. */
    DataTable {
        background: $surface;
        color: $foreground;
        border: round $border;
        height: 1fr;
        scrollbar-size-vertical: 1;
    }
    DataTable:focus {
        border: round $primary;
    }
    DataTable > .datatable--header {
        background: $surface;
        color: $primary;
        text-style: bold;
    }
    DataTable > .datatable--cursor {
        background: $primary;
        color: $background;
        text-style: bold;
    }

    #log {
        height: 9;
        border: round $border;
        background: $surface;
        color: $foreground;
        padding: 0 1;
    }

    Footer {
        background: $background;
    }
    """

    # The footer deliberately shows only the five anchors - scope (setup),
    # run-all (the whole pipeline in one key), CVE lookup, help and quit.
    # The granular stage keys and the red-team actions still work; they're
    # kept out of the footer (show=False) and listed in the `?` overlay so
    # the status bar stays calm instead of spelling out a dozen shortcuts.
    BINDINGS = [
        Binding("s", "edit_scope", "Scope"),
        Binding("a", "run_all", "Run-all"),
        Binding("c", "cve_lookup", "CVEs"),
        Binding("question_mark", "show_help", "Help", key_display="?"),
        Binding("q", "quit", "Quit"),
        Binding("d", "run_discover", "Discover", show=False),
        Binding("D", "run_discover_deep", "Deep-scan", show=False),
        Binding("e", "run_enumerate", "Enumerate", show=False),
        Binding("m", "run_vuln_map", "Vuln-map", show=False),
        Binding("v", "run_validate", "Validate", show=False),
        Binding("r", "run_report", "Report", show=False),
        Binding("p", "redteam_plan", "Plan", show=False),
        Binding("x", "redteam_simulate", "Simulate", show=False),
    ]

    def __init__(self, cfg: Config, config_path: Path):
        super().__init__()
        self.cfg = cfg
        self.config_path = config_path
        self.store = Store(cfg.storage.db_path)
        self.redteam_store = RedTeamStore(self.store)
        self._signatures: object | None = None  # loaded on first use via .signatures
        self._tools_registered = False
        self.run_id: int | None = None
        self.redteam_plan: AttackPlan | None = None
        self._main_screen: Screen = None  # type: ignore[assignment]  # set in on_mount
        self._cve_detail_map: dict[object, tuple[str, str, CveResult]] = {}

    @property
    def signatures(self):
        """Offline signature dataset, parsed on first access (vuln-map /
        validate / plan) rather than in __init__ - keeps the TUI's cold
        start off the critical path to first paint."""
        if self._signatures is None:
            from scripter.intel.vuln_db import load_signatures

            self._signatures = load_signatures()
        return self._signatures

    def _ensure_tools(self) -> None:
        """Register the built-in red-team tools once, lazily. Pulls in the
        heavy executor/tool modules only when a tool actually runs."""
        if not self._tools_registered:
            from scripter.redteam import registry

            registry.ensure_builtin_tools_registered()
            self._tools_registered = True

    # --- layout ------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static(self._status_text(), id="status")
        with TabbedContent(initial="hosts", id="main_tabs"):
            with TabPane("Hosts", id="hosts"):
                yield DataTable(id="hosts_table", zebra_stripes=True, cursor_type="row")
            with TabPane("Services", id="services"):
                yield DataTable(id="services_table", zebra_stripes=True, cursor_type="row")
            with TabPane("Findings", id="findings"):
                yield DataTable(id="findings_table", zebra_stripes=True, cursor_type="row")
            with TabPane("CVEs", id="cves"):
                yield DataTable(id="cves_table", zebra_stripes=True, cursor_type="row")
            with TabPane("Red Team", id="redteam"):
                yield DataTable(id="redteam_table", zebra_stripes=True, cursor_type="row")
        with Vertical():
            yield RichLog(id="log", highlight=True, markup=True, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        # Register and switch to the Scripter theme first, so the very
        # first paint is already in the right palette (no neon flash).
        self.register_theme(SCRIPTER_THEME)
        self.theme = "scripter"
        # Captured once, while this dashboard screen is still the only one
        # on the stack. ServiceActionsScreen (and any other screen we push
        # later) sits *on top* of it - and App.query_one only ever searches
        # the current top-of-stack screen (App.children returns just that
        # one screen), so looking up "#redteam_table" etc. via self.query_one
        # once a modal is open raises NoMatches. Routing through this fixed
        # reference instead means those lookups keep working no matter what
        # screen is on top.
        self._main_screen = self.screen
        self._main_screen.query_one("#hosts_table", DataTable).add_columns("Host", "Open ports", "Discovered")
        self._main_screen.query_one("#services_table", DataTable).add_columns(
            "Host", "Port", "Service", "Version", "Banner"
        )
        self._main_screen.query_one("#findings_table", DataTable).add_columns(
            "#", "Score", "Host:Port", "Signature", "CVE", "Severity", "Status"
        )
        self._main_screen.query_one("#cves_table", DataTable).add_columns(
            "Service", "Version", "CVE", "Severity", "CVSS", "Summary"
        )
        self._main_screen.query_one("#redteam_table", DataTable).add_columns(
            "Host:Port", "Tool", "Manual review", "Status", "Evidence/Rationale"
        )
        self.run_id = self.store.latest_run_id()
        self._refresh_status()
        self._log(
            f"[bold {_ACCENT}]scripter[/] ready  ·  scope: {len(self.cfg.scope.hosts)} host(s)  ·  "
            f"press [bold {_ACCENT}]?[/] for the keymap"
        )
        if not self.cfg.scope.hosts:
            self._log(f"[{_WARN}]no scope set - press [b]s[/] to set \\[scope] targets before running discover[/]")
        # Paint the shell first, then pull any prior run's rows in on the
        # next frame - a populated database no longer blocks first paint.
        if self.run_id is not None:
            self.call_after_refresh(self._load_existing_run)

    def on_unmount(self) -> None:
        self.store.close()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Clicking (or pressing enter on) a Services row opens the
        red-team actions screen for that one host:port:service; clicking
        a CVEs row opens the detail screen for that one CVE hit."""
        if event.data_table.id == "services_table":
            host, port, service, _version, _banner = event.data_table.get_row(event.row_key)
            self.push_screen(
                ServiceActionsScreen(
                    host=str(host),
                    port=int(port),
                    service="" if service == "-" else str(service),
                    cfg=self.cfg,
                    run_id=self.run_id,
                    store=self.store,
                    redteam_store=self.redteam_store,
                )
            )
        elif event.data_table.id == "cves_table":
            detail = self._cve_detail_map.get(event.row_key)
            if detail is None:
                return
            service, version, result = detail
            self.push_screen(CveDetailScreen(service, version, result))

    def refresh_redteam_results(self) -> None:
        """Re-pull this run's saved redteam results into the Red Team
        tab - called after an ad-hoc tool run from ServiceActionsScreen
        so the table reflects what was just executed."""
        if self.run_id is None:
            return
        self._apply_redteam_results(self.redteam_store.load_results(self.run_id), log=False)

    # --- helpers -------------------------------------------------------

    def _log(self, message: str) -> None:
        self._main_screen.query_one("#log", RichLog).write(message)

    def _status_text(self) -> str:
        return (
            f"scope: {len(self.cfg.scope.hosts)} host(s)   "
            f"run: {self.run_id if self.run_id is not None else '-'}   "
            f"validate: {'enabled' if self.cfg.validate.enabled else 'disabled'}"
        )

    def _refresh_status(self) -> None:
        self._main_screen.query_one("#status", Static).update(self._status_text())

    def _load_existing_run(self) -> None:
        assert self.run_id is not None
        self._apply_discover(self.run_id, self.store.load_hosts(self.run_id), log=False)
        self._apply_enumerate(self.store.load_services(self.run_id), log=False)
        self._apply_findings(self.store.load_matches(self.run_id), log=False)
        self.redteam_plan = self.redteam_store.load_plan(self.run_id)
        if self.redteam_plan is not None:
            self._apply_redteam_plan(self.redteam_plan, log=False)
        results = self.redteam_store.load_results(self.run_id)
        if results:
            self._apply_redteam_results(results, log=False)

    # --- apply-result callbacks (run on the UI thread) ----------------

    def _apply_discover(self, run_id: int, hosts: list[Host], log: bool = True) -> None:
        self.run_id = run_id
        self._refresh_status()
        table = self._main_screen.query_one("#hosts_table", DataTable)
        table.clear()
        for h in hosts:
            table.add_row(h.ip, ", ".join(str(p) for p in h.open_ports) or "-", h.discovered_at.strftime("%H:%M:%S"))
        if log:
            self._log(f"[green]discover complete[/]: {len(hosts)} live host(s) - run {run_id}")

    def _apply_enumerate(self, findings: list[ServiceFinding], log: bool = True) -> None:
        table = self._main_screen.query_one("#services_table", DataTable)
        table.clear()
        for f in findings:
            banner = f.banner.replace("\n", " ").replace("\r", "")
            if len(banner) > 60:
                banner = banner[:60] + "..."
            table.add_row(f.host, str(f.port), f.service or "-", f.version or "-", banner or "-")
        if log:
            self._log(f"[green]enumerate complete[/]: {len(findings)} service(s)")

    def _apply_findings(self, matches: list[VulnMatch], log: bool = True) -> None:
        from scripter.prioritize import prioritize as prioritize_matches

        ranked = prioritize_matches(matches)
        table = self._main_screen.query_one("#findings_table", DataTable)
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

    def _apply_redteam_plan(self, plan: AttackPlan, log: bool = True) -> None:
        self.redteam_plan = plan
        table = self._main_screen.query_one("#redteam_table", DataTable)
        table.clear()
        for item in plan.items:
            table.add_row(
                f"{item.host}:{item.port}", item.tool_name, "yes" if item.manual_review_required else "no",
                "planned", item.rationale,
            )
        if log:
            self._log(
                f"[green]redteam plan complete[/]: {len(plan.items)} planned action(s), "
                f"{len(plan.skipped)} skipped"
            )
            for reason in plan.skipped:
                self._log(f"[dim]skipped: {reason}[/]")

    def _apply_redteam_results(self, results: list[ToolResult], log: bool = True) -> None:
        table = self._main_screen.query_one("#redteam_table", DataTable)
        table.clear()
        for r in results:
            style = _REDTEAM_STATUS_STYLE.get(r.status, "white")
            table.add_row(f"{r.host}:{r.port}", r.tool_name, "-", f"[{style}]{r.status.value}[/]", r.evidence)
        if log:
            self._log(f"[green]redteam execution complete[/]: {len(results)} result(s)")

    # --- pure pipeline steps (no UI access - safe to call off-thread) -

    def _do_discover(self) -> tuple[int, list[Host]]:
        from scripter.recon.discovery import discover_hosts

        run_id = self.store.start_run(str(self.config_path))
        hosts = discover_hosts(self.cfg.scope, self.cfg.scan.ports, self.cfg.scan.timeout_seconds, self.cfg.scan.max_concurrency)
        self.store.save_hosts(run_id, hosts)
        return run_id, hosts

    def _do_discover_deep(self) -> tuple[int, list[Host], list[ServiceFinding]]:
        """Full-port nmap sweep (``-Pn -sV -sC -p-``) in one pass: unlike
        ``_do_discover`` + ``_do_enumerate``, this starts a fresh run and
        populates both Hosts and Services directly from nmap's own
        detection, so filtered/firewalled ports show up too."""
        from scripter.recon.enumeration import deep_scan_hosts

        run_id = self.store.start_run(str(self.config_path))
        hosts, findings = deep_scan_hosts(self.cfg.scope, self.cfg.scan.deep_scan_timeout_seconds)
        self.store.save_hosts(run_id, hosts)
        self.store.save_services(run_id, findings)
        return run_id, hosts, findings

    def _do_enumerate(self, run_id: int) -> list[ServiceFinding]:
        from scripter.recon.enumeration import enumerate_services

        hosts = self.store.load_hosts(run_id)
        hosts_with_ports = {h.ip: h.open_ports for h in hosts}
        findings = enumerate_services(self.cfg.scope, hosts_with_ports, self.cfg.scan.timeout_seconds)
        self.store.save_services(run_id, findings)
        return findings

    def _do_vuln_map(self, run_id: int) -> list[VulnMatch]:
        from scripter.intel.matcher import match_findings

        findings = self.store.load_services(run_id)
        matches = match_findings(findings, self.signatures)
        self.store.clear_matches_for_run(run_id)
        self.store.save_matches(run_id, matches)
        return matches

    def _do_validate(self, run_id: int) -> list[VulnMatch]:
        from scripter.validation.checks import run_validation

        matches = self.store.load_matches(run_id)
        signature_checks = {s.id: s.check for s in self.signatures if s.check}
        updated = run_validation(matches, signature_checks, self.cfg.scope, self.cfg.validate.timeout_seconds)
        self.store.clear_matches_for_run(run_id)
        self.store.save_matches(run_id, updated)
        return updated

    def _do_redteam_plan(self, run_id: int) -> AttackPlan:
        from scripter.redteam.planner import build_plan

        self._ensure_tools()
        matches = self.store.load_matches(run_id)
        plan = build_plan(run_id, matches, self.signatures, self.cfg.scope)
        self.redteam_store.save_plan(plan)
        return plan

    def _do_redteam_simulate(self, plan: AttackPlan) -> list[ToolResult]:
        from scripter.redteam.executor import execute_item

        self._ensure_tools()
        results = [execute_item(item, self.cfg, simulate_only=True, run_id=plan.run_id) for item in plan.items]
        self.redteam_store.save_results(results)
        return results

    def _do_report(self, run_id: int) -> list[Path]:
        from scripter.prioritize import prioritize as prioritize_matches
        from scripter.reporting.report import write_csv, write_html, write_json

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

    def action_show_help(self) -> None:
        self.push_screen(HelpScreen())

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

    def action_run_discover_deep(self) -> None:
        from scripter.recon.enumeration import nmap_available

        if not self.cfg.scope.hosts:
            self._log("[red]no scope configured - press s to set \\[scope] targets[/]")
            return
        if not nmap_available():
            self._log("[red]nmap not found on PATH - deep-scan (-p-) needs nmap installed[/]")
            return
        self.worker_discover_deep()

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

    def action_redteam_plan(self) -> None:
        if self.run_id is None:
            self._log("[red]no run yet - press d first[/]")
            return
        self.worker_redteam_plan()

    def action_redteam_simulate(self) -> None:
        if not self.cfg.redteam.simulate_enabled:
            self._log("[yellow]\\[redteam] simulate_enabled = false - enable it in config to simulate[/]")
            return
        if self.redteam_plan is None or not self.redteam_plan.items:
            self._log("[red]no plan yet - press p first[/]")
            return
        self.worker_redteam_simulate()

    def action_cve_lookup(self) -> None:
        if self.run_id is None:
            self._log("[red]no run yet - press d first[/]")
            return
        if not self.cfg.intel.cve_lookup_enabled:
            self._log(
                "[yellow]\\[intel] cve_lookup_enabled = false - enable it in config to query the NVD CVE API[/]"
            )
            return
        services = self.store.load_services(self.run_id)
        if not services:
            self._log("[red]no services enumerated yet - press e to run enumerate first[/]")
            return
        self.worker_cve_lookup(services)

    # --- background workers -------------------------------------------

    @work(thread=True, exclusive=True)
    def worker_discover(self) -> None:
        self.call_from_thread(self._log, "[cyan]discover: sweeping scope...[/]")
        run_id, hosts = self._do_discover()
        self.call_from_thread(self._apply_discover, run_id, hosts)

    @work(thread=True, exclusive=True)
    def worker_discover_deep(self) -> None:
        self.call_from_thread(
            self._log,
            "[cyan]deep-scan: nmap -Pn -sV -sC -p- across scope (all 65535 ports/host - this can take a while)...[/]",
        )
        run_id, hosts, findings = self._do_discover_deep()
        self.call_from_thread(self._apply_discover, run_id, hosts)
        self.call_from_thread(self._apply_enumerate, findings)

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
    def worker_redteam_plan(self) -> None:
        assert self.run_id is not None
        self.call_from_thread(self._log, "[cyan]redteam plan: scoring matches, no network access...[/]")
        plan = self._do_redteam_plan(self.run_id)
        self.call_from_thread(self._apply_redteam_plan, plan)

    @work(thread=True, exclusive=True)
    def worker_redteam_simulate(self) -> None:
        assert self.redteam_plan is not None
        self.call_from_thread(self._log, "[cyan]redteam simulate: deterministic offline mock, no network access...[/]")
        results = self._do_redteam_simulate(self.redteam_plan)
        self.call_from_thread(self._apply_redteam_results, results)

    @work(thread=True, exclusive=False)
    def worker_cve_lookup(self, services: list[ServiceFinding]) -> None:
        from scripter.intel.cve_lookup import CveLookupError, lookup_cves

        pairs = sorted({(s.service, s.version or "") for s in services if s.service})
        pairs = pairs[: self.cfg.intel.cve_lookup_max_pairs]
        self.call_from_thread(
            self._log, f"[cyan]cve-lookup: querying NVD for {len(pairs)} service/version pair(s)...[/]"
        )
        grouped: list[tuple[str, str, list[CveResult] | None, str | None]] = []
        for i, (service, version) in enumerate(pairs):
            try:
                results = lookup_cves(
                    service, version or None,
                    timeout_seconds=self.cfg.intel.cve_lookup_timeout_seconds,
                    max_results=self.cfg.intel.cve_lookup_max_results,
                    api_key=self.cfg.intel.nvd_api_key or None,
                )
                grouped.append((service, version, results, None))
            except CveLookupError as exc:
                grouped.append((service, version, None, str(exc)))
            if i < len(pairs) - 1:
                time.sleep(self.cfg.intel.cve_lookup_delay_seconds)
        self.call_from_thread(self._apply_cve_results, grouped)

    def _apply_cve_results(self, grouped: list[tuple[str, str, list[CveResult] | None, str | None]]) -> None:
        table = self._main_screen.query_one("#cves_table", DataTable)
        table.clear()
        self._cve_detail_map = {}
        for service, version, results, error in grouped:
            if error is not None:
                table.add_row(service, version or "-", "-", "-", "-", f"[red]lookup failed: {error}[/]")
                continue
            if not results:
                table.add_row(service, version or "-", "-", "-", "-", "[dim]no CVEs found[/]")
                continue
            for r in results:
                severity = r.severity or "-"
                score = f"{r.cvss_score:.1f}" if r.cvss_score is not None else "-"
                summary = r.summary[:100] + ("..." if len(r.summary) > 100 else "")
                row_key = table.add_row(service, version or "-", r.cve_id, severity, score, summary)
                self._cve_detail_map[row_key] = (service, version, r)
        self._main_screen.query_one("#main_tabs", TabbedContent).active = "cves"
        self._log(f"[green]cve-lookup complete[/]: {len(grouped)} service/version pair(s) checked")

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
