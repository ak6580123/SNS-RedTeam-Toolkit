import datetime as dt
from pathlib import Path

from typer.testing import CliRunner

from scripter.cli import app
from scripter.models import Exploitability, MatchStatus, Severity, VulnMatch
from scripter.storage.db import Store

runner = CliRunner()


def _write_cfg(tmp_path, extra: str = ""):
    log_dir = (tmp_path / "logs").as_posix()
    db_path = (tmp_path / "data" / "scripter.db").as_posix()
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        '[scope]\ntargets = ["127.0.0.1"]\n\n'
        f'[storage]\ndb_path = "{db_path}"\n\n'
        f'[logging]\nlog_dir = "{log_dir}"\n\n'
        f"{extra}"
    )
    return cfg, db_path


def test_list_tools_works_fully_offline_without_config():
    result = runner.invoke(app, ["redteam", "list-tools"])
    assert result.exit_code == 0
    assert "http_audit" in result.stdout


def test_plan_without_a_run_exits_with_runtime_error(tmp_path):
    cfg, _ = _write_cfg(tmp_path)
    result = runner.invoke(app, ["redteam", "plan", "--config", str(cfg)])
    assert result.exit_code == 1


def test_simulate_refuses_when_disabled(tmp_path):
    cfg, _ = _write_cfg(tmp_path, "[redteam]\nsimulate_enabled = false\n")
    result = runner.invoke(app, ["redteam", "simulate", "--config", str(cfg)])
    assert result.exit_code == 2


def test_audit_http_rejects_out_of_scope_host(tmp_path):
    cfg, _ = _write_cfg(tmp_path)
    result = runner.invoke(app, ["redteam", "audit-http", "--config", str(cfg), "--host", "10.99.99.99"])
    assert result.exit_code == 2


def test_audit_http_reports_blocked_when_network_audits_disabled(tmp_path):
    cfg, _ = _write_cfg(tmp_path, "[redteam]\nnetwork_audits_enabled = false\n")
    result = runner.invoke(
        app, ["redteam", "audit-http", "--config", str(cfg), "--host", "127.0.0.1", "--port", "59999"]
    )
    assert result.exit_code == 0
    assert "blocked" in result.stdout


def test_audit_ssh_reports_blocked_when_network_audits_disabled(tmp_path):
    cfg, _ = _write_cfg(tmp_path, "[redteam]\nnetwork_audits_enabled = false\n")
    result = runner.invoke(
        app, ["redteam", "audit-ssh", "--config", str(cfg), "--host", "127.0.0.1", "--port", "59999"]
    )
    assert result.exit_code == 0
    assert "blocked" in result.stdout


def test_audit_smtp_reports_blocked_when_network_audits_disabled(tmp_path):
    cfg, _ = _write_cfg(tmp_path, "[redteam]\nnetwork_audits_enabled = false\n")
    result = runner.invoke(
        app, ["redteam", "audit-smtp", "--config", str(cfg), "--host", "127.0.0.1", "--port", "59999"]
    )
    assert result.exit_code == 0
    assert "blocked" in result.stdout


def test_audit_mysql_reports_blocked_when_network_audits_disabled(tmp_path):
    cfg, _ = _write_cfg(tmp_path, "[redteam]\nnetwork_audits_enabled = false\n")
    result = runner.invoke(
        app, ["redteam", "audit-mysql", "--config", str(cfg), "--host", "127.0.0.1", "--port", "59999"]
    )
    assert result.exit_code == 0
    assert "blocked" in result.stdout


def test_audit_mysql_rejects_out_of_scope_host(tmp_path):
    cfg, _ = _write_cfg(tmp_path)
    result = runner.invoke(app, ["redteam", "audit-mysql", "--config", str(cfg), "--host", "10.99.99.99"])
    assert result.exit_code == 2


def test_plan_then_simulate_full_flow(tmp_path):
    cfg, db_path = _write_cfg(tmp_path)
    with Store(Path(db_path)) as store:
        run_id = store.start_run(str(cfg))
        match = VulnMatch(
            host="127.0.0.1", port=80, service="http", version=None, signature_id="tls-weak-protocol",
            cve_id="N/A", description="d", severity=Severity.MEDIUM, exploitability=Exploitability.MODERATE,
            time_to_validate_minutes=5, status=MatchStatus.HYPOTHESIS, confidence=0.3, evidence="banner",
            matched_at=dt.datetime.now(dt.timezone.utc),
        )
        store.save_matches(run_id, [match])

    plan_result = runner.invoke(app, ["redteam", "plan", "--config", str(cfg)])
    assert plan_result.exit_code == 0
    assert "http_audit" in plan_result.stdout

    sim_result = runner.invoke(app, ["redteam", "simulate", "--config", str(cfg)])
    assert sim_result.exit_code == 0
    assert "SIMULATED" in sim_result.stdout


def test_diagnostics_without_a_run_exits_with_runtime_error(tmp_path):
    cfg, _ = _write_cfg(tmp_path)
    result = runner.invoke(app, ["redteam", "diagnostics", "--config", str(cfg)])
    assert result.exit_code == 1
