from typer.testing import CliRunner

from scripter.cli import app

runner = CliRunner()


def test_doctor_without_config_exits_usage_error(tmp_path):
    result = runner.invoke(app, ["doctor", "--config", str(tmp_path / "missing.toml")])
    assert result.exit_code == 2


def test_doctor_with_valid_config(tmp_path):
    log_dir = (tmp_path / "logs").as_posix()
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[scope]\ntargets = ["10.10.1.5"]\n\n[logging]\nlog_dir = "{log_dir}"\n')
    result = runner.invoke(app, ["doctor", "--config", str(cfg)])
    assert result.exit_code == 0
    assert "config OK" in result.stdout


def test_validate_refuses_when_disabled(tmp_path):
    log_dir = (tmp_path / "logs").as_posix()
    db_path = (tmp_path / "data" / "scripter.db").as_posix()
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f'[scope]\ntargets = ["10.10.1.5"]\n\n'
        f'[storage]\ndb_path = "{db_path}"\n\n'
        f'[logging]\nlog_dir = "{log_dir}"\n'
    )
    result = runner.invoke(app, ["validate", "--config", str(cfg)])
    assert result.exit_code == 2


def test_discover_against_loopback_closed_port_reports_no_hosts(tmp_path):
    log_dir = (tmp_path / "logs").as_posix()
    db_path = (tmp_path / "data" / "scripter.db").as_posix()
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f'[scope]\ntargets = ["127.0.0.1"]\n\n'
        f'[storage]\ndb_path = "{db_path}"\n\n'
        f'[logging]\nlog_dir = "{log_dir}"\n\n'
        f'[scan]\nports = [55443]\ntimeout_seconds = 1.0\n'
    )
    result = runner.invoke(app, ["discover", "--config", str(cfg)])
    assert result.exit_code == 0
    assert "no live hosts found in scope" in result.stdout
