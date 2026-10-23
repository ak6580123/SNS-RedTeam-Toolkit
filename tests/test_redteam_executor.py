from scripter.config import load_config
from scripter.redteam.executor import execute_item
from scripter.redteam.models import AttackPlanItem, ExecutionStatus


def _item(tool="http_audit", host="127.0.0.1", port=1):
    return AttackPlanItem(
        host=host, port=port, service="http", signature_id="sig-a", tool_name=tool, rationale="r",
        prerequisites=(), planned_action="a", manual_review_required=False, source_status="hypothesis",
        source_score=1.0,
    )


def _cfg(tmp_path, extra=""):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        '[scope]\ntargets = ["127.0.0.1"]\n\n'
        f'[storage]\ndb_path = "{(tmp_path / "data" / "s.db").as_posix()}"\n\n'
        f'[logging]\nlog_dir = "{(tmp_path / "logs").as_posix()}"\n\n'
        f"{extra}"
    )
    return load_config(cfg_path)


def test_simulate_only_never_reaches_network_gates(tmp_path, monkeypatch):
    import socket

    def boom(*args, **kwargs):
        raise AssertionError("simulate_only must never open a socket")

    monkeypatch.setattr(socket, "create_connection", boom)
    cfg = _cfg(tmp_path, "[redteam]\nnetwork_audits_enabled = false\n")
    result = execute_item(_item(), cfg, simulate_only=True, run_id=1)
    assert result.simulated is True
    assert result.status in {
        ExecutionStatus.COMPLETED, ExecutionStatus.FAILED, ExecutionStatus.BLOCKED, ExecutionStatus.INCONCLUSIVE,
    }


def test_real_execution_blocked_when_network_audits_disabled(tmp_path):
    cfg = _cfg(tmp_path, "[redteam]\nnetwork_audits_enabled = false\n")
    result = execute_item(_item(), cfg, simulate_only=False, run_id=1)
    assert result.status == ExecutionStatus.BLOCKED
    assert "network_audits_enabled" in result.evidence


def test_real_execution_blocked_for_out_of_scope_host(tmp_path):
    cfg = _cfg(tmp_path, "[redteam]\nnetwork_audits_enabled = true\n")
    result = execute_item(_item(host="10.99.99.99"), cfg, simulate_only=False, run_id=1)
    assert result.status == ExecutionStatus.BLOCKED
    assert "not in the configured scope" in result.evidence


def test_authenticated_tool_blocked_when_validate_disabled(tmp_path):
    cfg = _cfg(tmp_path, "[redteam]\nnetwork_audits_enabled = true\n\n[validate]\nenabled = false\n")
    result = execute_item(_item(tool="ftp_audit", port=21), cfg, simulate_only=False, run_id=1)
    assert result.status == ExecutionStatus.BLOCKED
    assert "validate" in result.evidence


def test_tool_blocked_when_category_not_allowed(tmp_path):
    cfg = _cfg(
        tmp_path,
        '[redteam]\nnetwork_audits_enabled = true\nallowed_categories = ["tls"]\n',
    )
    result = execute_item(_item(tool="http_audit", port=1), cfg, simulate_only=False, run_id=1)
    assert result.status == ExecutionStatus.BLOCKED
    assert "allowed_categories" in result.evidence


def test_external_adapter_blocked_when_external_tools_disabled(tmp_path):
    cfg = _cfg(
        tmp_path,
        '[redteam]\nnetwork_audits_enabled = true\nexternal_tools_enabled = false\n'
        'allowed_categories = ["nmap"]\n',
    )
    result = execute_item(_item(tool="nmap_adapter", port=1), cfg, simulate_only=False, run_id=1)
    assert result.status == ExecutionStatus.BLOCKED
    assert "external_tools_enabled" in result.evidence


def test_tool_exception_degrades_to_failed_without_crashing(tmp_path, monkeypatch):
    from scripter.redteam.tools import http_audit

    def boom(*args, **kwargs):
        raise RuntimeError("simulated tool failure")

    monkeypatch.setattr(http_audit, "run", boom)
    cfg = _cfg(tmp_path, "[redteam]\nnetwork_audits_enabled = true\n")
    result = execute_item(_item(tool="http_audit", port=1), cfg, simulate_only=False, run_id=1)
    assert result.status == ExecutionStatus.FAILED
    assert result.error is not None
