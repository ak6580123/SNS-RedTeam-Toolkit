from scripter.redteam.models import AttackPlanItem, ExecutionStatus
from scripter.redteam.tools import simulate


def _item(host="10.10.1.5", port=80, tool="http_audit", sig="sig-a"):
    return AttackPlanItem(
        host=host, port=port, service="http", signature_id=sig, tool_name=tool, rationale="r",
        prerequisites=(), planned_action="a", manual_review_required=False, source_status="hypothesis",
        source_score=1.0,
    )


def test_simulation_is_deterministic_for_identical_input():
    item = _item()
    status1, evidence1 = simulate.run(item)
    status2, evidence2 = simulate.run(item)
    assert status1 == status2
    assert evidence1 == evidence2


def test_simulation_evidence_is_clearly_labelled_as_simulated():
    _status, evidence = simulate.run(_item())
    assert evidence.startswith("SIMULATED:")


def test_simulation_never_opens_a_socket(monkeypatch):
    import socket

    def boom(*args, **kwargs):
        raise AssertionError("simulate must never touch the network")

    monkeypatch.setattr(socket, "create_connection", boom)
    simulate.run(_item())


def test_simulation_covers_more_than_one_outcome_across_inputs():
    outcomes = {simulate.run(_item(port=p))[0] for p in range(1, 60)}
    assert len(outcomes) > 1


def test_simulation_status_is_always_a_documented_outcome():
    status, _evidence = simulate.run(_item())
    assert status in {
        ExecutionStatus.COMPLETED, ExecutionStatus.FAILED, ExecutionStatus.BLOCKED, ExecutionStatus.INCONCLUSIVE,
    }
