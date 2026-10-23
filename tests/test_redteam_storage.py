import datetime as dt

from scripter.redteam.models import AttackPlan, AttackPlanItem, ExecutionStatus, ToolResult
from scripter.redteam.storage import RedTeamStore
from scripter.storage.db import Store


def _item() -> AttackPlanItem:
    return AttackPlanItem(
        host="10.10.1.5", port=80, service="http", signature_id="sig-a", tool_name="http_audit",
        rationale="r", prerequisites=("[validate] enabled = true",), planned_action="run http_audit",
        manual_review_required=True, source_status="hypothesis", source_score=1.23,
    )


def test_plan_round_trip(tmp_path):
    store = Store(tmp_path / "s.db")
    run_id = store.start_run("cfg")
    rt = RedTeamStore(store)
    plan = AttackPlan(
        run_id=run_id, created_at=dt.datetime.now(dt.timezone.utc), items=(_item(),), skipped=("reason one",)
    )
    rt.save_plan(plan)
    loaded = rt.load_plan(run_id)
    store.close()

    assert loaded is not None
    assert loaded.items == plan.items
    assert loaded.skipped == plan.skipped
    assert loaded.created_at == plan.created_at


def test_load_plan_returns_none_when_absent(tmp_path):
    store = Store(tmp_path / "s.db")
    run_id = store.start_run("cfg")
    rt = RedTeamStore(store)
    assert rt.load_plan(run_id) is None
    store.close()


def test_results_round_trip(tmp_path):
    store = Store(tmp_path / "s.db")
    run_id = store.start_run("cfg")
    rt = RedTeamStore(store)
    now = dt.datetime.now(dt.timezone.utc)
    result = ToolResult(
        run_id=run_id, host="10.10.1.5", port=80, tool_name="http_audit", status=ExecutionStatus.COMPLETED,
        simulated=True, started_at=now, finished_at=now, evidence="SIMULATED: ok", error=None,
    )
    rt.save_results([result])
    loaded = rt.load_results(run_id)
    store.close()

    assert loaded == [result]


def test_save_plan_replaces_previous_plan_for_same_run(tmp_path):
    store = Store(tmp_path / "s.db")
    run_id = store.start_run("cfg")
    rt = RedTeamStore(store)
    rt.save_plan(AttackPlan(run_id=run_id, created_at=dt.datetime.now(dt.timezone.utc), items=(_item(),), skipped=()))
    rt.save_plan(
        AttackPlan(run_id=run_id, created_at=dt.datetime.now(dt.timezone.utc), items=(), skipped=("skip-reason",))
    )
    loaded = rt.load_plan(run_id)
    store.close()

    assert loaded.items == ()
    assert loaded.skipped == ("skip-reason",)


def test_plans_for_different_runs_do_not_mix(tmp_path):
    store = Store(tmp_path / "s.db")
    run_a = store.start_run("cfg")
    run_b = store.start_run("cfg")
    rt = RedTeamStore(store)
    rt.save_plan(AttackPlan(run_id=run_a, created_at=dt.datetime.now(dt.timezone.utc), items=(_item(),), skipped=()))
    loaded_a = rt.load_plan(run_a)
    loaded_b = rt.load_plan(run_b)
    store.close()

    assert loaded_a is not None and len(loaded_a.items) == 1
    assert loaded_b is None
