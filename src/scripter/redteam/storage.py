"""Red-team persistence, layered on the existing Store's connection/lock.

One SQLite file, one thread-safety story: RedTeamStore does not open a
second database connection and does not invent a second locking scheme -
it extends the same scripter.storage.db.Store the base pipeline already
uses with its own tables, reusing ``store.connection``/``store.lock``.
All queries are parameterized, matching storage/db.py's own convention.
"""
from __future__ import annotations

import datetime as dt

from scripter.redteam.models import AttackPlan, AttackPlanItem, ExecutionStatus, ToolResult
from scripter.storage.db import Store

_SCHEMA = """
CREATE TABLE IF NOT EXISTS redteam_plans (
    run_id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

CREATE TABLE IF NOT EXISTS redteam_plan_items (
    run_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    service TEXT NOT NULL,
    signature_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    rationale TEXT NOT NULL,
    prerequisites TEXT NOT NULL,
    planned_action TEXT NOT NULL,
    manual_review_required INTEGER NOT NULL,
    source_status TEXT NOT NULL,
    source_score REAL NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

CREATE TABLE IF NOT EXISTS redteam_plan_skipped (
    run_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

CREATE TABLE IF NOT EXISTS redteam_results (
    run_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    tool_name TEXT NOT NULL,
    status TEXT NOT NULL,
    simulated INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    evidence TEXT NOT NULL,
    error TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);
"""


class RedTeamStore:
    def __init__(self, store: Store):
        self._store = store
        with store.lock:
            store.connection.executescript(_SCHEMA)
            store.connection.commit()

    def save_plan(self, plan: AttackPlan) -> None:
        conn, lock = self._store.connection, self._store.lock
        with lock:
            conn.execute("DELETE FROM redteam_plan_items WHERE run_id = ?", (plan.run_id,))
            conn.execute("DELETE FROM redteam_plan_skipped WHERE run_id = ?", (plan.run_id,))
            conn.execute("DELETE FROM redteam_plans WHERE run_id = ?", (plan.run_id,))
            conn.execute(
                "INSERT INTO redteam_plans (run_id, created_at) VALUES (?, ?)",
                (plan.run_id, plan.created_at.isoformat()),
            )
            conn.executemany(
                """INSERT INTO redteam_plan_items
                   (run_id, host, port, service, signature_id, tool_name, rationale, prerequisites,
                    planned_action, manual_review_required, source_status, source_score)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        plan.run_id, it.host, it.port, it.service, it.signature_id, it.tool_name, it.rationale,
                        "|".join(it.prerequisites), it.planned_action, int(it.manual_review_required),
                        it.source_status, it.source_score,
                    )
                    for it in plan.items
                ],
            )
            conn.executemany(
                "INSERT INTO redteam_plan_skipped (run_id, reason) VALUES (?, ?)",
                [(plan.run_id, reason) for reason in plan.skipped],
            )
            conn.commit()

    def load_plan(self, run_id: int) -> AttackPlan | None:
        conn, lock = self._store.connection, self._store.lock
        with lock:
            meta = conn.execute("SELECT created_at FROM redteam_plans WHERE run_id = ?", (run_id,)).fetchone()
            if meta is None:
                return None
            item_rows = conn.execute(
                """SELECT host, port, service, signature_id, tool_name, rationale, prerequisites,
                          planned_action, manual_review_required, source_status, source_score
                   FROM redteam_plan_items WHERE run_id = ? ORDER BY host, port""",
                (run_id,),
            ).fetchall()
            skipped_rows = conn.execute(
                "SELECT reason FROM redteam_plan_skipped WHERE run_id = ?", (run_id,)
            ).fetchall()

        items = tuple(
            AttackPlanItem(
                host=host, port=port, service=service, signature_id=signature_id, tool_name=tool_name,
                rationale=rationale, prerequisites=tuple(p for p in prerequisites.split("|") if p),
                planned_action=planned_action, manual_review_required=bool(manual_review_required),
                source_status=source_status, source_score=source_score,
            )
            for (
                host, port, service, signature_id, tool_name, rationale, prerequisites, planned_action,
                manual_review_required, source_status, source_score,
            ) in item_rows
        )
        return AttackPlan(
            run_id=run_id,
            created_at=dt.datetime.fromisoformat(meta[0]),
            items=items,
            skipped=tuple(r[0] for r in skipped_rows),
        )

    def save_results(self, results: list[ToolResult]) -> None:
        conn, lock = self._store.connection, self._store.lock
        with lock:
            conn.executemany(
                """INSERT INTO redteam_results
                   (run_id, host, port, tool_name, status, simulated, started_at, finished_at, evidence, error)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        r.run_id, r.host, r.port, r.tool_name, r.status.value, int(r.simulated),
                        r.started_at.isoformat(), r.finished_at.isoformat(), r.evidence, r.error,
                    )
                    for r in results
                ],
            )
            conn.commit()

    def load_results(self, run_id: int) -> list[ToolResult]:
        conn, lock = self._store.connection, self._store.lock
        with lock:
            rows = conn.execute(
                """SELECT host, port, tool_name, status, simulated, started_at, finished_at, evidence, error
                   FROM redteam_results WHERE run_id = ? ORDER BY host, port""",
                (run_id,),
            ).fetchall()
        return [
            ToolResult(
                run_id=run_id, host=host, port=port, tool_name=tool_name, status=ExecutionStatus(status),
                simulated=bool(simulated), started_at=dt.datetime.fromisoformat(started_at),
                finished_at=dt.datetime.fromisoformat(finished_at), evidence=evidence, error=error,
            )
            for (host, port, tool_name, status, simulated, started_at, finished_at, evidence, error) in rows
        ]
