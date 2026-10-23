"""Attack-vs-Defense service diagnostics: compares a run's recorded
host/port availability against the immediately previous run.

Local-database comparison only (scripter.storage.db.Store) - it adds no
new network probe beyond what discover/enumerate already recorded, and
never restarts, modifies, or disables anything.
"""
from __future__ import annotations

from scripter.storage.db import Store


def run(store: Store, run_id: int, host: str, port: int) -> str:
    current_hosts = {h.ip: h.open_ports for h in store.load_hosts(run_id)}
    previous_run_id = run_id - 1
    previous_hosts = (
        {h.ip: h.open_ports for h in store.load_hosts(previous_run_id)} if previous_run_id > 0 else {}
    )

    now_open = port in current_hosts.get(host, ())
    was_open = port in previous_hosts.get(host, ())

    if was_open and not now_open:
        return f"status_change=now_closed previous_run={previous_run_id} - port was open before, is not now"
    if now_open and not was_open:
        return f"status_change=newly_open previous_run={previous_run_id or 'n/a'}"
    if now_open and was_open:
        return f"status_change=unchanged_open previous_run={previous_run_id}"
    return f"status_change=unchanged_closed previous_run={previous_run_id or 'n/a'}"
