"""SQLite-backed persistence for discovery/enumeration/vuln-match results.

One run = one pipeline invocation (``scripter run-all`` or a manual
discover/enumerate/vuln-map/validate sequence), tagged with a run_id so
results from different competition sessions or targets don't silently mix
in a report. All queries are parameterized - no f-string/``.format()`` SQL
construction anywhere.
"""
from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from pathlib import Path

from scripter.models import Exploitability, Host, MatchStatus, Severity, ServiceFinding, VulnMatch

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    config_path TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    run_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    open_ports TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

CREATE TABLE IF NOT EXISTS services (
    run_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service TEXT,
    version TEXT,
    banner TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

CREATE TABLE IF NOT EXISTS vuln_matches (
    run_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    service TEXT NOT NULL,
    version TEXT,
    signature_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    exploitability TEXT NOT NULL,
    time_to_validate_minutes INTEGER NOT NULL,
    status TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence TEXT NOT NULL,
    matched_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);
"""


class Store:
    """Not just single-process but single-connection-shared-across-threads
    safe: the CLI only ever touches a Store from one thread, but the TUI's
    background workers (``@work(thread=True)`` in tui/app.py) call the same
    Store instance from whichever worker thread is currently running a
    pipeline stage. ``check_same_thread=False`` plus ``self._lock`` around
    every method make that safe without needing a connection per thread.
    """

    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def start_run(self, config_path: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO runs (started_at, config_path) VALUES (?, ?)",
                (dt.datetime.now(dt.timezone.utc).isoformat(), config_path),
            )
            self._conn.commit()
            return cur.lastrowid

    def latest_run_id(self) -> int | None:
        with self._lock:
            row = self._conn.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 1").fetchone()
            return row[0] if row else None

    def save_hosts(self, run_id: int, hosts: list[Host]) -> None:
        with self._lock:
            self._conn.executemany(
                "INSERT INTO hosts (run_id, ip, discovered_at, open_ports) VALUES (?, ?, ?, ?)",
                [
                    (run_id, h.ip, h.discovered_at.isoformat(), ",".join(str(p) for p in h.open_ports))
                    for h in hosts
                ],
            )
            self._conn.commit()

    def load_hosts(self, run_id: int) -> list[Host]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, discovered_at, open_ports FROM hosts WHERE run_id = ? ORDER BY ip", (run_id,)
            ).fetchall()
        return [
            Host(
                ip=ip,
                discovered_at=dt.datetime.fromisoformat(discovered_at),
                open_ports=tuple(int(p) for p in open_ports.split(",") if p),
            )
            for ip, discovered_at, open_ports in rows
        ]

    def save_services(self, run_id: int, findings: list[ServiceFinding]) -> None:
        with self._lock:
            self._conn.executemany(
                """INSERT INTO services (run_id, host, port, protocol, service, version, banner, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (run_id, f.host, f.port, f.protocol, f.service, f.version, f.banner, f.discovered_at.isoformat())
                    for f in findings
                ],
            )
            self._conn.commit()

    def load_services(self, run_id: int) -> list[ServiceFinding]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT host, port, protocol, service, version, banner, discovered_at
                   FROM services WHERE run_id = ? ORDER BY host, port""",
                (run_id,),
            ).fetchall()
        return [
            ServiceFinding(
                host=host, port=port, protocol=protocol, service=service, version=version,
                banner=banner, discovered_at=dt.datetime.fromisoformat(discovered_at),
            )
            for host, port, protocol, service, version, banner, discovered_at in rows
        ]

    def save_matches(self, run_id: int, matches: list[VulnMatch]) -> None:
        with self._lock:
            self._conn.executemany(
                """INSERT INTO vuln_matches
                   (run_id, host, port, service, version, signature_id, cve_id, description, severity,
                    exploitability, time_to_validate_minutes, status, confidence, evidence, matched_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id, m.host, m.port, m.service, m.version, m.signature_id, m.cve_id, m.description,
                        m.severity.value, m.exploitability.value, m.time_to_validate_minutes, m.status.value,
                        m.confidence, m.evidence, m.matched_at.isoformat(),
                    )
                    for m in matches
                ],
            )
            self._conn.commit()

    def load_matches(self, run_id: int) -> list[VulnMatch]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT host, port, service, version, signature_id, cve_id, description, severity,
                          exploitability, time_to_validate_minutes, status, confidence, evidence, matched_at
                   FROM vuln_matches WHERE run_id = ? ORDER BY host, port""",
                (run_id,),
            ).fetchall()
        return [
            VulnMatch(
                host=host, port=port, service=service, version=version, signature_id=signature_id,
                cve_id=cve_id, description=description, severity=Severity(severity),
                exploitability=Exploitability(exploitability), time_to_validate_minutes=ttv,
                status=MatchStatus(status), confidence=confidence, evidence=evidence,
                matched_at=dt.datetime.fromisoformat(matched_at),
            )
            for (
                host, port, service, version, signature_id, cve_id, description, severity,
                exploitability, ttv, status, confidence, evidence, matched_at,
            ) in rows
        ]

    def clear_matches_for_run(self, run_id: int) -> None:
        """Used by ``validate`` to replace hypothesis-stage matches with
        their validated versions in place, instead of accumulating
        duplicates on repeated runs."""
        with self._lock:
            self._conn.execute("DELETE FROM vuln_matches WHERE run_id = ?", (run_id,))
            self._conn.commit()
