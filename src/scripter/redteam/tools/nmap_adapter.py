"""Thin adapter over the EXISTING nmap -sV wrapper.

All argument construction, hostname-injection protection, and subprocess
safety (argument list, no shell=True, explicit timeout, no NSE scripts)
live in recon.enumeration.run_nmap_version_scan - this module adds no new
nmap flags or scan logic, it only maps that function's result dict onto
the redteam ToolResult shape.
"""
from __future__ import annotations

from scripter.recon.enumeration import nmap_available, run_nmap_version_scan
from scripter.redteam.results import sanitize_evidence
from scripter.scope import Scope


def run(host: str, ports: tuple[int, ...], scope: Scope, *, timeout_seconds: int = 120) -> str:
    if not nmap_available():
        return "nmap not found on PATH"
    result = run_nmap_version_scan(host, ports, scope, timeout_seconds=timeout_seconds)
    status = result["status"]
    if status == "done":
        return sanitize_evidence(f"nmap -sV completed | {result['output'][:2000]}")
    return sanitize_evidence(f"nmap -sV {status}: {result.get('error', '')}")
