"""Red-team planning/simulation/audit extension to the base
discover -> enumerate -> vuln-map -> validate -> report pipeline.

Adds: attack-plan (offline, deterministic) -> execute (simulated or real,
scope-gated, non-destructive) -> report. See docs/architecture.md for how
this layers on top of the existing pipeline without a second scope or
storage implementation.
"""
