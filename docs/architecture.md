# Architecture

## Layers

```
scripter/
  cli.py              Typer CLI: one command per pipeline stage, shared --config
  scope.py             Explicit-opt-in scope validation (the one choke point
                        every active command must pass through)
  config.py            TOML config loading + validation (stdlib tomllib)
  logging_setup.py      Rotating file + console logging
  models.py             Shared dataclasses: Host, ServiceFinding, VulnMatch,
                        PrioritizedFinding, Severity, MatchStatus, Exploitability
  recon/                Active probing - always scope-gated
    discovery.py          TCP-connect host/port sweep, bounded concurrency
    enumeration.py         Banner grab + regex-based service/version parsing,
                        optional `nmap -sV` wrapper
  intel/                Offline vulnerability intelligence
    vuln_db.py             Load/validate intel/data/signatures.json
    matcher.py             Match ServiceFinding -> VulnMatch (status=hypothesis)
    data/signatures.json    The bundled, honest-starting-set signature dataset
  validation/            Non-destructive proof-of-vulnerability checks
    checks.py              3 registered checks + run_validation orchestration
  prioritize.py          Score/rank VulnMatch by severity x confidence x
                        exploitability / time-to-validate
  storage/               Local persistence
    db.py                  SQLite: runs/hosts/services/vuln_matches tables
  reporting/              Offline report generation
    report.py               JSON/CSV writers + escaped static HTML
```

## Data flow for `scripter run-all`

1. `cli.run_all` opens a `Store`, starts a new `run_id`.
2. `recon.discovery.discover_hosts` sweeps every host in `cfg.scope` across
   `cfg.scan.ports` with bounded `ThreadPoolExecutor` concurrency - plain
   TCP connects only. Results are saved as `Host` rows.
3. `recon.enumeration.enumerate_services` grabs a banner (and, for
   HTTP(S) ports, sends one benign `GET /` probe) for every open port the
   sweep found, then `parse_service` (a pure, network-free function)
   extracts a service name/version from the banner text via regex.
   Optionally, `run_nmap_version_scan` adds an `nmap -sV` pass. Results
   are saved as `ServiceFinding` rows.
4. `intel.matcher.match_findings` matches each finding's
   service/version against `intel.vuln_db.load_signatures()`'s bundled
   dataset, producing `VulnMatch` records all starting at
   `MatchStatus.HYPOTHESIS`.
5. If `--validate` was passed and `[validate] enabled = true`,
   `validation.checks.run_validation` runs the registered check for any
   match whose signature names one, promoting it to `CONFIRMED`,
   `RULED_OUT`, or `INCONCLUSIVE` with a logged evidence note. A check
   that raises is caught and degrades to `INCONCLUSIVE` - it never
   crashes the run.
6. `prioritize.prioritize` scores and sorts every `VulnMatch`.
7. `reporting.report.write_json/write_csv/write_html` export the ranked
   list to `[storage] reports_dir`.

## Why every active function takes `scope` and re-validates

`scope.require_in_scope` is called inside `discover_hosts`,
`enumerate_services`, `run_nmap_version_scan`, and every function in
`validation/checks.py` - not just once at the CLI entry point. This is
deliberate defense in depth: if a future caller (a new command, a bug in
run-all's loop) ever constructs a target list some other way, it still
cannot reach a host outside the configured scope without
`scope.ScopeError` stopping it first.

## Why matches start at `HYPOTHESIS` and only checks can promote them

`intel.matcher.match_findings` never sets anything but `HYPOTHESIS` -
a banner/version match is a lead, not a finding. Only
`validation/checks.py`'s registered, non-destructive checks (and nothing
else in the codebase) can write `CONFIRMED`/`RULED_OUT`. This mirrors the
operating constraint to "clearly distinguish confirmed findings from
hypotheses" and keeps that distinction enforced in code, not just in
documentation.

## Why SQLite instead of files for pipeline results

Each pipeline stage needs to read back the previous stage's output
(`enumerate` reads `discover`'s hosts, `vuln-map` reads `enumerate`'s
services, `validate` and `report` read `vuln-map`'s matches), scoped to a
specific `run_id` so results from different sessions/targets don't mix.
SQLite gives transactional writes and simple `WHERE run_id = ?` queries
for that without inventing an ad-hoc file-naming/locking scheme.
