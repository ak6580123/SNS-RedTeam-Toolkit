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
  intel/                Vulnerability intelligence
    vuln_db.py             Load/validate intel/data/signatures.json (offline)
    matcher.py             Match ServiceFinding -> VulnMatch (status=hypothesis)
    data/signatures.json    The bundled, honest-starting-set signature dataset
    cve_lookup.py          Online: keyword-search the public NVD CVE API for
                        a service/version pair - the one outbound call to a
                        third party anywhere in this codebase, gated by
                        [intel] cve_lookup_enabled (default false)
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

## The CVE lookup feature: the one call that leaves the lab

Everywhere else in this codebase, "network access" means a bounded,
scope-gated probe of a host inside `[scope]`. `intel/cve_lookup.py` is the
single exception: it queries the public NVD CVE API
(`services.nvd.nist.gov`) with a keyword built from an enumerated
service/version pair, to find real-world CVEs for it - a third party, not
a target.

Both entry points - the Findings tab's "Look up CVEs (NVD)" button/`c`
keybinding in `tui/app.py`, and the `scripter cve-lookup` CLI command -
check `[intel] cve_lookup_enabled` (default `false`) before calling
`lookup_cves`, the same opt-in pattern as `[validate] enabled` and
`[redteam] network_audits_enabled`. Both also cap the work per invocation
(`[intel] cve_lookup_max_pairs` distinct service/version pairs, each
capped to `cve_lookup_max_results` NVD records) and pace successive
queries with `cve_lookup_delay_seconds` to stay under NVD's public rate
limit. A lookup failure for one pair (bad network, HTTP error, timeout)
is caught and shown per-pair - it never aborts the rest of the batch, nor
is it ever confused with a `VulnMatch`'s offline `status`: NVD results are
informational cross-references, not something `validation/checks.py`
can promote to `CONFIRMED`.

## Why matches start at `HYPOTHESIS` and only checks can promote them

`intel.matcher.match_findings` never sets anything but `HYPOTHESIS` -
a banner/version match is a lead, not a finding. Only
`validation/checks.py`'s registered, non-destructive checks (and nothing
else in the codebase) can write `CONFIRMED`/`RULED_OUT`. This mirrors the
operating constraint to "clearly distinguish confirmed findings from
hypotheses" and keeps that distinction enforced in code, not just in
documentation.

## The redteam/ extension: planning, simulation, bounded audits

```
redteam/
  models.py      ToolDefinition, AttackPlan(Item), ToolResult, RedTeamEvent
  registry.py    name -> ToolDefinition, duplicate-id rejection, idempotent
                 ensure_builtin_tools_registered()
  planner.py     build_plan(): offline, deterministic VulnMatch -> AttackPlan
  executor.py    execute_item(): the ONLY place that dispatches to a real
                 tool or the simulator - every gate (network_audits_enabled,
                 external_tools_enabled, allowed_categories, validate
                 enabled, scope) lives here, in this order
  results.py     sanitize_evidence() (secret redaction + length cap),
                 to_event() (ToolResult -> RedTeamEvent)
  storage.py     RedTeamStore - extends the EXISTING Store's connection/
                 lock with its own tables, no second DB file
  tools/
    banner_probe.py   passive re-read via recon.enumeration.grab_banner
    http_audit.py     bounded GET via http.client (never auto-follows
                      redirects), security-header review
    tls_audit.py      cert metadata (real verification) + optional reuse
                      of the EXISTING tls_weak_protocol_check
    ftp_audit.py      passive banner + optional reuse of the EXISTING
                      ftp_anonymous_login_check
    redis_audit.py    passive banner + optional reuse of the EXISTING
                      redis_unauthenticated_check
    ssh_audit.py      passive SSH identification-string re-read + the
                      EXISTING openssh_legacy_version_check
    smtp_audit.py     one benign EHLO + QUIT - lists advertised
                      extensions/AUTH mechanisms, no mail sent
    mysql_audit.py    passive read of the unprompted MySQL handshake
                      packet - server version string, no login attempted
    nmap_adapter.py   thin wrapper over the EXISTING run_nmap_version_scan
    diagnostics.py    local-DB-only comparison against the previous run
    simulate.py       deterministic offline mock (sha256-seeded outcome)
```

`build_plan` never imports `socket`/`subprocess`/`http.client` - it only
reads the `VulnMatch` list `vuln-map` already produced and the offline
`Signature` dataset, maps each match's `service` to at most one tool
(`_SERVICE_TOOL_MAP`), reuses `prioritize.prioritize`'s own scoring so a
`CONFIRMED` match outranks a `HYPOTHESIS` one of equal severity, and skips
(with a recorded reason) anything out of scope, ruled out, unmapped, or
already covered by a higher-ranked finding on the same host:port.

`execute_item` is the single chokepoint for turning a plan item into a
`ToolResult`. `simulate_only=True` short-circuits straight to
`tools/simulate.py` before any gate runs. Otherwise, in order:
`network_audits_enabled` -> `external_tools_enabled` (adapters only) ->
`allowed_categories` -> `requires_validate_enabled` (ftp_audit/
redis_audit only) -> `scope.require_in_scope`. Any tool exception is
caught and degrades to `FAILED`, mirroring `validation.checks.run_validation`'s
own "a check failing must never crash the run" contract.

`redteam/storage.py`'s `RedTeamStore` does not open a second SQLite
connection: it takes the existing `Store`, extends its schema
(`redteam_plans`/`redteam_plan_items`/`redteam_plan_skipped`/
`redteam_results`), and reuses its connection/lock for every query -
one database file, one thread-safety story, same `run_id` scoping as
`hosts`/`services`/`vuln_matches`.

Every `ToolResult` can be projected into a `RedTeamEvent`
(`redteam/results.to_event`) - a stable, documented shape
(`event_id`/`run_id`/`timestamp`/`target`/`tool_name`/`action_category`/
`outcome`/`evidence`/`scope_decision`/`simulated`) intended for a future
blue/purple-team module to correlate against service-health checks and
detection rules. No such module exists yet; this only fixes the shape so
one could be added without reshaping `ToolResult` later.

## Why SQLite instead of files for pipeline results

Each pipeline stage needs to read back the previous stage's output
(`enumerate` reads `discover`'s hosts, `vuln-map` reads `enumerate`'s
services, `validate` and `report` read `vuln-map`'s matches), scoped to a
specific `run_id` so results from different sessions/targets don't mix.
SQLite gives transactional writes and simple `WHERE run_id = ?` queries
for that without inventing an ad-hoc file-naming/locking scheme.
