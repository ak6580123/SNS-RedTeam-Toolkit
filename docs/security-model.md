# Security Model

## No default scope, ever

Every active command (`discover`, `enumerate`, `validate`, and the
`nmap -sV` wrapper) requires `[scope] targets` to be a non-empty,
explicitly configured list (`scope.py`, `config.py`). There is no
fallback to "the current subnet" or any other implicit target. A missing
or empty config fails loudly (`ConfigError`/`ScopeError`), never silently.

Public (non-private, non-loopback, non-link-local) addresses are rejected
unless `[scope] allow_public = true` is set explicitly - this is meant for
the case where a competition assigns a public range, not as a default.

A CIDR range that would expand past `[scope] max_hosts` (default 4096) is
rejected, so a typo like `0.0.0.0/0` cannot silently become an
internet-wide sweep.

Every active function (`recon.discovery.discover_hosts`,
`recon.enumeration.enumerate_services`/`run_nmap_version_scan`, and every
check in `validation/checks.py`) calls `scope.require_in_scope` on its
target immediately before acting - defense in depth beyond the one
check at CLI startup.

The `tui` command is the one exception to "checked at startup": it loads
with `allow_empty_scope=True` (`config.load_config`) so the dashboard
shell itself can open with no targets configured yet, and lets the
operator set `[scope] targets` from inside the TUI (`s` key, see
`tui/app.py`'s `ScopeEditorScreen`) instead of hand-editing the file
first. The empty-scope bypass only ever produces a `Scope` with zero
hosts - it never skips `parse_scope`'s validation once targets are
entered - and every TUI action that would touch the network
(`action_run_discover`/`action_run_all`) checks `self.cfg.scope.hosts`
is non-empty before starting a worker, so no probe can fire with an
unset scope. Targets entered in the TUI are also written back to the
config file (`config.write_scope_targets`) so they survive a restart.

## What Scripter never does automatically

- Raw-socket or SYN scanning, ICMP floods, packet injection, or any form
  of traffic designed to evade detection.
- Credential brute forcing of any kind (no wordlists, no iterating
  default-credential lists against a login form).
- Triggering a known backdoor (e.g. the vsftpd 2.3.4 smiley-face USER
  trigger, the UnrealIRCd backdoor) - these are flagged as
  `hypothesis`/manual-review signatures with `"check": null` in
  `intel/data/signatures.json`, specifically so no automated code path
  can fire them.
- Any protocol exploit that reads or writes target memory, files, or
  process state (no RCE payloads, no memory-disclosure primitives).
- Destructive actions of any kind: nothing in this codebase deletes,
  modifies, or uploads anything to a target.

## The 3 non-destructive validation checks, and why they're safe

`validation/checks.py` implements exactly three automated checks, each
gated behind `[validate] enabled = true` in config:

- **`ftp_anonymous_login_check`**: sends `USER anonymous` /
  `PASS anonymous@...` and `QUIT`. This authenticates with the public,
  deliberately non-privileged identity the FTP protocol itself defines
  for this purpose. No file is listed, uploaded, downloaded, or deleted.
- **`redis_unauthenticated_check`**: sends a bare `PING`. A `+PONG` reply
  proves commands are accepted without authentication. No write command
  (`SET`/`FLUSHALL`/`CONFIG`/etc.) is ever issued.
- **`tls_weak_protocol_check`**: performs a TLS handshake restricted to
  SSLv3/TLS1.0 only, and reads back the negotiated version. A handshake
  reveals and changes nothing on the target beyond the connection itself.

Every check function has the same signature and contract
(`(VulnMatch, Scope, timeout) -> (MatchStatus, confidence, evidence_note)`)
and is wrapped in `run_validation`, which catches any exception and
degrades the result to `INCONCLUSIVE` rather than ever crashing a run or
retrying aggressively.

## Subprocess safety (optional nmap integration)

`recon.enumeration.run_nmap_version_scan` is the only module that shells
out (to `nmap`). Safety properties, matching the pattern used for every
other subprocess call in this kind of tool:

- `subprocess.run` is always called with an **argument list**, never
  `shell=True` or a concatenated shell string.
- The host argument is validated against a strict pattern (`_HOST_RE`,
  no leading `-`) before it reaches `nmap`'s argv, so a malformed/crafted
  target string can never be smuggled in as a flag.
- Only `-sV` (service/version detection) is ever passed - no NSE
  vulnerability/exploit scripts, no `-sS` raw-socket scanning, no root
  privilege requirement.
- Every subprocess call has an explicit `timeout_seconds`.
- stdout/stderr are captured, not inherited, and never `eval`'d or
  interpreted as further commands.

## Input validation and config safety

- `config.py` validates every field (scope entries, port ranges, log
  level, positive integers) at load time - a malformed config fails fast
  with a clear `ConfigError`, never a silent default or a crash deep in a
  collector.
- `intel/vuln_db.py` validates every signature's `severity`,
  `exploitability`, `confidence_base` range, and required fields at load
  time, and rejects duplicate signature ids.
- `storage/db.py` uses parameterized queries exclusively - no
  f-string/`.format()` SQL construction anywhere.
- `reporting/report.py`'s HTML output escapes every interpolated value
  with `html.escape` before writing it into a report - evidence pulled
  from a banner or description can never inject markup.

## Logging

`logging_setup.py` logs to console and a rotating local file only. No
credentials or full environment variable dumps are ever logged -
every logged field is a specific value a module already extracted
(host, port, service, version, status).

## Data storage and privacy

All data stays on the local machine: `data/scripter.db` (SQLite - hosts,
services, vuln matches per run), `data/logs/scripter.log` (rotating log
file), and `reports/` (generated JSON/CSV/HTML reports). Nothing is sent
anywhere. Scripter never calls an LLM or cloud API and never requires
internet access to function (the signature dataset is bundled, not
fetched).

## Deliberately out of scope (not deferred - excluded by design)

- Credential brute forcing / password spraying.
- Triggering known backdoors automatically.
- Any exploit that modifies target state or exfiltrates data beyond what
  a check's own evidence note records (e.g. a PING reply, a TLS version
  string).
- Post-exploitation, persistence, lateral movement, or stealth/evasion
  tooling of any kind.

Adding any of the above would require a separate, explicitly-scoped
module reviewed on its own terms - not an extension of the existing
validation-check registry.
