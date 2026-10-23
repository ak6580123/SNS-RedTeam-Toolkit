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
anywhere, and Scripter never calls an LLM or cloud API. Scripter does not
*require* internet access to function (the signature dataset is bundled,
not fetched) - the one opt-in exception is `intel/cve_lookup.py`'s CVE
lookup against the public NVD CVE API, reachable from the Findings tab's
"Look up CVEs (NVD)" button or `scripter cve-lookup`, gated off by default
behind `[intel] cve_lookup_enabled`. Enabling it sends only a service name
and version string (e.g. `"OpenSSH 7.2"`) to `services.nvd.nist.gov` -
never a target host/IP, port, banner, or anything else from `[scope]`.

## The redteam/ extension's safety gates

The `redteam/` planning+execution extension adds no new scope or storage
implementation - it reuses `scope.require_in_scope` and the existing
`Store`'s connection/lock exactly as every other module does. On top of
that, `redteam/executor.py`'s `execute_item` is the single place a plan
item can ever reach the network, and checks, in this exact order, before
any tool runs for real:

1. `simulate_only=True` always wins - a simulated run never reaches any
   gate below this one, and never imports `socket`/`subprocess`.
2. `[redteam] network_audits_enabled` - the master real-audit switch.
3. `[redteam] external_tools_enabled` - external-adapter tools only
   (currently just `nmap_adapter`, which itself only wraps the existing
   `run_nmap_version_scan` - no new nmap flags).
4. `[redteam] allowed_categories` - lets an operator narrow the toolkit
   to a subset for a specific competition.
5. `[validate] enabled` - for the two tools that authenticate
   (`ftp_audit`/`redis_audit`), which only ever delegate to the EXISTING
   `ftp_anonymous_login_check`/`redis_unauthenticated_check` - no new
   authentication logic is added anywhere in `redteam/`.
6. `scope.require_in_scope` - re-checked here, at the point of action,
   exactly like every other active function in the codebase.

A tool raising an exception degrades to a `FAILED` `ToolResult` rather
than crashing the run or retrying, mirroring `run_validation`'s own
contract. `[redteam] enabled` only gates the feature's own master switch;
`list-tools`/`plan`/`simulate` stay available regardless, because they
are offline and deterministic by construction - `planner.build_plan`
never imports `socket`, `subprocess`, or `http.client`, and
`tools/simulate.py`'s outcome is a pure hash of the plan item's own
fields, not a random number.

`redteam/results.sanitize_evidence` redacts `Authorization:`/
`Set-Cookie:`/`password=`/`token=`/`api_key=`-shaped substrings and caps
every evidence string's length before it is ever stored or reported -
every tool module in `redteam/tools/` routes its evidence through it.

`http_audit` uses `http.client` (not `urllib.request`) specifically
because it never auto-follows a redirect - a `Location` header is always
surfaced as evidence, never contacted. `tls_audit`'s certificate-metadata
read uses a normal, verifying handshake; the one place certificate
verification is intentionally disabled remains the pre-existing,
unchanged `tls_weak_protocol_check`, which `tls_audit` only ever calls
through, never reimplements.

`ssh_audit`, `smtp_audit`, and `mysql_audit` follow the same "read what
the protocol sends unprompted, or issue at most one benign,
non-authenticating command" shape as the tools above. None of the three
require `[validate] enabled` - `ssh_audit` only re-reads the
identification string every SSH server sends before any key exchange
(via the new `openssh_legacy_version_check`); `smtp_audit` sends a
single `EHLO`/`QUIT` and deliberately never sends `VRFY`/`EXPN` (which
can enumerate real mailboxes) or an actual message; `mysql_audit` only
reads the handshake packet a MySQL server sends on connect and never
attempts a login.

**Still deliberately not implemented anywhere in `redteam/`:** credential
brute forcing, triggering known backdoors, web crawling or form
submission, file upload/download, Redis write commands or key
enumeration, service restart/modification, or any exploit that reads or
writes target state. A completed audit is an *observation* - it is never
reported, logged, or described as a confirmed exploit or a captured flag.

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
