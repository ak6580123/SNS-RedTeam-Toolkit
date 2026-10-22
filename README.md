# Scripter 🍋 — Authorized Red-Team Automation for A/D CTF

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](#installation)
[![License](https://img.shields.io/badge/license-MIT-green)](#)
[![Offline](https://img.shields.io/badge/runs-100%25%20offline-orange)](#why-scripter)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](#installation)

**Scripter** automates the repeatable, deterministic grunt work of an
Attack-vs-Defense CTF round or an isolated cyber-range engagement —
host/port discovery, service enumeration, offline vulnerability mapping,
and a small set of non-destructive validation checks — and turns it into
structured, ranked, exportable findings.

No AI. No cloud APIs. No telemetry. Every signature, probe, and report is
local, deterministic Python that you can read end-to-end in an afternoon.

> **Scope first, always.** Scripter will not act on anything you have not
> explicitly listed. See [Authorization and scope](#authorization-and-scope--read-this-first)
> before you run anything.

---

## Table of contents

- [Why Scripter](#why-scripter)
- [Authorization and scope — read this first](#authorization-and-scope--read-this-first)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running](#running)
- [CLI reference](#cli-reference)
- [TUI dashboard](#tui-dashboard)
- [Pipeline](#pipeline)
- [Vulnerability signatures](#vulnerability-signatures)
- [Known limitations](#known-limitations)
- [Running tests](#running-tests)
- [Project layout](#project-layout)

---

## Why Scripter

| | |
|---|---|
| **Deterministic** | No LLMs, no heuristics that change between runs — the same scope + signatures always produce the same findings. |
| **Scope-enforced** | Every active function re-checks the target against `[scope] targets` at the moment it fires, not just once at startup. |
| **Honest about confidence** | A signature match is a `hypothesis` until one of three non-destructive checks promotes it to `confirmed` / `ruled_out` / `inconclusive`. |
| **Bounded by design** | Plain TCP connects only — no raw sockets, no SYN scans, no ICMP floods, no evasion tuning, and capped concurrency so a sweep can't become a stress test. |
| **Offline** | The vulnerability signature set ships with the repo. No CVE API calls, no internet dependency, no data leaves the machine. |
| **One pipeline, two views** | The CLI and the Textual TUI run the exact same `discover → enumerate → vuln-map → validate → report` pipeline — pick whichever fits the moment. |

---

## Authorization and scope — read this first

- There is **no default target**. `[scope] targets` in your config file
  must be a non-empty list of hosts/CIDR ranges you are authorized to
  test (a competition-provided range, or an isolated lab network).
- Public (non-private) addresses are rejected unless you explicitly set
  `[scope] allow_public = true` — only do this if the competition itself
  assigns a public range.
- Every active probe re-validates its target against the parsed scope at
  the point of action, not just once at startup.
- Discovery/enumeration use plain TCP connects only — no raw sockets, no
  SYN scanning, no ICMP floods, no retry/backoff tuning aimed at evading
  detection — and bounded concurrency (`[scan] max_concurrency`) so a
  sweep can't become a stress test against shared competition
  infrastructure.
- The validation checks (`scripter validate`) are opt-in
  (`[validate] enabled = true`) and are all non-destructive: an anonymous
  FTP login attempt, an unauthenticated Redis `PING`, and a TLS handshake
  restricted to legacy protocol versions. None of them write data,
  authenticate as a privileged user, or exploit a bug.
- Scripter does **not** implement credential brute forcing, known-backdoor
  triggering (e.g. the vsftpd 2.3.4 smiley-face trigger), or any protocol
  exploit that reads/writes target memory or files. See
  [`docs/security-model.md`](docs/security-model.md) for the full list
  and the reasoning.

**Only ever point this at systems you are explicitly authorized to test.**

---

## Installation

Works on **Windows and Kali Linux** (and generally any Linux/macOS with
Python 3.11+) — nothing in the codebase is platform-gated.

<details open>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
cd C:\Users\ASUS\Citrus
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
```
</details>

<details>
<summary><b>Kali Linux / other Linux / macOS (bash)</b></summary>

```bash
cd ~/Citrus
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -e .
```
</details>

Add test dependencies with `[dev]`, e.g. `-e ".[dev]"`.

**Optional:** install `nmap` and put it on `PATH` for richer version
detection (`[scan] use_nmap = true`). Kali ships it by default
(`sudo apt install nmap` elsewhere). Scripter works fine without it —
it falls back to its own banner-grabbing enumeration.

---

## Configuration

```powershell
# Windows
copy config\config.example.toml config\config.toml
```

```bash
# Kali / Linux / macOS
cp config/config.example.toml config/config.toml
```

Edit `config/config.toml` and set `[scope] targets`. Scripter refuses to
run any active command against an empty or missing scope.

| Section | Key | Default | Meaning |
|---|---|---|---|
| `[scope]` | `targets` | `[]` | Hosts/CIDRs you're authorized to test — **required** |
| `[scope]` | `allow_public` | `false` | Allow non-private addresses |
| `[scope]` | `max_hosts` | `4096` | Safety cap against a CIDR typo |
| `[scan]` | `ports` | 28 common ports | Ports probed by discover/enumerate |
| `[scan]` | `timeout_seconds` | `2.0` | Per-connection timeout |
| `[scan]` | `max_concurrency` | `50` | Bounded sweep concurrency |
| `[scan]` | `use_nmap` | `false` | Optional `nmap -sV` enrichment pass |
| `[validate]` | `enabled` | `false` | Opt-in gate for the 3 non-destructive checks |
| `[storage]` | `db_path` | `data/scripter.db` | SQLite run history |

---

## Running

```powershell
# Windows
.\.venv\Scripts\python.exe -m scripter --help
# or, after installation:
.\.venv\Scripts\scripter.exe --help
```

```bash
# Kali/Linux/macOS
./.venv/bin/python -m scripter --help
# or, after installation:
./.venv/bin/scripter --help
```

## CLI reference

| Command | What it does |
|---|---|
| `scripter doctor` | Sanity-checks environment + config (nmap on `PATH`, scope size, validate flag) |
| `scripter discover` | TCP-connect sweep of the configured scope |
| `scripter enumerate` | Banner-grabs every open port from the latest (or `--run-id`) run |
| `scripter vuln-map` | Matches enumerated services against the signature dataset |
| `scripter validate` | Runs the 3 non-destructive checks — requires `[validate] enabled = true` |
| `scripter report --formats json,csv,html` | Writes ranked, machine-readable findings |
| `scripter run-all [--validate] [--formats ...]` | Full pipeline in one shot |
| `scripter tui` | Interactive dashboard over the same pipeline |

```powershell
scripter run-all --validate --formats json,csv,html
```

---

## TUI dashboard

```powershell
scripter tui
```

A live, keyboard-driven dashboard built on [Textual](https://textual.textualize.io/)
over the exact same pipeline the CLI uses — no second implementation, just
a nicer way to watch it run. Tabs for Hosts / Services / Findings, a
scrolling log pane, and a status bar showing scope size, current run id,
and whether validation is enabled.

| Key | Action |
|---|---|
| `d` | **d**iscover — sweep the configured scope |
| `e` | **e**numerate — grab banners for the current run's open ports |
| `m` | vuln-**m**ap — match services against the signature dataset |
| `v` | **v**alidate — run non-destructive checks (if enabled) |
| `r` | **r**eport — write JSON/CSV/HTML for the current run |
| `a` | run-**a**ll — the full pipeline in one go |
| `s` | set/edit **s**cope targets without leaving the TUI |
| `q` | **q**uit |

Findings are color-coded by severity (critical/high/medium/low) and
status (confirmed/hypothesis/inconclusive/ruled_out). Reopening the TUI
against the same `db_path` reloads the latest run automatically.

Every pipeline command operates on a **run** — one `discover` invocation
and everything chained off it — persisted in SQLite. Commands default to
the most recent run; pass `--run-id <n>` to target an older one.

---

## Pipeline

```
 discover     TCP-connect sweep of [scope] targets × [scan] ports
     │
     ▼
 enumerate    banner grab + lightweight service/version parsing per open port
     │        (optional nmap -sV pass if [scan] use_nmap = true)
     ▼
 vuln-map     match service/version against intel/data/signatures.json
     │        → every match starts as status = hypothesis
     ▼
 validate     (opt-in) run the 3 registered non-destructive checks
     │        → promotes matches to confirmed / ruled_out / inconclusive
     ▼
 report       rank by severity × confidence × exploitability ÷ effort
              write JSON / CSV / HTML to [storage] reports_dir
```

Only `validate`'s registered checks can ever promote a match past
`hypothesis` — a banner/version match alone is a lead, never a finding.

---

## Vulnerability signatures

`src/scripter/intel/data/signatures.json` is a small, honest starting set
covering common CTF/lab teaching vulnerabilities: vsftpd 2.3.4 backdoor,
ProFTPD 1.3.3c backdoor, UnrealIRCd backdoor, Samba `usermap_script`,
end-of-life OpenSSH, Tomcat default manager, unauthenticated Redis, and
weak TLS. It is **not** a comprehensive CVE feed — extend it as you learn
the competition's actual service mix. Each entry marks whether it has an
automated validation check or needs manual confirmation (`"check": null`),
and every `description` says so explicitly.

## Known limitations

- Service/version fingerprinting is banner-regex based, not a full
  protocol-aware scanner — it will miss or mis-identify services that
  don't send an identifying banner on connect or an HTTP `Server` header.
- The signature dataset is intentionally small, not a comprehensive
  vulnerability feed, and ships offline (no CVE API lookups).
- Automated validation checks exist for only 3 of the 9 bundled
  signatures; the rest are flagged `hypothesis`/manual-review by design,
  not a gap to silently work around.
- `nmap` integration only runs `-sV` (service/version detection) — no NSE
  vulnerability or exploit scripts, no `-sS` raw-socket scanning.

## Running tests

```powershell
# Windows
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
```

```bash
# Kali/Linux/macOS
./.venv/bin/python -m pip install -e ".[dev]"
./.venv/bin/python -m pytest -q
```

Tests that need real network access are marked `@pytest.mark.network` and
excluded by default (see `pyproject.toml`'s `testpaths`); run
`pytest -m network` against a real lab target to include them explicitly.

## Project layout

```
src/scripter/
  cli.py            Typer CLI — one command per pipeline stage, shared --config
  scope.py          Explicit-opt-in scope validation (the one choke point
                     every active command must pass through)
  config.py         TOML config loading + validation
  models.py         Shared dataclasses: Host, ServiceFinding, VulnMatch, ...
  recon/            Active probing — always scope-gated
    discovery.py       TCP-connect host/port sweep, bounded concurrency
    enumeration.py     Banner grab + regex-based service/version parsing
  intel/            Offline vulnerability intelligence
    vuln_db.py         Load/validate the signature dataset
    matcher.py         ServiceFinding → VulnMatch (status = hypothesis)
    data/signatures.json
  validation/       Non-destructive proof-of-vulnerability checks
    checks.py
  prioritize.py     Score/rank matches by severity × confidence × exploitability
  storage/db.py     SQLite: runs/hosts/services/vuln_matches
  reporting/report.py  JSON/CSV writers + escaped static HTML
  tui/app.py        Textual dashboard
```

See [`docs/architecture.md`](docs/architecture.md) for the full data-flow
walkthrough and [`docs/security-model.md`](docs/security-model.md) for the
complete safety rationale — including exactly why each of the three
validation checks is non-destructive and what Scripter deliberately
never automates.
