"""Service enumeration: banner grabbing + lightweight version fingerprinting
for host/port pairs discovery.discover_hosts already found open.

Everything here is read-only - a connect, at most one small
protocol-appropriate probe (e.g. a plain HTTP GET), and a bounded read.
Nothing here authenticates, writes, or mutates target state; the one
exception in the whole toolkit (anonymous-FTP login) lives in
validation/checks.py, clearly separated and opt-in behind --validate.
"""
from __future__ import annotations

import datetime as dt
import re
import shutil
import socket
import ssl
import subprocess

from scripter.logging_setup import get_logger
from scripter.models import Host, ServiceFinding
from scripter.scope import Scope, require_in_scope

log = get_logger("enumeration")

#: Same anti-argv-injection pattern used for every subprocess target in this
#: project: no leading "-", so a malformed host can never be smuggled into
#: nmap's argv as a flag.
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,253}[A-Za-z0-9])?$")

#: Ports where sending a benign protocol-appropriate probe (rather than just
#: reading whatever the server volunteers on connect) gets a usable banner.
_HTTP_PORTS = {80, 8000, 8080, 8888}
_HTTPS_PORTS = {443, 8443}

_READ_BUFFER = 1024


def grab_banner(host: str, port: int, timeout: float) -> str:
    """Connect to host:port and return whatever banner text is available.
    HTTP(S) ports get a plain ``GET / HTTP/1.0`` probe; everything else is
    read passively (SSH/FTP/SMTP/etc. send a banner unprompted on connect).
    """
    try:
        if port in _HTTPS_PORTS:
            return _grab_https_banner(host, port, timeout)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in _HTTP_PORTS:
                sock.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii", errors="ignore"))
            data = sock.recv(_READ_BUFFER)
            return data.decode("utf-8", errors="replace").strip()
    except (OSError, socket.timeout) as exc:
        log.debug("banner grab failed for %s:%s: %s", host, port, exc)
        return ""


def _grab_https_banner(host: str, port: int, timeout: float) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                tls.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii", errors="ignore"))
                data = tls.recv(_READ_BUFFER)
                return data.decode("utf-8", errors="replace").strip()
    except (OSError, socket.timeout, ssl.SSLError) as exc:
        log.debug("TLS banner grab failed for %s:%s: %s", host, port, exc)
        return ""


#: (service name, compiled regex capturing a "version" group if present),
#: applied in order against the raw banner text. Pure/stateless on purpose
#: so it's unit-testable with synthetic banner strings, no network needed.
_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ssh", re.compile(r"SSH-\d\.\d-OpenSSH[_-](?P<version>[\w.]+)", re.IGNORECASE)),
    ("ssh", re.compile(r"(?P<version>SSH-\d\.\d-\S+)", re.IGNORECASE)),
    ("ftp", re.compile(r"\bvsFTPd[_ ](?P<version>[\d.]+)", re.IGNORECASE)),
    ("ftp", re.compile(r"\bProFTPD[_ ](?P<version>[\d.]+\w*)", re.IGNORECASE)),
    ("ftp", re.compile(r"220.*FTP", re.IGNORECASE)),
    ("smtp", re.compile(r"220.*(ESMTP|SMTP)", re.IGNORECASE)),
    ("http", re.compile(r"Server:\s*Apache/(?P<version>[\d.]+)", re.IGNORECASE)),
    ("http", re.compile(r"Server:\s*nginx/(?P<version>[\d.]+)", re.IGNORECASE)),
    ("http", re.compile(r"Server:\s*Microsoft-IIS/(?P<version>[\d.]+)", re.IGNORECASE)),
    ("http", re.compile(r"Server:\s*(?P<version>\S+)", re.IGNORECASE)),
    ("mysql", re.compile(r"(?P<version>\d+\.\d+\.\d+)-MariaDB", re.IGNORECASE)),
    ("smb", re.compile(r"\bSMB\b", re.IGNORECASE)),
)

#: Fallback service label by well-known port when the banner itself doesn't
#: identify the protocol (e.g. an empty read on a port that still accepted
#: the TCP connection).
_PORT_HINTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb", 6667: "irc",
}


def parse_service(port: int, banner: str) -> tuple[str | None, str | None]:
    """Pure, network-free parsing: given a port number and raw banner text,
    return (service, version). Deliberately separated from grab_banner so
    it's trivially unit-testable with synthetic banner strings."""
    for service, pattern in _SIGNATURES:
        match = pattern.search(banner)
        if match:
            groups = match.groupdict()
            version = groups.get("version") if groups else None
            return service, version
    return _PORT_HINTS.get(port), None


def enumerate_services(
    scope: Scope, hosts_with_ports: dict[str, tuple[int, ...]], timeout: float
) -> list[ServiceFinding]:
    """Grab banners and parse service/version for every (host, port) pair
    discovery already found open. ``hosts_with_ports`` maps scope host ->
    its open ports, as produced by discovery.discover_hosts."""
    now = dt.datetime.now(dt.timezone.utc)
    findings: list[ServiceFinding] = []
    for host, ports in hosts_with_ports.items():
        require_in_scope(host, scope)
        for port in ports:
            banner = grab_banner(host, port, timeout)
            service, version = parse_service(port, banner)
            findings.append(
                ServiceFinding(
                    host=host, port=port, protocol="tcp", service=service,
                    version=version, banner=banner, discovered_at=now,
                )
            )
    return findings


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_nmap_version_scan(
    host: str, ports: tuple[int, ...], scope: Scope, timeout_seconds: int = 120
) -> dict:
    """Optional ``nmap -sV`` pass for richer version detection than the
    built-in banner grabber. Read-only (``-sV`` only; no NSE vuln/exploit
    scripts, no ``-sS``/raw-socket scanning, no privilege escalation)."""
    require_in_scope(host, scope)
    if not _HOST_RE.match(host):
        return {"status": "error", "output": "", "error": f"refusing to scan - '{host}' isn't a valid target"}
    if not nmap_available():
        return {"status": "unsupported", "output": "", "error": "nmap not found on PATH"}
    if not ports:
        return {"status": "error", "output": "", "error": "no ports to scan"}

    port_list = ",".join(str(p) for p in ports)
    args = ["nmap", "-Pn", "-sV", "-p", port_list, host]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return {"status": "error", "output": "", "error": f"nmap timed out after {timeout_seconds}s"}
    except (FileNotFoundError, OSError) as exc:
        return {"status": "error", "output": "", "error": f"could not run nmap: {exc}"}

    if proc.returncode != 0 and not proc.stdout.strip():
        return {"status": "error", "output": proc.stdout, "error": proc.stderr.strip() or f"nmap exited {proc.returncode}"}
    return {"status": "done", "output": proc.stdout, "error": proc.stderr.strip()}


#: Matches an nmap port-table line, e.g. ``80/tcp   open  http    Apache
#: httpd 2.4.52`` or ``443/tcp  filtered  https``. Deliberately anchored so
#: it never matches indented NSE script-result lines (those start with
#: ``|`` or ``|_``), only the PORT/STATE/SERVICE/VERSION table itself.
_NMAP_PORT_LINE_RE = re.compile(
    r"^(?P<port>\d{1,5})/tcp\s+"
    r"(?P<state>open\|filtered|closed\|filtered|open|closed|filtered|unfiltered)\s+"
    r"(?P<service>\S+)(?:\s+(?P<version>.*))?$"
)


def parse_nmap_output(output: str) -> list[tuple[int, str, str | None, str]]:
    """Pure, network-free parsing of ``nmap -sV -sC -p-`` text output into
    ``(port, state, service, version)`` tuples - one per line of the
    PORT/STATE/SERVICE/VERSION table. ``closed`` ports are dropped (nmap
    already summarizes those in a "Not shown" line); every other state
    (``open``, ``filtered``, ``open|filtered``, ``unfiltered``) is kept so
    firewalled/filtered services remain visible to the caller."""
    results: list[tuple[int, str, str | None, str]] = []
    for line in output.splitlines():
        match = _NMAP_PORT_LINE_RE.match(line.strip())
        if not match:
            continue
        state = match.group("state")
        if state == "closed":
            continue
        port = int(match.group("port"))
        service = match.group("service")
        version = (match.group("version") or "").strip()
        results.append((port, state, None if service == "unknown" else service, version))
    return results


def run_nmap_full_scan(host: str, scope: Scope, timeout_seconds: float = 900.0) -> dict:
    """Full-port ``nmap`` sweep for the TUI's deep-scan action (Shift+D):
    ``-p-`` (all 65535 ports, not nmap's default top-1000), ``-Pn`` (skip
    host-discovery/ping so a host that drops ICMP isn't skipped entirely),
    ``-sV`` (service/version detection) and ``-sC`` (nmap's curated
    *default* NSE script set - banner/info/discovery scripts such as
    ``http-title``/``ssl-cert``; the *intrusive*, *exploit*, *brute* and
    *dos* categories are separate opt-in categories nmap does not run under
    ``-sC`` and this adapter never requests).

    Same safety properties as ``run_nmap_version_scan`` above: argument
    list (no ``shell=True``), the host is scope-checked and validated
    against ``_HOST_RE`` before it ever reaches nmap's argv, and no
    ``-sS``/raw-socket scanning or privilege escalation is used."""
    require_in_scope(host, scope)
    if not _HOST_RE.match(host):
        return {"status": "error", "output": "", "error": f"refusing to scan - '{host}' isn't a valid target"}
    if not nmap_available():
        return {"status": "unsupported", "output": "", "error": "nmap not found on PATH"}

    args = ["nmap", "-Pn", "-sV", "-sC", "-p-", host]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return {"status": "error", "output": "", "error": f"nmap timed out after {timeout_seconds}s"}
    except (FileNotFoundError, OSError) as exc:
        return {"status": "error", "output": "", "error": f"could not run nmap: {exc}"}

    if proc.returncode != 0 and not proc.stdout.strip():
        return {"status": "error", "output": proc.stdout, "error": proc.stderr.strip() or f"nmap exited {proc.returncode}"}
    return {"status": "done", "output": proc.stdout, "error": proc.stderr.strip()}


def deep_scan_hosts(scope: Scope, timeout_seconds: float = 900.0) -> tuple[list[Host], list[ServiceFinding]]:
    """Per-host ``nmap -Pn -sV -sC -p-`` sweep across every host in
    ``scope`` - the full-port, firewall-aware counterpart to running
    ``discovery.discover_hosts`` followed by ``enumerate_services``.
    Returns the same ``(hosts, findings)`` shape those two produce
    together, built from nmap's own detection instead of a bounded TCP
    connect sweep + banner grab, so ports nmap reports as ``filtered``/
    ``open|filtered`` show up as findings too instead of being silently
    skipped for not answering a plain connect."""
    now = dt.datetime.now(dt.timezone.utc)
    hosts: list[Host] = []
    findings: list[ServiceFinding] = []
    for host in scope.hosts:
        require_in_scope(host, scope)
        result = run_nmap_full_scan(host, scope, timeout_seconds=timeout_seconds)
        if result["status"] != "done":
            log.warning("deep scan for %s: %s - %s", host, result["status"], result.get("error", ""))
            continue
        ports = parse_nmap_output(result["output"])
        if not ports:
            continue
        open_ports = tuple(sorted(p for p, state, _, _ in ports if state == "open"))
        hosts.append(Host(ip=host, discovered_at=now, open_ports=open_ports))
        for port, state, service, version in ports:
            banner = version if state == "open" else f"[{state}] {version}".strip()
            findings.append(
                ServiceFinding(
                    host=host, port=port, protocol="tcp", service=service,
                    version=version or None, banner=banner, discovered_at=now,
                )
            )
    hosts.sort(key=lambda h: h.ip)
    return hosts, findings
