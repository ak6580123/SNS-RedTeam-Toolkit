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
from scripter.models import ServiceFinding
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
