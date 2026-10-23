"""Registers the bundled red-team tool set with redteam.registry.

Call redteam.registry.ensure_builtin_tools_registered() to populate the
registry - never import this module's individual tool submodules for
their side effects; registration only happens through
register_builtin_tools() below.
"""
from __future__ import annotations

from scripter.redteam import registry
from scripter.redteam.models import RiskLevel, ToolCapability, ToolDefinition


def register_builtin_tools() -> None:
    registry.register_tool(
        ToolDefinition(
            name="banner_probe",
            description="Passive banner re-read for an already-open host:port - no protocol-specific probe beyond a bounded read.",
            protocols=("tcp",),
            required_inputs=("host", "port"),
            capability=ToolCapability.PASSIVE_PROBE,
            risk=RiskLevel.PASSIVE,
            requires_network=True,
        )
    )
    registry.register_tool(
        ToolDefinition(
            name="http_audit",
            description="Bounded single-request HTTP GET + security-header review for an explicitly scoped web service.",
            protocols=("http",),
            required_inputs=("host", "port"),
            capability=ToolCapability.NON_AUTHENTICATING_PROBE,
            risk=RiskLevel.LOW,
            requires_network=True,
        )
    )
    registry.register_tool(
        ToolDefinition(
            name="tls_audit",
            description="Certificate metadata, negotiated protocol/cipher, and (optionally) the existing weak-protocol check.",
            protocols=("https",),
            required_inputs=("host", "port"),
            capability=ToolCapability.NON_AUTHENTICATING_PROBE,
            risk=RiskLevel.LOW,
            requires_network=True,
        )
    )
    registry.register_tool(
        ToolDefinition(
            name="ftp_audit",
            description="Passive FTP banner read plus the existing anonymous-login validation check.",
            protocols=("ftp",),
            required_inputs=("host", "port"),
            capability=ToolCapability.AUTHENTICATED_AUDIT,
            risk=RiskLevel.MEDIUM,
            requires_network=True,
            requires_validate_enabled=True,
        )
    )
    registry.register_tool(
        ToolDefinition(
            name="redis_audit",
            description="Passive Redis banner read plus the existing unauthenticated-PING validation check.",
            protocols=("redis",),
            required_inputs=("host", "port"),
            capability=ToolCapability.AUTHENTICATED_AUDIT,
            risk=RiskLevel.MEDIUM,
            requires_network=True,
            requires_validate_enabled=True,
        )
    )
    registry.register_tool(
        ToolDefinition(
            name="ssh_audit",
            description="Passive re-read of the unprompted SSH identification string plus the existing legacy-OpenSSH-version check.",
            protocols=("ssh",),
            required_inputs=("host", "port"),
            capability=ToolCapability.PASSIVE_PROBE,
            risk=RiskLevel.PASSIVE,
            requires_network=True,
        )
    )
    registry.register_tool(
        ToolDefinition(
            name="smtp_audit",
            description="One benign EHLO + QUIT - lists advertised extensions/AUTH mechanisms, sends no mail, no VRFY/EXPN.",
            protocols=("smtp",),
            required_inputs=("host", "port"),
            capability=ToolCapability.NON_AUTHENTICATING_PROBE,
            risk=RiskLevel.LOW,
            requires_network=True,
        )
    )
    registry.register_tool(
        ToolDefinition(
            name="mysql_audit",
            description="Passive read of the unprompted MySQL handshake packet - reveals the server version string, attempts no login.",
            protocols=("mysql",),
            required_inputs=("host", "port"),
            capability=ToolCapability.PASSIVE_PROBE,
            risk=RiskLevel.PASSIVE,
            requires_network=True,
        )
    )
    registry.register_tool(
        ToolDefinition(
            name="nmap_adapter",
            description="Wraps the existing nmap -sV version scan - adds no new scan logic or nmap flags.",
            protocols=("tcp",),
            required_inputs=("host", "ports"),
            capability=ToolCapability.EXTERNAL_ADAPTER,
            risk=RiskLevel.LOW,
            requires_network=True,
        )
    )
    registry.register_tool(
        ToolDefinition(
            name="diagnostics",
            description="Compares this run's recorded host/port availability against the previous run - local database only.",
            protocols=("tcp",),
            required_inputs=("host", "port"),
            capability=ToolCapability.PASSIVE_PROBE,
            risk=RiskLevel.PASSIVE,
            requires_network=False,
        )
    )
    registry.register_tool(
        ToolDefinition(
            name="simulate",
            description="Deterministic offline mock executor - never touches the network.",
            protocols=(),
            required_inputs=("host", "port", "tool_name"),
            capability=ToolCapability.PASSIVE_PROBE,
            risk=RiskLevel.PASSIVE,
            requires_network=False,
        )
    )
