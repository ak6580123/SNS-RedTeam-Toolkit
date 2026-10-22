"""Explicit-opt-in scope validation for every active module.

Scripter refuses to touch anything the operator has not explicitly listed.
There is no default target, no implicit "current subnet", and no automatic
expansion beyond what ``[scope] targets`` lists in the config file. This is
the single choke point every active command (discover, enumerate, validate)
must pass through before it sends a single packet.
"""
from __future__ import annotations

import ipaddress
import itertools
from dataclasses import dataclass


class ScopeError(ValueError):
    """Raised when a scope entry is malformed or outside policy."""


@dataclass(frozen=True)
class Scope:
    """A fully expanded, validated set of target hosts."""

    hosts: tuple[str, ...]
    raw_entries: tuple[str, ...]


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (ip.is_private or ip.is_loopback or ip.is_link_local)


def parse_scope(entries: list[str], allow_public: bool = False, max_hosts: int = 4096) -> Scope:
    """Expand a list of host/CIDR strings into concrete host addresses.

    Raises ScopeError on: empty input, a malformed entry, a public address
    when ``allow_public`` is False, or an expansion that would exceed
    ``max_hosts`` (a safety valve against a typo like "0.0.0.0/0" silently
    becoming an internet-wide sweep).
    """
    if not entries:
        raise ScopeError(
            "scope is empty - set [scope] targets in your config file before running any active command"
        )

    hosts: list[str] = []
    seen: set[str] = set()
    for raw in entries:
        raw = raw.strip()
        if not raw:
            continue
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ScopeError(f"'{raw}' is not a valid host or CIDR range: {exc}") from exc

        if network.num_addresses == 1:
            candidate_iter = iter((network.network_address,))
        else:
            candidate_iter = network.hosts()

        # Pull at most (budget + 1) addresses lazily - never materialize a
        # whole /8 (16M+ addresses) just to find out it's over the limit.
        # The +1 lets us detect "there's more than the budget" without
        # reading the rest of a huge range.
        budget = max(max_hosts - len(hosts), 0) + 1
        batch = list(itertools.islice(candidate_iter, budget))
        if not batch:
            batch = [network.network_address]

        if len(hosts) + len(batch) > max_hosts:
            raise ScopeError(
                f"scope expands past the safety limit of {max_hosts} hosts - "
                "narrow the CIDR ranges, or raise [scope] max_hosts explicitly if this is intended"
            )

        if not allow_public and any(_is_public(h) for h in batch):
            raise ScopeError(
                f"'{raw}' includes a public (non-private) address and [scope] allow_public is false - "
                "set allow_public = true only if this is an explicitly authorized competition range"
            )

        for h in batch:
            s = str(h)
            if s not in seen:
                seen.add(s)
                hosts.append(s)

    return Scope(hosts=tuple(hosts), raw_entries=tuple(entries))


def require_in_scope(host: str, scope: Scope) -> None:
    """Defense in depth: re-validate a single host against an already
    parsed scope before an active probe touches it. Call this at the point
    of action (socket connect, subprocess exec), not just at startup."""
    if host not in scope.hosts:
        raise ScopeError(f"'{host}' is not in the configured scope - refusing to act on it")
