"""Resolve a host and ask the network policy whether it may be contacted.

The rule lives in the domain (`NetworkPolicy`) and knows nothing about DNS.
This is the half that performs the lookup, which is I/O and therefore
belongs out here -- and keeping them apart is what lets the rule be tested
exhaustively against address literals with no network at all.

Answers are memoised for the lifetime of the guard: a `recommend` run asks
about the same handful of registries once per candidate, and a name that was
just refused does not become acceptable a millisecond later.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import TYPE_CHECKING, Any

from loguru import logger

from dockerls.domain.value_objects.network_policy import (
    NetworkDecision,
    NetworkPolicy,
    hostname_of,
)

if TYPE_CHECKING:
    from collections.abc import Iterable


class HostGuard:
    """Decides, with DNS, whether a host is within the configured policy."""

    def __init__(self, policy: NetworkPolicy | None = None):
        self._policy = policy or NetworkPolicy()
        self._decisions: dict[str, NetworkDecision] = {}

    @property
    def policy(self) -> NetworkPolicy:
        return self._policy

    def decide(self, host: str) -> NetworkDecision:
        cached = self._decisions.get(host)
        if cached is not None:
            return cached

        if self._policy.is_allowlisted(host):
            decision = NetworkDecision.ALLOWED_BY_ALLOWLIST
        else:
            hostname = hostname_of(host)
            decision = (
                self._policy.decide_addresses(_resolve(hostname))
                if hostname
                else NetworkDecision.BLOCKED_UNRESOLVABLE
            )
        self._decisions[host] = decision
        return decision

    def allows(self, host: str) -> bool:
        return self.decide(host) in (
            NetworkDecision.ALLOWED,
            NetworkDecision.ALLOWED_BY_ALLOWLIST,
        )

    def explain(self, host: str) -> str:
        return self._policy.explain(host, self.decide(host))


def _resolve(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Every address `hostname` resolves to, literals included.

    A failure returns an empty list, which the policy reads as
    "unresolvable" and therefore refuses -- the safe direction: a name that
    cannot be resolved cannot be verified either.
    """
    try:
        return [ipaddress.ip_address(hostname)]
    except ValueError:
        pass
    try:
        infos: Iterable[tuple[Any, ...]] = socket.getaddrinfo(
            hostname, None, proto=socket.IPPROTO_TCP
        )
    except (OSError, UnicodeError) as e:
        logger.debug(f"Could not resolve {hostname}: {e}")
        return []

    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(info[4][0]))
        except (ValueError, IndexError):
            continue
    return addresses
