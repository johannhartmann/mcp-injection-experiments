"""Outbound network guard.

The demo defaults to ``deny`` for every outbound URL. Operators may
allowlist specific hosts (typically ``127.0.0.1`` for the demo's own
endpoints), but cloud-metadata, link-local and private ranges are *always*
blocked - even when the allowlist contains ``*``.

The guard does not perform requests itself. It is consulted by experiment
code that *would* perform a request, and refuses early with a controlled
:class:`NetworkPolicyError`.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlsplit


class NetworkPolicyError(PermissionError):
    """Raised when the network guard refuses an outbound URL."""


_BLOCKED_NAMES = {
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "localhost.localdomain",
}

_ALLOWED_SCHEMES = frozenset({"http", "https"})


def _hostname_is_blocked_name(hostname: str) -> bool:
    return hostname.lower() in _BLOCKED_NAMES


def _hostname_is_blocked_ip(hostname: str) -> bool:
    """Return True if the hostname parses as a blocked IP.

    Loopback (``127.0.0.0/8``, ``::1``) is included in the block list because
    while ``127.0.0.1`` is *also* the typical operator-allowlisted demo host,
    this helper is only consulted *after* the allowlist match misses. So the
    operator must explicitly list ``127.0.0.1`` to reach the loopback.
    """

    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or str(ip) == "169.254.169.254"  # AWS / GCP IMDS, redundant but explicit
    )


@dataclass(frozen=True)
class NetworkGuard:
    """Outbound URL gatekeeper."""

    allowed_hosts: frozenset[str] = field(default_factory=frozenset)

    def __init__(self, allowed_hosts: Iterable[str] | None = None) -> None:
        # Allow construction from any iterable while still keeping the dataclass
        # frozen and immutable.
        hosts = frozenset(h.lower() for h in (allowed_hosts or ()))
        object.__setattr__(self, "allowed_hosts", hosts)

    @classmethod
    def deny_all(cls) -> "NetworkGuard":
        return cls(allowed_hosts=())

    def check(self, url: str) -> None:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise NetworkPolicyError(f"scheme not allowed: {scheme!r}")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise NetworkPolicyError(f"missing hostname in URL: {url!r}")

        # Explicit hostname match in the allowlist is the only way to reach
        # loopback, private or otherwise internal targets. The operator must
        # name them by hand, so a poisoned tool cannot trick the guard into
        # contacting an internal endpoint by widening the allowlist to ``*``.
        if hostname in self.allowed_hosts:
            return

        # Wildcard means "any external host" - never internal targets.
        if _hostname_is_blocked_name(hostname) or _hostname_is_blocked_ip(hostname):
            raise NetworkPolicyError(
                f"internal/metadata target is always blocked: {hostname!r}"
            )

        if "*" in self.allowed_hosts:
            return

        raise NetworkPolicyError(
            f"host not allowlisted: {hostname!r}; allowlist={sorted(self.allowed_hosts)}"
        )
