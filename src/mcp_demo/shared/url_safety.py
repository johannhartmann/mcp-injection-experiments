"""URL-safety classifier with DNS pinning.

``classify_url`` is the single decision the SSRF demo consults before any
"fetch" simulation. It enforces:

- HTTPS-only in production mode;
- explicit hostname allowlist;
- per-IP refusal of loopback, link-local, private, multicast, reserved
  ranges and the AWS/GCP IMDS literal ``169.254.169.254``;
- a redirect-target check (a 30x to a forbidden URL stays forbidden);
- DNS pinning so a re-resolve cannot smuggle a private IP in after a
  TOCTOU race.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit

from mcp_demo.shared.mock_resolver import MockResolver, MockResolverError


class UrlSafetyError(ValueError):
    """Raised when the URL fails a structural check (scheme, parse, ...)."""


@dataclass(frozen=True)
class UrlClassification:
    url: str
    host: str
    resolved_ips: tuple[str, ...]
    allowed: bool
    reason: str


def _is_internal_ip(ip: str) -> tuple[bool, str]:
    parsed = ipaddress.ip_address(ip)
    if str(parsed) == "169.254.169.254":
        return True, "cloud metadata literal 169.254.169.254"
    if parsed.is_loopback:
        return True, "loopback address"
    if parsed.is_link_local:
        return True, "link-local address"
    if parsed.is_private:
        return True, "private address range"
    if parsed.is_multicast:
        return True, "multicast address"
    if parsed.is_reserved:
        return True, "reserved address"
    if parsed.is_unspecified:
        return True, "unspecified address"
    return False, ""


def classify_url(
    url: str,
    *,
    allowed_hosts: Iterable[str],
    resolver: MockResolver,
    production: bool = False,
    pinned_ips: tuple[str, ...] | None = None,
    redirect_target: str | None = None,
) -> UrlClassification:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise UrlSafetyError(f"scheme not allowed: {scheme!r}")
    if production and scheme != "https":
        raise UrlSafetyError(f"production mode requires https; got {scheme!r}")

    host = (parsed.hostname or "").lower()
    if not host:
        raise UrlSafetyError(f"missing hostname: {url!r}")

    allowed = set(allowed_hosts)
    if host not in allowed:
        return UrlClassification(
            url=url, host=host, resolved_ips=(), allowed=False,
            reason=f"host {host!r} is not in allowlist",
        )

    if pinned_ips is not None:
        ips: tuple[str, ...] = pinned_ips
    else:
        try:
            ips = resolver.resolve(host)
        except MockResolverError:
            return UrlClassification(
                url=url, host=host, resolved_ips=(), allowed=False,
                reason=f"resolver has no record for {host!r}",
            )

    for ip in ips:
        is_internal, reason = _is_internal_ip(ip)
        if is_internal:
            return UrlClassification(
                url=url, host=host, resolved_ips=tuple(ips), allowed=False,
                reason=f"resolved IP {ip} is internal ({reason})",
            )

    # Redirect target check: any 30x to a different URL must also pass.
    if redirect_target is not None:
        redirect_class = classify_url(
            redirect_target,
            allowed_hosts=allowed,
            resolver=resolver,
            production=production,
        )
        if not redirect_class.allowed:
            return UrlClassification(
                url=url, host=host, resolved_ips=tuple(ips), allowed=False,
                reason=(
                    "redirect target would land at a forbidden URL: "
                    f"{redirect_class.reason}"
                ),
            )

    return UrlClassification(
        url=url, host=host, resolved_ips=tuple(ips), allowed=True,
        reason="ok",
    )
