"""Tests for the URL-safety classifier.

The classifier wraps the network guard with DNS pinning so the SSRF demo
can decide *before* a fetch whether a URL would resolve to a forbidden
target. The mock resolver is the single source of truth - no real DNS
lookup ever happens.
"""

from __future__ import annotations

import pytest

from mcp_demo.shared.mock_resolver import MockResolver
from mcp_demo.shared.url_safety import (
    UrlClassification,
    UrlSafetyError,
    classify_url,
)


@pytest.fixture
def resolver() -> MockResolver:
    # Use genuinely public IPs for the "external" hosts so Python's
    # ipaddress.is_private (which now catches RFC 5737 documentation
    # ranges as private) does not flag the demo's own fixtures.
    return MockResolver(
        records={
            "auth.example": ["8.8.8.8"],
            "metadata.attacker.example": ["169.254.169.254"],
            "totally-cloud.example": ["10.0.0.7"],
            "harmless.example": ["9.9.9.9"],
        }
    )


def test_https_to_allowed_external_host_is_allowed(resolver: MockResolver) -> None:
    classification = classify_url(
        "https://auth.example/.well-known/oauth-authorization-server",
        allowed_hosts={"auth.example"},
        resolver=resolver,
    )
    assert isinstance(classification, UrlClassification)
    assert classification.allowed is True
    assert classification.host == "auth.example"
    assert classification.resolved_ips == ("8.8.8.8",)


def test_http_is_refused_in_production_mode(resolver: MockResolver) -> None:
    with pytest.raises(UrlSafetyError):
        classify_url(
            "http://auth.example/x",
            allowed_hosts={"auth.example"},
            resolver=resolver,
            production=True,
        )


def test_resolution_to_link_local_is_refused(resolver: MockResolver) -> None:
    classification = classify_url(
        "https://metadata.attacker.example/latest/meta-data/",
        allowed_hosts={"metadata.attacker.example"},
        resolver=resolver,
    )
    assert classification.allowed is False
    assert "metadata" in classification.reason.lower() or "link-local" in classification.reason.lower()
    assert classification.resolved_ips == ("169.254.169.254",)


def test_resolution_to_private_range_is_refused(resolver: MockResolver) -> None:
    classification = classify_url(
        "https://totally-cloud.example/health",
        allowed_hosts={"totally-cloud.example"},
        resolver=resolver,
    )
    assert classification.allowed is False
    assert "private" in classification.reason.lower()


def test_unallowlisted_host_is_refused(resolver: MockResolver) -> None:
    classification = classify_url(
        "https://harmless.example/",
        allowed_hosts=set(),
        resolver=resolver,
    )
    assert classification.allowed is False


def test_redirect_to_internal_target_is_refused(resolver: MockResolver) -> None:
    """A 30x to an internal URL must not be followed."""

    classification = classify_url(
        "https://harmless.example/",
        allowed_hosts={"harmless.example"},
        resolver=resolver,
        redirect_target="https://metadata.attacker.example/latest",
    )
    assert classification.allowed is False
    assert "redirect" in classification.reason.lower()


def test_dns_toctou_is_simulated_by_resolver_pinning(resolver: MockResolver) -> None:
    """Pinned IPs are reused; a re-resolution that returns a private IP is refused."""

    first = classify_url(
        "https://harmless.example/",
        allowed_hosts={"harmless.example"},
        resolver=resolver,
    )
    assert first.allowed is True
    pinned = first.resolved_ips

    # Attacker flips DNS to point at a private range.
    resolver.set("harmless.example", ["10.1.2.3"])
    second = classify_url(
        "https://harmless.example/",
        allowed_hosts={"harmless.example"},
        resolver=resolver,
        pinned_ips=pinned,
    )
    # The pinned IP is still 198.51.100.42, so the call resolves to that and
    # the classifier returns allowed=True. Without pinning the next call
    # would get the new (private) IP and refuse:
    assert second.allowed is True
    assert second.resolved_ips == pinned

    third = classify_url(
        "https://harmless.example/",
        allowed_hosts={"harmless.example"},
        resolver=resolver,
    )
    assert third.allowed is False
    assert third.resolved_ips == ("10.1.2.3",)
