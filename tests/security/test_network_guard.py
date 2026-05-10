"""Tests for the outbound network guard.

The demo defaults to ``deny`` for every outbound request. Hosts must be
explicitly allowlisted, and only by the operator running the demo - not by an
experiment, and never by user input. Cloud-metadata, link-local and private
ranges are never reachable, even when they appear on the allowlist.
"""

from __future__ import annotations

import pytest

from mcp_demo.shared.network_guard import (
    NetworkGuard,
    NetworkPolicyError,
)


def test_default_policy_denies_everything() -> None:
    guard = NetworkGuard.deny_all()

    with pytest.raises(NetworkPolicyError):
        guard.check("https://example.com/healthz")


def test_allowlisted_host_is_allowed() -> None:
    guard = NetworkGuard(allowed_hosts={"127.0.0.1"})
    guard.check("http://127.0.0.1:8000/mcp/direct-poisoning")  # no raise


def test_non_allowlisted_host_is_blocked_even_if_allowlist_has_entries() -> None:
    guard = NetworkGuard(allowed_hosts={"127.0.0.1"})

    with pytest.raises(NetworkPolicyError):
        guard.check("https://attkr.example.com/exfil")


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
        "http://metadata.google.internal/",
        "http://metadata/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://[::1]/",
        "http://localhost.localdomain/",
        "http://0.0.0.0/",
    ],
)
def test_metadata_and_private_ranges_are_blocked(url: str) -> None:
    """Even when an operator allowlists ``*``, internal targets stay blocked."""

    guard = NetworkGuard(allowed_hosts={"*"})

    with pytest.raises(NetworkPolicyError):
        guard.check(url)


def test_only_http_and_https_schemes_are_allowed() -> None:
    guard = NetworkGuard(allowed_hosts={"127.0.0.1"})

    for url in [
        "file:///etc/passwd",
        "ftp://127.0.0.1/",
        "gopher://127.0.0.1/",
    ]:
        with pytest.raises(NetworkPolicyError):
            guard.check(url)


def test_user_input_cannot_widen_allowlist() -> None:
    """The guard must not accept new hosts at runtime."""

    guard = NetworkGuard(allowed_hosts={"127.0.0.1"})

    assert not hasattr(guard, "allow")
    # Even if a caller mutates the underlying set, the guard takes its own
    # frozen copy at construction time.
    with pytest.raises(NetworkPolicyError):
        guard.check("https://attkr.example.com/")
