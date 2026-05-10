"""Tests for the fake-OAuth token issuer + verifier.

Tokens here are intentionally non-cryptographic. They look like JWTs
(three base64-url segments) but use a deterministic 'fake' signature so
nobody mistakes them for real bearer credentials. Verification mimics the
checks the defended demo performs: audience, expiry, scope subset.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from mcp_demo.shared.auth_mock import (
    FakeAudienceError,
    FakeExpiryError,
    FakeScopeError,
    FakeTokenIssuer,
    verify_fake_token,
)


@pytest.fixture
def issuer() -> FakeTokenIssuer:
    return FakeTokenIssuer(issuer="https://issuer.demo.invalid")


def test_token_carries_required_claims(issuer: FakeTokenIssuer) -> None:
    token = issuer.issue(
        sub="alice",
        client_id="demo-client",
        audience="mcp-demo-server",
        scope=("read:profile",),
    )
    claims = verify_fake_token(
        token, expected_audience="mcp-demo-server", required_scope=("read:profile",)
    )
    assert claims["sub"] == "alice"
    assert claims["client_id"] == "demo-client"
    assert claims["aud"] == "mcp-demo-server"
    assert "read:profile" in claims["scope"]


def test_wrong_audience_is_rejected(issuer: FakeTokenIssuer) -> None:
    token = issuer.issue(
        sub="alice",
        client_id="demo-client",
        audience="some-other-service",
        scope=("read:profile",),
    )
    with pytest.raises(FakeAudienceError):
        verify_fake_token(token, expected_audience="mcp-demo-server")


def test_expired_token_is_rejected(issuer: FakeTokenIssuer) -> None:
    long_ago = datetime.now(tz=timezone.utc) - timedelta(hours=1)
    token = issuer.issue(
        sub="alice",
        client_id="demo-client",
        audience="mcp-demo-server",
        scope=("read:profile",),
        expires_at=long_ago,
    )
    with pytest.raises(FakeExpiryError):
        verify_fake_token(token, expected_audience="mcp-demo-server")


def test_scope_subset_is_required(issuer: FakeTokenIssuer) -> None:
    token = issuer.issue(
        sub="alice",
        client_id="demo-client",
        audience="mcp-demo-server",
        scope=("read:profile",),
    )
    with pytest.raises(FakeScopeError):
        verify_fake_token(
            token,
            expected_audience="mcp-demo-server",
            required_scope=("write:profile",),
        )


def test_token_is_obviously_fake(issuer: FakeTokenIssuer) -> None:
    token = issuer.issue(
        sub="alice",
        client_id="demo-client",
        audience="mcp-demo-server",
        scope=(),
    )
    # Header carries an explicit fake marker so reviewers can tell at a
    # glance this is not a real signed JWT.
    assert token.startswith("FAKEJWT.")
