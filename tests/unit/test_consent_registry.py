"""Tests for the per-user/per-client consent registry."""

from __future__ import annotations

import pytest

from mcp_demo.shared.consent import ConsentRegistry


def test_consent_is_bound_to_user_client_redirect_and_scopes() -> None:
    reg = ConsentRegistry()
    reg.record(
        user_id="alice",
        client_id="demo-client",
        redirect_uri="https://app.demo.invalid/cb",
        scopes=("read:profile",),
    )
    assert reg.is_consented(
        user_id="alice",
        client_id="demo-client",
        redirect_uri="https://app.demo.invalid/cb",
        scopes=("read:profile",),
    )


def test_redirect_uri_change_forces_re_consent() -> None:
    reg = ConsentRegistry()
    reg.record(
        user_id="alice",
        client_id="demo-client",
        redirect_uri="https://app.demo.invalid/cb",
        scopes=("read:profile",),
    )
    assert not reg.is_consented(
        user_id="alice",
        client_id="demo-client",
        redirect_uri="https://app.demo.invalid/other-cb",
        scopes=("read:profile",),
    )


def test_consent_is_per_client() -> None:
    reg = ConsentRegistry()
    reg.record(
        user_id="alice",
        client_id="client-a",
        redirect_uri="https://a.demo.invalid/cb",
        scopes=("read:profile",),
    )
    assert not reg.is_consented(
        user_id="alice",
        client_id="client-b",
        redirect_uri="https://a.demo.invalid/cb",
        scopes=("read:profile",),
    )


def test_scope_widening_forces_re_consent() -> None:
    reg = ConsentRegistry()
    reg.record(
        user_id="alice",
        client_id="client-a",
        redirect_uri="https://a.demo.invalid/cb",
        scopes=("read:profile",),
    )
    assert not reg.is_consented(
        user_id="alice",
        client_id="client-a",
        redirect_uri="https://a.demo.invalid/cb",
        scopes=("read:profile", "write:profile"),
    )


def test_redirect_uri_must_be_demo_invalid_or_example() -> None:
    reg = ConsentRegistry()
    with pytest.raises(ValueError):
        reg.record(
            user_id="alice",
            client_id="demo-client",
            redirect_uri="https://attacker.io/cb",
            scopes=("read:profile",),
        )
