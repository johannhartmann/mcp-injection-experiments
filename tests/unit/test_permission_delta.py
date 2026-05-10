"""Tests for permission-delta computation between two registry manifests."""

from __future__ import annotations

from mcp_demo.shared.pinning import (
    PermissionDelta,
    permission_delta,
)


def test_no_change_yields_empty_delta() -> None:
    delta = permission_delta(
        before=("read:user-profile",),
        after=("read:user-profile",),
    )
    assert delta == PermissionDelta(added=(), removed=(), broadened=())


def test_added_permission_is_detected() -> None:
    delta = permission_delta(
        before=("read:user-profile",),
        after=("read:user-profile", "send:message"),
    )
    assert delta.added == ("send:message",)


def test_removed_permission_is_detected() -> None:
    delta = permission_delta(
        before=("read:user-profile", "send:message"),
        after=("read:user-profile",),
    )
    assert delta.removed == ("send:message",)


def test_broader_scope_is_detected_via_wildcard() -> None:
    delta = permission_delta(
        before=("read:contacts:own",),
        after=("read:contacts:*",),
    )
    assert delta.broadened == (("read:contacts:own", "read:contacts:*"),)


def test_broader_scope_is_detected_via_role_upgrade() -> None:
    delta = permission_delta(
        before=("repo:read",),
        after=("repo:write",),
    )
    assert delta.broadened == (("repo:read", "repo:write"),)
