"""Tests for the in-memory fake registry."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.shared.fake_registry import (
    FakeRegistry,
    RegistryManifestError,
)


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "registry"


def test_registry_lists_versions() -> None:
    registry = FakeRegistry.from_directory(FIXTURES)
    versions = registry.versions("drift-mock.example-server")
    assert versions == ["1.0.0", "2.0.0"]


def test_registry_returns_manifest_v1_and_v2() -> None:
    registry = FakeRegistry.from_directory(FIXTURES)
    v1 = registry.get(server_id="drift-mock.example-server", version="1.0.0")
    v2 = registry.get(server_id="drift-mock.example-server", version="2.0.0")

    assert v1.server_id == "drift-mock.example-server"
    assert v1.permissions == ("read:user-profile",)
    assert [t.name for t in v1.tools] == ["profile.get"]

    assert "send:message" in v2.permissions
    assert any(t.name == "message.send" for t in v2.tools)


def test_registry_resolves_latest() -> None:
    registry = FakeRegistry.from_directory(FIXTURES)
    latest = registry.get(server_id="drift-mock.example-server", version="latest")
    assert latest.version == "2.0.0"


def test_registry_rejects_invalid_manifest(tmp_path: Path) -> None:
    bad = tmp_path / "registry"
    bad.mkdir()
    (bad / "broken.yaml").write_text(
        "server_id: x\nversion: 1.0.0\n# permissions is missing\ntools: []\n",
        encoding="utf-8",
    )
    with pytest.raises(RegistryManifestError):
        FakeRegistry.from_directory(bad)


def test_manifest_contains_tool_fingerprints() -> None:
    registry = FakeRegistry.from_directory(FIXTURES)
    v1 = registry.get(server_id="drift-mock.example-server", version="1.0.0")
    fps = {t.name: (t.description_hash, t.schema_hash) for t in v1.tools}
    assert "profile.get" in fps
    desc_hash, schema_hash = fps["profile.get"]
    assert len(desc_hash) >= 16
    assert len(schema_hash) >= 16


def test_unknown_server_raises() -> None:
    registry = FakeRegistry.from_directory(FIXTURES)
    with pytest.raises(KeyError):
        registry.get(server_id="never-heard-of", version="1.0.0")
