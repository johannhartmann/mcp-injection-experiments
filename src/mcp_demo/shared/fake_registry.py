"""In-memory fake MCP registry.

The demo never talks to a real package registry, never downloads anything.
It loads YAML manifests from a local directory and exposes them by
``(server_id, version)``. The schema is intentionally tiny:

```yaml
server_id: drift-mock.example-server
version: "1.0.0"
permissions:
  - read:user-profile
tools:
  - name: profile.get
    description: ...
    schema: { ... }
```
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from mcp_demo.shared.tool_metadata import (
    ToolFingerprint,
    fingerprint_tool,
)


class RegistryManifestError(ValueError):
    """Raised when a registry manifest is missing required fields."""


@dataclass(frozen=True)
class RegistryToolEntry:
    name: str
    description: str
    schema: dict[str, Any]
    description_hash: str
    schema_hash: str


@dataclass(frozen=True)
class RegistryManifest:
    server_id: str
    version: str
    permissions: tuple[str, ...]
    tools: tuple[RegistryToolEntry, ...]

    def fingerprints(self) -> dict[str, ToolFingerprint]:
        return {
            t.name: ToolFingerprint(
                name=t.name,
                description_hash=t.description_hash,
                schema_hash=t.schema_hash,
            )
            for t in self.tools
        }


def _parse_manifest(raw: Any, *, source: Path) -> RegistryManifest:
    if not isinstance(raw, dict):
        raise RegistryManifestError(f"{source}: top-level must be a mapping")
    for key in ("server_id", "version", "permissions", "tools"):
        if key not in raw:
            raise RegistryManifestError(f"{source}: missing required key {key!r}")
    if not isinstance(raw["permissions"], list):
        raise RegistryManifestError(f"{source}: permissions must be a list")
    if not isinstance(raw["tools"], list):
        raise RegistryManifestError(f"{source}: tools must be a list")

    tools: list[RegistryToolEntry] = []
    for tool_raw in raw["tools"]:
        if not isinstance(tool_raw, dict):
            raise RegistryManifestError(f"{source}: each tool must be a mapping")
        for tool_key in ("name", "description", "schema"):
            if tool_key not in tool_raw:
                raise RegistryManifestError(
                    f"{source}: tool missing required key {tool_key!r}"
                )
        fp = fingerprint_tool(
            name=str(tool_raw["name"]),
            description=str(tool_raw["description"]),
            schema=tool_raw["schema"],
        )
        tools.append(
            RegistryToolEntry(
                name=str(tool_raw["name"]),
                description=str(tool_raw["description"]),
                schema=tool_raw["schema"],
                description_hash=fp.description_hash,
                schema_hash=fp.schema_hash,
            )
        )

    return RegistryManifest(
        server_id=str(raw["server_id"]),
        version=str(raw["version"]),
        permissions=tuple(str(p) for p in raw["permissions"]),
        tools=tuple(tools),
    )


def _semver_key(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in version.split("."):
        try:
            parts.append(int(chunk))
        except ValueError:
            parts.append(0)
    return tuple(parts)


class FakeRegistry:
    def __init__(self, manifests: dict[str, dict[str, RegistryManifest]]) -> None:
        self._manifests = manifests

    @classmethod
    def from_directory(cls, directory: Path) -> "FakeRegistry":
        directory = Path(directory)
        if not directory.is_dir():
            raise FileNotFoundError(directory)
        manifests: dict[str, dict[str, RegistryManifest]] = {}
        for path in sorted(directory.glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            manifest = _parse_manifest(data, source=path)
            per_server = manifests.setdefault(manifest.server_id, {})
            if manifest.version in per_server:
                raise RegistryManifestError(
                    f"duplicate version {manifest.version!r} for "
                    f"server {manifest.server_id!r} (in {path})"
                )
            per_server[manifest.version] = manifest
        return cls(manifests)

    def versions(self, server_id: str) -> list[str]:
        per_server = self._manifests.get(server_id, {})
        return sorted(per_server.keys(), key=_semver_key)

    def get(self, *, server_id: str, version: str) -> RegistryManifest:
        per_server = self._manifests[server_id]
        if version == "latest":
            chosen = max(per_server.keys(), key=_semver_key)
            return per_server[chosen]
        return per_server[version]
