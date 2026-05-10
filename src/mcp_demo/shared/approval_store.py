"""User-consent store for tool metadata.

An approval binds (server_id, tool_name, description_hash, schema_hash) to
a user. When any of those four fields changes between loads, the
approval no longer applies and the defended demo refuses until the user
re-approves. This is the smallest mechanism that catches a sleeper rug
pull, where a benign first load is followed by a poisoned second load.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp_demo.shared.tool_metadata import ToolFingerprint


__all__ = ["ApprovalStore", "ToolFingerprint"]


@dataclass(frozen=True)
class _ApprovalKey:
    server_id: str
    tool_name: str
    description_hash: str
    schema_hash: str


@dataclass(frozen=True)
class ApprovalRecord:
    user: str
    fingerprint: ToolFingerprint


class ApprovalStore:
    def __init__(self) -> None:
        self._records: dict[_ApprovalKey, ApprovalRecord] = {}
        # Per (server_id, tool_name) we also track the *last* approved
        # fingerprint so the defended demo can show a diff between the
        # previously approved metadata and the new metadata.
        self._latest_per_tool: dict[tuple[str, str], ToolFingerprint] = {}

    def record(
        self, *, server_id: str, fingerprint: ToolFingerprint, user: str
    ) -> None:
        key = _ApprovalKey(
            server_id=server_id,
            tool_name=fingerprint.name,
            description_hash=fingerprint.description_hash,
            schema_hash=fingerprint.schema_hash,
        )
        self._records[key] = ApprovalRecord(user=user, fingerprint=fingerprint)
        self._latest_per_tool[(server_id, fingerprint.name)] = fingerprint

    def is_approved(
        self, *, server_id: str, fingerprint: ToolFingerprint
    ) -> bool:
        key = _ApprovalKey(
            server_id=server_id,
            tool_name=fingerprint.name,
            description_hash=fingerprint.description_hash,
            schema_hash=fingerprint.schema_hash,
        )
        return key in self._records

    def latest(
        self, *, server_id: str, tool_name: str
    ) -> ToolFingerprint | None:
        return self._latest_per_tool.get((server_id, tool_name))

    def diff(
        self, *, server_id: str, fingerprint: ToolFingerprint
    ) -> dict[str, tuple[str, str] | None] | None:
        previous = self.latest(server_id=server_id, tool_name=fingerprint.name)
        if previous is None:
            return None
        return {
            "description_hash": (
                (previous.description_hash, fingerprint.description_hash)
                if previous.description_hash != fingerprint.description_hash
                else None
            ),
            "schema_hash": (
                (previous.schema_hash, fingerprint.schema_hash)
                if previous.schema_hash != fingerprint.schema_hash
                else None
            ),
        }
