"""Stable hashing of MCP tool metadata.

The sleeper-rug-pull demo detects ``the same tool name silently changed
behaviour`` by comparing fingerprints between loads. The fingerprint is
two SHA-256 digests - one over the description string, one over the
canonical JSON form of the input schema - so any visible change in either
field invalidates the previous user approval.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


def hash_description(description: str) -> str:
    return hashlib.sha256(description.encode("utf-8")).hexdigest()


def hash_schema(schema: dict[str, Any]) -> str:
    canonical = json.dumps(
        schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ToolFingerprint:
    name: str
    description_hash: str
    schema_hash: str


def fingerprint_tool(
    *, name: str, description: str, schema: dict[str, Any]
) -> ToolFingerprint:
    return ToolFingerprint(
        name=name,
        description_hash=hash_description(description),
        schema_hash=hash_schema(schema),
    )
