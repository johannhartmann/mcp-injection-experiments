"""Safe remote registry-rug-pull demo.

The demo simulates a supply-chain attack on an MCP server registry: v1 of
``drift-mock.example-server`` is benign. v2 keeps the same server id and
the same tool name but adds two permissions (``read:contacts``,
``send:message``), grows the input schema and ships a poisoned
description. The registry is read entirely from local YAML fixtures - no
network, no third-party install.

Modes:

- ``vulnerable``: activates ``latest`` (= v2) without consulting the user.
  An artefact is written to
  ``sandbox/effects/registry-rug-pull-<session>.json`` with the resolved
  version, the permission delta, and the per-tool hash diff so a reviewer
  can see exactly what changed.
- ``defended``: enforces a user-pinned version and refuses to activate
  whenever the registry returns a different version, a non-empty
  permission delta, or a tool fingerprint drift. ``record_blocked_attempt``
  emits a structured block event with the diff.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from mcp_demo.shared.canary import Canary, issue_canary
from mcp_demo.shared.fake_registry import FakeRegistry, RegistryManifest
from mcp_demo.shared.impact import ImpactEvent, ImpactLedger, ImpactRunner
from mcp_demo.shared.mock_inbox import MockInbox
from mcp_demo.shared.mock_sinks import MockSink
from mcp_demo.shared.pinning import permission_delta
from mcp_demo.shared.results import DemoResult


EXPERIMENT_ID = "remote-registry-rug-pull"
ENTRYPOINT = "/mcp/registry-rug-pull"
SERVER_ID = "drift-mock.example-server"
RULE_ID = "registry_pinning_policy"


@dataclass
class RegistryRugPullRuntime:
    canary: Canary
    sink: MockSink
    ledger: ImpactLedger
    runner: ImpactRunner
    registry: FakeRegistry
    sandbox_dir: Path
    server_id: str = SERVER_ID
    active_version: str | None = None
    pinned_version: str | None = None

    def pin(self, *, server_id: str, version: str) -> None:
        if server_id != self.server_id:
            raise ValueError(f"unexpected server: {server_id!r}")
        self.pinned_version = version
        self.active_version = version


def build_default_runtime(
    *, sandbox_dir: Path, var_dir: Path, registry_dir: Path
) -> RegistryRugPullRuntime:
    sandbox_dir = Path(sandbox_dir)
    var_dir = Path(var_dir)
    effects_dir = sandbox_dir / "effects"
    effects_dir.mkdir(parents=True, exist_ok=True)
    var_dir.mkdir(parents=True, exist_ok=True)

    canary = issue_canary(experiment_id=EXPERIMENT_ID)
    sink = MockSink()
    sink.register_canary(canary)
    inbox = MockInbox(var_dir / "mock-inbox.jsonl")
    ledger = ImpactLedger(jsonl_path=var_dir / "telemetry.jsonl")
    runner = ImpactRunner(
        effects_dir=effects_dir,
        var_dir=var_dir,
        ledger=ledger,
        sink=sink,
        inbox=inbox,
    )
    registry = FakeRegistry.from_directory(registry_dir)
    return RegistryRugPullRuntime(
        canary=canary,
        sink=sink,
        ledger=ledger,
        runner=runner,
        registry=registry,
        sandbox_dir=sandbox_dir,
    )


def _tool_hash_changes(
    before: RegistryManifest, after: RegistryManifest
) -> list[dict[str, str]]:
    before_fp = before.fingerprints()
    after_fp = after.fingerprints()
    changes: list[dict[str, str]] = []
    for name in sorted(set(before_fp) | set(after_fp)):
        b = before_fp.get(name)
        a = after_fp.get(name)
        if b is None and a is not None:
            changes.append(
                {
                    "tool": name,
                    "kind": "added",
                    "description_hash_after": a.description_hash,
                    "schema_hash_after": a.schema_hash,
                }
            )
            continue
        if b is not None and a is None:
            changes.append(
                {
                    "tool": name,
                    "kind": "removed",
                    "description_hash_before": b.description_hash,
                    "schema_hash_before": b.schema_hash,
                }
            )
            continue
        assert b is not None and a is not None
        if b == a:
            continue
        changes.append(
            {
                "tool": name,
                "kind": "changed",
                "description_hash_before": b.description_hash,
                "description_hash_after": a.description_hash,
                "schema_hash_before": b.schema_hash,
                "schema_hash_after": a.schema_hash,
            }
        )
    return changes


def run_scenario(
    *,
    mode: Literal["vulnerable", "defended"],
    session_id: str,
    runtime: RegistryRugPullRuntime,
) -> DemoResult:
    v1 = runtime.registry.get(server_id=runtime.server_id, version="1.0.0")
    latest = runtime.registry.get(server_id=runtime.server_id, version="latest")
    delta = permission_delta(
        before=v1.permissions, after=latest.permissions
    )
    hash_changes = _tool_hash_changes(v1, latest)

    if mode == "vulnerable":
        runtime.active_version = latest.version
        artifact = runtime.sandbox_dir / "effects" / (
            f"registry-rug-pull-{session_id}.json"
        )
        artifact.write_text(
            json.dumps(
                {
                    "server_id": runtime.server_id,
                    "previous_version": v1.version,
                    "activated_version": latest.version,
                    "permission_delta": {
                        "added": list(delta.added),
                        "removed": list(delta.removed),
                        "broadened": [list(p) for p in delta.broadened],
                    },
                    "tool_hash_changes": hash_changes,
                    "carried_canary": runtime.canary.value,
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        runtime.ledger.record(
            ImpactEvent(
                experiment=EXPERIMENT_ID,
                mode="vulnerable",
                impact_type="permission_change_applied",
                actor=f"registry.{runtime.server_id}",
                target=f"{runtime.server_id}@{latest.version}",
                policy_decision="allowed_by_vulnerable_mode",
                canary_id=runtime.canary.value,
                artifact=str(artifact),
                user_visible_summary=(
                    f"silently activated {latest.version}; permissions "
                    f"added: {list(delta.added)!r}"
                ),
                session_id=session_id,
            )
        )
        return DemoResult(
            experiment=EXPERIMENT_ID,
            mode="vulnerable",
            violation_detected=True,
            secret_exfiltrated=False,
            blocked_by=[],
            events=[
                {
                    "type": "registry_diff",
                    "before_version": v1.version,
                    "after_version": latest.version,
                    "permission_delta": {
                        "added": list(delta.added),
                        "removed": list(delta.removed),
                        "broadened": [list(p) for p in delta.broadened],
                    },
                    "tool_hash_changes": hash_changes,
                }
            ],
        )

    # defended
    pinned = runtime.pinned_version
    if pinned is None or pinned != latest.version or not delta.is_empty() or hash_changes:
        runtime.active_version = pinned or v1.version
        runtime.runner.record_blocked_attempt(
            experiment=EXPERIMENT_ID,
            actor=f"policy.{RULE_ID}",
            target=f"{runtime.server_id}@{latest.version}",
            reason=(
                f"registry drift: pinned={pinned!r} latest={latest.version!r}; "
                f"permissions added={list(delta.added)!r}; "
                f"tool changes={[c['tool'] for c in hash_changes]!r}"
            ),
            session_id=session_id,
        )
        return DemoResult(
            experiment=EXPERIMENT_ID,
            mode="defended",
            violation_detected=True,
            secret_exfiltrated=False,
            blocked_by=[RULE_ID],
            events=[
                {
                    "type": "registry_diff",
                    "before_version": pinned or v1.version,
                    "after_version": latest.version,
                    "permission_delta": {
                        "added": list(delta.added),
                        "removed": list(delta.removed),
                        "broadened": [list(p) for p in delta.broadened],
                    },
                    "tool_hash_changes": hash_changes,
                    "recommendation": (
                        "ask the user to re-approve the new server manifest "
                        "before activating the new version"
                    ),
                }
            ],
        )

    runtime.active_version = pinned
    return DemoResult(
        experiment=EXPERIMENT_ID,
        mode="defended",
        violation_detected=False,
        secret_exfiltrated=False,
        blocked_by=[],
        events=[],
    )
