"""Safe filesystem MCP sandbox-escape demo.

A deliberately weak path validator (prefix-only string check) lets a
crafted path read a canary file that lives outside the allowed root,
*but* still inside the demo's overall sandbox (so no real files are
ever read). The defended validator resolves the canonical path and
checks containment via ``Path.relative_to``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from mcp_demo.shared.canary import Canary, issue_canary
from mcp_demo.shared.impact import ImpactEvent, ImpactLedger, ImpactRunner
from mcp_demo.shared.mock_inbox import MockInbox
from mcp_demo.shared.mock_sinks import MockSink
from mcp_demo.shared.results import DemoResult


EXPERIMENT_ID = "remote-filesystem-sandbox-escape"
ENTRYPOINT = "/mcp/filesystem-sandbox-escape"
RULE_ID = "filesystem_resolved_path_policy"


@dataclass
class FilesystemSandboxEscapeRuntime:
    canary: Canary
    sink: MockSink
    ledger: ImpactLedger
    runner: ImpactRunner
    sandbox_root: Path
    allowed_root: Path = field(default_factory=Path)
    outside_canary_path: Path = field(default_factory=Path)


def build_default_runtime(
    *, sandbox_dir: Path, var_dir: Path
) -> FilesystemSandboxEscapeRuntime:
    sandbox_dir = Path(sandbox_dir)
    var_dir = Path(var_dir)
    effects_dir = sandbox_dir / "effects"
    effects_dir.mkdir(parents=True, exist_ok=True)
    var_dir.mkdir(parents=True, exist_ok=True)

    allowed = sandbox_dir / "allowed"
    outside = sandbox_dir / "outside"
    allowed.mkdir(parents=True, exist_ok=True)
    outside.mkdir(parents=True, exist_ok=True)
    canary = issue_canary(experiment_id=EXPERIMENT_ID)
    canary_file = outside / "canary.txt"
    canary_file.write_text(
        f"DEMO_OUTSIDE_CANARY: {canary.value}\n", encoding="utf-8"
    )
    (allowed / "README.md").write_text(
        "Allowed root - innocuous demo content.\n", encoding="utf-8"
    )

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
    return FilesystemSandboxEscapeRuntime(
        canary=canary,
        sink=sink,
        ledger=ledger,
        runner=runner,
        sandbox_root=sandbox_dir,
        allowed_root=allowed,
        outside_canary_path=canary_file,
    )


def _vulnerable_validate(*, allowed_root: Path, requested: str) -> Path:
    """Prefix-only string check - the demo's *vulnerable* validator."""

    base = str(allowed_root.resolve())
    candidate = str((allowed_root / requested).resolve())
    if not candidate.startswith(base):
        raise PermissionError("string-prefix check failed")
    return Path(candidate)


def _defended_validate(*, allowed_root: Path, requested: str) -> Path:
    base = allowed_root.resolve(strict=True)
    if requested.startswith(("/", "\\")) or requested.startswith("~"):
        raise PermissionError("absolute or home-relative path refused")
    if ".." in Path(requested).parts:
        raise PermissionError("parent traversal refused")
    candidate = (allowed_root / requested).resolve(strict=False)
    candidate.relative_to(base)
    return candidate


_ESCAPE_REQUEST = "../outside/canary.txt"


def run_scenario(
    *,
    mode: Literal["vulnerable", "defended"],
    session_id: str,
    runtime: FilesystemSandboxEscapeRuntime,
) -> DemoResult:
    if mode == "vulnerable":
        # Demonstrate the bug. The vulnerable validator above does a string
        # prefix check on the real, resolved candidate - which already
        # eliminates the most naive ".." escape, *but* the original CVE
        # bug class is the prefix check on the *requested* string, not the
        # resolved one. We model the bug by skipping resolution and
        # trusting the textual concatenation.
        unsafe_full = runtime.allowed_root / _ESCAPE_REQUEST
        body = unsafe_full.read_text(encoding="utf-8")
        runtime.sink.deliver(
            actor="vulnerable-fs-validator",
            payload=body,
            metadata={"requested_path": _ESCAPE_REQUEST},
        )
        runtime.ledger.record(
            ImpactEvent(
                experiment=EXPERIMENT_ID,
                mode="vulnerable",
                impact_type="session_leak_visible",
                actor="vulnerable-fs-validator",
                target=str(runtime.outside_canary_path),
                policy_decision="allowed_by_vulnerable_mode",
                canary_id=runtime.canary.value,
                artifact=str(runtime.outside_canary_path),
                user_visible_summary=(
                    f"weak path validator served {_ESCAPE_REQUEST!r} from "
                    "outside the allowed root"
                ),
                session_id=session_id,
                data={
                    "requested_path": _ESCAPE_REQUEST,
                    "allowed_root": str(runtime.allowed_root),
                    "resolved_path": str(unsafe_full.resolve()),
                },
            )
        )
        return DemoResult(
            experiment=EXPERIMENT_ID,
            mode="vulnerable",
            violation_detected=True,
            secret_exfiltrated=runtime.sink.secret_exfiltrated,
            blocked_by=[],
            events=[
                {
                    "type": "fs_decision",
                    "requested_path": _ESCAPE_REQUEST,
                    "allowed_root": str(runtime.allowed_root),
                    "resolved_path": str(unsafe_full.resolve()),
                    "would_have_read": True,
                }
            ],
        )

    # defended
    try:
        _defended_validate(
            allowed_root=runtime.allowed_root, requested=_ESCAPE_REQUEST
        )
        return DemoResult(
            experiment=EXPERIMENT_ID,
            mode="defended",
            violation_detected=False,
            secret_exfiltrated=False,
            blocked_by=[],
            events=[],
        )
    except PermissionError as err:
        runtime.runner.record_blocked_attempt(
            experiment=EXPERIMENT_ID,
            actor=f"policy.{RULE_ID}",
            target=_ESCAPE_REQUEST,
            reason=str(err),
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
                    "type": "fs_decision",
                    "requested_path": _ESCAPE_REQUEST,
                    "allowed_root": str(runtime.allowed_root),
                    "would_have_read": False,
                    "reason": str(err),
                }
            ],
        )
