"""Safe SSRF metadata-discovery simulation.

A poisoned tool in the demo asks the agent to fetch
``https://metadata.attacker.example/latest/meta-data/`` for "service
discovery". The host is allowlisted (the operator approved it), but the
mock resolver maps it to ``169.254.169.254``. In the vulnerable mode the
demo records that the client *would* have hit the cloud-metadata
endpoint - without performing any real network call. In the defended mode
the URL-safety classifier refuses before any simulated fetch.

No real DNS lookup, no real socket connect: tests assert this with
``socket.getaddrinfo`` and ``urllib.request.urlopen`` monkeypatches.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from mcp_demo.shared.canary import Canary, issue_canary
from mcp_demo.shared.impact import ImpactEvent, ImpactLedger, ImpactRunner
from mcp_demo.shared.mock_inbox import MockInbox
from mcp_demo.shared.mock_resolver import MockResolver
from mcp_demo.shared.mock_sinks import MockSink
from mcp_demo.shared.results import DemoResult
from mcp_demo.shared.url_safety import classify_url


EXPERIMENT_ID = "remote-ssrf-metadata"
ENTRYPOINT = "/mcp/ssrf-metadata"
RULE_ID = "url_safety_policy"

DEMO_TARGET_URL = "https://metadata.attacker.example/latest/meta-data/"
DEMO_HOST = "metadata.attacker.example"


@dataclass
class SsrfMetadataRuntime:
    canary: Canary
    sink: MockSink
    ledger: ImpactLedger
    runner: ImpactRunner
    resolver: MockResolver
    sandbox_dir: Path


def build_default_runtime(
    *, sandbox_dir: Path, var_dir: Path
) -> SsrfMetadataRuntime:
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
    resolver = MockResolver(
        records={
            DEMO_HOST: ["169.254.169.254"],
            "auth.example": ["203.0.113.10"],
        }
    )
    return SsrfMetadataRuntime(
        canary=canary,
        sink=sink,
        ledger=ledger,
        runner=runner,
        resolver=resolver,
        sandbox_dir=sandbox_dir,
    )


def run_scenario(
    *,
    mode: Literal["vulnerable", "defended"],
    session_id: str,
    runtime: SsrfMetadataRuntime,
) -> DemoResult:
    classification = classify_url(
        DEMO_TARGET_URL,
        allowed_hosts={DEMO_HOST},
        resolver=runtime.resolver,
    )

    if mode == "vulnerable":
        # No URL-safety check: the simulator pretends to fetch.
        artifact = runtime.sandbox_dir / "effects" / (
            f"ssrf-metadata-{session_id}.json"
        )
        artifact.write_text(
            json.dumps(
                {
                    "url": DEMO_TARGET_URL,
                    "resolved_ips": list(classification.resolved_ips),
                    "would_have_fetched": True,
                    "carried_canary": runtime.canary.value,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        runtime.ledger.record(
            ImpactEvent(
                experiment=EXPERIMENT_ID,
                mode="vulnerable",
                impact_type="sandbox_file_written",
                actor="ssrf-simulator",
                target=DEMO_TARGET_URL,
                policy_decision="allowed_by_vulnerable_mode",
                canary_id=runtime.canary.value,
                artifact=str(artifact),
                user_visible_summary=(
                    f"client would have fetched {DEMO_TARGET_URL!r}; "
                    f"resolved IPs: {list(classification.resolved_ips)!r}"
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
                    "type": "ssrf_decision",
                    "url": DEMO_TARGET_URL,
                    "resolved_ips": list(classification.resolved_ips),
                    "classification": "would_have_fetched",
                    "would_have_fetched": True,
                    "reason": classification.reason,
                }
            ],
        )

    # defended
    if classification.allowed:
        # No drift: the simulator can proceed (in this demo, the host always
        # resolves internally, so this branch is for completeness).
        return DemoResult(
            experiment=EXPERIMENT_ID,
            mode="defended",
            violation_detected=False,
            secret_exfiltrated=False,
            blocked_by=[],
            events=[],
        )

    runtime.runner.record_blocked_attempt(
        experiment=EXPERIMENT_ID,
        actor=f"policy.{RULE_ID}",
        target=DEMO_TARGET_URL,
        reason=classification.reason,
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
                "type": "ssrf_decision",
                "url": DEMO_TARGET_URL,
                "resolved_ips": list(classification.resolved_ips),
                "classification": "blocked",
                "would_have_fetched": False,
                "reason": classification.reason,
            }
        ],
    )
