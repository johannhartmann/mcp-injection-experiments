"""Catalog-completeness checks for the 2025-2026 expansion phase.

Every expansion-phase manifest must:

- live under ``experiments/manifests/`` and load through
  :class:`ExperimentRegistry`,
- expose both ``vulnerable`` and ``defended`` modes,
- declare at least one MCP surface,
- declare at least one OWASP id or one Agent-Trap family,
- list at least one demo-zone artefact for vulnerable mode and one for
  defended mode (the latter is allowed to be ``var/telemetry.jsonl``
  alone).

The HTTP dashboard must list every expansion experiment on ``/demo``
and accept a vulnerable + defended ``/demo/scenario`` POST for each one.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from mcp_demo.app import create_app
from mcp_demo.experiments.registry import ExperimentRegistry


_REPO_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST_DIR = _REPO_ROOT / "experiments" / "manifests"


_EXPANSION_IDS = {
    "remote-github-issue-leak",
    "remote-slack-unfurl-leak",
    "remote-filesystem-sandbox-escape",
    "remote-inspector-proxy-auth-bypass",
    "remote-mcp-remote-auth-endpoint-injection",
    "remote-trustfall-project-mcp-settings",
    "remote-cross-agent-config-priv-esc",
    "remote-promptware-heartbeat",
    "remote-ai-clickfix",
    "remote-implicit-tool-poisoning",
    "remote-comment-and-control",
    "remote-agent-traps-hidden-html",
    "remote-agent-traps-memory-poisoning",
    "remote-agent-traps-subagent-spawning",
    "remote-agent-traps-approval-fatigue",
    "remote-agent-traps-sybil-and-fragments",
    "remote-git-filesystem-chain-safe",
}


def test_every_expansion_id_is_in_the_registry() -> None:
    registry = ExperimentRegistry.from_directory(_MANIFEST_DIR)
    missing = _EXPANSION_IDS - set(registry.list_ids())
    assert not missing, f"missing expansion manifests: {sorted(missing)}"


def test_every_expansion_manifest_supports_both_modes() -> None:
    registry = ExperimentRegistry.from_directory(_MANIFEST_DIR)
    for experiment_id in _EXPANSION_IDS:
        manifest = registry.get(experiment_id)
        assert manifest.phase == "expansion-2025-2026"
        assert "vulnerable" in manifest.mode_support
        assert "defended" in manifest.mode_support


def test_every_expansion_manifest_declares_mcp_surfaces_and_safe_impact() -> None:
    registry = ExperimentRegistry.from_directory(_MANIFEST_DIR)
    for experiment_id in _EXPANSION_IDS:
        manifest = registry.get(experiment_id)
        assert manifest.mcp_surfaces, f"{experiment_id} has no mcp_surfaces"
        assert manifest.safe_impact is not None
        assert manifest.safe_impact.vulnerable_artifacts
        assert manifest.safe_impact.defended_artifacts


def test_every_expansion_manifest_declares_owasp_or_agent_traps() -> None:
    registry = ExperimentRegistry.from_directory(_MANIFEST_DIR)
    for experiment_id in _EXPANSION_IDS:
        manifest = registry.get(experiment_id)
        assert manifest.owasp or manifest.agent_traps


@pytest.fixture
async def client():
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as ac:
        yield ac


async def test_demo_index_lists_every_expansion_experiment(
    client: AsyncClient,
) -> None:
    response = await client.get(
        "/demo",
        headers={"Origin": "http://testserver", "Accept": "text/html"},
    )
    assert response.status_code == 200
    body = response.text
    for experiment_id in _EXPANSION_IDS:
        assert experiment_id in body, f"{experiment_id} missing from /demo"


@pytest.mark.parametrize("experiment_id", sorted(_EXPANSION_IDS))
async def test_each_expansion_runs_vulnerable_and_defended_through_http(
    client: AsyncClient, experiment_id: str
) -> None:
    for mode in ("vulnerable", "defended"):
        response = await client.post(
            f"/demo/scenario/{experiment_id}",
            headers={"Origin": "http://testserver"},
            json={"mode": mode, "session_id": f"cat-{mode}-{experiment_id}"},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["experiment"] == experiment_id
        assert body["mode"] == mode


async def test_defended_runs_record_a_block_event(client: AsyncClient) -> None:
    """Each expansion experiment should record a blocked_attempt_recorded
    event in defended mode (the catalog contract). Subagent spawning's
    defended-with-trusted-operator path is not invoked here because the
    canonical /demo/scenario shape has no operator-source argument; the
    default invocation triggers a block."""

    for experiment_id in _EXPANSION_IDS:
        sid = f"cat-block-{experiment_id}"
        await client.post(
            f"/demo/scenario/{experiment_id}",
            headers={"Origin": "http://testserver"},
            json={"mode": "defended", "session_id": sid},
        )
        response = await client.get(
            f"/demo/events?session_id={sid}",
            headers={"Origin": "http://testserver"},
        )
        events = response.json()["events"]
        assert any(
            e["event_type"] == "policy_decision" for e in events
        ), f"{experiment_id} did not emit a policy_decision in defended mode"
