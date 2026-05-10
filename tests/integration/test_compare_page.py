"""Side-by-side compare page tests.

The compare page must (1) render HTML, (2) trigger both vulnerable and
defended runs of the requested experiment, (3) show the tool-description
diff, (4) include the per-mode telemetry events, and (5) be reachable
through a link from /demo.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


async def test_compare_page_renders_html(client: AsyncClient) -> None:
    response = await client.get("/demo/compare/remote-direct-poisoning")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    assert "<html" in body
    assert "Direct Poisoning" in body or "remote-direct-poisoning" in body


async def test_compare_page_runs_both_modes(client: AsyncClient) -> None:
    body = (await client.get("/demo/compare/remote-direct-poisoning")).text
    # vulnerable column shows the leak, defended column shows the block.
    assert "vulnerable mode" in body.lower()
    assert "defended mode" in body.lower()
    # Each summary row has at least one pill for violation_detected.
    assert body.count("violation_detected") >= 2


async def test_compare_page_shows_tool_description_diff(client: AsyncClient) -> None:
    body = (await client.get("/demo/compare/remote-direct-poisoning")).text
    # Diff highlighting classes are present.
    assert "diff-add" in body or "diff-del" in body
    # The narrative tool name is shown.
    assert "calculator.add" in body


async def test_compare_page_lists_per_mode_tools(client: AsyncClient) -> None:
    body = (await client.get("/demo/compare/remote-tool-shadowing")).text
    # tool-shadowing exposes helper.add + run_demo.
    assert body.count("helper.add") >= 2  # one in vuln + one in def column
    assert "run_demo" in body


async def test_compare_page_unknown_experiment_returns_404(
    client: AsyncClient,
) -> None:
    response = await client.get("/demo/compare/does-not-exist")
    assert response.status_code == 404


async def test_compare_page_includes_mount_paths(client: AsyncClient) -> None:
    body = (await client.get("/demo/compare/remote-direct-poisoning")).text
    assert "/mcp/direct-poisoning/vulnerable/" in body
    assert "/mcp/direct-poisoning/defended/" in body


async def test_compare_link_present_on_demo_index(client: AsyncClient) -> None:
    body = (
        await client.get(
            "/demo",
            headers={"Origin": "http://testserver", "Accept": "text/html"},
        )
    ).text
    assert "/demo/compare/remote-direct-poisoning" in body
    assert "Compare side-by-side" in body


@pytest.mark.parametrize(
    "experiment_id",
    [
        "remote-direct-poisoning",
        "remote-tool-shadowing",
        "remote-github-issue-leak",
        "remote-agent-traps-hidden-html",
    ],
)
async def test_compare_page_works_for_multiple_experiments(
    client: AsyncClient, experiment_id: str
) -> None:
    response = await client.get(f"/demo/compare/{experiment_id}")
    assert response.status_code == 200
    body = response.text
    assert experiment_id in body
