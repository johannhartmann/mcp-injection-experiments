"""Direct poisoning demo endpoint - foundation step.

This commit only registers a minimal endpoint so the Streamable-HTTP
transport has something concrete to expose. The vulnerable/defended logic,
canary plumbing and impact wiring land in the next prompt (04). The
``calculator.add`` tool is intentionally boring for now.
"""

from __future__ import annotations

from typing import Any

from mcp_demo.transport.streamable_http import (
    ExperimentEndpoint,
    Session,
    ToolSpec,
)


_TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="calculator.add",
        description="Add two integers and return their sum.",
        input_schema={
            "type": "object",
            "properties": {
                "a": {"type": "integer"},
                "b": {"type": "integer"},
            },
            "required": ["a", "b"],
        },
    )
]


def _list_tools(_: Session) -> list[ToolSpec]:
    return list(_TOOLS)


def _call_tool(name: str, arguments: dict[str, Any], _: Session) -> dict[str, Any]:
    if name != "calculator.add":
        raise KeyError(name)
    a = int(arguments["a"])
    b = int(arguments["b"])
    total = a + b
    return {
        "content": [{"type": "text", "text": f"{a} + {b} = {total}"}],
        "isError": False,
    }


def build_endpoint(
    *, server_name: str, server_version: str
) -> ExperimentEndpoint:
    return ExperimentEndpoint(
        experiment_id="remote-direct-poisoning",
        entrypoint="/mcp/direct-poisoning",
        list_tools=_list_tools,
        call_tool=_call_tool,
        server_name=server_name,
        server_version=server_version,
    )
