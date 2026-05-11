"""Server-side Gemini Flash Lite agent that drives the live MCP servers.

When ``DEMO_GEMINI_ENABLED=1`` and ``GEMINI_API_KEY`` is set, the
dashboard exposes a "Run with Gemini Flash Lite" button per experiment.
That button posts to ``/demo/agent/<experiment_id>``; the route calls
:func:`run_agent` against the matching :class:`FastMCP` instance.

The runner is a bounded multi-step loop:

1. List the live MCP tools via ``server.list_tools()``.
2. Convert each tool's ``inputSchema`` into a Gemini
   :class:`FunctionDeclaration`.
3. Initialise a Gemini chat with the manifest's ``user_task`` as the
   first user turn.
4. On each model response, dispatch every ``function_call`` against the
   same FastMCP instance via ``server.call_tool``. Append the result
   back into the conversation as a ``function_response`` part.
5. Stop when the model returns a pure-text response or when
   ``max_steps`` is reached.

Tool calls fire the real server-side telemetry and impact ledger -
the dashboard's live-feed sidebar reflects each step in real time.

The runner is intentionally side-effect-light at the LLM boundary:
nothing other than the configured API key is sent to Google, and the
caller is responsible for deciding whether to enable the feature
(opt-in, gated by ``DemoSettings.gemini_enabled``).
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from typing import Any

from mcp.server.fastmcp import FastMCP


@dataclass
class AgentStep:
    """One tool call in the agent's transcript."""

    tool: str
    args: dict[str, Any]
    result: dict[str, Any]


@dataclass
class AgentRunResult:
    """End-to-end transcript returned by :func:`run_agent`."""

    model: str
    user_task: str
    steps: list[AgentStep] = field(default_factory=list)
    final_text: str | None = None
    max_steps_reached: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# JSON Schema fields Gemini's FunctionDeclaration parameters won't tolerate;
# strip recursively before sending. Empirically Gemini accepts the core JSON
# Schema subset (type, properties, required, items, enum, description) and
# ignores extension fields like ``title`` / ``$schema`` - removing them keeps
# the call quiet and avoids a validation error class that's easy to miss.
_GEMINI_DROP_KEYS = frozenset({"title", "$schema", "$id", "$ref", "examples"})


def _sanitise_schema(schema: Any) -> Any:
    if isinstance(schema, dict):
        return {
            k: _sanitise_schema(v)
            for k, v in schema.items()
            if k not in _GEMINI_DROP_KEYS
        }
    if isinstance(schema, list):
        return [_sanitise_schema(v) for v in schema]
    return schema


def _mcp_tools_to_function_declarations(mcp_tools: list[Any]) -> list[Any]:
    from google.genai import types

    decls = []
    for tool in mcp_tools:
        schema = _sanitise_schema(tool.inputSchema) if tool.inputSchema else {
            "type": "object", "properties": {},
        }
        decls.append(
            types.FunctionDeclaration(
                name=tool.name,
                description=tool.description or "",
                parameters=schema,
            )
        )
    return decls


async def _dispatch_tool_call(
    server: FastMCP, name: str, args: dict[str, Any]
) -> dict[str, Any]:
    """Call ``name`` on ``server`` and serialise the result for both the
    transcript and the model's next-turn ``function_response`` part.

    FastMCP's ``call_tool`` returns either a ``(content_list,
    structured_dict)`` tuple (tools with an output schema, e.g. a typed
    ``def add(...) -> int`` whose schema FastMCP derived) or just a
    ``content_list`` (tools whose return type FastMCP could not
    introspect into an output schema). We accept both."""

    try:
        result = await server.call_tool(name, args)
    except Exception as exc:  # surfaced into the transcript so the model sees it
        return {"isError": True, "error": str(exc), "errorType": type(exc).__name__}

    if isinstance(result, tuple) and len(result) == 2:
        content_parts, structured = result
    elif isinstance(result, list):
        content_parts, structured = result, None
    else:
        content_parts, structured = [result], None

    texts: list[str] = []
    for c in content_parts or []:
        text = getattr(c, "text", None)
        if isinstance(text, str):
            texts.append(text)
    payload: dict[str, Any] = {
        "content": [{"type": "text", "text": t} for t in texts],
        "isError": False,
    }
    if structured is not None:
        payload["structuredContent"] = structured
    return payload


async def run_agent(
    *,
    server: FastMCP,
    user_task: str,
    api_key: str,
    model: str = "gemini-3.1-flash-lite",
    max_steps: int = 5,
) -> AgentRunResult:
    """Run a bounded function-calling loop against ``server``.

    Both ``list_tools`` and ``call_tool`` are invoked in-process on the
    FastMCP instance - no HTTP/SSE round trips. Server-side telemetry
    fires from inside the tool handlers, identical to a real MCP client
    driving the same server over the network."""

    from google import genai
    from google.genai import types

    mcp_tools = await server.list_tools()
    function_decls = _mcp_tools_to_function_declarations(mcp_tools)
    config = types.GenerateContentConfig(
        tools=(
            [types.Tool(function_declarations=function_decls)]
            if function_decls
            else None
        ),
    )

    client = genai.Client(api_key=api_key)
    contents: list[Any] = [
        types.Content(role="user", parts=[types.Part(text=user_task)])
    ]
    result = AgentRunResult(model=model, user_task=user_task)

    for _ in range(max_steps):
        try:
            response = await asyncio.to_thread(
                client.models.generate_content,
                model=model,
                contents=contents,
                config=config,
            )
        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            return result

        candidate = response.candidates[0] if response.candidates else None
        if candidate is None or candidate.content is None:
            result.error = "model returned no candidate content"
            return result
        parts = candidate.content.parts or []

        function_calls = [
            p.function_call for p in parts
            if getattr(p, "function_call", None) is not None
        ]
        if not function_calls:
            text_chunks = [
                p.text for p in parts if getattr(p, "text", None)
            ]
            result.final_text = "".join(text_chunks) or response.text or None
            return result

        contents.append(candidate.content)
        function_response_parts: list[Any] = []
        for fc in function_calls:
            args = dict(fc.args) if fc.args else {}
            tool_result = await _dispatch_tool_call(server, fc.name, args)
            result.steps.append(AgentStep(tool=fc.name, args=args, result=tool_result))
            function_response_parts.append(
                types.Part(
                    function_response=types.FunctionResponse(
                        name=fc.name,
                        response=tool_result,
                    )
                )
            )
        contents.append(types.Content(role="user", parts=function_response_parts))

    result.max_steps_reached = True
    return result
