"""Streamable HTTP transport for the MCP demo.

This module wires JSON-RPC into FastAPI/Starlette routes so each experiment
exposes the same minimal MCP shape:

- ``POST <entrypoint>`` accepts a single JSON-RPC request and returns a
  single JSON-RPC response (no batches; no SSE).
- ``GET  <entrypoint>`` returns ``405`` until SSE is wired in.

Cross-cutting checks live here, not in handlers:

- Origin must be allowlisted (HTTP 403 otherwise).
- ``initialize`` issues a fresh :class:`SessionStore` entry and returns the
  ``Mcp-Session-Id`` header.
- Subsequent requests must carry a known ``Mcp-Session-Id``.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from mcp_demo.config import DemoSettings
from mcp_demo.transport.jsonrpc import (
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    SESSION_INVALID,
    SESSION_REQUIRED,
    JsonRpcError,
    JsonRpcParseError,
    JsonRpcRequest,
    error_response,
    parse_request,
    success_response,
)


SESSION_HEADER = "Mcp-Session-Id"

# Returned by `initialize` and embedded in tool/list responses.
PROTOCOL_VERSION = "2025-03-26"


def _new_session_id() -> str:
    # token_urlsafe gives URL-safe base64 (printable ASCII).
    return secrets.token_urlsafe(24)


@dataclass
class Session:
    id: str
    created_at: datetime
    initialize_params: dict[str, Any] = field(default_factory=dict)


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def create(self, *, initialize_params: Mapping[str, Any] | None = None) -> Session:
        session = Session(
            id=_new_session_id(),
            created_at=datetime.now(tz=timezone.utc),
            initialize_params=dict(initialize_params or {}),
        )
        self._sessions[session.id] = session
        return session

    def get(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def reset(self) -> None:
        self._sessions.clear()


# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]

    def to_jsonrpc(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


ToolCallHandler = Callable[
    [str, dict[str, Any], Session],
    Awaitable[dict[str, Any]] | dict[str, Any],
]


@dataclass
class ExperimentEndpoint:
    """The minimal handler contract a demo MCP endpoint must satisfy."""

    experiment_id: str
    entrypoint: str
    list_tools: Callable[[Session], list[ToolSpec]]
    call_tool: ToolCallHandler
    server_name: str
    server_version: str


# ---------------------------------------------------------------------------


def _origin_ok(request: Request, settings: DemoSettings) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return False
    return origin in settings.allowed_origins


def _forbidden(reason: str) -> JSONResponse:
    return JSONResponse(
        status_code=403, content={"error": "forbidden", "reason": reason}
    )


def _bad_request(error: JsonRpcError, request_id: Any = None) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content=error_response(request_id=request_id, error=error),
    )


async def _maybe_await(value: Any) -> Any:
    if hasattr(value, "__await__"):
        return await value
    return value


def build_endpoint_router(
    *,
    endpoint: ExperimentEndpoint,
    sessions: SessionStore,
    settings: DemoSettings,
) -> APIRouter:
    """Mount POST/GET handlers for a single experiment endpoint."""

    router = APIRouter()

    @router.post(endpoint.entrypoint)
    async def handle_post(request: Request) -> Response:
        if not _origin_ok(request, settings):
            return _forbidden("origin not allowlisted")

        try:
            payload = await request.json()
        except Exception:
            return _bad_request(
                JsonRpcError(code=INVALID_REQUEST, message="invalid JSON body")
            )

        try:
            rpc_request: JsonRpcRequest = parse_request(payload)
        except JsonRpcParseError as err:
            return _bad_request(err.error, request_id=err.request_id)

        if rpc_request.method == "initialize":
            return await _handle_initialize(rpc_request, endpoint, sessions)

        # All non-initialize methods require a session.
        session_id = request.headers.get(SESSION_HEADER)
        if not session_id:
            return _bad_request(
                JsonRpcError(
                    code=SESSION_REQUIRED,
                    message=(
                        f"{SESSION_HEADER} header is required for method "
                        f"{rpc_request.method!r}"
                    ),
                ),
                request_id=rpc_request.id,
            )
        session = sessions.get(session_id)
        if session is None:
            return _bad_request(
                JsonRpcError(
                    code=SESSION_INVALID,
                    message=f"unknown {SESSION_HEADER}",
                ),
                request_id=rpc_request.id,
            )

        if rpc_request.method == "tools/list":
            return JSONResponse(
                success_response(
                    request_id=rpc_request.id,
                    result={
                        "tools": [t.to_jsonrpc() for t in endpoint.list_tools(session)]
                    },
                )
            )

        if rpc_request.method == "tools/call":
            params = rpc_request.params or {}
            if not isinstance(params, dict):
                return JSONResponse(
                    error_response(
                        request_id=rpc_request.id,
                        error=JsonRpcError(
                            code=INVALID_REQUEST,
                            message="tools/call params must be an object",
                        ),
                    )
                )
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(name, str) or not isinstance(arguments, dict):
                return JSONResponse(
                    error_response(
                        request_id=rpc_request.id,
                        error=JsonRpcError(
                            code=INVALID_REQUEST,
                            message="tools/call requires name (str) and arguments (object)",
                        ),
                    )
                )
            try:
                result = await _maybe_await(
                    endpoint.call_tool(name, arguments, session)
                )
            except KeyError:
                return JSONResponse(
                    error_response(
                        request_id=rpc_request.id,
                        error=JsonRpcError(
                            code=METHOD_NOT_FOUND,
                            message=f"unknown tool: {name!r}",
                        ),
                    )
                )
            return JSONResponse(
                success_response(request_id=rpc_request.id, result=result)
            )

        return JSONResponse(
            error_response(
                request_id=rpc_request.id,
                error=JsonRpcError(
                    code=METHOD_NOT_FOUND,
                    message=f"method not found: {rpc_request.method!r}",
                ),
            )
        )

    @router.get(endpoint.entrypoint)
    async def handle_get(request: Request) -> Response:
        # SSE not implemented for the foundation step; returning 405 is the
        # documented contract until prompts that need streaming arrive.
        if not _origin_ok(request, settings):
            return _forbidden("origin not allowlisted")
        return Response(status_code=405)

    return router


async def _handle_initialize(
    request: JsonRpcRequest,
    endpoint: ExperimentEndpoint,
    sessions: SessionStore,
) -> Response:
    params = request.params if isinstance(request.params, dict) else {}
    session = sessions.create(initialize_params=params)
    body = success_response(
        request_id=request.id,
        result={
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {
                "name": endpoint.server_name,
                "version": endpoint.server_version,
            },
        },
    )
    return JSONResponse(content=body, headers={SESSION_HEADER: session.id})
