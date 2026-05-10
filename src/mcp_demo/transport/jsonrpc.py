"""Minimal JSON-RPC 2.0 envelope used by the MCP demo facade.

We intentionally implement a small, well-documented subset rather than
pulling in the official MCP Python SDK. The reasons:

- the demo needs deliberate per-mode (vulnerable / defended) behaviour for
  every JSON-RPC call, including request- and response-level mutations
  (poisoned tool descriptions, hidden BCC arguments). A small facade keeps
  those deliberate mutations in plain sight.
- the demo treats Streamable HTTP as a teaching surface, not a production
  protocol. We only support what we test.

If a future commit replaces this with the SDK, the swap point is the
:func:`parse_request` / :class:`JsonRpcResponse` boundary; nothing outside
``transport/`` touches JSON-RPC details directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# Standard JSON-RPC error codes (https://www.jsonrpc.org/specification).
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# MCP-specific demo codes (in the JSON-RPC application range).
SESSION_REQUIRED = -32001
SESSION_INVALID = -32002


@dataclass(frozen=True)
class JsonRpcError:
    code: int
    message: str
    data: Any = None

    def to_response(self, *, request_id: Any) -> dict[str, Any]:
        body: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": self.code, "message": self.message},
        }
        if self.data is not None:
            body["error"]["data"] = self.data
        return body


class JsonRpcParseError(Exception):
    """Raised when an inbound payload is not a valid JSON-RPC request."""

    def __init__(self, error: JsonRpcError, request_id: Any = None) -> None:
        super().__init__(error.message)
        self.error = error
        self.request_id = request_id


@dataclass(frozen=True)
class JsonRpcRequest:
    jsonrpc: str
    id: Any
    method: str
    params: Any | None


def parse_request(payload: Any) -> JsonRpcRequest:
    if isinstance(payload, list):
        raise JsonRpcParseError(
            JsonRpcError(
                code=INVALID_REQUEST,
                message=(
                    "batch requests are not supported by this demo "
                    "(per JSON-RPC 2.0 -32600)"
                ),
            )
        )
    if not isinstance(payload, dict):
        raise JsonRpcParseError(
            JsonRpcError(
                code=INVALID_REQUEST,
                message="JSON-RPC payload must be a JSON object",
            )
        )

    request_id = payload.get("id")

    jsonrpc = payload.get("jsonrpc")
    if jsonrpc != "2.0":
        raise JsonRpcParseError(
            JsonRpcError(
                code=INVALID_REQUEST,
                message="jsonrpc field must be the literal string '2.0'",
            ),
            request_id=request_id,
        )

    method = payload.get("method")
    if not isinstance(method, str) or not method:
        raise JsonRpcParseError(
            JsonRpcError(
                code=INVALID_REQUEST,
                message="method must be a non-empty string",
            ),
            request_id=request_id,
        )

    params = payload.get("params")
    if params is not None and not isinstance(params, (dict, list)):
        raise JsonRpcParseError(
            JsonRpcError(
                code=INVALID_REQUEST,
                message="params must be an object or array when present",
            ),
            request_id=request_id,
        )

    return JsonRpcRequest(
        jsonrpc=jsonrpc,
        id=request_id,
        method=method,
        params=params,
    )


def success_response(*, request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_response(*, request_id: Any, error: JsonRpcError) -> dict[str, Any]:
    return error.to_response(request_id=request_id)
