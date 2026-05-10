"""Tests for the JSON-RPC envelope parser used by the MCP transport.

The demo speaks JSON-RPC 2.0 with a fixed shape: ``jsonrpc`` must be the
literal string ``"2.0"``, ``method`` is required, ``id`` may be string,
integer or null. Batch requests are explicitly refused with the standard
``-32600`` invalid-request code so attacker-controlled batch shapes cannot
sneak past method-level validation.
"""

from __future__ import annotations

import pytest

from mcp_demo.transport.jsonrpc import (
    INVALID_REQUEST,
    JsonRpcError,
    JsonRpcParseError,
    JsonRpcRequest,
    parse_request,
)


def test_valid_request_is_parsed() -> None:
    payload = {
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "initialize",
        "params": {"protocolVersion": "2025-03-26"},
    }
    request = parse_request(payload)

    assert isinstance(request, JsonRpcRequest)
    assert request.id == "init-1"
    assert request.method == "initialize"
    assert request.params == {"protocolVersion": "2025-03-26"}


def test_request_without_jsonrpc_field_is_rejected() -> None:
    with pytest.raises(JsonRpcParseError) as excinfo:
        parse_request({"id": 1, "method": "tools/list"})

    assert excinfo.value.error.code == INVALID_REQUEST


def test_request_with_wrong_jsonrpc_version_is_rejected() -> None:
    with pytest.raises(JsonRpcParseError) as excinfo:
        parse_request(
            {"jsonrpc": "1.0", "id": 1, "method": "tools/list"}
        )

    assert excinfo.value.error.code == INVALID_REQUEST


def test_request_without_method_is_rejected() -> None:
    with pytest.raises(JsonRpcParseError) as excinfo:
        parse_request({"jsonrpc": "2.0", "id": 1})

    assert excinfo.value.error.code == INVALID_REQUEST


def test_id_can_be_int_string_or_null() -> None:
    for ident in [1, "abc", None]:
        request = parse_request(
            {"jsonrpc": "2.0", "id": ident, "method": "ping"}
        )
        assert request.id == ident


def test_batch_request_is_rejected_with_documented_error() -> None:
    """Batch shape would let an attacker hide a poisoned call inside a list."""

    with pytest.raises(JsonRpcParseError) as excinfo:
        parse_request([{"jsonrpc": "2.0", "id": 1, "method": "ping"}])

    assert excinfo.value.error.code == INVALID_REQUEST
    assert "batch" in excinfo.value.error.message.lower()


def test_non_object_payload_is_rejected() -> None:
    with pytest.raises(JsonRpcParseError):
        parse_request("not-an-object")  # type: ignore[arg-type]


def test_jsonrpc_error_to_response_includes_id() -> None:
    err = JsonRpcError(code=INVALID_REQUEST, message="bad shape")
    response = err.to_response(request_id=42)
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 42
    assert response["error"]["code"] == INVALID_REQUEST
    assert response["error"]["message"] == "bad shape"
