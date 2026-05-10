"""Shared helpers for building per-experiment FastMCP servers.

Every expansion experiment exposes two real Streamable-HTTP MCP
servers built with the official ``mcp`` Python SDK: one for the
vulnerable mode and one for the defended mode. The servers are
mounted under ``/mcp/<experiment-id>/<mode>/`` by
:func:`mcp_demo.app.create_app`.

This module centralises the FastMCP construction so each experiment's
``build_mcp_servers`` function only has to register tools, resources
and prompts - never touch the transport, the security settings or the
mount path layout.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings


_DEFAULT_ALLOWED_HOSTS = (
    "127.0.0.1",
    "localhost",
    "testserver",
    "127.0.0.1:8000",
    "localhost:8000",
)


def build_transport_security(
    *, allowed_origins: tuple[str, ...]
) -> TransportSecuritySettings:
    """Return a :class:`TransportSecuritySettings` with DNS-rebinding
    protection enabled for the given Origin allowlist."""

    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_origins=list(allowed_origins),
        allowed_hosts=list(_DEFAULT_ALLOWED_HOSTS),
    )


def make_fastmcp(
    *,
    name: str,
    instructions: str,
    allowed_origins: tuple[str, ...],
) -> FastMCP:
    """Construct a stateful Streamable-HTTP FastMCP server.

    - ``streamable_http_path='/'`` so that mounting under
      ``/mcp/<id>/<mode>`` keeps the canonical request URL at
      ``/mcp/<id>/<mode>/`` (one trailing-slash redirect at most).
    - ``stateless_http=False`` enables proper ``Mcp-Session-Id``
      lifecycle.
    - ``json_response=False`` keeps SSE as the response shape so the
      official client behaves the same as it does against a remote
      production MCP server.
    """

    return FastMCP(
        name=name,
        instructions=instructions,
        stateless_http=False,
        json_response=False,
        streamable_http_path="/",
        transport_security=build_transport_security(
            allowed_origins=allowed_origins
        ),
    )


__all__ = ["build_transport_security", "make_fastmcp"]
