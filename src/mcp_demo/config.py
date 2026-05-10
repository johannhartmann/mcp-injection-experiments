"""Demo runtime settings.

Defaults match the public-demo guardrails in
``architecture/security-model.md``: bind to loopback only, deny outbound by
default, restrict the Origin allowlist to local development hosts.

Overrides come from environment variables prefixed ``DEMO_``. Tests use
:func:`testing_settings` to construct a stable config without touching the
process environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


_DEFAULT_ALLOWED_ORIGINS = (
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://testserver",  # ASGI test client default base URL
)


@dataclass(frozen=True)
class DemoSettings:
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    egress_mode: str = "deny"
    allowed_origins: tuple[str, ...] = _DEFAULT_ALLOWED_ORIGINS
    server_name: str = "mcp-demo"
    server_version: str = "0.0.1"

    @classmethod
    def from_env(cls) -> "DemoSettings":
        host = os.environ.get("DEMO_BIND_HOST", "127.0.0.1")
        port = int(os.environ.get("DEMO_BIND_PORT", "8000"))
        egress = os.environ.get("DEMO_EGRESS_MODE", "deny")
        origins_raw = os.environ.get("DEMO_ALLOWED_ORIGINS")
        if origins_raw:
            origins = tuple(o.strip() for o in origins_raw.split(",") if o.strip())
        else:
            origins = _DEFAULT_ALLOWED_ORIGINS
        return cls(
            bind_host=host,
            bind_port=port,
            egress_mode=egress,
            allowed_origins=origins,
        )


def testing_settings(**overrides) -> DemoSettings:
    return DemoSettings(**overrides)
