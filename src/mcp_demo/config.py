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
    admin_token: str = "local-dev"
    public_mode: bool = False

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
        admin_token = os.environ.get("DEMO_ADMIN_TOKEN", "local-dev")
        public_mode = os.environ.get("DEMO_PUBLIC_MODE", "").lower() in {
            "1", "true", "yes",
        }
        return cls(
            bind_host=host,
            bind_port=port,
            egress_mode=egress,
            allowed_origins=origins,
            admin_token=admin_token,
            public_mode=public_mode,
        )

    def with_public_mode(self) -> "DemoSettings":
        return DemoSettings(
            bind_host=self.bind_host,
            bind_port=self.bind_port,
            egress_mode=self.egress_mode,
            allowed_origins=self.allowed_origins,
            server_name=self.server_name,
            server_version=self.server_version,
            admin_token=self.admin_token,
            public_mode=True,
        )

    def validate_for_public_mode(self) -> None:
        """Refuse unsafe defaults when serving the demo to the open internet."""

        problems: list[str] = []
        if self.admin_token in {"", "local-dev"}:
            problems.append(
                "admin_token must be set to a non-default value in public mode"
            )
        if "*" in self.allowed_origins:
            problems.append(
                "allowed_origins must not contain '*' in public mode"
            )
        if not self.allowed_origins:
            problems.append("allowed_origins must not be empty in public mode")
        if problems:
            raise ValueError(
                "DemoSettings is unsafe for public deployment: "
                + "; ".join(problems)
            )


def testing_settings(**overrides) -> DemoSettings:
    return DemoSettings(**overrides)
