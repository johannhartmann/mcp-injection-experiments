"""In-memory DNS resolver for the SSRF demo.

The simulation never performs a real DNS query. Tests and the demo runtime
configure a static name-to-IP map and the URL-safety classifier consults
this map only.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class MockResolverError(KeyError):
    pass


@dataclass
class MockResolver:
    records: dict[str, list[str]] = field(default_factory=dict)

    def resolve(self, hostname: str) -> tuple[str, ...]:
        try:
            return tuple(self.records[hostname.lower()])
        except KeyError as err:
            raise MockResolverError(hostname) from err

    def set(self, hostname: str, ips: list[str]) -> None:
        self.records[hostname.lower()] = list(ips)
