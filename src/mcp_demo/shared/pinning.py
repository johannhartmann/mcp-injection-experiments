"""Permission delta + version pinning helpers.

The registry-rug-pull demo compares permissions and tool fingerprints
between two registry manifests. ``permission_delta`` reports what a new
manifest would *gain*, *lose*, or *broaden*. The defended client uses
this list to refuse activation when scope grew beyond the user-pinned
version.
"""

from __future__ import annotations

from dataclasses import dataclass


_ROLE_ORDER = {"read": 0, "write": 1, "admin": 2}


def _is_broader(*, after: str, before: str) -> bool:
    """Return True iff ``after`` strictly includes ``before``."""

    if after == before:
        return False

    # Wildcard expansion: "scope:resource:*" covers "scope:resource:..." as
    # well as the bare prefix.
    if after.endswith(":*"):
        prefix = after[:-2]
        return before == prefix or before.startswith(prefix + ":")

    # Role upgrade within the same prefix: read -> write -> admin.
    a_parts = after.split(":")
    b_parts = before.split(":")
    if len(a_parts) == len(b_parts) and a_parts[:-1] == b_parts[:-1]:
        a_rank = _ROLE_ORDER.get(a_parts[-1], -1)
        b_rank = _ROLE_ORDER.get(b_parts[-1], -1)
        return a_rank > b_rank

    return False


@dataclass(frozen=True)
class PermissionDelta:
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    broadened: tuple[tuple[str, str], ...] = ()

    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.broadened)


def permission_delta(
    *, before: tuple[str, ...], after: tuple[str, ...]
) -> PermissionDelta:
    before_set = set(before)
    after_set = set(after)

    added = tuple(sorted(after_set - before_set))
    removed = tuple(sorted(before_set - after_set))

    broadened: list[tuple[str, str]] = []
    for old in sorted(before_set):
        for new in after_set:
            if _is_broader(after=new, before=old):
                broadened.append((old, new))
                break

    return PermissionDelta(
        added=added, removed=removed, broadened=tuple(broadened)
    )
