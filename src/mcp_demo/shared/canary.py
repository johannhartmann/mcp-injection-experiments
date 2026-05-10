"""Canary value generation.

A canary is an obviously-fake marker that demos plant in mock-filesystem
files, mock-mail bodies and mock-OAuth tokens. Vulnerable demos succeed when
that exact canary later shows up in a sink. The format is intentionally
greppable so test runs and human reviewers can pinpoint exfiltration.

Canaries are unique per call - each call to :func:`issue_canary` returns a
fresh value with enough random suffix to avoid accidental collisions across
sessions. They never carry any real secret material.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass


CANARY_LOG_MARKER = "CANARY"
"""The fixed prefix every canary value carries.

Anything that looks like ``CANARY_<experiment>_<random>`` should be treated
as a demo canary, never as a real credential. Logs and dashboards key off
this marker.
"""


@dataclass(frozen=True)
class Canary:
    """A single demo canary value plus its provenance."""

    value: str
    experiment_id: str
    session_id: str | None = None


def _slug(experiment_id: str) -> str:
    return experiment_id.replace("-", "_")


def issue_canary(
    *,
    experiment_id: str,
    session_id: str | None = None,
    nbytes: int = 12,
) -> Canary:
    """Generate a fresh canary tied to an experiment.

    The value layout is ``CANARY_<experiment_slug>_<random_hex>``. ``nbytes``
    controls the random suffix length; the default gives 96 bits of entropy,
    which is plenty for collision avoidance during a demo run.
    """

    if not experiment_id:
        raise ValueError("experiment_id is required")
    suffix = secrets.token_hex(nbytes)
    value = f"{CANARY_LOG_MARKER}_{_slug(experiment_id)}_{suffix}"
    return Canary(value=value, experiment_id=experiment_id, session_id=session_id)
