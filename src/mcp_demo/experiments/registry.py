"""Experiment registry.

The registry loads validated experiment manifests from a directory and
exposes them by id. It is the single source of truth for which experiments
the runtime knows about.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from mcp_demo.shared.manifests import ExperimentManifest, load_manifest_file


class ExperimentNotFoundError(KeyError):
    """Raised when an unknown experiment id is requested."""

    def __init__(self, experiment_id: str) -> None:
        super().__init__(experiment_id)
        self.experiment_id = experiment_id

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"unknown experiment: {self.experiment_id!r}"


class ExperimentRegistry:
    """In-memory view of all experiments declared under a manifest directory."""

    def __init__(self, manifests: dict[str, ExperimentManifest]) -> None:
        self._manifests = dict(manifests)

    @classmethod
    def from_directory(cls, directory: Path) -> "ExperimentRegistry":
        directory = Path(directory)
        if not directory.is_dir():
            raise FileNotFoundError(f"manifest directory not found: {directory}")

        manifests: dict[str, ExperimentManifest] = {}
        for path in sorted(directory.glob("*.yaml")):
            manifest = load_manifest_file(path)
            if manifest.id in manifests:
                raise ValueError(
                    f"duplicate experiment id {manifest.id!r} "
                    f"(second file: {path})"
                )
            manifests[manifest.id] = manifest
        return cls(manifests)

    def list_ids(self) -> list[str]:
        return sorted(self._manifests)

    def get(self, experiment_id: str) -> ExperimentManifest:
        try:
            return self._manifests[experiment_id]
        except KeyError as err:
            raise ExperimentNotFoundError(experiment_id) from err

    def all(self) -> list[ExperimentManifest]:
        return [self._manifests[i] for i in self.list_ids()]

    def __iter__(self) -> Iterator[ExperimentManifest]:
        return iter(self.all())

    def __len__(self) -> int:
        return len(self._manifests)

    def __contains__(self, experiment_id: object) -> bool:
        return isinstance(experiment_id, str) and experiment_id in self._manifests
