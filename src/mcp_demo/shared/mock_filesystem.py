"""Mock filesystem with strict containment.

Experiments may only read from a designated sandbox directory that is set up
with canary content. Real paths (``~``, ``/etc``, ``.env``, ``..`` traversal,
symlink redirection) are refused before any I/O happens.

The contract is intentionally narrow:

- callers pass relative paths only,
- absolute paths are rejected even when they would resolve into the sandbox,
- the resolved path must be *under* the sandbox root after symlink
  resolution; if it is not, :class:`MockFilesystemPathError` is raised.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath


class MockFilesystemPathError(PermissionError):
    """Raised when a caller asks for a path outside the sandbox."""


# Filenames that real attacker payloads typically target. Even when they would
# resolve cleanly inside the sandbox, the mock filesystem refuses them so the
# demo never trains agents to ask for these paths verbatim.
_BLOCKED_BASENAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        "mcp.json",
        "credentials",
        "credentials.json",
        ".netrc",
    }
)
_BLOCKED_PARENT_DIRS = frozenset({".ssh", ".aws", ".cursor", ".config"})


class MockFilesystem:
    """Bounded read view of a sandbox directory."""

    def __init__(self, root: Path) -> None:
        root = Path(root)
        if not root.is_dir():
            raise MockFilesystemPathError(f"sandbox root does not exist: {root}")
        # Capture the fully-resolved root once so later checks are cheap and
        # immune to outside renames.
        self._root = root.resolve(strict=True)

    @property
    def root(self) -> Path:
        return self._root

    def _resolve_inside(self, relative_path: str) -> Path:
        if not isinstance(relative_path, str) or not relative_path:
            raise MockFilesystemPathError("path must be a non-empty string")

        # Reject anything that obviously means "leave the sandbox" before we
        # touch the filesystem at all.
        if relative_path.startswith("~"):
            raise MockFilesystemPathError(
                f"home-directory references are forbidden: {relative_path!r}"
            )
        # PurePosixPath covers both "/" and "\\" by treating them as
        # separators when we explicitly check for absolute form below.
        candidate = PurePosixPath(relative_path)
        if candidate.is_absolute() or relative_path.startswith(("/", "\\")):
            raise MockFilesystemPathError(
                f"absolute paths are forbidden: {relative_path!r}"
            )
        if ".." in candidate.parts:
            raise MockFilesystemPathError(
                f"parent traversal is forbidden: {relative_path!r}"
            )
        if candidate.name in _BLOCKED_BASENAMES:
            raise MockFilesystemPathError(
                f"suspicious basename refused by sandbox policy: {relative_path!r}"
            )
        if any(part in _BLOCKED_PARENT_DIRS for part in candidate.parts):
            raise MockFilesystemPathError(
                f"suspicious directory refused by sandbox policy: {relative_path!r}"
            )

        target = (self._root / relative_path).resolve(strict=False)
        # Containment check after symlink resolution.
        try:
            target.relative_to(self._root)
        except ValueError as err:
            raise MockFilesystemPathError(
                f"resolved path escapes sandbox: {relative_path!r}"
            ) from err
        return target

    def read_text(self, relative_path: str, *, encoding: str = "utf-8") -> str:
        target = self._resolve_inside(relative_path)
        if not target.exists():
            raise FileNotFoundError(relative_path)
        if not target.is_file():
            raise MockFilesystemPathError(
                f"sandbox entry is not a regular file: {relative_path!r}"
            )
        return target.read_text(encoding=encoding)

    def list_files(self) -> list[str]:
        """Return all sandbox-relative file paths, sorted."""

        results: list[str] = []
        for path in sorted(self._root.rglob("*")):
            if not path.is_file():
                continue
            # Skip symlinks that point outside the sandbox.
            try:
                resolved = path.resolve(strict=False)
                resolved.relative_to(self._root)
            except ValueError:
                continue
            results.append(str(path.relative_to(self._root)))
        return results
