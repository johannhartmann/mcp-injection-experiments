"""In-memory mock GitHub MCP surface.

A tiny stand-in for the GitHub MCP server that the GitHub-issue-leak,
comment-and-control and (later) sybil/fragment demos use. Public issues,
private repo files and PR comments live in a process-local dict; the
``post_pr_comment`` "tool" appends a JSON record to
``var/mock-github/public-pr-comments.jsonl``. Nothing reaches GitHub.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class MockGitHub:
    def __init__(self, *, public_pr_comments_path: Path) -> None:
        self._public_issues: dict[str, str] = {}
        self._private_repo_files: dict[str, str] = {}
        self._public_pr_comments_path = Path(public_pr_comments_path)
        self._public_pr_comments_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def public_pr_comments_path(self) -> Path:
        return self._public_pr_comments_path

    # --- Resource fixtures -------------------------------------------

    def set_public_issue(self, *, issue_id: str, body: str) -> None:
        self._public_issues[issue_id] = body

    def set_private_repo_file(self, *, path: str, body: str) -> None:
        self._private_repo_files[path] = body

    def read_public_issue(self, issue_id: str) -> str:
        return self._public_issues[issue_id]

    def read_private_repo_file(self, path: str) -> str:
        return self._private_repo_files[path]

    # --- Tool ---------------------------------------------------------

    def post_pr_comment(
        self,
        *,
        repo: str,
        pr_number: int,
        body: str,
        actor: str,
        session_id: str,
        experiment: str,
    ) -> dict[str, Any]:
        record = {
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "repo": repo,
            "pr_number": pr_number,
            "body": body,
            "actor": actor,
            "session_id": session_id,
            "experiment": experiment,
            "visibility": "public",
        }
        with self._public_pr_comments_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False))
            fh.write("\n")
        return record

    def public_pr_comments(self) -> list[dict[str, Any]]:
        if not self._public_pr_comments_path.exists():
            return []
        return [
            json.loads(line)
            for line in self._public_pr_comments_path.read_text(
                encoding="utf-8"
            ).splitlines()
        ]
