"""Per-user/per-client consent registry for the fake-OAuth demo.

Consent is bound to ``(user_id, client_id, redirect_uri, scopes)``. Any
change to the redirect URI or to the scope set forces a re-consent.
Redirect URIs must point at the demo zone (``demo.invalid`` or
``.example``) - any other host is rejected at record time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit


_ALLOWED_REDIRECT_HOSTS = (
    ".demo.invalid",
    ".example",
)


def _redirect_host_is_demo_safe(redirect_uri: str) -> bool:
    parsed = urlsplit(redirect_uri)
    if parsed.scheme not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").lower()
    return any(host == suffix.lstrip(".") or host.endswith(suffix) for suffix in _ALLOWED_REDIRECT_HOSTS)


@dataclass(frozen=True)
class _ConsentKey:
    user_id: str
    client_id: str
    redirect_uri: str
    scopes: tuple[str, ...]


@dataclass
class ConsentRegistry:
    _records: dict[_ConsentKey, bool] = field(default_factory=dict)

    def record(
        self,
        *,
        user_id: str,
        client_id: str,
        redirect_uri: str,
        scopes: tuple[str, ...],
    ) -> None:
        if not _redirect_host_is_demo_safe(redirect_uri):
            raise ValueError(
                f"redirect_uri must point at the demo zone (.demo.invalid / .example): {redirect_uri!r}"
            )
        key = _ConsentKey(
            user_id=user_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=tuple(sorted(scopes)),
        )
        self._records[key] = True

    def is_consented(
        self,
        *,
        user_id: str,
        client_id: str,
        redirect_uri: str,
        scopes: tuple[str, ...],
    ) -> bool:
        key = _ConsentKey(
            user_id=user_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=tuple(sorted(scopes)),
        )
        return self._records.get(key, False)
