"""Fake-OAuth issuer + verifier for auth-confused-deputy and token-passthrough demos.

Tokens are intentionally non-cryptographic. They look like a JWT (three
segments) but the third segment is the literal string ``fake`` instead of
a signature. The issuer prefixes the header with ``FAKEJWT.`` so reviewers
recognise demo tokens at a glance and tooling can refuse them as real
credentials.

The verifier mimics the four checks the defended mode runs: audience,
expiry, scope subset and signature shape.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable


_FAKE_HEADER = "FAKEJWT"
_FAKE_SIGNATURE = "fake"


class FakeAudienceError(ValueError):
    pass


class FakeExpiryError(ValueError):
    pass


class FakeScopeError(ValueError):
    pass


class FakeSignatureError(ValueError):
    pass


def _b64url(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> dict[str, Any]:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))


@dataclass
class FakeTokenIssuer:
    issuer: str
    default_ttl: timedelta = timedelta(minutes=10)

    def issue(
        self,
        *,
        sub: str,
        client_id: str,
        audience: str,
        scope: tuple[str, ...],
        expires_at: datetime | None = None,
    ) -> str:
        now = datetime.now(tz=timezone.utc)
        exp = expires_at if expires_at is not None else (now + self.default_ttl)
        payload = {
            "iss": self.issuer,
            "sub": sub,
            "client_id": client_id,
            "aud": audience,
            "scope": list(scope),
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
        }
        return f"{_FAKE_HEADER}.{_b64url(payload)}.{_FAKE_SIGNATURE}"


def verify_fake_token(
    token: str,
    *,
    expected_audience: str,
    required_scope: Iterable[str] = (),
    now: datetime | None = None,
) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != _FAKE_HEADER or parts[2] != _FAKE_SIGNATURE:
        raise FakeSignatureError("token is not a recognised demo FAKEJWT")
    claims = _b64url_decode(parts[1])

    if claims.get("aud") != expected_audience:
        raise FakeAudienceError(
            f"audience mismatch: expected {expected_audience!r}, got {claims.get('aud')!r}"
        )

    now = now or datetime.now(tz=timezone.utc)
    if int(now.timestamp()) >= int(claims.get("exp", 0)):
        raise FakeExpiryError("token expired")

    granted = set(claims.get("scope") or ())
    required = set(required_scope or ())
    if not required.issubset(granted):
        raise FakeScopeError(
            f"scope subset check failed: required {sorted(required)!r}, granted {sorted(granted)!r}"
        )

    return claims
