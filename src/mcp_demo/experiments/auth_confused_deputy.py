"""Safe fake-OAuth confused-deputy demo.

A fake CRM stores ``alice``'s display name. A fake "helper" client tries
to update it via an MCP tool whose proxy validates a bearer token. In
the vulnerable mode the proxy accepts the token without checking the
audience, the client identity or the consent record. In the defended
mode the proxy verifies audience (`mcp-demo-server`), expiry, scopes and
the per-client/per-redirect-uri consent record before applying the
change.

Nothing real is touched: tokens are FAKEJWT strings, the issuer URL is
``https://issuer.demo.invalid``, redirect URIs must end in
``.demo.invalid`` or ``.example``, and the CRM is a process-local dict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

from mcp_demo.shared.auth_mock import (
    FakeAudienceError,
    FakeExpiryError,
    FakeScopeError,
    FakeSignatureError,
    FakeTokenIssuer,
    verify_fake_token,
)
from mcp_demo.shared.canary import Canary, issue_canary
from mcp_demo.shared.consent import ConsentRegistry
from mcp_demo.shared.impact import ImpactEvent, ImpactLedger, ImpactRunner
from mcp_demo.shared.mock_inbox import MockInbox
from mcp_demo.shared.mock_sinks import MockSink
from mcp_demo.shared.results import DemoResult


EXPERIMENT_ID = "remote-auth-confused-deputy"
ENTRYPOINT = "/mcp/auth-confused-deputy"
EXPECTED_AUDIENCE = "mcp-demo-server"
WRONG_AUDIENCE = "other-mcp-service"


@dataclass
class AuthConfusedDeputyRuntime:
    canary: Canary
    sink: MockSink
    ledger: ImpactLedger
    runner: ImpactRunner
    issuer: FakeTokenIssuer
    consent: ConsentRegistry
    fake_crm: dict[str, dict[str, str]] = field(default_factory=dict)


def build_default_runtime(
    *, sandbox_dir: Path, var_dir: Path
) -> AuthConfusedDeputyRuntime:
    sandbox_dir = Path(sandbox_dir)
    var_dir = Path(var_dir)
    effects_dir = sandbox_dir / "effects"
    effects_dir.mkdir(parents=True, exist_ok=True)
    var_dir.mkdir(parents=True, exist_ok=True)

    canary = issue_canary(experiment_id=EXPERIMENT_ID)
    sink = MockSink()
    sink.register_canary(canary)
    inbox = MockInbox(var_dir / "mock-inbox.jsonl")
    ledger = ImpactLedger(jsonl_path=var_dir / "telemetry.jsonl")
    runner = ImpactRunner(
        effects_dir=effects_dir,
        var_dir=var_dir,
        ledger=ledger,
        sink=sink,
        inbox=inbox,
    )
    issuer = FakeTokenIssuer(
        issuer="https://issuer.demo.invalid",
        default_ttl=timedelta(minutes=10),
    )
    consent = ConsentRegistry()
    fake_crm = {"alice": {"display_name": "Alice"}}
    return AuthConfusedDeputyRuntime(
        canary=canary,
        sink=sink,
        ledger=ledger,
        runner=runner,
        issuer=issuer,
        consent=consent,
        fake_crm=fake_crm,
    )


def _apply_change(
    runtime: AuthConfusedDeputyRuntime, *, session_id: str, actor: str
) -> None:
    runtime.fake_crm["alice"]["display_name"] = "ALICE THE PWNED"
    runtime.ledger.record(
        ImpactEvent(
            experiment=EXPERIMENT_ID,
            mode="vulnerable",
            impact_type="permission_change_applied",
            actor=actor,
            target="fake-crm.alice",
            policy_decision="allowed_by_vulnerable_mode",
            canary_id=runtime.canary.value,
            user_visible_summary=(
                "fake-CRM display_name was rewritten via a token whose "
                "audience/consent the vulnerable proxy did not check"
            ),
            session_id=session_id,
        )
    )


def run_scenario(
    *,
    mode: Literal["vulnerable", "defended"],
    session_id: str,
    runtime: AuthConfusedDeputyRuntime,
    client_id: str = "demo-client",
    token_audience: str | None = None,
) -> DemoResult:
    # Default attack: token issued for another MCP service but the helper
    # relays it through to mcp-demo-server (wrong audience). Tests that
    # focus on a different defended-mode check (e.g. consent_missing) can
    # override the audience to the correct value to skip the audience
    # short-circuit.
    if token_audience is None:
        token_audience = (
            EXPECTED_AUDIENCE if client_id != "demo-client" else WRONG_AUDIENCE
        )
    attacker_token = runtime.issuer.issue(
        sub="alice",
        client_id=client_id,
        audience=token_audience,
        scope=("write:profile",),
    )

    if mode == "vulnerable":
        # No verification at all - this is the bug.
        _apply_change(
            runtime,
            session_id=session_id,
            actor=f"client:{client_id}",
        )
        return DemoResult(
            experiment=EXPERIMENT_ID,
            mode="vulnerable",
            violation_detected=True,
            secret_exfiltrated=False,
            blocked_by=[],
            events=[
                {
                    "type": "auth_decision",
                    "check": "skipped",
                    "outcome": "applied_change_without_verification",
                }
            ],
        )

    # defended
    try:
        claims = verify_fake_token(
            attacker_token,
            expected_audience=EXPECTED_AUDIENCE,
            required_scope=("write:profile",),
        )
    except FakeAudienceError as err:
        return _refuse(
            runtime,
            session_id=session_id,
            check="audience_mismatch",
            expected=EXPECTED_AUDIENCE,
            actual=WRONG_AUDIENCE,
            reason=str(err),
        )
    except FakeExpiryError as err:
        return _refuse(
            runtime,
            session_id=session_id,
            check="expired",
            expected="now < exp",
            actual="exp <= now",
            reason=str(err),
        )
    except FakeScopeError as err:
        return _refuse(
            runtime,
            session_id=session_id,
            check="scope_insufficient",
            expected="write:profile",
            actual="...",
            reason=str(err),
        )
    except FakeSignatureError as err:
        return _refuse(
            runtime,
            session_id=session_id,
            check="signature_invalid",
            expected="FAKEJWT.<payload>.fake",
            actual="malformed",
            reason=str(err),
        )

    if not runtime.consent.is_consented(
        user_id=str(claims["sub"]),
        client_id=str(claims["client_id"]),
        redirect_uri="https://app.demo.invalid/cb",
        scopes=tuple(claims["scope"]),
    ):
        return _refuse(
            runtime,
            session_id=session_id,
            check="consent_missing",
            expected="user has approved this client + redirect + scope",
            actual=str(claims["client_id"]),
            reason="no consent record matches token claims",
        )

    return DemoResult(
        experiment=EXPERIMENT_ID,
        mode="defended",
        violation_detected=False,
        secret_exfiltrated=False,
        blocked_by=[],
        events=[],
    )


def _refuse(
    runtime: AuthConfusedDeputyRuntime,
    *,
    session_id: str,
    check: str,
    expected: Any,
    actual: Any,
    reason: str,
) -> DemoResult:
    runtime.runner.record_blocked_attempt(
        experiment=EXPERIMENT_ID,
        actor=f"policy.fake_oauth.{check}",
        target="fake-crm.alice",
        reason=reason,
        session_id=session_id,
    )
    return DemoResult(
        experiment=EXPERIMENT_ID,
        mode="defended",
        violation_detected=True,
        secret_exfiltrated=False,
        blocked_by=[check],
        events=[
            {
                "type": "auth_decision",
                "check": check,
                "expected": expected,
                "actual": actual,
                "reason": reason,
            }
        ],
    )


# --- MCP servers (one per mode) ------------------------------------------

from mcp.server.fastmcp import FastMCP  # noqa: E402

from mcp_demo.shared.mcp_helpers import make_fastmcp  # noqa: E402


def build_mcp_servers(
    *,
    runtime: AuthConfusedDeputyRuntime,
    server_name: str,
    server_version: str,  # noqa: ARG001
    allowed_origins: tuple[str, ...] = (),
) -> dict[str, FastMCP]:
    """Two real MCP servers. Each exposes update_profile (tool that
    accepts a FAKEJWT) plus run_demo. Vulnerable mode skips token
    verification; defended mode runs verify_fake_token + ConsentRegistry."""

    def _build(*, mode: Literal["vulnerable", "defended"]) -> FastMCP:
        server = make_fastmcp(
            name=f"{server_name}.auth-confused-deputy.{mode}",
            instructions=(
                "auth-confused-deputy vulnerable demo: update_profile "
                "accepts any FAKEJWT and applies the change."
                if mode == "vulnerable"
                else "auth-confused-deputy defended demo: update_profile "
                "verifies audience, expiry, scope subset, signature "
                "shape, and per-client consent."
            ),
            allowed_origins=allowed_origins,
        )

        @server.tool(
            name="update_profile",
            description=(
                "Update the fake CRM record for a user. Authorisation "
                "via the bearer token argument."
            ),
        )
        def update_profile(
            user_id: str, new_display_name: str, bearer: str
        ) -> dict:  # noqa: D401
            from mcp_demo.shared.auth_mock import (
                FakeAudienceError,
                FakeExpiryError,
                FakeScopeError,
                FakeSignatureError,
                verify_fake_token,
            )

            if mode == "vulnerable":
                runtime.fake_crm.setdefault(user_id, {"display_name": user_id})
                runtime.fake_crm[user_id]["display_name"] = new_display_name
                return runtime.fake_crm[user_id]

            try:
                claims = verify_fake_token(
                    bearer,
                    expected_audience=EXPECTED_AUDIENCE,
                    required_scope=("write:profile",),
                )
            except (
                FakeAudienceError,
                FakeExpiryError,
                FakeScopeError,
                FakeSignatureError,
            ) as err:
                raise ValueError(f"refused: {err}")

            if not runtime.consent.is_consented(
                user_id=str(claims["sub"]),
                client_id=str(claims["client_id"]),
                redirect_uri="https://app.demo.invalid/cb",
                scopes=tuple(claims["scope"]),
            ):
                raise ValueError("refused: consent_missing")

            runtime.fake_crm.setdefault(user_id, {"display_name": user_id})
            runtime.fake_crm[user_id]["display_name"] = new_display_name
            return runtime.fake_crm[user_id]

        @server.tool(
            name="run_demo",
            description=(
                "Drive the canonical auth-confused-deputy scenario for "
                "this mode and return the DemoResult JSON."
            ),
        )
        def run_demo(session_id: str = f"mcp-{mode}") -> dict:  # noqa: D401
            result = run_scenario(
                mode=mode, session_id=session_id, runtime=runtime
            )
            return result.model_dump()

        return server

    return {
        "vulnerable": _build(mode="vulnerable"),
        "defended": _build(mode="defended"),
    }
