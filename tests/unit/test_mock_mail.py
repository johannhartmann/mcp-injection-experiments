"""Tests for the in-memory mock-mail server.

The mock-mail surface is intentionally narrow: it accepts only ``.example``
recipients (RFC 2606 reserved domain), keeps all messages in process and
never reaches an SMTP server. The shadowing demo can record hidden BCC
recipients here without any chance of leaking to a real address.
"""

from __future__ import annotations

import pytest

from mcp_demo.shared.mock_mail import (
    MockMailRecipientError,
    MockMailServer,
)


@pytest.fixture
def mail() -> MockMailServer:
    return MockMailServer()


def test_send_records_message_in_memory(mail: MockMailServer) -> None:
    record = mail.send_email(
        to="alice@example",
        subject="hello",
        body="hi",
        actor="trusted.mock-mail",
    )
    assert record["to"] == "alice@example"
    assert record["subject"] == "hello"
    assert mail.outbox()[0]["to"] == "alice@example"


def test_send_rejects_recipient_outside_example_tld(mail: MockMailServer) -> None:
    with pytest.raises(MockMailRecipientError):
        mail.send_email(
            to="alice@gmail.com",
            subject="x",
            body="y",
            actor="trusted.mock-mail",
        )


def test_send_rejects_real_attacker_targets(mail: MockMailServer) -> None:
    for evil in [
        "attkr@pwnd.com",
        "ops@invariantlabs.ai",
        "leak@attacker.io",
    ]:
        with pytest.raises(MockMailRecipientError):
            mail.send_email(to=evil, subject="x", body="y", actor="x")


def test_bcc_recipients_must_also_be_example_tld(mail: MockMailServer) -> None:
    with pytest.raises(MockMailRecipientError):
        mail.send_email(
            to="alice@example",
            bcc=["evil@attacker.io"],
            subject="x",
            body="y",
            actor="x",
        )


def test_send_records_bcc_when_present(mail: MockMailServer) -> None:
    record = mail.send_email(
        to="alice@example",
        bcc=["attacker@attacker.example"],
        subject="hello",
        body="ping",
        actor="trusted.mock-mail",
    )
    assert record["bcc"] == ["attacker@attacker.example"]


def test_outbox_isolated_per_instance() -> None:
    a = MockMailServer()
    b = MockMailServer()
    a.send_email(to="x@example", subject="s", body="b", actor="x")
    assert a.outbox()
    assert b.outbox() == []


def test_does_not_perform_outbound_io(
    mail: MockMailServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No socket / urllib / smtplib call is allowed."""

    import smtplib

    def boom(*a, **k):
        raise AssertionError("MockMailServer must not touch SMTP")

    monkeypatch.setattr(smtplib, "SMTP", boom)
    monkeypatch.setattr(smtplib, "SMTP_SSL", boom)
    mail.send_email(to="a@example", subject="s", body="b", actor="x")
