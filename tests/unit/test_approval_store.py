"""Tests for the user-consent store used by sleeper-rug-pull defense.

An approval is bound to (server_id, tool_name, description_hash,
schema_hash). Re-approval is required whenever any of those four fields
changes between loads.
"""

from __future__ import annotations

from mcp_demo.shared.approval_store import ApprovalStore, ToolFingerprint


FP_BENIGN = ToolFingerprint(
    name="random_fact.get",
    description_hash="d1",
    schema_hash="s1",
)
FP_BENIGN_OTHER_SERVER = ToolFingerprint(
    name="random_fact.get",
    description_hash="d1",
    schema_hash="s1",
)
FP_MUTATED_DESC = ToolFingerprint(
    name="random_fact.get",
    description_hash="d2",  # description changed
    schema_hash="s1",
)
FP_MUTATED_SCHEMA = ToolFingerprint(
    name="random_fact.get",
    description_hash="d1",
    schema_hash="s2",  # schema changed
)


def test_unapproved_fingerprint_is_not_approved() -> None:
    store = ApprovalStore()
    assert store.is_approved(server_id="srv", fingerprint=FP_BENIGN) is False


def test_approval_persists_for_same_fingerprint() -> None:
    store = ApprovalStore()
    store.record(server_id="srv", fingerprint=FP_BENIGN, user="alice")
    assert store.is_approved(server_id="srv", fingerprint=FP_BENIGN) is True


def test_changing_description_hash_invalidates_approval() -> None:
    store = ApprovalStore()
    store.record(server_id="srv", fingerprint=FP_BENIGN, user="alice")

    assert store.is_approved(server_id="srv", fingerprint=FP_MUTATED_DESC) is False


def test_changing_schema_hash_invalidates_approval() -> None:
    store = ApprovalStore()
    store.record(server_id="srv", fingerprint=FP_BENIGN, user="alice")

    assert store.is_approved(server_id="srv", fingerprint=FP_MUTATED_SCHEMA) is False


def test_approval_is_scoped_to_server_id() -> None:
    store = ApprovalStore()
    store.record(server_id="srv-a", fingerprint=FP_BENIGN, user="alice")

    assert store.is_approved(server_id="srv-b", fingerprint=FP_BENIGN_OTHER_SERVER) is False


def test_record_then_diff_against_new_fingerprint_returns_diff() -> None:
    store = ApprovalStore()
    store.record(server_id="srv", fingerprint=FP_BENIGN, user="alice")

    diff = store.diff(server_id="srv", fingerprint=FP_MUTATED_DESC)
    assert diff is not None
    assert diff["description_hash"] == ("d1", "d2")
    assert diff["schema_hash"] is None  # unchanged

    diff_schema = store.diff(server_id="srv", fingerprint=FP_MUTATED_SCHEMA)
    assert diff_schema is not None
    assert diff_schema["schema_hash"] == ("s1", "s2")
    assert diff_schema["description_hash"] is None
