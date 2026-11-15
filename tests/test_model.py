from __future__ import annotations

import socket

import pytest

from reqlens.errors import SafetyViolation
from reqlens.model import Concern, Confidence, Finding, Transaction, header_value, header_values


def make_finding(**overrides) -> Finding:
    base = dict(
        check_id="TEST-1",
        title="Example",
        category="API8:2023",
        concern=Concern.LOW,
        why="why",
        manual_test="test",
        learning="lesson",
    )
    base.update(overrides)
    return Finding(**base)


def test_transaction_url_parts():
    tx = Transaction(
        index=0, source="a.har", method="GET", url="https://API.App.test:8443/users/1?x=1"
    )
    assert tx.host == "api.app.test"
    assert tx.scheme == "https"
    assert tx.path == "/users/1"
    assert tx.query == "x=1"


def test_transaction_empty_path_is_root():
    tx = Transaction(index=0, source="a.har", method="GET", url="https://app.test")
    assert tx.path == "/"


def test_header_lookup_is_case_insensitive_and_keeps_duplicates():
    headers = [("Set-Cookie", "a=1"), ("set-cookie", "b=2"), ("X-Other", "z")]
    assert header_values(headers, "SET-COOKIE") == ["a=1", "b=2"]
    assert header_value(headers, "x-other") == "z"
    assert header_value(headers, "missing") is None


def test_finding_defaults_to_possible():
    assert make_finding().confidence is Confidence.POSSIBLE


def test_finding_accepts_string_enums():
    finding = make_finding(concern="high", confidence="informational")
    assert finding.concern is Concern.HIGH
    assert finding.confidence is Confidence.INFORMATIONAL


@pytest.mark.parametrize("value", ["confirmed", "certain", "high"])
def test_finding_refuses_confirmed_confidence(value):
    with pytest.raises(SafetyViolation):
        make_finding(confidence=value)


def test_finding_refuses_unknown_concern():
    with pytest.raises(SafetyViolation):
        make_finding(concern="critical")


def test_findings_sort_by_category_then_concern():
    findings = [
        make_finding(title="b", category="API8:2023", concern="low"),
        make_finding(title="a", category="API8:2023", concern="high"),
        make_finding(title="c", category="API1:2023", concern="info"),
    ]
    ordered = [f.title for f in sorted(findings, key=lambda f: f.sort_key)]
    assert ordered == ["c", "a", "b"]


def test_network_is_blocked_in_tests():
    with pytest.raises(AssertionError):
        socket.create_connection(("example.com", 80))
