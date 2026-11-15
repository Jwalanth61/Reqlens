from __future__ import annotations

import json

import pytest

from reqlens.errors import ScopeError
from reqlens.group import group_transactions, normalise_segment, path_pattern
from reqlens.model import Transaction
from reqlens.scope import apply_scope, host_matches, is_noise


def tx(url: str, method: str = "GET", status: int = 200, body: str = "", index: int = 0):
    return Transaction(index, "t", method, url, status=status, request_body=body)


# --- scope ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host, pattern, expected",
    [
        ("app.test", "app.test", True),
        ("APP.test", "app.test.", True),
        ("api.app.test", "app.test", False),
        ("api.app.test", "*.app.test", True),
        ("app.test", "*.app.test", False),
        ("evilapp.test", "*.app.test", False),
        ("app.test.evil.com", "app.test", False),
        ("app.test", "app.test:8443", True),
        ("10.0.0.5", "10.0.0.5", True),
        ("10.0.0.5", "*.0.0.5", False),
    ],
)
def test_host_matches(host, pattern, expected):
    assert host_matches(host, pattern) is expected


def test_noise_detection():
    assert is_noise("www.google-analytics.com")
    assert is_noise("fonts.gstatic.com")
    assert not is_noise("app.test")
    assert not is_noise("notgoogle-analytics.com")


def test_apply_scope_splits_and_summarises():
    txs = [
        tx("https://app.test/a"),
        tx("https://api.app.test/b"),
        tx("https://www.google-analytics.com/collect"),
        tx("https://other.example/x"),
        tx("https://other.example/y"),
    ]
    result = apply_scope(txs, ["app.test", "*.app.test"])
    assert [t.url for t in result.kept] == ["https://app.test/a", "https://api.app.test/b"]
    assert result.dropped["other.example"].count == 2
    assert result.dropped["other.example"].reason == "out of scope"
    assert result.dropped["www.google-analytics.com"].reason == "third-party noise"
    assert result.dropped_count == 3


def test_noise_dropped_even_under_wildcard_unless_named_exactly():
    txs = [tx("https://fonts.gstatic.com/x"), tx("https://app.test/")]
    assert len(apply_scope(txs, ["*.gstatic.com", "app.test"]).kept) == 1
    assert len(apply_scope(txs, ["fonts.gstatic.com", "app.test"]).kept) == 2


def test_empty_scope_match_is_an_error_listing_hosts():
    with pytest.raises(ScopeError, match="other.example"):
        apply_scope([tx("https://other.example/")], ["app.test"])


# --- grouping ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "segment, expected",
    [
        ("123", "{id}"),
        ("550e8400-e29b-41d4-a716-446655440000", "{uuid}"),
        ("507f1f77bcf86cd799439011", "{objectid}"),
        ("<redacted:ab12cd34>", "{token}"),
        ("<jwt:ab12cd34>", "{token}"),
        ("<email>", "{email}"),
        ("2026-11-15", "{date}"),
        ("users", "users"),
        ("v1", "v1"),
    ],
)
def test_normalise_segment(segment, expected):
    assert normalise_segment(segment) == expected


def test_path_pattern():
    assert path_pattern("/api/users/123/orders/9") == "/api/users/{id}/orders/{id}"
    assert path_pattern("/") == "/"


def test_group_collapses_ids_and_picks_2xx_representative():
    txs = [
        tx("https://app.test/users/1", status=403, index=0),
        tx("https://app.test/users/2", status=200, index=1),
        tx("https://app.test/users/3", method="DELETE", index=2),
        tx("https://api.app.test/users/1", index=3),
    ]
    endpoints = group_transactions(txs)
    assert [e.key for e in endpoints] == [
        "GET app.test/users/{id}",
        "DELETE app.test/users/{id}",
        "GET api.app.test/users/{id}",
    ]
    first = endpoints[0]
    assert len(first.members) == 2
    assert first.representative.index == 1
    assert first.statuses == [200, 403]


def test_graphql_operations_are_separate_endpoints():
    def gql(op):
        return tx(
            "https://app.test/graphql",
            "POST",
            body=json.dumps({"operationName": op, "query": "query { x }"}),
        )

    endpoints = group_transactions([gql("GetUser"), gql("GetUser"), gql("ListOrders")])
    assert [e.key for e in endpoints] == [
        "POST app.test/graphql (GetUser)",
        "POST app.test/graphql (ListOrders)",
    ]
