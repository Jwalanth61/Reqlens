"""Test configuration. Every test runs with the network blocked unless it opts in.

This is the structural half of the passive-only guarantee: if any code path tries to open
a socket during a test, the test fails. Only tests marked ``allow_network`` (local mock AI
servers in a later phase) may open sockets, and only to loopback addresses.
"""

from __future__ import annotations

import socket

import pytest


class NetworkBlocked(AssertionError):
    """Raised when code under test tries to use the network."""


def _blocked(*_args, **_kwargs):
    raise NetworkBlocked("network access attempted during an offline test")


@pytest.fixture(autouse=True)
def block_network(request, monkeypatch):
    """Forbid socket creation and name resolution for every test by default."""
    if request.node.get_closest_marker("allow_network"):
        yield
        return
    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(socket, "gethostbyname", _blocked)
    yield
