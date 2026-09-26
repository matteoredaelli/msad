"""Tests for msad.connection.connect error handling."""

from __future__ import annotations

import pytest
from ldap3.core.exceptions import LDAPSocketOpenError

from msad import connection
from msad.config import DomainConfig
from msad.exceptions import MsadConnectionError

KRB = DomainConfig(host="dc.example.com", base="dc=x", port=636, use_ssl=True)


def test_connect_wraps_ldap_socket_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(config: DomainConfig):
        raise LDAPSocketOpenError("invalid server address")

    monkeypatch.setattr(connection, "_build_connection", boom)

    with pytest.raises(MsadConnectionError) as exc:
        connection.connect(KRB)

    msg = str(exc.value)
    assert "ldaps://dc.example.com:636" in msg
    assert "Kerberos" in msg
    assert "invalid server address" in msg


def test_connect_reports_unbound_result(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeConn:
        bound = False
        result = {"description": "invalidCredentials"}

        def bind(self) -> bool:
            return False

    monkeypatch.setattr(connection, "_build_connection", lambda config: FakeConn())

    with pytest.raises(MsadConnectionError, match="invalidCredentials"):
        connection.connect(KRB)


def test_connect_returns_bound_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeConn:
        bound = True

        def bind(self) -> bool:
            return True

    fake = FakeConn()
    monkeypatch.setattr(connection, "_build_connection", lambda config: fake)

    assert connection.connect(KRB) is fake


def test_connect_reports_userpwd_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    userpwd = DomainConfig(host="dc.example.com", base="dc=x", user="svc", password="p")

    def boom(config: DomainConfig):
        raise LDAPSocketOpenError("nope")

    monkeypatch.setattr(connection, "_build_connection", boom)

    with pytest.raises(MsadConnectionError, match="user 'svc'"):
        connection.connect(userpwd)
