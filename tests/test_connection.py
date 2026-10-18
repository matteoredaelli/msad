"""Tests for msad.connection.connect error handling."""

from __future__ import annotations

from typing import Any

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


def test_check_connection_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeConn:
        bound = True

        def bind(self) -> bool:
            return True

        def unbind(self) -> bool:
            return True

    monkeypatch.setattr(connection, "_build_connection", lambda config: FakeConn())

    result = connection.check_connection(KRB)
    assert result["ok"] is True
    assert result["target"] == "ldaps://dc.example.com:636"
    assert result["auth"] == "kerberos"
    assert result["error"] is None


def test_check_connection_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(config: DomainConfig):
        raise LDAPSocketOpenError("invalid server address")

    monkeypatch.setattr(connection, "_build_connection", boom)

    result = connection.check_connection(KRB)
    assert result["ok"] is False
    assert "invalid server address" in result["error"]
    assert result["target"] == "ldaps://dc.example.com:636"


def test_check_connection_userpwd_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    userpwd = DomainConfig(host="dc.example.com", base="dc=x", user="svc", password="p")

    class FakeConn:
        bound = True

        def bind(self) -> bool:
            return True

        def unbind(self) -> bool:
            return True

    monkeypatch.setattr(connection, "_build_connection", lambda config: FakeConn())

    result = connection.check_connection(userpwd)
    assert result["ok"] is True
    assert result["auth"] == "user 'svc'"


def _capture_connection_kwargs(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch ldap3.Connection/Server/Tls to capture the Connection kwargs."""
    captured: dict[str, Any] = {}

    def fake_connection(server, **kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(connection.ldap3, "Connection", fake_connection)
    monkeypatch.setattr(connection.ldap3, "Server", lambda *a, **k: object())
    monkeypatch.setattr(connection.ldap3, "Tls", lambda *a, **k: object())
    return captured


def test_build_connection_passes_query_timeout_kerberos(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_connection_kwargs(monkeypatch)
    cfg = DomainConfig(host="dc", base="dc=x", use_ssl=True, query_timeout=30)
    connection._build_connection(cfg)
    assert captured["receive_timeout"] == 30


def test_build_connection_passes_query_timeout_userpwd(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_connection_kwargs(monkeypatch)
    cfg = DomainConfig(host="dc", base="dc=x", user="svc", password="p", query_timeout=15)
    connection._build_connection(cfg)
    assert captured["receive_timeout"] == 15


def test_build_connection_timeout_defaults_none(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_connection_kwargs(monkeypatch)
    cfg = DomainConfig(host="dc", base="dc=x", user="svc", password="p")
    connection._build_connection(cfg)
    assert captured["receive_timeout"] is None
