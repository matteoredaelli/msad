"""Security tests: LDAP filter escaping prevents injection."""

from __future__ import annotations

import pytest

from msad.search import (
    escape_exact,
    escape_pattern,
    find_users,
    get_dn,
    get_user,
    users,
)

# A classic LDAP injection payload trying to break out of the assertion.
INJECTION = "*)(objectClass=*"


def test_escape_exact_neutralizes_metachars() -> None:
    out = escape_exact(INJECTION)
    # No raw metacharacters remain.
    assert "(" not in out
    assert ")" not in out
    assert "*" not in out


def test_escape_pattern_keeps_wildcard_but_escapes_parens() -> None:
    out = escape_pattern("adm*(x)")
    assert "*" in out  # wildcard preserved
    assert "(" not in out
    assert ")" not in out


def test_get_dn_escapes_injection(conn) -> None:
    conn.queue([])  # not found; we only care about the filter built
    get_dn(conn, "dc=x", INJECTION)
    f = conn.last_filter
    # The payload must not create extra filter clauses.
    assert "(objectClass=*)" not in f
    assert f.count("(") == 1 and f.count(")") == 1


def test_get_user_escapes_injection(conn) -> None:
    conn.queue([])
    get_user(conn, "dc=x", INJECTION)
    f = conn.last_filter
    # No injected clause; the raw payload's parens are escaped.
    assert "(objectClass=*)" not in f


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_users_escapes_injection_but_keeps_our_wildcards(conn) -> None:
    conn.queue([])
    users(conn, "dc=x", INJECTION)
    f = conn.last_filter
    assert "(objectClass=*)" not in f
    # Our own trailing wildcards on cn/UPN are still present.
    assert "cn=" in f


def test_find_users_escapes_injection(conn) -> None:
    conn.queue([])
    find_users(conn, "dc=x", surname=INJECTION)
    f = conn.last_filter
    assert "(objectClass=*)" not in f
