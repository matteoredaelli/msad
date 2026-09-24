"""Tests for msad.search: verify the LDAP filters we build and response parsing."""

from __future__ import annotations

import ldap3
import pytest

from msad.search import (
    disabled_users,
    find_users,
    get_dn,
    get_user,
    locked_users,
    never_expires_password,
    search,
    users,
)


def test_search_parses_attributes_and_filters_dnless(conn, make_entry) -> None:
    conn.queue(
        [
            make_entry({"sAMAccountName": "matteo"}),
            {"type": "searchResRef", "uri": ["ldap://..."]},  # no 'dn' -> filtered out
            make_entry({"sAMAccountName": "anna"}),
        ]
    )
    result = search(conn, "dc=example,dc=com", "(objectClass=*)")
    assert result == [{"sAMAccountName": "matteo"}, {"sAMAccountName": "anna"}]


def test_search_default_attributes_is_all(conn) -> None:
    conn.queue([])
    search(conn, "dc=x", "(cn=a)")
    assert conn.searches[-1].attributes == ldap3.ALL_ATTRIBUTES


def test_search_passes_limit_and_attributes(conn) -> None:
    conn.queue([])
    search(conn, "dc=x", "(cn=a)", limit=50, attributes=["mail"])
    rec = conn.searches[-1]
    assert rec.size_limit == 50
    assert rec.attributes == ["mail"]
    assert rec.search_base == "dc=x"


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_users_filter(conn) -> None:
    conn.queue([])
    users(conn, "dc=x", "matteo")
    f = conn.last_filter
    assert "(objectclass=user)" in f
    assert "(samaccountname=matteo)" in f
    assert "(mail=matteo)" in f
    assert "(cn=matteo*)" in f
    assert "(userPrincipalName=matteo*)" in f


def test_get_dn_shortcircuits_on_cn(conn) -> None:
    dn = get_dn(conn, "dc=x", "CN=Matteo,DC=example,DC=com")
    assert dn == "CN=Matteo,DC=example,DC=com"
    assert conn.searches == []  # no query performed


def test_get_dn_looks_up_samaccountname(conn) -> None:
    conn.queue([{"dn": "d", "attributes": {"distinguishedName": "CN=Matteo,DC=x"}}])
    dn = get_dn(conn, "dc=x", "matteo")
    assert dn == "CN=Matteo,DC=x"
    assert conn.last_filter == "(sAMAccountName=matteo)"
    assert conn.searches[-1].attributes == ["distinguishedName"]


def test_get_dn_not_found_returns_none(conn) -> None:
    conn.queue([])  # empty response
    assert get_dn(conn, "dc=x", "ghost") is None


def test_never_expires_filter(conn) -> None:
    conn.queue([])
    never_expires_password(conn, "dc=x")
    assert "userAccountControl:1.2.840.113556.1.4.803:=65536" in conn.last_filter


def test_disabled_users_filter(conn) -> None:
    conn.queue([])
    disabled_users(conn, "dc=x", "(samaccountname=matteo)")
    f = conn.last_filter
    assert "userAccountControl:1.2.840.113556.1.4.803:=2" in f
    assert "(samaccountname=matteo)" in f


def test_locked_users_filter(conn) -> None:
    conn.queue([])
    locked_users(conn, "dc=x")
    assert "(lockoutTime>=1)" in conn.last_filter


def test_get_user_returns_single_or_none(conn) -> None:
    conn.queue([{"dn": "d", "attributes": {"sAMAccountName": "matteo"}}])
    user = get_user(conn, "dc=x", "matteo")
    assert user == {"sAMAccountName": "matteo"}
    f = conn.last_filter
    assert "(sAMAccountName=matteo)" in f
    assert "(mail=matteo)" in f
    assert "(cn=matteo)" in f  # exact, no trailing *


def test_get_user_none_when_absent(conn) -> None:
    conn.queue([])
    assert get_user(conn, "dc=x", "ghost") is None


def test_find_users_ands_criteria(conn) -> None:
    conn.queue([])
    find_users(conn, "dc=x", surname="Rossi", department="IT")
    f = conn.last_filter
    assert "(sn=Rossi)" in f
    assert "(department=IT)" in f
    assert "(givenName=" not in f  # not provided


def test_find_users_no_criteria_matches_all_users(conn) -> None:
    conn.queue([])
    find_users(conn, "dc=x")
    f = conn.last_filter
    assert "(objectClass=user)" in f
    assert "(objectCategory=person)" in f


def test_find_users_uses_default_attributes(conn) -> None:
    conn.queue([])
    find_users(conn, "dc=x", name="Matteo")
    assert conn.searches[-1].attributes == [
        "sAMAccountName",
        "cn",
        "displayName",
        "givenName",
        "sn",
        "mail",
        "userPrincipalName",
        "department",
        "title",
        "distinguishedName",
    ]
