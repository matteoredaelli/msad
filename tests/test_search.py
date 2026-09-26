"""Tests for msad.search: verify the LDAP filters we build and response parsing."""

from __future__ import annotations

import ldap3
import pytest

from msad.search import (
    DEFAULT_OU_ATTRIBUTES,
    DEFAULT_USER_ATTRIBUTES,
    disabled_users,
    find_computers,
    find_inactive_users,
    find_ous,
    find_stale_computers,
    find_users,
    get_by_dn,
    get_computer,
    get_dn,
    get_ou,
    get_ou_contents,
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
    assert conn.searches[-1].attributes == DEFAULT_USER_ATTRIBUTES
    assert "manager" in conn.searches[-1].attributes


def test_get_by_dn_uses_dn_as_base(conn, make_entry) -> None:
    dn = "CN=Anna Bianchi,OU=Staff,DC=example,DC=com"
    conn.queue([make_entry({"cn": "Anna Bianchi", "sAMAccountName": "abianchi"}, dn=dn)])

    result = get_by_dn(conn, dn)

    # The DN is used as the search base, with a catch-all filter.
    last = conn.searches[-1]
    assert last.search_base == dn
    assert last.search_filter == "(objectClass=*)"
    assert last.size_limit == 1
    assert result is not None
    assert result["sAMAccountName"] == "abianchi"


def test_get_by_dn_returns_none_when_absent(conn) -> None:
    conn.queue([])  # server returns nothing
    assert get_by_dn(conn, "CN=nope,DC=example,DC=com") is None


def test_get_by_dn_handles_ldap_error(conn) -> None:
    from ldap3.core.exceptions import LDAPInvalidDnError

    def boom(search_base, search_filter, size_limit=0, attributes=None):
        raise LDAPInvalidDnError("invalid DN syntax")

    conn.extend.standard.paged_search = boom  # type: ignore[assignment]
    assert get_by_dn(conn, "not-a-dn") is None


def test_find_computers_filters_and_class(conn) -> None:
    conn.queue([])
    find_computers(conn, "dc=x", name="PC0*", os="Windows*")
    f = conn.searches[-1].search_filter
    assert "(objectClass=computer)" in f
    assert "(cn=PC0*)" in f
    assert "(operatingSystem=Windows*)" in f


def test_find_computers_default_attributes(conn) -> None:
    from msad.search import DEFAULT_COMPUTER_ATTRIBUTES

    conn.queue([])
    find_computers(conn, "dc=x", name="PC001")
    assert conn.searches[-1].attributes == DEFAULT_COMPUTER_ATTRIBUTES
    assert "dNSHostName" in conn.searches[-1].attributes


def test_get_computer_appends_dollar_to_sam(conn, make_entry) -> None:
    conn.queue([make_entry({"sAMAccountName": "PC001$", "cn": "PC001"})])
    result = get_computer(conn, "dc=x", "PC001")
    f = conn.searches[-1].search_filter
    # sAMAccountName gets the trailing $, cn/dNSHostName use the raw value
    assert "(sAMAccountName=PC001$)" in f
    assert "(cn=PC001)" in f
    assert "(dNSHostName=PC001)" in f
    assert result is not None
    assert result["sAMAccountName"] == "PC001$"


def test_get_computer_keeps_existing_dollar(conn) -> None:
    conn.queue([])
    get_computer(conn, "dc=x", "PC001$")
    assert "(sAMAccountName=PC001$)" in conn.searches[-1].search_filter


def test_get_computer_none_when_absent(conn) -> None:
    conn.queue([])
    assert get_computer(conn, "dc=x", "nope") is None


def test_find_ous_filters_and_class(conn) -> None:
    conn.queue([])
    find_ous(conn, "dc=x", name="Staff*")
    f = conn.searches[-1].search_filter
    assert "(objectClass=organizationalUnit)" in f
    assert "(ou=Staff*)" in f


def test_find_ous_no_name_matches_all(conn) -> None:
    conn.queue([])
    find_ous(conn, "dc=x")
    f = conn.searches[-1].search_filter
    assert f == "(&(objectClass=organizationalUnit))"


def test_find_ous_default_attributes(conn) -> None:
    conn.queue([])
    find_ous(conn, "dc=x", name="Staff")
    assert conn.searches[-1].attributes == DEFAULT_OU_ATTRIBUTES


def test_get_ou_exact_match(conn, make_entry) -> None:
    dn = "OU=Staff,DC=example,DC=com"
    conn.queue([make_entry({"ou": "Staff"}, dn=dn)])
    result = get_ou(conn, "dc=x", "Staff")
    f = conn.searches[-1].search_filter
    assert "(objectClass=organizationalUnit)" in f
    assert "(ou=Staff)" in f
    assert "(distinguishedName=Staff)" in f
    assert conn.searches[-1].size_limit == 1
    assert result is not None
    assert result["ou"] == "Staff"


def test_get_ou_returns_none_when_absent(conn) -> None:
    conn.queue([])
    assert get_ou(conn, "dc=x", "Nope") is None


def test_get_ou_contents_uses_ou_as_base(conn, make_entry) -> None:
    ou_dn = "OU=Staff,DC=example,DC=com"
    conn.queue([make_entry({"cn": "Anna"}, dn=f"CN=Anna,{ou_dn}")])
    result = get_ou_contents(conn, ou_dn)
    last = conn.searches[-1]
    assert last.search_base == ou_dn
    assert last.search_filter == "(objectClass=*)"
    assert len(result) == 1


def test_get_ou_contents_filters_by_object_class(conn) -> None:
    conn.queue([])
    get_ou_contents(conn, "OU=Staff,DC=example,DC=com", object_class="user")
    assert conn.searches[-1].search_filter == "(objectClass=user)"


def test_get_ou_contents_handles_ldap_error(conn) -> None:
    from ldap3.core.exceptions import LDAPInvalidDnError

    def boom(search_base, search_filter, size_limit=0, attributes=None):
        raise LDAPInvalidDnError("invalid DN syntax")

    conn.extend.standard.paged_search = boom  # type: ignore[assignment]
    assert get_ou_contents(conn, "not-a-dn") == []


def test_find_inactive_users_filter(conn) -> None:
    conn.queue([])
    find_inactive_users(conn, "dc=x", days=90)
    f = conn.searches[-1].search_filter
    assert "(objectClass=user)" in f
    assert "(objectCategory=person)" in f
    assert "(lastLogonTimestamp<=" in f


def test_find_inactive_users_default_attributes(conn) -> None:
    conn.queue([])
    find_inactive_users(conn, "dc=x")
    assert conn.searches[-1].attributes == DEFAULT_USER_ATTRIBUTES


def test_find_stale_computers_filter(conn) -> None:
    conn.queue([])
    find_stale_computers(conn, "dc=x", days=30)
    f = conn.searches[-1].search_filter
    assert "(objectClass=computer)" in f
    assert "(lastLogonTimestamp<=" in f


def test_days_ago_filetime_is_monotonic() -> None:
    from msad.search import _days_ago_filetime

    # A more recent cutoff (fewer days ago) yields a larger FILETIME.
    older = _days_ago_filetime(365)
    newer = _days_ago_filetime(1)
    assert isinstance(older, int)
    assert older < newer
    # Sanity: a FILETIME for a recent date is a large positive integer.
    assert newer > 130_000_000_000_000_000


def test_find_inactive_users_include_never(conn) -> None:
    conn.queue([])
    find_inactive_users(conn, "dc=x", days=90, include_never=True)
    f = conn.searches[-1].search_filter
    assert "(lastLogonTimestamp<=" in f
    assert "(!(lastLogonTimestamp=*))" in f
    assert f.count("(|") >= 1


def test_find_stale_computers_include_never(conn) -> None:
    conn.queue([])
    find_stale_computers(conn, "dc=x", days=90, include_never=True)
    f = conn.searches[-1].search_filter
    assert "(!(lastLogonTimestamp=*))" in f
