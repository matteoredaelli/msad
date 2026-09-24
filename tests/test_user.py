"""Tests for msad.user: status checks, password age, group filters, password change."""

from __future__ import annotations

import datetime

import pytest

from msad.exceptions import MsadNotFoundError
from msad.user import (
    change_password,
    check_user,
    has_expired_password,
    has_never_expires_password,
    is_disabled,
    is_locked,
    password_changed_in_days,
    user_groups,
)

USER_DN = "CN=matteo,DC=example,DC=com"


def test_is_disabled_true(conn) -> None:
    conn.queue([{"dn": USER_DN, "attributes": {}}])
    assert is_disabled(conn, "dc=x", "matteo") is True
    assert "userAccountControl:1.2.840.113556.1.4.803:=2" in conn.last_filter


def test_is_disabled_none_when_absent(conn) -> None:
    conn.queue([])
    assert is_disabled(conn, "dc=x", "matteo") is None


def test_is_locked_true(conn) -> None:
    conn.queue([{"dn": USER_DN, "attributes": {}}])
    assert is_locked(conn, "dc=x", "matteo") is True
    assert "(lockoutTime>=1)" in conn.last_filter


def test_has_never_expires_true(conn) -> None:
    conn.queue([{"dn": USER_DN, "attributes": {}}])
    assert has_never_expires_password(conn, "dc=x", "matteo") is True
    assert "1.2.840.113556.1.4.803:=65536" in conn.last_filter


def test_password_changed_in_days_old_password(conn) -> None:
    old = datetime.datetime.now() - datetime.timedelta(days=200)
    conn.queue([{"dn": USER_DN, "attributes": {"pwdLastSet": old}}])
    assert password_changed_in_days(conn, "dc=x", "matteo", max_age=90) is True


def test_password_changed_in_days_recent_password(conn) -> None:
    recent = datetime.datetime.now() - datetime.timedelta(days=10)
    conn.queue([{"dn": USER_DN, "attributes": {"pwdLastSet": recent}}])
    assert password_changed_in_days(conn, "dc=x", "matteo", max_age=90) is False


def test_password_changed_in_days_zero_means_must_change(conn) -> None:
    conn.queue([{"dn": USER_DN, "attributes": {"pwdLastSet": 0}}])
    assert password_changed_in_days(conn, "dc=x", "matteo") is True


def test_password_changed_in_days_user_absent(conn) -> None:
    conn.queue([])
    assert password_changed_in_days(conn, "dc=x", "ghost") is None


def test_user_groups_nested_filter(conn) -> None:
    # get_dn short-circuits on DN, then the nested lookup runs
    conn.queue([{"dn": "g", "attributes": {"sAMAccountName": "grp"}}])
    user_groups(conn, "dc=x", 2000, USER_DN, nested=True)
    assert f"member:1.2.840.113556.1.4.1941:={USER_DN}" in conn.last_filter
    assert conn.searches[-1].attributes == ["sAMAccountName"]


def test_user_groups_direct_uses_memberof(conn) -> None:
    conn.queue([{"dn": "g", "attributes": {"memberOf": ["grp"]}}])
    user_groups(conn, "dc=x", 2000, USER_DN, nested=False)
    rec = conn.searches[-1]
    assert rec.search_base == USER_DN
    assert rec.attributes == ["memberOf"]


def test_user_groups_user_not_found_returns_none(conn) -> None:
    conn.queue([])  # get_dn lookup for sAMAccountName -> empty
    assert user_groups(conn, "dc=x", 2000, "ghost") is None


def test_change_password_calls_modify(conn) -> None:
    change_password(conn, "dc=x", USER_DN, "newpwd", "oldpwd")
    assert conn.calls[-1] == ("modify_password", USER_DN, "newpwd", "oldpwd")


def test_change_password_user_not_found_raises(conn) -> None:
    conn.queue([])  # get_dn lookup fails
    with pytest.raises(MsadNotFoundError, match="User not found"):
        change_password(conn, "dc=x", "ghost", "newpwd")


def test_has_expired_password_false_when_never_expires(conn) -> None:
    # never_expires lookup returns a hit -> treated as not expired, no further query
    conn.queue([{"dn": USER_DN, "attributes": {}}])
    assert has_expired_password(conn, "dc=x", "matteo") is False


def test_has_expired_password_true_when_old(conn) -> None:
    old = datetime.datetime.now() - datetime.timedelta(days=200)
    # 1) never_expires lookup: empty -> not never-expiring
    # 2) pwdLastSet lookup: old date
    conn.queue([], [{"dn": USER_DN, "attributes": {"pwdLastSet": old}}])
    assert has_expired_password(conn, "dc=x", "matteo", max_age=90) is True


def test_check_user_yields_all_checks(conn) -> None:
    # is_disabled, is_locked, has_never_expires, password_changed_in_days,
    # has_expired(never_expires + pwd), then group_member for the group.
    # Use a DN group so group_member's get_dn short-circuits (no extra query).
    conn.queue(*[[] for _ in range(8)])
    results = list(
        check_user(conn, "dc=x", USER_DN, max_age=90, groups=["CN=grp,DC=example,DC=com"])
    )
    keys = [next(iter(d)) for d in results]
    assert keys == [
        "is_disabled",
        "is_locked",
        "has_never_expires_password",
        "password_changed_in_days",
        "has_expired_password",
        "membership_CN=grp,DC=example,DC=com",
    ]
