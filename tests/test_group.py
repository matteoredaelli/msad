"""Tests for msad.group: direct vs nested filters, not-found errors, membership."""

from __future__ import annotations

import pytest

from msad.exceptions import MsadNotFoundError
from msad.group import (
    add_member,
    find_groups,
    get_group,
    group_members,
    is_member,
    remove_member,
)

GROUP_DN = "CN=grp,DC=example,DC=com"
USER_DN = "CN=matteo,DC=example,DC=com"


def test_group_members_direct_filter(conn) -> None:
    conn.queue([{"dn": USER_DN, "attributes": {"sAMAccountName": "matteo"}}])
    result = group_members(conn, "dc=x", GROUP_DN)
    f = conn.last_filter
    assert f"(memberOf={GROUP_DN})" in f
    assert "1.2.840.113556.1.4.1941" not in f  # NOT recursive
    assert result == [{"sAMAccountName": "matteo"}]


def test_group_members_nested_filter(conn) -> None:
    conn.queue([])
    group_members(conn, "dc=x", GROUP_DN, nested=True)
    f = conn.last_filter
    assert f"memberOf:1.2.840.113556.1.4.1941:={GROUP_DN}" in f  # recursive rule


def test_group_members_group_not_found_raises(conn) -> None:
    conn.queue([])  # get_dn lookup returns empty
    with pytest.raises(MsadNotFoundError, match="Group not found"):
        group_members(conn, "dc=x", "ghostgroup")


def test_is_member_true_when_one_result(conn) -> None:
    conn.queue([{"dn": USER_DN, "attributes": {"cn": "matteo"}}])
    assert is_member(conn, "dc=x", GROUP_DN, USER_DN) is True


def test_is_member_false_when_no_result(conn) -> None:
    conn.queue([])
    assert is_member(conn, "dc=x", GROUP_DN, USER_DN) is False


def test_is_member_filter_contents(conn) -> None:
    conn.queue([])
    is_member(conn, "dc=x", GROUP_DN, USER_DN)
    f = conn.last_filter
    assert f"memberOf:1.2.840.113556.1.4.1941:={GROUP_DN}" in f
    assert f"(distinguishedName={USER_DN})" in f


def test_add_member_calls_microsoft_extend(conn) -> None:
    result = add_member(conn, "dc=x", GROUP_DN, USER_DN)
    assert result is True
    assert conn.calls[-1] == ("add_members_to_groups", [USER_DN], [GROUP_DN])


def test_remove_member_calls_microsoft_extend(conn) -> None:
    result = remove_member(conn, "dc=x", GROUP_DN, USER_DN)
    assert result is True
    assert conn.calls[-1] == ("remove_members_from_groups", [USER_DN], [GROUP_DN])


def test_add_member_user_not_found_raises(conn) -> None:
    # group resolves (DN short-circuit), user lookup returns empty
    conn.queue([])
    with pytest.raises(MsadNotFoundError, match="User not found"):
        add_member(conn, "dc=x", GROUP_DN, "ghostuser")


def test_find_groups_filter(conn) -> None:
    conn.queue([])
    find_groups(conn, "dc=x", "admins*")
    f = conn.last_filter
    assert "(objectClass=group)" in f
    assert "(cn=admins*)" in f
    assert "(sAMAccountName=admins*)" in f
    assert "(displayName=admins*)" in f


def test_get_group_returns_single_or_none(conn) -> None:
    conn.queue([{"dn": GROUP_DN, "attributes": {"cn": "admins"}}])
    grp = get_group(conn, "dc=x", "admins")
    assert grp == {"cn": "admins"}
    f = conn.last_filter
    assert "(sAMAccountName=admins)" in f
    assert "(cn=admins)" in f


def test_get_group_none_when_absent(conn) -> None:
    conn.queue([])
    assert get_group(conn, "dc=x", "ghost") is None
