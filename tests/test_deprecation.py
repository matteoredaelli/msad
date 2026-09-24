"""Tests that deprecated aliases warn and delegate to the new functions."""

from __future__ import annotations

import pytest

from msad.group import group_flat_members, group_member, group_members, is_member
from msad.search import users

GROUP_DN = "CN=grp,DC=example,DC=com"
USER_DN = "CN=matteo,DC=example,DC=com"


def test_group_member_warns_and_delegates_to_is_member(conn) -> None:
    conn.queue([{"dn": USER_DN, "attributes": {"cn": "matteo"}}])
    with pytest.warns(DeprecationWarning, match="is_member"):
        result = group_member(conn, "dc=x", GROUP_DN, USER_DN)
    assert result is True
    # Same recursive membership filter is_member would build.
    assert f"memberOf:1.2.840.113556.1.4.1941:={GROUP_DN}" in conn.last_filter


def test_group_flat_members_warns_and_delegates_nested(conn) -> None:
    conn.queue([])
    with pytest.warns(DeprecationWarning, match="nested=True"):
        group_flat_members(conn, "dc=x", GROUP_DN)
    # Delegates to group_members(nested=True) -> recursive rule.
    assert f"memberOf:1.2.840.113556.1.4.1941:={GROUP_DN}" in conn.last_filter


def test_group_flat_members_matches_group_members_nested(conn) -> None:
    conn.queue([], [])  # one for each call
    with pytest.warns(DeprecationWarning):
        group_flat_members(conn, "dc=x", GROUP_DN)
    flat_filter = conn.last_filter
    group_members(conn, "dc=x", GROUP_DN, nested=True)
    assert conn.last_filter == flat_filter


def test_users_warns(conn) -> None:
    conn.queue([])
    with pytest.warns(DeprecationWarning, match="find_users"):
        users(conn, "dc=x", "matteo")


def test_is_member_does_not_warn(conn, recwarn) -> None:
    conn.queue([])
    is_member(conn, "dc=x", GROUP_DN, USER_DN)
    assert not [w for w in recwarn.list if issubclass(w.category, DeprecationWarning)]
