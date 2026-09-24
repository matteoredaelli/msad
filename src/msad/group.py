#!/usr/bin/env python3

# AD - Active Directory tool
# Copyright (C) 2020 - matteo.redaelli@gmail.com

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


from typing import Any

from ._deprecation import warn_deprecated
from .exceptions import MsadNotFoundError
from .search import (
    DEFAULT_GROUP_ATTRIBUTES,
    escape_exact,
    escape_pattern,
    get_dn,
    search,
)
from .types import Attributes, LdapConnection, LdapEntries, LdapEntry


def find_groups(
    conn: LdapConnection,
    search_base: str,
    string: str,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Search groups by cn, name, sAMAccountName or displayName.

    The value may contain ``*`` wildcards.
    """
    value = escape_pattern(string)
    search_filter = (
        f"(&(objectClass=group)(|(cn={value})(name={value})"
        f"(sAMAccountName={value})(displayName={value})))"
    )
    return search(
        conn,
        search_base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_GROUP_ATTRIBUTES,
    )


def get_group(
    conn: LdapConnection,
    search_base: str,
    identifier: str,
    attributes: Attributes = None,
) -> LdapEntry | None:
    """Return a single group matched by sAMAccountName or cn (exact).

    Returns the first match, or None if no group is found.
    """
    value = escape_exact(identifier)
    search_filter = f"(&(objectClass=group)(|(sAMAccountName={value})(cn={value})))"
    result = search(
        conn,
        search_base,
        search_filter,
        limit=1,
        attributes=attributes or DEFAULT_GROUP_ATTRIBUTES,
    )
    return result[0] if result else None


def add_member(conn: LdapConnection, search_base: str, group: str, user: str) -> Any:
    """Add a user to a group (both given as DN or sAMAccountName).

    Raises:
        MsadNotFoundError: if the group or user cannot be resolved.
    """
    group_dn = get_dn(conn, search_base, group)
    if not group_dn:
        raise MsadNotFoundError(f"Group not found: {group}")

    user_dn = get_dn(conn, search_base, user)
    if not user_dn:
        raise MsadNotFoundError(f"User not found: {user}")

    return conn.extend.microsoft.add_members_to_groups([user_dn], [group_dn])


def remove_member(conn: LdapConnection, search_base: str, group: str, user: str) -> Any:
    """Remove a user from a group (both given as DN or sAMAccountName).

    Raises:
        MsadNotFoundError: if the group or user cannot be resolved.
    """
    group_dn = get_dn(conn, search_base, group)
    if not group_dn:
        raise MsadNotFoundError(f"Group not found: {group}")

    user_dn = get_dn(conn, search_base, user)
    if not user_dn:
        raise MsadNotFoundError(f"User not found: {user}")

    return conn.extend.microsoft.remove_members_from_groups([user_dn], [group_dn])


def group_members(
    conn: LdapConnection,
    search_base: str,
    group: str,
    nested: bool = False,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Return the members of a group as person objects.

    Args:
        nested: if False (default), only direct members. If True, recurse
            into nested groups using the LDAP_MATCHING_RULE_IN_CHAIN
            (1.2.840.113556.1.4.1941) matching rule.

    Raises:
        MsadNotFoundError: if the group cannot be resolved.
    """
    group_dn = get_dn(conn, search_base, group)
    if not group_dn:
        raise MsadNotFoundError(f"Group not found: {group}")

    escaped = escape_exact(group_dn)
    member_clause = (
        f"memberOf:1.2.840.113556.1.4.1941:={escaped}" if nested else f"memberOf={escaped}"
    )
    search_filter = f"(&(objectClass=person)(sAMAccountName=*)({member_clause}))"
    return search(conn, search_base, search_filter, limit=limit, attributes=attributes)


def is_member(conn: LdapConnection, search_base: str, group: str, user: str) -> bool:
    """Check whether a user is a (possibly nested) member of a group.

    Raises:
        MsadNotFoundError: if the group or user cannot be resolved.
    """
    group_dn = get_dn(conn, search_base, group)
    if not group_dn:
        raise MsadNotFoundError(f"Group not found: {group}")

    user_dn = get_dn(conn, search_base, user)
    if not user_dn:
        raise MsadNotFoundError(f"User not found: {user}")

    search_filter = (
        f"(&(memberOf:1.2.840.113556.1.4.1941:={escape_exact(group_dn)})"
        f"(objectCategory=person)(objectClass=user)(distinguishedName={escape_exact(user_dn)}))"
    )
    result = search(conn, search_base, search_filter)
    return len(result) == 1


# --- Deprecated aliases (to be removed in the next release) ----------------


def group_flat_members(
    conn: LdapConnection,
    search_base: str,
    group: str,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Deprecated: use ``group_members(..., nested=True)`` instead."""
    warn_deprecated("group_flat_members()", "group_members(..., nested=True)")
    return group_members(conn, search_base, group, nested=True, limit=limit, attributes=attributes)


def group_member(conn: LdapConnection, search_base: str, group: str, user: str) -> bool:
    """Deprecated: use ``is_member()`` instead."""
    warn_deprecated("group_member()", "is_member()")
    return is_member(conn, search_base, group, user)
