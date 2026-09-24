#!/usr/bin/env python

# msad - Active Directory tool
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

import datetime
import logging
from collections.abc import Iterator, Sequence
from typing import Any

from .exceptions import MsadNotFoundError
from .group import is_member
from .search import (
    disabled_users,
    escape_exact,
    get_dn,
    locked_users,
    never_expires_password,
    search,
)
from .types import LdapConnection, LdapEntries


def change_password(
    conn: LdapConnection,
    search_base: str,
    user: str,
    new_password: str,
    old_password: str | None = None,
) -> Any:
    """Change (or reset) a user's password.

    This is a pure function: it does not prompt for input. The caller
    (CLI or MCP) is responsible for collecting passwords securely.

    Args:
        conn: a bound ldap3 connection.
        search_base: the AD search base.
        user: sAMAccountName or DN of the user.
        new_password: the new password to set.
        old_password: the current password. Required for a self-service
            change; omit (None) for an administrative reset.

    Raises:
        MsadNotFoundError: if the user cannot be resolved to a DN.
    """
    user_dn = get_dn(conn, search_base, user)
    if not user_dn:
        raise MsadNotFoundError(f"User not found: {user}")

    return conn.extend.microsoft.modify_password(user_dn, new_password, old_password)


def is_disabled(conn: LdapConnection, search_base: str, user: str) -> bool | None:
    """Return True if the user account is disabled, None if not found."""
    result = disabled_users(
        conn, search_base, f"(samaccountname={escape_exact(user)})", limit=1, attributes=None
    )
    logging.debug(result)
    return True if len(result) == 1 else None


def is_locked(conn: LdapConnection, search_base: str, user: str) -> bool | None:
    """Return True if the user account is locked, None if not found."""
    result = locked_users(
        conn, search_base, f"(samaccountname={escape_exact(user)})", limit=1, attributes=None
    )
    return True if len(result) == 1 else None


def has_never_expires_password(conn: LdapConnection, search_base: str, user: str) -> bool | None:
    """Return True if the user's password never expires, None if not found."""
    result = never_expires_password(
        conn, search_base, f"(samaccountname={escape_exact(user)})", limit=1, attributes=None
    )
    return True if len(result) == 1 else None


def password_changed_in_days(
    conn: LdapConnection, search_base: str, user: str, max_age: int = 90
) -> bool | None:
    """Return True if the password is older than max_age days.

    Returns None if the user (or pwdLastSet) is not found.
    """
    search_filter = f"(samaccountname={escape_exact(user)})"
    result = search(conn, search_base, search_filter, limit=1, attributes=["pwdLastSet"])

    if len(result) == 0:
        return None
    pwd_last_set = result[0]["pwdLastSet"]
    logging.info(f"Password changed at {pwd_last_set}")
    now = datetime.datetime.now()

    if pwd_last_set == 0:
        return True
    delta = now - pwd_last_set.replace(tzinfo=None)
    return delta.days > max_age


def has_expired_password(
    conn: LdapConnection, search_base: str, user: str, max_age: int = 90
) -> bool | None:
    """Check if the user's password is older than max_age days.

    Users whose password never expires are treated as not expired.
    """
    if has_never_expires_password(conn, search_base, user):
        return False
    return password_changed_in_days(conn, search_base, user, max_age=max_age)


def check_user(
    conn: LdapConnection,
    search_base: str,
    user: str,
    max_age: int,
    groups: Sequence[str] | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield a series of checks about a user (disabled, locked, password, ...).

    Each yielded dict has a single key describing the check and its result.
    """
    groups = groups or []
    yield {"is_disabled": is_disabled(conn, search_base, user)}
    yield {"is_locked": is_locked(conn, search_base, user)}
    yield {"has_never_expires_password": has_never_expires_password(conn, search_base, user)}
    yield {"password_changed_in_days": password_changed_in_days(conn, search_base, user)}
    yield {"has_expired_password": has_expired_password(conn, search_base, user, max_age)}
    for group in groups:
        yield {f"membership_{group}": is_member(conn, search_base, group=group, user=user)}


def user_groups(
    conn: LdapConnection,
    search_base: str,
    limit: int,
    user: str,
    nested: bool = True,
) -> LdapEntries | None:
    """Retrieve the groups of a user (nested by default).

    Returns None if the user cannot be resolved to a DN.
    """
    user_dn = get_dn(conn, search_base, user)
    if not user_dn:
        return None

    attributes: list[str]
    if nested:
        search_filter = f"(member:1.2.840.113556.1.4.1941:={escape_exact(user_dn)})"
        attributes = ["sAMAccountName"]
    else:
        search_filter = "(objectClass=*)"
        search_base = user_dn
        attributes = ["memberOf"]
    return search(conn, search_base, search_filter, limit=limit, attributes=attributes)
