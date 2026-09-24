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
import logging

import ldap3
from ldap3.utils.conv import escape_filter_chars

from ._deprecation import warn_deprecated
from .types import Attributes, LdapConnection, LdapEntries, LdapEntry

#: A sensible default set of user attributes (keeps MCP/LLM output focused).
DEFAULT_USER_ATTRIBUTES = [
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

#: A sensible default set of group attributes.
DEFAULT_GROUP_ATTRIBUTES = [
    "sAMAccountName",
    "cn",
    "displayName",
    "description",
    "mail",
    "distinguishedName",
]


def escape_exact(value: str) -> str:
    """Escape an LDAP filter assertion value (exact match).

    Escapes ``*``, ``(``, ``)``, ``\\`` and NUL to prevent LDAP injection.
    Use for identifiers that must match literally (sAMAccountName, DN, ...).
    """
    return escape_filter_chars(value)


def escape_pattern(value: str) -> str:
    """Escape a value used in a wildcard search, preserving user ``*``.

    Every metacharacter is escaped except ``*``, so the caller/user can still
    use ``*`` as a wildcard while injection via ``()\\`` is prevented.
    """
    # Escape everything, then restore intentional wildcards.
    return escape_filter_chars(value).replace("\\2a", "*")


def search(
    conn: LdapConnection,
    search_base: str,
    search_filter: str,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Run a paged LDAP search and return the matching entries' attributes.

    Note:
        ``search_filter`` is used verbatim. Callers that interpolate
        user-provided values must escape them first (see :func:`escape_exact`
        and :func:`escape_pattern`). The higher-level helpers in this module
        do this for you.

    Args:
        conn: a bound ldap3 connection.
        search_base: the DN to search under.
        search_filter: a raw LDAP filter.
        limit: max number of entries (0 = no limit).
        attributes: attributes to fetch (None = all attributes).

    Returns:
        A list of entries, each a dict of attribute name -> value(s).
    """
    effective_attributes = attributes if attributes else ldap3.ALL_ATTRIBUTES

    resultgenerator = conn.extend.standard.paged_search(
        search_base, search_filter, size_limit=limit, attributes=effective_attributes
    )
    result = list(resultgenerator)
    entries = [r["attributes"] for r in result if "dn" in r]
    logging.debug(entries)
    return entries


def users(
    conn: LdapConnection,
    search_base: str,
    string: str,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Deprecated: use ``find_users()`` or ``get_user()`` instead.

    Searches users by an OR across sAMAccountName, mail, cn* and UPN*.
    The value may contain ``*`` wildcards.
    """
    warn_deprecated("users()", "find_users() or get_user()")
    value = escape_pattern(string)
    search_filter = (
        f"(&(objectclass=user)(|(samaccountname={value})(mail={value})"
        f"(cn={value}*)(userPrincipalName={value}*)))"
    )
    return search(conn, search_base, search_filter, limit=limit, attributes=attributes)


def find_users(
    conn: LdapConnection,
    search_base: str,
    *,
    name: str | None = None,
    surname: str | None = None,
    mail: str | None = None,
    sam: str | None = None,
    department: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find users by one or more specific fields (all ANDed together).

    Each provided criterion is matched independently; values may contain
    ``*`` wildcards. Passing no criteria matches all users.

    Args:
        name: matches ``givenName`` (first name).
        surname: matches ``sn`` (last name).
        mail: matches ``mail``.
        sam: matches ``sAMAccountName``.
        department: matches ``department``.

    Returns:
        A list of matching user entries (default attributes if none given).
    """
    clauses: list[str] = []
    for attr, value in (
        ("givenName", name),
        ("sn", surname),
        ("mail", mail),
        ("sAMAccountName", sam),
        ("department", department),
    ):
        if value:
            clauses.append(f"({attr}={escape_pattern(value)})")

    inner = "".join(clauses)
    search_filter = f"(&(objectClass=user)(objectCategory=person){inner})"
    return search(
        conn,
        search_base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )


def get_user(
    conn: LdapConnection,
    search_base: str,
    identifier: str,
    attributes: Attributes = None,
) -> LdapEntry | None:
    """Return a single user matched by sAMAccountName, UPN, mail or cn.

    Uses an exact match on each identifier field (no wildcards). Returns the
    first match, or None if no user is found.
    """
    value = escape_exact(identifier)
    search_filter = (
        f"(&(objectClass=user)(objectCategory=person)"
        f"(|(sAMAccountName={value})(userPrincipalName={value})(mail={value})(cn={value})))"
    )
    result = search(
        conn,
        search_base,
        search_filter,
        limit=1,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )
    return result[0] if result else None


def get_dn(conn: LdapConnection, search_base: str, entry: str) -> str | None:
    """Resolve an sAMAccountName (or DN) to a distinguished name.

    Returns the DN unchanged if ``entry`` already looks like a DN
    (starts with ``cn=``), otherwise looks it up. Returns None if not found.
    """
    if entry.lower().startswith("cn="):
        return entry
    search_filter = f"(sAMAccountName={escape_exact(entry)})"
    result = search(conn, search_base, search_filter, attributes=["distinguishedName"])
    logging.debug(result)
    if len(result) < 1:
        logging.error(f"entry {entry} not found")
        return None

    return result[0]["distinguishedName"]


def never_expires_password(
    conn: LdapConnection,
    search_base: str,
    extra_filter: str = "",
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Search users whose password never expires (UAC flag 65536)."""
    search_filter = (
        f"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536){extra_filter})"
    )
    return search(conn, search_base, search_filter, limit=limit, attributes=attributes)


def disabled_users(
    conn: LdapConnection,
    search_base: str,
    extra_filter: str = "",
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Search disabled user accounts (UAC flag 2)."""
    search_filter = (
        f"(&(objectCategory=Person)(objectClass=User){extra_filter}"
        f"(userAccountControl:1.2.840.113556.1.4.803:=2))"
    )
    return search(conn, search_base, search_filter, limit=limit, attributes=attributes)


def locked_users(
    conn: LdapConnection,
    search_base: str,
    extra_filter: str = "",
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Search locked-out user accounts (lockoutTime >= 1)."""
    search_filter = f"(&(objectCategory=Person)(objectClass=User){extra_filter}(lockoutTime>=1))"
    return search(conn, search_base, search_filter, attributes=attributes)
