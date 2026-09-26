# msad - Active Directory tool
# Copyright (C) 2025 - matteo.redaelli@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Read-only auditing helpers: domain info, privileged groups, password policy.

These build on :func:`msad.search.search` so they share the same connection
handling, paging and result shape (plain dicts) as the rest of the library.
"""

from __future__ import annotations

import logging

from .group import get_group, group_members
from .search import escape_exact, search
from .types import Attributes, LdapConnection, LdapEntries, LdapEntry

#: Domain object attributes worth surfacing for an audit overview.
DEFAULT_DOMAIN_ATTRIBUTES = [
    "name",
    "whenCreated",
    "objectSid",
    "ms-DS-MachineAccountQuota",
    "maxPwdAge",
    "minPwdAge",
    "minPwdLength",
    "pwdHistoryLength",
    "pwdProperties",
    "lockoutThreshold",
    "lockoutDuration",
    "lockOutObservationWindow",
    "msDS-Behavior-Version",
    "distinguishedName",
]

#: Password-policy attributes, read from the domain (default domain policy).
DEFAULT_PASSWORD_POLICY_ATTRIBUTES = [
    "maxPwdAge",
    "minPwdAge",
    "minPwdLength",
    "pwdHistoryLength",
    "pwdProperties",
    "lockoutThreshold",
    "lockoutDuration",
    "lockOutObservationWindow",
]

#: Well-known privileged groups (matched by sAMAccountName or cn). Names are
#: locale-dependent in AD; sAMAccountName of built-ins is stable in English.
DEFAULT_PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "Group Policy Creator Owners",
    "DnsAdmins",
]


def get_domain_info(
    conn: LdapConnection,
    base: str,
    attributes: Attributes = None,
) -> LdapEntry | None:
    """Read the domain object (security-relevant settings and metadata).

    Args:
        base: the domain naming context DN (e.g. ``DC=example,DC=com``); it is
            used as the search base.
        attributes: attributes to fetch (defaults to a curated audit set).

    Returns:
        The domain object's attributes as a dict, or None if not found.
    """
    result = search(
        conn,
        base,
        "(objectClass=domainDNS)",
        limit=1,
        attributes=attributes or DEFAULT_DOMAIN_ATTRIBUTES,
    )
    return result[0] if result else None


def get_password_policy(
    conn: LdapConnection,
    base: str,
) -> LdapEntry | None:
    """Read the default domain password policy from the domain object.

    Args:
        base: the domain naming context DN (used as the search base).

    Returns:
        A dict of the password-policy attributes, or None if not found.
    """
    result = search(
        conn,
        base,
        "(objectClass=domainDNS)",
        limit=1,
        attributes=DEFAULT_PASSWORD_POLICY_ATTRIBUTES,
    )
    return result[0] if result else None


def get_privileged_groups(
    conn: LdapConnection,
    base: str,
    *,
    names: list[str] | None = None,
    with_members: bool = False,
    nested: bool = False,
) -> LdapEntries:
    """Report on well-known privileged groups present in the domain.

    Args:
        base: the DN to search under (usually the domain naming context).
        names: override the default list of privileged group names to look up.
        with_members: also include each group's members (see ``nested``).
        nested: when ``with_members`` is set, expand nested membership.

    Returns:
        One entry per privileged group that exists, each a dict with the
        group's default attributes plus ``member_count`` and, when
        ``with_members`` is set, a ``members`` list.
    """
    wanted = names if names is not None else DEFAULT_PRIVILEGED_GROUPS
    report: LdapEntries = []
    for name in wanted:
        group = get_group(conn, base, name)
        if group is None:
            logging.debug("privileged group %r not found", name)
            continue
        members = group_members(conn, base, name, nested=nested)
        entry: LdapEntry = dict(group)
        entry["member_count"] = len(members)
        if with_members:
            entry["members"] = members
        report.append(entry)
    return report


# escape_exact is re-exported for callers that build their own audit filters.
__all__ = [
    "DEFAULT_DOMAIN_ATTRIBUTES",
    "DEFAULT_PASSWORD_POLICY_ATTRIBUTES",
    "DEFAULT_PRIVILEGED_GROUPS",
    "escape_exact",
    "get_domain_info",
    "get_password_policy",
    "get_privileged_groups",
]
