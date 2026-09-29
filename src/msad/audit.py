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

import datetime
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


# FILETIME epoch offset (seconds between 1601-01-01 and 1970-01-01).
_FILETIME_EPOCH_OFFSET = 11644473600

#: Attributes returned for each user flagged by a password-policy check.
DEFAULT_PWD_VIOLATION_ATTRIBUTES = [
    "sAMAccountName",
    "cn",
    "mail",
    "pwdLastSet",
    "userAccountControl",
    "whenCreated",
    "distinguishedName",
]


def _now_filetime() -> int:
    """Current time as a Windows FILETIME (100-ns intervals since 1601)."""
    unix_seconds = datetime.datetime.now(datetime.UTC).timestamp()
    return int((unix_seconds + _FILETIME_EPOCH_OFFSET) * 10_000_000)


def _max_pwd_age_filetime_span(max_pwd_age: object) -> int | None:
    """Normalize a domain ``maxPwdAge`` value to a positive FILETIME span.

    AD stores ``maxPwdAge`` as a negative FILETIME interval; ldap3 may surface
    it as a negative int (100-ns units) or a ``timedelta``. Returns the span in
    100-ns units (positive), or None if passwords never expire (age is 0).
    """
    if isinstance(max_pwd_age, datetime.timedelta):
        span = int(abs(max_pwd_age.total_seconds()) * 10_000_000)
    elif isinstance(max_pwd_age, int):
        span = abs(max_pwd_age)
    else:
        return None
    return span or None


def get_password_policy_violations(
    conn: LdapConnection,
    base: str,
    *,
    include_never_set: bool = True,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find enabled users whose password violates the domain password policy.

    A user is flagged when the password is older than the domain ``maxPwdAge``
    (i.e. it has expired), optionally also when it was never set
    (``pwdLastSet=0``, meaning the user must change it at next logon). Accounts
    whose password never expires (``DONT_EXPIRE_PASSWORD``) are excluded, since
    the age rule does not apply to them.

    Args:
        base: the domain naming context DN (used to read the policy and as the
            user search base).
        include_never_set: also flag users with ``pwdLastSet=0``.

    Returns:
        A list of flagged user entries. Empty if the policy has no maximum age.
    """
    policy = get_password_policy(conn, base)
    if not policy:
        logging.debug("password policy not found under %r", base)
        return []

    span = _max_pwd_age_filetime_span(policy.get("maxPwdAge"))
    if span is None:
        # maxPwdAge = 0 -> passwords never expire domain-wide: no age violations.
        logging.debug("domain maxPwdAge is 0 (passwords never expire)")
        return []

    cutoff = _now_filetime() - span
    # DONT_EXPIRE_PASSWORD = 0x10000 (65536); exclude those accounts via a
    # bitwise-AND matching rule (1.2.840.113556.1.4.803).
    not_never_expires = "(!(userAccountControl:1.2.840.113556.1.4.803:=65536))"
    expired = f"(pwdLastSet<={cutoff})"
    if include_never_set:
        expired = f"(|{expired}(pwdLastSet=0))"
    search_filter = f"(&(objectClass=user)(objectCategory=person){not_never_expires}{expired})"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_PWD_VIOLATION_ATTRIBUTES,
    )


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
    "DEFAULT_PWD_VIOLATION_ATTRIBUTES",
    "escape_exact",
    "get_domain_info",
    "get_password_policy",
    "get_password_policy_violations",
    "get_privileged_groups",
]
