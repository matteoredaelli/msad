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

from ldap3.core.exceptions import LDAPExceptionError

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


def _configuration_nc(base: str) -> str:
    """Return the Configuration naming context DN for a domain base.

    For a single-domain forest the forest root equals the domain base, so the
    Configuration NC is ``CN=Configuration,<base>``. In a multi-domain forest
    pass an explicit ``config_base`` to the callers below.
    """
    return f"CN=Configuration,{base}"


#: The five FSMO roles and the well-known container (relative to the domain
#: base or the Configuration NC) whose ``fSMORoleOwner`` names the role holder.
_FSMO_ROLES = [
    ("schema_master", "CN=Schema,{config}"),
    ("domain_naming_master", "CN=Partitions,{config}"),
    ("pdc_emulator", "{base}"),
    ("rid_master", "CN=RID Manager$,CN=System,{base}"),
    ("infrastructure_master", "CN=Infrastructure,{base}"),
]


def list_fsmo_roles(
    conn: LdapConnection,
    base: str,
    *,
    config_base: str | None = None,
) -> LdapEntries:
    """Report the owner (``fSMORoleOwner``) of each of the five FSMO roles.

    The schema and domain-naming masters live in the Configuration naming
    context; the other three are domain-scoped. For a single-domain forest the
    Configuration NC is derived from ``base``; pass ``config_base`` explicitly
    for a multi-domain forest.

    Returns:
        One entry per role that could be read, each a dict with ``role``,
        ``container`` (the DN queried) and ``owner`` (the owning DSA DN, or
        None if the attribute was absent). A container that cannot be read is
        skipped (logged at debug level).
    """
    config = config_base or _configuration_nc(base)
    report: LdapEntries = []
    for role, template in _FSMO_ROLES:
        container = template.format(base=base, config=config)
        try:
            result = search(
                conn, container, "(objectClass=*)", limit=1, attributes=["fSMORoleOwner"]
            )
        except LDAPExceptionError as exc:
            logging.debug("FSMO role %s: cannot read %r: %s", role, container, exc)
            continue
        if not result:
            continue
        owner = result[0].get("fSMORoleOwner")
        if isinstance(owner, list):
            owner = owner[0] if owner else None
        report.append({"role": role, "container": container, "owner": owner})
    return report


#: Attributes worth surfacing for each trust relationship.
DEFAULT_TRUST_ATTRIBUTES = [
    "trustPartner",
    "flatName",
    "trustDirection",
    "trustType",
    "trustAttributes",
    "whenCreated",
    "distinguishedName",
]


def list_trusts(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List the domain's trust relationships (``objectClass=trustedDomain``).

    Trust objects live under ``CN=System,<base>``.

    Returns:
        A list of trust entries (default attributes if none given).
    """
    system = f"CN=System,{base}"
    try:
        return search(
            conn,
            system,
            "(objectClass=trustedDomain)",
            limit=limit,
            attributes=attributes or DEFAULT_TRUST_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("list_trusts: cannot read %r: %s", system, exc)
        return []


#: Attributes worth surfacing for each AD site.
DEFAULT_SITE_ATTRIBUTES = [
    "cn",
    "description",
    "whenCreated",
    "distinguishedName",
]


def list_sites(
    conn: LdapConnection,
    base: str,
    *,
    config_base: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List the AD sites (``objectClass=site``) from the Configuration NC.

    Sites live under ``CN=Sites,CN=Configuration,<forest root>``. For a
    single-domain forest the Configuration NC is derived from ``base``; pass
    ``config_base`` explicitly for a multi-domain forest.

    Returns:
        A list of site entries (default attributes if none given).
    """
    config = config_base or _configuration_nc(base)
    sites = f"CN=Sites,{config}"
    try:
        return search(
            conn,
            sites,
            "(objectClass=site)",
            limit=limit,
            attributes=attributes or DEFAULT_SITE_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("list_sites: cannot read %r: %s", sites, exc)
        return []


#: Attributes worth surfacing for each Group Policy Object.
DEFAULT_GPO_ATTRIBUTES = [
    "cn",
    "displayName",
    "gPCFileSysPath",
    "versionNumber",
    "flags",
    "whenCreated",
    "whenChanged",
    "distinguishedName",
]


def list_gpos(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List Group Policy Objects (``groupPolicyContainer``).

    GPOs live under ``CN=Policies,CN=System,<base>``. Each GPO's ``cn`` is its
    GUID; ``displayName`` is the friendly name.

    Returns:
        A list of GPO entries (default attributes if none given). Empty if the
        Policies container cannot be read.
    """
    policies = f"CN=Policies,CN=System,{base}"
    try:
        return search(
            conn,
            policies,
            "(objectClass=groupPolicyContainer)",
            limit=limit,
            attributes=attributes or DEFAULT_GPO_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("list_gpos: cannot read %r: %s", policies, exc)
        return []


def get_gpo(
    conn: LdapConnection,
    base: str,
    identifier: str,
    attributes: Attributes = None,
) -> LdapEntry | None:
    """Return a single GPO matched by its ``cn`` (GUID) or ``displayName``.

    The GUID may be given with or without surrounding braces. Returns the first
    match, or None if no GPO is found.
    """
    value = escape_exact(identifier)
    braced = value if value.startswith("{") else f"{{{value}}}"
    policies = f"CN=Policies,CN=System,{base}"
    search_filter = (
        f"(&(objectClass=groupPolicyContainer)(|(cn={value})(cn={braced})(displayName={value})))"
    )
    try:
        result = search(
            conn,
            policies,
            search_filter,
            limit=1,
            attributes=attributes or DEFAULT_GPO_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("get_gpo(%r): cannot read %r: %s", identifier, policies, exc)
        return None
    return result[0] if result else None


#: Attributes worth surfacing for each fine-grained password policy (PSO).
DEFAULT_PSO_ATTRIBUTES = [
    "cn",
    "msDS-PasswordSettingsPrecedence",
    "msDS-MinimumPasswordLength",
    "msDS-PasswordHistoryLength",
    "msDS-MaximumPasswordAge",
    "msDS-MinimumPasswordAge",
    "msDS-LockoutThreshold",
    "msDS-LockoutDuration",
    "msDS-PasswordComplexityEnabled",
    "msDS-PSOAppliesTo",
    "distinguishedName",
]


def list_fine_grained_password_policies(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List fine-grained password policies (PSOs, ``msDS-PasswordSettings``).

    PSOs live under ``CN=Password Settings Container,CN=System,<base>``. Reading
    their contents may require extra directory rights; when the container is not
    readable an empty list is returned.

    Returns:
        A list of PSO entries (default attributes if none given).
    """
    container = f"CN=Password Settings Container,CN=System,{base}"
    try:
        return search(
            conn,
            container,
            "(objectClass=msDS-PasswordSettings)",
            limit=limit,
            attributes=attributes or DEFAULT_PSO_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("list_fine_grained_password_policies: cannot read %r: %s", container, exc)
        return []


# escape_exact is re-exported for callers that build their own audit filters.
__all__ = [
    "DEFAULT_DOMAIN_ATTRIBUTES",
    "DEFAULT_GPO_ATTRIBUTES",
    "DEFAULT_PASSWORD_POLICY_ATTRIBUTES",
    "DEFAULT_PRIVILEGED_GROUPS",
    "DEFAULT_PSO_ATTRIBUTES",
    "DEFAULT_PWD_VIOLATION_ATTRIBUTES",
    "DEFAULT_SITE_ATTRIBUTES",
    "DEFAULT_TRUST_ATTRIBUTES",
    "escape_exact",
    "get_domain_info",
    "get_gpo",
    "get_password_policy",
    "get_password_policy_violations",
    "get_privileged_groups",
    "list_fine_grained_password_policies",
    "list_fsmo_roles",
    "list_gpos",
    "list_sites",
    "list_trusts",
]
