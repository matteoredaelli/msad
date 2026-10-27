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

import ldap3
from ldap3.core.exceptions import LDAPExceptionError
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
    "company",
    "physicalDeliveryOfficeName",
    "telephoneNumber",
    "employeeID",
    "manager",
    "memberOf",
    "userAccountControl",
    "accountExpires",
    "lastLogonTimestamp",
    "whenCreated",
    "distinguishedName",
    "extensionAttribute1",
    "extensionAttribute2",
    "extensionAttribute3",
    "extensionAttribute4",
    "extensionAttribute5",
    "extensionAttribute6",
    "extensionAttribute7",
    "extensionAttribute8",
    "extensionAttribute9",
    "extensionAttribute10",
    "extensionAttribute11",
    "extensionAttribute12",
    "extensionAttribute13",
    "extensionAttribute14",
    "extensionAttribute15",
]

#: A sensible default set of group attributes.
DEFAULT_GROUP_ATTRIBUTES = [
    "sAMAccountName",
    "cn",
    "displayName",
    "description",
    "managedBy",
    "mail",
    "member",
    "groupType",
    "whenCreated",
    "distinguishedName",
]

#: A sensible default set of computer attributes.
DEFAULT_COMPUTER_ATTRIBUTES = [
    "sAMAccountName",
    "cn",
    "dNSHostName",
    "operatingSystem",
    "operatingSystemVersion",
    "userAccountControl",
    "lastLogonTimestamp",
    "description",
    "managedBy",
    "distinguishedName",
]

DEFAULT_OU_ATTRIBUTES = [
    "ou",
    "name",
    "description",
    "managedBy",
    "whenCreated",
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
    base: str,
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
        base: the DN to search under.
        search_filter: a raw LDAP filter.
        limit: max number of entries (0 = no limit).
        attributes: attributes to fetch (None = all attributes).

    Returns:
        A list of entries, each a dict of attribute name -> value(s).
    """
    effective_attributes = attributes if attributes else ldap3.ALL_ATTRIBUTES

    resultgenerator = conn.extend.standard.paged_search(
        base, search_filter, size_limit=limit, attributes=effective_attributes
    )
    result = list(resultgenerator)
    entries = [r["attributes"] for r in result if "dn" in r]
    logging.debug(entries)
    return entries


def users(
    conn: LdapConnection,
    base: str,
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
    return search(conn, base, search_filter, limit=limit, attributes=attributes)


def find_users(
    conn: LdapConnection,
    base: str,
    *,
    name: str | None = None,
    surname: str | None = None,
    mail: str | None = None,
    sam: str | None = None,
    department: str | None = None,
    city: str | None = None,
    state: str | None = None,
    country: str | None = None,
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
        city: matches ``l`` (office city).
        state: matches ``st`` (state/province).
        country: matches ``co`` (country name, as typed; distinct from the
            2-letter ``c`` attribute).

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
        ("l", city),
        ("st", state),
        ("co", country),
    ):
        if value:
            clauses.append(f"({attr}={escape_pattern(value)})")

    inner = "".join(clauses)
    search_filter = f"(&(objectClass=user)(objectCategory=person){inner})"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )


def get_user(
    conn: LdapConnection,
    base: str,
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
        base,
        search_filter,
        limit=1,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )
    return result[0] if result else None


def find_computers(
    conn: LdapConnection,
    base: str,
    *,
    name: str | None = None,
    dns: str | None = None,
    os: str | None = None,
    exclude_domain_controllers: bool = False,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find computers by one or more specific fields (all ANDed together).

    Each provided criterion is matched independently; values may contain
    ``*`` wildcards. Passing no criteria matches all computers.

    Args:
        name: matches ``cn`` (computer name).
        dns: matches ``dNSHostName`` (FQDN).
        os: matches ``operatingSystem``.
        exclude_domain_controllers: if True, excludes domain controllers
            (``primaryGroupID=516``) from the results.

    Returns:
        A list of matching computer entries (default attributes if none given).
    """
    clauses: list[str] = []
    for attr, value in (
        ("cn", name),
        ("dNSHostName", dns),
        ("operatingSystem", os),
    ):
        if value:
            clauses.append(f"({attr}={escape_pattern(value)})")
    if exclude_domain_controllers:
        clauses.append("(!(primaryGroupID=516))")

    inner = "".join(clauses)
    search_filter = f"(&(objectClass=computer){inner})"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_COMPUTER_ATTRIBUTES,
    )


def get_computer(
    conn: LdapConnection,
    base: str,
    identifier: str,
    attributes: Attributes = None,
) -> LdapEntry | None:
    """Return a single computer matched by sAMAccountName, cn or dNSHostName.

    Uses an exact match. The machine ``sAMAccountName`` ends with ``$``; if the
    identifier does not, both forms are tried, so ``PC001`` matches ``PC001$``.
    Returns the first match, or None if no computer is found.
    """
    value = escape_exact(identifier)
    sam = value if identifier.endswith("$") else f"{value}$"
    search_filter = (
        f"(&(objectClass=computer)(|(sAMAccountName={sam})(cn={value})(dNSHostName={value})))"
    )
    result = search(
        conn,
        base,
        search_filter,
        limit=1,
        attributes=attributes or DEFAULT_COMPUTER_ATTRIBUTES,
    )
    return result[0] if result else None


def get_by_dn(
    conn: LdapConnection,
    dn: str,
    attributes: Attributes = None,
) -> LdapEntry | None:
    """Fetch a single entry directly by its distinguished name (DN).

    This is the most efficient lookup: the DN is used as the search base with
    a catch-all filter, so the server returns exactly that object (or nothing).
    Handy to resolve DN-valued attributes such as ``manager`` (users) or
    ``managedBy`` (groups) into full records.

    Args:
        conn: a bound ldap3 connection.
        dn: the distinguished name of the entry to fetch.
        attributes: attributes to fetch (None = all attributes).

    Returns:
        The entry as a dict of attribute name -> value(s), or None if the DN
        does not exist (or is malformed).
    """
    try:
        result = search(conn, dn, "(objectClass=*)", limit=1, attributes=attributes)
    except LDAPExceptionError as exc:
        # e.g. the DN does not exist (noSuchObject) or is syntactically invalid.
        logging.debug("get_by_dn(%r) failed: %s", dn, exc)
        return None
    return result[0] if result else None


def find_ous(
    conn: LdapConnection,
    base: str,
    *,
    name: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find organizational units (OUs).

    Args:
        base: the DN to search under (whole domain by default, or a parent OU).
        name: matches ``ou`` (the OU name); may contain ``*`` wildcards.
            Passing no name matches all OUs.

    Returns:
        A list of matching OU entries (default attributes if none given).
    """
    inner = f"(ou={escape_pattern(name)})" if name else ""
    search_filter = f"(&(objectClass=organizationalUnit){inner})"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_OU_ATTRIBUTES,
    )


def find_empty_ous(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find organizational units that have no nested sub-OU.

    Matches ``(!(ou=*))``. A common hygiene/audit check, analogous to
    :func:`list_empty_groups`. Note this only checks for nested OUs, not for
    leaf objects (users, computers, groups) directly inside the OU.

    Returns:
        A list of matching OU entries (default OU attributes if none given).
    """
    search_filter = "(&(objectCategory=organizationalUnit)(!(ou=*)))"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_OU_ATTRIBUTES,
    )


def get_ou(
    conn: LdapConnection,
    base: str,
    identifier: str,
    attributes: Attributes = None,
) -> LdapEntry | None:
    """Return a single OU matched by its ``ou`` name or full DN (exact match).

    Returns the first match, or None if no OU is found.
    """
    value = escape_exact(identifier)
    search_filter = f"(&(objectClass=organizationalUnit)(|(ou={value})(distinguishedName={value})))"
    result = search(
        conn,
        base,
        search_filter,
        limit=1,
        attributes=attributes or DEFAULT_OU_ATTRIBUTES,
    )
    return result[0] if result else None


def get_ou_contents(
    conn: LdapConnection,
    ou_dn: str,
    *,
    object_class: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List the objects contained under an OU (using the OU DN as search base).

    Args:
        ou_dn: the distinguished name of the OU whose contents to list.
        object_class: restrict to a single ``objectClass`` (e.g. ``user``,
            ``group``, ``computer``, ``organizationalUnit``). None returns
            every object under the OU.

    Returns:
        A list of entries below the OU, or an empty list if the OU does not
        exist (or the DN is malformed).
    """
    cls = escape_exact(object_class) if object_class else "*"
    search_filter = f"(objectClass={cls})"
    try:
        return search(conn, ou_dn, search_filter, limit=limit, attributes=attributes)
    except LDAPExceptionError as exc:
        logging.debug("get_ou_contents(%r) failed: %s", ou_dn, exc)
        return []


#: Offset in seconds between the Windows FILETIME epoch (1601-01-01) and the
#: Unix epoch (1970-01-01).
_FILETIME_EPOCH_OFFSET = 11644473600


def _days_ago_filetime(days: int) -> int:
    """Return the Windows FILETIME for ``now - days``.

    AD stores ``lastLogonTimestamp`` (and similar) as FILETIME: the number of
    100-nanosecond intervals since 1601-01-01 UTC. LDAP range filters must use
    this integer form, so we convert a day-based cutoff here.
    """
    cutoff = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)
    unix_seconds = cutoff.timestamp()
    return int((unix_seconds + _FILETIME_EPOCH_OFFSET) * 10_000_000)


def _days_ago_generalized_time(days: int) -> str:
    """Return the LDAP generalized-time string for ``now - days``.

    ``whenChanged``/``whenCreated`` use the generalized-time syntax
    (``YYYYMMDDHHMMSS.0Z``), unlike the FILETIME integers used by
    ``lastLogonTimestamp``/``pwdLastSet``/``accountExpires``.
    """
    cutoff = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)
    return cutoff.strftime("%Y%m%d%H%M%S.0Z")


def find_recently_modified(
    conn: LdapConnection,
    base: str,
    *,
    days: int = 7,
    object_class: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find objects whose ``whenChanged`` is within the last ``days`` days.

    Useful for a "what changed recently in AD" audit. Pass ``object_class``
    (e.g. ``"user"``, ``"group"``, ``"computer"``) to restrict to one object
    type; omit it to match any object.

    Returns:
        A list of matching entries (all attributes if none given).
    """
    cutoff = _days_ago_generalized_time(days)
    class_filter = f"(objectClass={escape_exact(object_class)})" if object_class else ""
    search_filter = f"(&{class_filter}(whenChanged>={cutoff}))"
    return search(conn, base, search_filter, limit=limit, attributes=attributes)


def find_recently_created(
    conn: LdapConnection,
    base: str,
    *,
    days: int = 7,
    object_class: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find objects whose ``whenCreated`` is within the last ``days`` days.

    Pass ``object_class`` (e.g. ``"user"``, ``"group"``, ``"computer"``) to
    restrict to one object type; omit it to match any object.

    Returns:
        A list of matching entries (all attributes if none given).
    """
    cutoff = _days_ago_generalized_time(days)
    class_filter = f"(objectClass={escape_exact(object_class)})" if object_class else ""
    search_filter = f"(&{class_filter}(whenCreated>={cutoff}))"
    return search(conn, base, search_filter, limit=limit, attributes=attributes)


def find_inactive_users(
    conn: LdapConnection,
    base: str,
    *,
    days: int = 90,
    include_never: bool = False,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find enabled users whose last logon is older than ``days`` days.

    Matches users whose ``lastLogonTimestamp`` is at or before the cutoff.

    Args:
        base: the DN to search under (whole domain by default, or an OU).
        days: inactivity threshold in days (default 90).
        include_never: also return users that have never logged on (no
            ``lastLogonTimestamp`` attribute). Defaults to False.

    Returns:
        A list of matching user entries (default attributes if none given).
    """
    cutoff = _days_ago_filetime(days)
    stale = f"(lastLogonTimestamp<={cutoff})"
    if include_never:
        stale = f"(|{stale}(!(lastLogonTimestamp=*)))"
    search_filter = f"(&(objectClass=user)(objectCategory=person){stale})"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )


def find_stale_computers(
    conn: LdapConnection,
    base: str,
    *,
    days: int = 90,
    include_never: bool = False,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find computers whose last logon is older than ``days`` days.

    Matches computers whose ``lastLogonTimestamp`` is at or before the cutoff.

    Args:
        base: the DN to search under (whole domain by default, or an OU).
        days: staleness threshold in days (default 90).
        include_never: also return computers that have never logged on (no
            ``lastLogonTimestamp`` attribute). Defaults to False.

    Returns:
        A list of matching computer entries (default attributes if none given).
    """
    cutoff = _days_ago_filetime(days)
    stale = f"(lastLogonTimestamp<={cutoff})"
    if include_never:
        stale = f"(|{stale}(!(lastLogonTimestamp=*)))"
    search_filter = f"(&(objectClass=computer){stale})"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_COMPUTER_ATTRIBUTES,
    )


def get_dn(conn: LdapConnection, base: str, entry: str) -> str | None:
    """Resolve an sAMAccountName (or DN) to a distinguished name.

    Returns the DN unchanged if ``entry`` already looks like a DN
    (starts with ``cn=``), otherwise looks it up. Returns None if not found.
    """
    if entry.lower().startswith("cn="):
        return entry
    search_filter = f"(sAMAccountName={escape_exact(entry)})"
    result = search(conn, base, search_filter, attributes=["distinguishedName"])
    logging.debug(result)
    if len(result) < 1:
        logging.error(f"entry {entry} not found")
        return None

    return result[0]["distinguishedName"]


def never_expires_password(
    conn: LdapConnection,
    base: str,
    extra_filter: str = "",
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Search users whose password never expires (UAC flag 65536)."""
    search_filter = (
        f"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536){extra_filter})"
    )
    return search(conn, base, search_filter, limit=limit, attributes=attributes)


def disabled_users(
    conn: LdapConnection,
    base: str,
    extra_filter: str = "",
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Search disabled user accounts (UAC flag 2)."""
    search_filter = (
        f"(&(objectCategory=Person)(objectClass=User){extra_filter}"
        f"(userAccountControl:1.2.840.113556.1.4.803:=2))"
    )
    return search(conn, base, search_filter, limit=limit, attributes=attributes)


def locked_users(
    conn: LdapConnection,
    base: str,
    extra_filter: str = "",
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Search locked-out user accounts (lockoutTime >= 1)."""
    search_filter = f"(&(objectCategory=Person)(objectClass=User){extra_filter}(lockoutTime>=1))"
    return search(conn, base, search_filter, attributes=attributes)


def list_domain_controllers(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List the domain controllers (computer accounts that are DCs).

    Matches computer objects with the ``SERVER_TRUST_ACCOUNT`` userAccountControl
    flag (0x2000 = 8192), which is set on domain controllers.

    Returns:
        A list of DC computer entries (default computer attributes if none given).
    """
    search_filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_COMPUTER_ATTRIBUTES,
    )


def list_empty_groups(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List groups that have no direct members (``(!(member=*))``).

    A common hygiene/audit check. Note that a group with only *nested* members
    via ``memberOf`` elsewhere still counts as empty here if its own ``member``
    attribute is unset.

    Returns:
        A list of empty-group entries (default group attributes if none given).
    """
    search_filter = "(&(objectClass=group)(!(member=*)))"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_GROUP_ATTRIBUTES,
    )


#: groupType bit flags (see MS-ADTS); combined with the
#: LDAP_MATCHING_RULE_BIT_AND matching rule (1.2.840.113556.1.4.803).
_GROUP_TYPE_SECURITY_ENABLED = 2147483648
_GROUP_TYPE_GLOBAL = 2
_GROUP_TYPE_DOMAIN_LOCAL = 4
_GROUP_TYPE_UNIVERSAL = 8

_GROUP_SCOPE_BITS = {
    "global": _GROUP_TYPE_GLOBAL,
    "domain_local": _GROUP_TYPE_DOMAIN_LOCAL,
    "universal": _GROUP_TYPE_UNIVERSAL,
}


def find_security_groups(
    conn: LdapConnection,
    base: str,
    *,
    scope: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find security-enabled groups (as opposed to distribution groups).

    Uses the ``groupType`` bit-AND matching rule
    (``LDAP_MATCHING_RULE_BIT_AND``) to find any security group regardless of
    scope, optionally narrowed to one scope.

    Args:
        scope: restrict to one scope: ``"global"``, ``"domain_local"`` or
            ``"universal"``. None (default) returns security groups of any
            scope.

    Returns:
        A list of matching group entries (default group attributes if none given).
    """
    bits = _GROUP_TYPE_SECURITY_ENABLED
    if scope:
        try:
            bits |= _GROUP_SCOPE_BITS[scope]
        except KeyError:
            raise ValueError(
                f"Invalid scope {scope!r}, expected one of {sorted(_GROUP_SCOPE_BITS)}"
            ) from None
    search_filter = f"(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:={bits}))"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_GROUP_ATTRIBUTES,
    )


def find_distribution_groups(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find distribution groups (as opposed to security-enabled groups).

    Complement of :func:`find_security_groups`: matches groups that do NOT
    have the security-enabled ``groupType`` bit set, using the ``groupType``
    bit-AND matching rule (``LDAP_MATCHING_RULE_BIT_AND``).

    Returns:
        A list of matching group entries (default group attributes if none given).
    """
    search_filter = (
        "(&(objectClass=group)"
        f"(!(groupType:1.2.840.113556.1.4.803:={_GROUP_TYPE_SECURITY_ENABLED})))"
    )
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_GROUP_ATTRIBUTES,
    )


def find_contacts(
    conn: LdapConnection,
    base: str,
    string: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find contact objects (``objectClass=contact``).

    Args:
        string: matches ``cn``, ``mail`` or ``displayName``; may contain
            ``*`` wildcards. Passing None matches all contacts.

    Returns:
        A list of matching contact entries.
    """
    inner = ""
    if string:
        value = escape_pattern(string)
        inner = f"(|(cn={value})(mail={value})(displayName={value}))"
    search_filter = f"(&(objectClass=contact){inner})"
    return search(conn, base, search_filter, limit=limit, attributes=attributes)


def find_password_not_required(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find user accounts with the risky ``PASSWD_NOTREQD`` UAC flag (32).

    These accounts may have no password at all, allowing anyone to
    authenticate as them and set their own password. A common hygiene/
    security-audit check.

    Returns:
        A list of matching user entries (default attributes if none given).
    """
    search_filter = (
        "(&(objectCategory=person)(objectClass=user)"
        "(userAccountControl:1.2.840.113556.1.4.803:=32))"
    )
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )


def find_kerberos_preauth_not_required(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find user accounts that do NOT require Kerberos pre-authentication.

    Matches the ``DONT_REQ_PREAUTH`` UAC flag (4194304). These accounts are
    vulnerable to offline (AS-REP roasting) password-guessing attacks.

    Returns:
        A list of matching user entries (default attributes if none given).
    """
    search_filter = (
        "(&(objectCategory=person)(objectClass=user)"
        "(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    )
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )


def find_not_delegated(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find accounts flagged \"sensitive and cannot be delegated\".

    Matches the ``NOT_DELEGATED`` UAC flag (1048576). These accounts carry a
    sensitive privilege but were explicitly excluded from Kerberos
    delegation; a mismatch between the two is worth auditing.

    Returns:
        A list of matching user entries (default attributes if none given).
    """
    search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=1048576)"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )


def find_service_accounts(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find user accounts with a Service Principal Name (SPN) set.

    Matches ``servicePrincipalName=*``. Any account with an SPN can have a
    Kerberos service ticket requested for it by any authenticated user, then
    cracked offline ("Kerberoasting") if its password is weak. A common
    hygiene/security-audit check.

    Returns:
        A list of matching user entries (default attributes if none given).
    """
    search_filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )


def find_admin_count_accounts(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find user accounts with ``adminCount=1`` (protected-admin marker).

    AD sets ``adminCount=1`` on accounts that are (or were) members of a
    protected group such as Domain Admins or Enterprise Admins, via the
    AdminSDHolder process, and does not automatically clear it once the
    account is later removed from every such group. Accounts that still
    carry ``adminCount=1`` but are no longer privileged keep a
    non-inherited, hardened ACL and are a common, easily-overlooked
    audit finding. Cross-reference against
    :func:`msad.audit.get_privileged_groups` members to find the stale ones.

    Returns:
        A list of matching user entries (default attributes if none given).
    """
    search_filter = "(&(objectCategory=person)(objectClass=user)(adminCount=1))"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )


def find_must_change_password(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find enabled users who must change their password at next logon.

    Matches ``pwdLastSet=0``, excluding disabled accounts (UAC flag 2). This
    is a standalone check independent of the domain password policy; compare
    with :func:`msad.audit.get_password_policy_violations`, which only
    flags ``pwdLastSet=0`` accounts together with actual password-age
    violations (and requires the domain to have a ``maxPwdAge``).

    Returns:
        A list of matching user entries (default attributes if none given).
    """
    search_filter = (
        "(&(objectCategory=person)(objectClass=user)(pwdLastSet=0)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    )
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )


def find_users_without_email(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find user accounts with no ``mail`` attribute set.

    A data-quality/hygiene check: accounts without an email address often
    can't receive password-expiry notices, MFA prompts or other automated
    notifications.

    Returns:
        A list of matching user entries (default attributes if none given).
    """
    search_filter = "(&(objectCategory=person)(objectClass=user)(!(mail=*)))"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )


def find_never_expiring_accounts(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find user accounts whose ACCOUNT (not password) never expires.

    Matches ``accountExpires`` set to ``0`` or ``9223372036854775807``
    (the two sentinel values AD uses for "never"). This is distinct from
    :func:`never_expires_password`, which checks the password-never-expires
    UAC flag instead.

    Returns:
        A list of matching user entries (default attributes if none given).
    """
    search_filter = (
        "(&(objectCategory=person)(objectClass=user)"
        "(|(accountExpires=0)(accountExpires=9223372036854775807)))"
    )
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )


def find_expired_accounts(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """Find user accounts whose ``accountExpires`` date is in the past.

    Excludes the two "never expire" sentinel values (``0`` and
    ``9223372036854775807``); the account must have an actual expiration
    timestamp at or before now.

    Returns:
        A list of matching user entries (default attributes if none given).
    """
    cutoff = _days_ago_filetime(0)
    search_filter = (
        "(&(objectCategory=person)(objectClass=user)"
        f"(accountExpires<={cutoff})"
        "(!(accountExpires=0))(!(accountExpires=9223372036854775807)))"
    )
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_USER_ATTRIBUTES,
    )


def summarize_computer_os(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
) -> list[dict[str, object]]:
    """Summarize computer accounts grouped by ``operatingSystem``.

    Reads every computer's ``operatingSystem`` and counts them in-process.

    Returns:
        A list of ``{"operatingSystem": <name>, "count": <n>}`` dicts, sorted by
        descending count. Computers with no ``operatingSystem`` are reported
        under the name ``"(unknown)"``.
    """
    entries = search(
        conn,
        base,
        "(objectClass=computer)",
        limit=limit,
        attributes=["operatingSystem"],
    )
    counts: dict[str, int] = {}
    for entry in entries:
        os_value = entry.get("operatingSystem") or "(unknown)"
        if isinstance(os_value, list):
            os_value = os_value[0] if os_value else "(unknown)"
        counts[os_value] = counts.get(os_value, 0) + 1
    return [
        {"operatingSystem": name, "count": count}
        for name, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    ]
