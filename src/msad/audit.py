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
from typing import Any

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


def get_site(
    conn: LdapConnection,
    base: str,
    identifier: str,
    *,
    config_base: str | None = None,
    attributes: Attributes = None,
) -> LdapEntry | None:
    """Return a single AD site matched by its ``cn`` (name).

    Sites live under ``CN=Sites,CN=Configuration,<forest root>``. Uses an exact
    match on ``cn``. For a single-domain forest the Configuration NC is derived
    from ``base``; pass ``config_base`` explicitly for a multi-domain forest.

    Returns:
        The site's attributes as a dict, or None if not found.
    """
    config = config_base or _configuration_nc(base)
    sites = f"CN=Sites,{config}"
    search_filter = f"(&(objectClass=site)(cn={escape_exact(identifier)}))"
    try:
        result = search(
            conn,
            sites,
            search_filter,
            limit=1,
            attributes=attributes or DEFAULT_SITE_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("get_site(%r): cannot read %r: %s", identifier, sites, exc)
        return None
    return result[0] if result else None


#: Attributes worth surfacing for each AD subnet.
DEFAULT_SUBNET_ATTRIBUTES = [
    "cn",
    "siteObject",
    "location",
    "description",
    "whenCreated",
    "distinguishedName",
]


def list_subnets(
    conn: LdapConnection,
    base: str,
    *,
    config_base: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List the AD subnets (``objectClass=subnet``) from the Configuration NC.

    Subnets live under ``CN=Subnets,CN=Sites,CN=Configuration,<forest root>``.
    Each subnet's ``cn`` is its network prefix in CIDR form (e.g.
    ``10.20.0.0/16``) and ``siteObject`` is the DN of the AD site it is
    associated with. For a single-domain forest the Configuration NC is derived
    from ``base``; pass ``config_base`` explicitly for a multi-domain forest.

    Returns:
        A list of subnet entries (default attributes if none given). Empty if
        the Subnets container cannot be read.
    """
    config = config_base or _configuration_nc(base)
    subnets = f"CN=Subnets,CN=Sites,{config}"
    try:
        return search(
            conn,
            subnets,
            "(objectClass=subnet)",
            limit=limit,
            attributes=attributes or DEFAULT_SUBNET_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("list_subnets: cannot read %r: %s", subnets, exc)
        return []


def get_subnet(
    conn: LdapConnection,
    base: str,
    identifier: str,
    *,
    config_base: str | None = None,
    attributes: Attributes = None,
) -> LdapEntry | None:
    """Return a single AD subnet matched by its ``cn`` (CIDR prefix).

    Subnets live under ``CN=Subnets,CN=Sites,CN=Configuration,<forest root>``;
    the ``cn`` is the network prefix in CIDR form (e.g. ``10.20.0.0/16``). Uses
    an exact match. For a single-domain forest the Configuration NC is derived
    from ``base``; pass ``config_base`` explicitly for a multi-domain forest.

    Returns:
        The subnet's attributes as a dict (including ``siteObject``), or None if
        not found.
    """
    config = config_base or _configuration_nc(base)
    subnets = f"CN=Subnets,CN=Sites,{config}"
    search_filter = f"(&(objectClass=subnet)(cn={escape_exact(identifier)}))"
    try:
        result = search(
            conn,
            subnets,
            search_filter,
            limit=1,
            attributes=attributes or DEFAULT_SUBNET_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("get_subnet(%r): cannot read %r: %s", identifier, subnets, exc)
        return None
    return result[0] if result else None


#: Attributes worth surfacing for each site link.
DEFAULT_SITE_LINK_ATTRIBUTES = [
    "cn",
    "description",
    "cost",
    "replInterval",
    "siteList",
    "whenCreated",
    "distinguishedName",
]


def list_site_links(
    conn: LdapConnection,
    base: str,
    *,
    config_base: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List AD site links (``objectClass=siteLink``) from the Configuration NC.

    Site links live under ``CN=Inter-Site Transports,CN=Sites,CN=Configuration,
    <forest root>`` (typically in the ``CN=IP`` transport). Each link's
    ``siteList`` is the list of site DNs it connects, ``cost`` and
    ``replInterval`` drive inter-site replication topology. For a single-domain
    forest the Configuration NC is derived from ``base``; pass ``config_base``
    explicitly for a multi-domain forest.

    Returns:
        A list of site-link entries (default attributes if none given). Empty if
        the Inter-Site Transports container cannot be read.
    """
    config = config_base or _configuration_nc(base)
    transports = f"CN=Inter-Site Transports,CN=Sites,{config}"
    try:
        return search(
            conn,
            transports,
            "(objectClass=siteLink)",
            limit=limit,
            attributes=attributes or DEFAULT_SITE_LINK_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("list_site_links: cannot read %r: %s", transports, exc)
        return []


#: Attributes worth surfacing for each directory server (DC) object.
DEFAULT_SERVER_ATTRIBUTES = [
    "cn",
    "dNSHostName",
    "serverReference",
    "whenCreated",
    "distinguishedName",
]


def list_servers(
    conn: LdapConnection,
    base: str,
    *,
    config_base: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List directory servers (``objectClass=server``) from the Configuration NC.

    Server objects live under ``CN=Servers`` of each site, below
    ``CN=Sites,CN=Configuration,<forest root>``. This is the site-centric view
    of the forest's domain controllers: the parent of each ``server`` object is
    its AD site, and ``serverReference`` links to the DC's computer object. For
    a single-domain forest the Configuration NC is derived from ``base``; pass
    ``config_base`` explicitly for a multi-domain forest.

    Returns:
        A list of server entries (default attributes if none given). Empty if
        the Sites container cannot be read.
    """
    config = config_base or _configuration_nc(base)
    sites = f"CN=Sites,{config}"
    try:
        return search(
            conn,
            sites,
            "(objectClass=server)",
            limit=limit,
            attributes=attributes or DEFAULT_SERVER_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("list_servers: cannot read %r: %s", sites, exc)
        return []


#: Attributes surfaced for each replication connection (``nTDSConnection``).
DEFAULT_REPLICATION_CONNECTION_ATTRIBUTES = [
    "cn",
    "fromServer",
    "enabledConnection",
    "options",
    "transportType",
    "whenCreated",
    "whenChanged",
    "distinguishedName",
]

#: ``nTDSConnection.options`` bit 0: connection generated by the KCC.
_NTDSCONN_OPT_IS_GENERATED = 0x1


def _first(value: object) -> object:
    """Unwrap a single-valued attribute that ldap3 may return as a list."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _rdn_values(dn: object) -> list[str]:
    """Return the RDN values of a DN (naive split, fine for AD config DNs)."""
    if not isinstance(dn, str):
        return []
    return [part.split("=", 1)[1] for part in dn.split(",") if "=" in part]


def _decode_replication_connection(entry: LdapEntry, dn: object) -> LdapEntry:
    """Add ``source_dc``/``destination_dc``/``site`` etc. to a connection entry.

    A connection DN looks like
    ``CN=<guid>,CN=NTDS Settings,CN=<DEST>,CN=Servers,CN=<SITE>,CN=Sites,...``
    and ``fromServer`` like ``CN=NTDS Settings,CN=<SRC>,CN=Servers,CN=<SITE>,...``.
    """
    out = dict(entry)
    parts = _rdn_values(dn)
    if len(parts) > 4:
        out["destination_dc"] = parts[2]
        out["site"] = parts[4]
    src = _rdn_values(_first(entry.get("fromServer")))
    if len(src) > 3:
        out["source_dc"] = src[1]
        out["source_site"] = src[3]
    options = _first(entry.get("options"))
    if isinstance(options, int):
        out["kcc_generated"] = bool(options & _NTDSCONN_OPT_IS_GENERATED)
    return out


def list_replication_connections(
    conn: LdapConnection,
    base: str,
    *,
    config_base: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List the AD replication topology (``nTDSConnection`` objects).

    Each connection is an inbound replication link under a DC's
    ``CN=NTDS Settings``. Entries are enriched with decoded companions:
    ``destination_dc``, ``site``, ``source_dc``, ``source_site`` and
    ``kcc_generated`` (False = manually created). The ``distinguishedName``
    attribute is always fetched so the decoding works.

    This is topology, not live status: it shows who replicates from whom, not
    sync success or lag (that needs the DC's replication metadata, which is not
    readable through a plain LDAP search).

    Returns:
        A list of connection entries; empty if the Sites container is unreadable.
    """
    config = config_base or _configuration_nc(base)
    sites = f"CN=Sites,{config}"
    attrs = list(attributes or DEFAULT_REPLICATION_CONNECTION_ATTRIBUTES)
    for needed in ("distinguishedName", "fromServer", "options"):
        if needed not in attrs:
            attrs.append(needed)
    try:
        entries = search(conn, sites, "(objectClass=nTDSConnection)", limit=limit, attributes=attrs)
    except LDAPExceptionError as exc:
        logging.debug("list_replication_connections: cannot read %r: %s", sites, exc)
        return []
    return [_decode_replication_connection(e, _first(e.get("distinguishedName"))) for e in entries]


#: Attributes surfaced for replication-conflict objects.
DEFAULT_REPLICATION_CONFLICT_ATTRIBUTES = [
    "name",
    "objectClass",
    "whenCreated",
    "whenChanged",
    "distinguishedName",
]


def list_replication_conflicts(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List replication-conflict objects (names containing ``\\nCNF:<guid>``).

    When two DCs create the same name concurrently, AD renames the loser to
    ``<name>\\0ACNF:<guid>``. These are a classic sign of replication problems
    and should be reviewed and cleaned up.

    Returns:
        A list of conflict entries under ``base``.
    """
    search_filter = "(|(cn=*\\0aCNF:*)(ou=*\\0aCNF:*)(name=*\\0aCNF:*))"
    return search(
        conn,
        base,
        search_filter,
        limit=limit,
        attributes=attributes or DEFAULT_REPLICATION_CONFLICT_ATTRIBUTES,
    )


def first_look(
    conn: LdapConnection,
    base: str,
    *,
    config_base: str | None = None,
) -> LdapEntry:
    """One-call health/inventory overview of the forest/domain.

    Gathers domain info, password policy, FSMO owners, DCs, sites, trusts,
    replication connections and conflicts into a single dict. Each section is
    collected independently: a section that cannot be read is ``None`` (with an
    entry in ``errors``) instead of failing the whole call.

    Returns:
        A dict with ``domain``, ``password_policy``, ``fsmo_roles``,
        ``domain_controllers``, ``sites``, ``trusts``, ``replication_connections``,
        ``replication_conflicts`` (up to 50 listed, with the full count in
        ``summary``), ``summary`` (counts and warnings) and ``errors``.
    """
    from .search import list_domain_controllers

    errors: dict[str, str] = {}

    def collect(name: str, fn: Any) -> Any:
        try:
            return fn()
        except LDAPExceptionError as exc:
            errors[name] = str(exc)
            return None

    domain = collect("domain", lambda: get_domain_info(conn, base))
    policy = collect("password_policy", lambda: get_password_policy(conn, base))
    fsmo = collect("fsmo_roles", lambda: list_fsmo_roles(conn, base, config_base=config_base))
    dcs = collect(
        "domain_controllers",
        lambda: list_domain_controllers(
            conn, base, attributes=["name", "dNSHostName", "operatingSystem", "distinguishedName"]
        ),
    )
    sites = collect("sites", lambda: list_sites(conn, base, config_base=config_base))
    trusts = collect("trusts", lambda: list_trusts(conn, base))
    conns = collect(
        "replication_connections",
        lambda: list_replication_connections(conn, base, config_base=config_base),
    )
    conflicts = collect(
        "replication_conflicts", lambda: list_replication_conflicts(conn, base, limit=50)
    )

    warnings: list[str] = []
    if conflicts:
        warnings.append(f"{len(conflicts)} replication conflict object(s) found")
    if fsmo is not None and len(fsmo) < len(_FSMO_ROLES):
        warnings.append("some FSMO roles could not be read")
    if conns is not None and any(c.get("enabledConnection") is False for c in conns):
        warnings.append("one or more replication connections are disabled")

    def count(x: Any) -> int | None:
        return None if x is None else len(x)

    return {
        "domain": domain,
        "password_policy": policy,
        "fsmo_roles": fsmo,
        "domain_controllers": dcs,
        "sites": sites,
        "trusts": trusts,
        "replication_connections": conns,
        "replication_conflicts": conflicts,
        "summary": {
            "domain_controllers": count(dcs),
            "sites": count(sites),
            "trusts": count(trusts),
            "replication_connections": count(conns),
            "replication_conflicts": count(conflicts),
            "warnings": warnings,
        },
        "errors": errors,
    }


#: Attributes worth surfacing for each AD-integrated DNS zone.
DEFAULT_DNS_ZONE_ATTRIBUTES = [
    "name",
    "dc",
    "whenCreated",
    "whenChanged",
    "distinguishedName",
]


def list_dns_zones(
    conn: LdapConnection,
    base: str,
    *,
    zone_base: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List AD-integrated DNS zones (``objectClass=dnsZone``).

    For AD-integrated DNS, zones are stored as LDAP objects in the application
    partition ``DC=DomainDnsZones,<base>`` (and legacy zones under
    ``CN=MicrosoftDNS,CN=System,<base>``). This queries ``DC=DomainDnsZones,
    <base>`` by default; pass ``zone_base`` to target the forest-wide partition
    (``DC=ForestDnsZones,<forest root>``) or the legacy System container.

    Note: only AD-integrated zones live in the directory. File-backed zones are
    not visible over LDAP.

    Returns:
        A list of DNS-zone entries (default attributes if none given). Empty if
        the partition cannot be read.
    """
    zones = zone_base or f"DC=DomainDnsZones,{base}"
    try:
        return search(
            conn,
            zones,
            "(objectClass=dnsZone)",
            limit=limit,
            attributes=attributes or DEFAULT_DNS_ZONE_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("list_dns_zones: cannot read %r: %s", zones, exc)
        return []


#: Attributes worth surfacing for each DNS resource-record node.
DEFAULT_DNS_RECORD_ATTRIBUTES = [
    "name",
    "dnsRecord",
    "dc",
    "whenChanged",
    "distinguishedName",
]


def list_dns_records(
    conn: LdapConnection,
    base: str,
    zone: str,
    *,
    zone_base: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List the DNS records (``objectClass=dnsNode``) of an AD-integrated zone.

    Each ``dnsNode`` under the zone holds one or more binary ``dnsRecord``
    values (the DNS_RPC_RECORD blob). The raw bytes are returned as-is; decode
    them with :func:`msad.decode.decode_dns_records` (or run the whole result
    set through :func:`msad.decode.decode_entries`, which adds a
    ``dnsRecord_decoded`` companion key).

    Args:
        base: the domain naming context DN, used to locate the default zone
            partition ``DC=DomainDnsZones,<base>``.
        zone: the DNS zone name (e.g. ``example.com``); it becomes the
            ``DC=<zone>`` search base within the partition.
        zone_base: override the partition holding the zone (e.g.
            ``DC=ForestDnsZones,<forest root>`` or the legacy
            ``CN=MicrosoftDNS,CN=System,<base>``).

    Returns:
        A list of ``dnsNode`` entries (default attributes if none given). Empty
        if the zone cannot be read.
    """
    partition = zone_base or f"DC=DomainDnsZones,{base}"
    zone_dn = f"DC={zone},{partition}"
    try:
        return search(
            conn,
            zone_dn,
            "(objectClass=dnsNode)",
            limit=limit,
            attributes=attributes or DEFAULT_DNS_RECORD_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("list_dns_records: cannot read %r: %s", zone_dn, exc)
        return []


#: Attributes worth surfacing for each authorized DHCP server.
DEFAULT_DHCP_SERVER_ATTRIBUTES = [
    "cn",
    "dhcpServers",
    "dhcpIdentification",
    "whenCreated",
    "distinguishedName",
]


def list_authorized_dhcp_servers(
    conn: LdapConnection,
    base: str,
    *,
    config_base: str | None = None,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List DHCP servers authorized in AD (``objectClass=dHCPClass``).

    DHCP authorization objects live under ``CN=NetServices,CN=Services,
    CN=Configuration,<forest root>``. This reflects only which DHCP servers are
    *authorized* in the directory; scopes, pools, leases and reservations are
    held in each DHCP server's own database and are NOT exposed over LDAP. For a
    single-domain forest the Configuration NC is derived from ``base``; pass
    ``config_base`` explicitly for a multi-domain forest.

    Returns:
        A list of authorized-DHCP-server entries (default attributes if none
        given). Empty if the NetServices container cannot be read.
    """
    config = config_base or _configuration_nc(base)
    netservices = f"CN=NetServices,CN=Services,{config}"
    try:
        return search(
            conn,
            netservices,
            "(objectClass=dHCPClass)",
            limit=limit,
            attributes=attributes or DEFAULT_DHCP_SERVER_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("list_authorized_dhcp_servers: cannot read %r: %s", netservices, exc)
        return []


#: Attributes worth surfacing for each DFS namespace root.
DEFAULT_DFS_NAMESPACE_ATTRIBUTES = [
    "cn",
    "description",
    "whenCreated",
    "whenChanged",
    "distinguishedName",
]


def list_dfs_namespaces(
    conn: LdapConnection,
    base: str,
    *,
    limit: int = 0,
    attributes: Attributes = None,
) -> LdapEntries:
    """List domain-based DFS namespace roots (``objectClass=fTDfs``).

    Domain-based DFS namespaces are stored under
    ``CN=Dfs-Configuration,CN=System,<base>``; each namespace root is an
    ``fTDfs`` object whose ``cn`` is the namespace name. The topology/links are
    held in the binary ``pKT`` blob, which this function does not decode.
    Stand-alone (server-based) DFS namespaces are not stored in AD and are not
    visible here.

    Returns:
        A list of DFS namespace entries (default attributes if none given).
        Empty if the Dfs-Configuration container cannot be read.
    """
    container = f"CN=Dfs-Configuration,CN=System,{base}"
    try:
        return search(
            conn,
            container,
            "(objectClass=fTDfs)",
            limit=limit,
            attributes=attributes or DEFAULT_DFS_NAMESPACE_ATTRIBUTES,
        )
    except LDAPExceptionError as exc:
        logging.debug("list_dfs_namespaces: cannot read %r: %s", container, exc)
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
    "DEFAULT_DFS_NAMESPACE_ATTRIBUTES",
    "DEFAULT_DHCP_SERVER_ATTRIBUTES",
    "DEFAULT_DNS_RECORD_ATTRIBUTES",
    "DEFAULT_DNS_ZONE_ATTRIBUTES",
    "DEFAULT_DOMAIN_ATTRIBUTES",
    "DEFAULT_GPO_ATTRIBUTES",
    "DEFAULT_PASSWORD_POLICY_ATTRIBUTES",
    "DEFAULT_PRIVILEGED_GROUPS",
    "DEFAULT_PSO_ATTRIBUTES",
    "DEFAULT_PWD_VIOLATION_ATTRIBUTES",
    "DEFAULT_SERVER_ATTRIBUTES",
    "DEFAULT_SITE_ATTRIBUTES",
    "DEFAULT_SITE_LINK_ATTRIBUTES",
    "DEFAULT_SUBNET_ATTRIBUTES",
    "DEFAULT_TRUST_ATTRIBUTES",
    "escape_exact",
    "get_domain_info",
    "get_gpo",
    "get_password_policy",
    "get_password_policy_violations",
    "get_privileged_groups",
    "get_site",
    "get_subnet",
    "list_authorized_dhcp_servers",
    "list_dfs_namespaces",
    "list_dns_records",
    "list_dns_zones",
    "list_fine_grained_password_policies",
    "list_fsmo_roles",
    "list_gpos",
    "list_servers",
    "list_site_links",
    "list_sites",
    "list_subnets",
    "list_trusts",
]
