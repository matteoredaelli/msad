# msad - Active Directory tool
# Copyright (C) 2025 - matteo.redaelli@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Build and bind ldap3 connections, translating ldap3 errors to MsadError.

Keeping the connection logic in the library (rather than the CLI) lets every
front end -- the CLI, the MCP server, tests -- share the same behaviour and
the same typed error handling.
"""

from __future__ import annotations

import logging
import ssl
from typing import Any

import ldap3
from ldap3.core.exceptions import LDAPExceptionError, LDAPPackageUnavailableError

from .config import DomainConfig
from .exceptions import MsadConnectionError
from .types import LdapConnection


def _build_connection(config: DomainConfig) -> LdapConnection:
    """Create an (unbound) ldap3 Connection from a domain config."""
    # Per-operation receive timeout (seconds); None leaves ldap3's default.
    timeout = config.query_timeout
    if config.uses_kerberos:
        # ``ssl.PROTOCOL_TLSv1_2`` was deprecated in Python 3.10 and removed in
        # 3.14. ``PROTOCOL_TLS_CLIENT`` is the modern replacement: it negotiates
        # the highest protocol both ends support while keeping TLS 1.2 as the
        # effective floor (older protocols are disabled by default), which
        # preserves the original intent across Python 3.11 - 3.14.
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
        server = ldap3.Server(config.host, port=config.port, use_ssl=config.use_ssl, tls=tls)
        return ldap3.Connection(
            server,
            authentication=ldap3.SASL,
            sasl_mechanism=ldap3.KERBEROS,
            auto_bind=False,
            receive_timeout=timeout,
        )

    # user/password bind (both guaranteed present when uses_kerberos is False)
    server = ldap3.Server(config.host, port=config.port, use_ssl=config.use_ssl)
    return ldap3.Connection(
        server,
        user=config.user,
        password=config.password,
        auto_bind=False,
        receive_timeout=timeout,
    )


def connect(config: DomainConfig) -> LdapConnection:
    """Build and bind a connection to the AD server.

    Args:
        config: the resolved domain configuration.

    Returns:
        A bound ldap3 Connection.

    Raises:
        MsadConnectionError: if the connection or bind fails (unreachable
            host, wrong port, TLS problem, bad credentials, ...).
    """
    auth = "Kerberos" if config.uses_kerberos else f"user {config.user!r}"
    scheme = "ldaps" if config.use_ssl else "ldap"
    target = f"{scheme}://{config.host}:{config.port}"

    try:
        conn = _build_connection(config)
        conn.bind()
    except LDAPPackageUnavailableError as exc:
        raise MsadConnectionError(
            "Kerberos authentication requires the optional 'kerberos' extra "
            "(install with `pip install msad[kerberos]` or "
            "`uv tool install 'msad[kerberos]'`). On macOS/Linux this pulls in "
            "'gssapi', which needs the system Kerberos dev headers to build; "
            "on Windows it pulls in 'winkerberos' instead (prebuilt wheel, no "
            f"system headers needed). Original error: {exc}"
        ) from exc
    except LDAPExceptionError as exc:
        raise MsadConnectionError(f"Could not connect to {target} ({auth}): {exc}") from exc

    if not conn.bound:
        # bind() returned False rather than raising: surface the LDAP result.
        detail = getattr(conn, "result", None) or "bind rejected by server"
        raise MsadConnectionError(f"Could not bind to {target} ({auth}): {detail}")

    return conn


def check_connection(config: DomainConfig) -> dict[str, Any]:
    """Test connectivity and bind without raising, returning a status dict.

    Useful for health checks and diagnostics: it attempts a full connect/bind
    and reports the outcome instead of raising.

    Args:
        config: the resolved domain configuration.

    Returns:
        A dict with:
        - ``ok`` (bool): whether the connection and bind succeeded.
        - ``target`` (str): the server URL, e.g. ``ldaps://dc:636``.
        - ``auth`` (str): the authentication method used.
        - ``error`` (str | None): the error message when ``ok`` is False.
    """
    auth = "kerberos" if config.uses_kerberos else f"user {config.user!r}"
    scheme = "ldaps" if config.use_ssl else "ldap"
    target = f"{scheme}://{config.host}:{config.port}"

    try:
        conn = connect(config)
    except MsadConnectionError as exc:
        return {"ok": False, "target": target, "auth": auth, "error": str(exc)}

    try:
        conn.unbind()
    except LDAPExceptionError:
        # Closing the probe connection is best-effort; ignore teardown errors.
        logging.debug("unbind after check_connection failed", exc_info=True)

    return {"ok": True, "target": target, "auth": auth, "error": None}


def whoami(conn: LdapConnection) -> str | None:
    """Return the identity the connection is bound as (RFC 4532 "Who Am I?").

    Works regardless of the authentication method (Kerberos/SASL-GSSAPI or
    simple user/password bind): the directory server reports the identity it
    actually authenticated, which is the authoritative answer, as opposed to
    inspecting the local Kerberos credential cache (``klist``) or the bind
    user configured client-side.

    Returns:
        The ``authzid`` string reported by the server (e.g.
        ``"u:redaema001"`` or ``"dn:CN=...,DC=..."``), or None if the server
        didn't return one (e.g. anonymous bind, or the extended operation is
        unsupported).
    """
    result = conn.extend.standard.who_am_i()
    return result if result else None


#: rootDSE attributes worth surfacing (read anonymously-safe, DC-scoped).
DEFAULT_ROOTDSE_ATTRIBUTES = [
    "dnsHostName",
    "serverName",
    "dsServiceName",
    "ldapServiceName",
    "defaultNamingContext",
    "rootDomainNamingContext",
    "configurationNamingContext",
    "schemaNamingContext",
    "namingContexts",
    "domainFunctionality",
    "forestFunctionality",
    "domainControllerFunctionality",
    "isGlobalCatalogReady",
    "isSynchronized",
    "highestCommittedUSN",
    "currentTime",
    "supportedLDAPVersion",
    "supportedSASLMechanisms",
    "supportedCapabilities",
    "supportedControl",
]

#: AD functional-level numbers (``msDS-Behavior-Version`` values) -> name.
#: Level 7 covers Windows Server 2016 and later (2019/2022 use the same level).
_FUNCTIONAL_LEVELS = {
    0: "Windows 2000",
    1: "Windows Server 2003 interim",
    2: "Windows Server 2003",
    3: "Windows Server 2008",
    4: "Windows Server 2008 R2",
    5: "Windows Server 2012",
    6: "Windows Server 2012 R2",
    7: "Windows Server 2016",
}


def get_rootdse_info(conn: LdapConnection, attributes: list[str] | None = None) -> dict[str, Any]:
    """Read the rootDSE of the domain controller that answers this connection.

    The rootDSE is per-DC (not per-domain): it reports which DC you are talking
    to (``dnsHostName``, ``serverName``), the naming contexts, the domain/forest/
    DC functional levels and the supported controls/capabilities. Adds
    ``*_name`` companions for the three functional levels (e.g.
    ``domainFunctionality_name``).

    Args:
        attributes: attributes to keep (defaults to a curated set).

    Returns:
        The rootDSE attributes as a plain dict (empty if the server returned none).
    """
    wanted = attributes or DEFAULT_ROOTDSE_ATTRIBUTES
    # Ask for everything ("*" + operational "+"): ldap3 validates explicit
    # attribute names against the schema, and many rootDSE attributes are not
    # in it. The selection is applied client-side below.
    conn.search(
        "", "(objectClass=*)", search_scope=ldap3.BASE, attributes=[ldap3.ALL_ATTRIBUTES, "+"]
    )
    response = [r for r in (conn.response or []) if "attributes" in r]
    if not response:
        return {}
    wanted_lc = {w.lower() for w in wanted}
    info: dict[str, Any] = {
        str(k): v for k, v in response[0]["attributes"].items() if str(k).lower() in wanted_lc
    }
    for key in ("domainFunctionality", "forestFunctionality", "domainControllerFunctionality"):
        raw = info.get(key)
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        try:
            level = int(raw) if raw is not None else None
        except (TypeError, ValueError):
            level = None
        if level is not None:
            info[f"{key}_name"] = _FUNCTIONAL_LEVELS.get(level, f"Unknown ({level})")
    return info
