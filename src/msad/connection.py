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
from ldap3.core.exceptions import LDAPExceptionError

from .config import DomainConfig
from .exceptions import MsadConnectionError
from .types import LdapConnection


def _build_connection(config: DomainConfig) -> LdapConnection:
    """Create an (unbound) ldap3 Connection from a domain config."""
    if config.uses_kerberos:
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        server = ldap3.Server(config.host, port=config.port, use_ssl=config.use_ssl, tls=tls)
        return ldap3.Connection(
            server,
            authentication=ldap3.SASL,
            sasl_mechanism=ldap3.KERBEROS,
            auto_bind=False,
        )

    # user/password bind (both guaranteed present when uses_kerberos is False)
    server = ldap3.Server(config.host, port=config.port, use_ssl=config.use_ssl)
    return ldap3.Connection(server, user=config.user, password=config.password, auto_bind=False)


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
