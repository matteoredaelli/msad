#!/usr/bin/env python3

# msad - Active Directory tool
# Copyright (C) 2025 - matteo.redaelli@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>

from __future__ import annotations

import datetime
import functools
import getpass
import json
import logging
import os
import ssl
from collections.abc import Callable
from enum import StrEnum
from typing import Any

import ldap3
import typer

import msad
from msad.config import DomainConfig, load_domain_config
from msad.exceptions import MsadError
from msad.types import LdapEntries

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))

app = typer.Typer()


class OutFormat(StrEnum):
    """Output serialization formats for CLI commands."""

    jsonl = "jsonl"  # one JSON object per line (JSON Lines / NDJSON)
    json = "json"  # a single JSON array
    csv = "csv"  # tab-separated, list values joined with "|"


def _handle_errors(func: Callable[..., Any]) -> Callable[..., Any]:
    """Map MsadError to a clean typer exit code instead of a traceback."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except MsadError as exc:
            logging.error(str(exc))
            raise typer.Exit(code=1) from exc

    return wrapper


def _json_converter(o: Any) -> Any:
    if isinstance(o, datetime.datetime):
        return str(o)
    elif isinstance(o, list):
        return ";".join(o)
    return o


def _get_connection_krb(host: str, port: int, use_ssl: bool):
    tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    server = ldap3.Server(host, port=port, use_ssl=use_ssl, tls=tls)
    return ldap3.Connection(
        server,
        authentication=ldap3.SASL,
        sasl_mechanism=ldap3.KERBEROS,
        auto_bind=False,
    )


def _get_connection_user_pwd(host: str, port: int, use_ssl: bool, user: str, password: str):
    server = ldap3.Server(host, port=port, use_ssl=use_ssl)
    return ldap3.Connection(server, user=user, password=password, auto_bind=False)


def _get_connection(config: DomainConfig):
    if config.uses_kerberos:
        conn = _get_connection_krb(config.host, config.port, config.use_ssl)
    else:
        assert config.user is not None and config.password is not None
        conn = _get_connection_user_pwd(
            config.host, config.port, config.use_ssl, config.user, config.password
        )
    conn.bind()
    return conn


def _connect(domain: str | None, config_file: str | None) -> tuple[DomainConfig, ldap3.Connection]:
    config = load_domain_config(domain, config_file)
    conn = _get_connection(config)
    return config, conn


def _pprint(
    ldapresult: LdapEntries | None, out_format: OutFormat = OutFormat.jsonl, sep: str = "\t"
) -> Any:
    if not ldapresult:
        return ldapresult
    elif out_format == OutFormat.json:
        # A single, valid JSON array containing every object.
        return json.dumps([dict(obj) for obj in ldapresult], default=_json_converter)
    else:
        result = ""
        for obj in ldapresult:
            if out_format == OutFormat.jsonl:
                # JSON Lines / NDJSON: one JSON object per line.
                result = result + json.dumps(dict(obj), default=_json_converter) + "\n"
            elif out_format == OutFormat.csv:
                sorted_obj = dict(sorted(obj.items()))
                new_values = [
                    "|".join(v) if isinstance(v, list) else str(v) for v in sorted_obj.values()
                ]
                result = result + sep.join(new_values) + "\n"
        return result


@app.command()
@_handle_errors
def change_password(user: str, domain: str | None = None, config_file: str | None = None):
    """Change a user's password (prompts interactively)."""
    config, conn = _connect(domain, config_file)

    old_password = getpass.getpass("Old password: ")
    new_password = getpass.getpass("New password: ")
    new_password_check = getpass.getpass("New password (check): ")
    if new_password != new_password_check:
        logging.error("Passwords do not match. Aborting.")
        raise typer.Exit(code=1)

    msad.change_password(conn, config.search_base, user, new_password, old_password)


@app.command()
@_handle_errors
def group_add_member(
    group: str, user: str, domain: str | None = None, config_file: str | None = None
):
    """Add the user to a group (using DN or sAMAccountName)."""
    config, conn = _connect(domain, config_file)
    result = msad.add_member(conn=conn, search_base=config.search_base, group=group, user=user)
    print(result)


@app.command()
@_handle_errors
def group_remove_member(
    group: str, user: str, domain: str | None = None, config_file: str | None = None
):
    """Remove the user from a group (using DN or sAMAccountName)."""
    config, conn = _connect(domain, config_file)
    result = msad.remove_member(conn=conn, search_base=config.search_base, group=group, user=user)
    print(result)


@app.command()
@_handle_errors
def group_members(
    group: str,
    nested: bool = False,
    limit: int = 2000,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Extract the members of a group (direct, or nested with --nested)."""
    config, conn = _connect(domain, config_file)
    result = msad.group_members(
        conn, config.search_base, group, nested=nested, limit=limit, attributes=attributes
    )
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def search(
    filter: str,
    limit: int = 2000,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Search Active Directory with a raw LDAP filter."""
    config, conn = _connect(domain, config_file)
    result = msad.search(conn, config.search_base, filter, limit=limit, attributes=attributes)
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def user_groups(
    user: str,
    nested: bool = False,
    limit: int = 2000,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
):
    """Extract the groups of a user (direct, or nested with --nested)."""
    config, conn = _connect(domain, config_file)
    result = msad.user_groups(conn, config.search_base, limit, user, nested=nested)
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def user_search(
    name: str | None = None,
    surname: str | None = None,
    mail: str | None = None,
    sam: str | None = None,
    department: str | None = None,
    limit: int = 2000,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Find users by field (name/surname/mail/sam/department, all ANDed)."""
    config, conn = _connect(domain, config_file)
    result = msad.find_users(
        conn,
        config.search_base,
        name=name,
        surname=surname,
        mail=mail,
        sam=sam,
        department=department,
        limit=limit,
        attributes=attributes,
    )
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def user_get(
    identifier: str,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Get a single user by sAMAccountName, UPN, mail or cn (exact match)."""
    config, conn = _connect(domain, config_file)
    result = msad.get_user(conn, config.search_base, identifier, attributes=attributes)
    print(_pprint([result] if result else [], out_format))


@app.command()
@_handle_errors
def group_search(
    string: str,
    limit: int = 2000,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Find groups by cn/name/sAMAccountName/displayName (supports * wildcards)."""
    config, conn = _connect(domain, config_file)
    result = msad.find_groups(conn, config.search_base, string, limit=limit, attributes=attributes)
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def group_get(
    identifier: str,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Get a single group by sAMAccountName or cn (exact match)."""
    config, conn = _connect(domain, config_file)
    result = msad.get_group(conn, config.search_base, identifier, attributes=attributes)
    print(_pprint([result] if result else [], out_format))


@app.command()
@_handle_errors
def is_member(
    group: str,
    user: str,
    domain: str | None = None,
    config_file: str | None = None,
):
    """Check whether a user is a (nested) member of a group. Prints true/false."""
    config, conn = _connect(domain, config_file)
    result = msad.is_member(conn, config.search_base, group, user)
    print("true" if result else "false")


def _print_bool(result: bool | None) -> None:
    """Print a bool|None check result as true/false/not found."""
    if result is None:
        print("not found")
    else:
        print("true" if result else "false")


@app.command()
@_handle_errors
def is_disabled(user: str, domain: str | None = None, config_file: str | None = None):
    """Check whether a user account is disabled. Prints true/false/not found."""
    config, conn = _connect(domain, config_file)
    _print_bool(msad.is_disabled(conn, config.search_base, user))


@app.command()
@_handle_errors
def is_locked(user: str, domain: str | None = None, config_file: str | None = None):
    """Check whether a user account is locked. Prints true/false/not found."""
    config, conn = _connect(domain, config_file)
    _print_bool(msad.is_locked(conn, config.search_base, user))


@app.command()
@_handle_errors
def has_expired_password(
    user: str,
    max_age: int = 90,
    domain: str | None = None,
    config_file: str | None = None,
):
    """Check whether a user's password is expired. Prints true/false/not found."""
    config, conn = _connect(domain, config_file)
    _print_bool(msad.has_expired_password(conn, config.search_base, user, max_age=max_age))


@app.command()
@_handle_errors
def has_never_expires_password(
    user: str, domain: str | None = None, config_file: str | None = None
):
    """Check whether a user's password never expires. Prints true/false/not found."""
    config, conn = _connect(domain, config_file)
    _print_bool(msad.has_never_expires_password(conn, config.search_base, user))


@app.command()
@_handle_errors
def check_user(
    user: str,
    max_age: int = 90,
    group: list[str] | None = None,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
):
    """Run all checks on a user (disabled, locked, password, memberships)."""
    config, conn = _connect(domain, config_file)
    result = list(msad.check_user(conn, config.search_base, user, max_age=max_age, groups=group))
    print(_pprint(result, out_format))


@app.command()
def get_sample_config():
    """Print a sample configuration file."""
    output = """
[defaults]

domain = "mydomain"

[domains]

[domains.mydomain]

host = "example.com"
search_base = "dc=example,dc=com"

port = 636
use_ssl = true
#port = 389
#use_ssl = false

# user =
# password =
"""
    print(output)


if __name__ == "__main__":
    app()
