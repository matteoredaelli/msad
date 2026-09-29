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
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Any

import ldap3
import typer

import msad
from msad.config import DEFAULT_CONFIG_PATH, SAMPLE_CONFIG, DomainConfig, load_domain_config
from msad.connection import connect
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


def _connect(domain: str | None, config_file: str | None) -> tuple[DomainConfig, ldap3.Connection]:
    config = load_domain_config(domain, config_file)
    conn = connect(config)
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

    msad.change_password(conn, config.base, user, new_password, old_password)


@app.command()
@_handle_errors
def group_add_member(
    group: str, user: str, domain: str | None = None, config_file: str | None = None
):
    """Add the user to a group (using DN or sAMAccountName)."""
    config, conn = _connect(domain, config_file)
    result = msad.add_member(conn=conn, base=config.base, group=group, user=user)
    print(result)


@app.command()
@_handle_errors
def group_remove_member(
    group: str, user: str, domain: str | None = None, config_file: str | None = None
):
    """Remove the user from a group (using DN or sAMAccountName)."""
    config, conn = _connect(domain, config_file)
    result = msad.remove_member(conn=conn, base=config.base, group=group, user=user)
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
        conn, config.base, group, nested=nested, limit=limit, attributes=attributes
    )
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def test_connection(
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
):
    """Test connectivity and bind to the AD server. Exits non-zero on failure."""
    config = load_domain_config(domain, config_file)
    result = msad.check_connection(config)
    print(_pprint([result], out_format))
    if not result["ok"]:
        raise typer.Exit(1)


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
    result = msad.search(conn, config.base, filter, limit=limit, attributes=attributes)
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
    result = msad.user_groups(conn, config.base, limit, user, nested=nested)
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def user_search(
    name: str | None = None,
    surname: str | None = None,
    mail: str | None = None,
    sam: str | None = None,
    department: str | None = None,
    base: str | None = None,
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
        base or config.base,
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
    result = msad.get_user(conn, config.base, identifier, attributes=attributes)
    print(_pprint([result] if result else [], out_format))


@app.command()
@_handle_errors
def group_search(
    string: str,
    base: str | None = None,
    limit: int = 2000,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Find groups by cn/name/sAMAccountName/displayName (supports * wildcards)."""
    config, conn = _connect(domain, config_file)
    result = msad.find_groups(conn, base or config.base, string, limit=limit, attributes=attributes)
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
    result = msad.get_group(conn, config.base, identifier, attributes=attributes)
    print(_pprint([result] if result else [], out_format))


@app.command()
@_handle_errors
def get_by_dn(
    dn: str,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Fetch any entry directly by its DN (resolves manager / managedBy)."""
    _, conn = _connect(domain, config_file)
    result = msad.get_by_dn(conn, dn, attributes=attributes)
    print(_pprint([result] if result else [], out_format))


@app.command()
@_handle_errors
def computer_search(
    name: str | None = None,
    dns: str | None = None,
    os: str | None = None,
    base: str | None = None,
    limit: int = 2000,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Find computers by field (name/dns/os, all ANDed; values may contain *)."""
    config, conn = _connect(domain, config_file)
    result = msad.find_computers(
        conn,
        base or config.base,
        name=name,
        dns=dns,
        os=os,
        limit=limit,
        attributes=attributes,
    )
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def computer_get(
    identifier: str,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Get a single computer by sAMAccountName, cn or dNSHostName (exact match)."""
    config, conn = _connect(domain, config_file)
    result = msad.get_computer(conn, config.base, identifier, attributes=attributes)
    print(_pprint([result] if result else [], out_format))


@app.command()
@_handle_errors
def ou_search(
    name: str | None = None,
    base: str | None = None,
    limit: int = 2000,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Find organizational units by name (matches ou; values may contain *)."""
    config, conn = _connect(domain, config_file)
    result = msad.find_ous(conn, base or config.base, name=name, limit=limit, attributes=attributes)
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def ou_get(
    identifier: str,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Get a single OU by its ou name or full DN (exact match)."""
    config, conn = _connect(domain, config_file)
    result = msad.get_ou(conn, config.base, identifier, attributes=attributes)
    print(_pprint([result] if result else [], out_format))


@app.command()
@_handle_errors
def ou_contents(
    ou_dn: str,
    object_class: str | None = None,
    limit: int = 2000,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """List the objects contained under an OU (optionally filtered by objectClass)."""
    _, conn = _connect(domain, config_file)
    result = msad.get_ou_contents(
        conn, ou_dn, object_class=object_class, limit=limit, attributes=attributes
    )
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def inactive_users(
    days: int = 90,
    base: str | None = None,
    include_never: bool = False,
    limit: int = 2000,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Find enabled users whose last logon is older than --days (default 90)."""
    config, conn = _connect(domain, config_file)
    result = msad.find_inactive_users(
        conn,
        base or config.base,
        days=days,
        include_never=include_never,
        limit=limit,
        attributes=attributes,
    )
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def stale_computers(
    days: int = 90,
    base: str | None = None,
    include_never: bool = False,
    limit: int = 2000,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Find computers whose last logon is older than --days (default 90)."""
    config, conn = _connect(domain, config_file)
    result = msad.find_stale_computers(
        conn,
        base or config.base,
        days=days,
        include_never=include_never,
        limit=limit,
        attributes=attributes,
    )
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def domain_info(
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Read the domain object: security settings and metadata (audit)."""
    config, conn = _connect(domain, config_file)
    result = msad.get_domain_info(conn, config.base, attributes=attributes)
    print(_pprint([result] if result else [], out_format))


@app.command()
@_handle_errors
def password_policy(
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
):
    """Read the default domain password policy (audit)."""
    config, conn = _connect(domain, config_file)
    result = msad.get_password_policy(conn, config.base)
    print(_pprint([result] if result else [], out_format))


@app.command()
@_handle_errors
def password_policy_violations(
    include_never_set: bool = True,
    limit: int = 2000,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
    attributes: list[str] | None = None,
):
    """Find users whose password violates the domain policy (expired/never set)."""
    config, conn = _connect(domain, config_file)
    result = msad.get_password_policy_violations(
        conn,
        config.base,
        include_never_set=include_never_set,
        limit=limit,
        attributes=attributes,
    )
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def privileged_groups(
    with_members: bool = False,
    nested: bool = False,
    domain: str | None = None,
    config_file: str | None = None,
    out_format: OutFormat = OutFormat.jsonl,
):
    """Report on well-known privileged groups and their member counts (audit)."""
    config, conn = _connect(domain, config_file)
    result = msad.get_privileged_groups(conn, config.base, with_members=with_members, nested=nested)
    print(_pprint(result, out_format))


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
    result = msad.is_member(conn, config.base, group, user)
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
    _print_bool(msad.is_disabled(conn, config.base, user))


@app.command()
@_handle_errors
def is_locked(user: str, domain: str | None = None, config_file: str | None = None):
    """Check whether a user account is locked. Prints true/false/not found."""
    config, conn = _connect(domain, config_file)
    _print_bool(msad.is_locked(conn, config.base, user))


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
    _print_bool(msad.has_expired_password(conn, config.base, user, max_age=max_age))


@app.command()
@_handle_errors
def has_never_expires_password(
    user: str, domain: str | None = None, config_file: str | None = None
):
    """Check whether a user's password never expires. Prints true/false/not found."""
    config, conn = _connect(domain, config_file)
    _print_bool(msad.has_never_expires_password(conn, config.base, user))


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
    result = list(msad.check_user(conn, config.base, user, max_age=max_age, groups=group))
    print(_pprint(result, out_format))


@app.command()
@_handle_errors
def init(config_file: str | None = None, force: bool = False):
    """Create a sample config file in the user's home (~/.msad.toml).

    Does nothing (with a warning) if the file already exists, unless --force
    is given. Use --config-file to write to a different path.
    """
    path = Path(config_file) if config_file else DEFAULT_CONFIG_PATH

    if path.exists() and not force:
        logging.warning("Config file already exists, not overwriting: %s", path)
        logging.warning("Use --force to overwrite it.")
        return

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(SAMPLE_CONFIG, encoding="utf-8")
    except OSError as exc:
        logging.error("Could not write config file %s: %s", path, exc)
        raise typer.Exit(code=1) from exc

    action = "Overwrote" if force else "Created"
    print(f"{action} sample config: {path}")
    print("Edit it to set your domain(s), then run e.g. `msad user-get <name>`.")


if __name__ == "__main__":
    app()
