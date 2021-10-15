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

import getpass
import ldap3
import datetime
from .search import *
from .group import *


def _enter_password(text):
    try:
        p = getpass.getpass(text)
    except Exception as error:
        print("ERROR", error)
        return None
    else:
        return p


def change_password(conn):
    conn = _get_connection(args)
    user = users(args)
    oldpwd = _enter_password("Old password: ")
    newpwd = _enter_password("New password : ")
    newpwd2 = _enter_password("New password (check): ")
    if newpwd == newpwd2:
        conn.extend.microsoft.modify_password(user, newpwd, oldpwd)


def is_disabled(conn, search_base, user):
    result = disabled_users(
        conn, search_base, f"(samaccountname={user})", limit=1, attributes=None
    )
    logging.debug(result)
    return True if len(result) == 1 else False


def is_locked(conn, search_base, user):
    result = locked_users(
        conn, search_base, f"(samaccountname={user})", limit=1, attributes=None
    )
    return True if len(result) == 1 else False


def has_never_expires_password(conn, search_base, user):
    result = never_expires_password(
        conn, search_base, f"(samaccountname={user})", limit=1, attributes=None
    )
    return True if len(result) == 1 else False


def has_expired_password(conn, search_base, user, max_age):
    #    return search(conn, search_base, search_filter, attributes=attributes)
    search_filter = f"(samaccountname={user})"
    result = search(
        conn, search_base, search_filter, limit=1, attributes=["pwdLastSet"]
    )

    if len(result) == 0:
        return None
    result = result[0]["pwdLastSet"]
    logging.info(f"Password changed at {result}")
    now = datetime.datetime.now()

    if result == 0:
        return True
    else:
        delta = now - result.replace(tzinfo=None)
        days = delta.days
        return True if days > max_age else False


def check_user(conn, search_base, user, max_age, groups=[]):
    # result = {}
    yield ({"is_disabled": is_disabled(conn, search_base, user)})
    yield ({"is_locked": is_locked(conn, search_base, user)})
    yield (
        {
            "has_never_expires_password": has_never_expires_password(
                conn, search_base, user
            )
        }
    )
    yield (
        {"has_expired_password": has_expired_password(conn, search_base, user, max_age)}
    )
    for group in groups:
        yield (
            {
                f"membership_{group}": group_member(
                    conn, search_base, group_name=group, user_name=user
                )
            }
        )


def user_groups(conn, search_base, limit, user_name=None, user_dn=None):
    """retrieve all groups (also nested) of a user"""

    if user_name:
        user_dn = get_dn(conn, search_base, user_name)

    if not user_dn:
        return None

    search_filter = f"(member:1.2.840.113556.1.4.1941:={user_dn})"
    return search(
        conn, search_base, search_filter, limit_limit, attributes=["sAMaccountName"]
    )
