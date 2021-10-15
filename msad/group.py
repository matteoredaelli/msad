#!/usr/bin/env python3

# AD - Active Directory tool
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

from .search import *


def add_member(
    conn, search_base=None, group_name=None, group_dn=None, user_name=None, user_dn=None
):
    if group_name:
        group_dn = get_dn(conn, search_base, group_name)
    if not group_dn:
        logging.error("Missing group DN")
        return None

    if user_name:
        user_dn = get_dn(conn, search_base, user_name)
    if not user_dn:
        logging.error("Missing user DN")
        return None

    return conn.extend.microsoft.add_members_to_groups([user_dn], [group_dn])


def remove_member(
    conn, search_base=None, group_name=None, group_dn=None, user_name=None, user_dn=None
):
    if group_name:
        group_dn = get_dn(conn, search_base, group_name)

    if not group_dn:
        return None
    if user_name:
        user_dn = get_dn(conn, search_base, user_name)

    if not user_dn:
        return None

    return conn.extend.microsoft.remove_members_from_groups([user_dn], [group_dn])


def group_flat_members(
    conn, search_base, limit, group_name=None, group_dn=None, attributes=None
):
    if group_name:
        group_dn = get_dn(conn, search_base, group_name)

    if not group_dn:
        return None

    filter = f"(&(objectClass=person)(sAMAccountName=*)(memberOf:1.2.840.113556.1.4.1941:={group_dn}))"
    return search(conn, search_base, search_filter, attributes=attributes)


def group_members(conn, search_base, group_name=None, group_dn=None):
    if group_name:
        group_dn = get_dn(conn, search_base, group_name)
    if not group_dn:
        return None

    search_filter = f"(distinguishedName={group_dn})"
    return search(conn, group_dn, search_filter, limit=1, attributes=["member"])


def group_member(
    conn, search_base, group_name=None, group_dn=None, user_name=None, user_dn=None
):
    if group_name:
        group_dn = get_dn(conn, search_base, group_name)
    if not group_dn:
        return None

    if user_name:
        user_dn = get_dn(conn, search_base, user_name)
    if not user_dn:
        return None

    search_filter = f"(&(memberOf:1.2.840.113556.1.4.1941:={group_dn})(objectCategory=person)(objectClass=user)(distinguishedName={user_dn}))"
    result = search(conn, search_base, search_filter)
    return True if len(result) == 1 else False
