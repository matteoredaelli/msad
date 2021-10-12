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

import ldap3


def users(conn, search_base, string, attributes=None):
    """Search users inside AD
    filter: is the cn or userPrincipalName or samaccoutnname or mail to be searched. Can contain *
    """
    search_filter = f"(&(objectclass=user)(|(samaccountname={string})(mail={string})(cn={string})(userPrincipalName={string})))"
    conn.search(search_base, search_filter, attributes=attributes)
    result = conn.response
    return result


def get_dn(conn, search_base, sAMAccountName):
    search_filter = f"(sAMAccountName={sAMAccountName})"
    conn.search(search_base, search_filter, size_limit=1)
    result = conn.response
    if len(result) < 1:
        return nil
    return result[0]["dn"]


def locked_users(conn, search_base, filter, limit=0, attributes=None):
    ## (userAccountControl:1.2.840.113556.1.4.803:=2)
    search_filter = (
        f"(&(objectCategory=Person)(objectClass=User){filter}(lockoutTime>=1))"
    )
    conn.search(search_base, search_filter, size_limit=limit, attributes=attributes)
    result = conn.response
    return result
