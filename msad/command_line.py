#!/usr/bin/env python3

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
# along with this program.  If not, see <https://www.gnu.org/licenses/>

import logging
import os
import datetime
import sys
import msad
import fire
import ldap3
import ssl
import json
from typing import List, Tuple, Dict
import pprint


def _json_converter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()
    elif isinstance(o, list):
        return ";".join(o)
    # else return o


def _get_connection_krb(host, port, use_ssl):
    tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    server = ldap3.Server(host, port=port, use_ssl=use_ssl, tls=tls)

    conn = ldap3.Connection(
        server,
        authentication=ldap3.SASL,
        sasl_mechanism=ldap3.KERBEROS,
        auto_bind=False,
    )
    # conn.bind()
    return conn


def _get_connection_user_pwd(host, port, use_ssl, user, password):
    server = ldap3.Server(host, port, use_ssl)

    conn = ldap3.Connection(server, user=user, password=password, auto_bind=False)
    # conn.bind()
    return conn


def _get_connection(host, port, use_ssl, sso, user, password):
    if user and password:
        conn = _get_connection_user_pwd(host, port, use_ssl, user, password)
    else:
        conn = _get_connection_krb(host, port, use_ssl)

    conn.bind()
    return conn


class AD:
    """*msad* is command line tool for Active Directory. With it you can
    search objects,
    add/remove members to/from groups,
    change password
    check if a user is locked, disabled
    check if a user's password is expired"""

    def __init__(
        self,
        host,
        port,
        use_ssl=True,
        sso=True,
        user=None,
        password=None,
        search_base=None,
        limit=0,
        attributes=None,
        out_format="default",
        sep=";",
    ):
        try:
            self._conn = _get_connection(host, port, use_ssl, sso, user, password)
        except:
            logging.error("Cannot loging to Active Directory. Bye")
            sys.exit(1)
        self._attributes = attributes
        self._sep = sep
        self._search_base = search_base
        self._limit = limit
        self._out_format = out_format

    def change_password(self, user_name=None, user_dn=None):
        return msad.user.change_password(
            self._conn, self._search_base, user_name, user_dn
        )

    def search(self, search_filter):
        self._conn.search(
            self._search_base,
            search_filter,
            size_limit=self._limit,
            attributes=self._attributes,
        )
        result = list(filter(lambda e: "attributes" in e, self._conn.response))
        result = list(map(lambda e: e["attributes"], result))
        return self.pprint(result)

    def pprint(self, ldapresult):
        if not ldapresult or self._out_format == "default":
            return ldapresult
        elif self._out_format == "json1":
            return json.dumps(dict(ldapresult))
        else:
            result = ""
            for obj in ldapresult:
                if self._out_format == "json":
                    result = (
                        result + json.dumps(dict(obj), default=_json_converter) + "\n"
                    )
                elif self._out_format == "csv":
                    sorted_obj = dict(sorted(obj.items()))
                    new_values = list(
                        map(
                            lambda v: "|".join(v) if isinstance(v, list) else v,
                            sorted_obj.values(),
                        )
                    )
                    result = result + self._sep.join(new_values) + "\n"
            return result

    def users(self, user):
        """Search users inside AD
        filter: is the cn or userPrincipalName or samaccoutnname or mail to be searched. Can contain *
        """
        result = msad.users(
            self._conn, self._search_base, user, attributes=self._attributes
        )
        return self.pprint(result)

    def is_disabled(self, user):
        """Check if a user is disabled"""
        return msad.user.is_disabled(self._conn, self._search_base, user)

    def is_locked(self, user):
        """Locked user?"""
        return msad.user.is_locked(self._conn, self._search_base, user)

    def has_expired_password(self, user, max_age):
        """user with expired password?"""
        return msad.has_expired_password(self._conn, self._search_base, user, max_age)

    def has_never_expires_password(self, user):
        """user with never exires password?"""
        return msad.has_never_expires_password(self._conn, self._search_base, user)

    def check_user(self, user, max_age, groups=[]):
        """Get info about a user"""
        return msad.check_user(self._conn, self._search_base, user, max_age, groups)

    def group_flat_members(self, group_name=None, group_dn=None):
        result = msad.group_flat_members(
            self._conn,
            self._search_base,
            self._limit,
            group_name,
            group_dn,
            attributes=self._attributes,
        )
        return self.pprint(result)

    def group_members(self, group_name=None, group_dn=None):
        """Get members od a group"""
        if group_name is None and group_dn is None:
            logging.error("group_name or group_dn must be entered")
            return None
        result = msad.group_members(self._conn, self._search_base, group_name, group_dn)
        return self.pprint(result)

    def add_member(self, group_name=None, group_dn=None, user_name=None, user_dn=None):
        """Adding a user to a group"""
        return msad.add_member(
            conn=self._conn,
            search_base=self._search_base,
            group_name=group_name,
            group_dn=group_dn,
            user_name=user_name,
            user_dn=user_dn,
        )

    def user_groups(self, user_name=None, user_dn=None):
        """groups of a user"""
        return msad.user.user_groups(
            self._conn, self._search_base, self._limit, user_name, user_dn
        )

    def remove_member(
        self, group_name=None, group_dn=None, user_name=None, user_dn=None
    ):
        """Remove a user from a group"""
        return msad.remove_member(
            conn=self._conn,
            search_base=self._search_base,
            group_name=group_name,
            group_dn=group_dn,
            user_name=user_name,
            user_dn=user_dn,
        )

    def group_member(
        self, group_name=None, group_dn=None, user_name=None, user_dn=None
    ):
        """group membership"""
        return msad.group_member(
            conn=self._conn,
            search_base=self._search_base,
            group_name=group_name,
            group_dn=group_dn,
            user_name=user_name,
            user_dn=user_dn,
        )


BANNER = """
    _    ____
   / \  |  _ \
  / _ \ | | | |
 / ___ \| |_| |
/_/   \_\____/

"""


def main():
    """main"""
    logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
    fire.Fire(AD)


if __name__ == "__main__":
    main()
