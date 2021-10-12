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

import getpass
import ldap3


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
