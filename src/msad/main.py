#!/usr/bin/env python3

# msad - Active Directory tool
# Copyright (C) 2025 - matteo.redaelli@gmail.com

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
import datetime
import os
import json
import ssl
import sys
import tomllib

import typer

import msad
import ldap3

from pathlib import Path


BANNER = """

"""

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
logging.info(BANNER)
    
def _get_domain_config(config: dict|None, domain: str|None):
    if "defaults" not in config:
        logging.error(f"Missing entry 'defaults' in config file. Bye!")
        sys.exit(100)
    if "domain" not in config["defaults"]:
        logging.error("Missing entry 'domain' in section 'defaults' in config file. Bye!")
        sys.exit(101)
        
    default_domain = config["defaults"]["domain"]
    
    if "domains" not in config:
        logging.error("Missing section 'domains' in config file. Bye!")
        sys.exit(102)
        
    if default_domain not in config["domains"] :
        logging.error(f"Missing section '{default_domain}' in section 'domains' in config file. Bye!")
        sys.exit(103)

    if domain and domain not in config["domains"] :
        logging.error(f"Missing section '{domain}' in section 'domains' in config file. Bye!")
        sys.exit(104)

    # TODO: validateing domain sections
    if not domain:
        domain = default_domain

    domain_config = config["domains"][domain]
    for field in ["host", "port", "search_base", "use_ssl"]:
        if field not in domain_config:
            logging.error(f"Missing required field '{field}' in section 'domains.{domain}' in config file. Bye!")
            sys.exit(105)
    return domain_config
        
def _get_config(domain: str|None, config_file: str|None):
    if not config_file:
        home = Path.home()
        config_file = home / ".msad.toml"

    if not os.path.isfile(config_file):
        logging.error(f"Missing file {config_file}. Bye!")
        sys.exit(1)
        
    if not os.access(config_file, os.R_OK):
        logging.error(f"File {config_file} is not readable. Bye!")
        sys.exit(2)
    
    """Read config file"""
    with open(config_file, "rb") as f:
        data = tomllib.load(f)
        return _get_domain_config(data, domain)

def _json_converter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()
    elif isinstance(o, list):
        return ";".join(o)
    # else return o


def _get_connection_krb(host: str, port: int, use_ssl: bool):
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


def _get_connection_user_pwd(host: str, port: int, use_ssl: bool, user: str, password: str):
    server = ldap3.Server(host, port=port, use_ssl=use_ssl)

    conn = ldap3.Connection(server, user=user, password=password, auto_bind=False)
    # conn.bind()
    return conn


def _get_connection(config: dict):
    if "user" in config and "password" in config:
        conn = _get_connection_user_pwd(config["host"],
                                        config["port"],
                                        config["use_ssl"],
                                        config["user"],
                                        config["password"])
    else:
        conn = _get_connection_krb(config["host"],
                                   config["port"],
                                   config["use_ssl"])
    conn.bind()
    return conn

def _pprint(ldapresult, out_format="json", sep="\t"):
    if not ldapresult or out_format == "default":
        return ldapresult
    elif out_format == "json1":
        return json.dumps(dict(ldapresult))
    else:
        result = ""
        for obj in ldapresult:
            if out_format == "json":
                result = (
                    result + json.dumps(dict(obj), default=_json_converter) + "\n"
                )
            elif out_format == "csv":
                sorted_obj = dict(sorted(obj.items()))
                new_values = list(
                    map(
                        lambda v: "|".join(v) if isinstance(v, list) else v,
                        sorted_obj.values(),
                    )
                )
                result = result + sep.join(new_values) + "\n"
        return result

    # def users(self, user):
    #     """Find users inside AD. The
    #     filter can be the cn or userPrincipalName or samaccoutnname or mail to be searched. Can contain *
    #     """
    #     result = msad.users(
    #         self._conn, self._search_base, user, attributes=self._attributes
    #     )
    #     return self._pprint(result)

    # def is_disabled(self, user):
    #     """Check if a user is disabled"""
    #     return msad.user.is_disabled(self._conn, self._search_base, user)

    # def is_locked(self, user):
    #     """Check if the user is locked"""
    #     return msad.user.is_locked(self._conn, self._search_base, user)

    # def password_changed_in_days(self, user):
    #     return msad.user.password_changed_in_days(self._conn, self._search_base, user)
    
    # def has_expired_password(self, user, max_age):
    #     """Check is user has the expired password"""
    #     return msad.has_expired_password(self._conn, self._search_base, user, max_age)

    # def has_never_expires_password(self, user):
    #     """Check if a user has never expires password"""
    #     return msad.has_never_expires_password(self._conn, self._search_base, user)

    # def check_user(self, user, max_age, groups=[]):
    #     """Get some info about a user: is it locked? disabled? password expired?"""
    #     return msad.check_user(self._conn, self._search_base, user, max_age, groups)



    # def user_groups(self, user_name=None, user_dn=None):
    #     """Extract the list of groups of a user (using DN or sAMAccountName)"""
    #     return msad.user.user_groups(
    #         self._conn, self._search_base, self._limit, user_name, user_dn
    #     )


    # def group_member(
    #     self, group_name=None, group_dn=None, user_name=None, user_dn=None
    # ):
    #     """Check if the user is a member of a group (using DN or sAMAccountName)"""
    #     return msad.group_member(
    #         conn=self._conn,
    #         search_base=self._search_base,
    #         group_name=group_name,
    #         group_dn=group_dn,
    #         user_name=user_name,
    #         user_dn=user_dn,
    #     )



app = typer.Typer()

@app.command()
def change_password(user: str,
                    domain: str|None = None,
                    config_file: str|None = None):
    config = _get_config(config_file, domain)
    conn = _get_connection(config)
    return msad.user.change_password(
        conn, config["search_base"], user)

@app.command()
def group_add_member(group: str,
                     user: str,
                     domain: str|None = None,
                     config_file: str|None = None):
    """Adds the user to a group (using DN or sAMAccountName)"""
    
    config = _get_config(config_file, domain)
    conn = _get_connection(config)
    result =  msad.add_member(
        conn=conn,
        search_base=config["search_base"],
        group=group,
        user=user,
    )
    return result

@app.command()
def group_remove_member(group: str,
                     user: str,
                     domain: str|None = None,
                     config_file: str|None = None):
    """Remove the user to a group (using DN or sAMAccountName)"""
    
    config = _get_config(config_file, domain)
    conn = _get_connection(config)
    result =  msad.remove_member(
        conn=conn,
        search_base=config["search_base"],
        group=group,
        user=user,
    )
    return result

@app.command()
def group_members(group: str,
                  nested: bool=False,
                  limit: int = 2000,
                  domain: str|None = None,
                  config_file: str|None = None,
                  out_format: str = "json",
                  attributes: list[str] = []):
    
    config = _get_config(config_file, domain)
    conn = _get_connection(config)
    if nested:
        result = msad.group_flat_members(
            conn,
            config["search_base"],
            limit,
            group,
            attributes=attributes,
        )
    else:
        """Extract the direct members of a group"""
        result = msad.group_members(
            conn,
            config["search_base"],
            group)
    print(_pprint(result))
    
@app.command()
def search(filter: str,
           limit: int = 2000,
           domain: str|None = None,
           config_file: str|None = None,
           out_format: str = "json",
           attributes: list[str] = []):
    config = _get_config(config_file, domain)
    conn = _get_connection(config)
    result = msad.search(conn, config["search_base"], filter, limit=limit, attributes=attributes)
    print(_pprint(result, out_format))

@app.command()
def get_sample_config():
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

@app.command()
def user_groups(user: str,
                nested: bool=False,
                limit: int = 2000,
                domain: str|None = None,
                config_file: str|None = None,
                out_format: str = "json"):
    
    config = _get_config(config_file, domain)
    conn = _get_connection(config)

    result = msad.user.user_groups(conn, config["search_base"], limit, user, nested=nested)
    print(_pprint(result, out_format))

if __name__ == "__main__":
    app()
