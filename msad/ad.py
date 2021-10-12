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
import json
import argparse

def _get_server(host, port, use_ssl):
    return ldap3.Server(host, port=port, get_info=ldap3.ALL, use_ssl=use_ssl)

def _get_connection(host, port, use_ssl, binddn, bindpwd):
    server = _get_server(host, port, use_ssl)
    return ldap3.Connection(server, user=binddn, password=bindpwd, auto_bind=True)

def search(args):
    print(args)
    SEARCH_FILTER = "(&(objectClass={OBJECT_CLASS}){FILTER})".format(OBJECT_CLASS=args.object_class,
                                                                     FILTER=args.filter)

    conn =  _get_connection(args.host, args.port, args.use_ssl, args.binddn, args.bindpwd)
    conn.search(search_base = args.searchbase,
                search_filter = SEARCH_FILTER,
                search_scope = ldap3.SUBTREE,
                attributes = args.attributes,
                paged_size = args.limit)

    for obj in conn.response:
        if "attributes" in obj:
            if args.out_format == "json":
                print(json.dumps(dict(obj["attributes"])))
            else:
                print(args.sep.join(obj["attributes"].values()))

def search_users(args):
    """ Search users inside AD

        filter: is the cn or userPrincipalName or samaccoutnname or mail to be searched. Can contain *
    """
    #SEARCH_FILTER = "(&(objectClass=person)(|(userPrincipalName={USER})(samaccountname={USER})(mail={USER})(cn={USER})))".format(USER=filter)
    args.filter = "(|(samaccountname={USER})(mail={USER})(cn={USER})(userPrincipalName={USER}))".format(USER=args.filter)
    args.object_class = "user"
    return search(args)


def search_members(args):
    args.filter = "(&(objectClass=person)(sAMAccountName=*)(memberOf:1.2.840.113556.1.4.1941:={GROUP_DN}))".format(GROUP_DN=args.groupdn)
    return search(args)

def change_password(args, userdn, new_password, old_password):
    conn =  _get_connection(args.server, args.port, args.use_ssl, args.user, args.password)
    conn.extend.microsoft.modify_password(userdn, new_password, old_password)

def locked_users(args):
    ## (userAccountControl:1.2.840.113556.1.4.803:=2)
    SEARCH_FILTER = "(&(objectCategory=Person)(objectClass=User){filter}(lockoutTime>=1)))".format(filter=filter)
    return args.search(args)

def add_member(args):
    conn =  _get_connection(args.host, args.port, args.use_ssl, args.binddn, args.bindpwd)
    conn.extend.microsoft.add_members_to_groups(dn, groupdn)

def remove_member(args):
    conn =  _get_connection(args.host, args.port, args.use_ssl, args.binddn, args.bindpwd)
    conn.extend.microsoft.remove_members_from_groups(dn, groupdn)

def main():
    parser = argparse.ArgumentParser(prog="ad",
                                     description="A command line tool for intarecting woth Active Directory"
    )
    #parser.add_argument('command', metavar='CMD', type=str, nargs=1, choices=['search', 'remove_member'],
    #                    help='search|add_member')

    parser.add_argument('-p', '--port', nargs='?', type=int, default=389, help='389|636')
    parser.add_argument('-H', '--host', required=True, type=str)
    parser.add_argument('-S', '--use_ssl', action='store_true', default=False)
    parser.add_argument('-D', '--binddn', required=True, type=str)
    parser.add_argument('-P', '--bindpwd', required=True, type=str)
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1')

    subparsers = parser.add_subparsers(title='subcommands',
                                       description='search|change_password|add_member|remove_member',
                                       help='additional help')

    parser_search = subparsers.add_parser('search')
    parser_search.add_argument('-a', '--attributes', nargs='*', type=str, default=['distinguishedName'])
    parser_search.add_argument('-b', '--searchbase', required=True, type=str)
    parser_search.add_argument('-f', '--filter', required=True, type=str)
    parser_search.add_argument('-O', '--object_class', nargs='?', type=str, default='*')
    parser_search.add_argument('-o', '--out_format', nargs='?', type=str, default="json", help="csv | json")
    parser_search.add_argument('-s', '--sep', nargs='?', type=str, default="\t")
    parser_search.add_argument('-z', '--limit', nargs='?', type=int, default=1)
    parser_search.set_defaults(func=search)

    parser_search_members = subparsers.add_parser('search_members')
    parser_search_members.add_argument('-g', '--groudn', required=True, type=str)
    parser_search_members.set_defaults(func=search_members)

    parser_search_users = subparsers.add_parser('search_users')
    parser_search_users.add_argument('-f', '--filter', required=True, type=str)
    parser_search_users.set_defaults(func=search_users)

    args = parser.parse_args()
    args and args.func and args.func(args)
    #(args.command and args.user) or parser.print_usage()

if __name__ == '__main__':
    main()
