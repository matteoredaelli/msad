# msad - Active Directory tool
# Copyright (C) 2025 - matteo.redaelli@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Shared type aliases for the msad library.

LDAP entries are inherently dynamic (the returned attributes depend on the
requested ``attributes`` list), so results are typed as plain dictionaries
rather than rigid models. Structured Pydantic response models can be layered
on top by consumers such as the MCP server.
"""

from __future__ import annotations

from typing import Any, TypeAlias

from ldap3 import Connection

#: A bound (or bindable) ldap3 connection.
LdapConnection: TypeAlias = Connection

#: A single LDAP entry: attribute name -> value(s).
LdapEntry: TypeAlias = dict[str, Any]

#: A list of LDAP entries, as returned by search operations.
LdapEntries: TypeAlias = list[LdapEntry]

#: Attributes to request from LDAP. ``None`` means "all attributes".
Attributes: TypeAlias = list[str] | None
